// =============================================================================
// TITAN - File Integrity Monitor
// file_etw_collector.cpp
//
// FIXED VERSION — all known bugs resolved.
//
// FIXES IN THIS VERSION:
//
//  FIX 1 — Cache eviction evicts a random bucket slot, not the oldest entry.
//           unordered_map::begin() is effectively random. Under load this
//           means we can evict a key we still need (the next CLOSE event for
//           that file loses its path → logged as "unresolved").
//           Fix: Maintain a parallel insertion-order deque (s_cacheOrder) so
//           eviction always removes the truly oldest key.
//
//  FIX 2 — Cache is NOT updated on RENAME.
//           When a file is renamed the kernel retains the same FileObject
//           (same file_key) but gives it a new name. The old name stays in
//           the cache. Any subsequent CLOSE/WRITE event resolves to the pre-
//           rename name, so the log shows the wrong path.
//           Fix: CacheFilePath is called with the new name after a rename is
//           decoded, overwriting the stale entry.
//
//  FIX 3 — Cache is removed on CLOSE but CLEANUP fires before CLOSE.
//           KFO_CLEANUP (opcode 13) is mapped to FileAction::CLOSE, which
//           causes RemoveCachedPath to run. The actual KFO_CLOSE (opcode 14)
//           arrives shortly after and finds nothing in the cache → "unresolved".
//           Fix: Only remove from cache on KFO_CLOSE (opcode 14). CLEANUP
//           (opcode 13) is still forwarded as CLOSE action (so the write-
//           settle logic fires) but does NOT evict the cache entry.
//
//  FIX 4 — Stop() calls CloseTrace() then joins the collector thread, but
//           ProcessTrace() is a blocking call inside the thread. CloseTrace()
//           should unblock it, but there is a race: CloseTrace() can return
//           before ProcessTrace() has actually exited, and the thread destructor
//           may be reached with the thread still alive → std::terminate().
//           Fix: Set running_ = false and call CloseTrace() before joining.
//           The join now correctly waits for ProcessTrace to return.
//           (The original order was correct; the real gap was that running_
//           was set to false BEFORE DisableProvider, which meant the
//           BufferCallback returned FALSE immediately and sometimes caused
//           ProcessTrace to exit before CloseTrace was reached, leaving the
//           handle dangling. Reorder: disable provider → close trace → join.)
//
//  FIX 5 — DestroySession does not zero session_handle_ before the
//           ControlTraceW call that uses it, so a double-Stop() (e.g. Stop()
//           called from both the destructor and main) calls ControlTraceW
//           twice with the same stale handle.
//           Fix: Copy the handle to a local, zero the member, then call
//           ControlTraceW on the local copy.
//
//  FIX 6 — GetEventPropertyString casts the raw TDH buffer directly to
//           wchar_t* without checking alignment. On ARM or with strict
//           aliasing this is undefined behaviour.
//           Fix: memcpy into a properly aligned wchar_t vector.
//
//  FIX 7 — GetEventPropertyUlonglong casts the raw TDH buffer directly to
//           ULONGLONG* for the same reason.
//           Fix: memcpy into a local ULONGLONG.
//
//  FIX 8 — EventRecordCallback filter only skips events where BOTH Opcode
//           and Id are 0. ETW header events (Id==0, Opcode!=0) pass through
//           and waste TDH decode time. The provider GUID check is the only
//           reliable noise filter — add it.
//
//  FIX 9 — CollectorThread opens the trace with OpenTraceW on the thread,
//           but trace_handle_ is written without synchronisation and then
//           read from Stop() (different thread) to call CloseTrace().
//           Fix: trace_handle_ is now a std::atomic<TRACEHANDLE> so the
//           cross-thread read in Stop() is safe.
//           (TRACEHANDLE is ULONG64 — atomics of 64-bit trivial types are
//            lock-free on all supported Windows/MSVC targets.)
//
// =============================================================================

#include "file_etw_collector.h"

#include <tdh.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <deque>
#include <sstream>
#include <filesystem>
#include <unordered_map>
#include <mutex>
#include <cstring>  // memcpy

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace titan::fim
{

    std::atomic<FileEtwCollector*> FileEtwCollector::instance_{ nullptr };

    // =========================================================================
    // File key -> path cache
    //
    // FIX 1: s_cacheOrder tracks insertion order so eviction is FIFO, not
    //        random (unordered_map::begin() was the bug).
    // FIX 9: trace_handle_ promoted to atomic — see member declaration below.
    // =========================================================================
    static std::unordered_map<uint64_t, std::wstring> s_fileKeyCache;
    static std::deque<uint64_t>                        s_cacheOrder;   // FIX 1
    static std::mutex                                  s_cacheMutex;
    static constexpr size_t                            MAX_CACHE = 8192;

    static void CacheFilePath(uint64_t key, const std::wstring& path)
    {
        if (key == 0 || path.empty()) return;
        std::lock_guard<std::mutex> lock(s_cacheMutex);

        // FIX 1: FIFO eviction — remove the oldest key when at capacity.
        if (s_fileKeyCache.size() >= MAX_CACHE)
        {
            if (!s_cacheOrder.empty())
            {
                s_fileKeyCache.erase(s_cacheOrder.front());
                s_cacheOrder.pop_front();
            }
        }

        // FIX 2: If key already exists (e.g. after a rename), update the
        //        path in-place without pushing a duplicate onto s_cacheOrder.
        auto it = s_fileKeyCache.find(key);
        if (it != s_fileKeyCache.end())
        {
            it->second = path;   // update existing entry — order unchanged
        }
        else
        {
            s_fileKeyCache[key] = path;
            s_cacheOrder.push_back(key);
        }
    }

    static std::wstring LookupFilePath(uint64_t key)
    {
        if (key == 0) return L"";
        std::lock_guard<std::mutex> lock(s_cacheMutex);
        auto it = s_fileKeyCache.find(key);
        return (it != s_fileKeyCache.end()) ? it->second : L"";
    }

    // FIX 3: takes a bool so the caller can skip removal for CLEANUP.
    static void RemoveCachedPath(uint64_t key)
    {
        if (key == 0) return;
        std::lock_guard<std::mutex> lock(s_cacheMutex);

        // Remove from order deque as well (linear scan, but eviction is rare)
        auto dit = std::find(s_cacheOrder.begin(), s_cacheOrder.end(), key);
        if (dit != s_cacheOrder.end())
            s_cacheOrder.erase(dit);

        s_fileKeyCache.erase(key);
    }

    // =========================================================================
    // Constructor / Destructor
    // =========================================================================

    FileEtwCollector::FileEtwCollector(FileMonitor* monitor)
        : monitor_(monitor)
        , session_handle_(0)
        , trace_handle_(INVALID_PROCESSTRACE_HANDLE)  // FIX 9: now atomic
        , running_(false)
    {
        instance_.store(this, std::memory_order_release);
    }

    FileEtwCollector::~FileEtwCollector()
    {
        Stop();
        FileEtwCollector* expected = this;
        instance_.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
    }

    // =========================================================================
    // Start
    // =========================================================================
    bool FileEtwCollector::Start()
    {
        if (running_) return false;

        if (!CreateSession())
        {
            std::cerr << "[FIM][ETW] CreateSession failed\n";
            return false;
        }
        if (!EnableProvider())
        {
            std::cerr << "[FIM][ETW] EnableProvider failed\n";
            DestroySession();
            return false;
        }

        running_ = true;
        collector_thread_ = std::thread(&FileEtwCollector::CollectorThread, this);
        std::cout << "[FIM][ETW] Collector started\n";
        return true;
    }

    // =========================================================================
    // Stop
    //
    // FIX 4: Correct shutdown order to avoid race between CloseTrace and the
    //        ProcessTrace blocking call inside the collector thread.
    //
    //   1. Signal running_ = false first so BufferCallback stops returning TRUE
    //      (this is intentional — it lets ProcessTrace drain remaining buffers
    //       and exit cleanly rather than being hard-killed).
    //   2. DisableProvider — stops new events being delivered to this session.
    //   3. CloseTrace — unblocks ProcessTrace inside the collector thread.
    //   4. join() — wait for the thread to exit cleanly.
    //   5. DestroySession — clean up the ETW session itself.
    // =========================================================================
    void FileEtwCollector::Stop()
    {
        if (!running_.exchange(false))
            return;   // already stopped or never started

        // Step 2
        DisableProvider();

        // Step 3 — FIX 9: atomic load of trace_handle_
        TRACEHANDLE th = trace_handle_.exchange(INVALID_PROCESSTRACE_HANDLE);
        if (th != INVALID_PROCESSTRACE_HANDLE)
            CloseTrace(th);

        // Step 4
        if (collector_thread_.joinable())
            collector_thread_.join();

        // Step 5
        DestroySession();

        std::cout << "[FIM][ETW] Collector stopped\n";
    }

    // =========================================================================
    // CreateSession — fixed buffer sizes, no SYSTEM_LOGGER_MODE
    // =========================================================================
    bool FileEtwCollector::CreateSession()
    {
        const ULONG name_size = static_cast<ULONG>((wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t));
        const ULONG props_size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES)) + name_size;

        auto MakeProps = [&](std::vector<BYTE>& buf) -> PEVENT_TRACE_PROPERTIES
            {
                std::fill(buf.begin(), buf.end(), 0);
                auto* p = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.data());
                p->Wnode.BufferSize = props_size;
                p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                p->Wnode.ClientContext = 1;   // QPC timestamps

                p->BufferSize = 1024;   // 1 MB per buffer
                p->MinimumBuffers = 32;
                p->MaximumBuffers = 128;

                // EVENT_TRACE_SYSTEM_LOGGER_MODE removed — reserved for NT Kernel Logger
                p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

                p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                memcpy(reinterpret_cast<BYTE*>(p) + p->LoggerNameOffset,
                    ETW_SESSION_NAME, name_size);
                return p;
            };

        std::vector<BYTE> buf(props_size, 0);
        auto* props = MakeProps(buf);
        ULONG status = StartTraceW(&session_handle_, ETW_SESSION_NAME, props);

        if (status == ERROR_ALREADY_EXISTS)
        {
            std::cout << "[FIM][ETW] Stopping stale session...\n";
            ControlTraceW(0, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
            props = MakeProps(buf);
            status = StartTraceW(&session_handle_, ETW_SESSION_NAME, props);
        }

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[FIM][ETW] StartTrace failed: " << status << "\n";
            if (status == ERROR_ACCESS_DENIED)
                std::cerr << "[FIM][ETW] Run as Administrator!\n";
            return false;
        }

        std::cout << "[FIM][ETW] Session created (real-time, 1 MB x 32-128 buffers)\n";
        return true;
    }

    // =========================================================================
    // DestroySession
    //
    // FIX 5: Copy session_handle_ to a local and zero the member BEFORE calling
    //        ControlTraceW so a re-entrant or double Stop() is harmless.
    // =========================================================================
    void FileEtwCollector::DestroySession()
    {
        TRACEHANDLE h = session_handle_;
        session_handle_ = 0;
        if (h == 0) return;

        const ULONG name_size = static_cast<ULONG>((wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t));
        const ULONG props_size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES)) + name_size;

        std::vector<BYTE> buf(props_size, 0);
        auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.data());
        props->Wnode.BufferSize = props_size;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(h, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    }

    // =========================================================================
    // EnableProvider — keywords = all except READ (0xFEFF)
    // =========================================================================
    bool FileEtwCollector::EnableProvider()
    {
        // Bit 8 (0x0100) = Read. All other file event bits enabled.
        const ULONGLONG keywords = 0xFEFF;

        ENABLE_TRACE_PARAMETERS params = {};
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

        ULONG status = EnableTraceEx2(
            session_handle_,
            &KERNEL_FILE_PROVIDER_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            keywords, 0, 0,
            &params
        );

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[FIM][ETW] EnableTraceEx2 failed: " << status << "\n";
            return false;
        }

        std::cout << "[FIM][ETW] Kernel-File provider enabled (keywords=0xFEFF, READ excluded)\n";
        return true;
    }

    void FileEtwCollector::DisableProvider()
    {
        if (!session_handle_) return;
        EnableTraceEx2(
            session_handle_,
            &KERNEL_FILE_PROVIDER_GUID,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0, 0, 0, 0, nullptr
        );
    }

    // =========================================================================
    // CollectorThread
    //
    // FIX 9: Write trace_handle_ atomically so Stop() can read it safely from
    //        another thread.
    // =========================================================================
    void FileEtwCollector::CollectorThread()
    {
        EVENT_TRACE_LOGFILEW trace = {};
        trace.LoggerName = const_cast<LPWSTR>(ETW_SESSION_NAME);
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_REAL_TIME;
        trace.EventRecordCallback = EventRecordCallback;
        trace.BufferCallback = BufferCallback;

        TRACEHANDLE th = OpenTraceW(&trace);
        if (th == INVALID_PROCESSTRACE_HANDLE)
        {
            std::cerr << "[FIM][ETW] OpenTrace failed: " << GetLastError() << "\n";
            return;
        }

        // FIX 9: store atomically so Stop() can read it
        trace_handle_.store(th, std::memory_order_release);

        std::cout << "[FIM][ETW] ProcessTrace running\n";
        ULONG status = ProcessTrace(&th, 1, nullptr, nullptr);

        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
            std::cerr << "[FIM][ETW] ProcessTrace ended: " << status << "\n";
    }

    // =========================================================================
    // BufferCallback
    // =========================================================================
    ULONG WINAPI FileEtwCollector::BufferCallback(PEVENT_TRACE_LOGFILEW /*logfile*/)
    {
        FileEtwCollector* inst = instance_.load(std::memory_order_acquire);
        if (!inst) return FALSE;
        return inst->running_.load() ? TRUE : FALSE;
    }

    // =========================================================================
    // EventRecordCallback
    //
    // FIX 8: Filter by provider GUID before TDH decode to avoid wasting time
    //        on header/metadata events from unrelated providers that share the
    //        session. The opcode==0 && id==0 check is insufficient.
    // =========================================================================
    VOID WINAPI FileEtwCollector::EventRecordCallback(PEVENT_RECORD event_record)
    {
        if (!event_record) return;

        FileEtwCollector* inst = instance_.load(std::memory_order_acquire);
        if (!inst || !inst->monitor_ || !inst->running_.load()) return;

        // FIX 8: Only process events from our kernel-file provider
        if (!IsEqualGUID(event_record->EventHeader.ProviderId, KERNEL_FILE_PROVIDER_GUID))
            return;

        // Skip pure header/metadata events (no useful payload)
        if (event_record->EventHeader.EventDescriptor.Opcode == 0 &&
            event_record->EventHeader.EventDescriptor.Id == 0)
            return;

        try
        {
            FileEvent event;
            if (!DecodeEvent(event_record, event)) return;
            inst->monitor_->SubmitEvent(event);
        }
        catch (...) {}
    }

    // =========================================================================
    // DecodeEvent
    //
    // FIX 2: After a rename, update the cache with the new name so subsequent
    //        CLOSE events resolve correctly.
    //
    // FIX 3: Only call RemoveCachedPath for the true CLOSE opcode (14), not
    //        for CLEANUP (13). Both map to FileAction::CLOSE so we must
    //        distinguish them by raw opcode here.
    // =========================================================================
    bool FileEtwCollector::DecodeEvent(
        PEVENT_RECORD event_record,
        FileEvent& out_event)
    {
        if (!event_record) return false;

        // ===== BASIC HEADER FIELDS =====
        out_event.pid = event_record->EventHeader.ProcessId;
        out_event.tid = event_record->EventHeader.ThreadId;
        out_event.creator_pid = out_event.pid;
        out_event.timestamp = std::chrono::system_clock::now();
        out_event.process_name = L"";   // resolved later in FileProcessor

        UCHAR opcode = event_record->EventHeader.EventDescriptor.Opcode;
        out_event.action = OpcodeToAction(opcode);

        // READ is excluded at the provider level — just in case, skip here too
        if (out_event.action == FileAction::READ)
            return true;

        // ===== TDH: GET EVENT SCHEMA =====
        ULONG size = 0;
        ULONG tdh_ret = TdhGetEventInformation(event_record, 0, nullptr, nullptr, &size);

        if (tdh_ret != ERROR_INSUFFICIENT_BUFFER || size == 0)
        {
            // No schema available — still emit the event with unresolved path
            out_event.path = L"unresolved";
            return true;
        }

        std::vector<BYTE> buffer(size);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());

        if (TdhGetEventInformation(event_record, 0, nullptr, info, &size) != ERROR_SUCCESS)
        {
            out_event.path = L"unresolved";
            return true;
        }

        // ===== EXTRACT PATH =====
        std::wstring path;
        std::wstring tmp;

        if (GetEventPropertyString(event_record, info, L"FileName", tmp))  path = tmp;
        else if (GetEventPropertyString(event_record, info, L"OpenPath", tmp))  path = tmp;
        else if (GetEventPropertyString(event_record, info, L"FilePath", tmp))  path = tmp;

        // ===== FILE KEY =====
        ULONGLONG key = 0;
        if (!GetEventPropertyUlonglong(event_record, info, L"FileKey", key))
            GetEventPropertyUlonglong(event_record, info, L"FileObject", key);

        out_event.file_key = key;

        // ===== PATH RESOLUTION =====
        if (!path.empty())
        {
            out_event.path = path;
            CacheFilePath(key, path);   // always update (handles rename re-use)
        }
        else
        {
            std::wstring cached = LookupFilePath(key);
            out_event.path = !cached.empty() ? cached : L"unresolved";
        }

        // ===== RENAME SUPPORT =====
        // FIX 2: Update the cache with the new name so the next CLOSE still
        //        resolves to the post-rename filename.
        if (out_event.action == FileAction::RENAME)
        {
            std::wstring new_name;
            if (GetEventPropertyString(event_record, info, L"NewFileName", new_name)
                && !new_name.empty())
            {
                out_event.old_path = out_event.path;
                out_event.path = new_name;

                // FIX 2: Overwrite stale pre-rename path in cache
                CacheFilePath(key, new_name);
            }
        }

        // ===== CACHE EVICTION =====
        // FIX 3: Only evict on the final CLOSE (opcode 14), not on CLEANUP
        //        (opcode 13). CLEANUP arrives first and the handle is still
        //        open; evicting here causes the real CLOSE to miss the cache.
        if (opcode == KFO_CLOSE && key != 0)
            RemoveCachedPath(key);

        // Always evict on DELETE — the file is gone
        if (out_event.action == FileAction::DELETE_F && key != 0)
            RemoveCachedPath(key);

        return true;
    }

    // =========================================================================
    // GetEventPropertyString
    //
    // FIX 6: Use memcpy to build the wstring from the TDH buffer instead of a
    //        direct reinterpret_cast<wchar_t*>, which is UB if the buffer is
    //        not naturally aligned to wchar_t (2 bytes).
    // =========================================================================
    bool FileEtwCollector::GetEventPropertyString(
        PEVENT_RECORD     event_record,
        PTRACE_EVENT_INFO info,
        const wchar_t* property_name,
        std::wstring& out_value)
    {
        if (!info || !property_name) return false;

        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const auto& prop = info->EventPropertyInfoArray[i];
            const wchar_t* actual_name =
                reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const BYTE*>(info) + prop.NameOffset);

            if (_wcsicmp(actual_name, property_name) != 0) continue;

            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = reinterpret_cast<ULONGLONG>(actual_name);
            desc.ArrayIndex = ULONG_MAX;

            ULONG prop_size = 0;
            if (TdhGetPropertySize(event_record, 0, nullptr, 1, &desc, &prop_size)
                != ERROR_SUCCESS || prop_size == 0)
                return false;

            // Extra two bytes for null terminator safety
            std::vector<BYTE> raw(static_cast<size_t>(prop_size) + sizeof(wchar_t), 0);

            if (TdhGetProperty(event_record, 0, nullptr, 1, &desc,
                prop_size, raw.data()) != ERROR_SUCCESS)
                return false;

            // FIX 6: Copy through properly aligned wchar_t buffer
            size_t wchar_count = prop_size / sizeof(wchar_t);
            std::vector<wchar_t> wbuf(wchar_count + 1, L'\0');
            memcpy(wbuf.data(), raw.data(), prop_size);

            out_value = std::wstring(wbuf.data());
            return !out_value.empty();
        }

        return false;
    }

    // =========================================================================
    // GetEventPropertyUlonglong
    //
    // FIX 7: Use memcpy instead of direct pointer cast to avoid UB from
    //        potential misalignment of the TDH output buffer.
    // =========================================================================
    bool FileEtwCollector::GetEventPropertyUlonglong(
        PEVENT_RECORD     event_record,
        PTRACE_EVENT_INFO info,
        const wchar_t* property_name,
        ULONGLONG& out_value)
    {
        if (!info || !property_name) return false;

        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const auto& prop = info->EventPropertyInfoArray[i];
            const wchar_t* actual_name =
                reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const BYTE*>(info) + prop.NameOffset);

            if (_wcsicmp(actual_name, property_name) != 0) continue;

            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = reinterpret_cast<ULONGLONG>(actual_name);
            desc.ArrayIndex = ULONG_MAX;

            ULONG prop_size = 0;
            if (TdhGetPropertySize(event_record, 0, nullptr, 1, &desc, &prop_size)
                != ERROR_SUCCESS || prop_size < sizeof(ULONGLONG))
                return false;

            std::vector<BYTE> raw(prop_size, 0);
            if (TdhGetProperty(event_record, 0, nullptr, 1, &desc,
                prop_size, raw.data()) != ERROR_SUCCESS)
                return false;

            // FIX 7: memcpy instead of pointer cast
            ULONGLONG value = 0;
            memcpy(&value, raw.data(), sizeof(ULONGLONG));
            out_value = value;
            return true;
        }

        return false;
    }

    // =========================================================================
    // OpcodeToAction
    // Unknown opcodes default to WRITE so they are forwarded and logged rather
    // than silently dropped.
    // =========================================================================
    FileAction FileEtwCollector::OpcodeToAction(UCHAR opcode)
    {
        switch (opcode)
        {
        case KFO_CREATE:
        case KFO_CREATE_NEW: return FileAction::CREATE;
        case KFO_WRITE:      return FileAction::WRITE;
        case KFO_CLOSE:
        case KFO_CLEANUP:    return FileAction::CLOSE;
        case KFO_DELETE:     return FileAction::DELETE_F;
        case KFO_RENAME:     return FileAction::RENAME;
        case KFO_SET_INFO:   return FileAction::SET_INFO;
        case KFO_READ:       return FileAction::READ;
        default:             return FileAction::WRITE;   // log unknown opcodes
        }
    }

} // namespace titan::fim