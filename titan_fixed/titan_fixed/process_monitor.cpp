#include "process_monitor.h"

#include <algorithm>
#include <iostream>
#include <sddl.h>
#include <vector>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")

namespace titan {

    // ============================================================================
    // HELPERS — ETW TIMESTAMP CONVERSION
    //
    // ETW timestamps are FILETIME values: 100-nanosecond intervals since
    // 1 January 1601 UTC.  We convert to system_clock::time_point (Unix epoch,
    // 1 January 1970) by subtracting the 116-year offset.
    // ============================================================================

    static std::chrono::system_clock::time_point
        EtwTimestampToTimePoint(uint64_t ts) {
        if (ts == 0)
            return {};

        // Offset between Windows epoch (1601-01-01) and Unix epoch (1970-01-01)
        // in 100-nanosecond intervals.
        constexpr uint64_t kEpochDelta = 116444736000000000ULL;
        if (ts < kEpochDelta)
            return {};  // before Unix epoch — treat as unset

        const uint64_t unix_100ns = ts - kEpochDelta;
        const auto us = std::chrono::microseconds(unix_100ns / 10);
        return std::chrono::system_clock::time_point(us);
    }

    // ============================================================================
    // HELPERS — COMMAND LINE VIA NtQueryInformationProcess
    //
    // Reads the process command line from the target process's PEB without using
    // ToolHelp32 (which is slow and locks the process list).  Requires
    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
    //
    // Falls back to empty string if the process has already exited or we lack
    // the required access.
    // ============================================================================

    static std::wstring QueryCommandLine(DWORD pid) {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess)
            return {};

        // Obtain a pointer to the function at runtime to avoid hard-linking ntdll.
        using NtQIP_t = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG,
            PULONG);
        static auto NtQIP = reinterpret_cast<NtQIP_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                "NtQueryInformationProcess"));
        if (!NtQIP) {
            CloseHandle(hProcess);
            return {};
        }

        // Use ProcessCommandLineInformation (60) — available Windows 8.1+.
        // On older systems this returns STATUS_INVALID_INFO_CLASS; we return ""
        // gracefully.
        constexpr PROCESSINFOCLASS kProcessCommandLineInformation =
            static_cast<PROCESSINFOCLASS>(60);

        ULONG return_length = 0;
        NtQIP(hProcess, kProcessCommandLineInformation,
            nullptr, 0, &return_length);

        // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) or STATUS_BUFFER_TOO_SMALL
        // are expected on the first call — they give us the required size.
        if (return_length == 0) {
            CloseHandle(hProcess);
            return {};
        }

        std::vector<BYTE> buf(return_length);
        NTSTATUS st = NtQIP(hProcess, kProcessCommandLineInformation,
            buf.data(), return_length, &return_length);

        CloseHandle(hProcess);

        if (st != 0)  // Non-zero NTSTATUS = failure
            return {};

        // The returned buffer is a UNICODE_STRING (Length, MaximumLength, Buffer*).
        auto* us = reinterpret_cast<UNICODE_STRING*>(buf.data());
        if (!us->Buffer || us->Length == 0)
            return {};

        // Buffer is a pointer INTO the remote process — we need to copy it here.
        // NtQueryInformationProcess with ProcessCommandLineInformation copies the
        // actual string into the caller-supplied buffer (it's in-process), so
        // us->Buffer is a pointer within buf itself.
        const ULONG char_count = us->Length / sizeof(wchar_t);
        const auto* src = reinterpret_cast<const wchar_t*>(
            buf.data() + sizeof(UNICODE_STRING));

        // Bounds check: ensure the string fits inside the returned buffer.
        if (reinterpret_cast<const BYTE*>(src) + us->Length > buf.data() + buf.size())
            return {};

        return std::wstring(src, static_cast<size_t>(char_count));
    }

    // ============================================================================
    // CONSOLE HELPER — per-event terminal output
    //
    // Prints one compact line per event so operators can watch the live stream.
    // FORWARD = novel event, written to log + shown here.
    // COMPRESS = duplicate suppressed, shown as counter update only.
    // ============================================================================

    static std::string WstrToUtf8Console(const std::wstring& w) {
        if (w.empty()) return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.data(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (n <= 0 || n > 4096) return {};
        std::string s(static_cast<size_t>(n), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(),
            static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
        return s;
    }

    static void PrintEventLine(const char* subtype,
        FilterDecision     decision,
        const V3ProcessInfo& v3)
    {
        std::string name = WstrToUtf8Console(v3.process_name);
        if (name.empty()) name = "(unknown)";

        std::string parent;
        if (!v3.parent_canonical_path.empty()) {
            auto pos = v3.parent_canonical_path.find_last_of(L"\\/");
            parent = WstrToUtf8Console(
                pos != std::wstring::npos
                ? v3.parent_canonical_path.substr(pos + 1)
                : v3.parent_canonical_path);
        }
        if (parent.empty()) parent = "?";

        if (decision == FilterDecision::FORWARD) {
            std::cout
                << "[FWD ] " << subtype
                << " | pid=" << v3.pid
                << " | " << name
                << " <- " << parent
                << " | " << utils::LocationTypeToString(v3.location_type)
                << " | sig=" << (v3.signature_valid ? "Y" : "N")
                << '\n';
        }
        else {
            // COMPRESS — show only when count is a round number to avoid spam
            if (v3.compress_count <= 2 || v3.compress_count % 10 == 0) {
                std::cout
                    << "[CMP ] " << subtype
                    << " | pid=" << v3.pid
                    << " | " << name
                    << " | x" << v3.compress_count
                    << '\n';
            }
        }
    }

    // ============================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ============================================================================

    ProcessMonitor::ProcessMonitor(AsyncLogger& logger, FilterEngine& filter)
        : logger_(logger), filter_(filter) {
    }

    ProcessMonitor::~ProcessMonitor() {
        if (running_.load())
            Stop();
    }

    // ============================================================================
    // START / STOP
    // ============================================================================

    bool ProcessMonitor::Start() {
        if (running_.load())
            return false;

        ConsoleLogger::LogInfo("Starting ProcessMonitor (ETW Kernel-Process)...");

        if (!StartEtwSession()) {
            ConsoleLogger::LogError("Failed to start ETW session");
            return false;
        }

        running_.store(true);
        ConsoleLogger::LogInfo("ProcessMonitor started");
        return true;
    }

    void ProcessMonitor::Stop() {
        if (!running_.load())
            return;

        stop_requested_.store(true);
        StopEtwSession();

        if (consumer_thread_.joinable())
            consumer_thread_.join();

        running_.store(false);
        ConsoleLogger::LogInfo("ProcessMonitor stopped");
    }

    // ============================================================================
    // ETW SESSION LIFECYCLE
    // ============================================================================

    bool ProcessMonitor::StartEtwSession() {
        // FIX C4267: explicit cast from size_t -> ULONG (treated as error under /WX)
        const size_t name_bytes = (session_name_.size() + 1) * sizeof(wchar_t);
        const ULONG buf_size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + name_bytes);

        auto* props =
            reinterpret_cast<EVENT_TRACE_PROPERTIES*>(new char[buf_size]());
        props->Wnode.BufferSize = buf_size;
        props->Wnode.Guid = kKernelProcessGuid;
        props->Wnode.ClientContext = 1;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->FlushTimer = 1;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        auto* name_dest = reinterpret_cast<wchar_t*>(
            reinterpret_cast<char*>(props) + props->LoggerNameOffset);
        wcscpy_s(name_dest, static_cast<rsize_t>(session_name_.size() + 1), session_name_.c_str());

        // Clean up any leftover session from a previous run.
        ControlTraceW(0, session_name_.c_str(), props, EVENT_TRACE_CONTROL_STOP);

        ULONG status = StartTraceW(&session_handle_, session_name_.c_str(), props);
        if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
            ConsoleLogger::LogError("StartTrace failed: " + std::to_string(status));
            delete[] reinterpret_cast<char*>(props);
            return false;
        }

        // FIX: Use explicit keywords so the Kernel-Process provider delivers events.
        //
        //   0x10  WINEVENT_KEYWORD_PROCESS  — ProcessStart / ProcessStop / DCStart
        //   0x20  WINEVENT_KEYWORD_THREAD   — ThreadCreate
        //
        // Previously keyword was 0, which caused NO events to be received and
        // therefore NO log file entries were ever written.
        constexpr ULONG64 kKeywordProcessAndThread = 0x10 | 0x20;

        status = EnableTraceEx2(session_handle_, &kKernelProcessGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            kKeywordProcessAndThread,  // FIX: was 0 (received nothing)
            0, 0, nullptr);
        if (status != ERROR_SUCCESS) {
            ConsoleLogger::LogError("EnableTraceEx2 failed: " +
                std::to_string(status));
            ControlTraceW(session_handle_, session_name_.c_str(), props,
                EVENT_TRACE_CONTROL_STOP);
            delete[] reinterpret_cast<char*>(props);
            return false;
        }

        delete[] reinterpret_cast<char*>(props);

        consumer_thread_ = std::thread([this] {
            EVENT_TRACE_LOGFILEW logfile{};
            logfile.LoggerName = const_cast<wchar_t*>(session_name_.c_str());
            logfile.EventRecordCallback = EtwEventCallback;
            logfile.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

            EtwSessionContext ctx{ this, session_handle_, session_name_ };
            logfile.Context = &ctx;

            consumer_handle_ = OpenTraceW(&logfile);
            if (consumer_handle_ == INVALID_PROCESSTRACE_HANDLE) {
                ConsoleLogger::LogError("OpenTrace failed: " +
                    std::to_string(GetLastError()));
                return;
            }

            ULONG result = ProcessTrace(&consumer_handle_, 1, nullptr, nullptr);
            if (result != ERROR_SUCCESS && result != ERROR_CANCELLED)
                ConsoleLogger::LogError("ProcessTrace error: " +
                    std::to_string(result));

            CloseTrace(consumer_handle_);
            consumer_handle_ = 0;
            });

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    }

    void ProcessMonitor::StopEtwSession() {
        if (!session_handle_)
            return;

        char buf[sizeof(EVENT_TRACE_PROPERTIES) + 256]{};
        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf);
        props->Wnode.BufferSize = sizeof(buf);
        ControlTraceW(session_handle_, session_name_.c_str(), props,
            EVENT_TRACE_CONTROL_STOP);
        session_handle_ = 0;
    }

    // ============================================================================
    // ETW CALLBACK
    // ============================================================================

    void WINAPI ProcessMonitor::EtwEventCallback(PEVENT_RECORD record) {
        auto* ctx = static_cast<EtwSessionContext*>(record->UserContext);
        if (ctx && ctx->monitor) {
            try {
                ctx->monitor->OnProcessEvent(record);
            }
            catch (...) {
            }
        }
    }

    void ProcessMonitor::OnProcessEvent(PEVENT_RECORD record) {
        if (stop_requested_.load())
            return;

        try {
            const BYTE* data = static_cast<const BYTE*>(record->UserData);
            const ULONG  len = record->UserDataLength;
            const uint64_t ts = record->EventHeader.TimeStamp.QuadPart;

            switch (record->EventHeader.EventDescriptor.Id) {
            case kEvtProcessStart:
                HandleProcessStart(data, len, ts);
                break;
            case kEvtProcessStop:
                HandleProcessStop(data, len, ts);
                break;
            case kEvtProcessDCStart:
                HandleProcessDCStart(data, len, ts);
                break;
            case kEvtThreadCreate:
                HandleThreadCreate(data, len, ts);
                break;
            default:
                break;
            }
        }
        catch (...) {
            // Iron Dome: keep agent alive on any bad event
        }
    }

    // ============================================================================
    // HANDLE PROCESS START
    //
    // FIX summary vs original:
    //   1. ETW timestamp ts -> info.create_time (was ignored with /*ts*/)
    //   2. parent binary path stored in info.parent_image_path (not working_directory)
    //   3. command_line populated via QueryCommandLine(NtQIP) (was always empty)
    //   4. user_name populated via LookupAccountSidW (was always empty)
    //   5. is_64bit populated via IsWow64Process (was always false)
    //   6. session_id populated via ProcessIdToSessionId (was always 0)
    //   7. Per-event console output added
    // ============================================================================

    void ProcessMonitor::HandleProcessStart(const BYTE* data, ULONG len,
        uint64_t ts) {
        if (len < 16)
            return;

        const DWORD pid =
            static_cast<DWORD>(*reinterpret_cast<const uint32_t*>(data));
        const DWORD parent_pid =
            static_cast<DWORD>(*reinterpret_cast<const uint32_t*>(data + 4));

        HANDLE hProcess =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        // Also try limited info if full info was denied (e.g. protected process).
        if (!hProcess)
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

        std::wstring image_path = ResolveImagePath(pid);
        std::wstring parent_path = ResolveImagePath(parent_pid);

        // Command line via NtQueryInformationProcess (no ToolHelp32).
        std::wstring cmdline = QueryCommandLine(pid);

        TokenElevation elev = TokenElevation::Unknown;
        IntegrityLevel integ = IntegrityLevel::Unknown;
        std::wstring   sid_str;
        std::wstring   user_name;
        DWORD          real_parent = parent_pid;
        bool           is_64bit = false;
        DWORD          session_id = 0;

        if (hProcess) {
            real_parent = QueryRealParent(hProcess);

            // Architecture — if the process is NOT WoW64 on a 64-bit OS it is 64-bit.
            BOOL is_wow64 = FALSE;
            if (IsWow64Process(hProcess, &is_wow64))
                is_64bit = !is_wow64;

            HANDLE hToken = nullptr;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                elev = QueryElevation(hToken);
                integ = QueryIntegrity(hToken);

                // SID
                DWORD return_len = 0;
                GetTokenInformation(hToken, TokenUser, nullptr, 0, &return_len);
                if (return_len > 0) {
                    std::vector<BYTE> tu_buf(return_len);
                    if (GetTokenInformation(hToken, TokenUser, tu_buf.data(), return_len,
                        &return_len)) {
                        auto* tu = reinterpret_cast<TOKEN_USER*>(tu_buf.data());

                        wchar_t* raw_sid = nullptr;
                        if (ConvertSidToStringSidW(tu->User.Sid, &raw_sid)) {
                            sid_str = raw_sid;
                            LocalFree(raw_sid);
                        }

                        // Username via LookupAccountSidW.
                        wchar_t   name_buf[256]{};
                        wchar_t   domain_buf[256]{};
                        DWORD     name_len = static_cast<DWORD>(std::size(name_buf));
                        DWORD     domain_len = static_cast<DWORD>(std::size(domain_buf));
                        SID_NAME_USE sid_use = SidTypeUnknown;
                        if (LookupAccountSidW(nullptr, tu->User.Sid,
                            name_buf, &name_len,
                            domain_buf, &domain_len, &sid_use)) {
                            user_name = std::wstring(domain_buf) + L"\\" + name_buf;
                        }
                    }
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProcess);
        }

        // Session ID — fast, no handle needed.
        ProcessIdToSessionId(pid, &session_id);

        // ── Build ProcessInfo ──────────────────────────────────────────────────────
        ProcessInfo info;
        info.pid = pid;
        info.parent_pid = parent_pid;
        info.real_parent_pid = real_parent;
        info.image_path = image_path;
        // Store parent binary path in dedicated field, not working_directory.
        info.parent_image_path = parent_path;
        info.working_directory = {};
        info.command_line = cmdline;
        info.user_name = user_name;
        info.user_sid = sid_str;
        info.elevation = elev;
        info.integrity = integ;
        info.is_64bit = is_64bit;
        info.session_id = session_id;
        // Actual process creation time from ETW timestamp.
        info.create_time = EtwTimestampToTimePoint(ts);
        info.log_time = std::chrono::system_clock::now();

        // ── Update accumulator for parent ─────────────────────────────────────────
        {
            std::lock_guard<std::mutex> lock(accum_mutex_);
            auto& parent_acc = accumulators_[parent_pid];
            parent_acc.child_count++;

            std::wstring child_name = image_path;
            auto pos = child_name.find_last_of(L"\\/");
            if (pos != std::wstring::npos)
                child_name = child_name.substr(pos + 1);
            parent_acc.unique_child_names.insert(child_name);

            // Flag children from suspicious locations (raw path heuristic;
            // FilterEngine Stage4 will confirm using canonical path).
            std::wstring pl = image_path;
            std::transform(pl.begin(), pl.end(), pl.begin(), ::towlower);
            if (pl.find(L"\\temp\\") != std::wstring::npos ||
                pl.find(L"\\downloads\\") != std::wstring::npos ||
                pl.find(L"\\desktop\\") != std::wstring::npos) {
                parent_acc.new_child_flag = true;
            }

            // FIX: Store image path in this PID's own accumulator so HandleProcessStop
            // can emit a meaningful process_name even after the process has exited.
            auto& self_acc = accumulators_[pid];
            self_acc.last_image_path = image_path;
            self_acc.last_parent_image_path = parent_path;
            self_acc.last_parent_pid = parent_pid;
        }

        // ── Create and dispatch event ──────────────────────────────────────────────
        auto event = Event::CreateProcessEvent(info, EventSource::EtwKernelProcess);
        EnrichV3Fields(pid, parent_pid, event);

        FilterResult result = filter_.Process(event);
        events_processed_.fetch_add(1, std::memory_order_relaxed);

        // FIX: Print per-event line to terminal for live visibility.
        PrintEventLine("proc_start", result.decision, event.GetV3());

        if (result.decision == FilterDecision::FORWARD) {
            logger_.LogEvent(std::move(event));
            events_forwarded_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            events_compressed_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ============================================================================
    // HANDLE PROCESS STOP
    //
    // FIX: Originally just erased the accumulator and returned — no log event
    //      was ever emitted, so process lifetime was invisible.
    //
    //      Now builds a minimal ProcessInfo for the stopping PID and emits a
    //      ProcessStop event so the detection pipeline can track exit times and
    //      compute process lifetimes.
    // ============================================================================

    void ProcessMonitor::HandleProcessStop(const BYTE* data, ULONG len,
        uint64_t ts) {
        if (len < 4)
            return;
        const DWORD pid = *reinterpret_cast<const uint32_t*>(data);
        const DWORD parent_pid_for_stop = (len >= 8)
            ? *reinterpret_cast<const uint32_t*>(data + 4)
            : 0;

        // FIX: Read cached identity BEFORE erasing the accumulator.
        // ResolveImagePath(pid) almost always returns empty for a stopped process
        // because the kernel has already released the image by the time ETW
        // delivers the stop event.  The accumulator holds the path we recorded
        // when the process started, so we use that instead.
        std::wstring image_path;
        std::wstring parent_path;
        DWORD        effective_parent = parent_pid_for_stop;
        {
            std::lock_guard<std::mutex> lock(accum_mutex_);
            if (auto it = accumulators_.find(pid); it != accumulators_.end()) {
                image_path = it->second.last_image_path;
                parent_path = it->second.last_parent_image_path;
                if (effective_parent == 0)
                    effective_parent = it->second.last_parent_pid;
            }
            accumulators_.erase(pid);
        }

        // Fall back to live query in the unlikely case the process is still alive
        // (e.g. very short-lived processes where stop arrives slightly early).
        if (image_path.empty())
            image_path = ResolveImagePath(pid);

        // Build ProcessInfo for the stop event.
        ProcessInfo info;
        info.pid = pid;
        info.parent_pid = effective_parent;
        info.image_path = image_path;
        info.parent_image_path = parent_path;
        info.create_time = EtwTimestampToTimePoint(ts);
        info.log_time = std::chrono::system_clock::now();
        ProcessIdToSessionId(pid, &info.session_id);

        // Use CreateProcessStopEvent so EventType::ProcessStop is set.
        auto event =
            Event::CreateProcessStopEvent(info, EventSource::EtwKernelProcess);

        // Set exit_time on the V3 struct — the time we received this stop event.
        event.GetV3().exit_time = std::chrono::system_clock::now();

        // Run through filter — stop events usually COMPRESS for known system processes.
        FilterResult result = filter_.Process(event);
        events_processed_.fetch_add(1, std::memory_order_relaxed);

        // Print per-event line to terminal.
        PrintEventLine("proc_stop ", result.decision, event.GetV3());

        if (result.decision == FilterDecision::FORWARD) {
            logger_.LogEvent(std::move(event));
            events_forwarded_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            events_compressed_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ============================================================================
    // HANDLE PROCESS DC START  (processes already running at trace begin)
    //
    // FIX: Was calling HandleProcessStart() which emits EventType::ProcessStart.
    //      DCStart events represent ALREADY-RUNNING processes — they must use
    //      EventType::ProcessSnapshot (CreateProcessSnapshotEvent).
    // ============================================================================

    void ProcessMonitor::HandleProcessDCStart(const BYTE* data, ULONG len,
        uint64_t ts) {
        if (len < 16)
            return;

        const DWORD pid =
            static_cast<DWORD>(*reinterpret_cast<const uint32_t*>(data));
        const DWORD parent_pid =
            static_cast<DWORD>(*reinterpret_cast<const uint32_t*>(data + 4));

        HANDLE hProcess =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess)
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

        std::wstring image_path = ResolveImagePath(pid);
        std::wstring parent_path = ResolveImagePath(parent_pid);
        std::wstring cmdline = QueryCommandLine(pid);

        TokenElevation elev = TokenElevation::Unknown;
        IntegrityLevel integ = IntegrityLevel::Unknown;
        std::wstring   sid_str;
        std::wstring   user_name;
        DWORD          real_parent = parent_pid;
        bool           is_64bit = false;
        DWORD          session_id = 0;

        if (hProcess) {
            real_parent = QueryRealParent(hProcess);

            BOOL is_wow64 = FALSE;
            if (IsWow64Process(hProcess, &is_wow64))
                is_64bit = !is_wow64;

            HANDLE hToken = nullptr;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                elev = QueryElevation(hToken);
                integ = QueryIntegrity(hToken);

                DWORD return_len = 0;
                GetTokenInformation(hToken, TokenUser, nullptr, 0, &return_len);
                if (return_len > 0) {
                    std::vector<BYTE> tu_buf(return_len);
                    if (GetTokenInformation(hToken, TokenUser, tu_buf.data(), return_len,
                        &return_len)) {
                        auto* tu = reinterpret_cast<TOKEN_USER*>(tu_buf.data());
                        wchar_t* raw_sid = nullptr;
                        if (ConvertSidToStringSidW(tu->User.Sid, &raw_sid)) {
                            sid_str = raw_sid;
                            LocalFree(raw_sid);
                        }
                        wchar_t   name_buf[256]{};
                        wchar_t   domain_buf[256]{};
                        DWORD     name_len = static_cast<DWORD>(std::size(name_buf));
                        DWORD     domain_len = static_cast<DWORD>(std::size(domain_buf));
                        SID_NAME_USE sid_use = SidTypeUnknown;
                        if (LookupAccountSidW(nullptr, tu->User.Sid, name_buf, &name_len,
                            domain_buf, &domain_len, &sid_use)) {
                            user_name = std::wstring(domain_buf) + L"\\" + name_buf;
                        }
                    }
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProcess);
        }

        ProcessIdToSessionId(pid, &session_id);

        ProcessInfo info;
        info.pid = pid;
        info.parent_pid = parent_pid;
        info.real_parent_pid = real_parent;
        info.image_path = image_path;
        info.parent_image_path = parent_path;
        info.command_line = cmdline;
        info.user_name = user_name;
        info.user_sid = sid_str;
        info.elevation = elev;
        info.integrity = integ;
        info.is_64bit = is_64bit;
        info.session_id = session_id;
        info.create_time = EtwTimestampToTimePoint(ts);
        info.log_time = std::chrono::system_clock::now();

        {
            std::lock_guard<std::mutex> lock(accum_mutex_);
            auto& parent_acc = accumulators_[parent_pid];
            parent_acc.child_count++;
            std::wstring child_name = image_path;
            auto pos = child_name.find_last_of(L"\\/");
            if (pos != std::wstring::npos)
                child_name = child_name.substr(pos + 1);
            parent_acc.unique_child_names.insert(child_name);

            // FIX: Cache image path for this PID so stop event can identify it.
            auto& self_acc = accumulators_[pid];
            self_acc.last_image_path = image_path;
            self_acc.last_parent_image_path = parent_path;
            self_acc.last_parent_pid = parent_pid;
        }

        // FIX: CreateProcessSnapshotEvent -> EventType::ProcessSnapshot
        auto event =
            Event::CreateProcessSnapshotEvent(info, EventSource::EtwKernelProcess);
        EnrichV3Fields(pid, parent_pid, event);

        FilterResult result = filter_.Process(event);
        events_processed_.fetch_add(1, std::memory_order_relaxed);

        // Print per-event line to terminal (snapshot = already-running at trace start).
        PrintEventLine("proc_snap ", result.decision, event.GetV3());

        if (result.decision == FilterDecision::FORWARD) {
            logger_.LogEvent(std::move(event));
            events_forwarded_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            events_compressed_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ============================================================================
    // HANDLE THREAD CREATE
    // ============================================================================

    void ProcessMonitor::HandleThreadCreate(const BYTE* data, ULONG len,
        uint64_t /*ts*/) {
        if (len < 4)
            return;
        const DWORD pid = *reinterpret_cast<const uint32_t*>(data);

        std::lock_guard<std::mutex> lock(accum_mutex_);
        accumulators_[pid].thread_count++;
    }

    // ============================================================================
    // ENRICH V3 FIELDS
    // ============================================================================

    void ProcessMonitor::EnrichV3Fields(DWORD pid, DWORD parent_pid,
        Event& event) {
        V3ProcessInfo& v3 = event.GetV3();

        std::lock_guard<std::mutex> lock(accum_mutex_);

        // Populate this process's own thread/instance counters.
        if (auto it = accumulators_.find(pid); it != accumulators_.end()) {
            v3.thread_count = it->second.thread_count;
            v3.duplicate_instances = it->second.duplicate_instances;
        }

        // Populate parent's child-spawn summary into this event's V3 fields.
        if (auto it = accumulators_.find(parent_pid); it != accumulators_.end()) {
            v3.child_count = it->second.child_count;
            v3.new_child_flag = it->second.new_child_flag;

            v3.unique_child_names.clear();
            for (const auto& name : it->second.unique_child_names)
                v3.unique_child_names.push_back(name);

            // FIX: Consume new_child_flag after reading it.
            // Without this reset the flag stays true forever on the parent's
            // accumulator, causing every subsequent child of that parent to also
            // appear novel — flooding FORWARD events for known-good processes.
            it->second.new_child_flag = false;
        }
    }

    // ============================================================================
    // STATIC HELPERS
    // ============================================================================

    std::wstring ProcessMonitor::ResolveImagePath(DWORD pid) {
        if (pid <= 4)
            return {};

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h)
            return {};

        wchar_t buf[2048]{};
        DWORD   size = static_cast<DWORD>(std::size(buf));
        std::wstring result;

        if (QueryFullProcessImageNameW(h, 0, buf, &size)) {
            if (size > 0 && size < 32768)
                result.assign(buf, size);
        }

        CloseHandle(h);
        return result;
    }

    DWORD ProcessMonitor::QueryRealParent(HANDLE hProcess) {
        using NtQIP_t = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG,
            PULONG);
        static auto NtQIP = reinterpret_cast<NtQIP_t>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!NtQIP)
            return 0;

        // FIX: winternl.h's public PROCESS_BASIC_INFORMATION uses Reserved3[] and
        // does NOT expose InheritedFromUniqueProcessId by name.  Define our own
        // layout that mirrors the real NT structure so we can read the field safely.
        struct PROCESS_BASIC_INFO_FULL {
            PVOID     ExitStatus;
            PVOID     PebBaseAddress;
            PVOID     AffinityMask;
            PVOID     BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;  // named field — accessible here
        };

        PROCESS_BASIC_INFO_FULL pbi{};
        if (NtQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0)
            return 0;

        return static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
    }

    TokenElevation ProcessMonitor::QueryElevation(HANDLE hToken) {
        TOKEN_ELEVATION_TYPE et{};
        DWORD len = 0;
        if (!GetTokenInformation(hToken, TokenElevationType, &et, sizeof(et), &len))
            return TokenElevation::Unknown;

        switch (et) {
        case TokenElevationTypeFull:    return TokenElevation::Full;
        case TokenElevationTypeLimited: return TokenElevation::Limited;
        default:                        return TokenElevation::Default;
        }
    }

    IntegrityLevel ProcessMonitor::QueryIntegrity(HANDLE hToken) {
        return utils::GetIntegrityFromToken(hToken);
    }

    std::wstring ProcessMonitor::ReadUnicodeString(const BYTE* data, ULONG& offset,
        ULONG len) {
        if (offset + 2 > len)
            return {};
        const auto* str = reinterpret_cast<const wchar_t*>(data + offset);
        size_t n = 0;
        while (offset + (n + 1) * 2 <= len && str[n] != L'\0')
            ++n;
        std::wstring result(str, n);
        offset += static_cast<ULONG>((n + 1) * sizeof(wchar_t));
        return result;
    }

    std::string ProcessMonitor::ReadSidString(const BYTE* data, ULONG& offset,
        ULONG len) {
        if (offset >= len)
            return {};
        auto* psid = reinterpret_cast<PSID>(const_cast<BYTE*>(data + offset));
        if (!IsValidSid(psid))
            return {};
        LPSTR s = nullptr;
        std::string result;
        if (ConvertSidToStringSidA(psid, &s)) {
            result = s;
            LocalFree(s);
        }
        return result;
    }

} // namespace titan