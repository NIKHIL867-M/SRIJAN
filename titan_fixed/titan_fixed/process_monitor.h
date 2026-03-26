#ifndef TITAN_PROCESS_MONITOR_H
#define TITAN_PROCESS_MONITOR_H

// ============================================================================
// process_monitor.h  —  TITAN V3  Enriched Sensor
//
// Responsibilities:
//   1. Open an ETW real-time session on the Kernel-Process provider.
//   2. For every process-start event, resolve the TRUE binary path via
//      QueryFullProcessImageNameW (kernel path, not ETW-reported string).
//   3. Resolve the PARENT's canonical path via the same API so the filter
//      can evaluate parent-child relationships (Rule 10, bloom filter).
//   4. Populate fork/thread summary fields in V3ProcessInfo:
//        child_count, unique_child_names, thread_count,
//        duplicate_instances, new_child_flag
//   5. Pass the enriched Event to FilterEngine::Process().
//   6. If decision == FORWARD  → logger_.LogEvent()
//      If decision == COMPRESS → counter only (ticker handles the summary)
//
// V3 changes vs V2:
//   REMOVED: FilterAction::Drop path, events_dropped_ counter, Evaluate()
//   ADDED:   EnrichV3Fields(), parent path resolution, fork/thread tracking,
//            GetEventsForwarded(), GetEventsCompressed()
// ============================================================================

#include "event.h"
#include "filter.h"
#include "logger.h"

#include <atomic>
#include <evntcons.h>
#include <evntrace.h>
#include <mutex>
#include <string>
#include <thread>
#include <set>
#include <unordered_map>
#include <windows.h>

namespace titan {

    class ProcessMonitor;

    // ETW callback context
    struct EtwSessionContext {
        ProcessMonitor* monitor;
        TRACEHANDLE session_handle;
        std::wstring session_name;
    };

    // Per-PID fork/thread accumulator — updated on every child-spawn /
    // thread-create event. Cleared when the parent process terminates.
    struct ProcessAccumulator {
        uint32_t child_count{ 0 };
        std::set<std::wstring> unique_child_names;
        uint32_t thread_count{ 0 };
        uint32_t duplicate_instances{ 0 };
        bool new_child_flag{ false };

        // FIX: Cache the last known image path so HandleProcessStop can emit a
        // useful process_name even after the process has already exited and
        // ResolveImagePath(pid) returns empty.
        std::wstring last_image_path;
        std::wstring last_parent_image_path;
        DWORD        last_parent_pid{ 0 };
    };

    // ============================================================================
    // PROCESS MONITOR
    // ============================================================================

    class ProcessMonitor {
    public:
        explicit ProcessMonitor(AsyncLogger& logger, FilterEngine& filter);
        ~ProcessMonitor();

        ProcessMonitor(const ProcessMonitor&) = delete;
        ProcessMonitor& operator=(const ProcessMonitor&) = delete;

        bool Start();
        void Stop();
        bool IsRunning() const noexcept { return running_.load(); }

        // V3 pipeline counters (replaces events_dropped_)
        uint64_t GetEventsProcessed() const noexcept {
            return events_processed_.load();
        }
        uint64_t GetEventsForwarded() const noexcept {
            return events_forwarded_.load();
        }
        uint64_t GetEventsCompressed() const noexcept {
            return events_compressed_.load();
        }

    private:
        // ETW session lifecycle
        bool StartEtwSession();
        void StopEtwSession();

        // ETW callback (static, routes to instance method)
        static void WINAPI EtwEventCallback(PEVENT_RECORD record);

        // Event dispatch
        void OnProcessEvent(PEVENT_RECORD record);

        // Per-event-type handlers
        void HandleProcessStart(const BYTE* data, ULONG len, uint64_t ts);
        void HandleProcessStop(const BYTE* data, ULONG len, uint64_t ts);
        void HandleProcessDCStart(const BYTE* data, ULONG len, uint64_t ts);
        void HandleThreadCreate(const BYTE* data, ULONG len, uint64_t ts);

        // Enrichment: resolve parent canonical path and populate V3ProcessInfo
        // fork/thread summary fields from the per-PID accumulator.
        // NOTE: not const — consumes new_child_flag after reading it.
        void EnrichV3Fields(DWORD pid, DWORD parent_pid, Event& event);

        // Resolve real binary path from kernel via QueryFullProcessImageNameW.
        // Returns empty string on failure.
        static std::wstring ResolveImagePath(DWORD pid);

        // Helpers
        static IntegrityLevel QueryIntegrity(HANDLE hToken);
        static TokenElevation QueryElevation(HANDLE hToken);
        static DWORD QueryRealParent(HANDLE hProcess);
        static std::wstring ReadUnicodeString(const BYTE* data, ULONG& offset,
            ULONG len);
        static std::string ReadSidString(const BYTE* data, ULONG& offset, ULONG len);

        // Members
        AsyncLogger& logger_;
        FilterEngine& filter_;

        TRACEHANDLE session_handle_{ 0 };
        TRACEHANDLE consumer_handle_{ 0 };
        std::wstring session_name_{ L"TitanProcessSession" };
        std::thread consumer_thread_;

        std::atomic<bool> running_{ false };
        std::atomic<bool> stop_requested_{ false };

        // Per-PID fork/thread accumulators (guarded by accum_mutex_)
        mutable std::mutex accum_mutex_;
        std::unordered_map<DWORD, ProcessAccumulator> accumulators_;

        // V3 counters
        std::atomic<uint64_t> events_processed_{ 0 };
        std::atomic<uint64_t> events_forwarded_{ 0 };
        std::atomic<uint64_t> events_compressed_{ 0 };

        // ETW provider GUID: Microsoft-Windows-Kernel-Process
        static constexpr GUID kKernelProcessGuid = {
            0x22FB2CD6,
            0x0E7B,
            0x422B,
            {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16} };

        // ETW event IDs
        static constexpr uint16_t kEvtProcessStart = 1;
        static constexpr uint16_t kEvtProcessStop = 2;
        static constexpr uint16_t kEvtProcessDCStart = 3;
        static constexpr uint16_t kEvtThreadCreate = 5;
    };

} // namespace titan

#endif // TITAN_PROCESS_MONITOR_H