#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// file_monitor.h
//
// FileMonitor is the central coordinator.
// It owns the event queue, FileProcessor (Bucket A/C), and TempTracker (Bucket B).
//
// ROUTING in MonitorLoop:
//   BUCKET_DROP → discard immediately
//   BUCKET_A    → FileProcessor::ProcessEvent()
//   BUCKET_B    → TempTracker::TrackEvent()
//                 if TrackEvent returns true (elevated) → also log via processor
//   BUCKET_C    → FileProcessor::ProcessEvent()
//
// Additionally: any directory showing high-churn behaviour is dynamically
// reclassified to Bucket B even if not in GetKnownTempPaths().
// =============================================================================

#include <atomic>
#include <thread>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "file_processor.h"
#include "file_logger.h"
#include "file_tracker.h"
#include "_file_scope.h"

namespace titan::fim
{

    static constexpr size_t MAX_EVENT_QUEUE_DEPTH = 8192;

    class FileMonitor
    {
    public:

        FileMonitor();
        ~FileMonitor();

        bool Start(const std::wstring& log_path = L"logs\\fim_events.json");
        void Stop();

        // Called by ETW collector — thread safe, non-blocking
        void SubmitEvent(const FileEvent& event);

        FileLogger* GetLogger() { return logger_.get(); }

    private:

        std::unique_ptr<FileLogger>    logger_;
        std::unique_ptr<FileProcessor> processor_;
        std::unique_ptr<TempTracker>   tracker_;

        std::queue<FileEvent>          event_queue_;
        std::mutex                     queue_mutex_;
        std::condition_variable        queue_cv_;

        std::atomic<bool>              running_;
        std::thread                    monitor_thread_;

        void MonitorLoop();
        void DispatchEvent(const FileEvent& event);

        std::chrono::steady_clock::time_point last_maintenance_;
    };

} // namespace titan::fim