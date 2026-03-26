#include "file_monitor.h"

// =============================================================================
// TITAN - File Integrity Monitor
// file_monitor.cpp
//
// FIXES IN THIS VERSION (on top of previous round):
//
// FIX A — Empty path silent drop:
//   ETW WRITE/CLOSE events often carry no FileName — only FileKey. When the
//   FileKey→path cache lookup misses, the path stays L"". ClassifyEvent("")
//   returns DROP, so the event vanishes before FileProcessor ever sees it.
//   Fix: DispatchEvent now normalises L"" and L"unknown" to L"unresolved"
//   before calling ClassifyEvent. ClassifyEvent routes non-empty paths
//   normally; "unresolved" reaches FileProcessor as Bucket C and is logged.
//
// FIX B — MonitorLoop single-event-per-wakeup bottleneck:
//   The previous loop woke up, dequeued exactly ONE event, processed it,
//   then went back to sleep for up to 500ms. Under any sustained activity
//   the queue would grow without bound (capped at 8192 with drop-on-full)
//   because the consumer was far slower than the producer.
//   Fix: each wakeup drains the ENTIRE queue before sleeping. One lock
//   acquisition takes all pending events; they are processed outside the lock.
//   This keeps queue depth near zero under normal load.
//
// All other logic (ResolveLogPath, Stop, SubmitEvent, maintenance) unchanged.
// =============================================================================

#include "_file_scope.h"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <psapi.h>

namespace titan::fim
{

    FileMonitor::FileMonitor()
        : running_(false)
        , last_maintenance_(std::chrono::steady_clock::now())
    {
        logger_ = std::make_unique<FileLogger>();
        processor_ = std::make_unique<FileProcessor>();
    }

    FileMonitor::~FileMonitor()
    {
        Stop();
    }

    // =========================================================================
    // ResolveLogPath
    // If log_path is already absolute use it verbatim.
    // If relative, anchor it to the exe's own directory so logs always land
    // next to the binary regardless of Visual Studio's working directory setting.
    // =========================================================================
    static std::wstring ResolveLogPath(const std::wstring& log_path)
    {
        std::filesystem::path p(log_path);

        if (p.is_absolute())
            return log_path;

        wchar_t exe_buf[MAX_PATH * 2] = {};
        DWORD   exe_len = GetModuleFileNameW(nullptr, exe_buf, MAX_PATH * 2);

        if (exe_len == 0 || exe_len >= MAX_PATH * 2)
        {
            std::wcerr << L"[FIM][Monitor] Warning: cannot resolve exe path, "
                L"using log_path as-is\n";
            return log_path;
        }

        std::filesystem::path exe_dir =
            std::filesystem::path(exe_buf).parent_path();

        return (exe_dir / p).wstring();
    }

    // =========================================================================
    // Start
    // =========================================================================
    bool FileMonitor::Start(const std::wstring& log_path)
    {
        if (running_) return false;

        std::wstring abs_log_path = ResolveLogPath(log_path);

        std::wcout << L"[FIM][Monitor] Log: " << abs_log_path << L"\n";

        if (!logger_->Initialize(abs_log_path))
        {
            std::cerr << "[FIM][Monitor] Failed to initialize logger\n";
            return false;
        }

        if (!processor_->Initialize(logger_.get()))
        {
            std::cerr << "[FIM][Monitor] Failed to initialize processor\n";
            return false;
        }

        tracker_ = std::make_unique<TempTracker>(logger_.get());

        // Startup entry — proves logger + flush are working
        std::string startup =
            std::string("{\"endpoint\":\"file_integrity\"")
            + ",\"action\":\"startup\""
            + ",\"path\":\"TITAN_FIM_started\""
            + ",\"pid\":0,\"tid\":0"
            + ",\"process\":\"file_test.exe\""
            + ",\"timestamp\":\"startup\""
            + ",\"protected\":false"
            + ",\"executable\":false"
            + ",\"document\":false"
            + "}";
        logger_->Log(startup, LogSeverity::INFO);

        running_ = true;
        monitor_thread_ = std::thread(&FileMonitor::MonitorLoop, this);

        std::cout << "[FIM][Monitor] Started — watching all file activity\n";
        return true;
    }

    // =========================================================================
    // Stop
    // =========================================================================
    void FileMonitor::Stop()
    {
        if (!running_) return;

        running_ = false;
        queue_cv_.notify_all();

        if (monitor_thread_.joinable())
            monitor_thread_.join();

        if (logger_) logger_->Flush();

        std::cout << "[FIM][Monitor] Stopped\n";
    }

    // =========================================================================
    // SubmitEvent — called from ETW thread (must be fast, non-blocking)
    // =========================================================================
    void FileMonitor::SubmitEvent(const FileEvent& event)
    {
        if (!running_) return;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (event_queue_.size() >= MAX_EVENT_QUEUE_DEPTH)
                event_queue_.pop();
            event_queue_.push(event);
        }

        queue_cv_.notify_one();
    }

    // =========================================================================
    // DispatchEvent
    //
    // FIX A: Normalise empty / "unknown" paths to L"unresolved" BEFORE calling
    // ClassifyEvent. ClassifyEvent drops empty paths, so without this fix every
    // WRITE/CLOSE event whose FileKey→path cache lookup missed was silently
    // discarded. Now those events reach FileProcessor as Bucket C and are
    // logged with path="unresolved".
    // =========================================================================
    void FileMonitor::DispatchEvent(const FileEvent& event)
    {
        // FIX A: work on a local copy so the original queue entry is unchanged
        FileEvent ev = event;
        if (ev.path.empty() || ev.path == L"unknown")
            ev.path = L"unresolved";

        EventBucket bucket = ClassifyEvent(ev.path);

        // Dynamic high-churn rerouting (Bucket C → B when dir is churning)
        if (bucket == EventBucket::C && tracker_)
        {
            std::filesystem::path fp(ev.path);
            std::wstring dir = fp.has_parent_path()
                ? fp.parent_path().wstring()
                : ev.path;
            if (tracker_->IsHighChurnDirectory(dir))
                bucket = EventBucket::B;
        }

        switch (bucket)
        {
        case EventBucket::DROP:
            return; // only truly unresolvable events

        case EventBucket::A:
            if (processor_) processor_->ProcessEvent(ev);
            break;

        case EventBucket::B:
            if (tracker_)
            {
                bool elevated = tracker_->TrackEvent(ev);
                if (elevated && processor_)
                    processor_->ProcessEvent(ev);
            }
            break;

        case EventBucket::C:
            if (processor_) processor_->ProcessEvent(ev);
            break;
        }
    }

    // =========================================================================
    // MonitorLoop
    //
    // FIX B: Batch drain — each wakeup takes ALL pending events out of the
    // queue in a single lock acquisition, then processes them outside the lock.
    //
    // Previous behaviour: dequeue ONE event per wakeup, sleep up to 500ms,
    // repeat. With ETW firing hundreds of events per second the queue would
    // grow to 8192 and start dropping events. Consumer latency was up to 500ms
    // per event.
    //
    // New behaviour: wake up when any event arrives, grab everything in the
    // queue at once, release the lock, process the batch. Queue depth stays
    // near zero under normal load. Processing is still single-threaded
    // (no lock contention on map_mutex_ inside FileProcessor).
    // =========================================================================
    void FileMonitor::MonitorLoop()
    {
        while (running_.load())
        {
            // ---------------------------------------------------------------
            // FIX B: Drain the entire queue under one lock acquisition.
            // ---------------------------------------------------------------
            std::vector<FileEvent> batch;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait_for(
                    lock,
                    std::chrono::milliseconds(500),
                    [this]() -> bool {
                        return !event_queue_.empty() || !running_.load();
                    }
                );

                // Take everything that arrived while we were waiting
                batch.reserve(event_queue_.size());
                while (!event_queue_.empty())
                {
                    batch.push_back(event_queue_.front());
                    event_queue_.pop();
                }
            } // lock released — ETW thread can keep submitting

            // Process the batch outside the lock
            for (const auto& ev : batch)
            {
                try { DispatchEvent(ev); }
                catch (...) {}
            }

            // Periodic maintenance (every 30 s)
            auto now = std::chrono::steady_clock::now();
            if (now - last_maintenance_ >= std::chrono::seconds(30))
            {
                last_maintenance_ = now;
                try
                {
                    if (processor_) processor_->CleanupStaleEntries();
                    if (tracker_)   tracker_->Maintenance();
                    if (logger_)    logger_->Flush();
                }
                catch (...) {}
            }
        }

        // Final drain — process everything left in the queue on shutdown
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            while (!event_queue_.empty())
            {
                try { DispatchEvent(event_queue_.front()); }
                catch (...) {}
                event_queue_.pop();
            }
        }

        if (logger_) logger_->Flush();
    }

} // namespace titan::fim