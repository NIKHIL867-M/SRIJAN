#pragma once
#include "titan_pch.h"
#include <queue>
#include <condition_variable>
#include <unordered_map>

class AppLogEtwCollector;
class AppLogEventSubscriber;
class AppLogWatchlist;
class AppLogDecoder;

struct AppLogEvent {
    std::string source;
    std::string event_id;
    std::string timestamp;
    std::string raw_data;
    std::string decoded_json;
};

class AppLogMonitor {
public:
    AppLogMonitor();
    ~AppLogMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Called from ETW/WEL threads — thread safe, non-blocking
    void OnEventReceived(AppLogEvent event);

    void AddToWatchlist(const std::string& appName);
    void RemoveFromWatchlist(const std::string& appName);
    void PrintWatchlist() const;

private:
    void WorkerThreadFunc();
    void MonitorThreadFunc();
    void ProcessEvent(AppLogEvent& event);
    void LogEvent(const AppLogEvent& event) const;
    void CleanupDedupCache();

    std::atomic<bool> m_running{ false };
    std::thread       m_monitorThread;
    std::thread       m_workerThread;

    // Event queue
    std::queue<AppLogEvent>  m_eventQueue;
    std::mutex               m_queueMutex;
    std::condition_variable  m_queueCv;

    // Deduplication
    std::unordered_map<std::string,
        std::chrono::steady_clock::time_point> m_recentKeys;

    // Stats
    std::atomic<uint64_t> m_eventCount{ 0 };
    std::atomic<uint64_t> m_droppedCount{ 0 };

    std::unique_ptr<AppLogEtwCollector>    m_etwCollector;
    std::unique_ptr<AppLogEventSubscriber> m_eventSubscriber;
    std::unique_ptr<AppLogWatchlist>       m_watchlist;
    std::unique_ptr<AppLogDecoder>         m_decoder;
};