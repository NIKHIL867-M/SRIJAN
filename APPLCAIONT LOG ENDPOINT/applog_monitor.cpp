#include "titan_pch.h"
#include "applog_monitor.h"
#include "applog_etw_collector.h"
#include "applog_event_subscriber.h"
#include "applog_watchlist.h"
#include "applog_decoder.h"
#include "applog_logger.h"

// =============================================================================
// AppLogMonitor
//
// FIXES FROM ORIGINAL:
//   1. Hardcoded log path replaced — path resolved relative to exe location
//   2. ProcessEvent now passes event.timestamp to Decode()
//      → timestamp field populated in every log entry
//   3. OnEventReceived now pushes to a queue instead of calling ProcessEvent
//      directly — ETW callback thread is never blocked by decoder/logger
//   4. Deduplication — identical source+content within 2 seconds dropped
//      → eliminates the flood of duplicate "prompt", "ipconfig" entries
//   5. Stats counter — total events and dropped count on shutdown
// =============================================================================

AppLogMonitor::AppLogMonitor()
    : m_eventCount(0)
    , m_droppedCount(0)
{
    m_decoder = std::make_unique<AppLogDecoder>();
    m_watchlist = std::make_unique<AppLogWatchlist>();
    m_etwCollector = std::make_unique<AppLogEtwCollector>(
        this, m_watchlist.get());
    m_eventSubscriber = std::make_unique<AppLogEventSubscriber>(this);
}

AppLogMonitor::~AppLogMonitor() {
    Stop();
}

// ─── Start ───────────────────────────────────────────────────────────────────

bool AppLogMonitor::Start() {
    if (m_running.load()) return true;

    // FIXED: resolve log path relative to exe — not hardcoded username
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string logDir(exePath);
    auto slash = logDir.find_last_of("\\/");
    if (slash != std::string::npos)
        logDir = logDir.substr(0, slash);
    std::string logPath = logDir + "\\titan_applog.json";

    AppLogLogger::Instance().Init(logPath);

    m_running.store(true);

    // Start worker thread BEFORE ETW/WEL so queue is ready
    m_workerThread = std::thread([this]() { WorkerThreadFunc(); });

    if (!m_etwCollector->Start()) {
        std::cerr << "[AppLogMonitor] ETW failed — activating fallback.\n";
        m_eventSubscriber->EnableFallbackMode(true);
    }

    if (!m_eventSubscriber->Start()) {
        std::cerr << "[AppLogMonitor] Event subscriber failed.\n";
        m_running.store(false);
        m_queueCv.notify_all();
        if (m_workerThread.joinable()) m_workerThread.join();
        return false;
    }

    m_monitorThread = std::thread([this]() { MonitorThreadFunc(); });

    std::cout << "[AppLogMonitor] Started. Log: " << logPath << "\n";
    return true;
}

// ─── Stop ────────────────────────────────────────────────────────────────────

void AppLogMonitor::Stop() {
    if (!m_running.load()) return;
    m_running.store(false);

    m_etwCollector->Stop();
    m_eventSubscriber->Stop();

    // Wake worker thread so it can drain and exit
    m_queueCv.notify_all();

    if (m_workerThread.joinable())  m_workerThread.join();
    if (m_monitorThread.joinable()) m_monitorThread.join();

    AppLogLogger::Instance().Shutdown();

    std::cout << "[AppLogMonitor] Stopped."
        << " Events captured: " << m_eventCount.load()
        << "  Deduped/dropped: " << m_droppedCount.load() << "\n";
}

// ─── OnEventReceived — called from ETW/WEL threads ───────────────────────────
// Must be fast. Pushes to queue and returns immediately.

void AppLogMonitor::OnEventReceived(AppLogEvent event) {
    if (!m_running.load()) return;

    {
        std::lock_guard<std::mutex> lock(m_queueMutex);

        // Deduplication: drop if same source+content seen in last 2 seconds
        auto now = std::chrono::steady_clock::now();
        std::string dedupKey = event.source + "|"
            + event.raw_data.substr(0, std::min<size_t>(100, event.raw_data.size()));

        auto it = m_recentKeys.find(dedupKey);
        if (it != m_recentKeys.end()) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second).count();
            if (age < 2) {
                m_droppedCount++;
                return;
            }
        }
        m_recentKeys[dedupKey] = now;

        // Backpressure: cap queue depth
        if (m_eventQueue.size() >= 4096)
            m_eventQueue.pop();  // drop oldest

        m_eventQueue.push(std::move(event));
    }
    m_queueCv.notify_one();
}

// ─── Worker thread — drains queue, decodes, logs ─────────────────────────────

void AppLogMonitor::WorkerThreadFunc() {
    while (true) {
        AppLogEvent event;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCv.wait(lock, [this] {
                return !m_eventQueue.empty() || !m_running.load();
                });

            if (!m_running.load() && m_eventQueue.empty()) break;
            if (m_eventQueue.empty()) continue;

            event = std::move(m_eventQueue.front());
            m_eventQueue.pop();
        }

        try { ProcessEvent(event); }
        catch (...) {}
    }

    // Drain any remaining events on shutdown
    std::lock_guard<std::mutex> lock(m_queueMutex);
    while (!m_eventQueue.empty()) {
        try { ProcessEvent(m_eventQueue.front()); }
        catch (...) {}
        m_eventQueue.pop();
    }
}

// ─── Coordinator thread ───────────────────────────────────────────────────────

void AppLogMonitor::MonitorThreadFunc() {
    auto lastStats = std::chrono::steady_clock::now();
    auto lastCleanup = std::chrono::steady_clock::now();

    while (m_running.load()) {
        // Refresh watched process PIDs every 5 seconds
        m_watchlist->RefreshPIDs();
        m_etwCollector->UpdatePIDFilter(m_watchlist->GetActivePIDs());

        auto now = std::chrono::steady_clock::now();

        // Print stats every 60 seconds
        if (std::chrono::duration_cast<std::chrono::seconds>(
            now - lastStats).count() >= 60)
        {
            lastStats = now;
            std::cout << "[AppLogMonitor] Stats — captured: "
                << m_eventCount.load()
                << "  deduped: " << m_droppedCount.load() << "\n";
        }

        // Clean up old dedup keys every 30 seconds
        if (std::chrono::duration_cast<std::chrono::seconds>(
            now - lastCleanup).count() >= 30)
        {
            lastCleanup = now;
            CleanupDedupCache();
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

// ─── ProcessEvent — called on worker thread only ─────────────────────────────

void AppLogMonitor::ProcessEvent(AppLogEvent& event) {
    // FIXED: pass event.timestamp to decoder — appears in JSON output
    event.decoded_json = m_decoder->Decode(
        event.source,
        event.raw_data,
        event.timestamp   // ← this is the fix
    );

    m_eventCount++;
    LogEvent(event);
}

void AppLogMonitor::LogEvent(const AppLogEvent& event) const {
    std::cout << "[" << event.timestamp << "] "
        << "[" << event.source << "] "
        << "ID=" << event.event_id << "\n"
        << event.decoded_json << "\n"
        << std::string(60, '-') << "\n";

    AppLogLogger::Instance().Write(event.decoded_json);
}

// ─── Dedup cache cleanup ──────────────────────────────────────────────────────

void AppLogMonitor::CleanupDedupCache() {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    auto now = std::chrono::steady_clock::now();
    for (auto it = m_recentKeys.begin(); it != m_recentKeys.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second).count();
        it = (age > 10) ? m_recentKeys.erase(it) : ++it;
    }
}

// ─── Watchlist API ────────────────────────────────────────────────────────────

void AppLogMonitor::AddToWatchlist(const std::string& appName) {
    m_watchlist->Add(appName);
}

void AppLogMonitor::RemoveFromWatchlist(const std::string& appName) {
    m_watchlist->Remove(appName);
}

void AppLogMonitor::PrintWatchlist() const {
    auto entries = m_watchlist->GetAll();
    if (entries.empty()) { std::cout << "[Watchlist] Empty.\n"; return; }

    std::cout << "\n[Watchlist] " << entries.size() << " app(s):\n";
    for (const auto& e : entries) {
        std::cout << "  - " << e.appName;
        if (e.active) {
            std::cout << "  [RUNNING, PIDs: ";
            for (DWORD pid : e.pids) std::cout << pid << " ";
            std::cout << "]";
        }
        else {
            std::cout << "  [not running]";
        }
        std::cout << "\n";
    }
}