#include "agent.h"

#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <thread>
#include <windows.h>

namespace titan {

    // ============================================================================
    // GLOBAL SIGNAL HANDLER
    // ============================================================================

    static Agent* g_agent = nullptr;

    static void SignalHandler(int) {
        if (g_agent)
            g_agent->Stop();
    }

    // ============================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ============================================================================

    Agent::Agent() = default;

    Agent::~Agent() { Stop(); }

    // ============================================================================
    // ADMIN PRIVILEGE CHECK
    // ============================================================================

    bool Agent::CheckAdminPrivileges() {
        BOOL is_admin = FALSE;
        PSID administrators_group = nullptr;

        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
            &administrators_group)) {
            CheckTokenMembership(nullptr, administrators_group, &is_admin);
            FreeSid(administrators_group);
        }

        return is_admin == TRUE;
    }

    // ============================================================================
    // PRE-WARM CACHES
    // ============================================================================

    bool Agent::PreWarmCaches() {
        ConsoleLogger::LogInfo("Pre-warming O(1) caches...");

        if (!filter_) {
            ConsoleLogger::LogError("Filter not initialized");
            return false;
        }

        // Derive bloom filter persistence directory alongside the log directory.
        // e.g. if log_path_ = ".\logs\" then bloom_dir_ = ".\logs\bloom\"
        std::wstring bloom_dir = log_path_ + L"bloom\\";

        // Initialize all fixed data structures (builds known root set, DLL set,
        // loads persisted bloom filters from disk).
        if (!filter_->Initialize(bloom_dir)) {
            ConsoleLogger::LogError("Failed to initialize filter caches");
            return false;
        }

        ConsoleLogger::LogInfo("Caches pre-warmed successfully");
        return true;
    }

    // ============================================================================
    // INITIALIZE
    // ============================================================================

    bool Agent::Initialize(const std::wstring& log_path) {
        if (initialized_)
            return true;

        log_path_ = log_path;
        if (!log_path_.empty() && log_path_.back() != L'\\' && log_path_.back() != L'/') {
            log_path_ += L'\\';
        }

        ConsoleLogger::LogInfo("Initializing TITAN V3.0 Agent...");
        ConsoleLogger::LogInfo("Signal Amplifier + Noise Suppressor");
        ConsoleLogger::LogInfo("Fixed RAM: ~1.3MB | No scoring | No detection");

        // --------------------------------------------------------
        // Admin Check
        // --------------------------------------------------------

        if (!CheckAdminPrivileges()) {
            ConsoleLogger::LogError("Administrator privileges required");
            ConsoleLogger::LogError("Please run as Administrator");
            return false;
        }

        ConsoleLogger::LogInfo("Administrator privileges confirmed");

        // --------------------------------------------------------
        // Logger
        // --------------------------------------------------------

        logger_ = std::make_unique<AsyncLogger>(log_path_);

        if (!logger_->Initialize()) {
            ConsoleLogger::LogError("Failed to initialize logger");
            return false;
        }

        // --------------------------------------------------------
        // Filter Engine (V3.0 - Signal Amplifier)
        // --------------------------------------------------------

        filter_ = std::make_unique<FilterEngine>();

        // Ensure bloom filter persistence directory exists before pre-warming.
        std::filesystem::create_directories(
            std::filesystem::path(log_path_ + L"bloom\\"));

        if (!PreWarmCaches()) {
            ConsoleLogger::LogError("Failed to pre-warm caches");
            return false;
        }

        // --------------------------------------------------------
        // Process Monitor (Enriched Sensor)
        // --------------------------------------------------------

        process_monitor_ = std::make_unique<ProcessMonitor>(*logger_, *filter_);

        // Wire the filter into the logger so the compress ticker can reach it
        logger_->SetFilter(filter_.get());

        initialized_ = true;

        ConsoleLogger::LogInfo("TITAN V3.0 Agent initialized successfully");
        ConsoleLogger::LogInfo("Ready for process event stream processing");

        return true;
    }

    // ============================================================================
    // START
    // ============================================================================

    bool Agent::Start() {
        if (!initialized_) {
            ConsoleLogger::LogError("Agent not initialized");
            return false;
        }

        if (running_)
            return true;

        ConsoleLogger::LogInfo("Starting TITAN V3.0 Agent...");

        if (!process_monitor_->Start()) {
            ConsoleLogger::LogError("Failed to start process monitor");
            return false;
        }

        running_ = true;

        g_agent = this;

        // --------------------------------------------------------
        // SIGNAL HANDLING
        // --------------------------------------------------------

        std::signal(SIGINT, SignalHandler);
        std::signal(SIGTERM, SignalHandler);

        ConsoleLogger::LogInfo("TITAN V3.0 Agent running. Press Ctrl+C to stop.");
        ConsoleLogger::LogInfo("Output: FORWARD (novel) | COMPRESS (redundant)");

        // --------------------------------------------------------
        // MAIN LOOP
        // --------------------------------------------------------

        int counter = 0;

        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (++counter >= 10) {
                PrintStatus();
                counter = 0;
            }
        }

        return true;
    }

    // ============================================================================
    // STOP
    // ============================================================================

    void Agent::Stop() {
        if (!running_)
            return;

        ConsoleLogger::LogInfo("Stopping TITAN V3.0 Agent...");

        running_ = false;

        if (process_monitor_)
            process_monitor_->Stop();

        if (logger_)
            logger_->Shutdown();

        // FilterEngine cleans up in its destructor — no explicit Shutdown() needed

        ConsoleLogger::LogInfo("TITAN V3.0 Agent stopped");
    }

    // ============================================================================
    // STATUS (V3.0 - Compression Stats)
    // ============================================================================

    void Agent::PrintStatus() const {
        if (!process_monitor_ || !logger_ || !filter_)
            return;

        const uint64_t total = filter_->GetTotalSeen();
        const uint64_t forwarded = filter_->GetForwardedCount();
        const uint64_t compressed = filter_->GetCompressedCount();
        const uint64_t ratio = total > 0 ? (compressed * 100) / total : 0;

        std::cout << "[STATUS]"
            << " Events: " << total << " | Fwd: " << forwarded
            << " | Cmp: " << compressed << " | Ratio: " << ratio << "%"
            << " | Q: " << logger_->GetQueuedCount() << std::endl;
    }

} // namespace titan