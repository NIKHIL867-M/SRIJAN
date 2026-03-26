#include "agent.h"

#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

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
        if (!filter_->Initialize()) {
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

        ConsoleLogger::LogInfo("Initializing TITAN V4 Network Agent...");
        ConsoleLogger::LogInfo("Signal Amplifier + Noise Suppressor");
        ConsoleLogger::LogInfo("Fixed RAM: ~1.3MB | No scoring | No detection");

        if (!CheckAdminPrivileges()) {
            ConsoleLogger::LogError("Administrator privileges required");
            ConsoleLogger::LogError("Please run as Administrator");
            return false;
        }
        ConsoleLogger::LogInfo("Administrator privileges confirmed");

        // Logger
        logger_ = std::make_unique<AsyncLogger>(log_path_);
        if (!logger_->Initialize()) {
            ConsoleLogger::LogError("Failed to initialize logger");
            return false;
        }

        // Filter Engine
        filter_ = std::make_unique<FilterEngine>();
        if (!PreWarmCaches()) {
            ConsoleLogger::LogError("Failed to pre-warm caches");
            return false;
        }

        // Network Monitor (Npcap — required)
        network_monitor_ = std::make_unique<NetworkMonitor>(*logger_, *filter_);

        // Wire the filter into the logger for the compress ticker
        logger_->SetFilter(filter_.get());

        initialized_ = true;
        ConsoleLogger::LogInfo("TITAN V4 Network Agent initialized successfully");
        ConsoleLogger::LogInfo("Ready: Npcap deep-packet capture active");
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

        ConsoleLogger::LogInfo("Starting TITAN V4 Network Agent...");

        if (!network_monitor_->Start()) {
            ConsoleLogger::LogError("Failed to start network monitor — is Npcap installed?");
            return false;
        }

        running_ = true;
        g_agent = this;

        std::signal(SIGINT, SignalHandler);
        std::signal(SIGTERM, SignalHandler);

        ConsoleLogger::LogInfo("TITAN V4 running. Press Ctrl+C to stop.");
        ConsoleLogger::LogInfo("Output: FORWARD (novel) | COMPRESS (redundant)");

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

        ConsoleLogger::LogInfo("Stopping TITAN V4 Network Agent...");
        running_ = false;

        if (network_monitor_)
            network_monitor_->Stop();

        if (logger_)
            logger_->Shutdown();

        ConsoleLogger::LogInfo("TITAN V4 Network Agent stopped");
    }

    // ============================================================================
    // STATUS
    // ============================================================================

    void Agent::PrintStatus() const {
        if (!network_monitor_ || !logger_ || !filter_)
            return;

        const uint64_t total = filter_->GetTotalSeen();
        const uint64_t forwarded = filter_->GetForwardedCount();
        const uint64_t compressed = filter_->GetCompressedCount();
        const uint64_t ratio = total > 0 ? (compressed * 100) / total : 0;

        std::cout << "[STATUS]"
            << " Events: " << total
            << " | Fwd: " << forwarded
            << " | Cmp: " << compressed
            << " | Ratio: " << ratio << "%"
            << " | Q: " << logger_->GetQueuedCount()
            << " | Pkts: " << network_monitor_->GetPacketsCaptured()
            << " | NetFwd: " << network_monitor_->GetFlowsForwarded()
            << " | NetCmp: " << network_monitor_->GetFlowsCompressed()
            << std::endl;
    }

} // namespace titan