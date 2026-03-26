#ifndef TITAN_AGENT_H
#define TITAN_AGENT_H

#include "filter.h"
#include "logger.h"
#include "network_monitor.h"

#include <atomic>
#include <memory>
#include <string>

namespace titan {

    // ============================================================================
    // Agent  —  TITAN V4  Network Endpoint
    // Boots and owns all components.
    // Responsibilities:
    //   - Initialize FilterEngine (O(1) structures, pre-warmed caches)
    //   - Initialize AsyncLogger (no drop, compress-only)
    //   - Initialize NetworkMonitor (Npcap deep-packet capture)
    //   - Run main loop, emit compression stats every 10s
    //   - Clean shutdown on SIGINT / SIGTERM
    // ============================================================================

    class Agent {
    public:
        Agent();
        ~Agent();

        Agent(const Agent&) = delete;
        Agent& operator=(const Agent&) = delete;

        // Initialize all sub-components.
        // log_path: directory where .jsonl log packs are written.
        bool Initialize(const std::wstring& log_path);

        // Start monitoring. Blocks until Stop() is called.
        bool Start();

        // Signal-safe stop. Can be called from signal handler.
        void Stop();

        // Print compression pipeline stats to stdout.
        void PrintStatus() const;

    private:
        bool CheckAdminPrivileges();
        bool PreWarmCaches();

        std::atomic<bool> initialized_{ false };
        std::atomic<bool> running_{ false };
        std::wstring log_path_;

        std::unique_ptr<AsyncLogger>    logger_;
        std::unique_ptr<FilterEngine>   filter_;
        std::unique_ptr<NetworkMonitor> network_monitor_;
    };

} // namespace titan

#endif // TITAN_AGENT_H