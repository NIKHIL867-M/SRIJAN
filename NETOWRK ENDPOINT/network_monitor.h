#ifndef TITAN_NETWORK_MONITOR_H
#define TITAN_NETWORK_MONITOR_H

// ============================================================================
// network_monitor.h  —  TITAN V4  Npcap Deep-Packet Network Monitor
//
// Responsibilities:
//   1. Load Npcap DLLs from System32\Npcap.
//   2. Enumerate all non-loopback adapters.
//   3. Per-adapter pcap_loop capture thread.
//   4. Parse Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP.
//   5. Application-layer identification (HTTP, TLS-SNI, DNS, QUIC, RDP, SMB, SSH, SMTP).
//   6. PID resolution via GetExtendedTcpTable / GetExtendedUdpTable (refreshed every 500ms).
//   7. Process enrichment: image path, SHA-256, user SID.
//   8. Flow state tracking in a fixed-size flow table.
//   9. Pass enriched NetworkEvent to FilterEngine::Process().
//  10. If FORWARD -> logger_.LogEvent(); if COMPRESS -> counter only.
//
// V4 -- replaces the old ETW-network path entirely.
// ============================================================================

// Winsock2 must precede windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "event.h"
#include "filter.h"
#include "logger.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Npcap
#include <pcap.h>

namespace titan {

    // ============================================================================
    // FLOW KEY -- 5-tuple used as hash map key
    // ============================================================================

    struct FlowKey {
        std::string local_addr;
        std::string remote_addr;
        uint16_t    local_port{ 0 };
        uint16_t    remote_port{ 0 };
        uint8_t     protocol{ 0 };

        bool operator==(const FlowKey& o) const noexcept {
            return local_addr == o.local_addr && remote_addr == o.remote_addr
                && local_port == o.local_port && remote_port == o.remote_port
                && protocol == o.protocol;
        }
    };

    struct FlowKeyHash {
        size_t operator()(const FlowKey& k) const noexcept {
            size_t h = std::hash<std::string>{}(k.local_addr);
            h ^= std::hash<std::string>{}(k.remote_addr) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint32_t>{}(
                (static_cast<uint32_t>(k.local_port) << 16) | k.remote_port)
                + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    // ============================================================================
    // FLOW STATE -- per-flow accumulator
    // ============================================================================

    struct FlowState {
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        NetworkDirection direction{ NetworkDirection::UNKNOWN };
        TcpState         tcp_state{ TcpState::UNKNOWN };
        uint32_t         pid{ 0 };
        uint64_t         bytes_sent{ 0 };
        uint64_t         bytes_recv{ 0 };
        uint32_t         packet_count{ 0 };
    };

    // ============================================================================
    // SOCKET->PID CACHE KEY
    // ============================================================================

    struct SocketPidKey {
        std::string local_ip;
        uint16_t    local_port{ 0 };
        uint8_t     proto{ 0 };

        bool operator==(const SocketPidKey& o) const noexcept {
            return local_ip == o.local_ip && local_port == o.local_port
                && proto == o.proto;
        }
    };

    struct SocketPidKeyHash {
        size_t operator()(const SocketPidKey& k) const noexcept {
            size_t h = std::hash<std::string>{}(k.local_ip);
            h ^= std::hash<uint32_t>{}(
                (static_cast<uint32_t>(k.local_port) << 8) | k.proto)
                + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    // ============================================================================
    // ADAPTER CONTEXT
    // ============================================================================

    struct AdapterCtx {
        std::string  name;
        pcap_t* handle{ nullptr };
        std::thread  thread;
    };

    // ============================================================================
    // NETWORK MONITOR
    // ============================================================================

    class NetworkMonitor {
    public:
        explicit NetworkMonitor(AsyncLogger& logger, FilterEngine& filter);
        ~NetworkMonitor();

        NetworkMonitor(const NetworkMonitor&) = delete;
        NetworkMonitor& operator=(const NetworkMonitor&) = delete;

        bool Start();
        void Stop();
        bool IsRunning() const noexcept { return running_.load(); }

        // V4 counters (names match Agent.cpp usage exactly)
        uint64_t GetPacketsCaptured()  const noexcept { return pkts_captured_.load(); }
        uint64_t GetFlowsForwarded()   const noexcept { return flows_forwarded_.load(); }
        uint64_t GetFlowsCompressed()  const noexcept { return flows_compressed_.load(); }

    private:
        // Startup helpers
        bool LoadNpcapDlls();
        void EnumerateAdapters();
        void BuildLocalIpSet();
        void BuildPortAppMap();
        bool IsLocalIp(const std::string& ip) const;

        // Per-adapter capture thread entry point
        void CaptureThread(std::string adapter_name);

        // Packet pipeline
        void HandlePacket(const struct pcap_pkthdr* header,
            const uint8_t* data,
            const std::string& adapter_name);

        // Parsers
        bool ParseEthernet(const uint8_t* data, uint32_t len, NetworkInfo& out);
        bool ParseIPv4(const uint8_t* data, uint32_t len, NetworkInfo& out);
        bool ParseIPv6(const uint8_t* data, uint32_t len, NetworkInfo& out);
        void ParseTCP(const uint8_t* data, uint32_t len, NetworkInfo& out, bool is_src_local);
        void ParseUDP(const uint8_t* data, uint32_t len, NetworkInfo& out, bool is_src_local);
        void ParseICMP(const uint8_t* data, uint32_t len, NetworkInfo& out);

        // Application-layer identification
        void IdentifyAppLayer(const uint8_t* payload, uint32_t len, NetworkInfo& out);

        // Flow state
        void UpdateFlowState(const NetworkInfo& info, uint32_t payload_bytes);

        // PID resolution
        void  RefreshPidCache();
        DWORD LookupPid(const std::string& local_ip, uint16_t local_port,
            uint8_t proto) const;

        // Process enrichment
        // Lightweight process name resolution (short name only)
        void ResolveProcessName(DWORD pid, NetworkInfo& out);

        // DNS hostname cache

        // ---- members ----
        AsyncLogger& logger_;
        FilterEngine& filter_;

        std::vector<AdapterCtx> adapters_;

        // Local IP set for direction detection
        mutable std::mutex                  local_ip_mutex_;
        std::unordered_set<std::string>     local_ips_;

        // Flow table
        static constexpr size_t kMaxFlows = 50000;
        mutable std::mutex                                          flow_mutex_;
        std::unordered_map<FlowKey, FlowState, FlowKeyHash>        flow_table_;

        // Port -> AppLayer hint map
        std::unordered_map<uint16_t, AppLayer> port_app_map_;

        // PID cache (refreshed every kPidRefreshMs)
        static constexpr uint32_t kPidRefreshMs = 500;
        mutable std::mutex  pid_mutex_;
        std::unordered_map<SocketPidKey, DWORD, SocketPidKeyHash>  pid_cache_;
        std::thread         pid_refresh_thread_;

        std::atomic<bool>     running_{ false };
        std::atomic<bool>     stop_requested_{ false };

        // V4 counters
        std::atomic<uint64_t> pkts_captured_{ 0 };
        std::atomic<uint64_t> flows_forwarded_{ 0 };
        std::atomic<uint64_t> flows_compressed_{ 0 };
    };

} // namespace titan

#endif // TITAN_NETWORK_MONITOR_H