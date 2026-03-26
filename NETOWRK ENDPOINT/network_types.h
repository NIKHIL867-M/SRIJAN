#ifndef NETWORK_TYPES_H
#define NETWORK_TYPES_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>


#pragma comment(lib, "ws2_32.lib")

namespace network {

    // ============================================================================
    // MEMORY SAFETY CONSTANTS
    // ============================================================================

    constexpr size_t MAX_FLOW_TABLE_SIZE = 100000;
    constexpr size_t MAX_PACKET_QUEUE = 50000;
    constexpr size_t MAX_PAYLOAD_SIZE = 65535;
    constexpr uint32_t FLOW_TIMEOUT_SECONDS = 300;
    constexpr uint32_t PACKET_TIMEOUT_MS = 100;

    // ============================================================================
    // PACKET STRUCTURE
    // ============================================================================

    struct Packet {

        std::chrono::steady_clock::time_point timestamp;

        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t protocol;

        uint16_t src_port;
        uint16_t dst_port;

        std::vector<uint8_t> payload;
        size_t payload_size;

        uint32_t pid;
        std::wstring process_name;
        std::wstring process_path;

        Packet()
            : src_ip(0), dst_ip(0), protocol(0), src_port(0), dst_port(0),
            payload_size(0), pid(0) {
        }
    };

    // ============================================================================
    // FLOW KEY
    // ============================================================================

    struct FlowKey {

        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;

        bool operator==(const FlowKey& other) const {
            return src_ip == other.src_ip && dst_ip == other.dst_ip &&
                src_port == other.src_port && dst_port == other.dst_port &&
                protocol == other.protocol;
        }

        bool operator<(const FlowKey& other) const {

            if (src_ip != other.src_ip)
                return src_ip < other.src_ip;

            if (dst_ip != other.dst_ip)
                return dst_ip < other.dst_ip;

            if (src_port != other.src_port)
                return src_port < other.src_port;

            if (dst_port != other.dst_port)
                return dst_port < other.dst_port;

            return protocol < other.protocol;
        }
    };

    // ============================================================================
    // HASH FOR FLOWKEY
    // ============================================================================

    struct FlowKeyHash {

        size_t operator()(const FlowKey& key) const {

            // FIX C4244: explicit casts on all hash operands
            return std::hash<uint64_t>{}((static_cast<uint64_t>(key.src_ip) << 32) |
                static_cast<uint64_t>(key.dst_ip)) ^
                std::hash<uint32_t>{}((static_cast<uint32_t>(key.src_port) << 16) |
                    static_cast<uint32_t>(key.dst_port)) ^
                std::hash<uint8_t>{}(key.protocol);
        }
    };

    // ============================================================================
    // FLOW STATISTICS
    // ============================================================================

    struct FlowStats {

        FlowKey key;

        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;

        uint64_t total_bytes;
        uint64_t total_packets;

        uint32_t pid;
        std::wstring process_name;
        std::wstring process_path;

        bool is_suspicious;
        std::vector<std::string> tags;

        FlowStats()
            : key{}, total_bytes(0), total_packets(0), pid(0), is_suspicious(false) {
        }

        uint64_t duration_seconds() const {

            return std::chrono::duration_cast<std::chrono::seconds>(last_seen -
                first_seen)
                .count();
        }
    };

    // ============================================================================
    // NETWORK EVENT
    // ============================================================================

    enum class EventSeverity { INFO, LOW, MEDIUM, HIGH, CRITICAL };

    struct NetworkEvent {

        std::chrono::steady_clock::time_point timestamp;

        EventSeverity severity;

        std::string src_ip_str;
        std::string dst_ip_str;

        uint16_t src_port;
        uint16_t dst_port;

        std::string protocol_str;

        uint32_t pid;
        std::wstring process_name;
        std::wstring process_path;

        uint64_t bytes_transferred;
        uint64_t packet_count;
        uint64_t duration_seconds;

        bool is_tagged;
        std::vector<std::string> tags;

        std::string description;

        NetworkEvent()
            : src_port(0), dst_port(0), pid(0), bytes_transferred(0), packet_count(0),
            duration_seconds(0), is_tagged(false), severity(EventSeverity::INFO) {
        }
    };

    // ============================================================================
    // FILTER STATISTICS
    // FIX: Split into two structs:
    //   - FilterStatsAtomic  -> used internally (has atomics, lives in
    //   NetworkFilter)
    //   - FilterStats        -> plain copyable snapshot returned by GetStats()
    // ============================================================================

    // Plain copyable snapshot — safe to return by value
    struct FilterStats {
        uint64_t packets_received = 0;
        uint64_t packets_dropped = 0;
        uint64_t packets_validated = 0;
        uint64_t flows_created = 0;
        uint64_t flows_expired = 0;
        uint64_t events_generated = 0;
        uint64_t noise_suppressed = 0;
    };

    // Atomic version used internally by NetworkFilter
    struct FilterStatsAtomic {
        std::atomic<uint64_t> packets_received{ 0 };
        std::atomic<uint64_t> packets_dropped{ 0 };
        std::atomic<uint64_t> packets_validated{ 0 };
        std::atomic<uint64_t> flows_created{ 0 };
        std::atomic<uint64_t> flows_expired{ 0 };
        std::atomic<uint64_t> events_generated{ 0 };
        std::atomic<uint64_t> noise_suppressed{ 0 };

        void reset() {
            packets_received = 0;
            packets_dropped = 0;
            packets_validated = 0;
            flows_created = 0;
            flows_expired = 0;
            events_generated = 0;
            noise_suppressed = 0;
        }

        // Snapshot to plain copyable struct
        FilterStats snapshot() const {
            FilterStats s;
            s.packets_received = packets_received.load();
            s.packets_dropped = packets_dropped.load();
            s.packets_validated = packets_validated.load();
            s.flows_created = flows_created.load();
            s.flows_expired = flows_expired.load();
            s.events_generated = events_generated.load();
            s.noise_suppressed = noise_suppressed.load();
            return s;
        }
    };

    // ============================================================================
    // UTILITIES
    // ============================================================================

    inline std::string IpToString(uint32_t ip) {

        struct in_addr addr {};
        addr.s_addr = ip;

        char str[INET_ADDRSTRLEN]{}; // FIX C6001

        inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);

        return std::string(str);
    }

    inline std::wstring StringToWstring(const std::string& str) {

        if (str.empty())
            return std::wstring();

        int size_needed =
            MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);

        std::wstring wstr(size_needed, 0);

        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0],
            size_needed);

        return wstr;
    }

} // namespace network

#endif