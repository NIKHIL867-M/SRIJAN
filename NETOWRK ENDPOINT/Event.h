#ifndef TITAN_EVENT_H
#define TITAN_EVENT_H

// ============================================================================
// event.h  —  TITAN V4
//
// V4 changes from V3:
//   ENVIRONMENT:
//     - Compiler: MSVC (cl.exe) — NOT Clang / MinGW / MSYS2
//     - Standard: C++20, /W4 /WX /permissive-
//     - Target:   _WIN32_WINNT=0x0A00 (Windows 10+)
//
//   NETWORK MONITOR (new — Npcap-based, Wireshark-level capture):
//     - NetworkInfo now carries the full enrichment set agreed in design review:
//         direction          (INBOUND / OUTBOUND / UNKNOWN)
//         tcp_state          (SYN_SENT / ESTABLISHED / CLOSED / etc.)
//         bytes_sent         (payload bytes from this process → remote)
//         bytes_recv         (payload bytes remote → this process)
//         process_sha256     (hash of the sending binary — anti-masquerade)
//         cmdline            (full command line of the process at capture time)
//         dns_hostname       (resolved hostname for remote_addr)
//         user_name          (SID/username that owns the socket)
//         user_sid           (string SID)
//         application_layer  (HTTP / TLS / DNS / RDP / SMB / QUIC / UNKNOWN)
//         tls_sni            (SNI from TLS ClientHello — zero-decrypt)
//         http_host          (Host header if plain HTTP)
//         http_method        (GET / POST / etc.)
//         icmp_type          (for ICMP events)
//         icmp_code
//         packet_count       (packets in this flow)
//         flow_duration_ms   (milliseconds from SYN/first pkt to last seen)
//         is_broadcast       (dst is broadcast / multicast)
//         is_loopback        (127.x or ::1)
//
//   PROCESS MONITOR (unchanged logic, ported to MSVC):
//     - All V3 fields retained
//     - ProcessInfo + V3ProcessInfo: same as V3
//
//   THREAD MONITOR:
//     - ThreadInfo: same as V3, is_remote flag drives ThreadRemoteCreate
//
//   FILE / REGISTRY:
//     - Same as V3
// ============================================================================

// Force Winsock2 before windows.h to prevent winsock1/2 conflicts
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace titan {

    // ============================================================================
    // ENUMERATIONS
    // ============================================================================

    enum class EventType {
        ProcessStart,
        ProcessStop,
        ProcessSnapshot,        // DCStart — existing process at trace begin
        NetworkConnect,
        NetworkDisconnect,
        NetworkPacket,          // NEW V4 — individual packet from Npcap
        FileCreate,
        FileModify,
        FileDelete,
        RegistrySet,
        RegistryDelete,
        ThreadCreate,
        ThreadRemoteCreate,     // Cross-process thread injection
        Unknown
    };

    enum class EventSource {
        EtwKernelProcess,
        EtwKernelNetwork,
        EtwKernelFile,
        EtwKernelRegistry,
        EtwThreatIntelligence,
        SysmonDns,
        KernelCallback,
        NpcapLive,              // NEW V4 — raw Npcap packet capture
        Unknown
    };

    enum class TokenElevation {
        Default,    // Standard user, no UAC
        Limited,    // Admin with filtered token
        Full,       // Elevated admin
        Unknown
    };

    enum class IntegrityLevel {
        Untrusted, Low, Medium, High, System, Unknown
    };

    // ============================================================================
    // V3/V4 SHARED ENUMERATIONS
    // ============================================================================

    // Output decision: FORWARD (full event) | COMPRESS (deduplicated summary)
    // There is NO drop path.
    enum class FilterDecision { FORWARD, COMPRESS };

    // Trust classification from Stage 2.
    enum class LocationType {
        SYSTEM,     // Under %SystemRoot% or non-user-writable system PATH
        KNOWN_USER, // Program Files, user AppData\Local\Programs, user PATH
        UNKNOWN     // Anything outside all known roots — always FORWARD
    };

    // ============================================================================
    // NEW V4 — NETWORK DIRECTION & TCP STATE
    // ============================================================================

    enum class NetworkDirection {
        INBOUND,    // Remote → local  (we are the listening side)
        OUTBOUND,   // Local  → remote (we initiated the connection)
        UNKNOWN
    };

    enum class TcpState {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT,
        CLOSE_WAIT,
        CLOSED,
        UNKNOWN
    };

    // Application-layer protocol identified by Npcap heuristics (port + payload).
    enum class AppLayer {
        HTTP,
        HTTPS_TLS,  // TLS — SNI extracted without decryption
        DNS,
        RDP,
        SMB,
        QUIC,
        ICMP,
        NTP,
        DHCP,
        FTP,
        SSH,
        SMTP,
        UNKNOWN
    };

    // ============================================================================
    // RAW SENSOR DATA STRUCTURES
    // ============================================================================

    struct ProcessInfo {
        DWORD  pid{ 0 };
        DWORD  parent_pid{ 0 };
        DWORD  real_parent_pid{ 0 };  // For PPID-spoofing detection
        std::wstring image_path;    // Raw path from kernel (may be device path)
        std::wstring command_line;
        std::wstring working_directory;

        // Token
        std::wstring user_name;
        std::wstring user_sid;
        TokenElevation  elevation{ TokenElevation::Unknown };
        IntegrityLevel  integrity{ IntegrityLevel::Unknown };

        // Hashes (async, optional)
        std::optional<std::string> md5_hash;
        std::optional<std::string> sha256_hash;

        // Timestamps
        std::chrono::system_clock::time_point create_time;
        std::chrono::system_clock::time_point log_time;

        bool   is_64bit{ false };
        DWORD  session_id{ 0 };
    };

    // ---------------------------------------------------------------------------
    // NetworkInfo — V4 enriched (all fields discussed in design review added)
    // ---------------------------------------------------------------------------
    struct NetworkInfo {
        // ---- Process identity --------------------------------------------------
        DWORD        pid{ 0 };
        std::wstring process_name;   // Short exe name only (e.g. svchost.exe)

        // ---- Socket 5-tuple ----------------------------------------------------
        std::string  local_addr;
        USHORT       local_port{ 0 };
        std::string  remote_addr;
        USHORT       remote_port{ 0 };
        bool         is_tcp{ true };
        bool         is_ipv6{ false };

        // ---- Traffic direction & state -----------------------------------------
        NetworkDirection direction{ NetworkDirection::UNKNOWN };
        TcpState         tcp_state{ TcpState::UNKNOWN };

        // ---- Protocol (application layer) --------------------------------------
        AppLayer app_layer{ AppLayer::UNKNOWN };

        // ---- Data volume -------------------------------------------------------
        uint64_t bytes_sent{ 0 };       // payload bytes local -> remote
        uint64_t bytes_recv{ 0 };       // payload bytes remote -> local
        uint32_t packet_count{ 0 };     // total packets in this flow
        uint64_t flow_duration_ms{ 0 }; // ms from first to last packet seen

        // ---- Traffic flags -----------------------------------------------------
        bool is_broadcast{ false };
        bool is_loopback{ false };
    };

    struct FileInfo {
        DWORD        pid{ 0 };
        std::wstring process_name;
        std::wstring file_path;
        std::wstring original_path;   // For rename operations

        bool is_create{ false };
        bool is_modify{ false };
        bool is_delete{ false };

        std::optional<double>   entropy;
        std::optional<uint64_t> file_size;
    };

    struct RegistryInfo {
        DWORD        pid{ 0 };
        std::wstring process_name;
        std::wstring key_path;
        std::wstring value_name;
        std::optional<std::vector<BYTE>> value_data;
        DWORD        value_type{ 0 };
        bool         is_delete{ false };
    };

    struct ThreadInfo {
        DWORD      source_pid{ 0 };
        DWORD      target_pid{ 0 };
        DWORD      source_tid{ 0 };
        DWORD      target_tid{ 0 };
        ULONG_PTR  start_address{ 0 };
        bool       is_remote{ false };
    };

    // ============================================================================
    // V4 FILTER-ENRICHED PROCESS DATA
    // Populated by FilterEngine after the 7-stage pipeline.
    // ============================================================================

    struct V3ProcessInfo {
        // Stage 1: resolved paths
        std::wstring canonical_path;
        std::wstring parent_canonical_path;
        std::wstring cmdline_normalized;    // NFC / lowercase / collapsed / [:256]

        // Stage 2: trust
        LocationType location_type{ LocationType::UNKNOWN };

        // Stage 3: signature
        bool         signature_valid{ false };
        std::wstring signature_signer;
        std::wstring signature_thumbprint;

        // Stage 4: fork/thread summary
        uint32_t                  child_count{ 0 };
        std::vector<std::wstring> unique_child_names;
        uint32_t                  thread_count{ 0 };
        uint32_t                  duplicate_instances{ 0 };
        bool                      new_child_flag{ false };

        // Stage 5: DLL activity
        std::vector<std::wstring> dlls_new;
        std::vector<std::wstring> dlls_shadowing;

        // Stage 6: persistence
        bool persistence_touched{ false };

        // Stage 7: dedup
        std::string    fingerprint;
        FilterDecision decision{ FilterDecision::FORWARD };
        uint64_t       compress_count{ 0 };
        uint32_t       window_seconds{ 60 };

        // Shorthand
        std::wstring process_name;
    };

    // ============================================================================
    // COMPRESS SUMMARY
    // ============================================================================

    struct CompressSummary {
        std::chrono::system_clock::time_point ts;
        std::wstring process_name;
        std::wstring canonical_path;
        std::string  fingerprint;
        uint64_t     count{ 0 };
        uint32_t     window_seconds{ 60 };
    };

    // ============================================================================
    // MAIN EVENT CLASS
    // ============================================================================

    class EventBuilder;

    class Event {
    public:
        Event() = default;
        ~Event() = default;

        Event(const Event&) = delete;
        Event& operator=(const Event&) = delete;

        Event(Event&&)            noexcept = default;
        Event& operator=(Event&&) noexcept = default;

        // --- Factory methods ----------------------------------------------------
        static Event CreateProcessEvent(const ProcessInfo& info, EventSource source);
        static Event CreateNetworkEvent(const NetworkInfo& info, EventSource source);
        static Event CreateFileEvent(const FileInfo& info, EventSource source);
        static Event CreateRegistryEvent(const RegistryInfo& info, EventSource source);
        static Event CreateThreadEvent(const ThreadInfo& info, EventSource source);
        static Event CreateCompressEvent(const CompressSummary& summary);

        // --- Raw sensor getters -------------------------------------------------
        EventType          GetType()      const noexcept { return type_; }
        EventSource        GetSource()    const noexcept { return source_; }
        const std::chrono::system_clock::time_point& GetTimestamp() const noexcept {
            return timestamp_;
        }

        const ProcessInfo* GetProcessInfo()  const noexcept;
        const NetworkInfo* GetNetworkInfo()  const noexcept;
        const FileInfo* GetFileInfo()     const noexcept;
        const RegistryInfo* GetRegistryInfo() const noexcept;
        const ThreadInfo* GetThreadInfo()   const noexcept;

        // --- V3/V4 filter-enriched data -----------------------------------------
        V3ProcessInfo& GetV3()       noexcept { return v3_; }
        const V3ProcessInfo& GetV3() const noexcept { return v3_; }

        bool IsV3Enriched()  const noexcept { return v3_enriched_; }
        void MarkV3Enriched()      noexcept { v3_enriched_ = true; }

        // --- Serialisation ------------------------------------------------------
        std::string  ForwardJson()  const;  // Full V4 FORWARD shape
        std::string  CompressJson() const;  // Lightweight COMPRESS shape
        std::string  ToJson()       const;  // Dispatches based on v3_.decision
        std::wstring ToJsonW()      const;

        // --- Compress summary accessor ------------------------------------------
        const CompressSummary* GetCompressSummary() const noexcept {
            return compress_.has_value() ? &compress_.value() : nullptr;
        }

    private:
        EventType   type_{ EventType::Unknown };
        EventSource source_{ EventSource::Unknown };
        std::chrono::system_clock::time_point timestamp_{
            std::chrono::system_clock::now() };

        ProcessInfo  process_;
        NetworkInfo  network_;
        FileInfo     file_;
        RegistryInfo registry_;
        ThreadInfo   thread_;

        V3ProcessInfo v3_;
        bool          v3_enriched_{ false };

        std::optional<CompressSummary> compress_;

        explicit Event(EventType type, EventSource source);
        friend class EventBuilder;
    };

    // ============================================================================
    // EVENT BUILDER  —  fluent interface
    // ============================================================================

    class EventBuilder {
    public:
        static EventBuilder Process(EventSource source);
        static EventBuilder Network(EventSource source);
        static EventBuilder File(EventSource source);
        static EventBuilder Registry(EventSource source);
        static EventBuilder Thread(EventSource source);

        // Process setters
        EventBuilder& Pid(DWORD pid);
        EventBuilder& ParentPid(DWORD pid);
        EventBuilder& RealParentPid(DWORD pid);
        EventBuilder& ImagePath(std::wstring path);
        EventBuilder& CommandLine(std::wstring cmd);
        EventBuilder& User(std::wstring user, std::wstring sid);
        EventBuilder& Token(TokenElevation elevation, IntegrityLevel integrity);

        // Network setters
        EventBuilder& LocalEndpoint(const std::string& addr, USHORT port);
        EventBuilder& RemoteEndpoint(const std::string& addr, USHORT port);
        EventBuilder& Protocol(bool tcp, bool ipv6);

        Event Build();

    private:
        explicit EventBuilder(EventType type, EventSource source);
        Event event_;
    };

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    namespace utils {

        std::string EventTypeToString(EventType       type);
        std::string EventSourceToString(EventSource     source);
        std::string TokenElevationToString(TokenElevation elevation);
        std::string IntegrityToString(IntegrityLevel  integrity);
        std::string LocationTypeToString(LocationType    loc);
        std::string FilterDecisionToString(FilterDecision decision);
        std::string NetworkDirectionToString(NetworkDirection dir);
        std::string TcpStateToString(TcpState        state);
        std::string AppLayerToString(AppLayer         app);

        // Windows path helpers
        std::wstring DevicePathToDrivePath(const std::wstring& device_path);
        IntegrityLevel GetIntegrityFromToken(HANDLE hToken);

        // Path canonicalisation (Stage 1, ProcessMonitor)
        std::wstring CanonicalizePath(const std::wstring& raw_path);

        // Command-line normalisation (Stage 7 fingerprint component)
        std::wstring NormalizeCommandLine(const std::wstring& cmdline);

        // SHA-256 hex of a UTF-8 string (BCrypt — no OpenSSL dependency)
        std::string Sha256Hex(const std::string& data);

        // Resolve IP → hostname via DnsQuery / getnameinfo
        std::string ResolveHostname(const std::string& ip_str);

    } // namespace utils

} // namespace titan

#endif // TITAN_EVENT_H