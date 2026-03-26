#ifndef TITAN_EVENT_H
#define TITAN_EVENT_H

// ============================================================================
// event.h  —  TITAN V3
//
// Changes in this revision:
//   ProcessInfo:
//     ADDED parent_image_path  — dedicated field for the resolved parent binary
//       path (was incorrectly stored in working_directory before).
//
//   V3ProcessInfo:
//     ADDED pid, parent_pid, real_parent_pid  — critical; were never in JSON.
//     ADDED exit_time  — set on ProcessStop events for lifetime calculation.
//     ADDED image_path_raw  — raw kernel path before canonicalisation.
//     ADDED command_line_raw  — raw command line from NtQueryInformationProcess.
//     ADDED user_name, user_sid, elevation, integrity, session_id, is_64bit
//           — token / process metadata carried into JSON.
//
//   ForwardJson():
//     Emits all new fields above plus event_subtype ("process_start" |
//     "process_stop" | "process_snapshot") so callers know the event kind.
// ============================================================================

#include <chrono>
#include <optional>
#include <string>
#include <vector>
#include <windows.h>

namespace titan {

    // ============================================================================
    // ENUMERATIONS
    // ============================================================================

    enum class EventType {
        ProcessStart,
        ProcessStop,
        ProcessSnapshot,
        NetworkConnect,
        NetworkDisconnect,
        FileCreate,
        FileModify,
        FileDelete,
        RegistrySet,
        RegistryDelete,
        ThreadCreate,
        ThreadRemoteCreate,
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
        Unknown
    };

    enum class TokenElevation {
        Default,
        Limited,
        Full,
        Unknown
    };

    enum class IntegrityLevel { Untrusted, Low, Medium, High, System, Unknown };

    // ============================================================================
    // V3-SPECIFIC ENUMERATIONS
    // ============================================================================

    enum class FilterDecision { FORWARD, COMPRESS };

    enum class LocationType {
        SYSTEM,
        KNOWN_USER,
        UNKNOWN
    };

    // ============================================================================
    // RAW SENSOR DATA STRUCTURES
    // ============================================================================

    struct ProcessInfo {
        DWORD pid{ 0 };
        DWORD parent_pid{ 0 };
        DWORD real_parent_pid{ 0 };
        std::wstring image_path;         // Raw path from kernel / QueryFullProcessImageName
        std::wstring parent_image_path;  // FIX: dedicated parent binary path field
        // (was incorrectly stored in working_directory)
        std::wstring command_line;       // Raw command line from NtQueryInformationProcess
        std::wstring working_directory;  // Actual CWD (separate from parent path)

        // Token
        std::wstring user_name;
        std::wstring user_sid;
        TokenElevation elevation{ TokenElevation::Unknown };
        IntegrityLevel integrity{ IntegrityLevel::Unknown };

        // Hashes (computed async, optional)
        std::optional<std::string> md5_hash;
        std::optional<std::string> sha256_hash;

        // Timestamps
        std::chrono::system_clock::time_point create_time;  // Actual process creation (ETW ts)
        std::chrono::system_clock::time_point log_time;     // When we processed this event

        bool  is_64bit{ false };
        DWORD session_id{ 0 };
    };

    struct NetworkInfo {
        DWORD pid{ 0 };
        std::wstring process_name;

        std::string local_addr;
        USHORT local_port{ 0 };

        std::string remote_addr;
        USHORT remote_port{ 0 };

        bool is_tcp{ true };
        bool is_ipv6{ false };

        std::optional<std::wstring> dns_query;
        std::optional<std::wstring> dns_answer;
    };

    struct FileInfo {
        DWORD pid{ 0 };
        std::wstring process_name;
        std::wstring file_path;
        std::wstring original_path;

        bool is_create{ false };
        bool is_modify{ false };
        bool is_delete{ false };

        std::optional<double>   entropy;
        std::optional<uint64_t> file_size;
    };

    struct RegistryInfo {
        DWORD pid{ 0 };
        std::wstring process_name;
        std::wstring key_path;
        std::wstring value_name;
        std::optional<std::vector<BYTE>> value_data;
        DWORD value_type{ 0 };
        bool  is_delete{ false };
    };

    struct ThreadInfo {
        DWORD source_pid{ 0 };
        DWORD target_pid{ 0 };
        DWORD source_tid{ 0 };
        DWORD target_tid{ 0 };
        ULONG_PTR start_address{ 0 };
        bool  is_remote{ false };
    };

    // ============================================================================
    // V3 FILTER-ENRICHED PROCESS DATA
    // Populated by FilterEngine after the 7-stage pipeline runs.
    // ============================================================================

    struct V3ProcessInfo {
        // ---- Critical IDs (FIX: were completely missing from JSON) ----------
        DWORD pid{ 0 };
        DWORD parent_pid{ 0 };
        DWORD real_parent_pid{ 0 };   // For PPID spoofing detection

        // ---- Stage 1: resolved paths ----------------------------------------
        std::wstring canonical_path;
        std::wstring parent_canonical_path;
        std::wstring cmdline_normalized;

        // Raw values (before canonicalisation) — useful for detection pipeline
        std::wstring image_path_raw;
        std::wstring command_line_raw;

        // ---- Stage 2: trust classification ----------------------------------
        LocationType location_type{ LocationType::UNKNOWN };

        // ---- Stage 3: signature ---------------------------------------------
        bool         signature_valid{ false };
        std::wstring signature_signer;
        std::wstring signature_thumbprint;

        // ---- Stage 4: fork / thread summary ---------------------------------
        uint32_t                  child_count{ 0 };
        std::vector<std::wstring> unique_child_names;
        uint32_t                  thread_count{ 0 };
        uint32_t                  duplicate_instances{ 0 };
        bool                      new_child_flag{ false };

        // ---- Stage 5: DLL activity ------------------------------------------
        std::vector<std::wstring> dlls_new;
        std::vector<std::wstring> dlls_shadowing;

        // ---- Stage 6: persistence -------------------------------------------
        bool persistence_touched{ false };

        // ---- Stage 7: deduplication result ----------------------------------
        std::string    fingerprint;
        FilterDecision decision{ FilterDecision::FORWARD };
        uint64_t       compress_count{ 0 };
        uint32_t       window_seconds{ 60 };

        // ---- Process metadata -----------------------------------------------
        std::wstring   process_name;      // basename of canonical_path
        std::wstring   user_name;
        std::wstring   user_sid;
        TokenElevation elevation{ TokenElevation::Unknown };
        IntegrityLevel integrity{ IntegrityLevel::Unknown };
        DWORD          session_id{ 0 };
        bool           is_64bit{ false };

        // ---- Timestamps -----------------------------------------------------
        // create_time: actual process start time (from ETW FILETIME).
        // exit_time:   set on ProcessStop events. Zero for Start/Snapshot.
        // log_time:    when we processed the event (system_clock::now()).
        std::chrono::system_clock::time_point create_time;
        std::chrono::system_clock::time_point exit_time;
        std::chrono::system_clock::time_point log_time;
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

        Event(Event&&) noexcept = default;
        Event& operator=(Event&&) noexcept = default;

        // ------------------------------------------------------------------
        // Static factory methods
        // ------------------------------------------------------------------
        static Event CreateProcessEvent(const ProcessInfo& info, EventSource source);
        static Event CreateNetworkEvent(const NetworkInfo& info, EventSource source);
        static Event CreateFileEvent(const FileInfo& info, EventSource source);
        static Event CreateRegistryEvent(const RegistryInfo& info, EventSource source);
        static Event CreateThreadEvent(const ThreadInfo& info, EventSource source);
        static Event CreateCompressEvent(const CompressSummary& summary);

        // FIX: factory that creates a ProcessStop event from a ProcessInfo
        static Event CreateProcessStopEvent(const ProcessInfo& info, EventSource source);

        // FIX: factory that creates a ProcessSnapshot (DCStart) event
        static Event CreateProcessSnapshotEvent(const ProcessInfo& info, EventSource source);

        // ------------------------------------------------------------------
        // Getters — raw sensor data
        // ------------------------------------------------------------------
        EventType   GetType()   const noexcept { return type_; }
        EventSource GetSource() const noexcept { return source_; }
        const std::chrono::system_clock::time_point& GetTimestamp() const noexcept {
            return timestamp_;
        }

        const ProcessInfo* GetProcessInfo()  const noexcept;
        const NetworkInfo* GetNetworkInfo()  const noexcept;
        const FileInfo* GetFileInfo()     const noexcept;
        const RegistryInfo* GetRegistryInfo() const noexcept;
        const ThreadInfo* GetThreadInfo()   const noexcept;

        // ------------------------------------------------------------------
        // V3 filter-enriched data
        // ------------------------------------------------------------------
        V3ProcessInfo& GetV3()       noexcept { return v3_; }
        const V3ProcessInfo& GetV3() const noexcept { return v3_; }

        bool IsV3Enriched() const noexcept { return v3_enriched_; }
        void MarkV3Enriched() noexcept { v3_enriched_ = true; }

        // ------------------------------------------------------------------
        // Serialisation
        // ------------------------------------------------------------------
        std::string  ForwardJson()  const;
        std::string  CompressJson() const;
        std::string  ToJson()       const;
        std::wstring ToJsonW()      const;

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

        Event(EventType type, EventSource source);

        friend class EventBuilder;
    };

    // ============================================================================
    // EVENT BUILDER
    // ============================================================================

    class EventBuilder {
    public:
        static EventBuilder Process(EventSource source);
        static EventBuilder Network(EventSource source);
        static EventBuilder File(EventSource source);
        static EventBuilder Registry(EventSource source);
        static EventBuilder Thread(EventSource source);

        EventBuilder& Pid(DWORD pid);
        EventBuilder& ParentPid(DWORD pid);
        EventBuilder& RealParentPid(DWORD pid);
        EventBuilder& ImagePath(std::wstring path);
        EventBuilder& CommandLine(std::wstring cmd);
        EventBuilder& User(std::wstring user, std::wstring sid);
        EventBuilder& Token(TokenElevation elevation, IntegrityLevel integrity);

        EventBuilder& LocalEndpoint(const std::string& addr, USHORT port);
        EventBuilder& RemoteEndpoint(const std::string& addr, USHORT port);
        EventBuilder& Protocol(bool tcp, bool ipv6);
        EventBuilder& DnsInfo(std::wstring query, std::wstring answer);

        Event Build();

    private:
        explicit EventBuilder(EventType type, EventSource source);
        Event event_;
    };

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    namespace utils {

        std::string EventTypeToString(EventType type);
        std::string EventSourceToString(EventSource source);
        std::string TokenElevationToString(TokenElevation elevation);
        std::string IntegrityToString(IntegrityLevel integrity);
        std::string LocationTypeToString(LocationType loc);
        std::string FilterDecisionToString(FilterDecision decision);

        std::wstring DevicePathToDrivePath(const std::wstring& device_path);
        IntegrityLevel GetIntegrityFromToken(HANDLE hToken);
        std::wstring CanonicalizePath(const std::wstring& raw_path);
        std::wstring NormalizeCommandLine(const std::wstring& cmdline);

    } // namespace utils

} // namespace titan

#endif // TITAN_EVENT_H