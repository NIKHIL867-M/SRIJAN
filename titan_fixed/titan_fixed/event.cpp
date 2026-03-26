#include "event.h"

#include <algorithm>
#include <cwctype>   // std::iswspace, ::towlower — required for wide-char classification
#include <iomanip>
#include <sstream>

#pragma comment(lib, "normaliz.lib")

// ============================================================================
// event.cpp  —  TITAN V3
//
// Changes in this revision:
//   ForwardJson():
//     ADDED: event_subtype ("process_start" | "process_stop" | "process_snapshot")
//     ADDED: pid, parent_pid, real_parent_pid  (CRITICAL — were always missing)
//     ADDED: process_start_time, log_time      (ISO-8601 UTC with microseconds)
//     ADDED: exit_time                         (for process_stop events only)
//     ADDED: user_name, user_sid, elevation, integrity, session_id, is_64bit
//     ADDED: image_path_raw, command_line_raw  (before canonicalisation)
//
//   New factory methods:
//     CreateProcessStopEvent()     — emits EventType::ProcessStop
//     CreateProcessSnapshotEvent() — emits EventType::ProcessSnapshot
//
//   CreateProcessEvent():
//     Sets timestamp_ from info.create_time when it is non-zero,
//     so the JSON "ts" field reflects when the process ACTUALLY started.
// ============================================================================

namespace titan {

    // ============================================================================
    // INTERNAL HELPERS
    // ============================================================================

    namespace {

        static std::string WstringToUtf8(const std::wstring& wstr) {
            if (wstr.empty())
                return {};
            if (wstr.data() == nullptr)
                return {};
            if (wstr.size() > 65536)
                return "ERROR_PATH_TOO_LONG";

            int needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
                static_cast<int>(wstr.size()), nullptr, 0,
                nullptr, nullptr);
            if (needed <= 0 || needed > 131072)
                return {};

            std::string out;
            try {
                out.resize(static_cast<size_t>(needed));
            }
            catch (const std::length_error&) {
                return "ERROR_ALLOCATION_FAILED";
            }

            WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
                out.data(), needed, nullptr, nullptr);
            return out;
        }

        static std::string EscapeJson(const std::string& s) {
            std::ostringstream o;
            for (unsigned char c : s) {
                switch (c) {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b";  break;
                case '\f': o << "\\f";  break;
                case '\n': o << "\\n";  break;
                case '\r': o << "\\r";  break;
                case '\t': o << "\\t";  break;
                default:
                    if (c < 0x20) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(c) << std::dec;
                    }
                    else {
                        o << c;
                    }
                }
            }
            return o.str();
        }

        static std::string EscapeJsonW(const std::wstring& ws) {
            return EscapeJson(WstringToUtf8(ws));
        }

        // ISO-8601 with microsecond precision, always UTC ("Z").
        // Returns empty string for a default-constructed (zero) time_point so we
        // can distinguish "not set" from "epoch".
        static std::string
            FormatTimestamp(const std::chrono::system_clock::time_point& tp) {
            // A default-constructed time_point is epoch (zero duration).
            // Treat it as "not set" — return empty so callers can emit null or skip.
            static const std::chrono::system_clock::time_point kEpoch{};
            if (tp == kEpoch)
                return "";

            auto tt = std::chrono::system_clock::to_time_t(tp);
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                tp.time_since_epoch()) %
                1'000'000;

            std::tm gmt{};
            gmtime_s(&gmt, &tt);

            std::ostringstream oss;
            oss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%S");
            oss << '.' << std::setfill('0') << std::setw(6) << us.count() << 'Z';
            return oss.str();
        }




        static std::string JsonStringArray(const std::vector<std::wstring>& vec) {
            std::ostringstream o;
            o << '[';
            for (size_t i = 0; i < vec.size(); ++i) {
                if (i)
                    o << ',';
                o << '"' << EscapeJsonW(vec[i]) << '"';
            }
            o << ']';
            return o.str();
        }

    } // anonymous namespace

    // ============================================================================
    // EVENT FACTORY METHODS
    // ============================================================================

    Event::Event(EventType type, EventSource source)
        : type_(type), source_(source),
        timestamp_(std::chrono::system_clock::now()) {
    }

    // ---------------------------------------------------------------------------
    // CreateProcessEvent  — ProcessStart
    // FIX: If info.create_time is set (non-epoch), use it as timestamp_ so the
    //      JSON "ts" field reflects actual process creation, not log time.
    // ---------------------------------------------------------------------------
    Event Event::CreateProcessEvent(const ProcessInfo& info, EventSource source) {
        Event evt(EventType::ProcessStart, source);
        evt.process_ = info;
        evt.process_.log_time = evt.timestamp_;

        static const std::chrono::system_clock::time_point kEpoch{};
        if (info.create_time != kEpoch)
            evt.timestamp_ = info.create_time;

        return evt;
    }

    // ---------------------------------------------------------------------------
    // CreateProcessStopEvent  — ProcessStop
    // FIX: This factory was missing. HandleProcessStop() now calls it so exit
    //      events are logged and process lifetime is tracked.
    // ---------------------------------------------------------------------------
    Event Event::CreateProcessStopEvent(const ProcessInfo& info,
        EventSource source) {
        Event evt(EventType::ProcessStop, source);
        evt.process_ = info;
        evt.process_.log_time = evt.timestamp_;  // log_time = now (stop detected)

        // For stop events the "ts" in JSON is the log time (when we detected exit),
        // not the create_time.  The create_time is still emitted as process_start_time.
        return evt;
    }

    // ---------------------------------------------------------------------------
    // CreateProcessSnapshotEvent  — ProcessSnapshot (DCStart)
    // FIX: Was incorrectly calling HandleProcessStart → EventType::ProcessStart.
    //      DCStart events represent processes ALREADY running at trace begin.
    // ---------------------------------------------------------------------------
    Event Event::CreateProcessSnapshotEvent(const ProcessInfo& info,
        EventSource source) {
        Event evt(EventType::ProcessSnapshot, source);
        evt.process_ = info;
        evt.process_.log_time = evt.timestamp_;

        static const std::chrono::system_clock::time_point kEpoch{};
        if (info.create_time != kEpoch)
            evt.timestamp_ = info.create_time;

        return evt;
    }

    Event Event::CreateNetworkEvent(const NetworkInfo& info, EventSource source) {
        Event evt(EventType::NetworkConnect, source);
        evt.network_ = info;
        return evt;
    }

    Event Event::CreateFileEvent(const FileInfo& info, EventSource source) {
        Event evt(EventType::FileCreate, source);
        evt.file_ = info;
        return evt;
    }

    Event Event::CreateRegistryEvent(const RegistryInfo& info,
        EventSource source) {
        Event evt(EventType::RegistrySet, source);
        evt.registry_ = info;
        return evt;
    }

    Event Event::CreateThreadEvent(const ThreadInfo& info, EventSource source) {
        Event evt(info.is_remote ? EventType::ThreadRemoteCreate
            : EventType::ThreadCreate,
            source);
        evt.thread_ = info;
        return evt;
    }

    Event Event::CreateCompressEvent(const CompressSummary& summary) {
        Event evt(EventType::ProcessStart, EventSource::Unknown);
        evt.compress_ = summary;
        evt.timestamp_ = summary.ts;
        evt.v3_.decision = FilterDecision::COMPRESS;
        evt.v3_.process_name = summary.process_name;
        evt.v3_.canonical_path = summary.canonical_path;
        evt.v3_.fingerprint = summary.fingerprint;
        evt.v3_.compress_count = summary.count;
        evt.v3_.window_seconds = summary.window_seconds;
        evt.v3_enriched_ = true;
        return evt;
    }

    // ============================================================================
    // GETTERS — raw sensor data
    // ============================================================================

    const ProcessInfo* Event::GetProcessInfo() const noexcept {
        return (type_ == EventType::ProcessStart || type_ == EventType::ProcessStop ||
            type_ == EventType::ProcessSnapshot)
            ? &process_
            : nullptr;
    }

    const NetworkInfo* Event::GetNetworkInfo() const noexcept {
        return (type_ == EventType::NetworkConnect ||
            type_ == EventType::NetworkDisconnect)
            ? &network_
            : nullptr;
    }

    const FileInfo* Event::GetFileInfo() const noexcept {
        return (type_ == EventType::FileCreate || type_ == EventType::FileModify ||
            type_ == EventType::FileDelete)
            ? &file_
            : nullptr;
    }

    const RegistryInfo* Event::GetRegistryInfo() const noexcept {
        return (type_ == EventType::RegistrySet || type_ == EventType::RegistryDelete)
            ? &registry_
            : nullptr;
    }

    const ThreadInfo* Event::GetThreadInfo() const noexcept {
        return (type_ == EventType::ThreadCreate ||
            type_ == EventType::ThreadRemoteCreate)
            ? &thread_
            : nullptr;
    }

    // ============================================================================
    // JSON SERIALISATION — V3
    // ============================================================================

    // ---------------------------------------------------------------------------
    // ForwardJson
    //
    // Full V3 FORWARD event shape.  Every field the detection pipeline needs.
    //
    // Shape (all process event types share the same schema; event_subtype
    // distinguishes Start / Stop / Snapshot):
    // {
    //   "ts":                "<ISO-8601 UTC microseconds>",
    //   "event_type":        "FORWARD",
    //   "event_subtype":     "process_start" | "process_stop" | "process_snapshot",
    //   "pid":               <uint32>,
    //   "parent_pid":        <uint32>,
    //   "real_parent_pid":   <uint32>,
    //   "process_name":      "<string>",
    //   "canonical_path":    "<string>",
    //   "image_path_raw":    "<string>",
    //   "command_line_raw":  "<string>",
    //   "parent_name":       "<string>",
    //   "parent_canonical_path": "<string>",
    //   "cmdline_normalized":"<string>",
    //   "location_type":     "SYSTEM|KNOWN_USER|UNKNOWN",
    //   "signature_valid":   true|false,
    //   "signature_signer":  "<string>",
    //   "child_count":       <uint32>,
    //   "unique_child_names":[...],
    //   "thread_count":      <uint32>,
    //   "duplicate_instances":<uint32>,
    //   "new_child_flag":    true|false,
    //   "dlls_new":          [...],
    //   "dlls_shadowing":    [...],
    //   "persistence_touched":true|false,
    //   "fingerprint":       "<sha256 hex>",
    //   "user_name":         "<string>",
    //   "user_sid":          "<string>",
    //   "elevation":         "default|limited|full|unknown",
    //   "integrity":         "untrusted|low|medium|high|system|unknown",
    //   "session_id":        <uint32>,
    //   "is_64bit":          true|false,
    //   "process_start_time":"<ISO-8601>"|null,
    //   "exit_time":         "<ISO-8601>"|null,   (only set for process_stop)
    //   "log_time":          "<ISO-8601>"
    // }
    // ---------------------------------------------------------------------------
    // ---------------------------------------------------------------------------
    // ForwardJson  — V3 FORWARD event.
    //
    // Smart emission: fields are omitted when they hold empty/zero/default values
    // so the JSON stays compact and meaningful.  Every emitted field has a value.
    //
    // Shape:
    // {
    //   "ts":               "<ISO-8601 UTC us>",
    //   "event_type":       "FORWARD",
    //   "event_subtype":    "process_start|process_stop|process_snapshot",
    //   "pid":              <uint32>,
    //   "process_name":     "<string>",                      // always present
    //   "canonical_path":   "<string>",                      // always present
    //   "parent_pid":       <uint32>,                        // omitted if 0
    //   "real_parent_pid":  <uint32>,                        // omitted if == parent_pid or 0
    //   "image_path_raw":   "<string>",                      // omitted if == canonical_path
    //   "command_line_raw": "<string>",                      // omitted if empty
    //   "parent_name":      "<string>",                      // omitted if empty
    //   "parent_canonical_path": "<string>",                 // omitted if empty
    //   "cmdline_normalized": "<string>",                    // omitted if empty
    //   "location_type":    "SYSTEM|KNOWN_USER|UNKNOWN",
    //   "signature_valid":  true|false,
    //   "signature_signer": "<string>",                      // omitted if empty
    //   "child_count":      <uint32>,                        // omitted if 0
    //   "unique_child_names": [...],                         // omitted if empty
    //   "thread_count":     <uint32>,                        // omitted if 0
    //   "duplicate_instances": <uint32>,                     // omitted if 0
    //   "new_child_flag":   true,                            // omitted if false
    //   "dlls_new":         [...],                           // omitted if empty
    //   "dlls_shadowing":   [...],                           // omitted if empty
    //   "persistence_touched": true,                         // omitted if false
    //   "fingerprint":      "<sha256>",                      // omitted if empty
    //   "user_name":        "<string>",                      // omitted if empty
    //   "user_sid":         "<string>",                      // omitted if empty
    //   "elevation":        "full|limited|default",          // omitted if unknown
    //   "integrity":        "medium|high|...",               // omitted if unknown
    //   "session_id":       <uint32>,                        // omitted if 0
    //   "is_64bit":         true,                            // omitted if false
    //   "process_start_time": "<ISO-8601>",                  // omitted if unset
    //   "exit_time":        "<ISO-8601>",                    // omitted if unset
    //   "log_time":         "<ISO-8601>"
    // }
    // ---------------------------------------------------------------------------
    std::string Event::ForwardJson() const {
        const V3ProcessInfo& v = v3_;

        // Helper lambdas to conditionally add fields.
        std::ostringstream j;
        

        // Open brace + mandatory timestamp fields always present.
        j << '{';

        // ── Always-present core fields ─────────────────────────────────────────────
        j << "\"ts\":\"" << FormatTimestamp(timestamp_) << "\","
            << "\"event_type\":\"FORWARD\","
            << "\"event_subtype\":\"" << utils::EventTypeToString(type_) << "\","
            << "\"pid\":" << v.pid << ','
            << "\"process_name\":\"" << EscapeJsonW(v.process_name.empty()
                ? v.image_path_raw.substr(v.image_path_raw.find_last_of(L"\\/") + 1)
                : v.process_name) << "\","
            << "\"canonical_path\":\"" << EscapeJsonW(v.canonical_path) << "\","
            << "\"location_type\":\"" << utils::LocationTypeToString(v.location_type) << "\","
            << "\"signature_valid\":" << (v.signature_valid ? "true" : "false");

        // ── Conditionally emitted fields ───────────────────────────────────────────

        // Parent PID — omit if 0 (e.g. System/Idle)
        if (v.parent_pid != 0)
            j << ",\"parent_pid\":" << v.parent_pid;

        // Real parent — only emit when it differs from parent_pid (PPID spoof signal)
        if (v.real_parent_pid != 0 && v.real_parent_pid != v.parent_pid)
            j << ",\"real_parent_pid\":" << v.real_parent_pid;

        // Raw image path — omit if identical to canonical (saves space for most procs)
        if (!v.image_path_raw.empty() && v.image_path_raw != v.canonical_path)
            j << ",\"image_path_raw\":\"" << EscapeJsonW(v.image_path_raw) << '"';

        // Command line — both raw and normalised
        if (!v.command_line_raw.empty())
            j << ",\"command_line_raw\":\"" << EscapeJsonW(v.command_line_raw) << '"';
        if (!v.cmdline_normalized.empty() && v.cmdline_normalized != v.command_line_raw)
            j << ",\"cmdline_normalized\":\"" << EscapeJsonW(v.cmdline_normalized) << '"';

        // Parent identity
        if (!v.parent_canonical_path.empty()) {
            std::wstring parent_name;
            auto pos = v.parent_canonical_path.find_last_of(L"\\/");
            parent_name = (pos != std::wstring::npos)
                ? v.parent_canonical_path.substr(pos + 1)
                : v.parent_canonical_path;
            if (!parent_name.empty())
                j << ",\"parent_name\":\"" << EscapeJsonW(parent_name) << '"';
            j << ",\"parent_canonical_path\":\"" << EscapeJsonW(v.parent_canonical_path) << '"';
        }

        // Signature signer — only when we have one
        if (!v.signature_signer.empty())
            j << ",\"signature_signer\":\"" << EscapeJsonW(v.signature_signer) << '"';

        // Fork / thread summary — only emit non-zero / non-empty values
        if (v.child_count > 0)
            j << ",\"child_count\":" << v.child_count;
        if (!v.unique_child_names.empty())
            j << ",\"unique_child_names\":" << JsonStringArray(v.unique_child_names);
        if (v.thread_count > 0)
            j << ",\"thread_count\":" << v.thread_count;
        if (v.duplicate_instances > 0)
            j << ",\"duplicate_instances\":" << v.duplicate_instances;
        if (v.new_child_flag)
            j << ",\"new_child_flag\":true";

        // DLL activity — only when actually present
        if (!v.dlls_new.empty())
            j << ",\"dlls_new\":" << JsonStringArray(v.dlls_new);
        if (!v.dlls_shadowing.empty())
            j << ",\"dlls_shadowing\":" << JsonStringArray(v.dlls_shadowing);

        // Persistence — only when touched
        if (v.persistence_touched)
            j << ",\"persistence_touched\":true";

        // Fingerprint — omit if empty (shouldn't happen post-Stage7 but defensive)
        if (!v.fingerprint.empty())
            j << ",\"fingerprint\":\"" << EscapeJson(v.fingerprint) << '"';

        // Dedup counter — useful to see how often this fingerprint has been seen
        if (v.compress_count > 0)
            j << ",\"seen_count\":" << v.compress_count;

        // User / token context — omit unknown/empty
        if (!v.user_name.empty())
            j << ",\"user_name\":\"" << EscapeJsonW(v.user_name) << '"';
        if (!v.user_sid.empty())
            j << ",\"user_sid\":\"" << EscapeJsonW(v.user_sid) << '"';
        if (v.elevation != TokenElevation::Unknown)
            j << ",\"elevation\":\"" << utils::TokenElevationToString(v.elevation) << '"';
        if (v.integrity != IntegrityLevel::Unknown)
            j << ",\"integrity\":\"" << utils::IntegrityToString(v.integrity) << '"';
        if (v.session_id != 0)
            j << ",\"session_id\":" << v.session_id;
        if (v.is_64bit)
            j << ",\"is_64bit\":true";

        // Timestamps — omit if unset (epoch)
        static const std::chrono::system_clock::time_point kEpoch{};
        if (v.create_time != kEpoch)
            j << ",\"process_start_time\":\"" << FormatTimestamp(v.create_time) << '"';
        if (v.exit_time != kEpoch)
            j << ",\"exit_time\":\"" << FormatTimestamp(v.exit_time) << '"';

        // log_time — always emit (when was this event processed by TITAN)
        {
            std::string lt = FormatTimestamp(v.log_time);
            if (lt.empty()) lt = FormatTimestamp(timestamp_); // fallback
            j << ",\"log_time\":\"" << lt << '"';
        }

        j << '}';
        return j.str();
    }

    // ---------------------------------------------------------------------------
    // CompressJson  — lightweight COMPRESS summary
    // Emits a compact line: process identity + how many times seen + window.
    // Format: x5 = seen 5 times in the dedup window — shown in "repeat_count".
    // ---------------------------------------------------------------------------
    std::string Event::CompressJson() const {
        const V3ProcessInfo& v = v3_;

        // repeat_label: human-readable "x5" means 5 occurrences compressed into one line.
        std::string repeat_label = "x" + std::to_string(v.compress_count);

        std::ostringstream j;
        j << '{';
        j << "\"ts\":\"" << FormatTimestamp(timestamp_) << "\","
            << "\"event_type\":\"COMPRESS\","
            << "\"repeat_count\":" << v.compress_count << ","
            << "\"repeat_label\":\"" << repeat_label << "\","
            << "\"window_seconds\":" << v.window_seconds << ","
            << "\"process_name\":\"" << EscapeJsonW(v.process_name) << '"';

        if (!v.canonical_path.empty())
            j << ",\"canonical_path\":\"" << EscapeJsonW(v.canonical_path) << '"';
        if (!v.fingerprint.empty())
            j << ",\"fingerprint\":\"" << EscapeJson(v.fingerprint) << '"';
        if (v.pid != 0)
            j << ",\"pid\":" << v.pid;
        if (v.parent_pid != 0)
            j << ",\"parent_pid\":" << v.parent_pid;
        if (!v.user_name.empty())
            j << ",\"user_name\":\"" << EscapeJsonW(v.user_name) << '"';
        if (v.location_type != LocationType::UNKNOWN)
            j << ",\"location_type\":\"" << utils::LocationTypeToString(v.location_type) << '"';

        j << '}';
        return j.str();
    }

    // ---------------------------------------------------------------------------
    // ToJson  — dispatch on FilterDecision
    // ---------------------------------------------------------------------------
    std::string Event::ToJson() const {
        if (!v3_enriched_ || v3_.decision == FilterDecision::FORWARD)
            return ForwardJson();
        return CompressJson();
    }

    std::wstring Event::ToJsonW() const {
        const std::string utf8 = ToJson();
        int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
            static_cast<int>(utf8.size()), nullptr, 0);
        if (needed <= 0)
            return L"{}";

        std::wstring out;
        try {
            out.resize(static_cast<size_t>(needed), L'\0');
        }
        catch (const std::length_error&) {
            return L"{}";
        }

        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()),
            out.data(), needed);
        return out;
    }

    // ============================================================================
    // EVENT BUILDER
    // ============================================================================

    EventBuilder::EventBuilder(EventType type, EventSource source)
        : event_(type, source) {
    }

    EventBuilder EventBuilder::Process(EventSource source) {
        return EventBuilder(EventType::ProcessStart, source);
    }
    EventBuilder EventBuilder::Network(EventSource source) {
        return EventBuilder(EventType::NetworkConnect, source);
    }
    EventBuilder EventBuilder::File(EventSource source) {
        return EventBuilder(EventType::FileCreate, source);
    }
    EventBuilder EventBuilder::Registry(EventSource source) {
        return EventBuilder(EventType::RegistrySet, source);
    }
    EventBuilder EventBuilder::Thread(EventSource source) {
        return EventBuilder(EventType::ThreadCreate, source);
    }

    EventBuilder& EventBuilder::Pid(DWORD pid) {
        if (event_.type_ == EventType::ProcessStart)
            event_.process_.pid = pid;
        else if (event_.type_ == EventType::NetworkConnect)
            event_.network_.pid = pid;
        return *this;
    }

    EventBuilder& EventBuilder::ParentPid(DWORD pid) {
        event_.process_.parent_pid = pid;
        return *this;
    }
    EventBuilder& EventBuilder::RealParentPid(DWORD pid) {
        event_.process_.real_parent_pid = pid;
        return *this;
    }
    EventBuilder& EventBuilder::ImagePath(std::wstring p) {
        event_.process_.image_path = std::move(p);
        return *this;
    }
    EventBuilder& EventBuilder::CommandLine(std::wstring c) {
        event_.process_.command_line = std::move(c);
        return *this;
    }
    EventBuilder& EventBuilder::User(std::wstring user, std::wstring sid) {
        event_.process_.user_name = std::move(user);
        event_.process_.user_sid = std::move(sid);
        return *this;
    }
    EventBuilder& EventBuilder::Token(TokenElevation elevation,
        IntegrityLevel integrity) {
        event_.process_.elevation = elevation;
        event_.process_.integrity = integrity;
        return *this;
    }
    EventBuilder& EventBuilder::LocalEndpoint(const std::string& addr,
        USHORT port) {
        event_.network_.local_addr = addr;
        event_.network_.local_port = port;
        return *this;
    }
    EventBuilder& EventBuilder::RemoteEndpoint(const std::string& addr,
        USHORT port) {
        event_.network_.remote_addr = addr;
        event_.network_.remote_port = port;
        return *this;
    }
    EventBuilder& EventBuilder::Protocol(bool tcp, bool ipv6) {
        event_.network_.is_tcp = tcp;
        event_.network_.is_ipv6 = ipv6;
        return *this;
    }
    EventBuilder& EventBuilder::DnsInfo(std::wstring query, std::wstring answer) {
        event_.network_.dns_query = std::move(query);
        event_.network_.dns_answer = std::move(answer);
        return *this;
    }

    Event EventBuilder::Build() { return std::move(event_); }

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    std::string utils::EventTypeToString(EventType type) {
        switch (type) {
        case EventType::ProcessStart:        return "process_start";
        case EventType::ProcessStop:         return "process_stop";
        case EventType::ProcessSnapshot:     return "process_snapshot";
        case EventType::NetworkConnect:      return "network_connect";
        case EventType::NetworkDisconnect:   return "network_disconnect";
        case EventType::FileCreate:          return "file_create";
        case EventType::FileModify:          return "file_modify";
        case EventType::FileDelete:          return "file_delete";
        case EventType::RegistrySet:         return "registry_set";
        case EventType::RegistryDelete:      return "registry_delete";
        case EventType::ThreadCreate:        return "thread_create";
        case EventType::ThreadRemoteCreate:  return "thread_remote_create";
        default:                             return "unknown";
        }
    }

    std::string utils::EventSourceToString(EventSource source) {
        switch (source) {
        case EventSource::EtwKernelProcess:      return "etw_kernel_process";
        case EventSource::EtwKernelNetwork:      return "etw_kernel_network";
        case EventSource::EtwKernelFile:         return "etw_kernel_file";
        case EventSource::EtwKernelRegistry:     return "etw_kernel_registry";
        case EventSource::EtwThreatIntelligence: return "etw_threat_intel";
        case EventSource::SysmonDns:             return "sysmon_dns";
        case EventSource::KernelCallback:        return "kernel_callback";
        default:                                 return "unknown";
        }
    }

    std::string utils::TokenElevationToString(TokenElevation elevation) {
        switch (elevation) {
        case TokenElevation::Default: return "default";
        case TokenElevation::Limited: return "limited";
        case TokenElevation::Full:    return "full";
        default:                      return "unknown";
        }
    }

    std::string utils::IntegrityToString(IntegrityLevel integrity) {
        switch (integrity) {
        case IntegrityLevel::Untrusted: return "untrusted";
        case IntegrityLevel::Low:       return "low";
        case IntegrityLevel::Medium:    return "medium";
        case IntegrityLevel::High:      return "high";
        case IntegrityLevel::System:    return "system";
        default:                        return "unknown";
        }
    }

    std::string utils::LocationTypeToString(LocationType loc) {
        switch (loc) {
        case LocationType::SYSTEM:     return "SYSTEM";
        case LocationType::KNOWN_USER: return "KNOWN_USER";
        default:                       return "UNKNOWN";
        }
    }

    std::string utils::FilterDecisionToString(FilterDecision decision) {
        switch (decision) {
        case FilterDecision::FORWARD:  return "FORWARD";
        case FilterDecision::COMPRESS: return "COMPRESS";
        default:                       return "FORWARD";
        }
    }

    // ---------------------------------------------------------------------------
    // DevicePathToDrivePath
    // ---------------------------------------------------------------------------
    std::wstring utils::DevicePathToDrivePath(const std::wstring& device_path) {
        if (device_path.empty() || device_path[0] != L'\\')
            return device_path;

        wchar_t drives[512]{};
        if (!GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives))
            return device_path;

        for (const wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
            wchar_t device[512]{};
            wchar_t letter[3] = { drive[0], drive[1], L'\0' };

            if (QueryDosDeviceW(letter, device, static_cast<DWORD>(std::size(device)))) {
                const size_t dev_len = wcslen(device);
                if (device_path.compare(0, dev_len, device) == 0)
                    return std::wstring(letter) + device_path.substr(dev_len);
            }
        }

        return device_path;
    }

    // ---------------------------------------------------------------------------
    // GetIntegrityFromToken
    // ---------------------------------------------------------------------------
    IntegrityLevel utils::GetIntegrityFromToken(HANDLE hToken) {
        DWORD return_length = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &return_length);
        if (return_length == 0)
            return IntegrityLevel::Unknown;

        auto* til =
            static_cast<TOKEN_MANDATORY_LABEL*>(LocalAlloc(LPTR, return_length));
        if (!til)
            return IntegrityLevel::Unknown;

        DWORD level = 0;
        if (GetTokenInformation(hToken, TokenIntegrityLevel, til, return_length,
            &return_length)) {
            level = *GetSidSubAuthority(
                til->Label.Sid,
                static_cast<DWORD>(
                    static_cast<UCHAR>(*GetSidSubAuthorityCount(til->Label.Sid) - 1)));
        }
        LocalFree(til);

        if (level < SECURITY_MANDATORY_LOW_RID)    return IntegrityLevel::Untrusted;
        if (level < SECURITY_MANDATORY_MEDIUM_RID) return IntegrityLevel::Low;
        if (level < SECURITY_MANDATORY_HIGH_RID)   return IntegrityLevel::Medium;
        if (level < SECURITY_MANDATORY_SYSTEM_RID) return IntegrityLevel::High;
        return IntegrityLevel::System;
    }

    // ---------------------------------------------------------------------------
    // CanonicalizePath
    // ---------------------------------------------------------------------------
    std::wstring utils::CanonicalizePath(const std::wstring& raw_path) {
        if (raw_path.empty() || raw_path.size() > 32767)
            return {};

        wchar_t expanded[MAX_PATH * 2]{};
        DWORD exp_res = ExpandEnvironmentStringsW(
            raw_path.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
        if (exp_res == 0 || exp_res > std::size(expanded))
            return {};
        expanded[std::size(expanded) - 1] = L'\0';

        std::wstring working;
        try {
            working = DevicePathToDrivePath(expanded);
        }
        catch (...) {
            return {};
        }

        wchar_t full[MAX_PATH * 2]{};
        DWORD full_res = GetFullPathNameW(
            working.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
        if (full_res == 0 || full_res > std::size(full))
            return {};
        full[std::size(full) - 1] = L'\0';

        wchar_t longp[MAX_PATH * 2]{};
        DWORD long_res =
            GetLongPathNameW(full, longp, static_cast<DWORD>(std::size(longp)));
        if (long_res == 0 || long_res > std::size(longp)) {
            wcscpy_s(longp, std::size(longp), full);
        }
        else {
            longp[std::size(longp) - 1] = L'\0';
        }

        std::wstring result;
        try {
            result.assign(longp);
        }
        catch (...) {
            return {};
        }

        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }

    // ---------------------------------------------------------------------------
    // NormalizeCommandLine
    // ---------------------------------------------------------------------------
    std::wstring utils::NormalizeCommandLine(const std::wstring& cmdline) {
        if (cmdline.empty())
            return {};

        std::wstring safe_cmdline = cmdline;
        if (safe_cmdline.size() > 4096)
            safe_cmdline.resize(4096);

        int needed =
            NormalizeString(NormalizationC, safe_cmdline.c_str(),
                static_cast<int>(safe_cmdline.size()), nullptr, 0);
        std::wstring nfc;
        if (needed > 0 && needed < 32768) {
            nfc.resize(static_cast<size_t>(needed));
            int written = NormalizeString(NormalizationC, safe_cmdline.c_str(),
                static_cast<int>(safe_cmdline.size()),
                nfc.data(), needed);
            if (written > 0)
                nfc.resize(static_cast<size_t>(written));
            else
                nfc = safe_cmdline;
        }
        else {
            nfc = safe_cmdline;
        }

        std::transform(nfc.begin(), nfc.end(), nfc.begin(), ::towlower);

        std::wstring collapsed;
        collapsed.reserve(nfc.size());
        bool last_was_space = false;
        for (wchar_t c : nfc) {
            if (std::iswspace(c)) {
                if (!last_was_space)
                    collapsed += L' ';
                last_was_space = true;
            }
            else {
                collapsed += c;
                last_was_space = false;
            }
        }

        if (collapsed.size() > 256)
            collapsed.resize(256);

        return collapsed;
    }

} // namespace titan