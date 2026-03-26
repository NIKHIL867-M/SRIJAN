#include "event.h"

// Winsock2 MUST come before windows.h — event.h pulls windows.h,
// so we force winsock2 first via the pragma.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>      // BCrypt SHA-256 (Sha256Hex)
#include <algorithm>
#include <cwctype>       // std::iswspace, std::towlower
#include <iomanip>
#include <sstream>

#pragma comment(lib, "normaliz.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

// ============================================================================
// event.cpp  —  TITAN V4
//
// V4 additions vs V3:
//   - ForwardJson() now serialises the full NetworkInfo enrichment block
//     when the event type is NetworkConnect / NetworkPacket.
//   - New utils: NetworkDirectionToString, TcpStateToString, AppLayerToString,
//     ResolveHostname.
//   - All wstring/string helpers ported to MSVC (/W4 /WX /permissive-).
// ============================================================================

namespace titan {

    // ============================================================================
    // INTERNAL HELPERS (anonymous namespace)
    // ============================================================================

    namespace {

        // ---------------------------------------------------------------------------
        // WstringToUtf8
        // ---------------------------------------------------------------------------
        static std::string WstringToUtf8(const std::wstring& wstr) {
            if (wstr.empty()) return {};
            if (wstr.data() == nullptr) return {};
            if (wstr.size() > 65536) return "ERROR_PATH_TOO_LONG";

            int needed = WideCharToMultiByte(CP_UTF8, 0,
                wstr.data(), static_cast<int>(wstr.size()),
                nullptr, 0, nullptr, nullptr);
            if (needed <= 0 || needed > 131072) return {};

            std::string out;
            try { out.resize(static_cast<size_t>(needed)); }
            catch (const std::length_error&) { return "ERROR_ALLOCATION_FAILED"; }

            WideCharToMultiByte(CP_UTF8, 0,
                wstr.data(), static_cast<int>(wstr.size()),
                out.data(), needed, nullptr, nullptr);
            return out;
        }

        // ---------------------------------------------------------------------------
        // EscapeJson
        // ---------------------------------------------------------------------------
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
                    if (c < 0x20)
                        o << "\\u" << std::hex << std::setw(4)
                        << std::setfill('0') << static_cast<int>(c) << std::dec;
                    else
                        o << c;
                }
            }
            return o.str();
        }

        static std::string EscapeJsonW(const std::wstring& ws) {
            return EscapeJson(WstringToUtf8(ws));
        }

        // ---------------------------------------------------------------------------
        // FormatTimestamp  — ISO-8601 + microseconds, always UTC ("Z")
        // ---------------------------------------------------------------------------
        static std::string FormatTimestamp(
            const std::chrono::system_clock::time_point& tp)
        {
            auto tt = std::chrono::system_clock::to_time_t(tp);
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                tp.time_since_epoch()) % 1'000'000;
            std::tm gmt{};
            gmtime_s(&gmt, &tt);
            std::ostringstream oss;
            oss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%S");
            oss << '.' << std::setfill('0') << std::setw(6) << us.count() << 'Z';
            return oss.str();
        }

        // ---------------------------------------------------------------------------
        // JsonStringArray
        // ---------------------------------------------------------------------------
        static std::string JsonStringArray(const std::vector<std::wstring>& vec) {
            std::ostringstream o;
            o << '[';
            for (size_t i = 0; i < vec.size(); ++i) {
                if (i) o << ',';
                o << '"' << EscapeJsonW(vec[i]) << '"';
            }
            o << ']';
            return o.str();
        }

        // ---------------------------------------------------------------------------
        // OptStr / OptWStr helpers — emit "null" or quoted escaped string
        // ---------------------------------------------------------------------------
        static std::string OptStr(const std::optional<std::string>& opt) {
            if (!opt.has_value()) return "null";
            return '"' + EscapeJson(*opt) + '"';
        }
        static std::string OptWStr(const std::optional<std::wstring>& opt) {
            if (!opt.has_value()) return "null";
            return '"' + EscapeJsonW(*opt) + '"';
        }
        static std::string OptU8(const std::optional<uint8_t>& opt) {
            if (!opt.has_value()) return "null";
            return std::to_string(static_cast<unsigned>(*opt));
        }

    } // anonymous namespace

    // ============================================================================
    // EVENT FACTORY METHODS
    // ============================================================================

    Event::Event(EventType type, EventSource source)
        : type_(type), source_(source),
        timestamp_(std::chrono::system_clock::now()) {
    }

    Event Event::CreateProcessEvent(const ProcessInfo& info, EventSource source) {
        Event evt(EventType::ProcessStart, source);
        evt.process_ = info;
        evt.process_.log_time = evt.timestamp_;
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
    Event Event::CreateRegistryEvent(const RegistryInfo& info, EventSource source) {
        Event evt(EventType::RegistrySet, source);
        evt.registry_ = info;
        return evt;
    }
    Event Event::CreateThreadEvent(const ThreadInfo& info, EventSource source) {
        Event evt(info.is_remote
            ? EventType::ThreadRemoteCreate
            : EventType::ThreadCreate, source);
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
    // GETTERS
    // ============================================================================

    const ProcessInfo* Event::GetProcessInfo() const noexcept {
        return (type_ == EventType::ProcessStart ||
            type_ == EventType::ProcessStop ||
            type_ == EventType::ProcessSnapshot) ? &process_ : nullptr;
    }
    const NetworkInfo* Event::GetNetworkInfo() const noexcept {
        return (type_ == EventType::NetworkConnect ||
            type_ == EventType::NetworkDisconnect ||
            type_ == EventType::NetworkPacket) ? &network_ : nullptr;
    }
    const FileInfo* Event::GetFileInfo() const noexcept {
        return (type_ == EventType::FileCreate ||
            type_ == EventType::FileModify ||
            type_ == EventType::FileDelete) ? &file_ : nullptr;
    }
    const RegistryInfo* Event::GetRegistryInfo() const noexcept {
        return (type_ == EventType::RegistrySet ||
            type_ == EventType::RegistryDelete) ? &registry_ : nullptr;
    }
    const ThreadInfo* Event::GetThreadInfo() const noexcept {
        return (type_ == EventType::ThreadCreate ||
            type_ == EventType::ThreadRemoteCreate) ? &thread_ : nullptr;
    }

    // ============================================================================
    // JSON SERIALISATION — V4
    // ============================================================================

    // ---------------------------------------------------------------------------
    // ForwardJson
    //
    // For process events  → same V3 shape + any new V4 process fields
    // For network events  → full V4 enriched network shape
    // For file events     → file shape
    // For registry events → registry shape
    // For thread events   → thread shape
    // ---------------------------------------------------------------------------
    std::string Event::ForwardJson() const {
        std::ostringstream j;
        j << '{';

        j << "\"ts\":\"" << FormatTimestamp(timestamp_) << "\",";
        j << "\"event_type\":\"FORWARD\",";
        j << "\"source\":\"" << utils::EventSourceToString(source_) << "\",";

        // ----------------------------------------------------------------
        // NETWORK EVENT — clean network-only shape
        // ----------------------------------------------------------------
        if (type_ == EventType::NetworkConnect ||
            type_ == EventType::NetworkDisconnect ||
            type_ == EventType::NetworkPacket)
        {
            const NetworkInfo& n = network_;

            j << "\"record_type\":\"" << utils::EventTypeToString(type_) << "\",";

            // Process identity (pid + short name only — no path, no hash, no user)
            j << "\"pid\":" << n.pid << ',';
            j << "\"process_name\":\"" << EscapeJsonW(n.process_name) << "\",";

            // Socket 5-tuple
            j << "\"src_ip\":\"" << EscapeJson(n.local_addr) << "\",";
            j << "\"src_port\":" << n.local_port << ',';
            j << "\"dst_ip\":\"" << EscapeJson(n.remote_addr) << "\",";
            j << "\"dst_port\":" << n.remote_port << ',';
            j << "\"protocol\":\"" << utils::AppLayerToString(n.app_layer) << "\",";
            j << "\"ipv6\":" << (n.is_ipv6 ? "true" : "false") << ',';

            // Direction & state
            j << "\"direction\":\"" << utils::NetworkDirectionToString(n.direction) << "\",";
            j << "\"state\":\"" << utils::TcpStateToString(n.tcp_state) << "\",";

            // Data volume
            j << "\"bytes_sent\":" << n.bytes_sent << ',';
            j << "\"bytes_recv\":" << n.bytes_recv << ',';
            j << "\"packet_count\":" << n.packet_count << ',';
            j << "\"flow_duration_ms\":" << n.flow_duration_ms << ',';

            // Flags
            j << "\"is_broadcast\":" << (n.is_broadcast ? "true" : "false") << ',';
            j << "\"is_loopback\":" << (n.is_loopback ? "true" : "false");

            j << '}';
            return j.str();
        }

        // ----------------------------------------------------------------
        // PROCESS EVENT — V3-compatible shape (same fields, no severity)
        // ----------------------------------------------------------------
        if (type_ == EventType::ProcessStart ||
            type_ == EventType::ProcessStop ||
            type_ == EventType::ProcessSnapshot)
        {
            const V3ProcessInfo& v = v3_;

            j << "\"record_type\":\"" << utils::EventTypeToString(type_) << "\",";
            j << "\"process_name\":\"" << EscapeJsonW(v.process_name) << "\",";
            j << "\"canonical_path\":\"" << EscapeJsonW(v.canonical_path) << "\",";

            {
                std::wstring parent_name;
                if (!v.parent_canonical_path.empty()) {
                    auto pos = v.parent_canonical_path.find_last_of(L"\\/");
                    parent_name = (pos != std::wstring::npos)
                        ? v.parent_canonical_path.substr(pos + 1)
                        : v.parent_canonical_path;
                }
                j << "\"parent_name\":\"" << EscapeJsonW(parent_name) << "\",";
                j << "\"parent_canonical_path\":\"" << EscapeJsonW(v.parent_canonical_path) << "\",";
            }

            j << "\"cmdline_normalized\":\"" << EscapeJsonW(v.cmdline_normalized) << "\",";
            j << "\"location_type\":\"" << utils::LocationTypeToString(v.location_type) << "\",";
            j << "\"signature_valid\":" << (v.signature_valid ? "true" : "false") << ',';
            j << "\"signature_signer\":\"" << EscapeJsonW(v.signature_signer) << "\",";

            j << "\"child_count\":" << v.child_count << ',';
            j << "\"unique_child_names\":" << JsonStringArray(v.unique_child_names) << ',';
            j << "\"thread_count\":" << v.thread_count << ',';
            j << "\"duplicate_instances\":" << v.duplicate_instances << ',';
            j << "\"new_child_flag\":" << (v.new_child_flag ? "true" : "false") << ',';

            j << "\"dlls_new\":" << JsonStringArray(v.dlls_new) << ',';
            j << "\"dlls_shadowing\":" << JsonStringArray(v.dlls_shadowing) << ',';

            j << "\"persistence_touched\":" << (v.persistence_touched ? "true" : "false") << ',';
            j << "\"fingerprint\":\"" << EscapeJson(v.fingerprint) << '"';

            j << '}';
            return j.str();
        }

        // ----------------------------------------------------------------
        // FILE EVENT
        // ----------------------------------------------------------------
        if (type_ == EventType::FileCreate ||
            type_ == EventType::FileModify ||
            type_ == EventType::FileDelete)
        {
            const FileInfo& f = file_;
            j << "\"record_type\":\"" << utils::EventTypeToString(type_) << "\",";
            j << "\"pid\":" << f.pid << ',';
            j << "\"process_name\":\"" << EscapeJsonW(f.process_name) << "\",";
            j << "\"file_path\":\"" << EscapeJsonW(f.file_path) << "\",";
            j << "\"original_path\":\"" << EscapeJsonW(f.original_path) << "\",";
            j << "\"is_create\":" << (f.is_create ? "true" : "false") << ',';
            j << "\"is_modify\":" << (f.is_modify ? "true" : "false") << ',';
            j << "\"is_delete\":" << (f.is_delete ? "true" : "false");
            j << '}';
            return j.str();
        }

        // ----------------------------------------------------------------
        // REGISTRY EVENT
        // ----------------------------------------------------------------
        if (type_ == EventType::RegistrySet ||
            type_ == EventType::RegistryDelete)
        {
            const RegistryInfo& r = registry_;
            j << "\"record_type\":\"" << utils::EventTypeToString(type_) << "\",";
            j << "\"pid\":" << r.pid << ',';
            j << "\"process_name\":\"" << EscapeJsonW(r.process_name) << "\",";
            j << "\"key_path\":\"" << EscapeJsonW(r.key_path) << "\",";
            j << "\"value_name\":\"" << EscapeJsonW(r.value_name) << "\",";
            j << "\"is_delete\":" << (r.is_delete ? "true" : "false");
            j << '}';
            return j.str();
        }

        // ----------------------------------------------------------------
        // THREAD EVENT (including remote injection)
        // ----------------------------------------------------------------
        if (type_ == EventType::ThreadCreate ||
            type_ == EventType::ThreadRemoteCreate)
        {
            const ThreadInfo& t = thread_;
            j << "\"record_type\":\"" << utils::EventTypeToString(type_) << "\",";
            j << "\"source_pid\":" << t.source_pid << ',';
            j << "\"target_pid\":" << t.target_pid << ',';
            j << "\"source_tid\":" << t.source_tid << ',';
            j << "\"target_tid\":" << t.target_tid << ',';
            j << "\"start_address\":" << t.start_address << ',';
            j << "\"is_remote\":" << (t.is_remote ? "true" : "false");
            j << '}';
            return j.str();
        }

        // Fallback
        j << "\"record_type\":\"unknown\"}";
        return j.str();
    }

    // ---------------------------------------------------------------------------
    // CompressJson  —  lightweight COMPRESS summary shape
    // ---------------------------------------------------------------------------
    std::string Event::CompressJson() const {
        const V3ProcessInfo& v = v3_;
        std::ostringstream j;
        j << '{';
        j << "\"ts\":\"" << FormatTimestamp(timestamp_) << "\",";
        j << "\"event_type\":\"COMPRESS\",";
        j << "\"process_name\":\"" << EscapeJsonW(v.process_name) << "\",";
        j << "\"canonical_path\":\"" << EscapeJsonW(v.canonical_path) << "\",";
        j << "\"fingerprint\":\"" << EscapeJson(v.fingerprint) << "\",";
        j << "\"count\":" << v.compress_count << ',';
        j << "\"window_seconds\":" << v.window_seconds;
        j << '}';
        return j.str();
    }

    // ---------------------------------------------------------------------------
    // ToJson  —  dispatch
    // ---------------------------------------------------------------------------
    std::string Event::ToJson() const {
        if (!v3_enriched_ || v3_.decision == FilterDecision::FORWARD)
            return ForwardJson();
        return CompressJson();
    }

    std::wstring Event::ToJsonW() const {
        const std::string utf8 = ToJson();
        int needed = MultiByteToWideChar(CP_UTF8, 0,
            utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
        if (needed <= 0) return L"{}";

        std::wstring out;
        try { out.resize(static_cast<size_t>(needed), L'\0'); }
        catch (const std::length_error&) { return L"{}"; }

        MultiByteToWideChar(CP_UTF8, 0,
            utf8.c_str(), static_cast<int>(utf8.size()),
            out.data(), needed);
        return out;
    }

    // ============================================================================
    // EVENT BUILDER
    // ============================================================================

    EventBuilder::EventBuilder(EventType type, EventSource source)
        : event_(type, source) {
    }

    EventBuilder EventBuilder::Process(EventSource src) { return EventBuilder(EventType::ProcessStart, src); }
    EventBuilder EventBuilder::Network(EventSource src) { return EventBuilder(EventType::NetworkConnect, src); }
    EventBuilder EventBuilder::File(EventSource src) { return EventBuilder(EventType::FileCreate, src); }
    EventBuilder EventBuilder::Registry(EventSource src) { return EventBuilder(EventType::RegistrySet, src); }
    EventBuilder EventBuilder::Thread(EventSource src) { return EventBuilder(EventType::ThreadCreate, src); }

    EventBuilder& EventBuilder::Pid(DWORD pid) {
        if (event_.type_ == EventType::ProcessStart) event_.process_.pid = pid;
        else if (event_.type_ == EventType::NetworkConnect) event_.network_.pid = pid;
        return *this;
    }
    EventBuilder& EventBuilder::ParentPid(DWORD pid) { event_.process_.parent_pid = pid;       return *this; }
    EventBuilder& EventBuilder::RealParentPid(DWORD pid) { event_.process_.real_parent_pid = pid;       return *this; }
    EventBuilder& EventBuilder::ImagePath(std::wstring p) { event_.process_.image_path = std::move(p); return *this; }
    EventBuilder& EventBuilder::CommandLine(std::wstring c) { event_.process_.command_line = std::move(c); return *this; }
    EventBuilder& EventBuilder::User(std::wstring user, std::wstring sid) {
        event_.process_.user_name = std::move(user);
        event_.process_.user_sid = std::move(sid);
        return *this;
    }
    EventBuilder& EventBuilder::Token(TokenElevation elev, IntegrityLevel integ) {
        event_.process_.elevation = elev;
        event_.process_.integrity = integ;
        return *this;
    }
    EventBuilder& EventBuilder::LocalEndpoint(const std::string& addr, USHORT port) {
        event_.network_.local_addr = addr; event_.network_.local_port = port;
        return *this;
    }
    EventBuilder& EventBuilder::RemoteEndpoint(const std::string& addr, USHORT port) {
        event_.network_.remote_addr = addr; event_.network_.remote_port = port;
        return *this;
    }
    EventBuilder& EventBuilder::Protocol(bool tcp, bool ipv6) {
        event_.network_.is_tcp = tcp;
        event_.network_.is_ipv6 = ipv6;
        return *this;
    }

    Event EventBuilder::Build() { return std::move(event_); }

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    std::string utils::EventTypeToString(EventType type) {
        switch (type) {
        case EventType::ProcessStart:       return "process_start";
        case EventType::ProcessStop:        return "process_stop";
        case EventType::ProcessSnapshot:    return "process_snapshot";
        case EventType::NetworkConnect:     return "network_connect";
        case EventType::NetworkDisconnect:  return "network_disconnect";
        case EventType::NetworkPacket:      return "network_packet";
        case EventType::FileCreate:         return "file_create";
        case EventType::FileModify:         return "file_modify";
        case EventType::FileDelete:         return "file_delete";
        case EventType::RegistrySet:        return "registry_set";
        case EventType::RegistryDelete:     return "registry_delete";
        case EventType::ThreadCreate:       return "thread_create";
        case EventType::ThreadRemoteCreate: return "thread_remote_create";
        default:                            return "unknown";
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
        case EventSource::NpcapLive:             return "npcap_live";
        default:                                 return "unknown";
        }
    }
    std::string utils::TokenElevationToString(TokenElevation e) {
        switch (e) {
        case TokenElevation::Default: return "default";
        case TokenElevation::Limited: return "limited";
        case TokenElevation::Full:    return "full";
        default:                      return "unknown";
        }
    }
    std::string utils::IntegrityToString(IntegrityLevel i) {
        switch (i) {
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
    std::string utils::FilterDecisionToString(FilterDecision d) {
        return (d == FilterDecision::COMPRESS) ? "COMPRESS" : "FORWARD";
    }
    std::string utils::NetworkDirectionToString(NetworkDirection dir) {
        switch (dir) {
        case NetworkDirection::INBOUND:  return "INBOUND";
        case NetworkDirection::OUTBOUND: return "OUTBOUND";
        default:                         return "UNKNOWN";
        }
    }
    std::string utils::TcpStateToString(TcpState state) {
        switch (state) {
        case TcpState::SYN_SENT:      return "SYN_SENT";
        case TcpState::SYN_RECEIVED:  return "SYN_RECEIVED";
        case TcpState::ESTABLISHED:   return "ESTABLISHED";
        case TcpState::FIN_WAIT:      return "FIN_WAIT";
        case TcpState::CLOSE_WAIT:    return "CLOSE_WAIT";
        case TcpState::CLOSED:        return "CLOSED";
        default:                      return "UNKNOWN";
        }
    }
    std::string utils::AppLayerToString(AppLayer app) {
        switch (app) {
        case AppLayer::HTTP:       return "HTTP";
        case AppLayer::HTTPS_TLS:  return "HTTPS_TLS";
        case AppLayer::DNS:        return "DNS";
        case AppLayer::RDP:        return "RDP";
        case AppLayer::SMB:        return "SMB";
        case AppLayer::QUIC:       return "QUIC";
        case AppLayer::ICMP:       return "ICMP";
        case AppLayer::NTP:        return "NTP";
        case AppLayer::DHCP:       return "DHCP";
        case AppLayer::FTP:        return "FTP";
        case AppLayer::SSH:        return "SSH";
        case AppLayer::SMTP:       return "SMTP";
        default:                   return "UNKNOWN";
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
        if (return_length == 0) return IntegrityLevel::Unknown;

        auto* til = static_cast<TOKEN_MANDATORY_LABEL*>(LocalAlloc(LPTR, return_length));
        if (!til) return IntegrityLevel::Unknown;

        DWORD level = 0;
        if (GetTokenInformation(hToken, TokenIntegrityLevel, til, return_length, &return_length)) {
            level = *GetSidSubAuthority(til->Label.Sid,
                static_cast<DWORD>(static_cast<UCHAR>(
                    *GetSidSubAuthorityCount(til->Label.Sid) - 1)));
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
        if (raw_path.empty() || raw_path.size() > 32767) return {};

        wchar_t expanded[MAX_PATH * 2]{};
        DWORD exp_res = ExpandEnvironmentStringsW(
            raw_path.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
        if (exp_res == 0 || exp_res > std::size(expanded)) return {};
        expanded[std::size(expanded) - 1] = L'\0';

        std::wstring working;
        try { working = DevicePathToDrivePath(expanded); }
        catch (...) { return {}; }

        wchar_t full[MAX_PATH * 2]{};
        DWORD full_res = GetFullPathNameW(
            working.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
        if (full_res == 0 || full_res > std::size(full)) return {};
        full[std::size(full) - 1] = L'\0';

        wchar_t longp[MAX_PATH * 2]{};
        DWORD long_res = GetLongPathNameW(
            full, longp, static_cast<DWORD>(std::size(longp)));
        if (long_res == 0 || long_res > std::size(longp))
            wcscpy_s(longp, std::size(longp), full);
        else
            longp[std::size(longp) - 1] = L'\0';

        std::wstring result;
        try { result.assign(longp); }
        catch (...) { return {}; }

        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) -> wchar_t { return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c))); });
        return result;
    }

    // ---------------------------------------------------------------------------
    // NormalizeCommandLine
    // ---------------------------------------------------------------------------
    std::wstring utils::NormalizeCommandLine(const std::wstring& cmdline) {
        if (cmdline.empty()) return {};

        std::wstring safe = cmdline;
        if (safe.size() > 4096) safe.resize(4096);

        int needed = NormalizeString(NormalizationC,
            safe.c_str(), static_cast<int>(safe.size()), nullptr, 0);
        std::wstring nfc;
        if (needed > 0 && needed < 32768) {
            nfc.resize(static_cast<size_t>(needed));
            int written = NormalizeString(NormalizationC,
                safe.c_str(), static_cast<int>(safe.size()),
                nfc.data(), needed);
            if (written > 0) nfc.resize(static_cast<size_t>(written));
            else             nfc = safe;
        }
        else {
            nfc = safe;
        }

        std::transform(nfc.begin(), nfc.end(), nfc.begin(),
            [](wchar_t c) -> wchar_t { return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c))); });

        std::wstring collapsed;
        collapsed.reserve(nfc.size());
        bool last_space = false;
        for (wchar_t c : nfc) {
            if (std::iswspace(c)) {
                if (!last_space) collapsed += L' ';
                last_space = true;
            }
            else {
                collapsed += c;
                last_space = false;
            }
        }
        if (collapsed.size() > 256) collapsed.resize(256);
        return collapsed;
    }

    // ---------------------------------------------------------------------------
    // Sha256Hex  (BCrypt — no OpenSSL dependency)
    // ---------------------------------------------------------------------------
    std::string utils::Sha256Hex(const std::string& data) {
        BCRYPT_ALG_HANDLE  alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD hash_len = 0, result_len = 0;
        std::string hex;

        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return {};
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len),
            &result_len, 0) != 0) goto cleanup;
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0)
            goto cleanup;

        if (BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0) != 0) goto cleanup;
        {
            std::vector<BYTE> digest(hash_len);
            if (BCryptFinishHash(hash, digest.data(), hash_len, 0) == 0) {
                std::ostringstream oss;
                for (BYTE b : digest)
                    oss << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(b);
                hex = oss.str();
            }
        }

    cleanup:
        if (hash) BCryptDestroyHash(hash);
        if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
        return hex;
    }

    // ---------------------------------------------------------------------------
    // ResolveHostname — PTR lookup via getnameinfo (winsock2)
    // Returns empty string on failure; called from NetworkMonitor per flow.
    // ---------------------------------------------------------------------------
    std::string utils::ResolveHostname(const std::string& ip_str) {
        if (ip_str.empty()) return {};

        // Try IPv4
        sockaddr_in sa4{};
        sa4.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip_str.c_str(), &sa4.sin_addr) == 1) {
            char host[NI_MAXHOST]{};
            if (getnameinfo(reinterpret_cast<sockaddr*>(&sa4),
                sizeof(sa4), host, NI_MAXHOST,
                nullptr, 0, NI_NAMEREQD) == 0)
                return host;
            return {};
        }

        // Try IPv6
        sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ip_str.c_str(), &sa6.sin6_addr) == 1) {
            char host[NI_MAXHOST]{};
            if (getnameinfo(reinterpret_cast<sockaddr*>(&sa6),
                sizeof(sa6), host, NI_MAXHOST,
                nullptr, 0, NI_NAMEREQD) == 0)
                return host;
        }
        return {};
    }

} // namespace titan