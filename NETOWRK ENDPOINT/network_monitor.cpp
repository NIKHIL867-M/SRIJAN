#include "network_monitor.h"

// network_monitor.h already pulls in winsock2/ws2tcpip/iphlpapi in correct order.
// Add remaining needed headers here:
// winternl.h intentionally omitted: conflicts with /permissive- NTSTATUS typedef.
// PROCESS_BASIC_INFORMATION replaced with local PBI struct inside functions.
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cwctype>       // std::iswspace

// Net headers (platform pack ordering matters under MSVC)
#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ether_type; // big-endian
};
struct Ipv4Header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
};
struct Ipv6Header {
    uint32_t ver_tc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
};
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset; // upper 4 bits = header len in 32-bit words
    uint8_t  flags;       // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};
#pragma pack(pop)

static constexpr uint16_t kEtherTypeIPv4 = 0x0800;
static constexpr uint16_t kEtherTypeIPv6 = 0x86DD;

// TCP flag bits
static constexpr uint8_t kTcpSyn = 0x02;
static constexpr uint8_t kTcpAck = 0x10;
static constexpr uint8_t kTcpFin = 0x01;
static constexpr uint8_t kTcpRst = 0x04;

namespace titan {

    // ============================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ============================================================================

    NetworkMonitor::NetworkMonitor(AsyncLogger& logger, FilterEngine& filter)
        : logger_(logger), filter_(filter)
    {
        BuildPortAppMap();
    }

    NetworkMonitor::~NetworkMonitor() {
        if (running_.load()) Stop();
    }

    // ============================================================================
    // PORT → APP LAYER MAP
    // ============================================================================

    void NetworkMonitor::BuildPortAppMap() {
        port_app_map_ = {
            {80,   AppLayer::HTTP},
            {8080, AppLayer::HTTP},
            {8000, AppLayer::HTTP},
            {443,  AppLayer::HTTPS_TLS},
            {8443, AppLayer::HTTPS_TLS},
            {53,   AppLayer::DNS},
            {3389, AppLayer::RDP},
            {445,  AppLayer::SMB},
            {137,  AppLayer::SMB},
            {138,  AppLayer::SMB},
            {139,  AppLayer::SMB},
            {21,   AppLayer::FTP},
            {22,   AppLayer::SSH},
            {25,   AppLayer::SMTP},
            {587,  AppLayer::SMTP},
            {123,  AppLayer::NTP},
            {67,   AppLayer::DHCP},
            {68,   AppLayer::DHCP},
        };
    }

    // ============================================================================
    // LOAD NPCAP DLLs  — must load from System32\Npcap, not WinPcap
    // ============================================================================

    bool NetworkMonitor::LoadNpcapDlls() {
        wchar_t npcap_dir[512]{};
        UINT len = GetSystemDirectoryW(npcap_dir, 480);
        if (len == 0 || len > 480) {
            ConsoleLogger::LogError("GetSystemDirectory failed");
            return false;
        }
        wcsncat_s(npcap_dir, std::size(npcap_dir), L"\\Npcap", 6);

        if (SetDllDirectoryW(npcap_dir) == FALSE) {
            ConsoleLogger::LogError("SetDllDirectoryW(Npcap) failed");
            return false;
        }

        HMODULE h = LoadLibraryW(L"wpcap.dll");
        if (!h) {
            ConsoleLogger::LogError("Failed to load wpcap.dll from Npcap dir. "
                "Is Npcap installed?");
            SetDllDirectoryW(nullptr);
            return false;
        }

        SetDllDirectoryW(nullptr); // restore
        ConsoleLogger::LogInfo("Npcap DLLs loaded from System32\\Npcap");
        return true;
    }

    // ============================================================================
    // ENUMERATE ADAPTERS
    // ============================================================================

    void NetworkMonitor::EnumerateAdapters() {
        pcap_if_t* alldevs = nullptr;
        char errbuf[PCAP_ERRBUF_SIZE]{};

        if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
            ConsoleLogger::LogError(std::string("pcap_findalldevs: ") + errbuf);
            return;
        }

        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if (!d->name) continue;

            // Skip loopback unless explicitly requested
#ifndef TITAN_CAPTURE_LOOPBACK
            if (d->flags & PCAP_IF_LOOPBACK) continue;
#endif
            adapters_.push_back({ d->name, nullptr, {} });
            ConsoleLogger::LogInfo(std::string("Adapter found: ") + d->name +
                (d->description ? std::string(" — ") + d->description : ""));
        }

        pcap_freealldevs(alldevs);
    }

    // ============================================================================
    // BUILD LOCAL IP SET  — used for direction detection (INBOUND vs OUTBOUND)
    // ============================================================================

    void NetworkMonitor::BuildLocalIpSet() {
        std::lock_guard<std::mutex> lock(local_ip_mutex_);
        local_ips_.clear();

        ULONG buf_size = 15000;
        std::vector<BYTE> buf(buf_size);
        DWORD result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &buf_size);
        if (result == ERROR_BUFFER_OVERFLOW) {
            buf.resize(buf_size);
            result = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                &buf_size);
        }
        if (result != NO_ERROR) return;

        auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        while (adapter) {
            for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                char ip[46]{};
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                }
                else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* sa6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof(ip));
                }
                if (ip[0]) local_ips_.insert(ip);
            }
            adapter = adapter->Next;
        }
    }

    bool NetworkMonitor::IsLocalIp(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(local_ip_mutex_);
        return local_ips_.count(ip) > 0;
    }

    // ============================================================================
    // START
    // ============================================================================

    bool NetworkMonitor::Start() {
        if (running_.load()) return false;

        ConsoleLogger::LogInfo("Starting NetworkMonitor (Npcap deep-packet)...");

        if (!LoadNpcapDlls()) return false;

        WSADATA wsd{};
        // FIX C6031: check WSAStartup return value
        if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
            ConsoleLogger::LogError("WSAStartup failed");
            return false;
        }

        BuildLocalIpSet();
        EnumerateAdapters();

        if (adapters_.empty()) {
            ConsoleLogger::LogError("No suitable adapters found for capture");
            return false;
        }

        running_.store(true);

        // Start PID refresh thread
        pid_refresh_thread_ = std::thread([this] {
            while (running_.load()) {
                RefreshPidCache();
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(kPidRefreshMs));
            }
            });

        // Open pcap handle + start capture thread per adapter
        for (auto& ctx : adapters_) {
            char errbuf[PCAP_ERRBUF_SIZE]{};
            ctx.handle = pcap_open_live(
                ctx.name.c_str(),
                65535,           // snaplen — full packet
                1,               // promiscuous mode
                100,             // read timeout ms
                errbuf);

            if (!ctx.handle) {
                ConsoleLogger::LogError(
                    std::string("pcap_open_live(") + ctx.name + "): " + errbuf);
                continue;
            }

            ctx.thread = std::thread(
                &NetworkMonitor::CaptureThread, this, ctx.name);

            ConsoleLogger::LogInfo(
                std::string("Capture started on ") + ctx.name);
        }

        ConsoleLogger::LogInfo("NetworkMonitor running — capturing all protocols");
        return true;
    }

    // ============================================================================
    // STOP
    // ============================================================================

    void NetworkMonitor::Stop() {
        if (!running_.load()) return;

        stop_requested_.store(true);
        running_.store(false);

        for (auto& ctx : adapters_) {
            if (ctx.handle) {
                pcap_breakloop(ctx.handle);
            }
        }
        for (auto& ctx : adapters_) {
            if (ctx.thread.joinable()) ctx.thread.join();
            if (ctx.handle) {
                pcap_close(ctx.handle);
                ctx.handle = nullptr;
            }
        }
        if (pid_refresh_thread_.joinable())
            pid_refresh_thread_.join();

        WSACleanup();
        ConsoleLogger::LogInfo("NetworkMonitor stopped");
    }

    // ============================================================================
    // CAPTURE THREAD — one per adapter
    // ============================================================================

    void NetworkMonitor::CaptureThread(std::string adapter_name) {
        // Find our pcap handle
        pcap_t* handle = nullptr;
        for (auto& ctx : adapters_) {
            if (ctx.name == adapter_name) { handle = ctx.handle; break; }
        }
        if (!handle) return;

        // Lambda adapter for pcap_loop callback
        struct CbCtx { NetworkMonitor* self; std::string name; };
        CbCtx cb_ctx{ this, adapter_name };

        pcap_loop(handle, 0,
            [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
                auto* ctx = reinterpret_cast<CbCtx*>(user);
                ctx->self->HandlePacket(hdr,
                    reinterpret_cast<const uint8_t*>(pkt),
                    ctx->name);
            },
            reinterpret_cast<u_char*>(&cb_ctx));
    }

    // ============================================================================
    // HANDLE PACKET
    // ============================================================================

    void NetworkMonitor::HandlePacket(const struct pcap_pkthdr* header,
        const uint8_t* data,
        const std::string& /*adapter_name*/)
    {
        if (!data || header->caplen < sizeof(EthHeader)) return;
        pkts_captured_.fetch_add(1, std::memory_order_relaxed);

        NetworkInfo info;
        if (!ParseEthernet(data, header->caplen, info)) return;

        // Resolve PID (ICMP has no ports; fall back to UDP slot)
        info.pid = LookupPid(info.local_addr, info.local_port,
            static_cast<uint8_t>(info.is_tcp ? IPPROTO_TCP : IPPROTO_UDP));

        // Resolve short process name only (no hash, no path, no user context)
        if (info.pid != 0)
            ResolveProcessName(info.pid, info);

        // Update flow state
        uint32_t payload_bytes = header->caplen > sizeof(EthHeader)
            ? header->caplen - sizeof(EthHeader) : 0;
        UpdateFlowState(info, payload_bytes);

        // Create and route event
        auto event = Event::CreateNetworkEvent(info, EventSource::NpcapLive);
        FilterResult result = filter_.Process(event);

        if (result.decision == FilterDecision::FORWARD) {
            logger_.LogEvent(std::move(event));
            flows_forwarded_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            flows_compressed_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ============================================================================
    // ETHERNET PARSER
    // ============================================================================

    bool NetworkMonitor::ParseEthernet(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(EthHeader)) return false;
        const auto* eth = reinterpret_cast<const EthHeader*>(data);
        uint16_t etype = ntohs(eth->ether_type);

        const uint8_t* next = data + sizeof(EthHeader);
        uint32_t       remain = len - sizeof(EthHeader);

        if (etype == kEtherTypeIPv4) return ParseIPv4(next, remain, out);
        if (etype == kEtherTypeIPv6) return ParseIPv6(next, remain, out);
        return false; // ARP etc. — not of interest
    }

    // ============================================================================
    // IPv4 PARSER
    // ============================================================================

    bool NetworkMonitor::ParseIPv4(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(Ipv4Header)) return false;
        const auto* ip = reinterpret_cast<const Ipv4Header*>(data);
        uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > len) return false;

        char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, ip->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, ip->dst_ip, dst, sizeof(dst));

        bool src_local = IsLocalIp(src);
        bool dst_local = IsLocalIp(dst);

        out.is_ipv6 = false;
        out.is_loopback = (std::string(src).rfind("127.", 0) == 0 ||
            std::string(dst).rfind("127.", 0) == 0);
        out.is_broadcast = (ip->dst_ip[3] == 0xFF);

        // Direction: outbound if src is local, inbound if dst is local
        if (src_local && !dst_local) {
            out.local_addr = src;
            out.remote_addr = dst;
            out.direction = NetworkDirection::OUTBOUND;
        }
        else {
            out.local_addr = dst;
            out.remote_addr = src;
            out.direction = NetworkDirection::INBOUND;
        }

        const uint8_t* transport = data + ihl;
        uint32_t       t_len = len - ihl;

        switch (ip->protocol) {
        case IPPROTO_TCP:
            out.is_tcp = true;
            ParseTCP(transport, t_len, out, src_local);
            break;
        case IPPROTO_UDP:
            out.is_tcp = false;
            ParseUDP(transport, t_len, out, src_local);
            break;
        case IPPROTO_ICMP:
            out.is_tcp = false;
            ParseICMP(transport, t_len, out);
            break;
        default:
            return false;
        }
        return true;
    }

    // ============================================================================
    // IPv6 PARSER
    // ============================================================================

    bool NetworkMonitor::ParseIPv6(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(Ipv6Header)) return false;
        const auto* ip6 = reinterpret_cast<const Ipv6Header*>(data);

        char src[INET6_ADDRSTRLEN]{}, dst[INET6_ADDRSTRLEN]{};
        inet_ntop(AF_INET6, ip6->src_ip, src, sizeof(src));
        inet_ntop(AF_INET6, ip6->dst_ip, dst, sizeof(dst));

        bool src_local = IsLocalIp(src);
        out.is_ipv6 = true;
        out.is_loopback = (std::string(src) == "::1" || std::string(dst) == "::1");

        if (src_local) {
            out.local_addr = src; out.remote_addr = dst;
            out.direction = NetworkDirection::OUTBOUND;
        }
        else {
            out.local_addr = dst; out.remote_addr = src;
            out.direction = NetworkDirection::INBOUND;
        }

        const uint8_t* transport = data + sizeof(Ipv6Header);
        uint32_t       t_len = len - sizeof(Ipv6Header);

        switch (ip6->next_header) {
        case IPPROTO_TCP:
            out.is_tcp = true;
            ParseTCP(transport, t_len, out, src_local);
            break;
        case IPPROTO_UDP:
            out.is_tcp = false;
            ParseUDP(transport, t_len, out, src_local);
            break;
        case 58: // ICMPv6
            out.is_tcp = false;
            ParseICMP(transport, t_len, out);
            break;
        default:
            return false;
        }
        return true;
    }

    // ============================================================================
    // TCP PARSER
    // ============================================================================

    void NetworkMonitor::ParseTCP(const uint8_t* data, uint32_t len,
        NetworkInfo& out, bool is_src_local)
    {
        if (len < sizeof(TcpHeader)) return;
        const auto* tcp = reinterpret_cast<const TcpHeader*>(data);

        uint16_t sp = ntohs(tcp->src_port);
        uint16_t dp = ntohs(tcp->dst_port);

        out.local_port = is_src_local ? sp : dp;
        out.remote_port = is_src_local ? dp : sp;

        // TCP state from flags
        uint8_t fl = tcp->flags;
        if ((fl & kTcpSyn) && !(fl & kTcpAck))  out.tcp_state = TcpState::SYN_SENT;
        else if ((fl & kTcpSyn) && (fl & kTcpAck))  out.tcp_state = TcpState::SYN_RECEIVED;
        else if ((fl & kTcpFin) || (fl & kTcpRst))   out.tcp_state = TcpState::CLOSED;
        else                                            out.tcp_state = TcpState::ESTABLISHED;

        uint32_t hdr_len = static_cast<uint32_t>((tcp->data_offset >> 4) * 4);
        if (hdr_len > len) return;

        const uint8_t* payload = data + hdr_len;
        uint32_t       payload_len = len - hdr_len;

        if (payload_len > 0) {
            // Port-based initial hint
            auto it = port_app_map_.find(out.remote_port);
            if (it == port_app_map_.end()) it = port_app_map_.find(out.local_port);
            if (it != port_app_map_.end()) out.app_layer = it->second;

            // Payload inspection overrides port hint
            IdentifyAppLayer(payload, payload_len, out);
        }
    }

    // ============================================================================
    // UDP PARSER
    // ============================================================================

    void NetworkMonitor::ParseUDP(const uint8_t* data, uint32_t len,
        NetworkInfo& out, bool is_src_local)
    {
        if (len < sizeof(UdpHeader)) return;
        const auto* udp = reinterpret_cast<const UdpHeader*>(data);

        uint16_t sp = ntohs(udp->src_port);
        uint16_t dp = ntohs(udp->dst_port);

        out.local_port = is_src_local ? sp : dp;
        out.remote_port = is_src_local ? dp : sp;

        auto it = port_app_map_.find(out.remote_port);
        if (it == port_app_map_.end()) it = port_app_map_.find(out.local_port);
        if (it != port_app_map_.end()) out.app_layer = it->second;

        const uint8_t* payload = data + sizeof(UdpHeader);
        uint32_t       payload_len = len - sizeof(UdpHeader);
        if (payload_len > 0) {
            IdentifyAppLayer(payload, payload_len, out);
        }
    }

    // ============================================================================
    // ICMP PARSER
    // ============================================================================

    void NetworkMonitor::ParseICMP(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(IcmpHeader)) return;
        const auto* icmp = reinterpret_cast<const IcmpHeader*>(data);
        out.app_layer = AppLayer::ICMP;
        (void)icmp; // type/code fields removed from NetworkInfo
    }

    // ============================================================================
    // APPLICATION LAYER IDENTIFICATION
    // ============================================================================

    void NetworkMonitor::IdentifyAppLayer(const uint8_t* payload, uint32_t len,
        NetworkInfo& out)
    {
        if (len == 0 || payload == nullptr) return;

        // TLS ClientHello: record type 0x16, version 0x03xx
        if (len >= 5 && payload[0] == 0x16 && payload[1] == 0x03) {
            out.app_layer = AppLayer::HTTPS_TLS;
            return;
        }

        // HTTP request line
        if (len >= 4) {
            auto starts = [&](const char* s) {
                size_t n = strlen(s);
                return len >= n &&
                    memcmp(payload, s, n) == 0;
                };
            if (starts("GET ") || starts("POST ") || starts("PUT ") ||
                starts("HEAD ") || starts("PATCH") || starts("DELETE ") ||
                starts("OPTIO") || starts("HTTP/"))
            {
                out.app_layer = AppLayer::HTTP;
                return;
            }
        }

        // QUIC (v1 long header: first byte bit 7 set, bits 6-4 = 0x30..0x3F for Initial)
        if (len >= 5 && (payload[0] & 0xC0) == 0xC0) {
            uint32_t version = (static_cast<uint32_t>(payload[1]) << 24) |
                (static_cast<uint32_t>(payload[2]) << 16) |
                (static_cast<uint32_t>(payload[3]) << 8) |
                static_cast<uint32_t>(payload[4]);
            if (version == 0x00000001 || version == 0xFF000001) {
                out.app_layer = AppLayer::QUIC;
                return;
            }
        }

        // SSH banner
        if (len >= 4 && memcmp(payload, "SSH-", 4) == 0) {
            out.app_layer = AppLayer::SSH;
            return;
        }

        // SMTP greeting / HELO
        if (len >= 4 && (memcmp(payload, "220 ", 4) == 0 ||
            memcmp(payload, "EHLO", 4) == 0 ||
            memcmp(payload, "HELO", 4) == 0))
        {
            out.app_layer = AppLayer::SMTP;
            return;
        }

        // RDP: first byte 0x03, second 0x00 (TPKT header)
        if (len >= 4 && payload[0] == 0x03 && payload[1] == 0x00) {
            if (out.remote_port == 3389 || out.local_port == 3389) {
                out.app_layer = AppLayer::RDP;
                return;
            }
        }

        // SMB: NetBIOS Session Service 0x00 + SMB magic \xFFSMB or \xFESMB
        if (len >= 8 && payload[0] == 0x00) {
            if ((len >= 8 && memcmp(payload + 4, "\xFFSMB", 4) == 0) ||
                (len >= 8 && memcmp(payload + 4, "\xFESMB", 4) == 0))
            {
                out.app_layer = AppLayer::SMB;
                return;
            }
        }
    }

    // ============================================================================
    // FLOW STATE UPDATE
    // ============================================================================

    void NetworkMonitor::UpdateFlowState(const NetworkInfo& info,
        uint32_t payload_bytes)
    {
        FlowKey key{
            info.local_addr, info.remote_addr,
            info.local_port, info.remote_port,
            static_cast<uint8_t>(info.is_tcp ? IPPROTO_TCP : IPPROTO_UDP)
        };

        std::lock_guard<std::mutex> lock(flow_mutex_);
        auto now = std::chrono::steady_clock::now();

        auto it = flow_table_.find(key);
        if (it == flow_table_.end()) {
            if (flow_table_.size() >= kMaxFlows) {
                auto oldest = flow_table_.begin();
                for (auto jt = flow_table_.begin(); jt != flow_table_.end(); ++jt) {
                    if (jt->second.last_seen < oldest->second.last_seen)
                        oldest = jt;
                }
                flow_table_.erase(oldest);
            }
            FlowState state;
            state.first_seen = now;
            state.last_seen = now;
            state.direction = info.direction;
            state.tcp_state = info.tcp_state;
            state.pid = info.pid;
            state.packet_count = 1;
            if (info.direction == NetworkDirection::OUTBOUND)
                state.bytes_sent = payload_bytes;
            else
                state.bytes_recv = payload_bytes;
            flow_table_[key] = state;
        }
        else {
            FlowState& state = it->second;
            state.last_seen = now;
            state.packet_count++;
            state.tcp_state = info.tcp_state;
            if (info.direction == NetworkDirection::OUTBOUND)
                state.bytes_sent += payload_bytes;
            else
                state.bytes_recv += payload_bytes;
        }
    }

    // ============================================================================
    // PID RESOLUTION  (IP Helper API)
    // ============================================================================

    void NetworkMonitor::RefreshPidCache() {
        std::unordered_map<SocketPidKey, DWORD, SocketPidKeyHash> new_cache;

        // TCP v4
        {
            ULONG size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_TCPTABLE)))
                size = static_cast<ULONG>(sizeof(MIB_TCPTABLE));
            std::vector<BYTE> buf(size);
            if (GetExtendedTcpTable(buf.data(), &size, FALSE,
                AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                auto* tbl = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET_ADDRSTRLEN]{};
                    in_addr a{}; a.s_addr = tbl->table[i].dwLocalAddr;
                    inet_ntop(AF_INET, &a, ip, sizeof(ip));
                    SocketPidKey k;
                    k.local_ip = ip;
                    k.local_port = static_cast<uint16_t>(ntohs(static_cast<uint16_t>(tbl->table[i].dwLocalPort)));
                    k.proto = static_cast<uint8_t>(IPPROTO_TCP);
                    new_cache[k] = tbl->table[i].dwOwningPid;
                }
            }
        }

        // TCP v6
        {
            ULONG size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_TCP6TABLE_OWNER_PID)))
                size = static_cast<ULONG>(sizeof(MIB_TCP6TABLE_OWNER_PID));
            std::vector<BYTE> buf(size);
            if (GetExtendedTcpTable(buf.data(), &size, FALSE,
                AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                auto* tbl = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, tbl->table[i].ucLocalAddr, ip, sizeof(ip));
                    SocketPidKey k;
                    k.local_ip = ip;
                    k.local_port = static_cast<uint16_t>(ntohs(static_cast<uint16_t>(tbl->table[i].dwLocalPort)));
                    k.proto = static_cast<uint8_t>(IPPROTO_TCP);
                    new_cache[k] = tbl->table[i].dwOwningPid;
                }
            }
        }

        // UDP v4
        {
            ULONG size = 0;
            GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_UDPTABLE)))
                size = static_cast<ULONG>(sizeof(MIB_UDPTABLE));
            std::vector<BYTE> buf(size);
            if (GetExtendedUdpTable(buf.data(), &size, FALSE,
                AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            {
                auto* tbl = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET_ADDRSTRLEN]{};
                    in_addr a{}; a.s_addr = tbl->table[i].dwLocalAddr;
                    inet_ntop(AF_INET, &a, ip, sizeof(ip));
                    SocketPidKey k;
                    k.local_ip = ip;
                    k.local_port = static_cast<uint16_t>(ntohs(static_cast<uint16_t>(tbl->table[i].dwLocalPort)));
                    k.proto = static_cast<uint8_t>(IPPROTO_UDP);
                    new_cache[k] = tbl->table[i].dwOwningPid;
                }
            }
        }

        std::lock_guard<std::mutex> lock(pid_mutex_);
        pid_cache_ = std::move(new_cache);
    }

    DWORD NetworkMonitor::LookupPid(const std::string& local_ip,
        uint16_t local_port, uint8_t proto) const
    {
        std::lock_guard<std::mutex> lock(pid_mutex_);
        SocketPidKey key;
        key.local_ip = local_ip;
        key.local_port = local_port;
        key.proto = proto;
        auto it = pid_cache_.find(key);
        if (it != pid_cache_.end()) return it->second;
        return 0;
    }

    // ============================================================================
    // RESOLVE PROCESS NAME
    // Lightweight replacement for EnrichProcessFields.
    // Sets process_name to the short executable filename only.
    // No hash, no path, no user context -- this is a network endpoint.
    // ============================================================================

    void NetworkMonitor::ResolveProcessName(DWORD pid, NetworkInfo& out) {
        if (pid == 0) return;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return;

        std::vector<wchar_t> buf(32768, L'\0');
        DWORD sz = static_cast<DWORD>(buf.size());
        if (QueryFullProcessImageNameW(h, 0, buf.data(), &sz) && sz > 0) {
            std::wstring full(buf.data(), sz);
            auto pos = full.find_last_of(L"\\/");
            out.process_name = (pos != std::wstring::npos)
                ? full.substr(pos + 1)
                : full;
        }

        CloseHandle(h);
    }


} // namespace titan