#include "network_capture.h"

#include <iostream>
#include <iphlpapi.h>
#include <pcap.h>
#include <psapi.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

namespace network {

    // =============================
    // Headers
    // =============================

    struct EthernetHeader {
        uint8_t dst[6];
        uint8_t src[6];
        uint16_t type;
    };

    struct IPHeader {
        uint8_t ip_header_len : 4;
        uint8_t ip_version : 4;
        uint8_t ip_tos;
        uint16_t ip_total_length;
        uint16_t ip_id;
        uint16_t ip_flags_offset;
        uint8_t ip_ttl;
        uint8_t ip_protocol;
        uint16_t ip_checksum;
        uint32_t ip_src_addr;
        uint32_t ip_dst_addr;
    };

    struct TCPHeader {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq_num;
        uint32_t ack_num;
        uint8_t data_offset : 4;
        uint8_t reserved : 4;
        uint8_t flags;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_ptr;
    };

    struct UDPHeader {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };

    // =============================
    // Constructor
    // =============================

    NetworkCapture::NetworkCapture()
        : handle_(nullptr), snap_len_(65535), buffer_size_(1024 * 1024),
        running_(false), queue_size_(0), packets_captured_(0),
        packets_dropped_(0), memory_pressure_(false) {
    }

    NetworkCapture::~NetworkCapture() { Stop(); }

    // =============================
    // Resolve Device Name from IP
    // =============================
    // Npcap on Windows requires a device name like \Device\NPF_{GUID}
    // This function maps "0.0.0.0" (any) or a specific IP to the correct device.

    // Helper: get GUID string from adapter index via Windows IP Helper API
    // e.g. given index 5 -> returns "{ED7EB2DB-C88C-47A2-A07A-198F91BB4EF2}"
    static std::string GetAdapterGuidByIp(const std::string& target_ip) {
        ULONG buf_size = 0;
        GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &buf_size);
        std::vector<BYTE> buf(buf_size);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

        if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &buf_size) !=
            NO_ERROR)
            return "";

        for (auto* a = adapters; a != nullptr; a = a->Next) {
            for (auto* ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(
                        AF_INET,
                        &reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr)->sin_addr,
                        ip, INET_ADDRSTRLEN);
                    if (std::string(ip) == target_ip) {
                        // AdapterName is the GUID string like {ED7EB2DB-...}
                        return std::string(a->AdapterName);
                    }
                }
            }
        }
        return "";
    }

    std::string NetworkCapture::ResolveDevice(const std::string& interface_ip) {
        pcap_if_t* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "[Capture] pcap_findalldevs failed: " << errbuf << std::endl;
            return "";
        }

        std::string result = "";

        // --- Pass 1: "0.0.0.0" -> pick the first real physical adapter ---
        if (interface_ip == "0.0.0.0") {
            for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
                if (d->name == nullptr)
                    continue;
                // Skip WAN Miniports, loopback, virtual adapters
                std::string desc = d->description ? d->description : "";
                if (desc.find("WAN Miniport") != std::string::npos)
                    continue;
                if (desc.find("Loopback") != std::string::npos)
                    continue;
                if (desc.find("Virtual") != std::string::npos)
                    continue;
                if (desc.find("TAP") != std::string::npos)
                    continue;
                if (desc.find("Hyper-V") != std::string::npos)
                    continue;
                if (std::string(d->name).find("Loopback") != std::string::npos)
                    continue;
                result = d->name;
                std::cout << "[Capture] Auto-selected adapter: " << d->name;
                if (d->description)
                    std::cout << " (" << d->description << ")";
                std::cout << std::endl;
                break;
            }
        }
        else {
            // --- Pass 2: Match by IP via pcap address list ---
            for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
                for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
                    if (a->addr && a->addr->sa_family == AF_INET) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip,
                            INET_ADDRSTRLEN);
                        if (std::string(ip) == interface_ip) {
                            result = d->name;
                            std::cout << "[Capture] Matched adapter (pcap): " << d->name;
                            if (d->description)
                                std::cout << " (" << d->description << ")";
                            std::cout << std::endl;
                            break;
                        }
                    }
                }
                if (!result.empty())
                    break;
            }

            // --- Pass 3: Fallback - match via Windows IP Helper API
            // (GetAdaptersAddresses) --- Npcap sometimes doesn't populate pcap address
            // lists for all adapters
            if (result.empty()) {
                std::string guid = GetAdapterGuidByIp(interface_ip);
                if (!guid.empty()) {
                    // Build the Npcap device name from the GUID
                    std::string npcap_name = "\\Device\\NPF_" + guid;
                    // Verify this device exists in pcap list
                    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
                        if (d->name && std::string(d->name) == npcap_name) {
                            result = npcap_name;
                            std::cout << "[Capture] Matched adapter (WinAPI fallback): "
                                << d->name;
                            if (d->description)
                                std::cout << " (" << d->description << ")";
                            std::cout << std::endl;
                            break;
                        }
                    }
                    // Even if not in pcap list, try it anyway
                    if (result.empty() && !guid.empty()) {
                        result = npcap_name;
                        std::cout << "[Capture] Using adapter from WinAPI: " << npcap_name
                            << std::endl;
                    }
                }
            }
        }

        if (result.empty()) {
            std::cerr << "[Capture] No adapter found for: " << interface_ip
                << std::endl;
            std::cerr << "[Capture] Available adapters (use -i with one of these IPs):"
                << std::endl;
            for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
                std::cerr << "  " << (d->name ? d->name : "null");
                if (d->description)
                    std::cerr << " -> " << d->description;
                // Print IPs if available
                for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
                    if (a->addr && a->addr->sa_family == AF_INET) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip,
                            INET_ADDRSTRLEN);
                        std::cerr << " [" << ip << "]";
                    }
                }
                std::cerr << std::endl;
            }
        }

        pcap_freealldevs(alldevs);
        return result;
    }

    // =============================
    // Start Capture
    // =============================

    bool NetworkCapture::Start(const std::string& interface_ip) {

        if (running_.load())
            return true;

        char errbuf[PCAP_ERRBUF_SIZE];

        // Resolve IP / "0.0.0.0" to actual Npcap device name
        std::string device = ResolveDevice(interface_ip);
        if (device.empty()) {
            std::cerr
                << "[Capture] Could not resolve a valid adapter. Is Npcap installed?"
                << std::endl;
            return false;
        }

        handle_ = pcap_open_live(device.c_str(), static_cast<int>(snap_len_), 1, 1000, errbuf);

        if (!handle_) {
            std::cerr << "[Capture] Npcap open failed: " << errbuf << std::endl;
            return false;
        }

        std::cout << "[Capture] Npcap initialized on " << device << std::endl;

        running_ = true;
        capture_thread_ = std::thread(&NetworkCapture::CaptureLoop, this);

        return true;
    }

    // =============================
    // Stop Capture
    // =============================

    void NetworkCapture::Stop() {

        if (!running_.load())
            return;

        running_ = false;

        queue_cv_.notify_all();

        if (capture_thread_.joinable())
            capture_thread_.join();

        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }

        std::cout << "[Capture] Stopped. Total captured: " << packets_captured_.load()
            << ", dropped: " << packets_dropped_.load() << std::endl;
    }

    // =============================
    // Capture Loop
    // =============================

    void NetworkCapture::CaptureLoop() {

        std::cout << "[Capture] Capture loop started" << std::endl;

        struct pcap_pkthdr* header;
        const u_char* data;

        while (running_.load()) {

            int result = pcap_next_ex(handle_, &header, &data);

            if (result != 1)
                continue;

            if (queue_size_.load() >= MAX_PACKET_QUEUE) {
                packets_dropped_++;
                continue;
            }

            Packet packet;

            if (!ParsePacket(data, header->len, packet))
                continue;

            ResolveProcess(packet, packet.pid, packet.process_name,
                packet.process_path);

            PushPacket(packet);

            packets_captured_++;
        }

        std::cout << "[Capture] Capture loop ended" << std::endl;
    }

    // =============================
    // Packet Parsing
    // =============================

    bool NetworkCapture::ParsePacket(const uint8_t* raw_data, int raw_len,
        Packet& packet) {

        if (raw_len < (int)sizeof(EthernetHeader))
            return false;

        const EthernetHeader* eth =
            reinterpret_cast<const EthernetHeader*>(raw_data);

        uint16_t eth_type = ntohs(eth->type);

        packet.timestamp = std::chrono::steady_clock::now();

        // Handle ARP (EtherType 0x0806)
        if (eth_type == 0x0806) {
            packet.protocol = 0xFE; // sentinel: ARP
            packet.src_ip = packet.dst_ip = 0;
            packet.src_port = packet.dst_port = 0;
            // ARP IPv4 layout: 8 byte header, sender MAC(6), sender IP(4), target
            // MAC(6), target IP(4)
            if (raw_len >= (int)(sizeof(EthernetHeader) + 28)) {
                const uint8_t* arp = raw_data + sizeof(EthernetHeader);
                memcpy(&packet.src_ip, arp + 14, 4);
                memcpy(&packet.dst_ip, arp + 24, 4);
            }
            return true;
        }

        if (eth_type != 0x0800)
            return false; // drop non-IPv4, non-ARP

        const uint8_t* ip_data = raw_data + sizeof(EthernetHeader);

        const size_t raw_len_u = static_cast<size_t>(raw_len);
        if (!ParseIPHeader(ip_data, raw_len_u - sizeof(EthernetHeader), packet))
            return false;

        const IPHeader* ip_hdr = reinterpret_cast<const IPHeader*>(ip_data);
        size_t ip_header_len = static_cast<size_t>(ip_hdr->ip_header_len) * 4u;

        size_t transport_offset = sizeof(EthernetHeader) + ip_header_len;
        if (transport_offset < raw_len_u) {
            size_t payload_len = raw_len_u - transport_offset;
            if (payload_len > MAX_PAYLOAD_SIZE)
                payload_len = MAX_PAYLOAD_SIZE;
            packet.payload.assign(raw_data + transport_offset,
                raw_data + transport_offset + payload_len);
            packet.payload_size = payload_len;
        }

        switch (packet.protocol) {

        case IPPROTO_TCP:
            return ParseTCPHeader(ip_data, raw_len, packet, ip_header_len);

        case IPPROTO_UDP:
            return ParseUDPHeader(ip_data, raw_len, packet, ip_header_len);

        case IPPROTO_ICMP:
            // ICMP has no ports — set 0, ValidatePacket already allows this
            packet.src_port = 0;
            packet.dst_port = 0;
            return true;

        default:
            packet.src_port = 0;
            packet.dst_port = 0;
            return true;
        }
    }

    // =============================
    // IP
    // =============================

    bool NetworkCapture::ParseIPHeader(const uint8_t* data, size_t len,
        Packet& packet) {

        if (len < sizeof(IPHeader))
            return false;

        const IPHeader* hdr = reinterpret_cast<const IPHeader*>(data);

        if (hdr->ip_version != 4)
            return false;

        packet.src_ip = hdr->ip_src_addr;
        packet.dst_ip = hdr->ip_dst_addr;
        packet.protocol = hdr->ip_protocol;

        return true;
    }

    // =============================
    // TCP
    // =============================

    bool NetworkCapture::ParseTCPHeader(const uint8_t* data, size_t len,
        Packet& packet, size_t ip_header_len) {

        if (len < ip_header_len + sizeof(TCPHeader))
            return false;

        const TCPHeader* tcp_hdr =
            reinterpret_cast<const TCPHeader*>(data + ip_header_len);

        packet.src_port = ntohs(tcp_hdr->src_port);
        packet.dst_port = ntohs(tcp_hdr->dst_port);

        return true;
    }

    // =============================
    // UDP
    // =============================

    bool NetworkCapture::ParseUDPHeader(const uint8_t* data, size_t len,
        Packet& packet, size_t ip_header_len) {

        if (len < ip_header_len + sizeof(UDPHeader))
            return false;

        const UDPHeader* udp_hdr =
            reinterpret_cast<const UDPHeader*>(data + ip_header_len);

        packet.src_port = ntohs(udp_hdr->src_port);
        packet.dst_port = ntohs(udp_hdr->dst_port);

        return true;
    }

    // =============================
    // Queue Push
    // =============================

    void NetworkCapture::PushPacket(const Packet& packet) {

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);

            if (packet_queue_.size() >= MAX_PACKET_QUEUE) {
                packets_dropped_++;
                return;
            }

            packet_queue_.push(packet);
            queue_size_ = packet_queue_.size();
        }

        queue_cv_.notify_one();
    }

    // =============================
    // Packet Retrieval
    // =============================

    bool NetworkCapture::GetPacket(Packet& packet, uint32_t timeout_ms) {

        std::unique_lock<std::mutex> lock(queue_mutex_);

        bool has_packet =
            queue_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
            return !packet_queue_.empty() || !running_.load();
                });

        if (!has_packet || packet_queue_.empty())
            return false;

        packet = std::move(packet_queue_.front());

        packet_queue_.pop();

        queue_size_ = packet_queue_.size();

        return true;
    }

    size_t NetworkCapture::GetQueueSize() const { return queue_size_.load(); }

    bool NetworkCapture::ResolveProcess(const Packet& packet, uint32_t& pid,
        std::wstring& process_name,
        std::wstring& process_path) {
        pid = 0;
        process_name = L"Unknown";
        process_path = L"";

        if (packet.protocol != IPPROTO_TCP)
            return false;

        DWORD size = 0;

        GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        // FIX C28020: SAL annotation requires >= sizeof(MIB_TCPTABLE)
        if (size < static_cast<DWORD>(sizeof(MIB_TCPTABLE)))
            size = static_cast<DWORD>(sizeof(MIB_TCPTABLE));
        std::vector<BYTE> buffer(size);

        auto* tcp_table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());

        if (GetExtendedTcpTable(tcp_table, &size, TRUE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
            return false;

        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            auto& row = tcp_table->table[i];

            if (row.dwLocalPort == htons(packet.src_port)) {
                pid = row.dwOwningPid;

                HANDLE hProcess =
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

                if (hProcess) {
                    WCHAR path[MAX_PATH];
                    DWORD path_size = MAX_PATH;

                    if (QueryFullProcessImageNameW(hProcess, 0, path, &path_size)) {
                        process_path = path;

                        size_t pos = process_path.find_last_of(L'\\');

                        if (pos != std::wstring::npos)
                            process_name = process_path.substr(pos + 1);
                        else
                            process_name = process_path;
                    }

                    CloseHandle(hProcess);
                }

                return true;
            }
        }

        return false;
    }

} // namespace network