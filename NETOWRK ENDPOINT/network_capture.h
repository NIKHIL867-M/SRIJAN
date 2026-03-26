#ifndef NETWORK_CAPTURE_H
#define NETWORK_CAPTURE_H

#include "network_types.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

// Winsock must come before pcap on Windows
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Npcap
#include <pcap.h>

namespace network {

    class NetworkCapture {
    public:
        NetworkCapture();
        ~NetworkCapture();

        bool Start(const std::string& interface_ip);
        void Stop();

        bool GetPacket(Packet& packet, uint32_t timeout_ms);

        size_t GetQueueSize() const;

    private:
        std::string ResolveDevice(const std::string& interface_ip);

        void CaptureLoop();

        bool ParsePacket(const uint8_t* raw_data, int raw_len, Packet& packet);
        bool ParseIPHeader(const uint8_t* data, size_t len, Packet& packet);
        bool ParseTCPHeader(const uint8_t* data, size_t len, Packet& packet,
            size_t ip_header_len);
        bool ParseUDPHeader(const uint8_t* data, size_t len, Packet& packet,
            size_t ip_header_len);

        bool ResolveProcess(const Packet& packet, uint32_t& pid,
            std::wstring& process_name, std::wstring& process_path);

        void PushPacket(const Packet& packet);

    private:
        pcap_t* handle_;

        std::string interface_ip_;

        size_t snap_len_;
        int buffer_size_;

        std::atomic<bool> running_;

        std::thread capture_thread_;

        std::queue<Packet> packet_queue_;
        std::mutex queue_mutex_;
        std::condition_variable queue_cv_;

        std::atomic<size_t> queue_size_;

        std::atomic<uint64_t> packets_captured_;
        std::atomic<uint64_t> packets_dropped_;

        std::atomic<bool> memory_pressure_;
    };

} // namespace network

#endif