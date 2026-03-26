// usb_session.h
#pragma once

#include "usb_identity.h"
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <map>

// ─────────────────────────────────────────────────────────────────────────────
// Anomaly detection thresholds
// ─────────────────────────────────────────────────────────────────────────────
namespace AnomalyThresholds {
    constexpr uint64_t HIGH_READ_BYTES = 500ULL * 1024 * 1024;  // 500 MB
    constexpr uint64_t HIGH_WRITE_BYTES = 500ULL * 1024 * 1024;  // 500 MB
    constexpr uint64_t MANY_FILES_DELETED = 50;
    constexpr bool     EXECUTABLE_WRITE_ALERT = true;

    // Memory caps -- prevent unbounded growth on very active drives
    constexpr size_t   MAX_ANOMALY_ENTRIES = 64;    // max anomaly strings stored
    constexpr size_t   MAX_EXTENSION_TYPES = 128;   // max distinct extensions tracked
}

// ─────────────────────────────────────────────────────────────────────────────
// UsbSession
//
// Tracks file-level activity for one USB device insertion.
// Thread-safe: all public methods are guarded by m_mutex.
//
// Memory design:
//   m_anomalies   capped at MAX_ANOMALY_ENTRIES  -- no unbounded growth
//   m_fileExtensions capped at MAX_EXTENSION_TYPES -- bounded map
//   No per-file path storage -- only aggregated counters and extension counts
// ─────────────────────────────────────────────────────────────────────────────
class UsbSession {
public:
    UsbSession(const UsbIdentity& identity, const std::string& mountPoint);

    UsbSession(const UsbSession&) = delete;
    UsbSession& operator=(const UsbSession&) = delete;
    UsbSession(UsbSession&&) = delete;
    UsbSession& operator=(UsbSession&&) = delete;

    // Record one file-system event. No-op after Finalize().
    void AddFileEvent(const std::string& operation,
        const std::string& filePath,
        uint64_t           size);

    // Produce the final JSON summary. Returns "" on second call.
    std::string Finalize();

    const std::string& GetSessionId()  const { return m_sessionId; }
    const std::string& GetSerial()     const { return m_identity.serialNumber; }
    const std::string& GetMountPoint() const { return m_mountPoint; }
    bool               IsFinalized()   const { return m_finalized; }

private:
    static std::string GenerateSessionId(const UsbIdentity& identity);
    static std::string EscapeJson(const std::string& s);

    void UpdateFileExtension(const std::string& filePath);
    void CheckAnomalies(const std::string& operation,
        const std::string& filePath,
        uint64_t           size);

    // Immutable after construction
    const UsbIdentity  m_identity;
    const std::string  m_mountPoint;
    const std::string  m_sessionId;

    std::chrono::steady_clock::time_point m_startTime;
    std::chrono::steady_clock::time_point m_lastActivityTime;

    // Activity counters
    uint64_t m_totalReads = 0;
    uint64_t m_totalWrites = 0;
    uint64_t m_totalDeletes = 0;
    uint64_t m_totalExecutes = 0;
    uint64_t m_totalBytesRead = 0;
    uint64_t m_totalBytesWritten = 0;
    uint64_t m_totalFilesDeleted = 0;

    // Bounded collections -- capped to prevent RAM growth on busy drives
    std::map<std::string, uint32_t> m_fileExtensions;   // ext -> count, max 128 entries
    std::vector<std::string>        m_anomalies;         // max 64 entries

    bool m_finalized = false;

    mutable std::mutex m_mutex;
};