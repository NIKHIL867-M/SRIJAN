// usb_session.cpp
#include "usb_session.h"

#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <algorithm>
#include <cctype>
#include <cinttypes>   // PRIx32 — portable format for uint32_t/DWORD in snprintf

#ifdef _WIN32
#   ifndef WIN32_LEAN_AND_MEAN
#       define WIN32_LEAN_AND_MEAN
#   endif
#   include <windows.h>
#   include <objbase.h>
#   pragma comment(lib, "ole32.lib")
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// RFC 8259-compliant JSON string escaping.
/*static*/ std::string UsbSession::EscapeJson(const std::string& s)
{
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
            if (c < 0x20u) {
                o << "\\u"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(c);
            }
            else {
                o << c;   // unsigned char feeds operator<< directly — no cast needed
            }
        }
    }
    return o.str();
}

// UTC ISO-8601 timestamp with millisecond precision.
static std::string GetCurrentTimeISO()
{
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &tt);
#else
    gmtime_r(&tt, &utc);
#endif
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::ostringstream ss;
    ss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setw(3) << std::setfill('0') << ms.count() << 'Z';
    return ss.str();
}

// Platform UUID (CoCreateGuid on Win32, random fallback elsewhere).
static std::string GenerateUUID()
{
#ifdef _WIN32
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid))) return "00000000";
    char buf[37];
    // GUID.Data1 is DWORD (unsigned long on Win32). Cast to uint32_t + PRIx32
    // avoids the /W4+/sdl format-mismatch warning on 64-bit MSVC builds.
    snprintf(buf, sizeof(buf),
        "%08" PRIx32 "-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        static_cast<uint32_t>(guid.Data1), guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1],
        guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5],
        guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
#else
    static std::random_device               rd;
    static std::mt19937                     gen(rd());
    static std::uniform_int_distribution<>  dis(0, 15);
    static const char digits[] = "0123456789abcdef";
    std::string uuid(36, '-');
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        uuid[i] = digits[dis(gen)];
    }
    return uuid;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Session ID:  <serial>_<unix_ms>_<8-char UUID fragment>
// FIX: GenerateUUID() always returns ≥36 chars so substr(0,8) is always safe.
//      If the serial is empty (device has none) a placeholder is used so the
//      session ID remains meaningful.
// ─────────────────────────────────────────────────────────────────────────────
/*static*/ std::string UsbSession::GenerateSessionId(const UsbIdentity& identity)
{
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    const std::string& serial = identity.serialNumber.empty()
        ? "NO_SERIAL"
        : identity.serialNumber;

    std::string uuid = GenerateUUID();
    // uuid is always 36 chars; take the first 8 hex chars (before the first '-')
    std::string fragment = uuid.substr(0, 8);

    std::ostringstream ss;
    ss << serial << '_' << now_ms << '_' << fragment;
    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────
UsbSession::UsbSession(const UsbIdentity& identity, const std::string& mountPoint)
    : m_identity(identity)
    , m_mountPoint(mountPoint)
    , m_sessionId(GenerateSessionId(identity))
    , m_startTime(std::chrono::steady_clock::now())
    , m_lastActivityTime(m_startTime)
{
}

// ─────────────────────────────────────────────────────────────────────────────
// AddFileEvent
// ─────────────────────────────────────────────────────────────────────────────
void UsbSession::AddFileEvent(const std::string& operation,
    const std::string& filePath,
    uint64_t           size)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Guard: silently ignore events after Finalize() was called.
    if (m_finalized) return;

    m_lastActivityTime = std::chrono::steady_clock::now();

    // Normalise operation to lowercase for case-insensitive matching.
    std::string op = operation;
    for (char& c : op)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (op == "read") { ++m_totalReads;   m_totalBytesRead += size; }
    else if (op == "write") { ++m_totalWrites;  m_totalBytesWritten += size; }
    else if (op == "delete") { ++m_totalDeletes; ++m_totalFilesDeleted; }
    else if (op == "execute") { ++m_totalExecutes; }
    // Unknown operations are counted in extensions only (below).

    UpdateFileExtension(filePath);
    CheckAnomalies(op, filePath, size);
}

// ─────────────────────────────────────────────────────────────────────────────
// UpdateFileExtension  (mutex must be held by caller)
// ─────────────────────────────────────────────────────────────────────────────
void UsbSession::UpdateFileExtension(const std::string& filePath)
{
    size_t dot = filePath.find_last_of('.');
    if (dot == std::string::npos) {
        ++m_fileExtensions["(none)"];
        return;
    }
    size_t sep = filePath.find_last_of("/\\");
    if (sep != std::string::npos && dot < sep) {
        ++m_fileExtensions["(none)"];
        return;
    }

    std::string ext = filePath.substr(dot);
    for (char& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // If this is a known extension, always increment its count.
    // If it's a new extension, only add it if we're under the cap —
    // prevents unbounded map growth on drives with thousands of file types.
    auto it = m_fileExtensions.find(ext);
    if (it != m_fileExtensions.end()) {
        ++it->second;
    }
    else if (m_fileExtensions.size() < AnomalyThresholds::MAX_EXTENSION_TYPES) {
        m_fileExtensions[ext] = 1;
    }
    // else: new extension beyond cap — silently drop; counters still accurate
}

// ─────────────────────────────────────────────────────────────────────────────
// CheckAnomalies  (mutex must be held by caller)
//
// FIX: Previously (void)size suppressed ALL size-based anomaly checks.
//      Now all three threshold types are evaluated:
//        1. Executable write
//        2. Cumulative bytes read  > HIGH_READ_BYTES   (running total check)
//        3. Cumulative bytes written > HIGH_WRITE_BYTES
//        4. Cumulative files deleted ≥ MANY_FILES_DELETED
// ─────────────────────────────────────────────────────────────────────────────
void UsbSession::CheckAnomalies(const std::string& operation,
    const std::string& filePath,
    uint64_t           size)
{
    // ── 1. Executable write ───────────────────────────────────────────────
    if (AnomalyThresholds::EXECUTABLE_WRITE_ALERT && operation == "write") {
        size_t dot = filePath.find_last_of('.');
        if (dot != std::string::npos) {
            std::string ext = filePath.substr(dot);
            for (char& c : ext)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            static const std::vector<std::string> kExeExts = {
                ".exe", ".dll", ".scr", ".bat", ".cmd",
                ".ps1", ".vbs", ".js",  ".msi", ".com"
            };
            if (std::find(kExeExts.begin(), kExeExts.end(), ext) != kExeExts.end()) {
                std::string anomaly = "executable_written: " + filePath;
                bool alreadySeen = false;
                for (const auto& a : m_anomalies) {
                    if (a == anomaly) { alreadySeen = true; break; }
                }
                // Cap: only store if under the limit
                if (!alreadySeen &&
                    m_anomalies.size() < AnomalyThresholds::MAX_ANOMALY_ENTRIES)
                {
                    m_anomalies.push_back(anomaly);
                }
            }
        }
    }

    // ── 2. High-volume read threshold (cumulative, fires once) ───────────
    if (operation == "read"
        && m_totalBytesRead >= AnomalyThresholds::HIGH_READ_BYTES)
    {
        // Only emit the anomaly the first time the threshold is crossed.
        std::string tag = "high_read_volume";
        bool seen = false;
        for (const auto& a : m_anomalies)
            if (a.rfind(tag, 0) == 0) { seen = true; break; }
        if (!seen &&
            m_anomalies.size() < AnomalyThresholds::MAX_ANOMALY_ENTRIES)
        {
            std::ostringstream msg;
            msg << tag << ": " << (m_totalBytesRead / (1024 * 1024)) << " MB read";
            m_anomalies.push_back(msg.str());
        }
    }

    // ── 3. High-volume write threshold (cumulative, fires once) ──────────
    if (operation == "write"
        && m_totalBytesWritten >= AnomalyThresholds::HIGH_WRITE_BYTES)
    {
        std::string tag = "high_write_volume";
        bool seen = false;
        for (const auto& a : m_anomalies)
            if (a.rfind(tag, 0) == 0) { seen = true; break; }
        if (!seen &&
            m_anomalies.size() < AnomalyThresholds::MAX_ANOMALY_ENTRIES)
        {
            std::ostringstream msg;
            msg << tag << ": " << (m_totalBytesWritten / (1024 * 1024)) << " MB written";
            m_anomalies.push_back(msg.str());
        }
    }

    // ── 4. Mass-deletion threshold ────────────────────────────────────────
    if (operation == "delete"
        && m_totalFilesDeleted >= AnomalyThresholds::MANY_FILES_DELETED)
    {
        std::string tag = "mass_deletion";
        bool seen = false;
        for (const auto& a : m_anomalies)
            if (a.rfind(tag, 0) == 0) { seen = true; break; }
        if (!seen &&
            m_anomalies.size() < AnomalyThresholds::MAX_ANOMALY_ENTRIES)
        {
            std::ostringstream msg;
            msg << tag << ": " << m_totalFilesDeleted << " files deleted";
            m_anomalies.push_back(msg.str());
        }
    }

    (void)size;  // size is used via m_totalBytes* above; suppress any residual warning
}

// ─────────────────────────────────────────────────────────────────────────────
// Finalize
//
// FIX (major): Previously emitted only 5 fields (timestamp, endpoint,
// event_type, session_id, duration_seconds), discarding every stat that was
// painstakingly collected.  Now emits a complete, structured JSON object
// including:
//   • Device identity  (vid, pid, serial, manufacturer, product, instanceId)
//   • Mount point
//   • Activity summary (reads, writes, deletes, executes, bytes)
//   • File extension breakdown
//   • Anomalies list
//   • Timing (start_time, end_time, duration_seconds, idle_seconds)
//
// FIX (safety): m_finalized guard prevents double-finalization; returns ""
// on second call so callers can detect misuse.
// ─────────────────────────────────────────────────────────────────────────────
std::string UsbSession::Finalize()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Guard against double-finalize.
    if (m_finalized) return {};
    m_finalized = true;

    auto endTime = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - m_startTime).count();
    auto idleMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - m_lastActivityTime).count();

    std::ostringstream j;

    // ── Helper lambdas (local to this scope) ─────────────────────────────
    auto str = [&](const std::string& key, const std::string& val, bool comma = true) {
        j << '"' << key << "\":\"" << EscapeJson(val) << '"';
        if (comma) j << ',';
        };
    auto num = [&](const std::string& key, uint64_t val, bool comma = true) {
        j << '"' << key << "\":" << val;
        if (comma) j << ',';
        };
    // dbl() saves and restores stream flags so std::fixed doesn't bleed into
    // subsequent num() calls if the call order ever changes during refactoring.
    auto dbl = [&](const std::string& key, double val, bool comma = true) {
        auto savedFlags = j.flags();
        auto savedPrec = j.precision();
        j << '"' << key << "\":" << std::fixed << std::setprecision(3) << val;
        j.flags(savedFlags);
        j.precision(savedPrec);
        if (comma) j << ',';
        };

    // ── Root object ───────────────────────────────────────────────────────
    j << '{';

    // -- Metadata
    str("timestamp", GetCurrentTimeISO());
    str("endpoint", "usb_monitor");
    str("event_type", "USB_SESSION_END");
    str("session_id", m_sessionId);

    // -- Device identity
    j << "\"device\":{";
    str("vid", m_identity.vid);
    str("pid", m_identity.pid);
    str("serial", m_identity.serialNumber);
    str("manufacturer", m_identity.manufacturer);
    str("product", m_identity.product);
    str("instance_id", m_identity.instanceId);
    str("device_path", m_identity.devicePath, /*comma=*/false);
    j << "},";

    // -- Mount point
    str("mount_point", m_mountPoint);

    // -- Activity summary
    j << "\"activity\":{";
    num("reads", m_totalReads);
    num("writes", m_totalWrites);
    num("deletes", m_totalDeletes);
    num("executes", m_totalExecutes);
    num("bytes_read", m_totalBytesRead);
    num("bytes_written", m_totalBytesWritten, /*comma=*/false);
    j << "},";

    // -- File extension breakdown  { ".pdf": 3, ".exe": 1, ... }
    j << "\"file_extensions\":{";
    bool firstExt = true;
    for (const auto& [ext, count] : m_fileExtensions) {
        if (!firstExt) j << ',';
        j << '"' << EscapeJson(ext) << "\":" << count;
        firstExt = false;
    }
    j << "},";

    // -- Anomalies  ["executable_written: ...", ...]
    j << "\"anomalies\":[";
    for (size_t i = 0; i < m_anomalies.size(); ++i) {
        if (i) j << ',';
        j << '"' << EscapeJson(m_anomalies[i]) << '"';
    }
    j << "],";

    // -- Timing
    j << "\"timing\":{";
    dbl("duration_seconds", durationMs / 1000.0);
    dbl("idle_seconds", idleMs / 1000.0, /*comma=*/false);
    j << '}';

    j << '}';
    return j.str();
}