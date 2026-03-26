// usb_logger.cpp
#include "usb_logger.h"

#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>

// ── Static member definitions ─────────────────────────────────────────────────
std::mutex    UsbLogger::s_mutex;
std::ofstream UsbLogger::s_file;
std::string   UsbLogger::s_logPath;
size_t        UsbLogger::s_maxSize = 2ULL * 1024 * 1024;   // 2 MB — rotate frequently, keep RAM low
// FIX: was std::atomic<bool> — but s_initialized was only *read* atomically in
//      Log() before acquiring the mutex, then *written* inside the mutex in
//      Shutdown().  That creates a TOCTOU window: Log() could pass the atomic
//      check, then Shutdown() could close s_file before Log() re-acquires the
//      mutex and calls WriteLine().  Replacing with a plain bool and always
//      checking it inside the mutex eliminates the race entirely.
bool          UsbLogger::s_initialized = false;

// ─────────────────────────────────────────────────────────────────────────────
static std::string TimestampForFilename()
{
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbLogger::Initialize(const std::string& logPath, size_t maxSizeBytes)
{
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return false;   // already open — caller error, not fatal

    s_logPath = logPath;
    s_maxSize = maxSizeBytes;

    // Create parent directory tree if absent.
    auto dir = std::filesystem::path(s_logPath).parent_path();
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            std::cerr << "[UsbLogger] Cannot create directory '"
                << dir.string() << "': " << ec.message() << '\n';
            return false;
        }
    }

    s_file.open(s_logPath, std::ios::app);
    if (!s_file.is_open()) {
        std::cerr << "[UsbLogger] Cannot open log file: " << s_logPath << '\n';
        return false;
    }

    s_initialized = true;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::Shutdown()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    s_file.flush();
    s_file.close();
    s_initialized = false;
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::Log(const std::string& json)
{
    if (json.empty()) return;

    std::lock_guard<std::mutex> lock(s_mutex);
    // FIX: s_initialized checked inside the mutex — no race with Shutdown().
    if (!s_initialized) {
        std::cerr << "[UsbLogger] Log() called before Initialize().\n";
        return;
    }
    RotateIfNeeded();
    WriteLine(json);
}

// ─────────────────────────────────────────────────────────────────────────────
std::string UsbLogger::GetLogPath()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_logPath;
}

// ─────────────────────────────────────────────────────────────────────────────
// RotateIfNeeded  — mutex must be held by caller
// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::RotateIfNeeded()
{
    if (!s_file.is_open()) return;
    s_file.flush();

    std::error_code ec;
    auto fileSize = std::filesystem::file_size(s_logPath, ec);
    if (ec || fileSize < s_maxSize) return;

    s_file.close();

    std::string rotated = s_logPath + '.' + TimestampForFilename();
    std::error_code renameEc;
    std::filesystem::rename(s_logPath, rotated, renameEc);
    if (renameEc) {
        std::cerr << "[UsbLogger] Rotation rename failed: "
            << renameEc.message() << '\n';
    }

    s_file.open(s_logPath, std::ios::app);
    if (!s_file.is_open()) {
        std::cerr << "[UsbLogger] Failed to reopen log after rotation.\n";
        s_initialized = false;  // mark as broken so callers get the error message
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteLine  — mutex must be held by caller
// ─────────────────────────────────────────────────────────────────────────────
void UsbLogger::WriteLine(const std::string& line)
{
    if (!s_file.is_open()) return;
    s_file << line << '\n';
    s_file.flush();
}