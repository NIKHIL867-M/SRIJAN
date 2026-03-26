// usb_logger.h
#pragma once

#include <string>
#include <mutex>
#include <fstream>

// ─────────────────────────────────────────────────────────────────────────────
// UsbLogger
//
// Thread-safe append-only logger for USB session JSON summaries.
// Writes one JSON object per line (NDJSON / JSON-Lines format).
// Rotates the file by renaming it when it exceeds maxSizeBytes, then
// reopens a fresh file at the same path.
//
// Usage:
//   UsbLogger::Initialize("logs/usb.json");  // once at startup
//   UsbLogger::Log(jsonString);              // any thread
//   UsbLogger::Shutdown();                   // once at exit
//
// Thread-safety notes:
//   All public methods are mutex-guarded so they may be called concurrently.
//   FIX: s_initialized is now only checked and modified while holding s_mutex,
//        eliminating the previous TOCTOU race between the atomic load in Log()
//        and the file operations inside the same mutex scope.
// ─────────────────────────────────────────────────────────────────────────────
class UsbLogger {
public:
    // Open (or create) the log file at logPath.  Creates parent directories.
    // Returns true on success.  Returns false (no-op) if already initialized.
    static bool Initialize(const std::string& logPath,
        size_t             maxSizeBytes = 2ULL * 1024 * 1024);

    // Flush and close the log file.
    static void Shutdown();

    // Append a JSON string as one line.  No-op if not initialized.
    static void Log(const std::string& json);

    // Returns the active log file path, or empty string if not initialized.
    static std::string GetLogPath();

private:
    // Must be called with s_mutex held.
    static void RotateIfNeeded();
    static void WriteLine(const std::string& line);

    static std::mutex    s_mutex;
    static std::ofstream s_file;
    static std::string   s_logPath;
    static size_t        s_maxSize;
    static bool          s_initialized;  // FIX: plain bool — always accessed under s_mutex
};