#include "file_logger.h"

// =============================================================================
// TITAN - File Integrity Monitor
// file_logger.cpp
//
// FIX: Removed std::ios::binary. Binary mode buffers writes internally and
// only flushes when the 8KB buffer fills or flush() is called. If the process
// is killed (VS Stop button) before that, the file stays 0 KB.
// Text mode + explicit flush() after every write = every line hits disk
// immediately, no matter how the process ends.
// =============================================================================

#include <filesystem>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>

namespace titan::fim
{

    FileLogger::FileLogger()
        : max_file_bytes_(50ULL * 1024 * 1024)
        , bytes_written_(0)
        , initialized_(false)
    {
    }

    FileLogger::~FileLogger()
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (log_stream_.is_open())
        {
            log_stream_.flush();
            log_stream_.close();
        }
    }

    bool FileLogger::Initialize(const std::wstring& log_path, uint64_t max_file_bytes)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);

        try
        {
            log_path_ = log_path;
            max_file_bytes_ = max_file_bytes;

            std::filesystem::path path(log_path);

            if (path.has_parent_path())
                std::filesystem::create_directories(path.parent_path());

            // TEXT mode — no binary, so writes hit disk on flush() not on buffer fill
            log_stream_.open(path, std::ios::out | std::ios::app);

            if (!log_stream_.is_open())
            {
                std::cerr << "[FIM][Logger] Failed to open: " << path.string() << "\n";
                return false;
            }

            bytes_written_ = static_cast<uint64_t>(
                std::filesystem::exists(path) ? std::filesystem::file_size(path) : 0);

            initialized_ = true;

            std::cout << "[FIM][Logger] Initialized: " << path.string() << "\n";
            return true;
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Logger] Init error: " << ex.what() << "\n";
            return false;
        }
    }

    void FileLogger::Log(const std::string& json)
    {
        if (!initialized_ || json.empty()) return;

        std::lock_guard<std::mutex> lock(log_mutex_);
        try
        {
            RotateIfNeeded();
            log_stream_ << json << "\n";
            log_stream_.flush();  // hit disk immediately
            bytes_written_ += json.size() + 1;
        }
        catch (...) {}
    }

    void FileLogger::Log(const std::string& json, LogSeverity severity)
    {
        if (!initialized_ || json.empty()) return;

        std::string enriched;
        enriched.reserve(json.size() + 32);

        if (json.front() == '{')
        {
            enriched = "{\"severity\":\"";
            enriched += SeverityString(severity);
            enriched += "\",";
            enriched += json.substr(1);
        }
        else
        {
            enriched = json;
        }

        std::lock_guard<std::mutex> lock(log_mutex_);
        try
        {
            RotateIfNeeded();
            log_stream_ << enriched << "\n";
            log_stream_.flush();  // hit disk immediately
            bytes_written_ += enriched.size() + 1;
        }
        catch (...) {}
    }

    void FileLogger::Flush()
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (log_stream_.is_open()) log_stream_.flush();
    }

    void FileLogger::RotateIfNeeded()
    {
        if (bytes_written_ < max_file_bytes_) return;

        if (log_stream_.is_open())
        {
            log_stream_.flush();
            log_stream_.close();
        }

        try
        {
            std::filesystem::path current(log_path_);
            auto now = std::chrono::system_clock::now();
            auto now_t = std::chrono::system_clock::to_time_t(now);
            std::tm tm_info{};
            localtime_s(&tm_info, &now_t);

            std::ostringstream ts;
            ts << std::put_time(&tm_info, "%Y%m%d_%H%M%S");

            std::filesystem::path rotated =
                current.parent_path() /
                (current.stem().string() + "_" + ts.str() + current.extension().string());

            std::filesystem::rename(current, rotated);
            std::cout << "[FIM][Logger] Rotated to: " << rotated.string() << "\n";
        }
        catch (...) {}

        log_stream_.open(log_path_, std::ios::out | std::ios::trunc);
        bytes_written_ = 0;
    }

    const char* FileLogger::SeverityString(LogSeverity s)
    {
        switch (s)
        {
        case LogSeverity::INFO:     return "info";
        case LogSeverity::ALERT:    return "alert";
        case LogSeverity::WARNING:  return "warning";
        case LogSeverity::CRITICAL: return "critical";
        default:                    return "info";
        }
    }

} // namespace titan::fim