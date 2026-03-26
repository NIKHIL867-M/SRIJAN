#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// file_logger.h
// =============================================================================

#include <string>
#include <fstream>
#include <mutex>
#include <cstdint>

// LogSeverity is defined in file_processor.h
// Include it here so logger can accept it
#include "file_processor.h"

namespace titan::fim
{

    class FileLogger
    {
    public:

        FileLogger();
        ~FileLogger();

        bool Initialize(
            const std::wstring& log_path,
            uint64_t max_file_bytes = 50ULL * 1024 * 1024
        );

        void Log(const std::string& json);
        void Log(const std::string& json, LogSeverity severity);
        void Flush();

    private:

        std::ofstream log_stream_;
        std::mutex    log_mutex_;
        std::wstring  log_path_;
        uint64_t      max_file_bytes_;
        uint64_t      bytes_written_;
        bool          initialized_;

        void RotateIfNeeded();
        static const char* SeverityString(LogSeverity s);
    };

} // namespace titan::fim