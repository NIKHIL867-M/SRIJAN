#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// file_processor.h
//
// Handles Bucket A (protected/executable) and Bucket C (normal files).
// Bucket B (temp) is handled by TempTracker in file_tracker.h.
//
// UPGRADES vs original:
//   - Document extensions now hashed on write-close (ransomware detection)
//   - ShouldIgnore replaced by bucket routing from _file_scope.h
//   - ActiveWriteEntry tracks write_count and is_document flag
//   - BuildJsonLog includes write_count and is_document fields
//   - ScoreSeverity updated for document modifications
// =============================================================================

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace titan::fim
{

    class FileLogger;

    enum class LogSeverity
    {
        INFO = 0,
        ALERT = 1,
        WARNING = 2,
        CRITICAL = 3
    };

    // DELETE is a Win32 macro — renamed to DELETE_F to avoid conflict
    enum class FileAction
    {
        CREATE = 0,
        WRITE = 1,
        DELETE_F = 2,
        RENAME = 3,
        CLOSE = 4,
        SET_INFO = 5,
        READ = 6
    };

    struct FileEvent
    {
        FileAction   action = FileAction::WRITE;
        std::wstring path = L"";
        std::wstring old_path = L"";
        uint32_t     pid = 0;
        uint32_t     tid = 0;
        uint32_t     creator_pid = 0;   // PID that originally opened the handle
        std::wstring process_name = L"";
        uint64_t     file_key = 0;
        std::chrono::system_clock::time_point timestamp;
    };

    struct ActiveWriteEntry
    {
        std::wstring path;
        uint32_t     pid = 0;
        uint32_t     tid = 0;
        std::wstring process_name;
        uint64_t     file_key = 0;
        bool         is_document = false;
        bool         is_protected = false;
        bool         is_executable = false;
        std::chrono::steady_clock::time_point last_write_time;
        uint32_t     write_count = 0;
    };

    class FileProcessor
    {
    public:

        FileProcessor();
        ~FileProcessor();

        bool Initialize(FileLogger* logger);

        // Process a Bucket A or Bucket C event
        void ProcessEvent(const FileEvent& event);

        void CleanupStaleEntries();

    private:

        FileLogger* logger_;
        std::unordered_map<uint64_t, ActiveWriteEntry> active_writes_;
        std::mutex   map_mutex_;

        void HandleCreate(const FileEvent& event);
        void HandleWrite(const FileEvent& event);
        void HandleClose(const FileEvent& event);
        void HandleDelete(const FileEvent& event);
        void HandleRename(const FileEvent& event);
        void HandleSetInfo(const FileEvent& event);

        // Hash only for executables, documents, and protected-path files
        std::string  ComputeSHA256(const std::wstring& path);

        LogSeverity  ScoreSeverity(FileAction action,
            const std::wstring& path,
            const std::wstring& process_name) const;

        std::wstring ResolveProcessName(uint32_t pid) const;

        std::string  BuildJsonLog(
            const FileEvent& event,
            const std::string& sha256,
            bool               is_protected,
            bool               is_executable,
            bool               is_document,
            uint32_t           write_count = 0
        );

        static std::string EscapeJsonString(const std::wstring& ws);
        static uint64_t    WriteKey(const FileEvent& ev);
    };

} // namespace titan::fim