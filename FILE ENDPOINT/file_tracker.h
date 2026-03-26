#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// file_tracker.h
//
// TempTracker — lifecycle analysis for Bucket B (temp/high-churn) files.
//
// WHAT IT DOES:
//   Receives every Bucket B file event from FileMonitor.
//   Tracks files using per-directory buckets keyed by {dir + creator_pid}.
//   Makes intelligent decisions about what to compress vs what to elevate.
//
// THREE OUTCOMES FOR EVERY FILE:
//   1. COMPRESS  → normal temp activity, log one summary per batch
//   2. ELEVATE   → anomalous behaviour detected, promote to Bucket A treatment
//   3. DROP      → confirmed clean short-life file, no log needed
//
// ANOMALY RULES (any one triggers ELEVATE):
//   R1. A second PID opens a file from this batch
//   R2. Any file in the batch is renamed to an executable extension
//   R3. A file survives past TEMP_DEEP_WATCH_SECONDS (5 min default)
//       AND is still being accessed
//   R4. The creator PID terminates within 2 seconds of creating a batch
//       (dropper pattern: create-and-exit)
//   R5. The directory itself is not a known temp path but is exhibiting
//       high-churn behaviour (dynamic temp zone detection)
//
// DIRECTORY REPUTATION:
//   Each directory gets a churn counter per 1-second window.
//   If churn exceeds HIGH_CHURN_THRESHOLD, the directory is marked as a
//   "dynamic temp zone" and its files are routed through TempTracker even
//   if the path is not in GetKnownTempPaths().
//
// RAM MANAGEMENT:
//   Buckets are capped at TEMP_TRACKER_MAX_ENTRIES total live files.
//   When cap is reached, oldest clean buckets are compressed and evicted.
//   Anomalous entries are NEVER evicted until resolved.
// =============================================================================

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <functional>

#include "_file_scope.h"
#include "file_processor.h"   // FileEvent, FileAction, LogSeverity

namespace titan::fim
{
    class FileLogger;

    // =========================================================================
    // Lifecycle state of a single tracked temp file
    // =========================================================================
    enum class TempFileState
    {
        WATCHING,         // just arrived, we are observing
        TRUSTED_AGING,    // no anomaly, within normal lifespan
        ELEVATED,         // anomaly detected, treat as Bucket A
        DROPPED,          // confirmed clean, removed from tracking
    };

    // =========================================================================
    // Single file entry inside a TempBucket
    // =========================================================================
    struct TempFileEntry
    {
        std::wstring  path;
        uint64_t      file_key = 0;
        uint32_t      creator_pid = 0;
        std::wstring  creator_name;
        std::chrono::steady_clock::time_point born_at;
        std::chrono::steady_clock::time_point last_seen;
        TempFileState state = TempFileState::WATCHING;
        bool          was_renamed = false;
        bool          cross_pid = false;       // touched by a second PID
        uint32_t      write_count = 0;
        // Other PIDs that touched this file
        std::vector<std::pair<uint32_t, std::wstring>> other_pids; // {pid, name}
    };

    // =========================================================================
    // A batch of temp files grouped by {directory + creator_pid}
    // =========================================================================
    struct TempBucket
    {
        std::wstring  directory;
        uint32_t      creator_pid = 0;
        std::wstring  creator_name;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        uint32_t      total_created = 0;
        uint32_t      total_deleted = 0;
        uint32_t      total_alive = 0;
        bool          has_anomaly = false;
        std::unordered_map<std::wstring, TempFileEntry> files; // path → entry
    };

    // =========================================================================
    // Per-directory churn tracker (for dynamic temp zone detection)
    // =========================================================================
    struct DirChurnEntry
    {
        uint32_t      count_this_second = 0;
        std::chrono::steady_clock::time_point window_start;
        bool          is_high_churn = false;
    };

    // =========================================================================
    // TempTracker
    // =========================================================================
    class TempTracker
    {
    public:

        explicit TempTracker(FileLogger* logger);
        ~TempTracker() = default;

        // Called by FileMonitor for every Bucket B event
        // Returns true if the event was elevated to Bucket A treatment
        // (caller should then log it as a full detail event)
        bool TrackEvent(const FileEvent& event);

        // Called periodically from the monitor maintenance loop
        void Maintenance();

        // Is this directory currently classified as high-churn?
        bool IsHighChurnDirectory(const std::wstring& dir) const;

    private:

        FileLogger* logger_;
        mutable std::mutex mutex_;

        // Buckets keyed by lowercase(directory) + "|" + pid string
        std::unordered_map<std::wstring, TempBucket> buckets_;

        // Directory churn counters
        std::unordered_map<std::wstring, DirChurnEntry> dir_churn_;

        // --- internal helpers ---

        std::wstring  BucketKey(const std::wstring& dir, uint32_t pid) const;
        std::wstring  ExtractDir(const std::wstring& path) const;
        void          UpdateChurn(const std::wstring& dir);
        bool          CheckAnomalies(TempBucket& bucket, TempFileEntry& entry,
            const FileEvent& event);
        void          ElevateToBucketA(TempBucket& bucket,
            TempFileEntry& entry,
            const std::string& reason);
        void          CompressAndLogBucket(TempBucket& bucket);
        void          EvictCleanBuckets();

        std::string   BuildSummaryJson(const TempBucket& bucket,
            uint32_t elevated_count) const;
        std::string   BuildElevatedJson(const TempBucket& bucket,
            const TempFileEntry& entry,
            const std::string& reason) const;

        static std::string WstrToUtf8(const std::wstring& ws);
    };

} // namespace titan::fim