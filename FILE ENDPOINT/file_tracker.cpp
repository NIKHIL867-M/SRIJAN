// =============================================================================
// TITAN - File Integrity Monitor
// file_tracker.cpp
//
// TempTracker implementation.
// See file_tracker.h for full design notes.
// =============================================================================

#include "file_tracker.h"
#include "file_logger.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

namespace titan::fim
{

    // =========================================================================
    // Constructor
    // =========================================================================

    TempTracker::TempTracker(FileLogger* logger)
        : logger_(logger)
    {
    }

    // =========================================================================
    // TrackEvent
    // Called for every Bucket B event. Returns true if the event was elevated.
    // =========================================================================

    bool TempTracker::TrackEvent(const FileEvent& event)
    {
        if (!logger_) return false;
        if (event.path.empty() || event.path == L"unknown") return false;

        std::wstring dir = ExtractDir(event.path);
        std::wstring key = BucketKey(dir, event.creator_pid > 0
            ? event.creator_pid
            : event.pid);
        uint32_t     pid = event.pid;

        std::lock_guard<std::mutex> lock(mutex_);

        // Update directory churn counter
        UpdateChurn(dir);

        // Get or create bucket
        auto& bucket = buckets_[key];
        if (bucket.directory.empty())
        {
            bucket.directory = dir;
            bucket.creator_pid = pid;
            bucket.creator_name = event.process_name;
            bucket.first_seen = std::chrono::steady_clock::now();
        }
        bucket.last_seen = std::chrono::steady_clock::now();

        // Cap check — if we are at max entries, evict clean buckets
        if (buckets_.size() > TEMP_TRACKER_MAX_ENTRIES)
            EvictCleanBuckets();

        // Get or create file entry inside this bucket
        std::wstring path_lower = ToLower(event.path);
        auto& entry = bucket.files[path_lower];
        bool  is_new = entry.path.empty();

        if (is_new)
        {
            entry.path = event.path;
            entry.file_key = event.file_key;
            entry.creator_pid = pid;
            entry.creator_name = event.process_name;
            entry.born_at = std::chrono::steady_clock::now();
            entry.state = TempFileState::WATCHING;
            bucket.total_created++;
            bucket.total_alive++;
        }
        entry.last_seen = std::chrono::steady_clock::now();

        // Handle DELETE — file is gone
        if (event.action == FileAction::DELETE_F)
        {
            entry.state = TempFileState::DROPPED;
            bucket.total_alive = (bucket.total_alive > 0)
                ? bucket.total_alive - 1 : 0;
            bucket.total_deleted++;

            // Short-lived clean file with no anomaly → count it in the
            // compressed summary, do not elevate individually.
            // This is compression, not dropping — still recorded in bucket summary.
            if (entry.state != TempFileState::ELEVATED
                && !entry.cross_pid && !entry.was_renamed)
            {
                return false;
            }
        }

        // Handle WRITE
        if (event.action == FileAction::WRITE)
            entry.write_count++;

        // Check for cross-process access (a PID different from the creator)
        if (pid != bucket.creator_pid && event.action != FileAction::DELETE_F)
        {
            entry.cross_pid = true;
            // Record the other PID if not already seen
            bool already = false;
            for (const auto& op : entry.other_pids)
                if (op.first == pid) { already = true; break; }
            if (!already)
                entry.other_pids.emplace_back(pid, event.process_name);
        }

        // Handle RENAME — check if renamed to executable
        if (event.action == FileAction::RENAME)
        {
            entry.was_renamed = true;
            // If renamed to executable extension anywhere → immediate CRITICAL
            if (IsExecutableExtension(event.path))
            {
                ElevateToBucketA(bucket, entry, "rename_to_executable");
                return true;
            }
        }

        // Run anomaly checks
        bool elevated = CheckAnomalies(bucket, entry, event);
        return elevated;
    }

    // =========================================================================
    // CheckAnomalies
    // Returns true if this entry was elevated to Bucket A
    // =========================================================================

    bool TempTracker::CheckAnomalies(TempBucket& bucket,
        TempFileEntry& entry,
        const FileEvent& event)
    {
        if (entry.state == TempFileState::ELEVATED) return true;   // already elevated

        auto now = std::chrono::steady_clock::now();
        auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.born_at).count();

        // R1: Cross-process access
        if (entry.cross_pid && !entry.other_pids.empty())
        {
            // Only elevate if the second process is suspicious
            for (const auto& op : entry.other_pids)
            {
                std::wstring name = ToLower(op.second);
                if (name.find(L"powershell") != std::wstring::npos ||
                    name.find(L"cmd.exe") != std::wstring::npos ||
                    name.find(L"wscript") != std::wstring::npos ||
                    name.find(L"cscript") != std::wstring::npos ||
                    name.find(L"mshta") != std::wstring::npos ||
                    name.find(L"rundll32") != std::wstring::npos ||
                    name.find(L"regsvr32") != std::wstring::npos ||
                    name.find(L"certutil") != std::wstring::npos ||
                    name.find(L"bitsadmin") != std::wstring::npos)
                {
                    ElevateToBucketA(bucket, entry,
                        "suspicious_process_cross_access");
                    return true;
                }
            }
        }

        // R3: Long-lived temp file still being accessed
        if (age_s > static_cast<long long>(TEMP_DEEP_WATCH_SECONDS))
        {
            ElevateToBucketA(bucket, entry, "long_lived_temp_file");
            return true;
        }

        // R5: Directory is dynamically classified as high-churn but the
        //     file has an extension that doesn't match the noise pattern
        {
            std::wstring dir_lower = ToLower(bucket.directory);
            auto dit = dir_churn_.find(dir_lower);
            if (dit != dir_churn_.end() && dit->second.is_high_churn)
            {
                // Inside a high-churn zone, document files are suspicious
                if (IsDocumentExtension(event.path))
                {
                    ElevateToBucketA(bucket, entry,
                        "document_in_high_churn_zone");
                    return true;
                }
            }
        }

        return false;
    }

    // =========================================================================
    // ElevateToBucketA
    // Marks entry and bucket, logs an elevated detail event
    // =========================================================================

    void TempTracker::ElevateToBucketA(TempBucket& bucket,
        TempFileEntry& entry,
        const std::string& reason)
    {
        entry.state = TempFileState::ELEVATED;
        bucket.has_anomaly = true;

        if (logger_)
        {
            std::string json = BuildElevatedJson(bucket, entry, reason);
            logger_->Log(json, LogSeverity::ALERT);
        }
    }

    // =========================================================================
    // Maintenance
    // Called every 30 seconds from the monitor loop.
    // Handles:
    //   - Compressing and logging completed clean buckets
    //   - Checking long-lived entries that haven't been deleted yet
    //   - Cleaning up fully-resolved buckets
    // =========================================================================

    void TempTracker::Maintenance()
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::steady_clock::now();

        for (auto bit = buckets_.begin(); bit != buckets_.end(); )
        {
            TempBucket& bucket = bit->second;

            // Check each alive file for long-lived elevation
            for (auto& [path, entry] : bucket.files)
            {
                if (entry.state == TempFileState::WATCHING ||
                    entry.state == TempFileState::TRUSTED_AGING)
                {
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(
                        now - entry.born_at).count();

                    if (age > static_cast<long long>(TEMP_DEEP_WATCH_SECONDS))
                    {
                        ElevateToBucketA(bucket, entry,
                            "maintenance_long_lived_temp");
                    }
                }
            }

            // A bucket is "complete" when all files are dropped or
            // the bucket has been idle for a long time (creator done)
            auto idle_s = std::chrono::duration_cast<std::chrono::seconds>(
                now - bucket.last_seen).count();
            bool all_resolved = (bucket.total_alive == 0);
            bool long_idle = (idle_s > 30);   // 30 sec idle = creator is done, compress now

            if (all_resolved || long_idle)
            {
                // Count elevated entries before compressing
                uint32_t elevated_count = 0;
                for (const auto& [p, e] : bucket.files)
                    if (e.state == TempFileState::ELEVATED) elevated_count++;

                // Only log a summary if there was actual activity worth recording
                if (bucket.total_created > 0)
                    CompressAndLogBucket(bucket);

                bit = buckets_.erase(bit);
                continue;
            }

            ++bit;
        }

        // Reset per-second churn counters that have expired
        for (auto& [dir, churn] : dir_churn_)
        {
            auto window_age = std::chrono::duration_cast<std::chrono::seconds>(
                now - churn.window_start).count();
            if (window_age >= 5)   // reset every 5 seconds
            {
                churn.count_this_second = 0;
                churn.window_start = now;
                churn.is_high_churn = false;
            }
        }
    }

    // =========================================================================
    // CompressAndLogBucket
    // Emits one summary log entry for a completed clean bucket
    // =========================================================================

    void TempTracker::CompressAndLogBucket(TempBucket& bucket)
    {
        if (!logger_) return;

        uint32_t elevated_count = 0;
        for (const auto& [p, e] : bucket.files)
            if (e.state == TempFileState::ELEVATED) elevated_count++;

        // Always log a summary — even if some entries were elevated individually.
        // This gives a complete picture of all temp activity.
        std::string json = BuildSummaryJson(bucket, elevated_count);
        // Summary entries are INFO — they are for audit completeness, not alerts
        logger_->Log(json, LogSeverity::INFO);
    }

    // =========================================================================
    // UpdateChurn
    // Increments the churn counter for a directory
    // =========================================================================

    void TempTracker::UpdateChurn(const std::wstring& dir)
    {
        std::wstring key = ToLower(dir);
        auto& entry = dir_churn_[key];
        auto  now = std::chrono::steady_clock::now();

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - entry.window_start).count();

        if (elapsed >= 1)
        {
            entry.count_this_second = 0;
            entry.window_start = now;
        }

        entry.count_this_second++;

        if (entry.count_this_second >= HIGH_CHURN_THRESHOLD)
            entry.is_high_churn = true;
    }

    // =========================================================================
    // IsHighChurnDirectory
    // =========================================================================

    bool TempTracker::IsHighChurnDirectory(const std::wstring& dir) const
    {
        std::wstring key = ToLower(dir);
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = dir_churn_.find(key);
        if (it == dir_churn_.end()) return false;
        return it->second.is_high_churn;
    }

    // =========================================================================
    // EvictCleanBuckets
    // When cap is reached, evict the oldest clean (no anomaly) buckets
    // =========================================================================

    void TempTracker::EvictCleanBuckets()
    {
        // Collect clean buckets sorted by last_seen ascending
        std::vector<std::pair<std::chrono::steady_clock::time_point,
            std::wstring>> candidates;

        for (const auto& [k, b] : buckets_)
        {
            if (!b.has_anomaly)
                candidates.emplace_back(b.last_seen, k);
        }

        std::sort(candidates.begin(), candidates.end());

        // Evict oldest 10% up to 128 buckets
        size_t evict_count = std::min(candidates.size(),
            std::max(size_t(1),
                candidates.size() / 10));
        evict_count = std::min(evict_count, size_t(128));

        for (size_t i = 0; i < evict_count; ++i)
        {
            auto it = buckets_.find(candidates[i].second);
            if (it != buckets_.end())
            {
                // Log summary before evicting
                if (it->second.total_created > 0)
                    CompressAndLogBucket(it->second);
                buckets_.erase(it);
            }
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    std::wstring TempTracker::BucketKey(const std::wstring& dir,
        uint32_t pid) const
    {
        return ToLower(dir) + L"|" + std::to_wstring(pid);
    }

    std::wstring TempTracker::ExtractDir(const std::wstring& path) const
    {
        std::filesystem::path p(path);
        return p.has_parent_path() ? p.parent_path().wstring() : path;
    }

    // =========================================================================
    // JSON builders
    // =========================================================================

    std::string TempTracker::WstrToUtf8(const std::wstring& ws)
    {
        std::string out;
        out.reserve(ws.size() * 2);
        for (size_t i = 0; i < ws.size(); ++i)
        {
            uint32_t cp = static_cast<uint16_t>(ws[i]);
            if (cp >= 0xD800 && cp <= 0xDBFF)
            {
                if (i + 1 < ws.size())
                {
                    uint32_t low = static_cast<uint16_t>(ws[i + 1]);
                    if (low >= 0xDC00 && low <= 0xDFFF)
                    {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        ++i;
                    }
                    else cp = 0xFFFD;
                }
                else cp = 0xFFFD;
            }
            else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;

            if (cp < 0x80)
            {
                char c = static_cast<char>(cp);
                if (c == '"')  out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else if (c == '\n') out += "\\n";
                else if (c == '\r') out += "\\r";
                else if (c == '\t') out += "\\t";
                else                out += c;
            }
            else if (cp < 0x800)
            {
                out += static_cast<char>(0xC0 | (cp >> 6));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            else if (cp < 0x10000)
            {
                out += static_cast<char>(0xE0 | (cp >> 12));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            else
            {
                out += static_cast<char>(0xF0 | (cp >> 18));
                out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
        }
        return out;
    }

    std::string TempTracker::BuildSummaryJson(const TempBucket& bucket,
        uint32_t elevated_count) const
    {
        auto now_t = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        std::tm tm_info{};
        gmtime_s(&tm_info, &now_t);
        std::ostringstream ts;
        ts << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%SZ");

        auto duration_s = std::chrono::duration_cast<std::chrono::seconds>(
            bucket.last_seen - bucket.first_seen).count();

        std::ostringstream j;
        j << "{";
        j << "\"endpoint\":\"file_integrity\",";
        j << "\"type\":\"temp_batch_summary\",";
        j << "\"directory\":\"" << WstrToUtf8(bucket.directory) << "\",";
        j << "\"creator_pid\":" << bucket.creator_pid << ",";
        j << "\"creator\":\"" << WstrToUtf8(bucket.creator_name) << "\",";
        j << "\"total_created\":" << bucket.total_created << ",";
        j << "\"total_deleted\":" << bucket.total_deleted << ",";
        j << "\"elevated_count\":" << elevated_count << ",";
        j << "\"duration_seconds\":" << duration_s << ",";
        j << "\"timestamp\":\"" << ts.str() << "\"";
        j << "}";
        return j.str();
    }

    std::string TempTracker::BuildElevatedJson(const TempBucket& bucket,
        const TempFileEntry& entry,
        const std::string& reason) const
    {
        auto now_t = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        std::tm tm_info{};
        gmtime_s(&tm_info, &now_t);
        std::ostringstream ts;
        ts << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%SZ");

        auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
            entry.last_seen - entry.born_at).count();

        std::ostringstream j;
        j << "{";
        j << "\"endpoint\":\"file_integrity\",";
        j << "\"type\":\"temp_anomaly\",";
        j << "\"reason\":\"" << reason << "\",";
        j << "\"path\":\"" << WstrToUtf8(entry.path) << "\",";
        j << "\"directory\":\"" << WstrToUtf8(bucket.directory) << "\",";
        j << "\"creator_pid\":" << entry.creator_pid << ",";
        j << "\"creator\":\"" << WstrToUtf8(entry.creator_name) << "\",";
        j << "\"write_count\":" << entry.write_count << ",";
        j << "\"age_seconds\":" << age_s << ",";
        j << "\"was_renamed\":" << (entry.was_renamed ? "true" : "false") << ",";
        j << "\"cross_pid\":" << (entry.cross_pid ? "true" : "false");

        if (!entry.other_pids.empty())
        {
            j << ",\"other_pids\":[";
            for (size_t i = 0; i < entry.other_pids.size(); ++i)
            {
                if (i > 0) j << ",";
                j << "{\"pid\":" << entry.other_pids[i].first
                    << ",\"name\":\"" << WstrToUtf8(entry.other_pids[i].second)
                    << "\"}";
            }
            j << "]";
        }

        j << ",\"timestamp\":\"" << ts.str() << "\"";
        j << "}";
        return j.str();
    }

} // namespace titan::fim