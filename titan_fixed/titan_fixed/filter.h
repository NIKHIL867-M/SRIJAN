#ifndef TITAN_FILTER_H
#define TITAN_FILTER_H

// ============================================================================
// filter.h  —  TITAN V3  FilterEngine
//
// Changes in this revision:
//   DedupEntry: ADDED process_name, canonical_path fields so that
//     FlushCompressSummaries() can populate CompressSummary correctly.
//     Previously those fields were always empty in the COMPRESS JSON output.
//
//   FilterEngine::Stage1_CanonicalisePath():
//     Now copies pid, parent_pid, real_parent_pid, image_path_raw,
//     command_line_raw, user_name, user_sid, elevation, integrity,
//     session_id, is_64bit, create_time, log_time from ProcessInfo → V3.
//     These were all populated by ProcessMonitor but never transferred.
//
//   FilterEngine::Stage7_DedupAndCompress():
//     Stores process_name + canonical_path in the DedupEntry when created.
// ============================================================================

#include "event.h"

#include <atomic>
#include <bitset>
#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>

namespace titan {

    class FilterEngine;

    // ============================================================================
    // STRUCTURE 4 — SIGNATURE CACHE ENTRY
    // ============================================================================

    struct SignatureCacheEntry {
        bool         valid{ false };
        std::wstring signer;
        std::wstring thumbprint;
    };

    // ============================================================================
    // STRUCTURE 6 — DEDUP RING BUFFER ENTRY
    //
    // FIX: Added process_name and canonical_path so FlushCompressSummaries()
    //      can emit meaningful COMPRESS records (previously always empty strings).
    // ============================================================================

    struct DedupEntry {
        std::string  fingerprint;
        std::wstring process_name;      // FIX: basename of the compressed process
        std::wstring canonical_path;    // FIX: full resolved path of the process
        uint64_t     count{ 0 };
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
    };

    // ============================================================================
    // BLOOM FILTER
    // ============================================================================

    class BloomFilter {
    public:
        static constexpr size_t BITS = 65536;

        BloomFilter() = default;

        bool IsNovel(const std::string& key) const;
        void Insert(const std::string& key);

        bool LoadFromFile(const std::wstring& path);
        bool SaveToFile(const std::wstring& path) const;

        void Reset();

    private:
        std::bitset<BITS> bits_;

        void HashPositions(const std::string& key, size_t& h1, size_t& h2,
            size_t& h3) const;
    };

    // ============================================================================
    // LRU CACHE
    // ============================================================================

    template <typename Key, typename Value> class LruCache {
    public:
        explicit LruCache(size_t max_entries) : max_(max_entries) {}

        const Value* Get(const Key& key);
        void         Put(const Key& key, Value value);

        size_t Size()     const noexcept { return map_.size(); }
        size_t Capacity() const noexcept { return max_; }

    private:
        size_t max_;
        std::list<std::pair<Key, Value>> lru_list_;
        std::unordered_map<Key, typename std::list<std::pair<Key, Value>>::iterator>
            map_;
    };

    // ============================================================================
    // FILTER RESULT
    // ============================================================================

    struct FilterResult {
        FilterDecision decision{ FilterDecision::FORWARD };
        uint64_t       compress_count{ 0 };
        bool           is_novel_process{ false };
        bool           is_novel_relationship{ false };
        uint32_t       forward_rules_fired{ 0 };
    };

    // ============================================================================
    // FILTER ENGINE — V3
    // ============================================================================

    class FilterEngine {
    public:
        FilterEngine();
        ~FilterEngine() = default;

        FilterEngine(const FilterEngine&) = delete;
        FilterEngine& operator=(const FilterEngine&) = delete;

        bool Initialize(const std::wstring& bloom_dir = L".\\data\\");

        FilterResult Process(Event& event);

        std::vector<CompressSummary> FlushCompressSummaries();

        uint64_t GetForwardedCount()  const noexcept { return fwd_count_.load(); }
        uint64_t GetCompressedCount() const noexcept { return cmp_count_.load(); }
        uint64_t GetTotalSeen()       const noexcept { return total_count_.load(); }

    private:
        // Stage implementations
        bool           Stage1_CanonicalisePath(Event& event, V3ProcessInfo& v3) const;
        void           Stage2_ClassifyLocation(V3ProcessInfo& v3) const;
        void           Stage3_VerifySignature(V3ProcessInfo& v3);
        void           Stage4_ForkThreadSummary(const Event& event, V3ProcessInfo& v3) const;
        void           Stage5_DllActivity(const Event& event, V3ProcessInfo& v3) const;
        void           Stage6_PersistenceTouchpoints(const Event& event, V3ProcessInfo& v3) const;
        FilterDecision Stage7_DedupAndCompress(V3ProcessInfo& v3, FilterResult& result);

        bool ShouldAlwaysForward(const V3ProcessInfo& v3, FilterResult& result) const;

        // Helpers
        LocationType ClassifyPath(const std::wstring& canonical_path) const;
        bool IsDllShadowingSystemDll(const std::wstring& dll_canonical_path) const;
        bool IsPersistencePath(const std::wstring& path_or_key) const;

        SignatureCacheEntry VerifySignatureUncached(const std::wstring& canonical_path) const;

        std::string BloomKeyForProcess(const std::wstring& canonical_path) const;
        std::string BloomKeyForRelationship(const std::wstring& parent_path,
            const std::wstring& child_path) const;

        std::string ComputeFingerprint(const V3ProcessInfo& v3) const;
        static std::string Sha256Hex(const std::string& data);

        void BuildKnownRootSet();
        void BuildSystemDllSet();
        void BuildPersistenceSet();
        void AddRootFromEnv(const wchar_t* env_var, LocationType trust);
        void AddRootsFromPathEnv(const wchar_t* env_var, LocationType trust);

        // Structure 1 — Known Root Set
        struct RootEntry {
            std::wstring prefix;
            LocationType trust;
        };
        std::vector<RootEntry> known_roots_;

        // Structure 2 — System DLL Name Set
        std::unordered_set<std::wstring> system_dll_names_;
        std::vector<std::wstring>        system_dll_dirs_;

        // Structure 3 — Persistence Location Set
        std::unordered_set<std::wstring> persistence_paths_;

        // Structure 4 — Signature LRU Cache
        mutable std::mutex sig_cache_mutex_;
        LruCache<std::wstring, SignatureCacheEntry> sig_cache_{ 1000 };

        static constexpr const wchar_t* kMicrosoftSigners[] = {
            L"microsoft windows", L"microsoft corporation", nullptr };

        // Structure 5 — Bloom Filters
        mutable std::mutex bloom_mutex_;
        BloomFilter        bloom_process_;
        BloomFilter        bloom_relationship_;
        std::wstring       bloom_dir_;

        // Structure 6 — Dedup Ring Buffer
        static constexpr size_t   kRingMax = 2000;
        static constexpr uint32_t kWindowSecs = 60;

        mutable std::mutex ring_mutex_;
        std::vector<DedupEntry>               ring_;
        size_t                                ring_head_{ 0 };
        std::unordered_map<std::string, size_t> ring_index_;

        // Counters
        std::atomic<uint64_t> total_count_{ 0 };
        std::atomic<uint64_t> fwd_count_{ 0 };
        std::atomic<uint64_t> cmp_count_{ 0 };

        bool initialized_{ false };
    };

    // ============================================================================
    // LruCache — inline template implementation
    // ============================================================================

    template <typename Key, typename Value>
    const Value* LruCache<Key, Value>::Get(const Key& key) {
        auto it = map_.find(key);
        if (it == map_.end())
            return nullptr;
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
        return &it->second->second;
    }

    template <typename Key, typename Value>
    void LruCache<Key, Value>::Put(const Key& key, Value value) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second->second = std::move(value);
            lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
            return;
        }
        if (lru_list_.size() >= max_) {
            auto& back = lru_list_.back();
            map_.erase(back.first);
            lru_list_.pop_back();
        }
        lru_list_.emplace_front(key, std::move(value));
        map_[key] = lru_list_.begin();
    }

} // namespace titan

#endif // TITAN_FILTER_H