#ifndef TITAN_FILTER_H
#define TITAN_FILTER_H

// ============================================================================
// filter.h  —  TITAN V3  FilterEngine
//
// The FilterEngine is a pure Signal Amplifier + Noise Suppressor.
// It answers exactly ONE question per event:
//   "Is this event informationally redundant?"
//   YES  → COMPRESS (count it; emit summary every 60s)
//   NO   → FORWARD  (send to detection pipeline immediately)
//
// There is NO drop path. NO scoring. NO severity. NO attack classification.
// Detection is the downstream pipeline's job — not ours.
//
// Seven-stage pipeline (executed in order for every process event):
//   Stage 1 — Path Canonicalisation    (resolve env vars, traversal, symlinks)
//   Stage 2 — Known Location Check     (SYSTEM / KNOWN_USER / UNKNOWN)
//   Stage 3 — Signature Verification   (LRU-cached; determines compress
//   eligibility) Stage 4 — Fork / Thread Summary    (compresses child/thread
//   counts) Stage 5 — DLL Activity             (forward new/anomalous; compress
//   known repeats) Stage 6 — Persistence Touchpoints  (ALWAYS FORWARD if any
//   persistence key touched) Stage 7 — Deduplication + Compress (60s ring
//   buffer; fingerprint-based)
//
// Fixed RAM budget (~1.3 MB total — never grows at runtime):
//   Structure 1: Known Root Set       (prefix hash set,   ~50 KB)
//   Structure 2: System DLL Name Set  (hash set,          ~5 KB)
//   Structure 3: Persistence Set      (hash set,          ~2 KB)
//   Structure 4: Signature LRU Cache  (1000-entry LRU,    ~200 KB)
//   Structure 5: Bloom Filters x2     (process_seen +
//                                      relationship_seen,  ~8 KB)
//   Structure 6: Dedup Ring Buffer    (2000-entry fixed,  ~1 MB)
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

    // ============================================================================
    // FORWARD DECLARATIONS
    // ============================================================================

    class FilterEngine;

    // ============================================================================
    // STRUCTURE 4 — SIGNATURE CACHE ENTRY
    // ============================================================================

    struct SignatureCacheEntry {
        bool valid{ false };
        std::wstring signer;     // e.g. "Microsoft Windows"
        std::wstring thumbprint; // hex thumbprint — used as fingerprint component
    };

    // ============================================================================
    // STRUCTURE 6 — DEDUP RING BUFFER ENTRY
    // ============================================================================

    struct DedupEntry {
        std::string fingerprint;
        uint64_t count{ 0 };
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
    };

    // ============================================================================
    // BLOOM FILTER  (~4 KB each, O(1) lookup, no false negatives)
    // Two instances: process_seen and relationship_seen.
    // A false positive means one missed compression — acceptable.
    // A false negative is impossible by design.
    // ============================================================================

    class BloomFilter {
    public:
        // 8 KB = 65 536 bits — gives ~0.1% false-positive rate for 10K entries
        static constexpr size_t BITS = 65536;

        BloomFilter() = default;

        // Returns true if key was DEFINITELY NOT seen before (novel).
        // Returns false if key was PROBABLY seen before.
        bool IsNovel(const std::string& key) const;

        // Insert a key. After this, IsNovel(key) will return false.
        void Insert(const std::string& key);

        // Persist to / load from an on-disk file (binary bitset dump).
        bool LoadFromFile(const std::wstring& path);
        bool SaveToFile(const std::wstring& path) const;

        void Reset();

    private:
        std::bitset<BITS> bits_;

        // Three independent hash positions for each key.
        void HashPositions(const std::string& key, size_t& h1, size_t& h2,
            size_t& h3) const;
    };

    // ============================================================================
    // LRU CACHE  (Structure 4 — Signature Cache)
    // std::list (LRU order) + std::unordered_map (O(1) lookup).
    // ============================================================================

    template <typename Key, typename Value> class LruCache {
    public:
        explicit LruCache(size_t max_entries) : max_(max_entries) {}

        // Returns nullptr on miss.
        const Value* Get(const Key& key);

        // Insert or update.
        void Put(const Key& key, Value value);

        size_t Size() const noexcept { return map_.size(); }
        size_t Capacity() const noexcept { return max_; }

    private:
        size_t max_;
        // list: front = most recently used, back = LRU candidate for eviction
        std::list<std::pair<Key, Value>> lru_list_;
        std::unordered_map<Key, typename std::list<std::pair<Key, Value>>::iterator>
            map_;
    };

    // ============================================================================
    // FILTER RESULT  — returned by FilterEngine::Process()
    // ============================================================================

    struct FilterResult {
        FilterDecision decision{ FilterDecision::FORWARD };

        // Set when decision == COMPRESS
        // The ring buffer manages the actual counter; this is a snapshot.
        uint64_t compress_count{ 0 };

        // True if the event was the 1st-ever-seen occurrence (bloom miss)
        bool is_novel_process{ false };
        bool is_novel_relationship{ false };

        // Which of the 11 forward rules fired (bitmask for diagnostics)
        // Bit 0 = Rule 1, Bit 1 = Rule 2, ... Bit 10 = Rule 11
        uint32_t forward_rules_fired{ 0 };
    };

    // ============================================================================
    // FILTER ENGINE  —  V3
    // ============================================================================

    class FilterEngine {
    public:
        FilterEngine();
        ~FilterEngine() = default;

        // Non-copyable
        FilterEngine(const FilterEngine&) = delete;
        FilterEngine& operator=(const FilterEngine&) = delete;

        // ------------------------------------------------------------------
        // Initialise the engine.
        // bloom_dir: directory where process_seen.bin and relationship_seen.bin
        //            are stored (persists across reboots).
        // Resolves all known roots, system DLLs and persistence paths from
        // the live system — not from hardcoded strings.
        // Must be called once before Process().
        // ------------------------------------------------------------------
        bool Initialize(const std::wstring& bloom_dir = L".\\data\\");

        // ------------------------------------------------------------------
        // MAIN ENTRY POINT
        // Run the 7-stage pipeline on a process event.
        // Fills in event.GetV3() with enriched data and returns a FilterResult.
        // The caller (ProcessMonitor) decides whether to emit FORWARD or COMPRESS.
        // ------------------------------------------------------------------
        FilterResult Process(Event& event);

        // ------------------------------------------------------------------
        // Compress summary emitter.
        // Called by the dedup ring buffer's 60-second ticker to flush counts.
        // Returns one CompressSummary per active fingerprint.
        // ------------------------------------------------------------------
        std::vector<CompressSummary> FlushCompressSummaries();

        // ------------------------------------------------------------------
        // Statistics
        // ------------------------------------------------------------------
        uint64_t GetForwardedCount() const noexcept { return fwd_count_.load(); }
        uint64_t GetCompressedCount() const noexcept { return cmp_count_.load(); }
        uint64_t GetTotalSeen() const noexcept { return total_count_.load(); }

    private:
        // ------------------------------------------------------------------
        // STAGE IMPLEMENTATIONS
        // ------------------------------------------------------------------

        // Stage 1: Resolve raw image_path → canonical_path.
        //          Returns false if path cannot be resolved (treat as UNKNOWN).
        bool Stage1_CanonicalisePath(Event& event, V3ProcessInfo& v3) const;

        // Stage 2: Classify canonical_path into SYSTEM / KNOWN_USER / UNKNOWN.
        void Stage2_ClassifyLocation(V3ProcessInfo& v3) const;

        // Stage 3: Verify signature via LRU cache.
        //          Sets v3.signature_valid, v3.signature_signer,
        //          v3.signature_thumbprint.
        void Stage3_VerifySignature(V3ProcessInfo& v3);

        // Stage 4: Populate fork/thread summary fields in v3.
        //          (child_count, unique_child_names, thread_count,
        //           duplicate_instances, new_child_flag)
        void Stage4_ForkThreadSummary(const Event& event, V3ProcessInfo& v3) const;

        // Stage 5: Classify DLL activity.
        //          Populates v3.dlls_new and v3.dlls_shadowing.
        void Stage5_DllActivity(const Event& event, V3ProcessInfo& v3) const;

        // Stage 6: Persistence check REMOVED in V3 (moved to detection pipeline)

        // Stage 7: Compute fingerprint, check dedup ring buffer.
        //          Returns FilterDecision.
        FilterDecision Stage7_DedupAndCompress(V3ProcessInfo& v3,
            FilterResult& result);

        // ------------------------------------------------------------------
        // THE 11 HARD FORWARD RULES  (evaluated inside Stage 7)
        // If ANY returns true, the event is forwarded regardless of dedup state.
        // ------------------------------------------------------------------
        bool ShouldAlwaysForward(const V3ProcessInfo& v3, FilterResult& result) const;

        // ------------------------------------------------------------------
        // HELPER METHODS
        // ------------------------------------------------------------------

        // Structure 1 — known root lookup (O(1) prefix match)
        LocationType ClassifyPath(const std::wstring& canonical_path) const;

        // Structure 2 — DLL shadowing check
        bool IsDllShadowingSystemDll(const std::wstring& dll_canonical_path) const;

        // Structure 4 — signature verification (calls WinVerifyTrust if cache miss)
        SignatureCacheEntry
            VerifySignatureUncached(const std::wstring& canonical_path) const;

        // Structure 5 — bloom filter helpers
        std::string BloomKeyForProcess(const std::wstring& canonical_path) const;
        std::string BloomKeyForRelationship(const std::wstring& parent_path,
            const std::wstring& child_path) const;

        // Fingerprint construction (SHA-256 over canonical_path + parent +
        // cmdline_normalized[:256] + thumbprint + location_type)
        std::string ComputeFingerprint(const V3ProcessInfo& v3) const;

        // SHA-256 over an arbitrary byte string (used by fingerprint + bloom keys)
        static std::string Sha256Hex(const std::string& data);

        // Build the known-root set from live system env vars at startup
        void BuildKnownRootSet();

        // Build the system-DLL name set from System32 + SysWOW64 at startup
        void BuildSystemDllSet();

        // Resolve a single env-var path and add it to known_roots_ with its trust
        // level
        void AddRootFromEnv(const wchar_t* env_var, LocationType trust);

        // Add every subdirectory entry in a system PATH string
        void AddRootsFromPathEnv(const wchar_t* env_var, LocationType trust);

        // ------------------------------------------------------------------
        // STRUCTURE 1 — Known Root Set  (~50 KB)
        // Maps resolved lowercase prefix → LocationType
        // Sorted descending by length so longest-prefix wins.
        // ------------------------------------------------------------------
        struct RootEntry {
            std::wstring prefix; // lowercase, ends with backslash
            LocationType trust;
        };
        std::vector<RootEntry> known_roots_; // sorted longest-first at startup

        // ------------------------------------------------------------------
        // STRUCTURE 2 — System DLL Name Set  (~5 KB)
        // Lowercase filenames only (e.g. L"ntdll.dll")
        // ------------------------------------------------------------------
        std::unordered_set<std::wstring> system_dll_names_;

        // System DLL directory prefixes used for shadowing checks
        std::vector<std::wstring> system_dll_dirs_; // e.g. "c:\windows\system32\"

        // ------------------------------------------------------------------
        // STRUCTURE 4 — Signature LRU Cache  (~200 KB, 1000 entries max)
        // ------------------------------------------------------------------
        mutable std::mutex sig_cache_mutex_;
        LruCache<std::wstring, SignatureCacheEntry> sig_cache_{ 1000 };

        // Expected signer prefix per LocationType (SYSTEM only)
        // KNOWN_USER: any valid Authenticode signer is acceptable
        // UNKNOWN:    signature state not checked (already forwarded in Stage 2)
        static constexpr const wchar_t* kMicrosoftSigners[] = {
            L"microsoft windows", L"microsoft corporation", nullptr };

        // ------------------------------------------------------------------
        // STRUCTURE 5 — Bloom Filters  (~8 KB total)
        // ------------------------------------------------------------------
        mutable std::mutex bloom_mutex_;
        BloomFilter bloom_process_;      // key: SHA256(canonical_path)
        BloomFilter bloom_relationship_; // key: SHA256(parent+child paths)
        std::wstring bloom_dir_;         // where .bin files live

        // ------------------------------------------------------------------
        // STRUCTURE 6 — Dedup Ring Buffer  (~1 MB, 2000 entries max)
        // Fixed-size ring; old entries evicted on insert.
        // ------------------------------------------------------------------
        static constexpr size_t kRingMax = 2000;
        static constexpr uint32_t kWindowSecs = 60;

        mutable std::mutex ring_mutex_;
        std::vector<DedupEntry> ring_; // fixed capacity kRingMax
        size_t ring_head_{ 0 };
        std::unordered_map<std::string, size_t> ring_index_; // fingerprint → slot

        // ------------------------------------------------------------------
        // COUNTERS
        // ------------------------------------------------------------------
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
        // Move to front (most recently used)
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
            // Evict LRU (back of list)
            auto& back = lru_list_.back();
            map_.erase(back.first);
            lru_list_.pop_back();
        }
        lru_list_.emplace_front(key, std::move(value));
        map_[key] = lru_list_.begin();
    }

} // namespace titan

#endif // TITAN_FILTER_H