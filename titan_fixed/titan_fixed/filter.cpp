#include "filter.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>

#include <softpub.h>
#include <wintrust.h>
#pragma comment(lib, "wintrust.lib")

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#pragma comment(lib, "normaliz.lib")

namespace titan {

    // ============================================================================
    // BLOOM FILTER
    // ============================================================================

    void BloomFilter::HashPositions(const std::string& key, size_t& h1, size_t& h2,
        size_t& h3) const {
        auto fnv = [](const std::string& s, uint64_t seed) -> uint64_t {
            uint64_t h = seed;
            for (unsigned char c : s) {
                h ^= static_cast<uint64_t>(c);
                h *= 0x00000100000001B3ULL;
            }
            return h;
            };
        h1 = static_cast<size_t>(fnv(key, 0xcbf29ce484222325ULL) % BITS);
        h2 = static_cast<size_t>(fnv(key, 0x84222325cbf29ce4ULL) % BITS);
        h3 = static_cast<size_t>(fnv(key, 0x517cc1b727220a95ULL) % BITS);
    }

    bool BloomFilter::IsNovel(const std::string& key) const {
        size_t h1, h2, h3;
        HashPositions(key, h1, h2, h3);
        return !bits_[h1] || !bits_[h2] || !bits_[h3];
    }

    void BloomFilter::Insert(const std::string& key) {
        size_t h1, h2, h3;
        HashPositions(key, h1, h2, h3);
        bits_.set(h1);
        bits_.set(h2);
        bits_.set(h3);
    }

    bool BloomFilter::LoadFromFile(const std::wstring& path) {
        std::ifstream f(std::filesystem::path(path), std::ios::binary);
        if (!f.is_open())
            return false;
        for (size_t i = 0; i < BITS && f.good(); ++i) {
            uint8_t b = 0;
            f.read(reinterpret_cast<char*>(&b), 1);
            if (b)
                bits_.set(i);
        }
        return f.good() || f.eof();
    }

    bool BloomFilter::SaveToFile(const std::wstring& path) const {
        std::ofstream f(std::filesystem::path(path),
            std::ios::binary | std::ios::trunc);
        if (!f.is_open())
            return false;
        for (size_t i = 0; i < BITS; ++i) {
            uint8_t b = bits_[i] ? 1 : 0;
            f.write(reinterpret_cast<const char*>(&b), 1);
        }
        return f.good();
    }

    void BloomFilter::Reset() { bits_.reset(); }

    // ============================================================================
    // FILTER ENGINE — CONSTRUCTOR / INITIALIZE
    // ============================================================================

    FilterEngine::FilterEngine() {
        ring_.reserve(kRingMax);
        ring_index_.reserve(kRingMax);
    }

    bool FilterEngine::Initialize(const std::wstring& bloom_dir) {
        if (initialized_)
            return true;
        bloom_dir_ = bloom_dir;

        BuildKnownRootSet();
        BuildSystemDllSet();

        {
            std::lock_guard<std::mutex> lock(bloom_mutex_);
            bloom_process_.LoadFromFile(bloom_dir_ + L"process_seen.bin");
            bloom_relationship_.LoadFromFile(bloom_dir_ + L"relationship_seen.bin");
        }

        initialized_ = true;
        return true;
    }

    // ============================================================================
    // ROOT / DLL SET BUILDERS
    // ============================================================================

    void FilterEngine::AddRootFromEnv(const wchar_t* env_var, LocationType trust) {
        wchar_t buf[MAX_PATH * 2]{};
        if (!GetEnvironmentVariableW(env_var, buf,
            static_cast<DWORD>(std::size(buf))))
            return;
        std::wstring path = utils::CanonicalizePath(buf);
        if (path.empty())
            return;
        if (!path.empty() && path.back() != L'\\')
            path += L'\\';

        known_roots_.push_back({ path, trust });
        if (trust == LocationType::SYSTEM) {
            for (auto& sub : { L"system32\\", L"syswow64\\", L"winsxs\\" })
                known_roots_.push_back({ path + sub, LocationType::SYSTEM });
        }
    }

    // FIX C6262: wchar_t buf[32768] (64 KB) was a stack-local variable, triggering
    // the "function uses >16 KB of stack" SAL warning.  Allocate on the heap instead.
    void FilterEngine::AddRootsFromPathEnv(const wchar_t* env_var,
        LocationType trust) {
        constexpr DWORD kBufLen = 32768;
        auto buf = std::make_unique<wchar_t[]>(kBufLen);  // heap allocation
        if (!GetEnvironmentVariableW(env_var, buf.get(), kBufLen))
            return;

        std::wstring paths(buf.get());
        size_t start = 0;
        while (start < paths.size()) {
            size_t end = paths.find(L';', start);
            if (end == std::wstring::npos)
                end = paths.size();
            std::wstring entry = paths.substr(start, end - start);
            if (!entry.empty()) {
                std::wstring canonical = utils::CanonicalizePath(entry);
                if (!canonical.empty()) {
                    if (canonical.back() != L'\\')
                        canonical += L'\\';
                    known_roots_.push_back({ canonical, trust });
                }
            }
            start = end + 1;
        }
    }

    void FilterEngine::BuildKnownRootSet() {
        known_roots_.clear();

        AddRootFromEnv(L"SystemRoot", LocationType::SYSTEM);
        AddRootFromEnv(L"windir", LocationType::SYSTEM);
        AddRootsFromPathEnv(L"Path", LocationType::SYSTEM);

        AddRootFromEnv(L"ProgramFiles", LocationType::KNOWN_USER);
        AddRootFromEnv(L"ProgramFiles(x86)", LocationType::KNOWN_USER);
        AddRootFromEnv(L"ProgramData", LocationType::KNOWN_USER);
        AddRootsFromPathEnv(L"PATH", LocationType::KNOWN_USER);

        wchar_t appdata[MAX_PATH]{};
        if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) {
            std::wstring p = utils::CanonicalizePath(appdata);
            if (!p.empty()) {
                if (p.back() != L'\\') p += L'\\';
                known_roots_.push_back({ p, LocationType::KNOWN_USER });
            }
        }
        wchar_t localapp[MAX_PATH]{};
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", localapp, MAX_PATH)) {
            std::wstring p = utils::CanonicalizePath(localapp);
            if (!p.empty()) {
                if (p.back() != L'\\') p += L'\\';
                known_roots_.push_back({ p + L"programs\\", LocationType::KNOWN_USER });
            }
        }

        std::sort(known_roots_.begin(), known_roots_.end(),
            [](const RootEntry& a, const RootEntry& b) {
                return a.prefix.size() > b.prefix.size();
            });

        auto last = std::unique(known_roots_.begin(), known_roots_.end(),
            [](const RootEntry& a, const RootEntry& b) {
                return a.prefix == b.prefix;
            });
        known_roots_.erase(last, known_roots_.end());
    }

    void FilterEngine::BuildSystemDllSet() {
        system_dll_names_.clear();
        system_dll_dirs_.clear();

        wchar_t sysroot[MAX_PATH]{};
        GetEnvironmentVariableW(L"SystemRoot", sysroot, MAX_PATH);
        std::wstring root = utils::CanonicalizePath(sysroot);
        if (root.empty())
            return;
        if (root.back() != L'\\')
            root += L'\\';

        const std::wstring dirs[] = { root + L"system32\\", root + L"syswow64\\",
                                     root + L"system\\" };

        for (const auto& dir : dirs) {
            system_dll_dirs_.push_back(dir);
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW((dir + L"*.dll").c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE)
                continue;
            do {
                std::wstring name(fd.cFileName);
                std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                system_dll_names_.insert(name);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }

    void FilterEngine::BuildPersistenceSet() {
        // Placeholder — persistence checking is available when needed.
        persistence_paths_.clear();
    }

    bool FilterEngine::IsPersistencePath(const std::wstring& path_or_key) const {
        return persistence_paths_.count(path_or_key) > 0;
    }

    // ============================================================================
    // PROCESS  —  main entry point
    // ============================================================================

    FilterResult FilterEngine::Process(Event& event) {
        total_count_.fetch_add(1, std::memory_order_relaxed);

        FilterResult  result;
        V3ProcessInfo& v3 = event.GetV3();

        if (!Stage1_CanonicalisePath(event, v3)) {
            v3.location_type = LocationType::UNKNOWN;
            v3.decision = FilterDecision::FORWARD;
            result.decision = FilterDecision::FORWARD;
            result.forward_rules_fired |= (1u << 1);
            event.MarkV3Enriched();
            fwd_count_.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        Stage2_ClassifyLocation(v3);

        if (v3.location_type == LocationType::UNKNOWN) {
            v3.decision = FilterDecision::FORWARD;
            result.decision = FilterDecision::FORWARD;
            result.forward_rules_fired |= (1u << 0);
            event.MarkV3Enriched();
            fwd_count_.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        Stage3_VerifySignature(v3);
        Stage4_ForkThreadSummary(event, v3);
        Stage5_DllActivity(event, v3);
        // Stage6 available but not wired — persistence_touched defaults false.

        FilterDecision decision = Stage7_DedupAndCompress(v3, result);

        v3.decision = decision;
        result.decision = decision;

        event.MarkV3Enriched();

        if (decision == FilterDecision::FORWARD)
            fwd_count_.fetch_add(1, std::memory_order_relaxed);
        else
            cmp_count_.fetch_add(1, std::memory_order_relaxed);

        return result;
    }

    // ============================================================================
    // STAGE 1 — PATH CANONICALISATION + FIELD COPY
    //
    // FIX: Now also copies all raw sensor fields from ProcessInfo -> V3ProcessInfo
    // that were populated by ProcessMonitor but never transferred.  Previously
    // pid, parent_pid, real_parent_pid, user_*, elevation, integrity, session_id,
    // is_64bit, create_time, log_time were all set to their zero defaults in V3.
    // ============================================================================

    bool FilterEngine::Stage1_CanonicalisePath(Event& event,
        V3ProcessInfo& v3) const {
        const ProcessInfo* p = event.GetProcessInfo();
        if (!p)
            return false;

        // ---- FIX: Copy all raw sensor fields that were previously ignored -------

        // Critical IDs
        v3.pid = p->pid;
        v3.parent_pid = p->parent_pid;
        v3.real_parent_pid = p->real_parent_pid;

        // Raw (pre-canonicalisation) paths
        v3.image_path_raw = p->image_path;
        v3.command_line_raw = p->command_line;

        // User / token context
        v3.user_name = p->user_name;
        v3.user_sid = p->user_sid;
        v3.elevation = p->elevation;
        v3.integrity = p->integrity;
        v3.session_id = p->session_id;
        v3.is_64bit = p->is_64bit;

        // Timestamps
        v3.create_time = p->create_time;
        v3.log_time = p->log_time;
        // exit_time is set by HandleProcessStop, not here.

        // ---- Path canonicalisation (original logic) ------------------------------

        v3.canonical_path = utils::CanonicalizePath(p->image_path);
        if (v3.canonical_path.empty())
            return false;

        auto pos = v3.canonical_path.find_last_of(L"\\/");
        v3.process_name = (pos != std::wstring::npos)
            ? v3.canonical_path.substr(pos + 1)
            : v3.canonical_path;

        // FIX: Use dedicated parent_image_path field instead of working_directory.
        if (!p->parent_image_path.empty()) {
            v3.parent_canonical_path = utils::CanonicalizePath(p->parent_image_path);
        }

        v3.cmdline_normalized = utils::NormalizeCommandLine(p->command_line);
        return true;
    }

    // ============================================================================
    // STAGE 2 — LOCATION CLASSIFICATION
    // ============================================================================

    void FilterEngine::Stage2_ClassifyLocation(V3ProcessInfo& v3) const {
        v3.location_type = ClassifyPath(v3.canonical_path);
    }

    LocationType
        FilterEngine::ClassifyPath(const std::wstring& canonical_path) const {
        for (const auto& entry : known_roots_) {
            if (canonical_path.compare(0, entry.prefix.size(), entry.prefix) == 0)
                return entry.trust;
        }
        return LocationType::UNKNOWN;
    }

    // ============================================================================
    // STAGE 3 — SIGNATURE VERIFICATION
    // ============================================================================

    void FilterEngine::Stage3_VerifySignature(V3ProcessInfo& v3) {
        {
            std::lock_guard<std::mutex> lock(sig_cache_mutex_);
            const SignatureCacheEntry* cached = sig_cache_.Get(v3.canonical_path);
            if (cached) {
                v3.signature_valid = cached->valid;
                v3.signature_signer = cached->signer;
                v3.signature_thumbprint = cached->thumbprint;
                return;
            }
        }

        SignatureCacheEntry entry = VerifySignatureUncached(v3.canonical_path);

        {
            std::lock_guard<std::mutex> lock(sig_cache_mutex_);
            sig_cache_.Put(v3.canonical_path, entry);
        }

        v3.signature_valid = entry.valid;
        v3.signature_signer = entry.signer;
        v3.signature_thumbprint = entry.thumbprint;
    }

    SignatureCacheEntry FilterEngine::VerifySignatureUncached(
        const std::wstring& canonical_path) const {
        SignatureCacheEntry entry;

        WINTRUST_FILE_INFO file_info{};
        file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
        file_info.pcwszFilePath = canonical_path.c_str();

        GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trust_data{};
        trust_data.cbStruct = sizeof(WINTRUST_DATA);
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.pFile = &file_info;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG result = WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE), &action_guid, &trust_data);

        if (result == ERROR_SUCCESS) {
            entry.valid = true;

            // Extract signer info from the trust provider state.
            CRYPT_PROVIDER_DATA* prov_data =
                WTHelperProvDataFromStateData(trust_data.hWVTStateData);
            if (prov_data) {
                CRYPT_PROVIDER_SGNR* signer =
                    WTHelperGetProvSignerFromChain(prov_data, 0, FALSE, 0);
                if (signer && signer->pasCertChain && signer->csCertChain > 0) {
                    PCCERT_CONTEXT cert_ctx = signer->pasCertChain[0].pCert;
                    if (cert_ctx) {
                        // Subject CN -> signer name
                        wchar_t name_buf[256]{};
                        CertGetNameStringW(cert_ctx,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                            nullptr, name_buf,
                            static_cast<DWORD>(std::size(name_buf)));
                        entry.signer = name_buf;

                        // SHA-1 thumbprint
                        BYTE   tp_bytes[20]{};
                        DWORD  tp_size = sizeof(tp_bytes);
                        CertGetCertificateContextProperty(
                            cert_ctx, CERT_SHA1_HASH_PROP_ID, tp_bytes, &tp_size);

                        std::ostringstream oss;
                        for (int i = 0; i < 20; ++i)
                            oss << std::hex << std::setw(2) << std::setfill('0')
                            << static_cast<int>(tp_bytes[i]);
                        // FIX: store once to avoid oss.str() iterator aliasing.
                        const std::string tp_str = oss.str();
                        entry.thumbprint = std::wstring(tp_str.begin(), tp_str.end());

                        CertFreeCertificateContext(cert_ctx);
                    }
                }
            }
        }

        HCERTSTORE hStore = nullptr;
        HCRYPTMSG  hMsg = nullptr;
        if (result != ERROR_SUCCESS) {
            if (hStore) CertCloseStore(hStore, 0);
            if (hMsg)   CryptMsgClose(hMsg);
        }

        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action_guid,
            &trust_data);

        return entry;
    }

    // ============================================================================
    // STAGE 4 — FORK / THREAD SUMMARY
    // ============================================================================

    void FilterEngine::Stage4_ForkThreadSummary(const Event& /*event*/,
        V3ProcessInfo& v3) const {
        if (!v3.new_child_flag) {
            for (const auto& child_path : v3.unique_child_names) {
                if (ClassifyPath(child_path) == LocationType::UNKNOWN) {
                    v3.new_child_flag = true;
                    break;
                }
            }
        }
    }

    // ============================================================================
    // STAGE 5 — DLL ACTIVITY
    // ============================================================================

    void FilterEngine::Stage5_DllActivity(const Event& /*event*/,
        V3ProcessInfo& v3) const {
        std::vector<std::wstring> confirmed_shadowing;
        for (const auto& dll_path : v3.dlls_new) {
            if (IsDllShadowingSystemDll(dll_path))
                confirmed_shadowing.push_back(dll_path);
        }
        for (auto& s : confirmed_shadowing) {
            if (std::find(v3.dlls_shadowing.begin(), v3.dlls_shadowing.end(), s) ==
                v3.dlls_shadowing.end())
                v3.dlls_shadowing.push_back(s);
        }
    }

    bool FilterEngine::IsDllShadowingSystemDll(
        const std::wstring& dll_canonical_path) const {
        if (dll_canonical_path.empty())
            return false;

        auto pos = dll_canonical_path.find_last_of(L"\\/");
        std::wstring name = (pos != std::wstring::npos)
            ? dll_canonical_path.substr(pos + 1)
            : dll_canonical_path;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);

        if (system_dll_names_.find(name) == system_dll_names_.end())
            return false;

        std::wstring path_lower = dll_canonical_path;
        std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(),
            ::towlower);

        for (const auto& sys_dir : system_dll_dirs_) {
            if (path_lower.compare(0, sys_dir.size(), sys_dir) == 0)
                return false;
        }
        return true;
    }

    // ============================================================================
    // STAGE 6 — PERSISTENCE  (stub; persistence_touched defaults false)
    // ============================================================================

    void FilterEngine::Stage6_PersistenceTouchpoints(const Event& /*event*/,
        V3ProcessInfo& v3) const {
        (void)v3;
    }

    // ============================================================================
    // STAGE 7 — DEDUP AND COMPRESS
    //
    // FIX: When a new ring entry is created (first occurrence of a fingerprint),
    //      we now store v3.process_name and v3.canonical_path in the DedupEntry.
    //      FlushCompressSummaries() reads them to populate CompressSummary, so
    //      CompressJson() can emit meaningful process_name and canonical_path
    //      instead of always emitting empty strings.
    // ============================================================================

    FilterDecision FilterEngine::Stage7_DedupAndCompress(V3ProcessInfo& v3,
        FilterResult& result) {
        const std::string proc_key = BloomKeyForProcess(v3.canonical_path);
        const std::string rel_key =
            BloomKeyForRelationship(v3.parent_canonical_path, v3.canonical_path);

        bool novel_process = false;
        bool novel_relationship = false;

        {
            std::lock_guard<std::mutex> lock(bloom_mutex_);
            novel_process = bloom_process_.IsNovel(proc_key);
            if (novel_process)
                bloom_process_.Insert(proc_key);
            novel_relationship = bloom_relationship_.IsNovel(rel_key);
            if (novel_relationship)
                bloom_relationship_.Insert(rel_key);
        }

        result.is_novel_process = novel_process;
        result.is_novel_relationship = novel_relationship;

        v3.fingerprint = ComputeFingerprint(v3);

        if (ShouldAlwaysForward(v3, result) || novel_process || novel_relationship) {
            if (novel_process)       result.forward_rules_fired |= (1u << 10);
            if (novel_relationship)  result.forward_rules_fired |= (1u << 9);
            return FilterDecision::FORWARD;
        }

        std::lock_guard<std::mutex> ring_lock(ring_mutex_);
        auto now = std::chrono::steady_clock::now();
        auto it = ring_index_.find(v3.fingerprint);

        if (it == ring_index_.end()) {
            // First time we see this fingerprint — forward AND record in ring.
            if (ring_.size() < kRingMax) {
                // FIX: store process_name and canonical_path in the new entry.
                ring_.push_back({ v3.fingerprint, v3.process_name, v3.canonical_path,
                                 1, now, now });
                ring_index_[v3.fingerprint] = ring_.size() - 1;
            }
            else {
                ring_index_.erase(ring_[ring_head_].fingerprint);
                ring_[ring_head_] = { v3.fingerprint, v3.process_name,
                                     v3.canonical_path, 1, now, now };
                ring_index_[v3.fingerprint] = ring_head_;
                ring_head_ = (ring_head_ + 1) % kRingMax;
            }
            return FilterDecision::FORWARD;
        }

        DedupEntry& entry = ring_[it->second];
        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(now - entry.first_seen)
            .count();

        if (elapsed > static_cast<long long>(kWindowSecs)) {
            entry.count = 1;
            entry.first_seen = now;
            entry.last_seen = now;
            return FilterDecision::FORWARD;
        }

        entry.count++;
        entry.last_seen = now;
        v3.compress_count = entry.count;
        v3.window_seconds = kWindowSecs;
        result.compress_count = entry.count;

        return FilterDecision::COMPRESS;
    }

    // ============================================================================
    // SHOULD ALWAYS FORWARD  —  11 hard rules
    // ============================================================================

    bool FilterEngine::ShouldAlwaysForward(const V3ProcessInfo& v3,
        FilterResult& result) const {
        bool must_forward = false;

        if (v3.location_type == LocationType::UNKNOWN) {
            result.forward_rules_fired |= (1u << 0);
            must_forward = true;
        }

        if (v3.canonical_path.empty()) {
            result.forward_rules_fired |= (1u << 1);
            must_forward = true;
        }

        if (!v3.signature_valid && v3.location_type != LocationType::UNKNOWN) {
            result.forward_rules_fired |= (1u << 2);
            must_forward = true;
        }

        if (v3.signature_valid && v3.location_type == LocationType::SYSTEM) {
            std::wstring signer_lower = v3.signature_signer;
            std::transform(signer_lower.begin(), signer_lower.end(),
                signer_lower.begin(), ::towlower);
            bool expected_signer = false;
            for (const wchar_t* const* s = kMicrosoftSigners; *s; ++s) {
                if (signer_lower.find(*s) != std::wstring::npos) {
                    expected_signer = true;
                    break;
                }
            }
            if (!expected_signer) {
                result.forward_rules_fired |= (1u << 3);
                must_forward = true;
            }
        }

        if (!v3.process_name.empty() && !v3.canonical_path.empty()) {
            std::wstring name_lower = v3.process_name;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                ::towlower);
            static const std::unordered_set<std::wstring> kSystemExeNames = {
                L"svchost.exe",   L"lsass.exe",      L"csrss.exe",      L"winlogon.exe",
                L"services.exe",  L"smss.exe",        L"wininit.exe",    L"explorer.exe",
                L"taskhostw.exe", L"spoolsv.exe",     L"dllhost.exe",    L"rundll32.exe",
                L"regsvr32.exe",  L"msiexec.exe",     L"powershell.exe", L"cmd.exe",
                L"cscript.exe",   L"wscript.exe",     L"conhost.exe",    L"dwm.exe",
                L"audiodg.exe",   L"fontdrvhost.exe" };

            if (kSystemExeNames.count(name_lower) &&
                v3.location_type != LocationType::SYSTEM) {
                result.forward_rules_fired |= (1u << 4);
                must_forward = true;
            }
        }

        if (v3.new_child_flag) {
            result.forward_rules_fired |= (1u << 5);
            must_forward = true;
        }

        if (!v3.dlls_new.empty()) {
            for (const auto& dll : v3.dlls_new) {
                if (ClassifyPath(dll) == LocationType::UNKNOWN) {
                    result.forward_rules_fired |= (1u << 6);
                    must_forward = true;
                    break;
                }
            }
        }

        if (!v3.dlls_shadowing.empty()) {
            result.forward_rules_fired |= (1u << 7);
            must_forward = true;
        }

        return must_forward;
    }

    // ============================================================================
    // FLUSH COMPRESS SUMMARIES
    //
    // FIX: Now copies process_name and canonical_path from DedupEntry into the
    //      CompressSummary so CompressJson() emits non-empty strings.
    // ============================================================================

    std::vector<CompressSummary> FilterEngine::FlushCompressSummaries() {
        std::vector<CompressSummary> summaries;
        std::lock_guard<std::mutex> lock(ring_mutex_);
        auto now = std::chrono::steady_clock::now();

        for (auto& entry : ring_) {
            if (entry.fingerprint.empty())
                continue;
            // FIX: was `count <= 1` which skipped the very first COMPRESS flush.
            // A COMPRESS entry exists in the ring precisely because it was seen
            // more than once — count starts at 1 when first forwarded, then
            // increments on each subsequent compressed occurrence.  We flush
            // any entry that has accumulated at least one extra occurrence
            // (count >= 2) AND whose window has elapsed.
            if (entry.count < 2)
                continue;
            auto elapsed =
                std::chrono::duration_cast<std::chrono::seconds>(now - entry.first_seen)
                .count();

            if (elapsed >= static_cast<long long>(kWindowSecs)) {
                CompressSummary s;
                s.ts = std::chrono::system_clock::now();
                s.fingerprint = entry.fingerprint;
                s.process_name = entry.process_name;
                s.canonical_path = entry.canonical_path;
                s.count = entry.count;
                s.window_seconds = kWindowSecs;
                summaries.push_back(std::move(s));

                // Reset window — keep the entry in the ring for the next window.
                entry.count = 0;
                entry.first_seen = now;
                entry.last_seen = now;
            }
        }

        bloom_process_.SaveToFile(bloom_dir_ + L"process_seen.bin");
        bloom_relationship_.SaveToFile(bloom_dir_ + L"relationship_seen.bin");

        return summaries;
    }

    // ============================================================================
    // BLOOM KEY / FINGERPRINT / SHA-256
    // ============================================================================

    std::string
        FilterEngine::BloomKeyForProcess(const std::wstring& canonical_path) const {
        if (canonical_path.empty())
            return Sha256Hex("");

        int needed = WideCharToMultiByte(CP_UTF8, 0, canonical_path.data(),
            static_cast<int>(canonical_path.size()),
            nullptr, 0, nullptr, nullptr);
        if (needed <= 0 || needed > 131072)
            return Sha256Hex("");

        std::string utf8;
        try {
            utf8.resize(static_cast<size_t>(needed));
        }
        catch (...) {
            return Sha256Hex("");
        }

        WideCharToMultiByte(CP_UTF8, 0, canonical_path.data(),
            static_cast<int>(canonical_path.size()), utf8.data(),
            needed, nullptr, nullptr);
        return Sha256Hex(utf8);
    }

    std::string
        FilterEngine::BloomKeyForRelationship(const std::wstring& parent,
            const std::wstring& child) const {
        return Sha256Hex(BloomKeyForProcess(parent) + BloomKeyForProcess(child));
    }

    std::string FilterEngine::ComputeFingerprint(const V3ProcessInfo& v3) const {
        auto to_utf8 = [](const std::wstring& ws) -> std::string {
            if (ws.empty())
                return {};
            int n = WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                static_cast<int>(ws.size()), nullptr, 0,
                nullptr, nullptr);
            if (n <= 0 || n > 131072)
                return {};
            std::string s;
            try {
                s.resize(static_cast<size_t>(n));
            }
            catch (...) {
                return {};
            }
            WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                s.data(), n, nullptr, nullptr);
            return s;
            };

        std::string data;
        data += to_utf8(v3.canonical_path) + '\x00';
        data += to_utf8(v3.parent_canonical_path) + '\x00';
        data += to_utf8(v3.cmdline_normalized.substr(
            0, std::min<size_t>(v3.cmdline_normalized.size(), 256))) + '\x00';
        data += to_utf8(v3.signature_thumbprint) + '\x00';
        data += utils::LocationTypeToString(v3.location_type);

        return Sha256Hex(data);
    }

    std::string FilterEngine::Sha256Hex(const std::string& data) {
        BCRYPT_ALG_HANDLE  alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD hash_len = 0, result_len = 0;
        std::string hex;

        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return {};
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len),
            &result_len, 0) != 0)
            goto cleanup;
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0)
            goto cleanup;

        // FIX C6031: check and handle BCryptHashData return value.
        if (BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0) != 0)
            goto cleanup;

        {
            std::vector<BYTE> digest(hash_len);
            if (BCryptFinishHash(hash, digest.data(), hash_len, 0) == 0) {
                std::ostringstream oss;
                for (BYTE b : digest)
                    oss << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(b);
                hex = oss.str();
            }
        }

    cleanup:
        if (hash) BCryptDestroyHash(hash);
        if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
        return hex;
    }

} // namespace titan