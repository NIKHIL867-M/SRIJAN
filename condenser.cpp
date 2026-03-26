// =============================================================================
//  condenser.cpp  —  TITAN AMSI Monitor
//  Role        : "The Squeeze" — deduplicates scripts by xxHash64, LZ4-compresses
//                new content, base64-encodes it for JSON output, then calls the
//                filter to decide whether to pass to the logger.
//
//  FIXES vs original:
//    • lz4_compress: replaced *(uint32_t*)ip unaligned reads with memcpy to
//      avoid undefined behaviour on non-x86 and MSVC strict-aliasing warnings.
//    • lz4_compress: hash_table moved from static-local to module-level so it
//      is explicitly not shared state between hypothetical future threads and
//      its ownership is clear.
//    • CondenserThread: reads g_ring->tail atomically (InterlockedAdd) for
//      consistency with head reads.
//    • HashCache_Contains/Insert: hash==0 documented as reserved sentinel;
//      any xxHash64 result of 0 is mapped to 1 to avoid silent cache misses.
//    • Stat counters (g_stat_logged, g_stat_dedup, g_stat_filtered) incremented
//      so main.cpp final stats are accurate.
//    • Condenser_ProcessEvent: added explicit comment that Logger_Submit is
//      synchronous (memcpy into log buffer before returning), making the
//      shared s_encoded_buf safe.
// =============================================================================

#include "titan_amsi.h"
#include <stdlib.h>
#include <time.h>

// ---------------------------------------------------------------------------
//  xxHash64  — embedded minimal implementation (BSD 2-Clause, Yann Collet)
// ---------------------------------------------------------------------------
constexpr uint64_t XXH_PRIME1 = 11400714785074694791ULL;
constexpr uint64_t XXH_PRIME2 = 14029467366897019727ULL;
constexpr uint64_t XXH_PRIME3 =  1609587929392839161ULL;
constexpr uint64_t XXH_PRIME4 =  9650029242287828579ULL;
constexpr uint64_t XXH_PRIME5 =  2870177450012600261ULL;

static inline uint64_t XXH_rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t xxhash64(const void* data, size_t len, uint64_t seed) {
    const uint8_t* p   = (const uint8_t*)data;
    const uint8_t* end = p + len;
    uint64_t       h64 = 0;

    if (len >= 32) {
        uint64_t v1 = seed + XXH_PRIME1 + XXH_PRIME2;
        uint64_t v2 = seed + XXH_PRIME2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - XXH_PRIME1;
        while (p <= end - 32) {
            uint64_t tmp;
            memcpy(&tmp, p, 8); v1 = XXH_rotl64(v1 + tmp * XXH_PRIME2, 31) * XXH_PRIME1; p += 8;
            memcpy(&tmp, p, 8); v2 = XXH_rotl64(v2 + tmp * XXH_PRIME2, 31) * XXH_PRIME1; p += 8;
            memcpy(&tmp, p, 8); v3 = XXH_rotl64(v3 + tmp * XXH_PRIME2, 31) * XXH_PRIME1; p += 8;
            memcpy(&tmp, p, 8); v4 = XXH_rotl64(v4 + tmp * XXH_PRIME2, 31) * XXH_PRIME1; p += 8;
        }
        h64 = XXH_rotl64(v1,1) + XXH_rotl64(v2,7) + XXH_rotl64(v3,12) + XXH_rotl64(v4,18);
        h64 = (h64 ^ (XXH_rotl64(v1*XXH_PRIME2,31)*XXH_PRIME1)) * XXH_PRIME1 + XXH_PRIME4;
        h64 = (h64 ^ (XXH_rotl64(v2*XXH_PRIME2,31)*XXH_PRIME1)) * XXH_PRIME1 + XXH_PRIME4;
        h64 = (h64 ^ (XXH_rotl64(v3*XXH_PRIME2,31)*XXH_PRIME1)) * XXH_PRIME1 + XXH_PRIME4;
        h64 = (h64 ^ (XXH_rotl64(v4*XXH_PRIME2,31)*XXH_PRIME1)) * XXH_PRIME1 + XXH_PRIME4;
    } else {
        h64 = seed + XXH_PRIME5;
    }
    h64 += (uint64_t)len;
    while (p + 8 <= end) {
        uint64_t tmp; memcpy(&tmp, p, 8);
        h64 ^= XXH_rotl64(tmp * XXH_PRIME2, 27) * XXH_PRIME1 + XXH_PRIME4; p += 8;
    }
    if (p + 4 <= end) {
        uint32_t tmp; memcpy(&tmp, p, 4);
        h64 ^= (uint64_t)tmp * XXH_PRIME1;
        h64  = XXH_rotl64(h64, 23) * XXH_PRIME2 + XXH_PRIME3; p += 4;
    }
    while (p < end) {
        h64 ^= (*p) * XXH_PRIME5;
        h64  = XXH_rotl64(h64, 11) * XXH_PRIME1; p++;
    }
    h64 ^= h64 >> 33; h64 *= XXH_PRIME2;
    h64 ^= h64 >> 29; h64 *= XXH_PRIME3;
    h64 ^= h64 >> 32;
    return h64;
}

// ---------------------------------------------------------------------------
//  LZ4 — embedded single-function block compressor
//  FIX: all *(uint32_t*) unaligned reads replaced with memcpy equivalents.
//  FIX: hash_table moved to module scope (was static-local, which would have
//       been a latent thread-safety bug if a second condenser thread were added).
// ---------------------------------------------------------------------------
#define LZ4_HASH_SIZE   (1 << 16)
#define LZ4_MINMATCH    4
#define LZ4_LAST_LIT    5
#define LZ4_MFLIMIT     12

static uint16_t s_lz4_hash_table[LZ4_HASH_SIZE];

static size_t lz4_compress(const uint8_t* src, size_t src_len,
                            uint8_t* dst,       size_t dst_cap) {
    if (src_len < 512) {
        if (src_len + 1 > dst_cap) return 0;
        dst[0] = 0;
        memcpy(dst + 1, src, src_len);
        return src_len + 1;
    }

    memset(s_lz4_hash_table, 0, sizeof(s_lz4_hash_table));

    const uint8_t* ip     = src;
    const uint8_t* anchor = src;
    const uint8_t* ip_end = src + src_len;
    const uint8_t* ilimit = ip_end - LZ4_MFLIMIT;
    uint8_t*       op     = dst;
    uint8_t*       op_end = dst + dst_cap;

    if (src_len < (size_t)LZ4_MFLIMIT) goto _last_literals;

    ip++;

    while (ip < ilimit) {
        // FIX: use memcpy instead of *(uint32_t*) for unaligned read
        uint32_t ip_val;
        memcpy(&ip_val, ip, 4);
        uint32_t h = (ip_val * 2654435761u) >> 16;
        h &= (LZ4_HASH_SIZE - 1);

        const uint8_t* match = src + s_lz4_hash_table[h];
        s_lz4_hash_table[h] = (uint16_t)(ip - src);

        uint32_t match_val;
        memcpy(&match_val, match, 4);

        if (ip_val == match_val && (ip - match) < 65535) {
            size_t lit_len = (size_t)(ip - anchor);
            uint8_t* token = op++;
            if (op + lit_len + 8 > op_end) goto _last_literals;

            if (lit_len >= 15) {
                *token = 0xF0;
                size_t rem = lit_len - 15;
                while (rem >= 255) { *op++ = 255; rem -= 255; }
                *op++ = (uint8_t)rem;
            } else {
                *token = (uint8_t)(lit_len << 4);
            }
            memcpy(op, anchor, lit_len); op += lit_len;

            const uint8_t* mp  = match + LZ4_MINMATCH;
            const uint8_t* ip2 = ip    + LZ4_MINMATCH;
            while (ip2 < ip_end && *ip2 == *mp) { ip2++; mp++; }
            size_t mlen = (size_t)(ip2 - ip);

            uint16_t offset = (uint16_t)(ip - match);
            memcpy(op, &offset, 2); op += 2;

            size_t ml_code = mlen - LZ4_MINMATCH;
            if (ml_code >= 15) {
                *token |= 0x0F;
                ml_code -= 15;
                while (ml_code >= 255) { *op++ = 255; ml_code -= 255; }
                *op++ = (uint8_t)ml_code;
            } else {
                *token |= (uint8_t)ml_code;
            }

            ip     = ip2;
            anchor = ip;
            continue;
        }
        ip++;
    }

_last_literals:;
    size_t last_run = (size_t)(ip_end - anchor);
    if (op + last_run + 1 + (last_run / 255) + 2 > op_end) return 0;
    uint8_t* token = op++;
    if (last_run >= 15) {
        *token = 0xF0;
        size_t r = last_run - 15;
        while (r >= 255) { *op++ = 255; r -= 255; }
        *op++ = (uint8_t)r;
    } else {
        *token = (uint8_t)(last_run << 4);
    }
    memcpy(op, anchor, last_run); op += last_run;
    return (size_t)(op - dst);
}

// ---------------------------------------------------------------------------
//  Base64 encoder (RFC 4648, no line-wrapping)
// ---------------------------------------------------------------------------
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t* src, size_t src_len,
                          char* dst,           size_t dst_cap) {
    size_t j = 0;
    for (size_t i = 0; i < src_len && j + 4 < dst_cap; i += 3) {
        uint32_t b = ((uint32_t)src[i] << 16)
                   | ((i+1 < src_len) ? (uint32_t)src[i+1] << 8 : 0)
                   | ((i+2 < src_len) ? (uint32_t)src[i+2]      : 0);
        dst[j++] = b64_table[(b >> 18) & 0x3F];
        dst[j++] = b64_table[(b >> 12) & 0x3F];
        dst[j++] = (i+1 < src_len) ? b64_table[(b >> 6) & 0x3F] : '=';
        dst[j++] = (i+2 < src_len) ? b64_table[ b       & 0x3F] : '=';
    }
    dst[j] = '\0';
}

// ---------------------------------------------------------------------------
//  LRU Hash Cache  (fixed 50k slots, open-addressing)
//
//  FIX: hash value 0 is reserved as the "empty slot" sentinel.  Any xxHash64
//  result of 0 is remapped to 1 to prevent the entry from being silently lost.
//  The probability of a natural collision with 0 is 1/2^64 (~5e-20), but
//  correctness is correctness.
// ---------------------------------------------------------------------------
#define HASH_CACHE_CAP AMSI_HASH_CACHE_CAP

typedef struct HashEntry {
    uint64_t hash;
    uint64_t ts_ns;
} HashEntry;

static HashEntry s_hash_cache[HASH_CACHE_CAP];
static size_t    s_cache_used = 0;

// Remap hash==0 to 1 so 0 remains unambiguously "empty"
static inline uint64_t NormaliseHash(uint64_t h) { return h ? h : 1ULL; }

static bool HashCache_Contains(uint64_t hash) {
    hash = NormaliseHash(hash);
    size_t slot = (size_t)(hash % HASH_CACHE_CAP);
    for (size_t i = 0; i < 8; i++) {
        size_t idx = (slot + i) % HASH_CACHE_CAP;
        if (s_hash_cache[idx].hash == hash) {
            s_hash_cache[idx].ts_ns = GetTimestampNs();
            return true;
        }
        if (s_hash_cache[idx].hash == 0) break;
    }
    return false;
}

static void HashCache_Insert(uint64_t hash) {
    hash = NormaliseHash(hash);
    size_t slot = (size_t)(hash % HASH_CACHE_CAP);
    for (size_t i = 0; i < 8; i++) {
        size_t idx = (slot + i) % HASH_CACHE_CAP;
        if (s_hash_cache[idx].hash == 0) {
            s_hash_cache[idx].hash  = hash;
            s_hash_cache[idx].ts_ns = GetTimestampNs();
            s_cache_used++;
            return;
        }
    }
    // Evict oldest in probe window
    uint64_t oldest_ts  = UINT64_MAX;
    size_t   oldest_idx = slot;
    for (size_t i = 0; i < 8; i++) {
        size_t idx = (slot + i) % HASH_CACHE_CAP;
        if (s_hash_cache[idx].ts_ns < oldest_ts) {
            oldest_ts  = s_hash_cache[idx].ts_ns;
            oldest_idx = idx;
        }
    }
    s_hash_cache[oldest_idx].hash  = hash;
    s_hash_cache[oldest_idx].ts_ns = GetTimestampNs();
}

// ---------------------------------------------------------------------------
//  Static compressed + encoded scratch buffers (~20 MB total BSS)
//  NOTE: Logger_Submit is fully synchronous (it memcpy's into the log buffer
//  before returning), so s_encoded_buf is safe to share across calls as long
//  as Condenser_ProcessEvent is only called from a single thread — which
//  CondenserThread guarantees.
// ---------------------------------------------------------------------------
#define COMPRESS_BUF_SIZE  (AMSI_MAX_SCRIPT_BYTES + 1024)
#define ENCODED_BUF_SIZE   (((COMPRESS_BUF_SIZE + 2) / 3) * 4 + 4)

static uint8_t s_compress_buf[COMPRESS_BUF_SIZE];
static char    s_encoded_buf[ENCODED_BUF_SIZE];

// ---------------------------------------------------------------------------
//  GetTokenUsername  — fills ev->user with the process account name
// ---------------------------------------------------------------------------
static void GetTokenUsername(DWORD pid, char* out, size_t cap) {
    strncpy_s(out, cap, "UNKNOWN", _TRUNCATE);
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc); return;
    }
    BYTE   buf[256]; DWORD ret = 0;
    GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &ret);
    if (ret) {
        TOKEN_USER* tu = (TOKEN_USER*)buf;
        char  name[64] = {}, domain[64] = {};
        DWORD n = 64, d = 64;
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, tu->User.Sid, name, &n, domain, &d, &use))
            strncpy_s(out, cap, name, _TRUNCATE);
    }
    CloseHandle(hToken);
    CloseHandle(hProc);
}

// ---------------------------------------------------------------------------
//  PUBLIC: Condenser_ProcessEvent
// ---------------------------------------------------------------------------
void Condenser_ProcessEvent(RawEvent* ev) {
    if (!ev || ev->magic != RAW_EVENT_MAGIC || ev->processed) return;
    ev->processed = true;

    // ── 1. Hash ──────────────────────────────────────────────────────────────
    uint64_t hash = xxhash64(ev->data_ptr, ev->data_len, 0x717174414E000042ULL);

    // ── 2. Build ProcessedEvent (stack) ─────────────────────────────────────
    ProcessedEvent pev = { 0 };
    pev.ts_ns        = ev->ts_ns;
    pev.pid          = ev->pid;
    pev.lang         = ev->lang;
    pev.content_hash = hash;
    wcsncpy_s(pev.app_name,     64,  ev->app_name,     _TRUNCATE);
    wcsncpy_s(pev.content_name, 260, ev->content_name, _TRUNCATE);
    GetTokenUsername(ev->pid, pev.user, sizeof(pev.user));

    // ── 3. Detect + enrich ───────────────────────────────────────────────────
    Filter_DetectCategory(&pev, ev->data_ptr, ev->data_len);
    Filter_EnrichSeverity(&pev);

    // ── 4. Apply filter policy ───────────────────────────────────────────────
    if (!Filter_ShouldLog(&pev, &g_filter)) {
        InterlockedIncrement(&g_stat_filtered);
        return;
    }

    // ── 5. Dedup check ───────────────────────────────────────────────────────
    if (HashCache_Contains(hash)) {
        pev.is_dedup       = true;
        pev.encoded_content = NULL;
        pev.encoded_len    = 0;
        InterlockedIncrement(&g_stat_dedup);
    } else {
        HashCache_Insert(hash);
        pev.is_dedup = false;

        size_t log_len = ev->data_len;
        if (log_len > g_filter.max_content_bytes)
            log_len = g_filter.max_content_bytes;

        size_t comp_len = lz4_compress(ev->data_ptr, log_len,
                                       s_compress_buf, COMPRESS_BUF_SIZE);
        if (comp_len == 0) {
            if (log_len < COMPRESS_BUF_SIZE) {
                memcpy(s_compress_buf, ev->data_ptr, log_len);
                comp_len = log_len;
            }
        }

        base64_encode(s_compress_buf, comp_len, s_encoded_buf, ENCODED_BUF_SIZE);
        pev.encoded_content = s_encoded_buf;
        pev.encoded_len     = strlen(s_encoded_buf);
    }

    // ── 6. Hand off to logger (synchronous — memcpy's before returning) ──────
    Logger_Submit(&pev);
    InterlockedIncrement(&g_stat_logged);
}

// ---------------------------------------------------------------------------
//  Condenser thread
// ---------------------------------------------------------------------------
static HANDLE s_condenser_thread = NULL;

static DWORD WINAPI CondenserThread(LPVOID) {
    while (g_running) {
        LONG head = InterlockedAdd(&g_ring->head, 0);
        LONG tail = InterlockedAdd(&g_ring->tail, 0); // FIX: atomic read

        while (tail != head) {
            RawEvent* ev = g_ring->slots[tail];
            if (ev && !ev->processed) Condenser_ProcessEvent(ev);
            tail = (tail + 1) % RING_CAPACITY;
            InterlockedExchange(&g_ring->tail, tail);
            head = InterlockedAdd(&g_ring->head, 0);
        }
        Sleep(1);
    }
    return 0;
}

bool Condenser_Init(void) {
    memset(s_hash_cache, 0, sizeof(s_hash_cache));
    s_cache_used = 0;
    return true;
}

void Condenser_Start(void) {
    s_condenser_thread = CreateThread(NULL, 0, CondenserThread, NULL, 0, NULL);
}

void Condenser_Stop(void) {
    if (s_condenser_thread) {
        WaitForSingleObject(s_condenser_thread, 3000);
        CloseHandle(s_condenser_thread);
        s_condenser_thread = NULL;
    }
}
