// =============================================================================
//  titan_amsi.h  —  TITAN AMSI Monitor  |  Single Master Header
//  Project     : SentinelAI / TITAN Engine
//  Description : Defines every shared type, constant, and forward declaration
//                used across capture, condenser, filter, logger, and main.
// =============================================================================
#pragma once

// Removed WIN32_LEAN_AND_MEAN redefinition to fix C4005

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <wchar.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
//  VERSION  — constexpr (not macros)
// ---------------------------------------------------------------------------
constexpr int  TITAN_AMSI_VERSION_MAJOR = 2;
constexpr int  TITAN_AMSI_VERSION_MINOR = 0;
constexpr int  TITAN_AMSI_VERSION_PATCH = 1;
constexpr char TITAN_AMSI_VERSION_STR[] = "2.0.1";

// ---------------------------------------------------------------------------
//  TUNABLES
//  Keep as #define so CMake can override via -D flags at configure time.
// ---------------------------------------------------------------------------
#ifndef AMSI_RING_SIZE
#  define AMSI_RING_SIZE        (16 * 1024 * 1024)
#endif
#ifndef AMSI_LOG_BUF_SIZE
#  define AMSI_LOG_BUF_SIZE     (1 * 1024 * 1024)
#endif
#ifndef AMSI_HASH_CACHE_CAP
#  define AMSI_HASH_CACHE_CAP   50000
#endif
#ifndef AMSI_CONDENSER_THREADS
#  define AMSI_CONDENSER_THREADS 2
#endif
#ifndef AMSI_LOG_FLUSH_MS
#  define AMSI_LOG_FLUSH_MS     100
#endif
#ifndef AMSI_MAX_SCRIPT_BYTES
#  define AMSI_MAX_SCRIPT_BYTES (5 * 1024 * 1024)
#endif
#ifndef AMSI_OUTPUT_FILE
#  define AMSI_OUTPUT_FILE      L"logs\\titan_amsi.json"
#endif

// Internal constants that CMake never overrides — use constexpr
constexpr uint32_t RAW_EVENT_MAGIC = 0xA751E7C0u;
constexpr int      RING_CAPACITY = 1024;

// Proper UTF-8 buffer sizes for app/process names.
// A wchar_t[64] field can expand to up to 64*3 = 192 UTF-8 bytes.
constexpr size_t UTF8_APP_NAME_CAP = 192;
constexpr size_t UTF8_PROC_BL_CAP = 192;

// ---------------------------------------------------------------------------
//  SEVERITY  (ordered low→critical for numeric comparison)
// ---------------------------------------------------------------------------
typedef enum TitanSeverity {
    SEV_NONE = 0,
    SEV_INFO = 1,
    SEV_LOW = 2,
    SEV_MEDIUM = 3,
    SEV_HIGH = 4,
    SEV_CRITICAL = 5
} TitanSeverity;

static inline const char* SeverityStr(TitanSeverity s) {
    switch (s) {
    case SEV_INFO:     return "INFO";
    case SEV_LOW:      return "LOW";
    case SEV_MEDIUM:   return "MEDIUM";
    case SEV_HIGH:     return "HIGH";
    case SEV_CRITICAL: return "CRITICAL";
    default:           return "NONE";
    }
}

// ---------------------------------------------------------------------------
//  SCRIPT LANGUAGE
// ---------------------------------------------------------------------------
typedef enum ScriptLang {
    LANG_UNKNOWN = 0,
    LANG_POWERSHELL = 1,
    LANG_JAVASCRIPT = 2,
    LANG_VBSCRIPT = 3,
    LANG_JSCRIPT = 4,
    LANG_WMIC = 5,
    LANG_DOTNET = 6,
    LANG_BATCH = 7,
    LANG_PYTHON = 8,
    LANG_CSHARP = 9,
    LANG_MSHTA = 10,
    LANG_WSCRIPT = 11,
} ScriptLang;

static inline const char* LangStr(ScriptLang l) {
    switch (l) {
    case LANG_POWERSHELL: return "PowerShell";
    case LANG_JAVASCRIPT: return "JavaScript";
    case LANG_VBSCRIPT:   return "VBScript";
    case LANG_JSCRIPT:    return "JScript";
    case LANG_WMIC:       return "WMIC";
    case LANG_DOTNET:     return "DotNet";
    case LANG_BATCH:      return "Batch";
    case LANG_PYTHON:     return "Python";
    case LANG_CSHARP:     return "CSharp";
    case LANG_MSHTA:      return "MSHTA";
    case LANG_WSCRIPT:    return "WScript";
    default:              return "Unknown";
    }
}

// ---------------------------------------------------------------------------
//  DETECTION CATEGORY
// ---------------------------------------------------------------------------
typedef enum DetectionCategory {
    DET_NONE = 0,
    DET_AMSI_BYPASS = 1,
    DET_REFLECTIVE_LOAD = 2,
    DET_DOWNLOAD_EXEC = 3,
    DET_CRED_DUMP = 4,
    DET_OBFUSCATION = 5,
    DET_BASE64_PAYLOAD = 6,
    DET_SHELLCODE = 7,
    DET_RANSOMWARE = 8,
    DET_SUPPLY_CHAIN = 9,
    DET_LIVING_OFF_LAND = 10,
} DetectionCategory;

static inline const char* DetCatStr(DetectionCategory d) {
    switch (d) {
    case DET_AMSI_BYPASS:     return "AMSI_BYPASS_ATTEMPT";
    case DET_REFLECTIVE_LOAD: return "REFLECTIVE_LOAD";
    case DET_DOWNLOAD_EXEC:   return "DOWNLOAD_AND_EXECUTE";
    case DET_CRED_DUMP:       return "CREDENTIAL_DUMP";
    case DET_OBFUSCATION:     return "HEAVY_OBFUSCATION";
    case DET_BASE64_PAYLOAD:  return "BASE64_ENCODED_PAYLOAD";
    case DET_SHELLCODE:       return "SHELLCODE_PATTERN";
    case DET_RANSOMWARE:      return "RANSOMWARE_PATTERN";
    case DET_SUPPLY_CHAIN:    return "SUPPLY_CHAIN_SCRIPT";
    case DET_LIVING_OFF_LAND: return "LIVING_OFF_THE_LAND";
    default:                  return "NONE";
    }
}

// ---------------------------------------------------------------------------
//  FILTER CONFIG
// ---------------------------------------------------------------------------
typedef struct FilterConfig {
    TitanSeverity  min_severity;
    bool           log_dedup_refs;
    bool           capture_all_langs;
    bool           log_clean_scripts;
    DWORD          pid_whitelist[64];
    size_t         pid_whitelist_len;
    wchar_t        proc_blacklist[16][64];
    size_t         proc_blacklist_len;
    size_t         max_content_bytes;
} FilterConfig;

static inline void FilterConfig_Default(FilterConfig* cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->min_severity = SEV_LOW;
    cfg->log_dedup_refs = true;
    cfg->capture_all_langs = true;
    cfg->log_clean_scripts = false;
    cfg->max_content_bytes = 8192;
}

// ---------------------------------------------------------------------------
//  RAW EVENT  (one slot in the 16 MB capture ring — zero-copy)
// ---------------------------------------------------------------------------
typedef struct RawEvent {
    uint32_t   magic;
    uint32_t   seq;
    uint64_t   ts_ns;
    DWORD      pid;
    DWORD      tid;
    ScriptLang lang;
    wchar_t    app_name[64];
    wchar_t    content_name[260];
    uint8_t* data_ptr;
    size_t     data_len;
    bool       processed;
} RawEvent;

// ---------------------------------------------------------------------------
//  PROCESSED EVENT  (condenser → logger)
// ---------------------------------------------------------------------------
typedef struct ProcessedEvent {
    uint64_t          ts_ns;
    DWORD             pid;
    wchar_t           app_name[64];
    wchar_t           content_name[260];
    ScriptLang        lang;
    TitanSeverity     severity;
    DetectionCategory category;
    uint64_t          content_hash;
    bool              is_dedup;
    char* encoded_content;
    size_t            encoded_len;
    char              user[64];
} ProcessedEvent;

// ---------------------------------------------------------------------------
//  RING BUFFER  (lock-free SPSC, capture → condenser)
// ---------------------------------------------------------------------------
typedef struct RingBuffer {
    volatile LONG  head;
    volatile LONG  tail;
    LONG           cap;
    RawEvent* slots[RING_CAPACITY];
    uint8_t* arena;
    volatile LONG  arena_offset;
} RingBuffer;

// ---------------------------------------------------------------------------
//  LOG BUFFER  (double-buffer, condenser → logger)
//  FIX: Pragma disable C4324 safely ignores compiler padding warnings 
//  without having to hardcode padding bytes that break if config sizes change.
// ---------------------------------------------------------------------------
#pragma warning(push)
#pragma warning(disable : 4324) 
__declspec(align(64))
typedef struct LogBuffer {
    char          data[AMSI_LOG_BUF_SIZE];
    volatile LONG offset;
} LogBuffer;
#pragma warning(pop)

// ---------------------------------------------------------------------------
//  GLOBAL HANDLES  (defined in main.cpp)
// ---------------------------------------------------------------------------
extern RingBuffer* g_ring;
extern FilterConfig  g_filter;
extern volatile bool g_running;

// ---------------------------------------------------------------------------
//  RUNTIME STATS  (defined in main.cpp, incremented by all modules)
// ---------------------------------------------------------------------------
extern volatile LONG g_stat_captured;
extern volatile LONG g_stat_logged;
extern volatile LONG g_stat_dedup;
extern volatile LONG g_stat_filtered;

// ---------------------------------------------------------------------------
//  FORWARD DECLARATIONS
// ---------------------------------------------------------------------------

// capture.cpp
bool  Capture_Init(void);
void  Capture_Start(void);
void  Capture_Stop(void);

// condenser.cpp
bool  Condenser_Init(void);
void  Condenser_Start(void);
void  Condenser_Stop(void);
void  Condenser_ProcessEvent(RawEvent* ev);

// filter.cpp
bool  Filter_ShouldLog(const ProcessedEvent* ev, const FilterConfig* cfg);
void  Filter_EnrichSeverity(ProcessedEvent* ev);
void  Filter_DetectCategory(ProcessedEvent* ev, const uint8_t* content, size_t len);

// logger.cpp
bool  Logger_Init(const wchar_t* output_path);
void  Logger_Submit(const ProcessedEvent* ev);
void  Logger_Flush(void);
void  Logger_Shutdown(void);

// ---------------------------------------------------------------------------
//  INLINE UTILITY: Timestamp (100ns FILETIME → nanoseconds since Unix epoch)
// ---------------------------------------------------------------------------
static inline uint64_t GetTimestampNs(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (ul.QuadPart - 116444736000000000ULL) * 100ULL;
}

// ---------------------------------------------------------------------------
//  INLINE UTILITY: Wide → UTF-8
//  FIX: Int-uninit warning resolved by immediately zeroing the buffer.
// ---------------------------------------------------------------------------
static inline void WcharToUtf8(const wchar_t* src, char* dst, size_t cap) {
    if (!dst || cap == 0) return;
    dst[0] = '\0'; // Init immediately to silence static analyzer
    if (!src) return;

    int written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)cap, NULL, NULL);
    if (written <= 0) dst[0] = '\0';
    dst[cap - 1] = '\0';
}

// ---------------------------------------------------------------------------
//  INLINE UTILITY: Minimal JSON string escaper
//  FIX: Int-uninit warning resolved by immediately zeroing the buffer.
// ---------------------------------------------------------------------------
static inline void JsonEscapeStr(const char* in, char* out, size_t cap) {
    if (!out || cap == 0) return;
    out[0] = '\0'; // Init immediately to silence static analyzer
    if (!in) return;

    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') { out[j++] = '\\'; out[j++] = '"'; }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c < 0x20) { /* skip control chars */ }
        else { out[j++] = (char)c; }
    }
    out[j] = '\0';
}