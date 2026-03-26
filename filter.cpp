// =============================================================================
//  filter.cpp  —  TITAN AMSI Monitor
//  Role        : "The Brain" — decides what to log, what severity to assign,
//                and which attack category triggered.
//
//  FIXES vs original:
//    • Filter_DetectCategory: 64 KB scratch buffer moved from stack to static
//      module-level storage, eliminating a large stack allocation in an ETW
//      callback call chain.
//    • Filter_ShouldLog: UTF-8 buffers for app_name and proc_blacklist entries
//      enlarged from 64 bytes to UTF8_APP_NAME_CAP (192 bytes) to correctly
//      handle process names containing non-ASCII / multi-byte UTF-8 characters.
// =============================================================================

#include "titan_amsi.h"
#include <stdlib.h>
#include <ctype.h>

// ---------------------------------------------------------------------------
//  PATTERN TABLES
// ---------------------------------------------------------------------------
typedef struct PatternEntry {
    const char*       pattern;
    DetectionCategory category;
    TitanSeverity     severity;
} PatternEntry;

static const PatternEntry k_patterns[] = {
    // ── AMSI Bypass ──────────────────────────────────────────────────────────
    { "amsiinitfailed",               DET_AMSI_BYPASS,     SEV_CRITICAL },
    { "amsicontext",                  DET_AMSI_BYPASS,     SEV_CRITICAL },
    { "amsiutils",                    DET_AMSI_BYPASS,     SEV_CRITICAL },
    { "amsi.dll",                     DET_AMSI_BYPASS,     SEV_HIGH     },
    { "setvalue($null,$true)",        DET_AMSI_BYPASS,     SEV_CRITICAL },
    { "bypassamsi",                   DET_AMSI_BYPASS,     SEV_CRITICAL },

    // ── Reflective / In-Memory Load ──────────────────────────────────────────
    { "invoke-reflectivepeinjection", DET_REFLECTIVE_LOAD, SEV_CRITICAL },
    { "invoke-shellcode",             DET_REFLECTIVE_LOAD, SEV_CRITICAL },
    { "[reflection.assembly]::load",  DET_REFLECTIVE_LOAD, SEV_HIGH     },
    { "assembly::loadwithpartialname",DET_REFLECTIVE_LOAD, SEV_HIGH     },
    { "loadlibrarya",                 DET_REFLECTIVE_LOAD, SEV_MEDIUM   },

    // ── Download & Execute ───────────────────────────────────────────────────
    { "iex(",                         DET_DOWNLOAD_EXEC,   SEV_HIGH     },
    { "invoke-expression",            DET_DOWNLOAD_EXEC,   SEV_HIGH     },
    { "net.webclient",                DET_DOWNLOAD_EXEC,   SEV_MEDIUM   },
    { "downloadstring(",              DET_DOWNLOAD_EXEC,   SEV_HIGH     },
    { "downloadfile(",                DET_DOWNLOAD_EXEC,   SEV_MEDIUM   },
    { "bitstransfer",                 DET_DOWNLOAD_EXEC,   SEV_MEDIUM   },
    { "wget ",                        DET_DOWNLOAD_EXEC,   SEV_LOW      },
    { "curl ",                        DET_DOWNLOAD_EXEC,   SEV_LOW      },
    { "start-bitstransfer",           DET_DOWNLOAD_EXEC,   SEV_MEDIUM   },

    // ── Credential Dumping ───────────────────────────────────────────────────
    { "mimikatz",                     DET_CRED_DUMP,       SEV_CRITICAL },
    { "sekurlsa",                     DET_CRED_DUMP,       SEV_CRITICAL },
    { "lsadump",                      DET_CRED_DUMP,       SEV_CRITICAL },
    { "logonpasswords",               DET_CRED_DUMP,       SEV_CRITICAL },
    { "wce.exe",                      DET_CRED_DUMP,       SEV_CRITICAL },
    { "procdump",                     DET_CRED_DUMP,       SEV_HIGH     },
    { "lsass",                        DET_CRED_DUMP,       SEV_HIGH     },

    // ── Obfuscation ──────────────────────────────────────────────────────────
    { "[char]",                       DET_OBFUSCATION,     SEV_MEDIUM   },
    { "-join(",                       DET_OBFUSCATION,     SEV_MEDIUM   },
    { "replace(',','')",              DET_OBFUSCATION,     SEV_MEDIUM   },
    { "env:comspec",                  DET_OBFUSCATION,     SEV_MEDIUM   },
    { "-f '",                         DET_OBFUSCATION,     SEV_LOW      },
    { "invoke-obfuscation",           DET_OBFUSCATION,     SEV_HIGH     },
    { "out-string|-",                 DET_OBFUSCATION,     SEV_MEDIUM   },

    // ── Base64 Payloads ──────────────────────────────────────────────────────
    { "-encodedcommand",              DET_BASE64_PAYLOAD,  SEV_HIGH     },
    { "-enc ",                        DET_BASE64_PAYLOAD,  SEV_MEDIUM   },
    { "frombase64string",             DET_BASE64_PAYLOAD,  SEV_MEDIUM   },
    { "convert::frombase64",          DET_BASE64_PAYLOAD,  SEV_MEDIUM   },
    { "base64_decode(",               DET_BASE64_PAYLOAD,  SEV_MEDIUM   },

    // ── Shellcode ────────────────────────────────────────────────────────────
    { "virtualalloc",                 DET_SHELLCODE,       SEV_HIGH     },
    { "writeprocessmemory",           DET_SHELLCODE,       SEV_HIGH     },
    { "createthread",                 DET_SHELLCODE,       SEV_MEDIUM   },
    { "rtlmovememory",                DET_SHELLCODE,       SEV_HIGH     },
    { "getprocaddress",               DET_SHELLCODE,       SEV_MEDIUM   },

    // ── Ransomware ───────────────────────────────────────────────────────────
    { "encrypt-file",                 DET_RANSOMWARE,      SEV_CRITICAL },
    { "aes.create()",                 DET_RANSOMWARE,      SEV_HIGH     },
    { "get-childitem -recurse",       DET_RANSOMWARE,      SEV_MEDIUM   },
    { "vssadmin delete shadows",      DET_RANSOMWARE,      SEV_CRITICAL },
    { "bcdedit /set",                 DET_RANSOMWARE,      SEV_HIGH     },
    { "wbadmin delete catalog",       DET_RANSOMWARE,      SEV_CRITICAL },

    // ── Supply Chain ─────────────────────────────────────────────────────────
    { "setup.py",                     DET_SUPPLY_CHAIN,    SEV_LOW      },
    { "postinstall",                  DET_SUPPLY_CHAIN,    SEV_LOW      },
    { "preinstall",                   DET_SUPPLY_CHAIN,    SEV_LOW      },
    { "install.js",                   DET_SUPPLY_CHAIN,    SEV_MEDIUM   },
    { "subprocess.popen",             DET_SUPPLY_CHAIN,    SEV_MEDIUM   },
    { "os.system(",                   DET_SUPPLY_CHAIN,    SEV_MEDIUM   },
    { "eval(compile(",                DET_SUPPLY_CHAIN,    SEV_HIGH     },
    { "__import__(",                  DET_SUPPLY_CHAIN,    SEV_HIGH     },

    // ── Living Off the Land ──────────────────────────────────────────────────
    { "regsvr32 /s /u",               DET_LIVING_OFF_LAND, SEV_HIGH     },
    { "mshta vbscript:",              DET_LIVING_OFF_LAND, SEV_HIGH     },
    { "wmic process call create",     DET_LIVING_OFF_LAND, SEV_HIGH     },
    { "certutil -decode",             DET_LIVING_OFF_LAND, SEV_HIGH     },
    { "certutil -urlcache",           DET_LIVING_OFF_LAND, SEV_HIGH     },
    { "msiexec /q",                   DET_LIVING_OFF_LAND, SEV_MEDIUM   },
    { "expand-archive",               DET_LIVING_OFF_LAND, SEV_LOW      },
};

#define PATTERN_COUNT (sizeof(k_patterns) / sizeof(k_patterns[0]))

// ---------------------------------------------------------------------------
//  FIX: scratch buffer moved from stack to static module storage.
//  The original declared char scratch[65537] on the stack inside
//  Filter_DetectCategory.  While within the 1 MB Windows thread stack limit,
//  it was an unnecessary risk and caused stack-usage warnings.
//  This is safe because Filter_DetectCategory is only called from the single
//  CondenserThread (not re-entrant).
// ---------------------------------------------------------------------------
#define FILTER_SCAN_LIMIT  65536

static char s_filter_scratch[FILTER_SCAN_LIMIT + 1];

static void ToLowerAscii(const uint8_t* src, size_t len,
                         char* dst, size_t dst_cap) {
    size_t n = (len < dst_cap - 1) ? len : dst_cap - 1;
    if (n > FILTER_SCAN_LIMIT) n = FILTER_SCAN_LIMIT;
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[n] = '\0';
}

// ---------------------------------------------------------------------------
//  Filter_DetectCategory
// ---------------------------------------------------------------------------
void Filter_DetectCategory(ProcessedEvent* ev,
                           const uint8_t*  content,
                           size_t          len) {
    if (!content || len == 0) return;

    ToLowerAscii(content, len, s_filter_scratch, sizeof(s_filter_scratch));

    TitanSeverity     best_sev = SEV_NONE;
    DetectionCategory best_cat = DET_NONE;

    for (size_t i = 0; i < PATTERN_COUNT; i++) {
        if (strstr(s_filter_scratch, k_patterns[i].pattern)) {
            if (k_patterns[i].severity > best_sev) {
                best_sev = k_patterns[i].severity;
                best_cat = k_patterns[i].category;
            }
        }
    }

    if (best_sev > ev->severity) ev->severity = best_sev;
    if (best_cat != DET_NONE)    ev->category  = best_cat;

    if (ev->severity == SEV_NONE) ev->severity = SEV_INFO;
}

// ---------------------------------------------------------------------------
//  Filter_EnrichSeverity
// ---------------------------------------------------------------------------
void Filter_EnrichSeverity(ProcessedEvent* ev) {
    if (ev->category == DET_AMSI_BYPASS)
        ev->severity = SEV_CRITICAL;

    if (ev->category == DET_REFLECTIVE_LOAD && ev->lang == LANG_POWERSHELL)
        if (ev->severity < SEV_HIGH) ev->severity = SEV_HIGH;

    if (ev->category == DET_SUPPLY_CHAIN) {
        if (strcmp(ev->user, "SYSTEM") == 0 ||
            strstr(ev->user, "ADMIN") != NULL) {
            if (ev->severity < SEV_HIGH) ev->severity = SEV_HIGH;
        }
    }

    if (ev->category == DET_RANSOMWARE && ev->severity < SEV_CRITICAL)
        ev->severity = SEV_CRITICAL;
}

// ---------------------------------------------------------------------------
//  Filter_ShouldLog
//
//  FIX: app name and blacklist buffers enlarged from char[64] to
//  UTF8_APP_NAME_CAP (192) and UTF8_PROC_BL_CAP (192) respectively.
//  A wchar_t[64] field can expand to 192 UTF-8 bytes in the worst case
//  (all 3-byte characters).  The old 64-byte buffer silently truncated
//  non-ASCII process names, causing blacklist mismatches.
// ---------------------------------------------------------------------------
bool Filter_ShouldLog(const ProcessedEvent* ev, const FilterConfig* cfg) {
    // 1. PID whitelist — always log
    for (size_t i = 0; i < cfg->pid_whitelist_len; i++) {
        if (ev->pid == cfg->pid_whitelist[i]) return true;
    }

    // 2. Process blacklist — never log
    char app_utf8[UTF8_APP_NAME_CAP];
    WcharToUtf8(ev->app_name, app_utf8, sizeof(app_utf8));

    char app_lower[UTF8_APP_NAME_CAP] = {};
    for (int i = 0; i < (int)sizeof(app_lower) - 1 && app_utf8[i]; i++)
        app_lower[i] = (char)tolower((unsigned char)app_utf8[i]);

    for (size_t i = 0; i < cfg->proc_blacklist_len; i++) {
        char bl[UTF8_PROC_BL_CAP];
        WcharToUtf8(cfg->proc_blacklist[i], bl, sizeof(bl));
        for (int j = 0; j < (int)sizeof(bl) - 1 && bl[j]; j++)
            bl[j] = (char)tolower((unsigned char)bl[j]);
        if (strstr(app_lower, bl)) return false;
    }

    // 3. Language filter
    if (!cfg->capture_all_langs) {
        if (ev->lang == LANG_BATCH || ev->lang == LANG_PYTHON)
            return false;
    }

    // 4. Clean script filter
    if (!cfg->log_clean_scripts && ev->severity == SEV_INFO)
        return false;

    // 5. Dedup reference filter
    if (ev->is_dedup && !cfg->log_dedup_refs)
        return false;

    // 6. Minimum severity gate
    if (ev->severity < cfg->min_severity)
        return false;

    return true;
}
