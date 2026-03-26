// =============================================================================
//  main.cpp  —  TITAN AMSI Monitor
//  Role      : "The Heart" — initialises all modules, reads config from JSON,
//              handles Ctrl+C gracefully, reports runtime stats.
//
//  Build (MSVC):
//    cl /O2 /W4 /EHsc capture.cpp condenser.cpp filter.cpp logger.cpp main.cpp
//       /link advapi32.lib tdh.lib psapi.lib shell32.lib
//
//  FIXES vs original:
//    • Stats counters (g_stat_*) moved to extern globals so condenser and
//      logger can increment them. Prints are now accurate (not always 0).
//    • Config loader now parses the "proc_blacklist" and "pid_whitelist" JSON
//      arrays into g_filter, so the JSON config is actually honoured.
//    • Removed unused #include <io.h>.
//    • LoadConfig: malloc'd buffer freed on all error paths (was leaked on
//      the invalid-size path).
// =============================================================================

#include "titan_amsi.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

// ---------------------------------------------------------------------------
//  GLOBAL DEFINITIONS  (declared extern in titan_amsi.h)
// ---------------------------------------------------------------------------
static RingBuffer s_ring_storage;
RingBuffer*   g_ring    = &s_ring_storage;
FilterConfig  g_filter;
volatile bool g_running = false;

// FIX: stats as non-static externs so every translation unit can increment them
volatile LONG g_stat_captured = 0;
volatile LONG g_stat_logged   = 0;
volatile LONG g_stat_dedup    = 0;
volatile LONG g_stat_filtered = 0;

// ---------------------------------------------------------------------------
//  CONFIG FILE PARSER  (reads titan_amsi_config.json)
//  Simple key-value scanner — no full JSON parser dependency.
// ---------------------------------------------------------------------------
static bool ParseStringValue(const char* buf, const char* key,
                              char* out,        size_t cap) {
    const char* p = strstr(buf, key);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p++; while (*p == ' ' || *p == '"') p++;
    size_t n = 0;
    while (*p && *p != '"' && *p != ',' && *p != '\n' && n < cap - 1)
        out[n++] = *p++;
    out[n] = '\0';
    return n > 0;
}

static int ParseIntValue(const char* buf, const char* key, int def) {
    const char* p = strstr(buf, key);
    if (!p) return def;
    p = strchr(p, ':');
    if (!p) return def;
    p++; while (*p == ' ') p++;
    return atoi(p);
}

static bool ParseBoolValue(const char* buf, const char* key, bool def) {
    const char* p = strstr(buf, key);
    if (!p) return def;
    p = strchr(p, ':');
    if (!p) return def;
    p++; while (*p == ' ') p++;
    if (strncmp(p, "true",  4) == 0) return true;
    if (strncmp(p, "false", 5) == 0) return false;
    return def;
}

// ---------------------------------------------------------------------------
//  ParseStringArray  — extracts values from a JSON string array.
//  Finds the array starting at `key`, then walks through quoted entries.
//  Populates out_items[0..max_items) and sets *out_count.
// ---------------------------------------------------------------------------
static void ParseStringArray(const char* buf, const char* key,
                              wchar_t    (*out_items)[64], size_t max_items,
                              size_t*     out_count) {
    *out_count = 0;
    const char* p = strstr(buf, key);
    if (!p) return;
    p = strchr(p, '[');
    if (!p) return;
    p++;

    while (*p && *p != ']' && *out_count < max_items) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']' || *p == '\0') break;
        if (*p != '"') { p++; continue; }
        p++;  // skip opening quote
        size_t n = 0;
        wchar_t* dst = out_items[*out_count];
        while (*p && *p != '"' && n < 63) {
            dst[n++] = (wchar_t)(unsigned char)*p++;
        }
        dst[n] = L'\0';
        if (*p == '"') p++;  // skip closing quote
        if (n > 0) (*out_count)++;
    }
}

// ---------------------------------------------------------------------------
//  ParseIntArray  — extracts integer values from a JSON number array.
//  Used for pid_whitelist.
// ---------------------------------------------------------------------------
static void ParseIntArray(const char* buf, const char* key,
                          DWORD* out_items, size_t max_items,
                          size_t* out_count) {
    *out_count = 0;
    const char* p = strstr(buf, key);
    if (!p) return;
    p = strchr(p, '[');
    if (!p) return;
    p++;

    while (*p && *p != ']' && *out_count < max_items) {
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']' || *p == '\0') break;
        if (*p >= '0' && *p <= '9') {
            out_items[(*out_count)++] = (DWORD)atoi(p);
            while (*p >= '0' && *p <= '9') p++;
        } else {
            p++;
        }
    }
}

// ---------------------------------------------------------------------------
//  LoadConfig
// ---------------------------------------------------------------------------
static void LoadConfig(const char* path) {
    FilterConfig_Default(&g_filter);

    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        printf("[TITAN] Config not found at '%s', using defaults.\n", path);
        return;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    // FIX: free buf on early return paths too (was leaked on invalid-size path)
    if (sz <= 0 || sz > 65536) {
        fclose(f);
        printf("[TITAN] Config file size invalid (%ld bytes); using defaults.\n", sz);
        return;
    }

    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    size_t nread = fread(buf, 1, (size_t)sz, f);
    buf[nread] = '\0';
    fclose(f);

    // Scalar values
    char sev_str[16] = {};
    if (ParseStringValue(buf, "\"min_severity\"", sev_str, sizeof(sev_str))) {
        if      (strcmp(sev_str, "NONE")     == 0) g_filter.min_severity = SEV_NONE;
        else if (strcmp(sev_str, "INFO")     == 0) g_filter.min_severity = SEV_INFO;
        else if (strcmp(sev_str, "LOW")      == 0) g_filter.min_severity = SEV_LOW;
        else if (strcmp(sev_str, "MEDIUM")   == 0) g_filter.min_severity = SEV_MEDIUM;
        else if (strcmp(sev_str, "HIGH")     == 0) g_filter.min_severity = SEV_HIGH;
        else if (strcmp(sev_str, "CRITICAL") == 0) g_filter.min_severity = SEV_CRITICAL;
    }

    g_filter.log_dedup_refs    = ParseBoolValue(buf, "\"log_dedup_refs\"",    true);
    g_filter.capture_all_langs = ParseBoolValue(buf, "\"capture_all_langs\"", true);
    g_filter.log_clean_scripts = ParseBoolValue(buf, "\"log_clean_scripts\"", false);
    g_filter.max_content_bytes = (size_t)ParseIntValue(buf, "\"max_content_bytes\"", 8192);

    // FIX: array values now actually parsed from config
    ParseStringArray(buf, "\"proc_blacklist\"",
                     g_filter.proc_blacklist,
                     16,
                     &g_filter.proc_blacklist_len);

    ParseIntArray(buf, "\"pid_whitelist\"",
                  g_filter.pid_whitelist,
                  64,
                  &g_filter.pid_whitelist_len);

    free(buf);

    printf("[TITAN] Config loaded: min_severity=%s  all_langs=%s  clean=%s  "
           "blacklist=%zu  whitelist_pids=%zu\n",
           SeverityStr(g_filter.min_severity),
           g_filter.capture_all_langs ? "yes" : "no",
           g_filter.log_clean_scripts ? "yes" : "no",
           g_filter.proc_blacklist_len,
           g_filter.pid_whitelist_len);
}

// ---------------------------------------------------------------------------
//  Ctrl+C handler
// ---------------------------------------------------------------------------
static BOOL WINAPI ConsoleHandler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        printf("\n[TITAN] Shutting down...\n");
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
//  Banner
// ---------------------------------------------------------------------------
static void PrintBanner(void) {
    printf("\n");
    printf("  ████████╗██╗████████╗ █████╗ ███╗   ██╗\n");
    printf("     ██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║\n");
    printf("     ██║   ██║   ██║   ███████║██╔██╗ ██║\n");
    printf("     ██║   ██║   ██║   ██╔══██║██║╚██╗██║\n");
    printf("     ██║   ██║   ██║   ██║  ██║██║ ╚████║\n");
    printf("     ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝\n");
    printf("  AMSI Monitor v%s  |  SentinelAI / TITAN Engine\n\n",
           TITAN_AMSI_VERSION_STR);
}

// ---------------------------------------------------------------------------
//  STATS THREAD
// ---------------------------------------------------------------------------
static DWORD WINAPI StatsThread(LPVOID) {
    while (g_running) {
        Sleep(5000);
        if (!g_running) break;
        // FIX: uses g_stat_* externs — values are now non-zero
        printf("[STATS] captured=%ld  logged=%ld  dedup=%ld  filtered=%ld\n",
               InterlockedAdd(&g_stat_captured, 0),
               InterlockedAdd(&g_stat_logged,   0),
               InterlockedAdd(&g_stat_dedup,    0),
               InterlockedAdd(&g_stat_filtered, 0));
    }
    return 0;
}

// ---------------------------------------------------------------------------
//  ENTRY POINT
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    PrintBanner();

    const char* cfg_path = (argc > 1) ? argv[1] : "titan_amsi_config.json";
    LoadConfig(cfg_path);

    // Check for elevated privileges
    BOOL   elevated = FALSE;
    HANDLE token    = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev = {};
        DWORD ret = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &ret))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    if (!elevated) {
        fprintf(stderr,
            "[ERROR] TITAN AMSI Monitor requires Administrator/SYSTEM privileges.\n"
            "        Please run from an elevated command prompt.\n");
        return 1;
    }

    printf("[TITAN] Running as elevated process — OK\n");
    printf("[TITAN] Output → %ls\n",  AMSI_OUTPUT_FILE);
    printf("[TITAN] Ring   → %d MB | Hash cache → %d entries\n",
           AMSI_RING_SIZE / (1024 * 1024), AMSI_HASH_CACHE_CAP);
    printf("[TITAN] Press Ctrl+C to stop.\n\n");

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    g_running = true;

    // ── Initialise modules ───────────────────────────────────────────────────
    if (!Logger_Init(AMSI_OUTPUT_FILE)) {
        fprintf(stderr, "[ERROR] Logger failed to open output file.\n");
        return 2;
    }
    if (!Condenser_Init()) {
        fprintf(stderr, "[ERROR] Condenser init failed.\n");
        return 3;
    }
    if (!Capture_Init()) {
        fprintf(stderr, "[ERROR] Capture ring allocation failed.\n");
        return 4;
    }

    // ── Start pipeline ───────────────────────────────────────────────────────
    Condenser_Start();
    HANDLE stats_thread = CreateThread(NULL, 0, StatsThread, NULL, 0, NULL);
    Capture_Start();

    printf("[TITAN] Pipeline active. Monitoring all script executions...\n");

    // ── Wait for shutdown signal ─────────────────────────────────────────────
    while (g_running) Sleep(250);

    // ── Graceful shutdown ────────────────────────────────────────────────────
    printf("[TITAN] Stopping capture...\n");
    Capture_Stop();

    printf("[TITAN] Draining condenser...\n");
    Condenser_Stop();

    printf("[TITAN] Flushing logs...\n");
    Logger_Shutdown();

    if (stats_thread) {
        WaitForSingleObject(stats_thread, 2000);
        CloseHandle(stats_thread);
    }

    printf("\n[TITAN] Final stats:\n");
    printf("         Events captured : %ld\n", InterlockedAdd(&g_stat_captured, 0));
    printf("         Events logged   : %ld\n", InterlockedAdd(&g_stat_logged,   0));
    printf("         Dedup refs      : %ld\n", InterlockedAdd(&g_stat_dedup,    0));
    printf("         Filtered out    : %ld\n", InterlockedAdd(&g_stat_filtered, 0));
    printf("[TITAN] Shutdown complete.\n");
    return 0;
}
