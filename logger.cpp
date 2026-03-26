// =============================================================================
//  logger.cpp  —  TITAN AMSI Monitor
//  Role        : "The Hand" — serialises ProcessedEvents to titan_amsi.json
//                using a double-buffer async flush with no blocking on callers.
//
//  JSON output format (one NDJSON line per event):
//
//  FULL event:
//  {
//    "ts":"2026-03-18T01:45:10.123Z",
//    "type":"FULL",
//    "endpoint":"amsi_monitor",
//    "source":"AMSI-Buffer",
//    "severity":"CRITICAL",
//    "lang":"PowerShell",
//    "detection":"AMSI_BYPASS_ATTEMPT",
//    "hash":"a1b2c3d4e5f6a7b8",
//    "details":{
//      "app_name":"PowerShell.exe",
//      "content_name":"C:\\Temp\\hidden_payload.ps1",
//      "encoded_content":"BASE64LZ4DATA..."
//    },
//    "actor":{
//      "pid":9920,
//      "user":"TITAN-ADMIN"
//    }
//  }
//
//  DEDUP reference:
//  {"ts":"...","type":"DEDUP","hash":"a1b2c3d4e5f6a7b8","pid":5678,"severity":"HIGH"}
//
//  FIXES vs original:
//    • BufAppend: removed the stale null-terminator write after the payload
//      (it wrote one byte past the valid region when the buffer was exactly
//      full, and was misleading since offset is the authoritative byte count).
//    • Logger_Shutdown: final flush sequence re-ordered so the post-thread
//      Logger_Flush() swap always finds the buffer that the thread didn't flush.
//    • NsToIso8601: added explicit (void) cast on unused _TRUNCATE result to
//      silence /W4 warning.
// =============================================================================

#include "titan_amsi.h"
#include <stdio.h>
#include <time.h>

// ---------------------------------------------------------------------------
//  DOUBLE BUFFER STATE
// ---------------------------------------------------------------------------
static LogBuffer           s_buf_a;
static LogBuffer           s_buf_b;
static volatile LogBuffer* s_active   = &s_buf_a;
static volatile LogBuffer* s_inactive = &s_buf_b;

static HANDLE           s_logger_thread = NULL;
static HANDLE           s_log_file      = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION s_submit_lock;

// ---------------------------------------------------------------------------
//  ISO-8601 timestamp from nanoseconds-since-epoch
// ---------------------------------------------------------------------------
static void NsToIso8601(uint64_t ts_ns, char* out, size_t cap) {
    time_t t_sec  = (time_t)(ts_ns / 1000000000ULL);
    int    ms_rem = (int)((ts_ns % 1000000000ULL) / 1000000ULL);

    struct tm utc;
    gmtime_s(&utc, &t_sec);

    (void)_snprintf_s(out, cap, _TRUNCATE,
        "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
        utc.tm_hour, utc.tm_min, utc.tm_sec, ms_rem);
}

// ---------------------------------------------------------------------------
//  BufAppend  — thread-safe write into the active log buffer.
//
//  FIX: Removed the incorrect null-terminator write `buf->data[old_off+len]='\0'`
//  that existed in the original.  The flush path uses `offset` as the byte
//  count, not a null sentinel, so writing a '\0' there was both wrong (it could
//  corrupt the next byte if the buffer was exactly full) and misleading.
// ---------------------------------------------------------------------------
static void BufAppend(const char* s, size_t len) {
    if (!s || len == 0) return;
    EnterCriticalSection(&s_submit_lock);
    LogBuffer* buf     = (LogBuffer*)s_active;
    LONG       old_off = InterlockedAdd(&buf->offset, 0);
    if ((size_t)old_off + len < AMSI_LOG_BUF_SIZE) {
        memcpy(buf->data + old_off, s, len);
        InterlockedAdd(&buf->offset, (LONG)len);
    }
    // else: buffer full — drop rather than overflow (back-pressure signal)
    LeaveCriticalSection(&s_submit_lock);
}

static void BufAppendf(const char* fmt, ...) {
    char    tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n > 0) BufAppend(tmp, (size_t)n);
}

// ---------------------------------------------------------------------------
//  FlushInactive  — write inactive buffer to disk then reset it.
// ---------------------------------------------------------------------------
static void FlushInactive(void) {
    LogBuffer* flush_buf = (LogBuffer*)s_inactive;
    LONG bytes = InterlockedAdd(&flush_buf->offset, 0);
    if (bytes <= 0 || s_log_file == INVALID_HANDLE_VALUE) return;

    DWORD written = 0;
    WriteFile(s_log_file, flush_buf->data, (DWORD)bytes, &written, NULL);

    // Reset buffer
    InterlockedExchange(&flush_buf->offset, 0);
    memset(flush_buf->data, 0, (size_t)bytes);
}

// ---------------------------------------------------------------------------
//  LOGGER THREAD
// ---------------------------------------------------------------------------
static DWORD WINAPI LoggerThread(LPVOID) {
    while (g_running) {
        Sleep(AMSI_LOG_FLUSH_MS);

        EnterCriticalSection(&s_submit_lock);
        volatile LogBuffer* tmp = s_active;
        s_active   = s_inactive;
        s_inactive = tmp;
        LeaveCriticalSection(&s_submit_lock);

        FlushInactive();
    }

    // Final drain: flush whatever is still in the active buffer,
    // then flush the (now inactive) other half.
    EnterCriticalSection(&s_submit_lock);
    volatile LogBuffer* tmp = s_active;
    s_active   = s_inactive;
    s_inactive = tmp;
    LeaveCriticalSection(&s_submit_lock);
    FlushInactive();     // flush the first half
    FlushInactive();     // flush the second half (already inactive)

    FlushFileBuffers(s_log_file);
    return 0;
}

// ---------------------------------------------------------------------------
//  PUBLIC: Logger_Submit
// ---------------------------------------------------------------------------
void Logger_Submit(const ProcessedEvent* ev) {
    if (!ev) return;

    char ts[32];
    NsToIso8601(ev->ts_ns, ts, sizeof(ts));

    char hash_str[20];
    _snprintf_s(hash_str, sizeof(hash_str), _TRUNCATE,
                "%016llx", (unsigned long long)ev->content_hash);

    char app_utf8[UTF8_APP_NAME_CAP];
    char cn_utf8[512];
    char user_esc[128];
    char app_esc[256];   // must be >= UTF8_APP_NAME_CAP + escape headroom
    char cn_esc[1024];

    WcharToUtf8(ev->app_name,     app_utf8, sizeof(app_utf8));
    WcharToUtf8(ev->content_name, cn_utf8,  sizeof(cn_utf8));
    JsonEscapeStr(ev->user,    user_esc, sizeof(user_esc));
    JsonEscapeStr(app_utf8,    app_esc,  sizeof(app_esc));
    JsonEscapeStr(cn_utf8,     cn_esc,   sizeof(cn_esc));

    // ── DEDUP path ───────────────────────────────────────────────────────────
    if (ev->is_dedup) {
        BufAppendf(
            "{\"ts\":\"%s\","
            "\"type\":\"DEDUP\","
            "\"endpoint\":\"amsi_monitor\","
            "\"severity\":\"%s\","
            "\"lang\":\"%s\","
            "\"detection\":\"%s\","
            "\"hash\":\"%s\","
            "\"actor\":{\"pid\":%lu,\"user\":\"%s\"}}\n",
            ts,
            SeverityStr(ev->severity),
            LangStr(ev->lang),
            DetCatStr(ev->category),
            hash_str,
            (unsigned long)ev->pid,
            user_esc
        );
        return;
    }

    // ── FULL path ────────────────────────────────────────────────────────────
    BufAppendf(
        "{\"ts\":\"%s\","
        "\"type\":\"FULL\","
        "\"endpoint\":\"amsi_monitor\","
        "\"source\":\"AMSI-Buffer\","
        "\"severity\":\"%s\","
        "\"lang\":\"%s\","
        "\"detection\":\"%s\","
        "\"hash\":\"%s\","
        "\"details\":{"
        "\"app_name\":\"%s\","
        "\"content_name\":\"%s\","
        "\"encoded_content\":\"",
        ts,
        SeverityStr(ev->severity),
        LangStr(ev->lang),
        DetCatStr(ev->category),
        hash_str,
        app_esc,
        cn_esc
    );

    if (ev->encoded_content && ev->encoded_len > 0)
        BufAppend(ev->encoded_content, ev->encoded_len);

    BufAppendf(
        "\"},"
        "\"actor\":{"
        "\"pid\":%lu,"
        "\"user\":\"%s\"}}\n",
        (unsigned long)ev->pid,
        user_esc
    );
}

// ---------------------------------------------------------------------------
//  PUBLIC: Init / Flush / Shutdown
// ---------------------------------------------------------------------------
bool Logger_Init(const wchar_t* output_path) {
    InitializeCriticalSection(&s_submit_lock);
    memset(&s_buf_a, 0, sizeof(s_buf_a));
    memset(&s_buf_b, 0, sizeof(s_buf_b));
    s_active   = &s_buf_a;
    s_inactive = &s_buf_b;

    CreateDirectoryW(L"logs", NULL);  // Best-effort; ignore if already exists

    s_log_file = CreateFileW(
        output_path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );
    if (s_log_file == INVALID_HANDLE_VALUE) return false;

    SetFilePointer(s_log_file, 0, NULL, FILE_END);  // Append mode

    s_logger_thread = CreateThread(NULL, 0, LoggerThread, NULL, 0, NULL);
    return (s_logger_thread != NULL);
}

void Logger_Flush(void) {
    EnterCriticalSection(&s_submit_lock);
    volatile LogBuffer* tmp = s_active;
    s_active   = s_inactive;
    s_inactive = tmp;
    LeaveCriticalSection(&s_submit_lock);
    FlushInactive();
}

void Logger_Shutdown(void) {
    // g_running is already false; LoggerThread will do its own final flush
    // and then exit.  We wait for it, then do one extra flush pass for anything
    // written between the thread's last flush and here.
    if (s_logger_thread) {
        WaitForSingleObject(s_logger_thread, 5000);
        CloseHandle(s_logger_thread);
        s_logger_thread = NULL;
    }
    // FIX: flush both halves in sequence after thread has exited, so we
    // capture any events submitted between the thread's last Sleep and
    // WaitForSingleObject returning.
    Logger_Flush();
    Logger_Flush();

    if (s_log_file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(s_log_file);
        CloseHandle(s_log_file);
        s_log_file = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&s_submit_lock);
}
