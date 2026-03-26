#include "titan_amsi.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "psapi.lib")

// ---------------------------------------------------------------------------
//  AMSI ETW Provider GUID
//  {2A576B87-09A7-520E-C21A-4942F0271D67}
// ---------------------------------------------------------------------------
static const GUID AMSI_PROVIDER_GUID = {
    0x2A576B87, 0x09A7, 0x520E,
    {0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67}
};

// FIX: Converted macros to constexpr to resolve VCR101
constexpr const wchar_t* AMSI_SESSION_NAME = L"TitanAMSISession";
constexpr uint8_t        AMSI_EVENT_OPCODE = 0x01; // AmsiScanBuffer callback opcode

// ---------------------------------------------------------------------------
//  MODULE STATE  (static, no heap)
// ---------------------------------------------------------------------------
static TRACEHANDLE  s_session_handle = 0;
static TRACEHANDLE  s_consumer_handle = INVALID_PROCESSTRACE_HANDLE;
static HANDLE       s_consumer_thread = NULL;
static bool         s_session_started = false;
static uint32_t     s_seq = 0;

static_assert(RING_CAPACITY >= 256,
    "RING_CAPACITY must be >= 256 to prevent event pool slot reuse before drain");

// ---------------------------------------------------------------------------
//  HELPERS
// ---------------------------------------------------------------------------
static ScriptLang LangFromAppName(const wchar_t* app) {
    if (!app) return LANG_UNKNOWN;
    wchar_t lower[64] = { 0 };
    for (int i = 0; i < 63 && app[i]; i++)
        lower[i] = (wchar_t)towlower(app[i]);

    if (wcsstr(lower, L"powershell")) return LANG_POWERSHELL;
    if (wcsstr(lower, L"wscript"))   return LANG_WSCRIPT;
    if (wcsstr(lower, L"cscript"))   return LANG_VBSCRIPT;
    if (wcsstr(lower, L"mshta"))     return LANG_MSHTA;
    if (wcsstr(lower, L"jscript"))   return LANG_JSCRIPT;
    if (wcsstr(lower, L"node"))      return LANG_JAVASCRIPT;
    if (wcsstr(lower, L"dotnet") ||
        wcsstr(lower, L"csc.exe") ||
        wcsstr(lower, L"msbuild"))   return LANG_DOTNET;
    if (wcsstr(lower, L"python"))    return LANG_PYTHON;
    if (wcsstr(lower, L"cmd.exe"))   return LANG_BATCH;
    return LANG_UNKNOWN;
}

// ---------------------------------------------------------------------------
//  ArenaAlloc  — lock-free circular arena slot claim.
// ---------------------------------------------------------------------------
static uint8_t* ArenaAlloc(size_t len) {
    if (len == 0 || len > AMSI_MAX_SCRIPT_BYTES) return NULL;

    LONG observed, new_off;
    do {
        observed = InterlockedAdd(&g_ring->arena_offset, 0);
        LONG candidate = observed + (LONG)len;
        if (candidate > (LONG)AMSI_RING_SIZE) {
            new_off = (LONG)len;
            observed = 0;
            LONG current = InterlockedAdd(&g_ring->arena_offset, 0);
            if (current != 0) {
                continue;
            }
        }
        else {
            new_off = candidate;
        }
    } while (InterlockedCompareExchange(&g_ring->arena_offset, new_off, observed) != observed);

    LONG slot_start = new_off - (LONG)len;
    return g_ring->arena + slot_start;
}

// ---------------------------------------------------------------------------
//  RingPush  — SPSC push.  On overflow, evict the oldest slot.
// ---------------------------------------------------------------------------
static bool RingPush(RawEvent* ev) {
    LONG head = InterlockedAdd(&g_ring->head, 0);
    LONG next = (head + 1) % RING_CAPACITY;

    LONG tail = InterlockedAdd(&g_ring->tail, 0);
    if (next == tail) {
        LONG new_tail = (tail + 1) % RING_CAPACITY;
        InterlockedCompareExchange(&g_ring->tail, new_tail, tail);
    }

    g_ring->slots[head] = ev;
    MemoryBarrier();
    InterlockedExchange(&g_ring->head, next);

    InterlockedIncrement(&g_stat_captured);
    return true;
}

// ---------------------------------------------------------------------------
//  ETW EVENT CALLBACK  (HOT PATH — no malloc, no printf, no locks)
// ---------------------------------------------------------------------------
static void WINAPI OnAmsiEvent(PEVENT_RECORD rec) {
    if (!IsEqualGUID(rec->EventHeader.ProviderId, AMSI_PROVIDER_GUID))
        return;
    if (rec->EventHeader.EventDescriptor.Opcode != AMSI_EVENT_OPCODE)
        return;

    BYTE  tdhBuf[4096];
    DWORD tdhBufSize = sizeof(tdhBuf);
    PTRACE_EVENT_INFO tei = (PTRACE_EVENT_INFO)tdhBuf;
    if (TdhGetEventInformation(rec, 0, NULL, tei, &tdhBufSize) != ERROR_SUCCESS)
        return;

    const BYTE* ud = (const BYTE*)rec->UserData;
    DWORD       ud_rem = rec->UserDataLength;

    const wchar_t* app_name = (const wchar_t*)ud;
    size_t app_len = wcsnlen(app_name, ud_rem / sizeof(wchar_t));
    size_t app_bytes = (app_len + 1) * sizeof(wchar_t);
    if (app_bytes > ud_rem) return;
    ud += app_bytes; ud_rem -= (DWORD)app_bytes;

    const wchar_t* content_name = (const wchar_t*)ud;
    size_t cn_len = wcsnlen(content_name, ud_rem / sizeof(wchar_t));
    size_t cn_bytes = (cn_len + 1) * sizeof(wchar_t);
    if (cn_bytes > ud_rem) return;
    ud += cn_bytes; ud_rem -= (DWORD)cn_bytes;

    const uint8_t* content = ud;
    size_t         content_len = ud_rem;
    if (content_len == 0) return;

    uint8_t* arena_slot = ArenaAlloc(content_len);
    if (!arena_slot) return;
    memcpy(arena_slot, content, content_len);

    static RawEvent      s_event_pool[256];
    static volatile LONG s_pool_idx = 0;
    LONG idx = InterlockedIncrement(&s_pool_idx) & 0xFF;

    RawEvent* ev = &s_event_pool[idx];
    ev->magic = RAW_EVENT_MAGIC;
    ev->seq = InterlockedIncrement((LONG*)&s_seq);
    ev->ts_ns = GetTimestampNs();
    ev->pid = rec->EventHeader.ProcessId;
    ev->tid = rec->EventHeader.ThreadId;
    ev->lang = LangFromAppName(app_name);
    ev->data_ptr = arena_slot;
    ev->data_len = content_len;
    ev->processed = false;

    wcsncpy_s(ev->app_name, 64, app_name, _TRUNCATE);
    wcsncpy_s(ev->content_name, 260, content_name, _TRUNCATE);

    RingPush(ev);
}

// ---------------------------------------------------------------------------
//  CONSUMER THREAD  (blocks on ProcessTrace)
// ---------------------------------------------------------------------------
static DWORD WINAPI ConsumerThread(LPVOID) {
    EVENT_TRACE_LOGFILEW log = { 0 };
    log.LoggerName = (LPWSTR)AMSI_SESSION_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = OnAmsiEvent;

    s_consumer_handle = OpenTraceW(&log);
    if (s_consumer_handle == INVALID_PROCESSTRACE_HANDLE) {
        OutputDebugStringW(L"[TITAN] OpenTraceW failed in ConsumerThread\n");
        return 1;
    }

    ProcessTrace(&s_consumer_handle, 1, NULL, NULL);
    CloseTrace(s_consumer_handle);
    s_consumer_handle = INVALID_PROCESSTRACE_HANDLE;
    return 0;
}

// ---------------------------------------------------------------------------
//  PUBLIC API
// ---------------------------------------------------------------------------

bool Capture_Init(void) {
    g_ring->cap = RING_CAPACITY;
    g_ring->head = 0;
    g_ring->tail = 0;
    g_ring->arena_offset = 0;

    g_ring->arena = (uint8_t*)VirtualAlloc(
        NULL, AMSI_RING_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_ring->arena) return false;

    VirtualLock(g_ring->arena, AMSI_RING_SIZE);
    return true;
}

void Capture_Start(void) {
    const size_t NAME_EXTRA = (wcslen(AMSI_SESSION_NAME) + 1) * sizeof(wchar_t);
    size_t       buf_sz = sizeof(EVENT_TRACE_PROPERTIES) + NAME_EXTRA;

    // FIX: Replaced _alloca with a safer, fixed-size stack array to resolve C6255
    BYTE props_buf[1024] = { 0 };
    if (buf_sz > sizeof(props_buf)) return; // Failsafe

    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)props_buf;
    props->Wnode.BufferSize = (ULONG)buf_sz;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, AMSI_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    memset(props_buf, 0, sizeof(props_buf));
    props->Wnode.BufferSize = (ULONG)buf_sz;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&s_session_handle, AMSI_SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        OutputDebugStringW(L"[TITAN] StartTraceW failed\n");
        return;
    }
    s_session_started = true;

    EnableTraceEx2(
        s_session_handle,
        &AMSI_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0, NULL
    );

    s_consumer_thread = CreateThread(NULL, 0, ConsumerThread, NULL, 0, NULL);
}

void Capture_Stop(void) {
    if (s_session_started) {
        const size_t NAME_EXTRA = (wcslen(AMSI_SESSION_NAME) + 1) * sizeof(wchar_t);
        size_t       buf_sz = sizeof(EVENT_TRACE_PROPERTIES) + NAME_EXTRA;

        // FIX: Replaced _alloca with a safer, fixed-size stack array to resolve C6255
        BYTE buf[1024] = { 0 };
        if (buf_sz > sizeof(buf)) return; // Failsafe

        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)buf;
        p->Wnode.BufferSize = (ULONG)buf_sz;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(s_session_handle, NULL, p, EVENT_TRACE_CONTROL_STOP);
        s_session_started = false;
        s_session_handle = 0;
    }
    if (s_consumer_thread) {
        WaitForSingleObject(s_consumer_thread, 3000);
        CloseHandle(s_consumer_thread);
        s_consumer_thread = NULL;
    }
    if (g_ring->arena) {
        VirtualUnlock(g_ring->arena, AMSI_RING_SIZE);
        VirtualFree(g_ring->arena, 0, MEM_RELEASE);
        g_ring->arena = NULL;
    }
}