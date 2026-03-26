#pragma once
#include "titan_pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

class AppLogMonitor;
class AppLogWatchlist;

// =============================================================================
// FIXED: GUIDs are now 'inline constexpr' instead of 'static const'
//
// 'static const GUID' in a header = each .cpp that includes this gets its own
// copy → ODR (One Definition Rule) violation → linker warnings.
// 'inline constexpr' = one definition shared across all translation units.
//
// FIXED: POWERSHELL_PROVIDER_GUID had wrong last 8 bytes.
//   Wrong: {0x8A,0x3D,0x9A,0x81,0x4B,0x16,0xE2,0xBA}
//   Right: {0x87,0x66,0x3C,0xF1,0xC5,0x8F,0x98,0x5A}
//   Microsoft-Windows-PowerShell: {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
//   Wrong GUID = ETW session enables a provider that does not exist
//                = zero PowerShell events captured, ever.
// =============================================================================

// Microsoft-Windows-PowerShell ETW provider
// {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
inline constexpr GUID POWERSHELL_PROVIDER_GUID = {
    0xA0C1853B, 0x5C40, 0x4B15,
    { 0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A }
};

// Microsoft-Windows-WMI-Activity ETW provider
// {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
inline constexpr GUID WMI_ACTIVITY_PROVIDER_GUID = {
    0x1418EF04, 0xB0B4, 0x4623,
    { 0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA }
};

class AppLogEtwCollector {
public:
    AppLogEtwCollector(AppLogMonitor* monitor, AppLogWatchlist* watchlist);
    ~AppLogEtwCollector();

    bool Start();
    void Stop();
    void UpdatePIDFilter(const std::vector<DWORD>& activePIDs);

private:
    bool StartEtwSession();
    bool EnableProviders();
    void ProcessingThreadFunc();

    static VOID WINAPI StaticEventCallback(PEVENT_RECORD pEvent);
    void HandleEvent(PEVENT_RECORD pEvent);
    void HandlePowerShellEvent(PEVENT_RECORD pEvent);
    void HandleWmiEvent(PEVENT_RECORD pEvent);
    void HandleWatchlistEvent(PEVENT_RECORD pEvent);

    bool IsPIDWatched(DWORD pid) const;
    static std::string TimestampFromFiletime(const LARGE_INTEGER& ft);

    AppLogMonitor* m_monitor;
    AppLogWatchlist* m_watchlist;

    TRACEHANDLE       m_sessionHandle{ INVALID_PROCESSTRACE_HANDLE };
    TRACEHANDLE       m_traceHandle{ INVALID_PROCESSTRACE_HANDLE };

    std::thread       m_processingThread;
    std::atomic<bool> m_running{ false };

    mutable SRWLOCK           m_pidLock = SRWLOCK_INIT;
    std::unordered_set<DWORD> m_watchedPIDs;

    // FIXED: 'inline static constexpr' — safe in header, no ODR issue
    inline static constexpr wchar_t SESSION_NAME[] = L"TITAN_AppLog_ETW_Session";
};