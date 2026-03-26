#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <io.h>
#include <fcntl.h>

#include <windows.h>

#include "file_monitor.h"
#include "file_etw_collector.h"

// =============================================================================
// TITAN - File Integrity Monitor
// main_file_test.cpp
//
// FIX 1 — Banner mojibake: std::cout on Windows does not print UTF-8
//          box-drawing characters correctly unless SetConsoleOutputCP(CP_UTF8)
//          is called first. Replaced box-drawing with plain ASCII so the
//          banner works in every terminal regardless of code page.
//
// FIX 2 — Log path visibility: After monitor.Start() the resolved absolute
//          log path is now printed so the user always knows exactly which
//          file to open. Previously it was easy to look at the wrong copy
//          (e.g. the src3 sample file while real logs went to the build dir).
// =============================================================================

using namespace titan::fim;

static bool IsRunningAsAdmin()
{
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &nt_authority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group))
    {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    return is_admin == TRUE;
}

// FIX 1: Plain ASCII banner — no UTF-8 box-drawing, works in every terminal.
static void PrintBanner()
{
    // FIX 1: Enable UTF-8 output so any remaining non-ASCII text (process
    // names, paths) doesn't corrupt the console.
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "\n";
    std::cout << "  +-------------------------------------------------+\n";
    std::cout << "  |                                                 |\n";
    std::cout << "  |   TITAN  -  File Integrity Monitor              |\n";
    std::cout << "  |   Endpoint 04                                   |\n";
    std::cout << "  |                                                 |\n";
    std::cout << "  +-------------------------------------------------+\n";
    std::cout << "\n";
}

int main()
{
    PrintBanner();

    if (!IsRunningAsAdmin())
    {
        std::cerr << "[FIM] ERROR: Must run as Administrator\n";
        std::cerr << "[FIM] ETW kernel file provider requires elevated privileges\n";
        std::cerr << "[FIM] Right-click the executable and choose 'Run as administrator'\n\n";
        return -1;
    }

    std::cout << "[FIM] Running as Administrator: OK\n\n";

    // -------------------------------------------------------------------------
    // Start file monitor (owns logger + processor + event queue).
    //
    // The path passed here is relative — FileMonitor::ResolveLogPath anchors
    // it to the directory of the running exe automatically. The resolved
    // absolute path is printed by the monitor on startup so you always know
    // exactly which file to open in VS or a text editor.
    // -------------------------------------------------------------------------
    FileMonitor monitor;

    if (!monitor.Start(L"logs\\fim_events.json"))
    {
        std::cerr << "[FIM] Failed to start FileMonitor\n";
        return -1;
    }

    // -------------------------------------------------------------------------
    // Start ETW collector (owns ETW session + provider + collection thread).
    // -------------------------------------------------------------------------
    FileEtwCollector collector(&monitor);

    if (!collector.Start())
    {
        std::cerr << "[FIM] Failed to start ETW collector\n";
        monitor.Stop();
        return -1;
    }

    std::cout << "\n[FIM] Monitoring active — all file events are being captured\n";
    std::cout << "[FIM] Press Q then ENTER to stop\n\n";

    // Wait for stop command
    while (true)
    {
        std::string line;
        std::getline(std::cin, line);

        if (!line.empty() && (line[0] == 'q' || line[0] == 'Q'))
            break;
    }

    std::cout << "\n[FIM] Stopping...\n";

    // Stop in order: collector first (no new events), then monitor (drains queue)
    collector.Stop();
    monitor.Stop();

    std::cout << "[FIM] Clean shutdown — all queued events flushed to disk\n\n";
    return 0;
}