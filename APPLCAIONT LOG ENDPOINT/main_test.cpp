#include <sdkddkver.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>

#include "applog_monitor.h"

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

// ─── Graceful shutdown ────────────────────────────────────────────────────────

static std::atomic<bool> g_shutdown{ false };

static BOOL WINAPI ConsoleCtrlHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        std::cout << "\n[main] Shutdown signal received...\n";
        g_shutdown.store(true);
        return TRUE;
    }
    return FALSE;
}

// ─── Admin check ─────────────────────────────────────────────────────────────

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// ─── Banner — ASCII only, no UTF-8 box chars (MSVC without /utf-8 safe) ──────

static void PrintBanner() {
    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "   TITAN -- AppLog Monitor  (Test Mode)                     \n";
    std::cout << "   Default Suite: PowerShell | WMI | Defender | Security    \n";
    std::cout << "   Press Ctrl+C to stop cleanly                              \n";
    std::cout << "============================================================\n";
    std::cout << "\n";
}

// ─── Menu ─────────────────────────────────────────────────────────────────────

static void PrintMenu() {
    std::cout << "\n";
    std::cout << "+--------------------------------------------------+\n";
    std::cout << "|  add <app.exe>  -- add app to watchlist          |\n";
    std::cout << "|  rem <app.exe>  -- remove app from watchlist     |\n";
    std::cout << "|  list           -- show current watchlist        |\n";
    std::cout << "|  status         -- show monitor running status   |\n";
    std::cout << "|  quit           -- stop and exit                 |\n";
    std::cout << "+--------------------------------------------------+\n";
    std::cout << "> ";
}

static void RunInteractiveMenu(AppLogMonitor& monitor) {
    std::string line;

    while (!g_shutdown.load()) {
        PrintMenu();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Split into command + optional argument
        std::string cmd;
        std::string arg;
        auto space = line.find(' ');
        if (space != std::string::npos) {
            cmd = line.substr(0, space);
            arg = line.substr(space + 1);
            auto start = arg.find_first_not_of(' ');
            arg = (start == std::string::npos) ? "" : arg.substr(start);
        }
        else {
            cmd = line;
        }

        // Lowercase command
        for (char& c : cmd)
            c = static_cast<char>(
                std::tolower(static_cast<unsigned char>(c)));

        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            g_shutdown.store(true);
            break;
        }
        else if (cmd == "add") {
            if (arg.empty())
                std::cout << "[!] Usage: add <app.exe>\n";
            else
                monitor.AddToWatchlist(arg);
        }
        else if (cmd == "rem" || cmd == "remove") {
            if (arg.empty())
                std::cout << "[!] Usage: rem <app.exe>\n";
            else
                monitor.RemoveFromWatchlist(arg);
        }
        else if (cmd == "list") {
            monitor.PrintWatchlist();
        }
        else if (cmd == "status") {
            std::cout << "[Status] Monitor running: "
                << (monitor.IsRunning() ? "YES" : "NO") << "\n";
        }
        else {
            std::cout << "[!] Unknown command: " << cmd << "\n";
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

int main() {
    PrintBanner();

    if (!IsRunningAsAdmin()) {
        std::cerr << "[FATAL] TITAN requires Administrator privileges.\n"
            << "        Right-click terminal -> Run as administrator.\n";
        return 1;
    }
    std::cout << "[OK] Running as Administrator.\n";

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    AppLogMonitor monitor;

    monitor.AddToWatchlist("powershell.exe");
    monitor.AddToWatchlist("cmd.exe");
    monitor.AddToWatchlist("mshta.exe");
    monitor.AddToWatchlist("wscript.exe");
    monitor.AddToWatchlist("cscript.exe");

    if (!monitor.Start()) {
        std::cerr << "[FATAL] Monitor failed to start.\n";
        return 2;
    }
    std::cout << "[OK] Monitor started. Listening for events...\n";

    RunInteractiveMenu(monitor);

    std::cout << "[main] Stopping monitor...\n";
    monitor.Stop();
    std::cout << "[main] Clean exit.\n";
    return 0;
} 