#include "agent.h"

#include <iostream>
// windows.h pulled in via agent.h -> event.h (with winsock2 first)

// ============================================================================
// ELEVATION CHECK
// ============================================================================

static bool IsElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    TOKEN_ELEVATION elev{};
    DWORD len = 0;
    bool result =
        GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &len) &&
        elev.TokenIsElevated != 0;
    CloseHandle(hToken);
    return result;
}

// ============================================================================
// BANNER
// ============================================================================

static void PrintBanner() {
    std::cout << "\n"
        "  _______ _____ _____ ___  _   _ \n"
        " |__   __|_   _|_   _/ _ \\| \\ | |\n"
        "    | |    | |   | || | | |  \\| |\n"
        "    | |    | |   | || |_| | . ` |\n"
        "    | |   _| |_ _| | \\__/| |\\  |\n"
        "    |_|  |_____|_____\\___/|_| \\_|\n"
        "\n"
        "  TITAN V4  —  Signal Amplifier + Noise Suppressor\n"
        "  ETW Kernel-Process | Npcap Deep-Packet Network Capture\n"
        "  Protocols: TCP/UDP/ICMP/TLS-SNI/HTTP/DNS/QUIC/RDP/SMB/SSH\n"
        "  Fixed RAM ~1.3 MB | No scoring | No detection | No drop\n"
        "  Output: FORWARD (novel) | COMPRESS (redundant)\n"
        "  Compiler: MSVC | Standard: C++20 | Target: Windows 10+\n"
        "\n";
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    PrintBanner();

    if (!IsElevated()) {
        std::cerr << "[ERROR] TITAN requires Administrator privileges.\n"
            << "        Right-click -> Run as Administrator\n";
        return 1;
    }

    // Log directory — AsyncLogger creates it if it doesn't exist.
    // Pass a directory path ending in '\\'; the logger appends the filename.
    std::wstring log_dir = L".\\logs\\";
    if (argc > 1)
        log_dir = argv[1];

    // Ensure trailing backslash
    if (!log_dir.empty() && log_dir.back() != L'\\')
        log_dir += L'\\';

    std::wcout << L"[INFO]  Log directory: " << log_dir << L'\n';

    titan::Agent agent;

    if (!agent.Initialize(log_dir)) {
        std::cerr << "[ERROR] Failed to initialize TITAN V3.\n";
        return 1;
    }

    if (!agent.Start()) {
        std::cerr << "[ERROR] Failed to start TITAN V3.\n";
        return 1;
    }

    return 0;
}