// =============================================================================
//  dashboard.cpp - SentinelAI Master Command Grid
//  Role: Animated C++ Launcher that physically arranges terminal windows.
// =============================================================================
#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

using namespace std;

// Set text color in the console
void SetColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// "Hacker" typewriter animation effect
void Typewriter(const string& text, int speed_ms = 15) {
    for (char c : text) {
        cout << c << flush;
        this_thread::sleep_for(chrono::milliseconds(speed_ms));
    }
    cout << endl;
}

// ---------------------------------------------------------------------------
//  ENDPOINT CONFIGURATION
// ---------------------------------------------------------------------------
struct Endpoint {
    string title;
    string exe_name;
};

// These match your 6 files in the master folder
vector<Endpoint> endpoints = {
    {"[SentinelAI] AMSI Monitor",    "titan_amsi.exe"},
    {"[SentinelAI] Network Monitor", "titan.exe"},
    {"[SentinelAI] Process Monitor", "titan_process.exe"},
    {"[SentinelAI] File Monitor",    "file_test.exe"},
    {"[SentinelAI] App Monitor",     "applog_test.exe"},
    {"[SentinelAI] USB Monitor",     "usb_test.exe"}
};

// ---------------------------------------------------------------------------
//  MAIN EXECUTION
// ---------------------------------------------------------------------------
int main() {
    SetConsoleTitleA("SentinelAI - Master Control Node");

    // --- 1. ANIMATED BOOT SEQUENCE ---
    SetColor(10); // Matrix Green
    cout << R"(
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
    )" << "\n\n";

    SetColor(11); // Cyan
    Typewriter("[*] Initializing SentinelAI Global Grid...", 30);
    Typewriter("[*] Authenticating local endpoints...", 30);
    Typewriter("[+] Authentication successful. Establishing uplinks.\n", 30);

    // --- 2. LAUNCH ENDPOINTS ---
    SetColor(14); // Yellow
    for (const auto& ep : endpoints) {
        cout << "  -> Spawning " << ep.title << "..." << endl;

        // We use cmd.exe to launch the program so we can force a specific Window Title.
        // This makes it easy for our C++ code to find the window later.
        string command = "start \"\" cmd.exe /c \"title " + ep.title + " & " + ep.exe_name + "\"";
        system(command.c_str());

        this_thread::sleep_for(chrono::milliseconds(300)); // Small animation delay
    }

    SetColor(10);
    Typewriter("\n[+] All endpoints spawned. Acquiring window handles...", 20);

    // --- 3. THE MAGIC: SNAP WINDOWS INTO A GRID ---
    // Get the user's screen resolution
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    // Calculate width and height for a 3x2 grid
    int paneW = screenW / 3;
    int paneH = screenH / 2;

    int row = 0, col = 0;

    for (const auto& ep : endpoints) {
        HWND hwnd = NULL;
        int retries = 0;

        // Wait for the window to actually exist on the desktop
        while (hwnd == NULL && retries < 20) {
            hwnd = FindWindowA(NULL, ep.title.c_str());
            this_thread::sleep_for(chrono::milliseconds(100));
            retries++;
        }

        if (hwnd != NULL) {
            // Calculate exact X and Y coordinates for this box
            int x = col * paneW;
            int y = row * paneH;

            // Instantly move and resize the window into the grid slot
            MoveWindow(hwnd, x, y, paneW, paneH, TRUE);

            // Move to next column/row
            col++;
            if (col >= 3) {
                col = 0;
                row++;
            }
        }
    }

    SetColor(11);
    Typewriter("[+] Grid arrangement complete. System fully operational.\n", 20);

    // --- 4. CONTROL HUB ---
    SetColor(15);
    cout << "Press [ENTER] to exit Master Control and close all endpoints...";
    cin.get();

    // Cleanup: Close all the windows when the user presses Enter
    SetColor(12);
    Typewriter("Initiating shutdown sequence...", 30);
    for (const auto& ep : endpoints) {
        HWND hwnd = FindWindowA(NULL, ep.title.c_str());
        if (hwnd) PostMessage(hwnd, WM_CLOSE, 0, 0);
    }

    return 0;
}