// usb_kernel_listener.cpp
#include "usb_kernel_listener.h"
#include "usb_monitor.h"

#include <dbt.h>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>
#include <iostream>

// GUID for all USB device interfaces — triggers arrival/removal events for
// any USB device (storage, HID, audio, etc.).  Non-storage devices are
// filtered in UsbMonitor::OnDeviceArrived().
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE,
    0xA5DCBF10, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);

static void LogError(const std::string& msg) {
    std::cerr << "[UsbKernelListener] ERROR: " << msg << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
UsbKernelListener::UsbKernelListener(IUsbMonitorCallbacks* callbacks)
    : m_callbacks(callbacks)
    , m_running(false)
    , m_hWnd(nullptr)
    , m_hDevNotify(nullptr)
{
}

UsbKernelListener::~UsbKernelListener() {
    Stop();
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbKernelListener::Start() {
    if (m_running.exchange(true)) return true;  // already running

    m_ready = false;
    m_readyOk = false;

    m_thread = std::make_unique<std::thread>(
        &UsbKernelListener::MessageLoopThread, this);

    // Block until MessageLoopThread signals that registration is complete.
    // This guarantees the listener is truly ready before Start() returns.
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_readyCv.wait(lock, [this] { return m_ready; });
    }

    if (!m_readyOk) {
        // Registration failed — thread will exit on its own; join it.
        if (m_thread->joinable()) m_thread->join();
        m_thread.reset();
        m_running.store(false);
        return false;
    }

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop
//
// FIX: Originally m_running was set false *before* PostMessage(WM_QUIT),
// which meant the message loop could exit (via the m_running check) before
// the WM_QUIT was even posted, leaving the thread running until the next
// message arrived.  Now we post WM_QUIT first and let the message loop drain
// naturally; m_running is set false atomically at the top of exchange so we
// don't double-post.
// ─────────────────────────────────────────────────────────────────────────────
void UsbKernelListener::Stop() {
    if (!m_running.exchange(false)) return;  // wasn't running

    // Capture the HWND under the mutex before the thread might destroy it.
    HWND hWnd = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        hWnd = m_hWnd;
    }
    // Post WM_QUIT so GetMessage() returns 0 and the thread exits cleanly.
    if (hWnd) PostMessage(hWnd, WM_QUIT, 0, 0);

    if (m_thread && m_thread->joinable()) m_thread->join();
    m_thread.reset();
}

// ─────────────────────────────────────────────────────────────────────────────
// MessageLoopThread
//
// Runs entirely on the spawned thread.  All Win32 objects (window, notifier)
// are created and destroyed here to satisfy the message-loop threading rules.
//
// FIX: The original code had two early-return paths that called
//      UnregisterClassA() but a third path (CreateWindowExA failure) that
//      called UnregisterClassA() correctly.  Any path that returns after
//      RegisterClassA() must call UnregisterClassA() — verified below.
// ─────────────────────────────────────────────────────────────────────────────
void UsbKernelListener::MessageLoopThread() {
    // Use explicit ANSI (A) variants throughout: the window is ANSI so Windows
    // delivers WM_DEVICECHANGE with a DEV_BROADCAST_DEVICEINTERFACE_A struct.
    // Keeping everything in the A variant avoids any wide/narrow mismatch.
    static const char CLASS_NAME[] = "UsbKernelListenerHiddenWindow";

    HINSTANCE hInst = GetModuleHandleA(nullptr);

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProcStatic;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClassA(&wc)) {
        // Class may already be registered if Start()/Stop()/Start() is called.
        // GetLastError() == ERROR_CLASS_ALREADY_EXISTS is benign.
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            LogError("Failed to register window class (err=" + std::to_string(err) + ")");
            return;
        }
    }

    // Message-only window — HWND_MESSAGE parent means it never appears on screen.
    HWND hWnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "UsbKernelListenerWindow",   // non-empty ANSI title, avoids any wide/narrow
        // literal ambiguity in UNICODE builds
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr,
        hInst,
        this                         // passed through WM_NCCREATE → GWLP_USERDATA
    );

    if (!hWnd) {
        LogError("Failed to create hidden message window (err="
            + std::to_string(GetLastError()) + ")");
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_ready = true;
            m_readyOk = false;
        }
        m_readyCv.notify_one();
        UnregisterClassA(CLASS_NAME, hInst);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hWnd = hWnd;
    }

    if (!RegisterForNotifications(hWnd)) {
        LogError("Failed to register device notifications");
        DestroyWindow(hWnd);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_hWnd = nullptr;
            m_ready = true;    // signal failure
            m_readyOk = false;
        }
        m_readyCv.notify_one();
        UnregisterClassA(CLASS_NAME, hInst);
        return;
    }

    // Signal Start() that we are fully ready to receive notifications.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_ready = true;
        m_readyOk = true;
    }
    m_readyCv.notify_one();
    std::cout << "[UsbKernelListener] Ready -- listening for USB devices.\n";

    // ── Message loop ──────────────────────────────────────────────────────
    // FIX: The original loop was `while (GetMessage(...) && m_running)`.
    // After Stop() sets m_running=false and posts WM_QUIT, GetMessage() will
    // return 0 (for WM_QUIT) and the loop exits naturally — the m_running
    // check is redundant and was misleading.  Keeping only the GetMessage()
    // return-value check is correct and simpler.
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // ── Cleanup ───────────────────────────────────────────────────────────
    UnregisterNotifications();
    DestroyWindow(hWnd);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hWnd = nullptr;
    }
    UnregisterClassA(CLASS_NAME, hInst);
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbKernelListener::RegisterForNotifications(HWND hWnd) {
    // We use the ANSI (_A) variant here because the window was created with
    // CreateWindowExA.  Windows delivers WM_DEVICECHANGE lParam as a
    // DEV_BROADCAST_DEVICEINTERFACE_A struct (char[] path) to ANSI windows,
    // regardless of whether RegisterDeviceNotificationW or A is called.
    // Using the _A struct avoids the WCHAR/char mismatch that produces garbage.
    DEV_BROADCAST_DEVICEINTERFACE_A filter = {};
    filter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE_A);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

    HDEVNOTIFY hDevNotify = RegisterDeviceNotificationA(
        hWnd,
        &filter,
        DEVICE_NOTIFY_WINDOW_HANDLE);

    if (!hDevNotify) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_hDevNotify = hDevNotify;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbKernelListener::UnregisterNotifications() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_hDevNotify) {
        UnregisterDeviceNotification(m_hDevNotify);
        m_hDevNotify = nullptr;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WndProcStatic — static trampoline to instance WndProc
// ─────────────────────────────────────────────────────────────────────────────
/*static*/ LRESULT CALLBACK UsbKernelListener::WndProcStatic(
    HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    UsbKernelListener* pThis = nullptr;

    if (message == WM_NCCREATE) {
        auto pCreate = reinterpret_cast<CREATESTRUCTA*>(lParam);
        pThis = static_cast<UsbKernelListener*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
    }
    else {
        pThis = reinterpret_cast<UsbKernelListener*>(
            GetWindowLongPtr(hWnd, GWLP_USERDATA));
    }

    if (pThis) return pThis->WndProc(hWnd, message, wParam, lParam);
    return DefWindowProcA(hWnd, message, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// WndProc — instance message handler
//
// FIX: WM_DEVICECHANGE must return TRUE (non-zero) to allow future broadcasts.
//      All other messages are forwarded to DefWindowProcA.
// ─────────────────────────────────────────────────────────────────────────────
LRESULT UsbKernelListener::WndProc(HWND hWnd, UINT message,
    WPARAM wParam, LPARAM lParam)
{
    if (message == WM_DEVICECHANGE) {
        OnDeviceChange(wParam, lParam);
        return TRUE;   // required — tells the system to allow the change
    }
    return DefWindowProcA(hWnd, message, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// OnDeviceChange
//
// ANSI window delivers DEV_BROADCAST_DEVICEINTERFACE_A — char[] path.
// Read directly as std::string, no conversion needed.
// ─────────────────────────────────────────────────────────────────────────────
void UsbKernelListener::OnDeviceChange(WPARAM wParam, LPARAM lParam) {
    if (!m_callbacks) return;
    if (wParam != DBT_DEVICEARRIVAL && wParam != DBT_DEVICEREMOVECOMPLETE) return;

    auto pHdr = reinterpret_cast<PDEV_BROADCAST_HDR>(lParam);
    if (!pHdr || pHdr->dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE) return;

    // The window was created with CreateWindowExA so Windows delivers the
    // WM_DEVICECHANGE lParam as DEV_BROADCAST_DEVICEINTERFACE_A (char[] path).
    // Read it directly as a std::string — no wide-to-UTF8 conversion needed.
    auto pDevInf = reinterpret_cast<DEV_BROADCAST_DEVICEINTERFACE_A*>(pHdr);

    // dbcc_name is a char[] flexible array — use it directly as a C string.
    std::string devicePath(pDevInf->dbcc_name);
    if (devicePath.empty()) return;

    if (wParam == DBT_DEVICEARRIVAL)
        m_callbacks->OnDeviceArrived(devicePath);
    else
        m_callbacks->OnDeviceRemoved(devicePath);
}