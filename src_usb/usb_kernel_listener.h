// usb_kernel_listener.h
#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

class IUsbMonitorCallbacks;

// ─────────────────────────────────────────────────────────────────────────────
// UsbKernelListener
//
// Runs a hidden Win32 message-only window on a dedicated thread and registers
// for DBT_DEVTYP_DEVICEINTERFACE notifications.
//
// Start() blocks until the window is created and notifications are registered,
// so the caller knows the listener is truly ready before returning.
// ─────────────────────────────────────────────────────────────────────────────
class UsbKernelListener {
public:
    explicit UsbKernelListener(IUsbMonitorCallbacks* callbacks);
    ~UsbKernelListener();

    UsbKernelListener(const UsbKernelListener&) = delete;
    UsbKernelListener& operator=(const UsbKernelListener&) = delete;

    // Spawns the listener thread and waits until it is fully ready.
    // Returns true if registration succeeded, false otherwise.
    bool Start();
    void Stop();

private:
    static LRESULT CALLBACK WndProcStatic(HWND hWnd, UINT message,
        WPARAM wParam, LPARAM lParam);
    LRESULT WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

    void MessageLoopThread();
    bool RegisterForNotifications(HWND hWnd);
    void UnregisterNotifications();
    void OnDeviceChange(WPARAM wParam, LPARAM lParam);

    IUsbMonitorCallbacks* m_callbacks;
    std::atomic<bool>            m_running;
    std::unique_ptr<std::thread> m_thread;
    HWND                         m_hWnd;
    HDEVNOTIFY                   m_hDevNotify;
    std::mutex                   m_mutex;

    // Ready signal — MessageLoopThread signals this after registration.
    std::condition_variable      m_readyCv;
    bool                         m_ready = false;
    bool                         m_readyOk = false;   // true = success, false = failed
};