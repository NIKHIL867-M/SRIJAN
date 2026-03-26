// usb_watcher.h
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <thread>
#include <atomic>

// Forward declaration — avoids pulling usb_monitor.h into every TU
class UsbMonitor;

// ─────────────────────────────────────────────────────────────────────────────
// UsbWatcher
//
// Spawns one background thread per mounted USB drive.
// Uses ReadDirectoryChangesW (synchronous + CancelIoEx) to watch the root of
// the drive for file create / modify / delete / rename events and forwards
// them to UsbMonitor::OnFileEvent so the session gets real activity totals.
//
// Memory budget:
//   One 65536-byte stack buffer per watcher (allocated on the watcher thread
//   stack, not the heap).  No dynamic allocation during the watch loop.
//
// Noise reduction:
//   Only FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
//        FILE_NOTIFY_CHANGE_LAST_WRITE are watched.
//   FILE_NOTIFY_CHANGE_LAST_ACCESS is intentionally excluded — it fires on
//   every read and would produce enormous log noise with no extra signal.
//
// Lifecycle:
//   1. Construct with mountPoint, serial, monitor pointer.
//   2. Call Start() immediately after CreateSession().
//   3. Call Stop()  before or during EndSession().
// ─────────────────────────────────────────────────────────────────────────────
class UsbWatcher {
public:
    UsbWatcher(std::string mountPoint,
        std::string serial,
        UsbMonitor* monitor);
    ~UsbWatcher();

    // Non-copyable, non-movable (owns a thread and a HANDLE)
    UsbWatcher(const UsbWatcher&) = delete;
    UsbWatcher& operator=(const UsbWatcher&) = delete;

    void Start();
    void Stop();   // blocks until the watcher thread exits

private:
    void WatchLoop();

    // Translate a FILE_ACTION_* constant to the operation string used by
    // UsbSession::AddFileEvent ("write", "delete", "rename").
    static const char* ActionToOperation(DWORD action);

    std::string  m_mountPoint;
    std::string  m_serial;
    UsbMonitor* m_monitor;

    std::thread        m_thread;
    std::atomic<bool>  m_running{ false };
    HANDLE             m_hDir{ INVALID_HANDLE_VALUE };
};