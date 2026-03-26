// usb_monitor.h
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#include <cstdint>

class UsbKernelListener;
class UsbSessionManager;
class UsbWatcher;

// ─────────────────────────────────────────────────────────────────────────────
// IUsbMonitorCallbacks
// ─────────────────────────────────────────────────────────────────────────────
class IUsbMonitorCallbacks {
public:
    virtual ~IUsbMonitorCallbacks() = default;
    virtual void OnDeviceArrived(const std::string& devicePath) = 0;
    virtual void OnDeviceRemoved(const std::string& devicePath) = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// UsbMonitor
//
// Top-level coordinator.  Owns:
//   UsbKernelListener   -- Win32 message window watching WM_DEVICECHANGE
//   UsbSessionManager   -- per-device session lifecycle
//   UsbWatcher map      -- one ReadDirectoryChangesW thread per active drive
//   m_arrivalThreads    -- detached worker threads, one per arrival event
//
// Thread safety:
//   m_mutex guards m_deviceSerialMap, m_watchers, and m_arrivalThreads.
//
//   UsbKernelListener calls OnDeviceArrived/Removed from its Win32 message
//   thread.  OnDeviceArrived immediately spawns a worker thread so the
//   5-second drive-letter retry loop does NOT block the message thread — if
//   it did, no other WM_DEVICECHANGE messages (e.g. a second device arriving)
//   could be processed until the loop finished.
//
//   UsbWatcher calls OnFileEvent from its own thread.  This is safe: it only
//   acquires m_mutex briefly then delegates to UsbSessionManager which has
//   its own independent mutex.
//
//   Stop() joins all live arrival threads before tearing down sessions and
//   the kernel listener, ensuring a clean, race-free shutdown.
// ─────────────────────────────────────────────────────────────────────────────
class UsbMonitor : public IUsbMonitorCallbacks {
public:
    UsbMonitor();
    ~UsbMonitor();

    bool Start();
    void Stop();

    // Called by UsbWatcher threads to record a file-system event.
    void OnFileEvent(const std::string& deviceSerial,
        const std::string& operation,
        const std::string& filePath,
        uint64_t           size);

    // IUsbMonitorCallbacks — called from the kernel listener thread.
    void OnDeviceArrived(const std::string& devicePath) override;
    void OnDeviceRemoved(const std::string& devicePath) override;

private:
    // Actual arrival work — runs on a dedicated thread per arrival so the
    // Win32 message loop is never blocked by the drive-letter retry delay.
    void HandleArrival(std::string devicePath);

    std::unique_ptr<UsbKernelListener> m_listener;
    std::unique_ptr<UsbSessionManager> m_sessionManager;

    // devicePath -> session key  (so OnDeviceRemoved works after device gone)
    // The session key is the device serial number when present, or
    // "VID:PID:instanceId-suffix" when the device has no serial.
    // It MUST match the key used by UsbSessionManager::CreateSession().
    std::unordered_map<std::string, std::string> m_deviceSerialMap;

    // serial -> watcher  (one ReadDirectoryChangesW thread per active drive)
    std::unordered_map<std::string, std::unique_ptr<UsbWatcher>> m_watchers;

    // One worker thread per arrival event.  Collected here so Stop() can
    // join them all, preventing use-after-free of UsbMonitor members.
    std::vector<std::thread> m_arrivalThreads;

    std::mutex m_mutex;   // guards all three containers above

    void LogError(const std::string& message);
};