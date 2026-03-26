// usb_monitor.cpp
#include "usb_monitor.h"
#include "usb_kernel_listener.h"
#include "usb_session_manager.h"
#include "usb_identity.h"
#include "usb_logger.h"
#include "usb_watcher.h"

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>
#include <algorithm>

static void LogErrorToConsole(const std::string& msg) {
    std::cerr << "[UsbMonitor] ERROR: " << msg << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionKeyFor
//
// Computes the same key that UsbSessionManager::CreateSession() will store
// internally so that OnDeviceRemoved can look up the right session.
//
// Rules (must stay in sync with UsbSessionManager::CreateSession):
//   1. If the device has a non-empty serial number, use the serial.
//   2. Otherwise use "VID:PID:suffix" where suffix is the last segment of
//      the instance ID (unique per USB port, stable across plug cycles on the
//      same port).  This avoids collisions when multiple identical no-serial
//      devices are plugged into different ports simultaneously.
// ─────────────────────────────────────────────────────────────────────────────
static std::string SessionKeyFor(const UsbIdentity& identity)
{
    if (!identity.serialNumber.empty())
        return identity.serialNumber;

    // Derive a port-unique suffix from the instance ID tail.
    // e.g. "USB\VID_1BCF&PID_08A0\5&2AD35BE9&0&1" → suffix "5&2AD35BE9&0&1"
    std::string suffix;
    size_t lastSlash = identity.instanceId.find_last_of('\\');
    if (lastSlash != std::string::npos && lastSlash + 1 < identity.instanceId.size())
        suffix = identity.instanceId.substr(lastSlash + 1);

    return identity.vid + ":" + identity.pid + ":" + suffix;
}

// ─────────────────────────────────────────────────────────────────────────────
UsbMonitor::UsbMonitor()
    : m_listener(std::make_unique<UsbKernelListener>(this))
    , m_sessionManager(std::make_unique<UsbSessionManager>())
{
}

UsbMonitor::~UsbMonitor() {
    Stop();
}

bool UsbMonitor::Start() {
    if (!m_listener->Start()) {
        LogError("Failed to start USB kernel listener.");
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop
//
// Join all live arrival threads first.  Those threads may be in the middle of
// the drive-letter retry loop when Stop() is called; we must wait for them to
// finish before destroying m_sessionManager and m_listener, otherwise they
// would access freed objects.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::Stop() {
    // 1. Collect all joinable arrival threads under the lock, then release
    //    the lock before joining so the threads can still acquire it if needed.
    std::vector<std::thread> toJoin;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& t : m_arrivalThreads)
            if (t.joinable()) toJoin.push_back(std::move(t));
        m_arrivalThreads.clear();
    }
    for (auto& t : toJoin)
        t.join();

    // 2. Stop all active file watchers.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [serial, watcher] : m_watchers)
            watcher->Stop();
        m_watchers.clear();
    }

    // 3. Stop the kernel listener last.
    if (m_listener) m_listener->Stop();
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnFileEvent(const std::string& deviceSerial,
    const std::string& operation,
    const std::string& filePath,
    uint64_t           size)
{
    if (m_sessionManager)
        m_sessionManager->OnFileEvent(deviceSerial, operation, filePath, size);
}

// ─────────────────────────────────────────────────────────────────────────────
// OnDeviceArrived  (called on the Win32 message thread)
//
// FIX: Previously this function ran the entire drive-letter retry loop
// (up to 10 × 500 ms = 5 seconds) directly on the Win32 message thread.
// While blocked there, no other WM_DEVICECHANGE messages could be dispatched
// — meaning a second device arriving simultaneously would be invisible until
// the first device's retry loop completed.
//
// Fix: Immediately spawn a worker thread (HandleArrival) and return.  The
// message loop stays responsive.  The worker thread is stored in
// m_arrivalThreads and joined in Stop() to prevent use-after-free.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnDeviceArrived(const std::string& devicePath) {
    std::cout << "[UsbMonitor] Device arrival detected: " << devicePath << '\n';

    std::lock_guard<std::mutex> lock(m_mutex);

    // Prune any already-finished arrival threads before adding a new one.
    m_arrivalThreads.erase(
        std::remove_if(m_arrivalThreads.begin(), m_arrivalThreads.end(),
            [](std::thread& t) { return !t.joinable(); }),
        m_arrivalThreads.end());

    m_arrivalThreads.emplace_back(&UsbMonitor::HandleArrival, this, devicePath);
}

// ─────────────────────────────────────────────────────────────────────────────
// HandleArrival  (runs on a dedicated worker thread per arrival event)
//
// All the work that was previously done inline in OnDeviceArrived now lives
// here.  The drive-letter retry loop blocking is harmless on this thread.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::HandleArrival(std::string devicePath)
{
    // 1. Resolve identity.
    UsbIdentity identity;
    if (!ResolveDeviceIdentity(devicePath, identity)) {
        // Non-storage interfaces (HID, audio) often fail here — not an error.
        std::cout << "[UsbMonitor] Skipping (cannot resolve identity): "
            << devicePath << '\n';
        return;
    }

    std::cout << "[UsbMonitor] Identity resolved:"
        << " VID=" << identity.vid
        << " PID=" << identity.pid
        << " Serial=" << identity.serialNumber
        << " InstanceId=" << identity.instanceId << '\n';

    // 2. Quick sanity check — must be a USB bus device.
    if (identity.instanceId.find("USB") == std::string::npos) {
        std::cout << "[UsbMonitor] Skipping (not USB): "
            << identity.instanceId << '\n';
        return;
    }

    // 3. Check whether this is a storage device by walking PnP children.
    //    IsStorageDevice() now correctly walks the child chain of the USB
    //    interface node instead of checking the node itself (which is class
    //    "USB", not "DiskDrive").  Non-storage devices (webcams, keyboards,
    //    audio dongles) are filtered out here without wasting 5 seconds.
    if (!IsStorageDevice(identity)) {
        std::cout << "[UsbMonitor] Skipping (not a storage device): "
            << identity.instanceId << '\n';
        return;
    }

    // 4. Find mount point — retry loop because Windows assigns the drive
    //    letter asynchronously after the USB interface arrives.
    //    Running on a worker thread so this delay is harmless.
    std::vector<std::string> mountPoints;
    constexpr int   kMaxRetries = 10;
    constexpr DWORD kRetryMs = 500;

    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        if (attempt > 0) {
            std::cout << "[UsbMonitor] Waiting for drive letter... (attempt "
                << (attempt + 1) << "/" << kMaxRetries << ")\n";
            Sleep(kRetryMs);
        }
        GetMountPointsForDevice(devicePath, mountPoints);
        if (!mountPoints.empty()) break;
    }

    if (mountPoints.empty()) {
        std::cout << "[UsbMonitor] No drive letter found after retries -- skipping.\n";
        return;
    }

    const std::string& mountPoint = mountPoints[0];
    std::cout << "[UsbMonitor] Mount point: " << mountPoint << '\n';

    // 5. Compute the session key — MUST use the same logic as
    //    UsbSessionManager::CreateSession() so OnDeviceRemoved can find the
    //    session by looking up the key stored in m_deviceSerialMap.
    //
    //    FIX: Previously we stored identity.serialNumber (which is "" when the
    //    device has no serial) in m_deviceSerialMap, but CreateSession used a
    //    "VID:PID" fallback key.  EndSession("") then found no session.
    const std::string sessionKey = SessionKeyFor(identity);

    // 6. Cache devicePath -> session key for OnDeviceRemoved.
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Guard: if the device arrived twice (e.g. hot-plug race), skip.
        if (m_deviceSerialMap.count(devicePath)) {
            std::cout << "[UsbMonitor] Session already exists for: "
                << devicePath << " -- skipping duplicate arrival.\n";
            return;
        }
        m_deviceSerialMap[devicePath] = sessionKey;
    }

    // 7. Create session.
    if (!m_sessionManager->CreateSession(identity, mountPoint)) {
        LogError("Failed to create session for device: " + devicePath);
        std::lock_guard<std::mutex> lock(m_mutex);
        m_deviceSerialMap.erase(devicePath);
        return;
    }

    // 8. Start file watcher.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto watcher = std::make_unique<UsbWatcher>(
            mountPoint, sessionKey, this);
        watcher->Start();
        m_watchers[sessionKey] = std::move(watcher);
    }

    std::cout << "[UsbMonitor] Session started:"
        << " VID=" << identity.vid
        << " PID=" << identity.pid
        << " Key=" << sessionKey
        << " Mount=" << mountPoint << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// OnDeviceRemoved  (called on the Win32 message thread)
//
// Removal processing is fast (no blocking I/O, no retry loop) so it is safe
// to run directly on the message thread.
// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::OnDeviceRemoved(const std::string& devicePath) {

    std::cout << "[UsbMonitor] Device removal detected: " << devicePath << '\n';

    std::string sessionKey;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_deviceSerialMap.find(devicePath);
        if (it == m_deviceSerialMap.end()) {
            // Was never a tracked storage device (webcam, keyboard, etc.)
            // or HandleArrival is still in the retry loop — ignore silently.
            return;
        }
        sessionKey = it->second;
        m_deviceSerialMap.erase(it);

        // Stop watcher BEFORE ending session — prevents use-after-free.
        auto wit = m_watchers.find(sessionKey);
        if (wit != m_watchers.end()) {
            wit->second->Stop();
            m_watchers.erase(wit);
        }
    }

    if (!m_sessionManager->EndSession(sessionKey)) {
        LogError("Failed to end session for key: " + sessionKey);
        return;
    }

    std::cout << "[UsbMonitor] Session ended and logged: Key=" << sessionKey << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbMonitor::LogError(const std::string& message) {
    LogErrorToConsole(message);
}