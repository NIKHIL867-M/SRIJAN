// usb_session_manager.h
#pragma once

#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <cstdint>

class UsbSession;
struct UsbIdentity;

// ─────────────────────────────────────────────────────────────────────────────
// UsbSessionManager
//
// Manages all active USB sessions.  Each session is keyed by a "session key"
// that is computed by SessionKeyFor() (file-scope in usb_session_manager.cpp)
// using the same logic as the identical helper in usb_monitor.cpp:
//
//   • Serial number (globally unique per device), when present.
//   • "VID:PID:instanceId-suffix" (unique per USB port) when not.
//
// Thread-safe: a mutex guards the session map for all public methods.
//
// Lifecycle:
//   CreateSession()  — called from UsbMonitor::HandleArrival
//   OnFileEvent()    — called from UsbMonitor::OnFileEvent (UsbWatcher thread)
//   EndSession()     — called from UsbMonitor::OnDeviceRemoved
// ─────────────────────────────────────────────────────────────────────────────
class UsbSessionManager {
public:
    UsbSessionManager();
    ~UsbSessionManager();

    // Create a new session.  Returns false if a session already exists for
    // the same key (duplicate arrival — caller should not proceed).
    bool CreateSession(const UsbIdentity& identity, const std::string& mountPoint);

    // Route a file-system event to the active session identified by sessionKey.
    // Returns false if no active session is found (benign race condition).
    bool OnFileEvent(const std::string& sessionKey,
        const std::string& operation,
        const std::string& filePath,
        uint64_t           size);

    // Finalize the session, write its JSON summary to the logger, remove it.
    // Returns false if no active session is found for sessionKey.
    bool EndSession(const std::string& sessionKey);

    // Number of currently active sessions (for diagnostics).
    size_t GetActiveSessionCount() const;

private:
    std::unordered_map<std::string, std::unique_ptr<UsbSession>> m_sessions;
    mutable std::mutex m_mutex;

    void LogError(const std::string& msg) const;
};