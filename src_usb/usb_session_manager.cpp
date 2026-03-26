// usb_session_manager.cpp
#include "usb_session_manager.h"
#include "usb_session.h"
#include "usb_identity.h"
#include "usb_logger.h"

#include <iostream>

UsbSessionManager::UsbSessionManager() = default;
UsbSessionManager::~UsbSessionManager() = default;

void UsbSessionManager::LogError(const std::string& msg) const {
    std::cerr << "[UsbSessionManager] ERROR: " << msg << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionKeyFor (file-scope helper — mirrors UsbMonitor::SessionKeyFor)
//
// The session is keyed by:
//   • device serial number, when present (globally unique per device)
//   • "VID:PID:instanceId-suffix" otherwise (unique per USB port)
//
// This MUST stay in sync with the identical helper in usb_monitor.cpp.
// If you change the key format here, change it there too.
// ─────────────────────────────────────────────────────────────────────────────
static std::string SessionKeyFor(const UsbIdentity& identity)
{
    if (!identity.serialNumber.empty())
        return identity.serialNumber;

    std::string suffix;
    size_t lastSlash = identity.instanceId.find_last_of('\\');
    if (lastSlash != std::string::npos && lastSlash + 1 < identity.instanceId.size())
        suffix = identity.instanceId.substr(lastSlash + 1);

    return identity.vid + ":" + identity.pid + ":" + suffix;
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbSessionManager::CreateSession(const UsbIdentity& identity,
    const std::string& mountPoint)
{
    // Warn on empty serial — two devices with no serial on the same port
    // would collide even with the VID:PID:suffix fallback if they are
    // identical models connected via a hub.  Unlikely but worth logging.
    if (identity.serialNumber.empty()) {
        std::cerr << "[UsbSessionManager] WARNING: device has no serial number "
            "(VID=" << identity.vid << " PID=" << identity.pid
            << "); using port-based key as fallback.\n";
    }

    const std::string key = SessionKeyFor(identity);

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_sessions.count(key)) {
        LogError("CreateSession: session already exists for key '" + key + "'");
        return false;
    }
    m_sessions[key] = std::make_unique<UsbSession>(identity, mountPoint);
    std::cout << "[UsbSessionManager] Session created: key='" << key
        << "' mount='" << mountPoint << "'\n";
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbSessionManager::OnFileEvent(const std::string& sessionKey,
    const std::string& operation,
    const std::string& filePath,
    uint64_t           size)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_sessions.find(sessionKey);
    if (it == m_sessions.end()) {
        // Benign: can happen if watcher fires just after EndSession races.
        return false;
    }
    it->second->AddFileEvent(operation, filePath, size);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
bool UsbSessionManager::EndSession(const std::string& sessionKey) {
    std::unique_ptr<UsbSession> session;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(sessionKey);
        if (it == m_sessions.end()) {
            LogError("EndSession: no active session for key '" + sessionKey + "'");
            return false;
        }
        session = std::move(it->second);
        m_sessions.erase(it);
    }
    // Finalize and log OUTSIDE the lock.
    // UsbSession::Finalize() takes its own internal mutex; holding ours here
    // would create unnecessary contention with concurrent OnFileEvent calls.
    std::string summaryJson = session->Finalize();
    if (!summaryJson.empty()) {
        UsbLogger::Log(summaryJson);
        std::cout << "[UsbSessionManager] Session finalized and logged: key='"
            << sessionKey << "'\n";
    }
    else {
        // Finalize() returns "" only on a double-call — should never happen here.
        LogError("EndSession: Finalize() returned empty JSON for key '" + sessionKey + "'");
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
size_t UsbSessionManager::GetActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_sessions.size();
}