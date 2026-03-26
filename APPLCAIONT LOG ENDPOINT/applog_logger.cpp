#include "titan_pch.h"
#include "applog_logger.h"
#include <filesystem>

// =============================================================================
// FINAL LOGGER — SYNCHRONOUS (100% RELIABLE)
// =============================================================================

bool AppLogLogger::Init(const std::string& filePath) {
    if (m_initialized) return true;

    try {
        auto parent = std::filesystem::path(filePath).parent_path();
        if (!parent.empty())
            std::filesystem::create_directories(parent);
    }
    catch (...) {}

    // Open file
    m_file.open(filePath, std::ios::out | std::ios::trunc | std::ios::binary);

    if (!m_file.is_open()) {
        std::cerr << "[Logger] ❌ FAILED TO OPEN FILE: " << filePath << "\n";
        return false;
    }

    std::cout << "[Logger] ✅ FILE OPENED: " << filePath << "\n";

    m_initialized = true;
    return true;
}

// =============================================================================
// 🔥 DIRECT WRITE (NO THREAD, NO QUEUE)
// =============================================================================

void AppLogLogger::Write(const std::string& jsonEvent) {

    if (!m_file.is_open()) {
        std::cout << "[LOGGER ERROR] FILE NOT OPEN\n";
        return;
    }

    m_file << jsonEvent << "\n";

    if (m_file.fail()) {
        std::cout << "[LOGGER ERROR] WRITE FAILED\n";
    }
    else {
        std::cout << "[LOGGER OK] WRITE SUCCESS\n";
    }

    m_file.flush();   // FORCE write to disk
}

void AppLogLogger::Shutdown() {
    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }

    std::cout << "[Logger] Shutdown complete.\n";
}