#include "titan_pch.h"
#include "applog_watchlist.h"
#include <tlhelp32.h>

// ─── Constructor ─────────────────────────────────────────────────────────────

AppLogWatchlist::AppLogWatchlist() {
    std::cout << "[Watchlist] Initialized. Max: "
        << MAX_WATCHLIST_SIZE << " apps.\n";
}

// ─── Add ─────────────────────────────────────────────────────────────────────

void AppLogWatchlist::Add(const std::string& appName) {
    std::string key = ToLower(appName);
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    if (m_entries.size() >= MAX_WATCHLIST_SIZE) {
        std::cerr << "[Watchlist] Capacity full. Cannot add: "
            << appName << "\n";
        return;
    }
    if (m_entries.count(key)) {
        std::cout << "[Watchlist] Already watching: " << appName << "\n";
        return;
    }

    WatchlistEntry entry;
    entry.appName = key;
    entry.active = false;
    m_entries[key] = std::move(entry);

    std::cout << "[Watchlist] Added: " << appName
        << " (" << m_entries.size()
        << "/" << MAX_WATCHLIST_SIZE << ")\n";
}

// ─── Remove ──────────────────────────────────────────────────────────────────

void AppLogWatchlist::Remove(const std::string& appName) {
    std::string key = ToLower(appName);
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_entries.find(key);
    if (it == m_entries.end()) {
        std::cout << "[Watchlist] Not found: " << appName << "\n";
        return;
    }
    m_entries.erase(it);
    std::cout << "[Watchlist] Removed: " << appName << "\n";
}

// ─── Contains ────────────────────────────────────────────────────────────────

bool AppLogWatchlist::Contains(const std::string& appName) const {
    std::string key = ToLower(appName);
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_entries.count(key) > 0;
}

// ─── GetAll ──────────────────────────────────────────────────────────────────

std::vector<WatchlistEntry> AppLogWatchlist::GetAll() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<WatchlistEntry> result;
    result.reserve(m_entries.size());
    for (const auto& kv : m_entries)
        result.push_back(kv.second);
    return result;
}

// ─── RefreshPIDs ─────────────────────────────────────────────────────────────

void AppLogWatchlist::RefreshPIDs() {
    auto snapshot = SnapshotProcesses();
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    for (auto& kv : m_entries) {
        auto it = snapshot.find(kv.first);
        if (it != snapshot.end()) {
            kv.second.pids = it->second;
            kv.second.active = !kv.second.pids.empty();
        }
        else {
            kv.second.pids.clear();
            kv.second.active = false;
        }
    }
}

// ─── GetActivePIDs ───────────────────────────────────────────────────────────

std::vector<DWORD> AppLogWatchlist::GetActivePIDs() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    std::vector<DWORD> pids;
    for (const auto& kv : m_entries)
        for (DWORD pid : kv.second.pids)
            pids.push_back(pid);
    return pids;
}

// ─── SnapshotProcesses ───────────────────────────────────────────────────────

std::unordered_map<std::string, std::unordered_set<DWORD>>
AppLogWatchlist::SnapshotProcesses() const
{
    std::unordered_map<std::string, std::unordered_set<DWORD>> result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "[Watchlist] Snapshot failed: "
            << GetLastError() << "\n";
        return result;
    }

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            std::string name;
            for (int i = 0; pe.szExeFile[i] != L'\0'; ++i)
                name += static_cast<char>(pe.szExeFile[i]);
            name = ToLower(name);
            result[name].insert(pe.th32ProcessID);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

// ─── ToLower ─────────────────────────────────────────────────────────────────

std::string AppLogWatchlist::ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    return s;
}