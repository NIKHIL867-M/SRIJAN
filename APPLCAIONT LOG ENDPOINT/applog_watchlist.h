#pragma once
#include "titan_pch.h"

#include <tlhelp32.h>

struct WatchlistEntry {
    std::string               appName;
    std::unordered_set<DWORD> pids;
    bool                      active{ false };
};

class AppLogWatchlist {
public:
    AppLogWatchlist();
    ~AppLogWatchlist() = default;

    void Add(const std::string& appName);
    void Remove(const std::string& appName);
    bool Contains(const std::string& appName) const;

    std::vector<WatchlistEntry> GetAll() const;
    void RefreshPIDs();
    std::vector<DWORD> GetActivePIDs() const;

    static constexpr size_t MAX_WATCHLIST_SIZE = 20;

private:
    std::unordered_map<std::string, std::unordered_set<DWORD>>
        SnapshotProcesses() const;

    static std::string ToLower(std::string s);

    std::unordered_map<std::string, WatchlistEntry> m_entries;
    mutable std::shared_mutex                        m_mutex;
};