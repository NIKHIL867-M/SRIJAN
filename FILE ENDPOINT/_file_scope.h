#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// _file_scope.h
// =============================================================================

#include <string>
#include <vector>
#include <unordered_set>
#include <filesystem>
#include <windows.h>
#include <algorithm>

namespace titan::fim
{

    inline std::wstring ToLower(const std::wstring& s)
    {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }

    inline std::wstring ExpandEnvPath(const std::wstring& path)
    {
        wchar_t buf[MAX_PATH * 2] = {};
        DWORD len = ExpandEnvironmentStringsW(path.c_str(), buf, MAX_PATH * 2);
        if (len == 0 || len > MAX_PATH * 2) return path;
        return std::wstring(buf);
    }

    // Returns lowercased extension including dot, e.g. L".exe"
    inline std::wstring GetExtension(const std::wstring& path)
    {
        std::filesystem::path p(path);
        return ToLower(p.extension().wstring());
    }

    // =========================================================================
    // Path lists
    // =========================================================================

    inline std::vector<std::wstring> GetProtectedPaths()
    {
        return {
            ExpandEnvPath(L"%SystemRoot%\\System32"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\drivers"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\drivers\\etc"),
            ExpandEnvPath(L"%SystemRoot%\\SysWOW64"),
            ExpandEnvPath(L"%SystemRoot%\\System"),
            ExpandEnvPath(L"%SystemRoot%\\Boot"),
            ExpandEnvPath(L"%SystemRoot%\\Fonts"),
            ExpandEnvPath(L"%ProgramFiles%"),
            ExpandEnvPath(L"%ProgramFiles(x86)%"),
            ExpandEnvPath(L"%ProgramW6432%"),
            ExpandEnvPath(L"%USERPROFILE%\\Desktop"),
            ExpandEnvPath(L"%USERPROFILE%\\Documents"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Roaming"),
        };
    }

    inline std::vector<std::wstring> GetStartupPaths()
    {
        return {
            ExpandEnvPath(L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            ExpandEnvPath(L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\Tasks"),
            ExpandEnvPath(L"%SystemRoot%\\SysWOW64\\Tasks"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\wbem\\Repository"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\GroupPolicy\\Machine\\Scripts"),
            ExpandEnvPath(L"%SystemRoot%\\System32\\GroupPolicy\\User\\Scripts"),
        };
    }

    inline std::vector<std::wstring> GetKnownTempPaths()
    {
        return {
            ExpandEnvPath(L"%SystemRoot%\\Temp"),
            ExpandEnvPath(L"%TEMP%"),
            ExpandEnvPath(L"%TMP%"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Temp"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\WebCache"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
            ExpandEnvPath(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"),
            ExpandEnvPath(L"%SystemRoot%\\Prefetch"),
        };
    }

    // =========================================================================
    // Extension sets
    // =========================================================================

    inline const std::unordered_set<std::wstring> EXECUTABLE_EXTENSIONS = {
        L".exe", L".dll", L".sys", L".drv", L".ocx",
        L".bat", L".cmd", L".ps1", L".psm1",
        L".vbs", L".vbe", L".js",  L".jse", L".wsf",
        L".hta", L".scr", L".cpl", L".msi", L".com",
        L".pif", L".reg", L".inf", L".lnk",
        L".xsl", L".xslt", L".sct", L".wsc", L".application",
        L".jar", L".py", L".pyc", L".rb", L".pl",
    };

    inline const std::unordered_set<std::wstring> DOCUMENT_EXTENSIONS = {
        L".doc",  L".docx", L".xls",  L".xlsx", L".ppt",  L".pptx",
        L".odt",  L".ods",  L".odp",
        L".pdf",
        L".txt",  L".csv",  L".xml",  L".json", L".yaml", L".yml",
        L".conf", L".cfg",  L".toml",
        L".zip",  L".rar",  L".7z",   L".gz",   L".tar",  L".cab",
        L".iso",  L".img",
        L".pfx",  L".cer",  L".crt",  L".pem",  L".key",
        L".jpg",  L".jpeg", L".png",  L".gif",  L".bmp",  L".tiff",
    };

    // ==========================================================================
    // FIX: IGNORE_EXTENSIONS no longer causes a hard DROP.
    // These extensions are OS-internal noise that would normally flood the log,
    // but the user wants EVERYTHING monitored. They are now routed to Bucket C
    // so they are tracked as low-priority files.
    //
    // Only empty/null paths remain as true DROP conditions — every real file
    // event with a recoverable path must reach a handler.
    // ==========================================================================
    inline const std::unordered_set<std::wstring> LOW_PRIORITY_EXTENSIONS = {
        L".etl",    // ETW trace log
        L".evtx",   // Event log  (AppLog endpoint handles this, but still record it)
        L".pf",     // Prefetch
        L".mui",    // Multilingual UI resource
        L".db-shm", L".db-wal",
        L".msc",
        L".nls",
    };

    // =========================================================================
    // Thresholds
    // =========================================================================

    // Minimum file size only applied to NORMAL (Bucket C) files
    // NEVER applied to executables or files in protected/temp paths
    static constexpr uint64_t MIN_FILE_SIZE_BYTES = 512;
    static constexpr uint32_t WRITE_SETTLE_MS = 500;
    static constexpr uint32_t MAX_WRITE_ENTRY_AGE_SECONDS = 120;

    // TempTracker
    static constexpr uint32_t HIGH_CHURN_THRESHOLD = 30;
    static constexpr uint32_t TEMP_SHORT_LIFE_SECONDS = 60;
    static constexpr uint32_t TEMP_DEEP_WATCH_SECONDS = 300;
    static constexpr uint32_t TEMP_TRACKER_MAX_ENTRIES = 512;

    // =========================================================================
    // Path helpers
    // =========================================================================

    inline bool PathStartsWith(const std::wstring& path, const std::wstring& base)
    {
        if (base.empty()) return false;
        return ToLower(path).rfind(ToLower(base), 0) == 0;
    }

    inline bool IsProtectedPath(const std::wstring& path)
    {
        for (const auto& base : GetProtectedPaths())
            if (!base.empty() && PathStartsWith(path, base)) return true;
        return false;
    }

    inline bool IsStartupPath(const std::wstring& path)
    {
        for (const auto& base : GetStartupPaths())
            if (!base.empty() && PathStartsWith(path, base)) return true;
        return false;
    }

    inline bool IsKnownTempPath(const std::wstring& path)
    {
        for (const auto& base : GetKnownTempPaths())
            if (!base.empty() && PathStartsWith(path, base)) return true;
        return false;
    }

    inline bool IsExecutableExtension(const std::wstring& path)
    {
        return EXECUTABLE_EXTENSIONS.count(GetExtension(path)) > 0;
    }

    inline bool IsDocumentExtension(const std::wstring& path)
    {
        return DOCUMENT_EXTENSIONS.count(GetExtension(path)) > 0;
    }

    // FIX: Renamed from IsIgnoredExtension to IsLowPriorityExtension.
    // These files are no longer dropped — they are routed to Bucket C.
    inline bool IsLowPriorityExtension(const std::wstring& path)
    {
        return LOW_PRIORITY_EXTENSIONS.count(GetExtension(path)) > 0;
    }

    // Keep backward compat alias so existing callers still compile.
    inline bool IsIgnoredExtension(const std::wstring& path)
    {
        return IsLowPriorityExtension(path);
    }

    inline bool HasNoExtension(const std::wstring& path)
    {
        return std::filesystem::path(path).extension().empty();
    }

    // =========================================================================
    // EventBucket — classification of each incoming file event
    //
    //   DROP  — ONLY for truly unresolvable events (empty path, null path).
    //           Nothing else is ever hard-dropped. Every real file event is
    //           monitored and logged.
    //
    //   A     — protected path, startup path, or executable extension
    //           → FileProcessor (full detail log, hash on close)
    //
    //   B     — known temp/churn path OR dynamic churn zone
    //           → TempTracker (bucket compression, anomaly elevation)
    //
    //   C     — everything else: documents, images, config files, unknown
    //           extensions, extensionless files, low-priority OS files.
    //           All logged individually via FileProcessor.
    //
    // IMPORTANT: Bucket A takes priority.
    // An executable in a temp folder → Bucket A (not B).
    // A file in a protected path inside a temp subfolder → Bucket A.
    //
    // FIX: Previously, low-priority extensions (.etl, .evtx, .pf, .nls, etc.)
    // were hard-DROPped. They are now routed to Bucket C so all activity is
    // captured. The DROP bucket is reserved exclusively for events where the
    // path is genuinely unresolvable.
    // =========================================================================

    enum class EventBucket { DROP, A, B, C };

    inline EventBucket ClassifyEvent(const std::wstring& path)
    {
        // FIX: Only drop if path is completely empty or still unresolved.
        // Do NOT drop device paths (\\Device\\...) — they carry real events
        // even when drive-letter resolution fails.
        if (path.empty())
            return EventBucket::DROP;

        // Bucket A: startup persistence paths — CRITICAL priority
        if (IsStartupPath(path))
            return EventBucket::A;

        // Bucket A: protected OS/program paths (System32, ProgramFiles, etc.)
        if (IsProtectedPath(path))
            return EventBucket::A;

        // Bucket A: executable/script files ANYWHERE on the system.
        // A .exe or .ps1 in %TEMP% is just as important as one in System32.
        if (IsExecutableExtension(path))
            return EventBucket::A;

        // Bucket B: known temp/cache/churn paths.
        // TempTracker compresses them into summaries and elevates anomalies.
        if (IsKnownTempPath(path))
            return EventBucket::B;

        // Bucket C: all other files — documents, images, config files,
        // unknown extensions, extensionless files, low-priority OS files,
        // unresolved device paths, and anything not covered above.
        // FIX: Low-priority extensions (.etl, .evtx, .pf, etc.) land here
        // instead of being hard-dropped. Everything gets logged.
        return EventBucket::C;
    }

} // namespace titan::fim