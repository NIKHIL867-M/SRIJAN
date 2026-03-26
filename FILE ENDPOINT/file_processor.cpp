// =============================================================================
// TITAN - File Integrity Monitor
// file_processor.cpp
//
// FIXES IN THIS VERSION:
//
// FIX 3 — HandleSetInfo previously returned early for any path that was not
//          in a protected or startup directory. This silently dropped all
//          SET_INFO events on normal user files. The guard has been removed.
//          All SET_INFO events are now logged. Severity is INFO for normal
//          files, ALERT for protected paths, CRITICAL for startup paths.
//
// FIX 4 — ProcessEvent previously returned immediately when path was empty
//          or "unknown". These events still carry valid PID, TID, process
//          name, file_key, and action — enough to be useful for forensics.
//          They are now logged with path set to "unresolved" so nothing is
//          silently swallowed. Hashing is skipped (no file to open), but
//          everything else logs normally.
// =============================================================================

#include "file_logger.h"
#include "file_processor.h"
#include "_file_scope.h"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>

#include <filesystem>
#include <sstream>
#include <iomanip>
#include <vector>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

namespace titan::fim
{

    FileProcessor::FileProcessor() : logger_(nullptr) {}
    FileProcessor::~FileProcessor() {}

    bool FileProcessor::Initialize(FileLogger* logger)
    {
        if (!logger) return false;
        logger_ = logger;
        return true;
    }

    // =========================================================================
    // ProcessEvent
    //
    // FIX 4: Removed early-return for empty / "unknown" paths. Events with
    // unresolved paths still carry PID, TID, process name, action, and
    // file_key — they are logged with path="unresolved" so no activity is
    // silently dropped. Hashing is skipped for unresolved paths since there
    // is no file to open.
    // =========================================================================

    void FileProcessor::ProcessEvent(const FileEvent& event)
    {
        if (!logger_) return;

        try
        {
            // FIX 4: Instead of returning for unknown/empty paths, normalise
            // the path to "unresolved" so the event still flows through.
            // A local copy lets us fix up the path without modifying the
            // caller's event (SubmitEvent contracts).
            FileEvent ev = event;
            if (ev.path.empty() || ev.path == L"unknown")
                ev.path = L"unresolved";

            switch (ev.action)
            {
            case FileAction::CREATE:   HandleCreate(ev);  break;
            case FileAction::WRITE:    HandleWrite(ev);   break;
            case FileAction::CLOSE:    HandleClose(ev);   break;
            case FileAction::DELETE_F: HandleDelete(ev);  break;
            case FileAction::RENAME:   HandleRename(ev);  break;
            case FileAction::SET_INFO: HandleSetInfo(ev); break;
            default: break;
            }
        }
        catch (const std::exception& ex)
        {
            std::cerr << "[FIM][Processor] Exception: " << ex.what() << "\n";
        }
        catch (...) {}
    }

    // =========================================================================
    // Handlers
    // =========================================================================

    void FileProcessor::HandleCreate(const FileEvent& event)
    {
        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool is_protected = IsProtectedPath(ev.path);
        bool is_executable = IsExecutableExtension(ev.path);
        bool is_document = IsDocumentExtension(ev.path);

        LogSeverity sev = ScoreSeverity(FileAction::CREATE, ev.path, ev.process_name);
        std::string json = BuildJsonLog(ev, "", is_protected, is_executable, is_document, 0);

        std::cout << "[FIM][LOG] CREATE -> " << json.substr(0, 120) << "\n";
        logger_->Log(json, sev);
    }

    void FileProcessor::HandleWrite(const FileEvent& event)
    {
        uint64_t key = WriteKey(event);
        std::lock_guard<std::mutex> lock(map_mutex_);

        auto it = active_writes_.find(key);
        if (it != active_writes_.end())
        {
            it->second.last_write_time = std::chrono::steady_clock::now();
            it->second.write_count++;
            if (it->second.process_name.empty() ||
                it->second.process_name == L"unknown")
            {
                if (!event.process_name.empty() && event.process_name != L"unknown")
                    it->second.process_name = event.process_name;
                else
                {
                    std::wstring r = ResolveProcessName(event.pid);
                    if (!r.empty() && r != L"unknown")
                        it->second.process_name = r;
                }
            }
        }
        else
        {
            ActiveWriteEntry entry;
            entry.path = event.path;
            entry.pid = event.pid;
            entry.tid = event.tid;
            entry.file_key = event.file_key;
            entry.is_protected = IsProtectedPath(event.path);
            entry.is_executable = IsExecutableExtension(event.path);
            entry.is_document = IsDocumentExtension(event.path);
            entry.last_write_time = std::chrono::steady_clock::now();
            entry.write_count = 1;

            if (!event.process_name.empty() && event.process_name != L"unknown")
                entry.process_name = event.process_name;
            else
                entry.process_name = ResolveProcessName(event.pid);

            active_writes_[key] = std::move(entry);
        }
    }

    void FileProcessor::HandleClose(const FileEvent& event)
    {
        uint64_t        key = WriteKey(event);
        ActiveWriteEntry entry;

        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            auto it = active_writes_.find(key);
            if (it == active_writes_.end()) return;
            entry = it->second;
            active_writes_.erase(it);
        }

        // FIX 4: Skip hashing for unresolved paths (no file to open).
        std::string hash;
        if (entry.path != L"unresolved" &&
            (entry.is_executable || entry.is_document || entry.is_protected))
        {
            hash = ComputeSHA256(entry.path);
        }

        FileEvent final_event;
        final_event.action = FileAction::WRITE;
        final_event.path = entry.path;
        final_event.pid = entry.pid;
        final_event.tid = entry.tid;
        final_event.process_name = entry.process_name;
        final_event.file_key = entry.file_key;
        final_event.timestamp = std::chrono::system_clock::now();

        LogSeverity sev = ScoreSeverity(FileAction::WRITE,
            entry.path, entry.process_name);
        std::string json = BuildJsonLog(final_event, hash,
            entry.is_protected, entry.is_executable,
            entry.is_document, entry.write_count);

        std::cout << "[FIM][LOG] WRITE(close) -> " << json.substr(0, 120) << "\n";
        logger_->Log(json, sev);
    }

    void FileProcessor::HandleDelete(const FileEvent& event)
    {
        {
            uint64_t key = WriteKey(event);
            std::lock_guard<std::mutex> lock(map_mutex_);
            active_writes_.erase(key);
        }

        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool is_protected = IsProtectedPath(ev.path);
        bool is_executable = IsExecutableExtension(ev.path);
        bool is_document = IsDocumentExtension(ev.path);

        LogSeverity sev = ScoreSeverity(FileAction::DELETE_F,
            ev.path, ev.process_name);
        std::string json = BuildJsonLog(ev, "", is_protected,
            is_executable, is_document, 0);

        std::cout << "[FIM][LOG] DELETE -> " << json.substr(0, 120) << "\n";
        logger_->Log(json, sev);
    }

    void FileProcessor::HandleRename(const FileEvent& event)
    {
        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool dest_protected = IsProtectedPath(ev.path);
        bool dest_executable = IsExecutableExtension(ev.path);
        bool dest_document = IsDocumentExtension(ev.path);
        bool src_protected = !ev.old_path.empty() &&
            IsProtectedPath(ev.old_path);

        // FIX 4: Skip hashing for unresolved paths.
        std::string hash;
        if (ev.path != L"unresolved" && (dest_executable || dest_document))
            hash = ComputeSHA256(ev.path);

        LogSeverity sev = ScoreSeverity(FileAction::RENAME,
            ev.path, ev.process_name);
        if (dest_protected && !src_protected && sev < LogSeverity::WARNING)
            sev = LogSeverity::WARNING;

        std::string json = BuildJsonLog(ev, hash, dest_protected,
            dest_executable, dest_document, 0);

        std::cout << "[FIM][LOG] RENAME -> " << json.substr(0, 120) << "\n";
        logger_->Log(json, sev);
    }

    // =========================================================================
    // HandleSetInfo
    //
    // FIX 3: Removed the early-return guard that only logged events for
    // protected and startup paths. All SET_INFO events are now logged.
    //
    // Severity rules (from mildest to most severe):
    //   - Normal file → INFO
    //   - Protected path → ALERT
    //   - Startup path → CRITICAL
    // =========================================================================
    void FileProcessor::HandleSetInfo(const FileEvent& event)
    {
        FileEvent ev = event;
        if (ev.process_name.empty() || ev.process_name == L"unknown")
            ev.process_name = ResolveProcessName(ev.pid);

        bool is_protected = IsProtectedPath(ev.path);
        bool is_startup = IsStartupPath(ev.path);
        bool is_executable = IsExecutableExtension(ev.path);
        bool is_document = IsDocumentExtension(ev.path);

        // Determine severity: startup > protected > normal
        LogSeverity sev;
        if (is_startup)
            sev = LogSeverity::CRITICAL;
        else if (is_protected)
            sev = LogSeverity::ALERT;
        else
            sev = LogSeverity::INFO;

        std::string json = BuildJsonLog(ev, "", is_protected || is_startup,
            is_executable, is_document, 0);

        std::cout << "[FIM][LOG] SETINFO -> " << json.substr(0, 120) << "\n";
        logger_->Log(json, sev);
    }

    // =========================================================================
    // CleanupStaleEntries
    // =========================================================================

    void FileProcessor::CleanupStaleEntries()
    {
        auto now = std::chrono::steady_clock::now();

        std::vector<ActiveWriteEntry> stale;
        {
            std::lock_guard<std::mutex> lock(map_mutex_);
            for (auto it = active_writes_.begin(); it != active_writes_.end(); )
            {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.last_write_time).count();
                if (age > static_cast<long long>(MAX_WRITE_ENTRY_AGE_SECONDS))
                {
                    stale.push_back(it->second);
                    it = active_writes_.erase(it);
                }
                else ++it;
            }
        }

        for (const auto& entry : stale)
        {
            if (!logger_) continue;

            // FIX 4: Skip hashing for unresolved paths.
            std::string hash;
            if (entry.path != L"unresolved" &&
                (entry.is_executable || entry.is_document || entry.is_protected))
            {
                hash = ComputeSHA256(entry.path);
            }

            FileEvent ev;
            ev.action = FileAction::WRITE;
            ev.path = entry.path;
            ev.pid = entry.pid;
            ev.tid = entry.tid;
            ev.process_name = entry.process_name;
            ev.file_key = entry.file_key;
            ev.timestamp = std::chrono::system_clock::now();

            LogSeverity sev = ScoreSeverity(FileAction::WRITE,
                entry.path, entry.process_name);
            logger_->Log(BuildJsonLog(ev, hash,
                entry.is_protected, entry.is_executable,
                entry.is_document, entry.write_count), sev);
        }
    }

    // =========================================================================
    // SHA-256 via BCrypt
    // =========================================================================

    std::string FileProcessor::ComputeSHA256(const std::wstring& path)
    {
        HANDLE file = CreateFileW(
            path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE) return "";

        BCRYPT_ALG_HANDLE  alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;

        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        {
            CloseHandle(file); return "";
        }

        DWORD obj_size = 0, data_size = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&obj_size), sizeof(DWORD), &data_size, 0))
            || obj_size == 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(file); return "";
        }

        std::vector<BYTE> obj_buf(obj_size);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(
            alg, &hash, obj_buf.data(), obj_size, nullptr, 0, 0)))
        {
            BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(file); return "";
        }

        std::vector<BYTE> buf(65536);
        DWORD bytes_read = 0;
        while (ReadFile(file, buf.data(), 65536, &bytes_read, nullptr) && bytes_read > 0)
            BCryptHashData(hash, buf.data(), bytes_read, 0);

        DWORD hash_len = 0;
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_len), sizeof(DWORD), &data_size, 0);

        std::vector<BYTE> hash_bytes(hash_len);
        BCryptFinishHash(hash, hash_bytes.data(), hash_len, 0);
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(file);

        std::ostringstream ss;
        for (BYTE b : hash_bytes)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return ss.str();
    }

    // =========================================================================
    // ScoreSeverity
    // =========================================================================

    LogSeverity FileProcessor::ScoreSeverity(
        FileAction          action,
        const std::wstring& path,
        const std::wstring& process_name) const
    {
        if (IsStartupPath(path))
            return LogSeverity::CRITICAL;

        bool is_protected = IsProtectedPath(path);
        bool is_executable = IsExecutableExtension(path);
        bool is_document = IsDocumentExtension(path);

        if (is_executable && is_protected &&
            (action == FileAction::CREATE ||
                action == FileAction::WRITE ||
                action == FileAction::RENAME ||
                action == FileAction::DELETE_F))
            return LogSeverity::CRITICAL;

        if (is_protected)
        {
            std::wstring p = ToLower(process_name);
            if (p.find(L"powershell") != std::wstring::npos ||
                p.find(L"cmd.exe") != std::wstring::npos ||
                p.find(L"wscript") != std::wstring::npos ||
                p.find(L"cscript") != std::wstring::npos ||
                p.find(L"mshta") != std::wstring::npos ||
                p.find(L"rundll32") != std::wstring::npos ||
                p.find(L"regsvr32") != std::wstring::npos ||
                p.find(L"certutil") != std::wstring::npos ||
                p.find(L"bitsadmin") != std::wstring::npos)
                return LogSeverity::CRITICAL;
        }

        if (is_executable &&
            (action == FileAction::CREATE ||
                action == FileAction::WRITE ||
                action == FileAction::RENAME))
            return LogSeverity::WARNING;

        if (is_protected) return LogSeverity::WARNING;

        if (is_document &&
            (action == FileAction::WRITE || action == FileAction::DELETE_F))
        {
            std::wstring p = ToLower(process_name);
            if (p.find(L"powershell") != std::wstring::npos ||
                p.find(L"cmd.exe") != std::wstring::npos ||
                p.find(L"wscript") != std::wstring::npos ||
                p.find(L"cscript") != std::wstring::npos)
                return LogSeverity::ALERT;
        }

        {
            std::wstring ext = GetExtension(path);
            if (ext == L".ps1" || ext == L".psm1" || ext == L".vbs" ||
                ext == L".vbe" || ext == L".js" || ext == L".jse" ||
                ext == L".hta" || ext == L".wsf" || ext == L".sct" ||
                ext == L".xsl" || ext == L".wsc")
                return LogSeverity::ALERT;
        }

        return LogSeverity::INFO;
    }

    // =========================================================================
    // ResolveProcessName
    // =========================================================================

    std::wstring FileProcessor::ResolveProcessName(uint32_t pid) const
    {
        if (pid == 0 || pid == 4) return L"System";

        HANDLE proc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (!proc) return L"unknown";

        wchar_t name[MAX_PATH] = {};
        DWORD   size = MAX_PATH;

        if (QueryFullProcessImageNameW(proc, 0, name, &size))
        {
            CloseHandle(proc);
            return std::filesystem::path(name).filename().wstring();
        }

        if (GetModuleFileNameExW(proc, nullptr, name, MAX_PATH))
        {
            CloseHandle(proc);
            return std::filesystem::path(name).filename().wstring();
        }

        CloseHandle(proc);
        return L"unknown";
    }

    // =========================================================================
    // WriteKey
    // =========================================================================

    uint64_t FileProcessor::WriteKey(const FileEvent& ev)
    {
        if (ev.file_key != 0) return ev.file_key;
        return std::hash<std::wstring>{}(ev.path);
    }

    // =========================================================================
    // EscapeJsonString
    // =========================================================================

    std::string FileProcessor::EscapeJsonString(const std::wstring& ws)
    {
        std::string out;
        out.reserve(ws.size() * 2);

        for (size_t i = 0; i < ws.size(); ++i)
        {
            uint32_t cp = static_cast<uint16_t>(ws[i]);

            if (cp >= 0xD800u && cp <= 0xDBFFu)
            {
                if (i + 1 < ws.size())
                {
                    uint32_t low = static_cast<uint16_t>(ws[i + 1]);
                    if (low >= 0xDC00u && low <= 0xDFFFu)
                    {
                        cp = 0x10000u + ((cp - 0xD800u) << 10) + (low - 0xDC00u); ++i;
                    }
                    else cp = 0xFFFDu;
                }
                else cp = 0xFFFDu;
            }
            else if (cp >= 0xDC00u && cp <= 0xDFFFu)
                cp = 0xFFFDu;

            if (cp < 0x80u)
            {
                char c = static_cast<char>(cp);
                if (c == '"')       out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else if (c == '\n') out += "\\n";
                else if (c == '\r') out += "\\r";
                else if (c == '\t') out += "\\t";
                else                out += c;
            }
            else if (cp < 0x800u)
            {
                out += static_cast<char>(0xC0u | (cp >> 6));
                out += static_cast<char>(0x80u | (cp & 0x3Fu));
            }
            else if (cp < 0x10000u)
            {
                out += static_cast<char>(0xE0u | (cp >> 12));
                out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
                out += static_cast<char>(0x80u | (cp & 0x3Fu));
            }
            else
            {
                out += static_cast<char>(0xF0u | (cp >> 18));
                out += static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu));
                out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
                out += static_cast<char>(0x80u | (cp & 0x3Fu));
            }
        }
        return out;
    }

    // =========================================================================
    // BuildJsonLog  (no default param value here — header has it)
    // =========================================================================

    std::string FileProcessor::BuildJsonLog(
        const FileEvent& event,
        const std::string& sha256,
        bool               is_protected,
        bool               is_executable,
        bool               is_document,
        uint32_t           write_count)
    {
        const char* action_str = "unknown";
        switch (event.action)
        {
        case FileAction::CREATE:   action_str = "create";   break;
        case FileAction::WRITE:    action_str = "write";    break;
        case FileAction::DELETE_F: action_str = "delete";   break;
        case FileAction::RENAME:   action_str = "rename";   break;
        case FileAction::CLOSE:    action_str = "close";    break;
        case FileAction::SET_INFO: action_str = "set_info"; break;
        default: break;
        }

        auto now_t = std::chrono::system_clock::to_time_t(event.timestamp);
        std::tm tm_info{};
        gmtime_s(&tm_info, &now_t);
        std::ostringstream ts;
        ts << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%SZ");

        std::ostringstream json;
        json << "{";
        json << "\"endpoint\":\"file_integrity\",";
        json << "\"action\":\"" << action_str << "\",";
        json << "\"path\":\"" << EscapeJsonString(event.path) << "\",";
        if (!event.old_path.empty())
            json << "\"old_path\":\"" << EscapeJsonString(event.old_path) << "\",";
        json << "\"pid\":" << event.pid << ",";
        json << "\"tid\":" << event.tid << ",";
        json << "\"process\":\"" << EscapeJsonString(event.process_name) << "\",";
        json << "\"timestamp\":\"" << ts.str() << "\",";
        json << "\"protected\":" << (is_protected ? "true" : "false") << ",";
        json << "\"executable\":" << (is_executable ? "true" : "false") << ",";
        json << "\"document\":" << (is_document ? "true" : "false");
        if (write_count > 0)
            json << ",\"write_count\":" << write_count;
        if (!sha256.empty())
            json << ",\"sha256\":\"" << sha256 << "\"";
        json << "}";
        return json.str();
    }

} // namespace titan::fim