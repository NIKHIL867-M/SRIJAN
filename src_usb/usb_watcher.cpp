// usb_watcher.cpp
#include "usb_watcher.h"
#include "usb_monitor.h"

#include <iostream>
#include <string>
#include <cinttypes>

// ─────────────────────────────────────────────────────────────────────────────
// Watch buffer size.  64 KB is the practical maximum before the kernel starts
// dropping events on a busy drive.  Allocated on the watcher thread's stack —
// zero heap allocation during the loop.
// ─────────────────────────────────────────────────────────────────────────────
static constexpr DWORD kWatchBufBytes = 65536;

// Notify flags — deliberately minimal to reduce noise and CPU:
//   FILE_NOTIFY_CHANGE_FILE_NAME  : create / delete / rename
//   FILE_NOTIFY_CHANGE_SIZE       : file grew or shrank (write indicator)
//   FILE_NOTIFY_CHANGE_LAST_WRITE : write flushed to disk
// Excluded:
//   FILE_NOTIFY_CHANGE_LAST_ACCESS — fires on every read, far too noisy
//   FILE_NOTIFY_CHANGE_ATTRIBUTES — irrelevant for activity tracking
static constexpr DWORD kWatchFlags =
FILE_NOTIFY_CHANGE_FILE_NAME |
FILE_NOTIFY_CHANGE_SIZE |
FILE_NOTIFY_CHANGE_LAST_WRITE;

// ─────────────────────────────────────────────────────────────────────────────
UsbWatcher::UsbWatcher(std::string mountPoint,
    std::string serial,
    UsbMonitor* monitor)
    : m_mountPoint(std::move(mountPoint))
    , m_serial(std::move(serial))
    , m_monitor(monitor)
{
}

UsbWatcher::~UsbWatcher() {
    Stop();
}

// ─────────────────────────────────────────────────────────────────────────────
void UsbWatcher::Start()
{
    if (m_running.exchange(true)) return;   // already running

    // Open the drive root with FILE_FLAG_BACKUP_SEMANTICS (required for
    // directories) and without FILE_FLAG_OVERLAPPED so we can use the simple
    // synchronous ReadDirectoryChangesW + CancelIoEx shutdown pattern.
    m_hDir = CreateFileA(
        m_mountPoint.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,   // required for directories
        nullptr);

    if (m_hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "[UsbWatcher] Cannot open directory '"
            << m_mountPoint << "' (err=" << GetLastError() << ")\n";
        m_running.store(false);
        return;
    }

    m_thread = std::thread(&UsbWatcher::WatchLoop, this);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop
//
// CancelIoEx unblocks the synchronous ReadDirectoryChangesW call inside
// WatchLoop so the thread can exit cleanly.  We then join and close the handle.
// ─────────────────────────────────────────────────────────────────────────────
void UsbWatcher::Stop()
{
    if (!m_running.exchange(false)) return;   // wasn't running

    if (m_hDir != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_hDir, nullptr);   // unblocks ReadDirectoryChangesW
    }

    if (m_thread.joinable()) m_thread.join();

    if (m_hDir != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDir);
        m_hDir = INVALID_HANDLE_VALUE;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ActionToOperation
//
// Maps FILE_ACTION_* to the string UsbSession::AddFileEvent expects.
// ─────────────────────────────────────────────────────────────────────────────
/*static*/ const char* UsbWatcher::ActionToOperation(DWORD action)
{
    switch (action) {
    case FILE_ACTION_ADDED:            return "write";    // new file created
    case FILE_ACTION_MODIFIED:         return "write";    // existing file written
    case FILE_ACTION_REMOVED:          return "delete";
    case FILE_ACTION_RENAMED_OLD_NAME: return "rename";
    case FILE_ACTION_RENAMED_NEW_NAME: return nullptr;    // skip the "after" half
    default:                           return nullptr;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchLoop — runs on m_thread
//
// Design notes:
//   • Buffer lives on the stack — no heap allocation inside the loop.
//   • FILE_NOTIFY_INFORMATION records are variable-length and linked via
//     NextEntryOffset.  We walk the list manually.
//   • File size is obtained via GetFileAttributesEx immediately after
//     detecting the event.  There is an inherent race (the file could be
//     deleted between the notification and the size query) so we silently
//     use size=0 on failure rather than crashing.
//   • Renamed files: we skip FILE_ACTION_RENAMED_NEW_NAME (the "after" half)
//     to avoid double-counting; the "before" half already recorded the event.
// ─────────────────────────────────────────────────────────────────────────────
void UsbWatcher::WatchLoop()
{
    // Stack-allocated buffer, zero-initialized so MSVC's C4701 is satisfied.
    // ReadDirectoryChangesW fills this before we read it, but the compiler
    // cannot prove that statically.  Zero-init costs one memset per loop
    // iteration on a 64 KB stack buffer — negligible compared to the blocking
    // ReadDirectoryChangesW call that follows.
    alignas(DWORD) char buf[kWatchBufBytes] = {};

    while (m_running.load(std::memory_order_acquire)) {

        DWORD bytesReturned = 0;
        BOOL ok = ReadDirectoryChangesW(
            m_hDir,
            buf,
            kWatchBufBytes,
            TRUE,           // bWatchSubtree — watch all subdirectories
            kWatchFlags,
            &bytesReturned,
            nullptr,        // no OVERLAPPED — synchronous call
            nullptr);       // no completion routine

        if (!ok) {
            // ERROR_OPERATION_ABORTED is the normal return when CancelIoEx
            // fires during Stop().  Any other error is logged.
            DWORD err = GetLastError();
            if (err != ERROR_OPERATION_ABORTED && err != ERROR_ACCESS_DENIED) {
                std::cerr << "[UsbWatcher] ReadDirectoryChangesW error "
                    << err << " on '" << m_mountPoint << "'\n";
            }
            break;
        }

        if (bytesReturned == 0) {
            // Buffer overflow — too many events arrived at once.
            // Log a warning and continue; we don't want to crash the session.
            std::cerr << "[UsbWatcher] Buffer overflow on '"
                << m_mountPoint << "' — some events dropped\n";
            continue;
        }

        // Walk the linked list of FILE_NOTIFY_INFORMATION records.
        const char* ptr = buf;
        for (;;) {
            const auto* fni =
                reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(ptr);

            const char* op = ActionToOperation(fni->Action);
            if (op != nullptr) {

                // Convert the wide filename to UTF-8.
                // FileName is NOT null-terminated — use FileNameLength (bytes).
                int wLen = static_cast<int>(fni->FileNameLength / sizeof(WCHAR));
                int u8Len = WideCharToMultiByte(
                    CP_UTF8, 0,
                    fni->FileName, wLen,
                    nullptr, 0, nullptr, nullptr);

                if (u8Len > 0) {
                    std::string relName(static_cast<size_t>(u8Len), '\0');
                    WideCharToMultiByte(
                        CP_UTF8, 0,
                        fni->FileName, wLen,
                        &relName[0], u8Len, nullptr, nullptr);

                    // Build the full path for the session record.
                    std::string fullPath = m_mountPoint + relName;

                    // Get file size — best-effort, silently zero on failure.
                    uint64_t fileSize = 0;
                    if (fni->Action == FILE_ACTION_ADDED ||
                        fni->Action == FILE_ACTION_MODIFIED)
                    {
                        WIN32_FILE_ATTRIBUTE_DATA fa{};
                        if (GetFileAttributesExA(fullPath.c_str(),
                            GetFileExInfoStandard, &fa))
                        {
                            fileSize =
                                (static_cast<uint64_t>(fa.nFileSizeHigh) << 32)
                                | static_cast<uint64_t>(fa.nFileSizeLow);
                        }
                    }

                    // Forward to the monitor — fully thread-safe.
                    m_monitor->OnFileEvent(m_serial, op, fullPath, fileSize);
                }
            }

            if (fni->NextEntryOffset == 0) break;
            ptr += fni->NextEntryOffset;
        }
    }
}