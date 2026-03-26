#pragma once

// =============================================================================
// TITAN - File Integrity Monitor
// file_etw_collector.h
//
// CHANGED vs original:
//   trace_handle_ is now std::atomic<TRACEHANDLE> (FIX 9 in the .cpp).
//   CollectorThread writes it after OpenTraceW; Stop() reads it to call
//   CloseTrace — both happen on different threads, so the atomic is required.
// =============================================================================

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <thread>
#include <string>
#include <filesystem>

#include "file_monitor.h"

namespace titan::fim
{

    // Microsoft-Windows-Kernel-File provider GUID
    // {EDD08927-9CC4-4E65-B970-C2560FB5C289}
    static const GUID KERNEL_FILE_PROVIDER_GUID = {
        0xEDD08927, 0x9CC4, 0x4E65,
        { (BYTE)0xB9, (BYTE)0x70, (BYTE)0xC2, (BYTE)0x56,
          (BYTE)0x0F, (BYTE)0xB5, (BYTE)0xC2, (BYTE)0x89 }
    };

    static const wchar_t* ETW_SESSION_NAME = L"TITAN_FIM_KernelFile";

    enum KernelFileOpcode
    {
        KFO_CREATE = 12,
        KFO_CLEANUP = 13,
        KFO_CLOSE = 14,
        KFO_READ = 15,
        KFO_WRITE = 16,
        KFO_SET_INFO = 17,
        KFO_DELETE = 18,
        KFO_RENAME = 19,
        KFO_CREATE_NEW = 30,
    };

    class FileEtwCollector
    {
    public:

        explicit FileEtwCollector(FileMonitor* monitor);
        ~FileEtwCollector();

        bool Start();
        void Stop();

        bool IsRunning() const { return running_.load(); }

    private:

        FileMonitor* monitor_;
        TRACEHANDLE       session_handle_;

        // FIX 9: atomic so CollectorThread (writer) and Stop() (reader) are
        //        race-free without additional locking.
        std::atomic<TRACEHANDLE> trace_handle_;

        std::atomic<bool> running_;
        std::thread       collector_thread_;

        bool CreateSession();
        void DestroySession();
        bool EnableProvider();
        void DisableProvider();
        void CollectorThread();

        static VOID  WINAPI EventRecordCallback(PEVENT_RECORD event_record);
        static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW logfile);

        static bool DecodeEvent(
            PEVENT_RECORD event_record,
            FileEvent& out_event
        );

        static bool GetEventPropertyString(
            PEVENT_RECORD      event_record,
            PTRACE_EVENT_INFO  info,
            const wchar_t* property_name,
            std::wstring& out_value
        );

        static bool GetEventPropertyUlonglong(
            PEVENT_RECORD      event_record,
            PTRACE_EVENT_INFO  info,
            const wchar_t* property_name,
            ULONGLONG& out_value
        );

        static FileAction OpcodeToAction(UCHAR opcode);

        // FIX 9 (original note): atomic so ETW thread reads are race-free
        static std::atomic<FileEtwCollector*> instance_;
    };

} // namespace titan::fim