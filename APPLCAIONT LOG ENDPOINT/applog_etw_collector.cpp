#include "titan_pch.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include "applog_etw_collector.h"
#include "applog_monitor.h"
#include "applog_watchlist.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

static thread_local AppLogEtwCollector* g_activeCollector = nullptr;

AppLogEtwCollector::AppLogEtwCollector(AppLogMonitor* monitor,
    AppLogWatchlist* watchlist)
    : m_monitor(monitor), m_watchlist(watchlist) {
}

AppLogEtwCollector::~AppLogEtwCollector() { Stop(); }

bool AppLogEtwCollector::Start() {
    if (m_running.load()) return true;
    if (!StartEtwSession()) {
        std::cerr << "[EtwCollector] Failed to start ETW session.\n";
        return false;
    }
    if (!EnableProviders()) {
        std::cerr << "[EtwCollector] Failed to enable providers.\n";
        return false;
    }
    m_running.store(true);
    m_processingThread = std::thread([this]() { this->ProcessingThreadFunc(); });
    std::cout << "[EtwCollector] ETW session started.\n";
    return true;
}

void AppLogEtwCollector::Stop() {
    if (!m_running.load()) return;
    m_running.store(false);
    if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (m_processingThread.joinable())
        m_processingThread.join();
    if (m_sessionHandle != INVALID_PROCESSTRACE_HANDLE) {
        const size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES)
            + sizeof(SESSION_NAME) + sizeof(wchar_t);
        std::vector<BYTE> buf(bufSize, 0);
        EVENT_TRACE_PROPERTIES* props =
            reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
        props->Wnode.BufferSize = static_cast<ULONG>(bufSize);
        ControlTrace(m_sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    std::cout << "[EtwCollector] Stopped.\n";
}

bool AppLogEtwCollector::StartEtwSession() {
    const size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES)
        + sizeof(SESSION_NAME) + sizeof(wchar_t);
    std::vector<BYTE> buf(bufSize, 0);
    EVENT_TRACE_PROPERTIES* props =
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    props->Wnode.BufferSize = static_cast<ULONG>(bufSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ULONG status = StartTraceW(&m_sessionHandle, SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTrace(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        ZeroMemory(buf.data(), bufSize);
        props->Wnode.BufferSize = static_cast<ULONG>(bufSize);
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->BufferSize = 64;
        props->MinimumBuffers = 4;
        props->MaximumBuffers = 16;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        status = StartTraceW(&m_sessionHandle, SESSION_NAME, props);
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "[EtwCollector] StartTrace failed: " << status << "\n";
        return false;
    }
    return true;
}

bool AppLogEtwCollector::EnableProviders() {
    ULONG status = EnableTraceEx2(
        m_sessionHandle, &POWERSHELL_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[EtwCollector] PowerShell provider failed: " << status << "\n";
        return false;
    }
    EnableTraceEx2(
        m_sessionHandle, &WMI_ACTIVITY_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    return true;
}

void AppLogEtwCollector::ProcessingThreadFunc() {
    g_activeCollector = this;
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = StaticEventCallback;
    m_traceHandle = OpenTraceW(&logfile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[EtwCollector] OpenTrace failed: " << GetLastError() << "\n";
        return;
    }
    ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
}

VOID WINAPI AppLogEtwCollector::StaticEventCallback(PEVENT_RECORD pEvent) {
    if (g_activeCollector)
        g_activeCollector->HandleEvent(pEvent);
}

void AppLogEtwCollector::HandleEvent(PEVENT_RECORD pEvent) {
    if (!pEvent) return;
    const GUID& g = pEvent->EventHeader.ProviderId;
    if (IsEqualGUID(g, POWERSHELL_PROVIDER_GUID))
        HandlePowerShellEvent(pEvent);
    else if (IsEqualGUID(g, WMI_ACTIVITY_PROVIDER_GUID))
        HandleWmiEvent(pEvent);
    else if (IsPIDWatched(pEvent->EventHeader.ProcessId))
        HandleWatchlistEvent(pEvent);
}

// =============================================================================
// TDH property extractor
// PowerShell ETW payloads are BINARY — not XML.
// TDH decodes them into named properties like ScriptBlockText, Path, etc.
// =============================================================================

static std::string ExtractTdhProperty(
    PEVENT_RECORD  pEvent,
    const wchar_t* propertyName)
{
    ULONG schemaSize = 0;
    TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &schemaSize);
    if (schemaSize == 0) return "";

    std::vector<BYTE> schemaBuf(schemaSize);
    PTRACE_EVENT_INFO info = reinterpret_cast<PTRACE_EVENT_INFO>(schemaBuf.data());

    if (TdhGetEventInformation(pEvent, 0, nullptr, info, &schemaSize) != ERROR_SUCCESS)
        return "";

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        const wchar_t* name = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);

        if (wcscmp(name, propertyName) != 0) continue;

        PROPERTY_DATA_DESCRIPTOR desc{};
        desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
        desc.ArrayIndex = ULONG_MAX;

        ULONG valueSize = 0;
        if (TdhGetPropertySize(pEvent, 0, nullptr, 1, &desc, &valueSize) != ERROR_SUCCESS)
            return "";
        if (valueSize == 0) return "";

        std::vector<BYTE> valueBuf(valueSize + sizeof(wchar_t), 0);
        if (TdhGetProperty(pEvent, 0, nullptr, 1, &desc,
            valueSize, valueBuf.data()) != ERROR_SUCCESS)
            return "";

        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(valueBuf.data());
        std::string result;
        result.reserve(valueSize);
        for (size_t j = 0; wstr[j] != L'\0'; ++j) {
            wchar_t wc = wstr[j];
            if (wc < 0x80) { result += static_cast<char>(wc); }
            else if (wc < 0x800) {
                result += static_cast<char>(0xC0 | (wc >> 6));
                result += static_cast<char>(0x80 | (wc & 0x3F));
            }
            else {
                result += static_cast<char>(0xE0 | (wc >> 12));
                result += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (wc & 0x3F));
            }
        }
        return result;
    }
    return "";
}

// Builds XML that matches what AppLogDecoder::ExtractXmlData expects
static std::string BuildPowerShellXml(PEVENT_RECORD pEvent, DWORD pid)
{
    std::string scriptText = ExtractTdhProperty(pEvent, L"ScriptBlockText");
    std::string scriptPath = ExtractTdhProperty(pEvent, L"Path");
    std::string msgNumber = ExtractTdhProperty(pEvent, L"MessageNumber");
    std::string msgTotal = ExtractTdhProperty(pEvent, L"MessageTotal");

    std::ostringstream xml;
    xml << "<Event><s>"
        << "<EventID>4104</EventID>"
        << "<ProcessID>" << pid << "</ProcessID>"
        << "</s><EventData>"
        << "<Data Name=\"MessageNumber\">" << msgNumber << "</Data>"
        << "<Data Name=\"MessageTotal\">" << msgTotal << "</Data>"
        << "<Data Name=\"ScriptBlockText\">" << scriptText << "</Data>"
        << "<Data Name=\"Path\">" << scriptPath << "</Data>"
        << "</EventData></Event>";
    return xml.str();
}

static std::string BuildWmiXml(PEVENT_RECORD pEvent, DWORD pid)
{
    std::string consumer = ExtractTdhProperty(pEvent, L"CONSUMER");
    std::string filter = ExtractTdhProperty(pEvent, L"FILTER");
    std::string operation = ExtractTdhProperty(pEvent, L"Operation");
    std::string query = ExtractTdhProperty(pEvent, L"Query");
    if (consumer.empty())  consumer = ExtractTdhProperty(pEvent, L"ConsumerName");
    if (filter.empty())    filter = ExtractTdhProperty(pEvent, L"FilterName");
    if (operation.empty()) operation = ExtractTdhProperty(pEvent, L"OperationName");

    std::ostringstream xml;
    xml << "<Event><s>"
        << "<EventID>" << pEvent->EventHeader.EventDescriptor.Id << "</EventID>"
        << "<ProcessID>" << pid << "</ProcessID>"
        << "</s><EventData>"
        << "<Data Name=\"CONSUMER\">" << consumer << "</Data>"
        << "<Data Name=\"FILTER\">" << filter << "</Data>"
        << "<Data Name=\"Operation\">" << operation << "</Data>"
        << "<Data Name=\"Query\">" << query << "</Data>"
        << "</EventData></Event>";
    return xml.str();
}

void AppLogEtwCollector::HandlePowerShellEvent(PEVENT_RECORD pEvent) {
    if (pEvent->EventHeader.EventDescriptor.Id != 4104) return;
    AppLogEvent evt;
    evt.source = "PowerShell";
    evt.event_id = "4104";
    evt.timestamp = TimestampFromFiletime(pEvent->EventHeader.TimeStamp);
    evt.raw_data = BuildPowerShellXml(pEvent, pEvent->EventHeader.ProcessId);
    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEtwCollector::HandleWmiEvent(PEVENT_RECORD pEvent) {
    USHORT id = pEvent->EventHeader.EventDescriptor.Id;
    if (id != 5859 && id != 5861) return;
    AppLogEvent evt;
    evt.source = "WMI";
    evt.event_id = std::to_string(id);
    evt.timestamp = TimestampFromFiletime(pEvent->EventHeader.TimeStamp);
    evt.raw_data = BuildWmiXml(pEvent, pEvent->EventHeader.ProcessId);
    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEtwCollector::HandleWatchlistEvent(PEVENT_RECORD pEvent) {
    std::string anyText = ExtractTdhProperty(pEvent, L"Message");
    if (anyText.empty()) anyText = ExtractTdhProperty(pEvent, L"Description");

    AppLogEvent evt;
    evt.source = "Watchlist_PID_" + std::to_string(pEvent->EventHeader.ProcessId);
    evt.event_id = std::to_string(pEvent->EventHeader.EventDescriptor.Id);
    evt.timestamp = TimestampFromFiletime(pEvent->EventHeader.TimeStamp);

    std::ostringstream xml;
    xml << "<Event><EventData>"
        << "<Data Name=\"Message\">" << anyText << "</Data>"
        << "</EventData></Event>";
    evt.raw_data = xml.str();

    m_monitor->OnEventReceived(std::move(evt));
}

void AppLogEtwCollector::UpdatePIDFilter(const std::vector<DWORD>& activePIDs) {
    AcquireSRWLockExclusive(&m_pidLock);
    m_watchedPIDs.clear();
    for (size_t i = 0; i < activePIDs.size(); ++i)
        m_watchedPIDs.insert(activePIDs[i]);
    ReleaseSRWLockExclusive(&m_pidLock);
}

bool AppLogEtwCollector::IsPIDWatched(DWORD pid) const {
    AcquireSRWLockShared(&m_pidLock);
    bool found = m_watchedPIDs.count(pid) > 0;
    ReleaseSRWLockShared(&m_pidLock);
    return found;
}

std::string AppLogEtwCollector::TimestampFromFiletime(const LARGE_INTEGER& ft) {
    FILETIME   ftv{};
    SYSTEMTIME st{};
    ftv.dwLowDateTime = ft.LowPart;
    ftv.dwHighDateTime = static_cast<DWORD>(ft.HighPart);
    FileTimeToSystemTime(&ftv, &st);
    char buf[32] = { 0 };
    sprintf_s(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}