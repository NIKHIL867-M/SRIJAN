#pragma once
#include "titan_pch.h"
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

class AppLogMonitor;

struct ChannelSubscription {
    std::wstring channel;
    std::wstring xpath;
    EVT_HANDLE   handle{ nullptr };
};

class AppLogEventSubscriber {
public:
    explicit AppLogEventSubscriber(AppLogMonitor* monitor);
    ~AppLogEventSubscriber();

    bool Start();
    void Stop();
    void EnableFallbackMode(bool enable);   // kept for compile compat, now no-op

private:
    bool SubscribeToChannel(ChannelSubscription& sub);
    void UnsubscribeAll();

    static DWORD WINAPI StaticEventCallback(
        EVT_SUBSCRIBE_NOTIFY_ACTION action,
        PVOID                       context,
        EVT_HANDLE                  hEvent);

    void HandleEvent(EVT_HANDLE hEvent, const std::wstring& channel);
    void ParseSecurityEvent(EVT_HANDLE hEvent, DWORD eventId);
    void ParseDefenderEvent(EVT_HANDLE hEvent);
    void ParsePowerShellEvent(EVT_HANDLE hEvent);   // renamed from PowerShellFallback
    void ParseWmiEvent(EVT_HANDLE hEvent);   // renamed from WmiFallback
    void ParseGenericEvent(EVT_HANDLE hEvent,
        const std::wstring& channel,
        DWORD eventId);

    std::wstring GetEventChannel(EVT_HANDLE hEvent) const;
    std::wstring GetEventProperty(EVT_HANDLE hEvent, DWORD index) const;
    std::string  RenderEventXml(EVT_HANDLE hEvent) const;
    static std::string NowTimestamp();

    AppLogMonitor* m_monitor;
    std::atomic<bool>                m_running{ false };
    bool                             m_fallbackMode{ false };
    std::vector<ChannelSubscription> m_subscriptions;

    static const std::vector<std::pair<std::wstring, std::wstring>>
        DEFAULT_CHANNELS;
    static const std::vector<std::pair<std::wstring, std::wstring>>
        FALLBACK_CHANNELS;
};