#pragma once
#include "titan_pch.h"
#include <fstream>
#include <queue>
#include <condition_variable>

class AppLogLogger {
public:
    // Singleton — one logger for the whole module
    static AppLogLogger& Instance() {
        static AppLogLogger inst;
        return inst;
    }

    // Call once at startup with the output file path
    bool Init(const std::string& filePath);
    void Shutdown();

    // Thread-safe — called from any thread
    void Write(const std::string& jsonEvent);

private:
    AppLogLogger() = default;
    ~AppLogLogger() { Shutdown(); }

    AppLogLogger(const AppLogLogger&) = delete;
    AppLogLogger& operator=(const AppLogLogger&) = delete;

    void WorkerThreadFunc();

    std::ofstream               m_file;
    std::queue<std::string>     m_queue;
    std::mutex                  m_mutex;
    std::condition_variable     m_cv;
    std::thread                 m_worker;
    std::atomic<bool>           m_running{ false };
    bool                        m_initialized{ false };
};