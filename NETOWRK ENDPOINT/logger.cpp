#include "logger.h"

#include <chrono>
#include <filesystem>
#include <iostream>

namespace titan {
    namespace {
        // FIX C4244: wstring->UTF-8 string without narrowing char<-wchar_t
        static std::string WstrToUtf8Log(const std::wstring& ws) {
            if (ws.empty()) return {};
            int n = WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
            if (n <= 0) return {};
            std::string s(static_cast<size_t>(n), '\0');
            WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                static_cast<int>(ws.size()), s.data(), n, nullptr, nullptr);
            return s;
        }
    } // anonymous namespace


        // ============================================================================
        // CONSTRUCTOR / DESTRUCTOR
        // ============================================================================

    AsyncLogger::AsyncLogger(const std::wstring& log_dir) : log_dir_(log_dir) {}

    AsyncLogger::~AsyncLogger() { Shutdown(); }

    // ============================================================================
    // INITIALIZE
    // Creates the log directory, opens the first pack file, starts both threads.
    // ============================================================================

    bool AsyncLogger::Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);

        std::filesystem::create_directories(std::filesystem::path(log_dir_));

        current_pack_path_ = NewPackPath();
        pack_file_.open(std::filesystem::path(current_pack_path_),
            std::ios::out | std::ios::trunc);

        if (!pack_file_.is_open()) {
            ConsoleLogger::LogError(
                "Failed to open log pack: " +
                WstrToUtf8Log(current_pack_path_));
            return false;
        }

        running_ = true;
        worker_ = std::thread(&AsyncLogger::WorkerThread, this);
        ticker_ = std::thread(&AsyncLogger::CompressTicker, this);

        ConsoleLogger::LogInfo(
            "Logger V4 started: " +
            WstrToUtf8Log(current_pack_path_));
        return true;
    }

    // ============================================================================
    // SHUTDOWN
    // Drains the queue completely before closing — no events lost on exit.
    // ============================================================================

    void AsyncLogger::Shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_)
                return;
            running_ = false;
        }

        cv_.notify_all();

        if (worker_.joinable())
            worker_.join();
        if (ticker_.joinable())
            ticker_.join();

        if (pack_file_.is_open())
            pack_file_.close();
    }

    // ============================================================================
    // LOG EVENT  (FORWARD path)
    // Non-blocking under normal load. Applies back-pressure if queue is full
    // (waits briefly) rather than dropping the event silently.
    // ============================================================================

    void AsyncLogger::LogEvent(Event&& event) {
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // Back-pressure: wait up to 50ms if queue is at capacity.
            // This keeps the pipeline honest — no silent loss.
            if (event_queue_.size() >= kMaxQueue) {
                cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
                    return event_queue_.size() < kMaxQueue || !running_;
                    });
            }

            if (!running_)
                return;
            event_queue_.push(std::move(event));
            queued_count_.fetch_add(1, std::memory_order_relaxed);
        }
        cv_.notify_one();
    }

    // ============================================================================
    // LOG COMPRESS SUMMARY  (COMPRESS path)
    // Builds a CompressSummary into a COMPRESS event and writes it directly.
    // Called from CompressTicker — already on the ticker thread, not queued.
    // ============================================================================

    void AsyncLogger::LogCompressSummary(const CompressSummary& summary) {
        Event evt = Event::CreateCompressEvent(summary);
        std::string line = evt.CompressJson();

        std::lock_guard<std::mutex> lock(mutex_);
        WriteJsonLine(line);
        compressed_count_.fetch_add(1, std::memory_order_relaxed);
        written_count_.fetch_add(1, std::memory_order_relaxed);
    }

    // ============================================================================
    // WORKER THREAD
    // Drains event_queue_ in batches, serialises each event as a JSON line.
    // ============================================================================

    void AsyncLogger::WorkerThread() {
        std::vector<Event> batch;
        batch.reserve(128);

        while (true) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return !event_queue_.empty() || !running_; });

                if (!running_ && event_queue_.empty())
                    break;

                while (!event_queue_.empty() && batch.size() < 128) {
                    batch.push_back(std::move(event_queue_.front()));
                    event_queue_.pop();
                }
            }
            cv_.notify_all(); // unblock any back-pressured callers

            for (auto& evt : batch) {
                RotateIfNeeded();
                const bool is_compress = evt.IsV3Enriched() &&
                    evt.GetV3().decision == FilterDecision::COMPRESS;

                std::string line = evt.ToJson();

                std::lock_guard<std::mutex> lock(mutex_);
                WriteJsonLine(line);
                written_count_.fetch_add(1, std::memory_order_relaxed);

                if (is_compress)
                    compressed_count_.fetch_add(1, std::memory_order_relaxed);
                else
                    forwarded_count_.fetch_add(1, std::memory_order_relaxed);
            }

            batch.clear();
            pack_file_.flush();
        }
    }

    // ============================================================================
    // COMPRESS TICKER
    // Every 60 seconds, asks the FilterEngine to flush compress summaries and
    // writes each one to the log pack via LogCompressSummary().
    // ============================================================================

    void AsyncLogger::CompressTicker() {
        while (running_.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(kCompressWindowSec));

            if (!running_.load(std::memory_order_relaxed))
                break;
            if (!filter_)
                continue;

            auto summaries = filter_->FlushCompressSummaries();
            for (const auto& s : summaries)
                LogCompressSummary(s);
        }
    }

    // ============================================================================
    // WRITE JSON LINE
    // Writes one JSONL line (newline-delimited JSON — no wrapping array).
    // Must be called with mutex_ held.
    // ============================================================================

    void AsyncLogger::WriteJsonLine(const std::string& json) {
        pack_file_ << json << '\n';
        const uint64_t bytes_written = static_cast<uint64_t>(json.size()) + 1ULL;
        current_file_bytes_.fetch_add(bytes_written, std::memory_order_relaxed);
    }

    // ============================================================================
    // ROTATE IF NEEDED
    // Rolls to a new pack file when the current one exceeds kMaxFileBytes.
    // ============================================================================

    void AsyncLogger::RotateIfNeeded() {
        if (current_file_bytes_.load() < kMaxFileBytes)
            return;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            pack_file_.close();
            current_pack_path_ = NewPackPath();
            pack_file_.open(std::filesystem::path(current_pack_path_),
                std::ios::out | std::ios::trunc);
            current_file_bytes_.store(0);
        }

        ConsoleLogger::LogInfo(
            "Log pack rotated: " +
            WstrToUtf8Log(current_pack_path_));
    }

    // ============================================================================
    // NEW PACK PATH
    // Generates: <log_dir>\titan_YYYYMMDD_HHMMSS.jsonl
    // ============================================================================

    std::wstring AsyncLogger::NewPackPath() const {
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &tt);

        wchar_t buf[64]{};
        wcsftime(buf, std::size(buf), L"%Y%m%d_%H%M%S", &tm);

        return log_dir_ + L"titan_" + buf + L".jsonl";
    }

    // ============================================================================
    // FLUSH  —  wait until queue is empty
    // ============================================================================

    void AsyncLogger::Flush() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return event_queue_.empty(); });
    }

    // ============================================================================
    // CONSOLE LOGGER
    // ============================================================================

    void ConsoleLogger::LogInfo(const std::string& msg) {
        std::cout << "[INFO]  " << msg << '\n';
    }
    void ConsoleLogger::LogWarning(const std::string& msg) {
        std::cout << "[WARN]  " << msg << '\n';
    }
    void ConsoleLogger::LogError(const std::string& msg) {
        std::cerr << "[ERROR] " << msg << '\n';
    }

} // namespace titan