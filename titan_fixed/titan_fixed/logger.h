#ifndef TITAN_LOGGER_H
#define TITAN_LOGGER_H

// ============================================================================
// logger.h  —  TITAN V3
//
// V3 changes:
//   REMOVED: dropped_count_ / drop-on-full logic — no silent event loss
//   ADDED:   LogCompressSummary()  — writes lightweight COMPRESS JSON lines
//            GetForwardedCount() / GetCompressedCount() — V3 pipeline counters
//            compress_ticker_ thread — calls
//            FilterEngine::FlushCompressSummaries() every 60 seconds and writes
//            the summaries to the log pack
//   CHANGED: Queue back-pressure instead of drop (block caller briefly if full)
//            Log files are .jsonl (newline-delimited JSON) — one event per
//            line, no wrapping array — easier for streaming parsers
// ============================================================================

#include "event.h"
#include "filter.h"

#include <atomic>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace titan {

// ============================================================================
// ASYNC LOGGER  —  V3
// Thread-safe. Single worker thread drains the queue and writes .jsonl packs.
// A second ticker thread calls FlushCompressSummaries() every 60 seconds.
// NO events are ever silently dropped — back-pressure is applied instead.
// ============================================================================

class AsyncLogger {
public:
  explicit AsyncLogger(const std::wstring &log_dir);
  ~AsyncLogger();

  AsyncLogger(const AsyncLogger &) = delete;
  AsyncLogger &operator=(const AsyncLogger &) = delete;

  // Initialise: create log directory, open first pack, start worker threads.
  bool Initialize();

  // Drain queue, close file, stop threads. Safe to call multiple times.
  void Shutdown();

  // Enqueue a FORWARD event. Thread-safe, non-blocking under normal load.
  // If the queue is at capacity, caller blocks briefly (back-pressure).
  // Events are NEVER silently dropped.
  void LogEvent(Event &&event);

  // Enqueue a pre-built COMPRESS summary (called by compress ticker).
  void LogCompressSummary(const CompressSummary &summary);

  // Wait until the queue is fully drained.
  void Flush();

  // Wire the filter so the compress ticker can call FlushCompressSummaries().
  void SetFilter(FilterEngine *filter) noexcept { filter_ = filter; }

  // V3 counters
  uint64_t GetWrittenCount() const noexcept { return written_count_.load(); }
  uint64_t GetQueuedCount() const noexcept { return queued_count_.load(); }
  uint64_t GetForwardedCount() const noexcept {
    return forwarded_count_.load();
  }
  uint64_t GetCompressedCount() const noexcept {
    return compressed_count_.load();
  }

private:
  void WorkerThread();   // drains event_queue_, writes JSON lines
  void CompressTicker(); // every 60s: flush compress summaries from filter

  void WriteJsonLine(const std::string &json);
  void RotateIfNeeded();
  std::wstring NewPackPath() const;

  // ---- state ----
  std::wstring log_dir_;
  std::wstring current_pack_path_;
  std::ofstream pack_file_;
  FilterEngine *filter_{nullptr};

  std::thread worker_;
  std::thread ticker_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::queue<Event> event_queue_;
  std::atomic<bool> running_{false};

  // V3 counters
  std::atomic<uint64_t> queued_count_{0};
  std::atomic<uint64_t> written_count_{0};
  std::atomic<uint64_t> forwarded_count_{0};
  std::atomic<uint64_t> compressed_count_{0};
  std::atomic<uint64_t> current_file_bytes_{0};

  // Config
  static constexpr size_t kMaxQueue = 10'000; // back-pressure threshold
  static constexpr uint64_t kMaxFileBytes =
      100ULL * 1024 * 1024; // 100 MB per pack
  static constexpr uint32_t kCompressWindowSec = 60;
};

// ============================================================================
// CONSOLE LOGGER  —  lightweight, sync, for status/debug output only
// ============================================================================

class ConsoleLogger {
public:
  static void LogInfo(const std::string &msg);
  static void LogWarning(const std::string &msg);
  static void LogError(const std::string &msg);
};

} // namespace titan

#endif // TITAN_LOGGER_H