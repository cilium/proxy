#pragma once

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"

#include "test/test_common/utility.h"

#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "cilium/api/accesslog.pb.h"

namespace Envoy {

class AccessLogServer : Logger::Loggable<Logger::Id::router> {
public:
  AccessLogServer(const std::string path);
  ~AccessLogServer();

  void clear();
  absl::optional<::cilium::LogEntry>
  waitForMessage(::cilium::EntryType entry_type,
                 std::chrono::milliseconds timeout = TestUtility::DefaultTimeout);

  template <typename P>
  bool expectRequestTo(P&& pred, std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    auto maybe_entry = waitForMessage(::cilium::EntryType::Request, timeout);
    if (maybe_entry.has_value())
      return pred(maybe_entry.value());
    return false;
  }

  template <typename P>
  bool expectResponseTo(P&& pred, std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    auto maybe_entry = waitForMessage(::cilium::EntryType::Response, timeout);
    if (maybe_entry.has_value())
      return pred(maybe_entry.value());
    return false;
  }

  template <typename P>
  bool expectDeniedTo(P&& pred, std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    auto maybe_entry = waitForMessage(::cilium::EntryType::Denied, timeout);
    if (maybe_entry.has_value())
      return pred(maybe_entry.value());
    return false;
  }

private:
  void Close();
  void threadRoutine();

  const std::string path_;
  std::atomic<int> fd_;
  std::atomic<int> fd2_;
  Thread::ThreadPtr thread_;

  absl::Mutex mutex_;
  std::vector<::cilium::LogEntry> messages_ ABSL_GUARDED_BY(mutex_);
};

} // namespace Envoy
