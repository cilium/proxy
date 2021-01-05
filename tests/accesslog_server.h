#pragma once

#include <atomic>
#include <string>

#include "common/common/logger.h"
#include "common/common/thread.h"

namespace Envoy {

class AccessLogServer : Logger::Loggable<Logger::Id::router> {
public:
  AccessLogServer(const std::string path);
  ~AccessLogServer();

private:
  void Close();
  void threadRoutine();

  const std::string path_;
  std::atomic<int> fd_;
  std::atomic<int> fd2_;
  Thread::ThreadPtr thread_;
};

}
