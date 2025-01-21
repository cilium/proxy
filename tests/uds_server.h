#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include "envoy/thread/thread.h"

#include "source/common/common/logger.h"
#include "source/common/network/address_impl.h"

namespace Envoy {

class UDSServer : public Logger::Loggable<Logger::Id::router> {
public:
  UDSServer(const std::string& path, std::function<void(const std::string&)> cb);
  ~UDSServer();

private:
  void Close();
  void threadRoutine();

  std::function<void(const std::string&)> msg_cb_;
  std::shared_ptr<Network::Address::PipeInstance> addr_;
  std::atomic<int> fd_;
  std::atomic<int> fd2_;
  Thread::ThreadPtr thread_;
};

} // namespace Envoy
