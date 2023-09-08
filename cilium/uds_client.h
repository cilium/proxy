#pragma once

#include <map>
#include <string>

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/network/address_impl.h"

namespace Envoy {
namespace Cilium {

class UDSClient : Logger::Loggable<Logger::Id::router> {
public:
  UDSClient(const std::string& path);
  ~UDSClient();

  void Log(const std::string& msg);

  const std::string& asString() const { return addr_.asString(); }
  absl::string_view asStringView() const { return addr_.asStringView(); }

private:
  const Network::Address::PipeInstance addr_;
  bool try_connect() ABSL_EXCLUSIVE_LOCKS_REQUIRED(fd_mutex_);

  Thread::MutexBasicLockable fd_mutex_;
  int fd_ ABSL_GUARDED_BY(fd_mutex_);
  int errno_ ABSL_GUARDED_BY(fd_mutex_);
};

  
} // namespace Cilium
} // namespace Envoy
