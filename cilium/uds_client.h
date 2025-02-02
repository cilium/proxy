#pragma once

#include <memory>
#include <string>

#include "envoy/common/time.h"

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/common/token_bucket_impl.h"
#include "source/common/network/address_impl.h"

#include "absl/base/thread_annotations.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Cilium {

class UDSClient : Logger::Loggable<Logger::Id::router> {
public:
  UDSClient(const std::string& path, TimeSource& time_source);
  ~UDSClient();

  void log(const std::string& msg);

  const std::string& asString() const { return addr_->asString(); }
  absl::string_view asStringView() const { return addr_->asStringView(); }

private:
  bool tryConnect() ABSL_EXCLUSIVE_LOCKS_REQUIRED(fd_mutex_);

  Thread::MutexBasicLockable fd_mutex_;
  std::shared_ptr<Network::Address::PipeInstance> addr_;
  int fd_ ABSL_GUARDED_BY(fd_mutex_);
  int errno_ ABSL_GUARDED_BY(fd_mutex_);
  std::unique_ptr<TokenBucketImpl> logging_limiter_ ABSL_GUARDED_BY(fd_mutex_);
};

} // namespace Cilium
} // namespace Envoy
