#include "cilium/uds_client.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "envoy/common/exception.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/utility.h"

namespace Envoy {
namespace Cilium {

UDSClient::UDSClient(const std::string& path, TimeSource& time_source)
    : addr_(THROW_OR_RETURN_VALUE(Network::Address::PipeInstance::create(path),
                                  std::unique_ptr<Network::Address::PipeInstance>)),
      fd_(-1), errno_(0), logging_limiter_(std::make_unique<TokenBucketImpl>(10, time_source)) {
  if (path.length() == 0) {
    throw EnvoyException(fmt::format("cilium: Invalid Unix domain socket path: {}", path));
  }

  fd_ = -1;
  errno_ = 0;
  logging_limiter_ = std::make_unique<TokenBucketImpl>(10, time_source);
}

UDSClient::~UDSClient() {
  fd_mutex_.lock();
  if (fd_ != -1) {
    ::close(fd_);
    fd_ = -1;
  }
  fd_mutex_.unlock();
}

void UDSClient::Log(const std::string& msg) {
  {
    int tries = 2;
    ssize_t length = msg.length();

    Thread::LockGuard guard(fd_mutex_);
    while (tries-- > 0) {
      if (!try_connect())
        continue; // retry

      ssize_t sent = ::send(fd_, msg.data(), length, MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL);
      if (sent == -1) {
        errno_ = errno;
        continue;
      }

      if (sent < length) {
        ENVOY_LOG(debug, "Cilium access log send truncated by {} bytes.", length - sent);
      }
      return;
    }
  }

  // rate-limit to 1/second to avoid spamming the logs
  if (logging_limiter_->consume(1, false)) {
    ENVOY_LOG(warn, "Logging to {} failed: {}", asStringView(), Envoy::errorDetails(errno_));
  }
}

bool UDSClient::try_connect() {
  if (fd_ != -1) {
    if (errno_ == 0) {
      return true;
    }
    ENVOY_LOG(debug, "Cilium access log resetting socket due to error: {}",
              Envoy::errorDetails(errno_));
    ::close(fd_);
    fd_ = -1;
  }

  errno_ = 0;
  fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ == -1) {
    errno_ = errno;
    ENVOY_LOG(error, "Can't create socket: {}", Envoy::errorDetails(errno_));
    return false;
  }

  if (::connect(fd_, addr_->sockAddr(), addr_->sockAddrLen()) == -1) {
    errno_ = errno;
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  return true;
}

} // namespace Cilium
} // namespace Envoy
