#include "tests/uds_server.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

#include "source/common/common/lock_guard.h"
#include "source/common/common/utility.h"

#include "test/test_common/thread_factory_for_test.h"

namespace Envoy {

UDSServer::UDSServer(const std::string& path, std::function<void(const std::string&)> cb)
    : msg_cb_(cb), addr_(path), fd2_(-1) {
  ENVOY_LOG(trace, "Creating unix domain socket server: {}", addr_.asStringView());
  if (!addr_.pipe()->abstractNamespace()) {
    ::unlink(addr_.asString().c_str());
  }
  fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ == -1) {
    ENVOY_LOG(error, "Can't create socket: {}", Envoy::errorDetails(errno));
    return;
  }

  ENVOY_LOG(trace, "Binding to {}", addr_.asStringView());
  if (::bind(fd_, addr_.sockAddr(), addr_.sockAddrLen()) == -1) {
    ENVOY_LOG(warn, "Bind to {} failed: {}", addr_.asStringView(), Envoy::errorDetails(errno));
    Close();
    return;
  }

  ENVOY_LOG(trace, "Listening on {}", addr_.asStringView());
  if (::listen(fd_, 5) == -1) {
    ENVOY_LOG(warn, "Listen on {} failed: {}", addr_.asStringView(), Envoy::errorDetails(errno));
    Close();
    return;
  }

  ENVOY_LOG(trace, "Starting unix domain socket server thread fd: {}", fd_);

  thread_ = Thread::threadFactoryForTest().createThread([this]() { threadRoutine(); });
}

UDSServer::~UDSServer() {
  if (fd_ >= 0) {
    Close();
    ENVOY_LOG(trace, "Waiting on unix domain socket server to close: {}",
              Envoy::errorDetails(errno));
    thread_->join();
    thread_.reset();
  }
}

void UDSServer::Close() {
  ::shutdown(fd_, SHUT_RD);
  ::shutdown(fd2_, SHUT_RD);
  errno = 0;
  ::close(fd_);
  fd_ = -1;
  if (!addr_.pipe()->abstractNamespace()) {
    ::unlink(addr_.asString().c_str());
  }
}

void UDSServer::threadRoutine() {
  while (fd_ >= 0) {
    ENVOY_LOG(debug, "Unix domain socket server thread started on fd: {}", fd_);
    // Accept a new connection
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    ENVOY_LOG(trace, "Unix domain socket server blocking accept on fd: {}", fd_);
    fd2_ = ::accept(fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len);
    if (fd2_ < 0) {
      if (errno == EINVAL) {
        return; // fd_ was closed
      }
      ENVOY_LOG(warn, "Unix domain socket server accept on fd {} failed: {}", fd_,
                Envoy::errorDetails(errno));
      continue;
    }
    char buf[8192];
    while (true) {
      ENVOY_LOG(trace, "Unix domain socket server blocking recv on fd: {}", fd2_);
      ssize_t received = ::recv(fd2_, buf, sizeof(buf), 0);
      if (received < 0) {
        if (errno == EINTR)
          continue;
        ENVOY_LOG(warn, "Unix domain socket server recv on fd {} failed: {}", fd2_,
                  Envoy::errorDetails(errno));
        break;
      } else if (received == 0) {
        ENVOY_LOG(trace, "Unix domain socket server client on fd {} has closed socket", fd2_);
        break;
      } else {
        std::string data(buf, received);
        if (msg_cb_) {
          msg_cb_(data);
        }
      }
    }
    ::close(fd2_);
    fd2_ = -1;
  }
}

} // namespace Envoy
