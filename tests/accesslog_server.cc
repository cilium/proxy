#include "tests/accesslog_server.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

#include "cilium/api/accesslog.pb.h"
#include "test/test_common/thread_factory_for_test.h"

namespace Envoy {

AccessLogServer::AccessLogServer(const std::string path)
    : path_(path), fd2_(-1) {
  ENVOY_LOG(critical, "Creating access log server: {}", path_);
  ::unlink(path_.c_str());
  fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ == -1) {
    ENVOY_LOG(error, "Can't create socket: {}", strerror(errno));
    return;
  }

  ENVOY_LOG(critical, "Binding to {}", path_);
  struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = {}};
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) ==
      -1) {
    ENVOY_LOG(warn, "Bind to {} failed: {}", path_, strerror(errno));
    Close();
    return;
  }

  ENVOY_LOG(critical, "Listening on {}", path_);
  if (::listen(fd_, 5) == -1) {
    ENVOY_LOG(warn, "Listen on {} failed: {}", path_, strerror(errno));
    Close();
    return;
  }

  ENVOY_LOG(critical, "Starting access log server thread fd: {}", fd_);

  thread_ = Thread::threadFactoryForTest().createThread(
      [this]() { threadRoutine(); });
}

AccessLogServer::~AccessLogServer() {
  if (fd_ >= 0) {
    Close();
    ENVOY_LOG(warn, "Waiting on access log to close: {}", strerror(errno));
    thread_->join();
    thread_.reset();
  }
}

void AccessLogServer::Close() {
  ::shutdown(fd_, SHUT_RD);
  ::shutdown(fd2_, SHUT_RD);
  errno = 0;
  ::close(fd_);
  fd_ = -1;
  ::unlink(path_.c_str());
}

void AccessLogServer::threadRoutine() {
  while (fd_ >= 0) {
    ENVOY_LOG(critical, "Access Log thread started on fd: {}", fd_);
    // Accept a new connection
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    ENVOY_LOG(warn, "Access log blocking accept on fd: {}", fd_);
    fd2_ = ::accept(fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len);
    if (fd2_ < 0) {
      ENVOY_LOG(critical, "Access log accept failed: {}", strerror(errno));
    } else {
      char buf[8192];
      while (true) {
        ENVOY_LOG(warn, "Access log blocking recv on fd: {}", fd2_);
        ssize_t received = ::recv(fd2_, buf, sizeof(buf), 0);
        if (received < 0) {
          ENVOY_LOG(warn, "Access log recv failed: {}", strerror(errno));
          break;
        } else if (received == 0) {
          ENVOY_LOG(warn, "Access log recv got no data!");
          break;
        } else {
          std::string data(buf, received);
          ::cilium::LogEntry entry;
          if (!entry.ParseFromString(data)) {
            ENVOY_LOG(warn, "Access log parse failed!");
          } else {
            if (entry.method().length() > 0) {
              ENVOY_LOG(warn, "Access log deprecated format detected");
              // Deprecated format detected, map to the new one
              auto http = entry.mutable_http();
              http->set_http_protocol(entry.http_protocol());
              entry.clear_http_protocol();
              http->set_scheme(entry.scheme());
              entry.clear_scheme();
              http->set_host(entry.host());
              entry.clear_host();
              http->set_path(entry.path());
              entry.clear_path();
              http->set_method(entry.method());
              entry.clear_method();
              for (const auto& dep_hdr : entry.headers()) {
                auto hdr = http->add_headers();
                hdr->set_key(dep_hdr.key());
                hdr->set_value(dep_hdr.value());
              }
              entry.clear_headers();
              http->set_status(entry.status());
              entry.clear_status();
            }
            ENVOY_LOG(info, "Access log entry: {}", entry.DebugString());
          }
        }
      }
      ::close(fd2_);
      fd2_ = -1;
    }
  };
}

}  // namespace Envoy
