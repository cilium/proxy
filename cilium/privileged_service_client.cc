#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "cilium/privileged_service_client.h"

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

ProtocolClient::ProtocolClient()
    : Protocol(CILIUM_PRIVILEGED_SERVICE_FD), call_mutex_(PTHREAD_MUTEX_INITIALIZER), seq_(0) {
  // Check that the Envoy process isn't running with privileges.
  // The only exception is CAP_NET_BIND_SERVICE (if explicitly excluded from being dropped).
  RELEASE_ASSERT((get_capabilities(CAP_EFFECTIVE) & ~(1UL << CAP_NET_BIND_SERVICE)) == 0 &&
                     (get_capabilities(CAP_PERMITTED) & ~(1UL << CAP_NET_BIND_SERVICE)) == 0,
                 "cilium-envoy running with privileges, exiting");

  if (!check_privileged_service()) {
    // No Cilium privileged service detected
    close();
  }

  // Validate that direct SO_MARK is now prohibited
  int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
  RELEASE_ASSERT(sockfd >= 0, "socket failed");

  uint32_t mark = 12345;
  int rc = ::setsockopt(sockfd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
  RELEASE_ASSERT(rc == -1, "setsockopt");
  RELEASE_ASSERT(errno == EPERM, "setsockopt");

  ::close(sockfd);
}

ssize_t ProtocolClient::transact(MessageHeader& req, size_t req_len, const void* data,
                                 size_t data_len, int* fd, Response& resp, void* buf,
                                 size_t bufsize, bool assert) {
  uint32_t expected_response_type = resp.hdr_.msg_type_;

  // Serialize calls to cilium privileged service
  int rc = pthread_mutex_lock(&call_mutex_);
  RELEASE_ASSERT(rc == 0, "pthread_mutex_lock");

  req.msg_seq_ = ++seq_;
  ssize_t size = send_fd_msg(&req, req_len, data, data_len, *fd);
  if (!assert && size_t(size) != req_len + data_len) {
    goto out;
  }
  RELEASE_ASSERT(size != 0, "Cilium privileged service closed pipe");
  RELEASE_ASSERT(size > 0, "Cilium privileged service send failed");

  size = recv_fd_msg(&resp, sizeof(resp), buf, bufsize, fd);
  if (!assert && size_t(size) < sizeof(resp)) {
    goto out;
  }
  RELEASE_ASSERT(size != 0, "Cilium privileged service closed pipe");
  RELEASE_ASSERT(size < 0 || size_t(size) >= sizeof(resp),
                 "Cilium privileged service truncated response");
  RELEASE_ASSERT(resp.hdr_.msg_seq_ == req.msg_seq_,
                 "Cilium privileged service response out of sequence");
  RELEASE_ASSERT(resp.hdr_.msg_type_ == expected_response_type,
                 "Cilium privileged service unexpected response type");

out:
  rc = pthread_mutex_unlock(&call_mutex_);
  RELEASE_ASSERT(rc == 0, "pthread_mutex_unlock");
  return size;
}

bool ProtocolClient::check_privileged_service() {
  // Dump the effective capabilities of the privileged service process
  DumpRequest req;
  Response resp;
  uint8_t buf[1024];
  int fd = -1;
  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &fd, resp, buf, sizeof(buf), false);
  if (size < ssize_t(sizeof(resp))) {
    return false;
  }
  std::string str(reinterpret_cast<char*>(buf), size - sizeof(resp));
  ENVOY_LOG_MISC(debug, "Cilium privileged service detected with following capabilities: {}", str);
  return true;
}

Envoy::Api::SysCallIntResult ProtocolClient::bpf_open(const char* path) {
  if (!have_cilium_privileged_service()) {
    return {-1, EPERM};
  }

  BpfOpenRequest req;
  Response resp;
  size_t path_len = strlen(path);
  RELEASE_ASSERT(path_len <= PATH_MAX, "bpf open path too long");
  int fd = -1;
  ssize_t size = transact(req.hdr_, sizeof(req), path, path_len, &fd, resp);
  RELEASE_ASSERT(size == ssize_t(sizeof(resp)), "invalid received response size");
  if (resp.return_value_ == INT_MAX) {
    resp.return_value_ = fd;
  }
  return Envoy::Api::SysCallIntResult{resp.return_value_, resp.errno_};
}

Envoy::Api::SysCallIntResult ProtocolClient::bpf_lookup(int fd, const void* key, uint32_t key_size,
                                                        void* value, uint32_t value_size) {
  if (!have_cilium_privileged_service()) {
    return {-1, EPERM};
  }

  BpfLookupRequest req(value_size);
  Response resp;
  ssize_t size = transact(req.hdr_, sizeof(req), key, key_size, &fd, resp, value, value_size);
  RELEASE_ASSERT((size == ssize_t(sizeof(resp)) && resp.return_value_ == -1) ||
                     size == ssize_t(sizeof(resp) + value_size),
                 "invalid received bpf lookup value size");
  return Envoy::Api::SysCallIntResult{resp.return_value_, resp.errno_};
}

Envoy::Api::SysCallIntResult ProtocolClient::setsockopt(int sockfd, int level, int optname,
                                                        const void* optval, socklen_t optlen) {
  if (!have_cilium_privileged_service()) {
    return {-1, EPERM};
  }

  SetSockOptRequest req(level, optname, optval, optlen);
  Response resp;
  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &sockfd, resp);
  RELEASE_ASSERT(size == ssize_t(sizeof(resp)), "invalid received response size");
  return Envoy::Api::SysCallIntResult{resp.return_value_, resp.errno_};
}

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
