#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "cilium/envoy_wrapper.h"

namespace CiliumEnvoyWrapper {

WrapperProtocolClient::WrapperProtocolClient() :
  WrapperProtocol(CILIUM_ENVOY_WRAPPER_FD),
  call_mutex_(PTHREAD_MUTEX_INITIALIZER),
  seq_(0) {
  RELEASE_ASSERT(get_capabilities(CAP_EFFECTIVE) == 0 && get_capabilities(CAP_PERMITTED) == 0,
		 "cilium-envoy running with privileges, exiting");

  if (!check_wrapper()) {
    // Running without Cilium Envoy wrapper
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

ssize_t WrapperProtocolClient::transact(MessageHeader& req, size_t req_len, const void *data, size_t data_len, int *fd, Response& resp, void *buf, size_t bufsize, bool assert) {
  uint32_t expected_response_type = resp.hdr_.msg_type_;

  // Serialize calls to cilium wrapper
  int rc = pthread_mutex_lock(&call_mutex_);
  RELEASE_ASSERT(rc == 0, "pthread_mutex_lock");

  req.msg_seq_ = ++seq_;
  ssize_t size = send_fd_msg(&req, req_len, data, data_len, *fd);
  if (!assert && size_t(size) != req_len + data_len) {
    goto out;
  }
  RELEASE_ASSERT(size != 0, "Cilium wrapper closed pipe");
  RELEASE_ASSERT(size > 0, "Cilium wrapper send failed");

  size = recv_fd_msg(&resp, sizeof(resp), buf, bufsize, fd);
  if (!assert && size_t(size) < sizeof(resp)) {
    goto out;
  }
  RELEASE_ASSERT(size != 0, "Cilium wrapper closed pipe");
  RELEASE_ASSERT(size < 0 || size_t(size) >= sizeof(resp), "Cilium wrapper truncated response");
  RELEASE_ASSERT(resp.hdr_.msg_seq_ == req.msg_seq_, "Cilium wrapper response out of sequence");
  RELEASE_ASSERT(resp.hdr_.msg_type_ == expected_response_type,
		 "Cilium wrapper unexpected response type");

 out:
  rc = pthread_mutex_unlock(&call_mutex_);
  RELEASE_ASSERT(rc == 0, "pthread_mutex_unlock");
  return size;
}

bool WrapperProtocolClient::check_wrapper() {
  // Get the effective capabilities from the wrapper process
  DumpRequest req;
  Response resp;
  uint8_t buf[1024];
  int fd = -1;
  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &fd, resp, buf, sizeof(buf), false);
  if (size < ssize_t(sizeof(resp))) {
    return false;
  }
  std::string str(reinterpret_cast<char *>(buf), size - sizeof(resp));
  ENVOY_LOG_MISC(debug, "Running with Cilium wrapper with the following capabilities: {}", str);
  return true;
}

Envoy::Api::SysCallIntResult WrapperProtocolClient::bpf_open(const char *path) {
  if (!running_with_cilium_wrapper()) {
      return {-1, EPERM};
  }

  BpfOpenRequest req;
  Response resp;
  size_t path_len = strlen(path);
  RELEASE_ASSERT(path_len <= PATH_MAX, "bpf open path too long");
  int fd = -1;
  ssize_t size = transact(req.hdr_, sizeof(req), path, path_len, &fd, resp);
  RELEASE_ASSERT(size == ssize_t(sizeof(resp)), "invalid received response size");
  if (resp.ret_.return_value_ == INT_MAX) {
    resp.ret_.return_value_ = fd;
  }
  return resp.ret_;
}

Envoy::Api::SysCallIntResult WrapperProtocolClient::bpf_lookup(int fd, const void *key,
							       uint32_t key_size, void* value,
							       uint32_t value_size) {
  if (!running_with_cilium_wrapper()) {
      return {-1, EPERM};
  }

  BpfLookupRequest req(value_size);
  Response resp;
  ssize_t size = transact(req.hdr_, sizeof(req), key, key_size, &fd, resp, value, value_size);
  RELEASE_ASSERT((size == ssize_t(sizeof(resp)) && resp.ret_.return_value_ == -1)
                 || size == ssize_t(sizeof(resp) + value_size),
                 "invalid received bpf lookup value size");
  return resp.ret_;
}

Envoy::Api::SysCallIntResult WrapperProtocolClient::setsockopt(int sockfd, int level, int optname,
							       const void *optval,
							       socklen_t optlen) {
  if (!running_with_cilium_wrapper()) {
      return {-1, EPERM};
  }

  SetSockOptRequest req(level, optname, optval, optlen);
  Response resp;
  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &sockfd, resp);
  RELEASE_ASSERT(size == ssize_t(sizeof(resp)), "invalid received response size");
  return resp.ret_;
}

} // namespace CiliumEnvoyWrapper
