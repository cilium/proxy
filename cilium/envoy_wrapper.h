#pragma once

#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "cilium/envoy_wrapper_protocol.h"

#include "source/common/singleton/threadsafe_singleton.h"

namespace Envoy {
  namespace Cilium {
    class Bpf;
    class SocketMarkOption;
  }
}

namespace CiliumEnvoyWrapper {

// WrapperProtocolClient implements the client logic for communicating with the wrapper process.
class WrapperProtocolClient : public WrapperProtocol {
public:
  WrapperProtocolClient();

  // allow access to the classes that need it
  friend class Envoy::Cilium::Bpf;
  friend class Envoy::Cilium::SocketMarkOption;

protected:
  // Read-only bpf syscalls
  Envoy::Api::SysCallIntResult bpf_open(const char *path);
  Envoy::Api::SysCallIntResult bpf_lookup(int fd, const void *key, uint32_t key_size, void* value,
					  uint32_t value_size);

  // Set a socket option
  Envoy::Api::SysCallIntResult setsockopt(int sockfd, int level, int optname, const void *optval,
					  socklen_t optlen);

private:
  bool check_wrapper();
  bool running_with_cilium_wrapper() const { return is_open(); }

  ssize_t transact(MessageHeader& req, size_t req_len, const void *data, size_t datalen, int *fd, Response& resp, void *buf = nullptr, size_t bufsize = 0, bool assert = true);

  pthread_mutex_t call_mutex_;
  uint32_t seq_;
};

using CiliumCallsSingleton = Envoy::ThreadSafeSingleton<WrapperProtocolClient>;

} // namespace CiliumEnvoyWrapper
