#pragma once

#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include <limits.h>

#include "starter/privileged_service_protocol.h"

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

// ProtocolServer implements the privileged service server.
class ProtocolServer : public Protocol {
public:
  ProtocolServer(int pid, int pipe);
  ~ProtocolServer();

  void serve();

private:
  // receive buffer type
  union Buffer {
    MessageHeader hdr;
    DumpRequest dump_req;
    BpfOpenRequest bpf_open_req;
    BpfLookupRequest bpf_lookup_req;
    SetSockOptRequest setsockopt_req;
      
    // resposes use the same buffer, so they inherit the message sequence number from the request
    Response response;

    // make space for the largest possible request
    char buf[sizeof(BpfOpenRequest) + PATH_MAX + 1];
  };

  int pid_;  // child pid
};

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
