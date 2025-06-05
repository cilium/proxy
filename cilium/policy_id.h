#pragma once

#include <cstdint>

namespace Envoy {
namespace Cilium {

enum ID : uint64_t {
  Unknown = 0,
  Host = 1,
  World = 2,
  Unmanaged = 3,
  Health = 4,
  Init = 5,
  RemoteNode = 6,
  KubeApiServer = 7,
  Ingress = 8,
  WorldIPv4 = 9,
  WorldIPv6 = 10,
  EncryptedOverlay = 11,

  // LocalIdentityFlag is the bit in the numeric identity that identifies
  // a numeric identity to have local scope
  LocalIdentityFlag = 1 << 24,
};

} // namespace Cilium
} // namespace Envoy
