#pragma once

#include <cstdint>

namespace Envoy {
namespace Cilium {

enum ID : uint64_t {
  UNKNOWN = 0,
  WORLD = 2,
  // LocalIdentityFlag is the bit in the numeric identity that identifies
  // a numeric identity to have local scope
  LocalIdentityFlag = 1 << 24,
};

} // namespace Cilium
} // namespace Envoy
