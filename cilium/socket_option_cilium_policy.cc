#include "cilium/socket_option_cilium_policy.h"

#include <asm-generic/socket.h>
#include <netinet/in.h>

#include <cerrno>
#include <string>

#include "source/common/common/macros.h"

namespace Envoy {
namespace Cilium {

const std::string& Envoy::Cilium::CiliumPolicySocketOption::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "cilium.policy");
}

} // namespace Cilium
} // namespace Envoy
