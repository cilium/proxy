#include "cilium/socket_option_ip_transparent.h"

#include <netinet/in.h>

#include <cerrno>
#include <cstdint>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"

#include "cilium/privileged_service_client.h"

namespace Envoy {
namespace Cilium {

IpTransparentSocketOption::IpTransparentSocketOption() {
  ENVOY_LOG(debug, "Cilium IpTransparentSocketOption()");
}

bool IpTransparentSocketOption::setOption(
    Network::Socket& socket, envoy::config::core::v3::SocketOption::SocketState state) const {
  // Only set the option once per socket
  if (state != envoy::config::core::v3::SocketOption::STATE_PREBIND) {
    ENVOY_LOG(trace, "Skipping setting socket ({}) option IP_TRANSPARENT, state != STATE_PREBIND",
              socket.ioHandle().fdDoNotUse());
    return true;
  }

  auto& cilium_calls = PrivilegedService::Singleton::get();

  auto ip_version = socket.ipVersion();
  if (!ip_version.has_value()) {
    ENVOY_LOG(critical, "Socket address family is not available, can not choose source address");
    return false;
  }

  uint32_t one = 1;

  // Set ip transparent option based on the socket address family
  auto ip_socket_level = SOL_IP;
  auto ip_transparent_socket_option = IP_TRANSPARENT;
  auto ip_transparent_socket_option_name = "IP_TRANSPARENT";
  if (*ip_version == Network::Address::IpVersion::v6) {
    ip_socket_level = SOL_IPV6;
    ip_transparent_socket_option = IPV6_TRANSPARENT;
    ip_transparent_socket_option_name = "IPV6_TRANSPARENT";
  }

  auto status = cilium_calls.setsockopt(socket.ioHandle().fdDoNotUse(), ip_socket_level,
                                        ip_transparent_socket_option, &one, sizeof(one));
  if (status.return_value_ < 0) {
    if (status.errno_ == EPERM) {
      // Do not assert out in this case so that we can run tests without
      // CAP_NET_ADMIN.
      ENVOY_LOG(critical,
                "Failed to set socket option {}, capability "
                "CAP_NET_ADMIN needed: {}",
                ip_transparent_socket_option_name, Envoy::errorDetails(status.errno_));
    } else {
      ENVOY_LOG(critical, "Socket option failure. Failed to set {}: {}",
                ip_transparent_socket_option_name, Envoy::errorDetails(status.errno_));
      return false;
    }
  }

  ENVOY_LOG(trace, "Successfully set socket option {} on socket: {}",
            ip_transparent_socket_option_name, socket.ioHandle().fdDoNotUse());

  return true;
}

} // namespace Cilium
} // namespace Envoy
