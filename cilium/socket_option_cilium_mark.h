#pragma once

#include <asm-generic/socket.h>
#include <netinet/in.h>

#include <cerrno>
#include <cstdint>
#include <vector>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"

#include "absl/types/optional.h"
#include "cilium/privileged_service_client.h"

namespace Envoy {
namespace Cilium {

// Socket Option that sets the socket option SO_MARK on the socket.
// The mark contains the Cilium magic mark, cluster and security identity.
// It uses the Cilium Privileged Service to call out to the starter process to do the actual
// privileged syscall - as the Envoy process itself doesn't have the required capabilities.
class CiliumMarkSocketOption : public Network::Socket::Option,
                               public Logger::Loggable<Logger::Id::filter> {
public:
  CiliumMarkSocketOption(uint32_t mark) : mark_(mark) {
    ENVOY_LOG(debug,
              "Cilium CiliumMarkSocketOption(): mark: {:x} (magic mark: {:x}, cluster: {}, ID: {})",
              mark_, mark & 0xff00, mark & 0xff, mark >> 16);
  }

  absl::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&,
                   envoy::config::core::v3::SocketOption::SocketState) const override {
    return absl::nullopt;
  }

  bool setOption(Network::Socket& socket,
                 envoy::config::core::v3::SocketOption::SocketState state) const override {
    // Only set the option once per socket
    if (state != envoy::config::core::v3::SocketOption::STATE_PREBIND) {
      ENVOY_LOG(trace, "Skipping setting socket ({}) option SO_MARK, state != STATE_PREBIND",
                socket.ioHandle().fdDoNotUse());
      return true;
    }

    auto& cilium_calls = PrivilegedService::Singleton::get();
    auto status = cilium_calls.setsockopt(socket.ioHandle().fdDoNotUse(), SOL_SOCKET, SO_MARK,
                                          &mark_, sizeof(mark_));
    if (status.return_value_ < 0) {
      if (status.errno_ == EPERM) {
        // Do not assert out in this case so that we can run tests without
        // CAP_NET_ADMIN.
        ENVOY_LOG(critical,
                  "Failed to set socket option SO_MARK to {}, capability "
                  "CAP_NET_ADMIN needed: {}",
                  mark_, Envoy::errorDetails(status.errno_));
      } else {
        ENVOY_LOG(critical, "Socket option failure. Failed to set SO_MARK to {}: {}", mark_,
                  Envoy::errorDetails(status.errno_));
        return false;
      }
    }

    ENVOY_LOG(trace,
              "Set socket ({}) option SO_MARK to {:x} (magic mark: {:x}, id: "
              "{}, cluster: {})",
              socket.ioHandle().fdDoNotUse(), mark_, mark_ & 0xff00, mark_ >> 16, mark_ & 0xff);

    return true;
  }

  void hashKey([[maybe_unused]] std::vector<uint8_t>& key) const override {}

  bool isSupported() const override { return true; }

  uint32_t mark_;
};

} // namespace Cilium
} // namespace Envoy
