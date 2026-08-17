#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Cilium {

// Socket Option that sets the socket option SO_MARK on the socket.
// The mark contains the Cilium magic mark, cluster and security identity.
// It uses the Cilium Privileged Service to call out to the starter process to do the actual
// privileged syscall - as the Envoy process itself doesn't have the required capabilities.
class CiliumMarkSocketOption : public Network::Socket::Option,
                               public Logger::Loggable<Logger::Id::filter> {
public:
  CiliumMarkSocketOption(uint32_t mark);
  std::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&,
                   envoy::config::core::v3::SocketOption::SocketState) const override {
    return std::nullopt;
  }

  bool setOption(Network::Socket& socket,
                 envoy::config::core::v3::SocketOption::SocketState state) const override;

  void hashKey([[maybe_unused]] std::vector<uint8_t>& key) const override {}

  bool isSupported() const override { return true; }

  uint32_t mark_;
};

} // namespace Cilium
} // namespace Envoy
