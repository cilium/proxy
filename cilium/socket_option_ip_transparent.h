#pragma once

#include <cstdint>
#include <vector>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace Cilium {

// Socket Option that sets the socket option IP_TRANSPARENT (IPV6_TRANSPARENT) on the socket.
// It uses the Cilium Privileged Service to call out to the starter process to do the actual
// privileged syscall - as the Envoy process itself doesn't have the required capabilities.
class IpTransparentSocketOption : public Network::Socket::Option,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  IpTransparentSocketOption();

  absl::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&,
                   envoy::config::core::v3::SocketOption::SocketState) const override {
    return absl::nullopt;
  }

  bool setOption(Network::Socket& socket,
                 envoy::config::core::v3::SocketOption::SocketState state) const override;

  void hashKey([[maybe_unused]] std::vector<uint8_t>& key) const override {}

  bool isSupported() const override { return true; }
};

} // namespace Cilium
} // namespace Envoy
