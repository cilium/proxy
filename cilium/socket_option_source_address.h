#pragma once

#include <cstdint>
#include <vector>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace Cilium {

// Socket Option that restores the local address of the socket with the relevant
// source address which is either the original source address or a configured
// source address (used for Ingress - N/S load balancing).
// In addition its hashKey implementation is also responsible to introduct Envoy
// to separate upstream connection pools per source address or source security ID.
class SourceAddressSocketOption : public Network::Socket::Option,
                                  public Logger::Loggable<Logger::Id::filter> {
public:
  SourceAddressSocketOption(
      uint32_t source_identity,
      Network::Address::InstanceConstSharedPtr original_source_address = nullptr,
      Network::Address::InstanceConstSharedPtr ipv4_source_address = nullptr,
      Network::Address::InstanceConstSharedPtr ipv6_source_address = nullptr);

  absl::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&,
                   envoy::config::core::v3::SocketOption::SocketState) const override {
    return absl::nullopt;
  }

  bool setOption(Network::Socket& socket,
                 envoy::config::core::v3::SocketOption::SocketState state) const override;

  void hashKey(std::vector<uint8_t>& key) const override;

  bool isSupported() const override { return true; }

  uint32_t source_identity_;

  Network::Address::InstanceConstSharedPtr original_source_address_;
  // Version specific source addresses are only used if original source address is not used.
  // Selection is made based on the socket domain, which is selected based on the destination
  // address. This makes sure we don't try to bind IPv4 or IPv6 source address to a socket
  // connecting to IPv6 or IPv4 address, respectively.
  Network::Address::InstanceConstSharedPtr ipv4_source_address_;
  Network::Address::InstanceConstSharedPtr ipv6_source_address_;
};

} // namespace Cilium
} // namespace Envoy
