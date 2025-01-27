#include "cilium/socket_option_source_address.h"

#include <cstdint>
#include <utility>
#include <vector>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"

#include "source/common/common/hex.h"
#include "source/common/common/logger.h"

#include "absl/numeric/int128.h"

namespace Envoy {
namespace Cilium {

SourceAddressSocketOption::SourceAddressSocketOption(
    uint32_t source_identity, Network::Address::InstanceConstSharedPtr original_source_address,
    Network::Address::InstanceConstSharedPtr ipv4_source_address,
    Network::Address::InstanceConstSharedPtr ipv6_source_address)
    : source_identity_(source_identity),
      original_source_address_(std::move(original_source_address)),
      ipv4_source_address_(std::move(ipv4_source_address)),
      ipv6_source_address_(std::move(ipv6_source_address)) {
  ENVOY_LOG(debug,
            "Cilium SourceAddressSocketOption(): source_identity: {}, source_addresses: {}/{}/{}",
            source_identity, original_source_address_ ? original_source_address_->asString() : "",
            ipv4_source_address_ ? ipv4_source_address_->asString() : "",
            ipv6_source_address_ ? ipv6_source_address_->asString() : "");
}

bool SourceAddressSocketOption::setOption(
    Network::Socket& socket, envoy::config::core::v3::SocketOption::SocketState state) const {
  // Only set the option once per socket
  if (state != envoy::config::core::v3::SocketOption::STATE_PREBIND) {
    ENVOY_LOG(trace, "Skipping setting socket ({}) source address, state != STATE_PREBIND",
              socket.ioHandle().fdDoNotUse());
    return true;
  }

  auto ipVersion = socket.ipVersion();
  if (!ipVersion.has_value()) {
    ENVOY_LOG(critical, "Socket address family is not available, can not choose source address");
    return false;
  }

  Network::Address::InstanceConstSharedPtr source_address = original_source_address_;
  if (!source_address && (ipv4_source_address_ || ipv6_source_address_)) {
    // Select source address based on the socket address family
    source_address = ipv6_source_address_;
    if (*ipVersion == Network::Address::IpVersion::v4) {
      source_address = ipv4_source_address_;
    }
  }

  if (!source_address) {
    ENVOY_LOG(trace, "Skipping restore of local address on socket: {} - no source address",
              socket.ioHandle().fdDoNotUse());
    return true;
  }

  // Note: Restoration of the original source address happens on the socket of the upstream
  // connection.
  ENVOY_LOG(trace, "Restoring local address (original source) on socket: {} ({} -> {})",
            socket.ioHandle().fdDoNotUse(),
            socket.connectionInfoProvider().localAddress()
                ? socket.connectionInfoProvider().localAddress()->asString()
                : "n/a",
            source_address->asString());

  socket.connectionInfoProvider().setLocalAddress(std::move(source_address));

  return true;
}

template <typename T> void addressIntoVector(std::vector<uint8_t>& vec, const T& address) {
  const uint8_t* byte_array = reinterpret_cast<const uint8_t*>(&address);
  vec.insert(vec.end(), byte_array, byte_array + sizeof(T));
}

void SourceAddressSocketOption::hashKey(std::vector<uint8_t>& key) const {
  // Source address is more specific than policy ID. If using an original
  // source address, we do not need to also add the source security ID to the
  // hash key. Note that since the identity is 3 bytes it will not collide
  // with neither an IPv4 nor IPv6 address.
  if (original_source_address_) {
    const auto& ip = original_source_address_->ip();
    uint16_t port = ip->port();
    if (ip->version() == Network::Address::IpVersion::v4) {
      uint32_t raw_address = ip->ipv4()->address();
      addressIntoVector(key, raw_address);
    } else if (ip->version() == Network::Address::IpVersion::v6) {
      absl::uint128 raw_address = ip->ipv6()->address();
      addressIntoVector(key, raw_address);
    }
    // Add source port to the hash key if defined
    if (port != 0) {
      ENVOY_LOG(trace, "hashKey port: {:x}", port);
      key.emplace_back(uint8_t(port >> 8));
      key.emplace_back(uint8_t(port));
    }
    ENVOY_LOG(trace, "hashKey after with original source address: {}, original_source_address: {}",
              Hex::encode(key), original_source_address_->asString());
  } else {
    // Add the source identity to the hash key. This will separate upstream
    // connection pools per security ID.
    key.emplace_back(uint8_t(source_identity_ >> 16));
    key.emplace_back(uint8_t(source_identity_ >> 8));
    key.emplace_back(uint8_t(source_identity_));
    ENVOY_LOG(trace, "hashKey with source identity: {}, source_identity: {}", Hex::encode(key),
              source_identity_);
  }
}

} // namespace Cilium
} // namespace Envoy
