#pragma once

#include <asm-generic/socket.h>
#include <netinet/in.h>

#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"

#include "source/common/common/hex.h"
#include "source/common/common/logger.h"

#include "absl/numeric/int128.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/network_policy.h"
#include "cilium/policy_id.h"

namespace Envoy {
namespace Cilium {

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual uint32_t resolvePolicyId(const Network::Address::Ip*) const PURE;
  virtual const PolicyInstanceConstSharedPtr getPolicy(const std::string&) const PURE;
};

class SocketMarkOption : public Network::Socket::Option,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  SocketMarkOption(uint32_t identity,
                   Network::Address::InstanceConstSharedPtr original_source_address = nullptr,
                   Network::Address::InstanceConstSharedPtr ipv4_source_address = nullptr,
                   Network::Address::InstanceConstSharedPtr ipv6_source_address = nullptr)
      : identity_(identity), original_source_address_(std::move(original_source_address)),
        ipv4_source_address_(std::move(ipv4_source_address)),
        ipv6_source_address_(std::move(ipv6_source_address)) {}

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

    if (source_address) {
      socket.connectionInfoProvider().setLocalAddress(std::move(source_address));
    }

    return true;
  }

  template <typename T> void addressIntoVector(std::vector<uint8_t>& vec, const T& address) const {
    const uint8_t* byte_array = reinterpret_cast<const uint8_t*>(&address);
    vec.insert(vec.end(), byte_array, byte_array + sizeof(T));
  }

  void hashKey(std::vector<uint8_t>& key) const override {
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
      ENVOY_LOG(trace, "hashKey after Cilium: {}, source: {}", Hex::encode(key),
                original_source_address_->asString());
    } else {
      // Add the source identity to the hash key. This will separate upstream
      // connection pools per security ID.
      key.emplace_back(uint8_t(identity_ >> 16));
      key.emplace_back(uint8_t(identity_ >> 8));
      key.emplace_back(uint8_t(identity_));
    }
  }

  bool isSupported() const override { return true; }

  uint32_t identity_;
  Network::Address::InstanceConstSharedPtr original_source_address_;
  // Version specific source addresses are only used if original source address is not used.
  // Selection is made based on the socket domain, which is selected based on the destination
  // address. This makes sure we don't try to bind IPv4 or IPv6 source address to a socket
  // connecting to IPv6 or IPv4 address, respectively.
  Network::Address::InstanceConstSharedPtr ipv4_source_address_;
  Network::Address::InstanceConstSharedPtr ipv6_source_address_;
};

class SocketOption : public SocketMarkOption {
public:
  SocketOption(uint32_t ingress_source_identity, uint32_t source_identity, bool ingress, bool l7lb,
               uint16_t port, std::string&& pod_ip,
               Network::Address::InstanceConstSharedPtr original_source_address,
               Network::Address::InstanceConstSharedPtr ipv4_source_address,
               Network::Address::InstanceConstSharedPtr ipv6_source_address,
               const std::weak_ptr<PolicyResolver>& policy_resolver, uint32_t proxy_id,
               absl::string_view sni)
      : SocketMarkOption(source_identity, original_source_address, ipv4_source_address,
                         ipv6_source_address),
        ingress_source_identity_(ingress_source_identity), ingress_(ingress), is_l7lb_(l7lb),
        port_(port), pod_ip_(std::move(pod_ip)), proxy_id_(proxy_id), sni_(sni),
        policy_resolver_(policy_resolver) {
    ENVOY_LOG(
        debug,
        "Cilium SocketOption(): source_identity: {}, "
        "ingress: {}, port: {}, pod_ip: {}, source_addresses: {}/{}/{}, proxy_id: {}, sni: \"{}\"",
        identity_, ingress_, port_, pod_ip_,
        original_source_address_ ? original_source_address_->asString() : "",
        ipv4_source_address_ ? ipv4_source_address_->asString() : "",
        ipv6_source_address_ ? ipv6_source_address_->asString() : "", proxy_id_, sni_);
  }

  uint32_t resolvePolicyId(const Network::Address::Ip* ip) const {
    const auto resolver = policy_resolver_.lock();
    if (resolver)
      return resolver->resolvePolicyId(ip);
    return Cilium::ID::WORLD; // default to WORLD policy ID if resolver is no longer available
  }

  const PolicyInstanceConstSharedPtr getPolicy() const {
    const auto resolver = policy_resolver_.lock();
    if (resolver)
      return resolver->getPolicy(pod_ip_);
    return nullptr;
  }

  // policyUseUpstreamDestinationAddress returns 'true' if policy enforcement should be done on the
  // basis of the upstream destination address.
  bool policyUseUpstreamDestinationAddress() const { return is_l7lb_; }

  // Additional ingress policy enforcement is performed if ingress_source_identity is non-zero
  uint32_t ingress_source_identity_;
  bool ingress_;
  bool is_l7lb_;
  uint16_t port_;
  std::string pod_ip_;
  uint32_t proxy_id_;
  std::string sni_;

private:
  const std::weak_ptr<PolicyResolver> policy_resolver_;
};

using SocketOptionSharedPtr = std::shared_ptr<SocketOption>;

static inline const Cilium::SocketOption*
GetSocketOption(const Network::Socket::OptionsSharedPtr& options) {
  if (options) {
    for (const auto& option : *options) {
      auto opt = dynamic_cast<const Cilium::SocketOption*>(option.get());
      if (opt) {
        return opt;
      }
    }
  }
  return nullptr;
}

} // namespace Cilium
} // namespace Envoy
