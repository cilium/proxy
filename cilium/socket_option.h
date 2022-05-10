#pragma once

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"
#include "conntrack.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/network/listen_socket.h"

namespace Envoy {
namespace Cilium {

class PolicyInstance;

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual uint32_t resolvePolicyId(const Network::Address::Ip*) const PURE;
  virtual const PolicyInstanceConstSharedPtr getPolicy(const std::string&) const PURE;
};

class SocketMarkOption : public Network::Socket::Option,
                         public Logger::Loggable<Logger::Id::filter> {
 public:
  SocketMarkOption(uint32_t mark, uint32_t identity, bool ingress,
                   Network::Address::InstanceConstSharedPtr original_source_address,
                   Network::Address::InstanceConstSharedPtr ipv4_source_address,
                   Network::Address::InstanceConstSharedPtr ipv6_source_address)
      : identity_(identity),
        mark_(mark),
        ingress_(ingress),
        original_source_address_(std::move(original_source_address)),
        ipv4_source_address_(std::move(ipv4_source_address)),
        ipv6_source_address_(std::move(ipv6_source_address)) {}

  absl::optional<Network::Socket::Option::Details> getOptionDetails(
      const Network::Socket&,
      envoy::config::core::v3::SocketOption::SocketState) const override {
    return absl::nullopt;
  }

  bool setOption(
      Network::Socket& socket,
      envoy::config::core::v3::SocketOption::SocketState state) const override {
    // sidecars do not have mark
    if (mark_ == 0) {
      return true;
    }
    // Only set the option once per socket
    if (state != envoy::config::core::v3::SocketOption::STATE_PREBIND) {
      ENVOY_LOG(
          trace,
          "Skipping setting socket ({}) option SO_MARK, state != STATE_PREBIND",
          socket.ioHandle().fdDoNotUse());
      return true;
    }
    auto status = socket.setSocketOption(SOL_SOCKET, SO_MARK, &mark_, sizeof(mark_));
    if (status.return_value_ < 0) {
      if (status.errno_ == EPERM) {
        // Do not assert out in this case so that we can run tests without
        // CAP_NET_ADMIN.
        ENVOY_LOG(critical,
                  "Failed to set socket option SO_MARK to {}, capability "
                  "CAP_NET_ADMIN needed: {}",
                  mark_, Envoy::errorDetails(status.errno_));
      } else {
        ENVOY_LOG(critical,
                  "Socket option failure. Failed to set SO_MARK to {}: {}",
                  mark_, Envoy::errorDetails(status.errno_));
        return false;
      }
    }

    Network::Address::InstanceConstSharedPtr source_address = original_source_address_;
    if (source_address) {
      // Allow reuse of the original source address. This may by needed for
      // retries to not fail on "address already in use" when using a specific
      // source address and port.

      uint32_t one = 1;
      auto status = socket.setSocketOption(SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      if (status.return_value_ < 0) {
	ENVOY_LOG(critical,
		  "Failed to set socket option SO_REUSEADDR: {}",
		  Envoy::errorDetails(status.errno_));
	return false;
      }
    } else if (ipv4_source_address_ || ipv6_source_address_) {
      // Select source address based on the socket address family
      auto ipVersion = socket.ipVersion();
      if (!ipVersion.has_value()) {
	ENVOY_LOG(critical,
		  "Socket address family is not available, can not choose source address");
	return false;
      }
      source_address = ipv6_source_address_;
      if (*ipVersion == Network::Address::IpVersion::v4) {
	source_address = ipv4_source_address_;
      }
    }

    ENVOY_LOG(trace,
              "Set socket ({}) option SO_MARK to {:x} (magic mark: {:x}, id: "
              "{}, cluster: {}), src: {}",
              socket.ioHandle().fdDoNotUse(), mark_, mark_ & 0xff00, mark_ >> 16,
              mark_ & 0xff, source_address ? source_address->asString() : "");

    if (source_address) {
      socket.connectionInfoProvider().setLocalAddress(std::move(source_address));
    }

    return true;
  }

  template <typename T>
  void addressIntoVector(std::vector<uint8_t>& vec, const T& address) const {
    const uint8_t* byte_array = reinterpret_cast<const uint8_t*>(&address);
    vec.insert(vec.end(), byte_array, byte_array + sizeof(T));
  }

  void hashKey(std::vector<uint8_t>& key) const override {
    // sidecars have no mark
    if (mark_ == 0) {
      return;
    }
    // Source address is more specific than policy ID. If using an original
    // source address, we do not need to also add the source security ID to the
    // hash key. Note that since the identity is 3 bytes it will not collide
    // with neither an IPv4 nor IPv6 address.
    if (original_source_address_) {
      if (original_source_address_->ip()->version() == Network::Address::IpVersion::v4) {
        uint32_t raw_address = original_source_address_->ip()->ipv4()->address();
        addressIntoVector(key, raw_address);
      } else if (original_source_address_->ip()->version() ==
                 Network::Address::IpVersion::v6) {
        absl::uint128 raw_address = original_source_address_->ip()->ipv6()->address();
        addressIntoVector(key, raw_address);
      }
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
  uint32_t mark_;
  bool ingress_;
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
  SocketOption(PolicyInstanceConstSharedPtr policy, uint32_t mark,
               uint32_t source_identity,
               bool ingress, uint16_t port, std::string&& pod_ip,
               Network::Address::InstanceConstSharedPtr original_source_address,
               Network::Address::InstanceConstSharedPtr ipv4_source_address,
               Network::Address::InstanceConstSharedPtr ipv6_source_address,
               const std::shared_ptr<PolicyResolver>& policy_id_resolver)
    : SocketMarkOption(mark, source_identity, ingress, original_source_address, ipv4_source_address, ipv6_source_address),
        initial_policy_(policy),
        port_(port),
        pod_ip_(std::move(pod_ip)),
        policy_id_resolver_(policy_id_resolver) {
    ENVOY_LOG(
        debug,
        "Cilium SocketOption(): source_identity: {}, "
        "ingress: {}, port: {}, pod_ip: {}, source_addresses: {}/{}/{}, mark: {}",
        identity_, ingress_, port_, pod_ip_,
        original_source_address_ ? original_source_address_->asString() : "",
        ipv4_source_address_ ? ipv4_source_address_->asString() : "",
        ipv6_source_address_ ? ipv6_source_address_->asString() : "",
        mark_);
  }

  uint32_t resolvePolicyId(const Network::Address::Ip* ip) const {
    return policy_id_resolver_->resolvePolicyId(ip);
  }

  const PolicyInstanceConstSharedPtr getPolicy() const {
    return policy_id_resolver_->getPolicy(pod_ip_);
  }
 
  const PolicyInstanceConstSharedPtr initial_policy_;
  uint16_t port_;
  std::string pod_ip_;
private:
  const std::shared_ptr<PolicyResolver> policy_id_resolver_;
};

static inline const Cilium::SocketOption* GetSocketOption(
    const Network::Socket::OptionsSharedPtr& options) {
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

}  // namespace Cilium
}  // namespace Envoy
