#pragma once

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/network/listen_socket.h"
#include "common/common/logger.h"

#include "conntrack.h"
#include "proxymap.h"

namespace Envoy {
namespace Cilium {

class SocketMarkOption : public Network::Socket::Option, public Logger::Loggable<Logger::Id::filter> {
public:
  SocketMarkOption(bool no_mark, uint32_t identity, bool ingress, Network::Address::InstanceConstSharedPtr src_address)
   : identity_(identity), ingress_(ingress), no_mark_(no_mark), src_address_(std::move(src_address)) {}

  absl::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&, envoy::config::core::v3::SocketOption::SocketState) const override {
  	return absl::nullopt;
  }

  bool setOption(Network::Socket& socket, envoy::config::core::v3::SocketOption::SocketState state) const override {
    if (no_mark_) {
      return true;
    }
    // Only set the option once per socket
    if (state != envoy::config::core::v3::SocketOption::STATE_PREBIND) {
      ENVOY_LOG(trace, "Skipping setting socket ({}) option SO_MARK, state != STATE_PREBIND", socket.ioHandle().fd());
      return true;
    }
    uint32_t cluster_id = (identity_ >> 16) & 0xFF;
    uint32_t identity_id = (identity_ & 0xFFFF) << 16;
    uint32_t mark = ((ingress_) ? 0xA00 : 0xB00) | cluster_id | identity_id;
    int rc = setsockopt(socket.ioHandle().fd(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (rc < 0) {
      if (errno == EPERM) {
	// Do not assert out in this case so that we can run tests without CAP_NET_ADMIN.
	ENVOY_LOG(critical,
		  "Failed to set socket option SO_MARK to {}, capability CAP_NET_ADMIN needed: {}",
		  mark, strerror(errno));
      } else {
	ENVOY_LOG(critical, "Socket option failure. Failed to set SO_MARK to {}: {}", mark,
		  strerror(errno));
	return false;
      }
    }

    if (src_address_) {
      socket.setLocalAddress(src_address_);
    }

    ENVOY_LOG(trace, "Set socket ({}) option SO_MARK to {:x} (magic mark: {:x}, id: {}, cluster: {}), src: {}",
	      socket.ioHandle().fd(), mark, mark & 0xff00, mark >> 16, mark & 0xff, src_address_ ? src_address_->asString() : "");
    return true;
  }

  template <typename T> void addressIntoVector(std::vector<uint8_t>& vec, const T& address) const {
    const uint8_t* byte_array = reinterpret_cast<const uint8_t*>(&address);
    vec.insert(vec.end(), byte_array, byte_array + sizeof(T));
  }

  void hashKey(std::vector<uint8_t>& key) const override {
    if (no_mark_) {
      return;
    }
    // Source address is more specific than policy ID. If using an original source address,
    // we do not need to also add the source security ID to the hash key. Note that since
    // the identity is 3 bytes it will not collide with neither an IPv4 nor IPv6 address.
    if (src_address_) {
      if (src_address_->ip()->version() == Network::Address::IpVersion::v4) {
	uint32_t raw_address = src_address_->ip()->ipv4()->address();
	addressIntoVector(key, raw_address);
      } else if (src_address_->ip()->version() == Network::Address::IpVersion::v6) {
	absl::uint128 raw_address = src_address_->ip()->ipv6()->address();
	addressIntoVector(key, raw_address);
      }
    } else {
      // Add the source identity to the hash key. This will separate upstream connection pools
      // per security ID.
      key.emplace_back(uint8_t(identity_ >> 16));
      key.emplace_back(uint8_t(identity_ >> 8));
      key.emplace_back(uint8_t(identity_));
    }
  }

  uint32_t identity_;
  bool ingress_;
  bool no_mark_;
  Network::Address::InstanceConstSharedPtr src_address_;
};

class PolicyInstance;

class SocketOption : public SocketMarkOption {
public:
 SocketOption(std::shared_ptr<const PolicyInstance> policy, const ProxyMapSharedPtr& maps, bool no_mark, uint32_t source_identity, uint32_t destination_identity, bool ingress, uint16_t port, uint16_t proxy_port, std::string&& pod_ip, Network::Address::InstanceConstSharedPtr src_address)
   : SocketMarkOption(no_mark, source_identity, ingress, src_address), policy_(policy), maps_(maps), destination_identity_(destination_identity), port_(port), proxy_port_(proxy_port), pod_ip_(std::move(pod_ip)) {
    ENVOY_LOG(debug, "Cilium SocketOption(): source_identity: {}, destination_identity: {}, ingress: {}, port: {}, pod_ip: {}, src_address: {}, no_mark: {}", identity_, destination_identity_, ingress_, port_, pod_ip_, src_address_ ? src_address_->asString() : "", no_mark_);
  }

  ProxyMapSharedPtr GetProxyMap() const { return maps_; }

  const std::shared_ptr<const PolicyInstance> policy_;
private:
  ProxyMapSharedPtr maps_;
public:
  uint32_t destination_identity_;
  uint16_t port_;
  uint16_t proxy_port_;
  std::string pod_ip_;
};

static inline
const Cilium::SocketOption* GetSocketOption(const Network::Socket::OptionsSharedPtr& options) {
  if (options) {
    for (const auto& option: *options) {
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
