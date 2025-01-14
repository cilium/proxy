#pragma once

#include <asm-generic/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
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

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/conntrack.h"
#include "cilium/policy_id.h"

namespace Envoy {
namespace Cilium {

class PolicyInstance;
using PolicyInstanceConstSharedPtr = std::shared_ptr<const PolicyInstance>;

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual uint32_t resolvePolicyId(const Network::Address::Ip*) const PURE;
  virtual const PolicyInstanceConstSharedPtr getPolicy(const std::string&) const PURE;
};

class SocketMarkOption : public Network::Socket::Option,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  SocketMarkOption(uint32_t identity) : identity_(identity) {}

  absl::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&,
                   envoy::config::core::v3::SocketOption::SocketState) const override {
    return absl::nullopt;
  }

  bool setOption(
      [[maybe_unused]] Network::Socket& socket,
      [[maybe_unused]] envoy::config::core::v3::SocketOption::SocketState state) const override {

    return true;
  }

  void hashKey([[maybe_unused]] std::vector<uint8_t>& key) const override {}

  bool isSupported() const override { return true; }

  uint32_t identity_;
};

class SocketOption : public SocketMarkOption {
public:
  SocketOption(uint32_t ingress_source_identity, uint32_t source_identity, bool ingress, bool l7lb,
               uint16_t port, std::string&& pod_ip,
               const std::weak_ptr<PolicyResolver>& policy_resolver, uint32_t proxy_id,
               absl::string_view sni)
      : SocketMarkOption(source_identity), ingress_source_identity_(ingress_source_identity),
        ingress_(ingress), is_l7lb_(l7lb), port_(port), pod_ip_(std::move(pod_ip)),
        proxy_id_(proxy_id), sni_(sni), policy_resolver_(policy_resolver) {
    ENVOY_LOG(debug,
              "Cilium SocketOption(): source_identity: {}, "
              "ingress: {}, port: {}, pod_ip: {}, proxy_id: {}, sni: \"{}\"",
              identity_, ingress_, port_, pod_ip_, proxy_id_, sni_);
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
