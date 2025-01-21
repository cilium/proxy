#pragma once

// clang-format off
#include <netinet/in.h> // Must be included before linux/in.h

// clang-format on
#include <linux/in.h>
#include <linux/in6.h>

#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/common/pure.h"
#include "envoy/network/address.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "cilium/network_policy.h"
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

// Socket Option that holds relevant connection & policy information that can be retrieved
// by the Cilium network- and HTTP policy filters by using GetCiliumPolicySocketOption.
class CiliumPolicySocketOption : public StreamInfo::FilterState::Object,
                                 public Logger::Loggable<Logger::Id::filter> {
public:
  CiliumPolicySocketOption(uint32_t ingress_source_identity, uint32_t source_identity, bool ingress,
                           bool l7lb, uint16_t port, std::string&& pod_ip,
                           const std::weak_ptr<PolicyResolver>& policy_resolver, uint32_t proxy_id,
                           absl::string_view sni)
      : ingress_source_identity_(ingress_source_identity), source_identity_(source_identity),
        ingress_(ingress), is_l7lb_(l7lb), port_(port), pod_ip_(std::move(pod_ip)),
        proxy_id_(proxy_id), sni_(sni), policy_resolver_(policy_resolver) {
    ENVOY_LOG(debug,
              "Cilium CiliumPolicySocketOption(): source_identity: {}, "
              "ingress: {}, port: {}, pod_ip: {}, proxy_id: {}, sni: \"{}\"",
              source_identity_, ingress_, port_, pod_ip_, proxy_id_, sni_);
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

  static const std::string& key();

  // Additional ingress policy enforcement is performed if ingress_source_identity is non-zero
  uint32_t ingress_source_identity_;
  uint32_t source_identity_;
  bool ingress_;
  bool is_l7lb_;
  uint16_t port_;
  std::string pod_ip_;
  uint32_t proxy_id_;
  std::string sni_;

private:
  const std::weak_ptr<PolicyResolver> policy_resolver_;
};

using CiliumPolicySocketOptionSharedPtr = std::shared_ptr<CiliumPolicySocketOption>;

static inline const Cilium::CiliumPolicySocketOption*
GetCiliumPolicySocketOption(const StreamInfo::StreamInfo& streamInfo) {
  return streamInfo.filterState().getDataReadOnly<Cilium::CiliumPolicySocketOption>(
      Cilium::CiliumPolicySocketOption::key());
}

} // namespace Cilium
} // namespace Envoy
