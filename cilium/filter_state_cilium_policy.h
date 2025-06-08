#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/common/pure.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/network/connection.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/network_policy.h"

namespace Envoy {
namespace Cilium {

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual uint32_t resolvePolicyId(const Network::Address::Ip*) const PURE;
  virtual const PolicyInstance& getPolicy(const std::string&) const PURE;
};
using PolicyResolverSharedPtr = std::shared_ptr<PolicyResolver>;

// FilterState that holds relevant connection & policy information that can be retrieved
// by the Cilium network- and HTTP policy filters via filter state.
class CiliumPolicyFilterState : public StreamInfo::FilterState::Object,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  CiliumPolicyFilterState(uint32_t ingress_source_identity, uint32_t source_identity, bool ingress,
                          bool l7lb, uint16_t port, std::string&& pod_ip,
                          std::string&& ingress_policy_name,
                          const PolicyResolverSharedPtr& policy_resolver, uint32_t proxy_id,
                          absl::string_view sni)
      : ingress_source_identity_(ingress_source_identity), source_identity_(source_identity),
        ingress_(ingress), is_l7lb_(l7lb), port_(port), pod_ip_(std::move(pod_ip)),
        ingress_policy_name_(std::move(ingress_policy_name)), proxy_id_(proxy_id), sni_(sni),
        policy_resolver_(policy_resolver) {
    ENVOY_LOG(
        debug,
        "Cilium CiliumPolicyFilterState(): source_identity: {}, "
        "ingress: {}, port: {}, pod_ip: {}, ingress_policy_name: {}, proxy_id: {}, sni: \"{}\"",
        source_identity_, ingress_, port_, pod_ip_, ingress_policy_name_, proxy_id_, sni_);
  }

  uint32_t resolvePolicyId(const Network::Address::Ip* ip) const {
    return policy_resolver_->resolvePolicyId(ip);
  }

  const PolicyInstance& getPolicy() const { return policy_resolver_->getPolicy(pod_ip_); }

  bool enforcePodNetworkPolicy(const Network::Connection& conn, uint32_t destination_identity,
                               uint16_t destination_port, const absl::string_view sni) const;

  bool enforceIngressNetworkPolicy(const Network::Connection& conn, uint32_t destination_identity,
                                   uint16_t destination_port, const absl::string_view sni) const;

  bool enforceHTTPPolicy(const Network::Connection& conn, bool is_downstream,
                         uint32_t destination_identity, uint16_t destination_port,
                         /* INOUT */ Http::RequestHeaderMap& headers,
                         /* INOUT */ AccessLog::Entry& log_entry) const;

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
  std::string ingress_policy_name_;
  uint32_t proxy_id_;
  std::string sni_;

private:
  const PolicyResolverSharedPtr policy_resolver_;
};
} // namespace Cilium
} // namespace Envoy
