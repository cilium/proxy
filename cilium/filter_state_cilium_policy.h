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
#include "cilium/host_map.h"
#include "cilium/network_policy.h"

namespace Envoy {
namespace Cilium {

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual PolicyInfo resolvePolicyInfo(const Network::Address::Ip*) const PURE;
  uint32_t resolvePolicyId(const Network::Address::Ip* ip) const {
    return resolvePolicyInfo(ip).identity_;
  }
  virtual const PolicyInstance getPolicy(const std::string&) const PURE;

  // Returns 'true' if the given policy exists
  virtual bool exists(const std::string&) const PURE;
};
using PolicyResolverSharedPtr = std::shared_ptr<PolicyResolver>;

// FilterState that holds relevant connection & policy information that can be retrieved
// by the Cilium network- and HTTP policy filters via filter state.
class CiliumPolicyFilterState : public StreamInfo::FilterState::Object,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  CiliumPolicyFilterState(uint32_t ingress_source_identity, uint32_t source_identity,
                          PolicyInfo original_destination, bool ingress, bool l7lb, uint16_t port,
                          std::string&& pod_ip, std::string&& ingress_policy_name,
                          const PolicyResolverSharedPtr& policy_resolver, uint16_t proxy_id,
                          absl::string_view sni)
      : ingress_source_identity_(ingress_source_identity), source_identity_(source_identity),
        original_destination_(std::move(original_destination)), ingress_(ingress), is_l7lb_(l7lb),
        port_(port), pod_ip_(std::move(pod_ip)),
        ingress_policy_name_(std::move(ingress_policy_name)), proxy_id_(proxy_id), sni_(sni),
        policy_resolver_(policy_resolver) {
    ENVOY_LOG(
        debug,
        "Cilium CiliumPolicyFilterState(): source_identity: {}, original_destination_identity: {}, "
        "ingress: {}, port: {}, pod_ip: {}, ingress_policy_name: {}, proxy_id: {}, sni: \"{}\"",
        source_identity_, original_destination_.identity_, ingress_, port_, pod_ip_,
        ingress_policy_name_, proxy_id_, sni_);
  }

  uint32_t resolvePolicyId(const Network::Address::Ip* ip) const {
    return policy_resolver_->resolvePolicyId(ip);
  }

  PolicyInfo resolvePolicyInfo(const Network::Address::Ip* ip) const {
    return policy_resolver_->resolvePolicyInfo(ip);
  }

  bool exists(const std::string& ip) const { return policy_resolver_->exists(ip); }

  const PolicyInstance getPolicy() const { return policy_resolver_->getPolicy(pod_ip_); }

  bool enforceNetworkPolicy(const Network::Connection& conn, const PolicyInfo& destination,
                            uint16_t destination_port, const absl::string_view sni,
                            /* INOUT */ AccessLog::Entry& log_entry) const;

  bool enforcePodHTTPPolicy(const Network::Connection& conn, const PolicyInfo& destination,
                            uint16_t destination_port,
                            /* INOUT */ Http::RequestHeaderMap& headers,
                            /* INOUT */ AccessLog::Entry& log_entry) const;

  bool enforceIngressHTTPPolicy(const Network::Connection& conn, const PolicyInfo& destination,
                                uint16_t destination_port,
                                /* INOUT */ Http::RequestHeaderMap& headers,
                                /* INOUT */ AccessLog::Entry& log_entry) const;

  // policyUseUpstreamDestinationAddress returns 'true' if policy enforcement should be done on the
  // basis of the upstream destination address.
  bool policyUseUpstreamDestinationAddress() const { return is_l7lb_; }

  static const std::string& key();

  // Additional ingress policy enforcement is performed if the ingress source identity is non-zero.
  const uint32_t ingress_source_identity_;
  const uint32_t source_identity_;
  // Retain the original destination lookup. L7 LB enforcement resolves the selected destination
  // again. Pod ingress uses its bound Endpoint's named ports; legacy NPDS receives numeric ports.
  const PolicyInfo original_destination_;
  bool ingress_;
  bool is_l7lb_;
  uint16_t port_;
  std::string pod_ip_;
  std::string ingress_policy_name_;
  uint16_t proxy_id_;
  std::string sni_;

private:
  const PolicyResolverSharedPtr policy_resolver_;
};
} // namespace Cilium
} // namespace Envoy
