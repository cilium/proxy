#include "cilium/filter_state_cilium_policy.h"

#include <cstdint>
#include <string>

#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"

#include "source/common/common/logger.h"
#include "source/common/common/macros.h"

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/host_map.h"

namespace Envoy {
namespace Cilium {

const std::string& CiliumPolicyFilterState::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "cilium.policy");
}

bool CiliumPolicyFilterState::enforceNetworkPolicy(const Network::Connection& conn,
                                                   const PolicyInfo& destination,
                                                   uint16_t destination_port,
                                                   const absl::string_view sni,
                                                   /* INOUT */ AccessLog::Entry& log_entry) const {
  // enforce pod policy first, if any
  if (!pod_ip_.empty()) {
    const auto& policy = policy_resolver_->getPolicy(pod_ip_);
    const uint32_t remote_id = ingress_ ? source_identity_ : destination.identity_;
    auto port = ingress_ ? port_ : destination_port;

    auto port_policy = ingress_ ? policy.findIngressPortPolicy(port)
                                : policy.findEgressPortPolicy(port, destination.named_ports_);

    if (!port_policy.allowed(proxy_id_, remote_id, sni)) {
      ENVOY_CONN_LOG(debug, "Pod policy DENY on proxy_id: {} id: {} port: {} sni: \"{}\"", conn,
                     proxy_id_, remote_id, port, sni);
      return false;
    }
  }

  // enforce Ingress policy 2nd, if any
  if (!ingress_policy_name_.empty()) {
    log_entry.entry_.set_policy_name(ingress_policy_name_);
    const auto& policy = policy_resolver_->getPolicy(ingress_policy_name_);

    // Enforce ingress policy for Ingress, on the original destination port
    if (ingress_source_identity_ != 0) {
      auto ingress_port_policy = policy.findIngressPortPolicy(port_);
      if (!ingress_port_policy.allowed(proxy_id_, ingress_source_identity_, sni)) {
        ENVOY_CONN_LOG(debug,
                       "Ingress network policy {} DROP for source identity and destination "
                       "reserved ingress identity: {} proxy_id: {} port: {} sni: \"{}\"",
                       conn, ingress_policy_name_, ingress_source_identity_, proxy_id_, port_, sni);
        return false;
      }
    }

    // Enforce egress policy for Ingress
    auto egress_port_policy =
        policy.findEgressPortPolicy(destination_port, destination.named_ports_);
    if (!egress_port_policy.allowed(proxy_id_, destination.identity_, sni)) {
      ENVOY_CONN_LOG(debug,
                     "Egress network policy {} DROP for reserved ingress identity and destination "
                     "identity: {} proxy_id: {} port: {} sni: \"{}\"",
                     conn, ingress_policy_name_, destination.identity_, proxy_id_, destination_port,
                     sni);
      return false;
    }
  }

  // Connection allowed by policy
  return true;
}

bool CiliumPolicyFilterState::enforcePodHTTPPolicy(const Network::Connection& conn,
                                                   const PolicyInfo& destination,
                                                   uint16_t destination_port,
                                                   /* INOUT */ Http::RequestHeaderMap& headers,
                                                   /* INOUT */ AccessLog::Entry& log_entry) const {
  const auto& policy = policy_resolver_->getPolicy(pod_ip_);
  const uint32_t remote_id = ingress_ ? source_identity_ : destination.identity_;
  auto port = ingress_ ? port_ : destination_port;

  const auto port_policy = ingress_ ? policy.findIngressPortPolicy(port)
                                    : policy.findEgressPortPolicy(port, destination.named_ports_);
  if (!port_policy.allowed(proxy_id_, remote_id, headers, log_entry)) {
    ENVOY_CONN_LOG(debug,
                   "cilium.l7policy: Pod {} HTTP {} policy DENY on proxy_id: {} id: {} port: {}",
                   conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id, port);
    return false;
  }

  // Connection allowed by policy
  ENVOY_CONN_LOG(debug,
                 "cilium.l7policy: Pod {} HTTP {} policy ALLOW on proxy_id: {} id: {} port: {}",
                 conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id, port);
  return true;
}

bool CiliumPolicyFilterState::enforceIngressHTTPPolicy(
    const Network::Connection& conn, const PolicyInfo& destination, uint16_t destination_port,
    /* INOUT */ Http::RequestHeaderMap& headers,
    /* INOUT */ AccessLog::Entry& log_entry) const {
  log_entry.entry_.set_policy_name(ingress_policy_name_);
  log_entry.request_logged_ = false; // we reuse the same entry we used for the pod policy
  const auto& policy = policy_resolver_->getPolicy(ingress_policy_name_);

  // Enforce ingress policy for Ingress, on the original destination port
  if (ingress_source_identity_ != 0) {
    const auto port_policy = policy.findIngressPortPolicy(port_);
    if (!port_policy.allowed(proxy_id_, ingress_source_identity_, headers, log_entry)) {
      ENVOY_CONN_LOG(
          debug,
          "cilium.l7policy: Ingress {} HTTP ingress policy DROP on proxy_id: {} id: {} port: {}",
          conn, ingress_policy_name_, proxy_id_, ingress_source_identity_, port_);
      return false;
    }
  }

  // Enforce egress policy for Ingress on the upstream destination identity and port
  const auto port_policy = policy.findEgressPortPolicy(destination_port, destination.named_ports_);
  if (!port_policy.allowed(proxy_id_, destination.identity_, headers, log_entry)) {
    ENVOY_CONN_LOG(
        debug,
        "cilium.l7policy: Ingress {} HTTP egress policy DROP on proxy_id: {} id: {}  port: {}",
        conn, ingress_policy_name_, proxy_id_, destination.identity_, destination_port);
    return false;
  }

  // Connection allowed by policy
  ENVOY_CONN_LOG(debug,
                 "cilium.l7policy: Ingress {} HTTP policy ALLOW on proxy_id: {} id: {}  port: {}",
                 conn, ingress_policy_name_, proxy_id_, destination.identity_, destination_port);
  return true;
}

} // namespace Cilium
} // namespace Envoy
