#include "cilium/filter_state_cilium_policy.h"

#include <cstdint>
#include <string>

#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"

#include "source/common/common/logger.h"
#include "source/common/common/macros.h"

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"

namespace Envoy {
namespace Cilium {

const std::string& CiliumPolicyFilterState::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "cilium.policy");
}

bool CiliumPolicyFilterState::enforcePodNetworkPolicy(const Network::Connection& conn,
                                                      uint32_t destination_identity,
                                                      uint16_t destination_port,
                                                      const absl::string_view sni) const {
  auto remote_id = ingress_ ? source_identity_ : destination_identity;
  const auto& policy = policy_resolver_->getPolicy(pod_ip_);
  auto port = ingress_ ? port_ : destination_port;
  auto port_policy = policy.findPortPolicy(ingress_, port);

  if (!port_policy.allowed(proxy_id_, remote_id, sni)) {
    ENVOY_CONN_LOG(debug,
                   "cilium.network: Pod {} network {} policy DENY on proxy_id: {} id: {} port: {} "
                   "sni: \"{}\"",
                   conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id,
                   destination_port, sni);
    return false;
  }

  ENVOY_CONN_LOG(debug,
                 "cilium.network: Pod {} network {} policy ALLOW on proxy_id: {} id: {} port: {} "
                 "sni: \"{}\"",
                 conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id,
                 destination_port, sni);
  return true;
}

bool CiliumPolicyFilterState::enforceIngressNetworkPolicy(const Network::Connection& conn,
                                                          uint32_t destination_identity,
                                                          uint16_t destination_port,
                                                          const absl::string_view sni) const {
  const auto& policy = policy_resolver_->getPolicy(ingress_policy_name_);

  // Enforce ingress policy for Ingress, on the original destination port
  if (ingress_source_identity_ != 0) {
    auto ingress_port_policy = policy.findPortPolicy(true, port_);
    if (!ingress_port_policy.allowed(proxy_id_, ingress_source_identity_, sni)) {
      ENVOY_CONN_LOG(
          debug,
          "cilium.network: Ingress {} network ingress policy DENY on proxy_id: {} id: {} "
          "port: {} sni: \"{}\"",
          conn, ingress_policy_name_, proxy_id_, ingress_source_identity_, port_, sni);
      return false;
    }
  }

  // Enforce egress policy for Ingress
  auto egress_port_policy = policy.findPortPolicy(false, destination_port);
  if (!egress_port_policy.allowed(proxy_id_, destination_identity, sni)) {
    ENVOY_CONN_LOG(debug,
                   "cilium.network: Ingress {} network egress policy DENY on proxy_id: {} "
                   "id: {} port: {} sni: \"{}\"",
                   conn, ingress_policy_name_, proxy_id_, destination_identity, destination_port,
                   sni);
    return false;
  }

  ENVOY_CONN_LOG(debug,
                 "cilium.network: Ingress {} network policy ALLOW on proxy_id: {} id: {} port: {} "
                 "sni: \"{}\"",
                 conn, ingress_policy_name_, proxy_id_, destination_identity, destination_port,
                 sni);
  return true;
}

bool CiliumPolicyFilterState::enforcePodHTTPPolicy(const Network::Connection& conn,
                                                   uint32_t destination_identity,
                                                   uint16_t destination_port,
                                                   /* INOUT */ Http::RequestHeaderMap& headers,
                                                   /* INOUT */ AccessLog::Entry& log_entry) const {
  const auto& policy = policy_resolver_->getPolicy(pod_ip_);
  auto remote_id = ingress_ ? source_identity_ : destination_identity;
  auto port = ingress_ ? port_ : destination_port;
  if (!policy.allowed(ingress_, proxy_id_, remote_id, port, headers, log_entry)) {
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
    const Network::Connection& conn, uint32_t destination_identity, uint16_t destination_port,
    /* INOUT */ Http::RequestHeaderMap& headers,
    /* INOUT */ AccessLog::Entry& log_entry) const {
  log_entry.entry_.set_policy_name(ingress_policy_name_);
  log_entry.request_logged_ = false; // we reuse the same entry we used for the pod policy

  const auto& policy = policy_resolver_->getPolicy(ingress_policy_name_);

  // Enforce ingress policy for Ingress, on the original destination port
  if (ingress_source_identity_ != 0) {
    if (!policy.allowed(true, proxy_id_, ingress_source_identity_, port_, headers, log_entry)) {
      ENVOY_CONN_LOG(debug, "Ingress {} HTTP ingress policy DROP on proxy_id: {} id: {} port: {}",
                     conn, ingress_policy_name_, proxy_id_, ingress_source_identity_, port_);
      return false;
    }
  }

  // Enforce egress policy for Ingress
  if (!policy.allowed(false, proxy_id_, destination_identity, destination_port, headers,
                      log_entry)) {
    ENVOY_CONN_LOG(debug, "Ingress {} HTTP egress policy DROP on proxy_id: {} id: {}  port: {}",
                   conn, ingress_policy_name_, proxy_id_, destination_identity, destination_port);
    return false;
  }

  // Connection allowed by policy
  ENVOY_CONN_LOG(debug, "Ingress {} HTTP policy ALLOW on proxy_id: {} id: {}  port: {}", conn,
                 ingress_policy_name_, proxy_id_, destination_identity, destination_port);
  return true;
}

} // namespace Cilium
} // namespace Envoy
