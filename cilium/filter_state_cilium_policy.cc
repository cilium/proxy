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

bool CiliumPolicyFilterState::enforceNetworkPolicy(const Network::Connection& conn,
                                                   uint32_t destination_identity,
                                                   uint16_t destination_port,
                                                   const absl::string_view sni,
                                                   /* OUT */ bool& use_proxy_lib,
                                                   /* OUT */ std::string& l7_proto,
                                                   /* INOUT */ AccessLog::Entry& log_entry) const {
  use_proxy_lib = false;
  l7_proto = "";

  // enforce pod policy first, if any
  if (pod_ip_.length() > 0) {
    const auto& policy = policy_resolver_->getPolicy(pod_ip_);
    auto remote_id = ingress_ ? source_identity_ : destination_identity;
    auto port = ingress_ ? port_ : destination_port;

    auto port_policy = policy.findPortPolicy(ingress_, port);

    if (!port_policy.allowed(proxy_id_, remote_id, sni)) {
      ENVOY_CONN_LOG(debug, "Pod policy DENY on proxy_id: {} id: {} port: {} sni: \"{}\"", conn,
                     proxy_id_, remote_id, port, sni);
      return false;
    }

    // populate l7proto_ if available
    use_proxy_lib = port_policy.useProxylib(proxy_id_, remote_id, l7_proto);
  }

  // enforce Ingress policy 2nd, if any
  if (ingress_policy_name_.length() > 0) {
    log_entry.entry_.set_policy_name(ingress_policy_name_);
    const auto& policy = policy_resolver_->getPolicy(ingress_policy_name_);

    // Enforce ingress policy for Ingress, on the original destination port
    if (ingress_source_identity_ != 0) {
      auto ingress_port_policy = policy.findPortPolicy(true, port_);
      if (!ingress_port_policy.allowed(proxy_id_, ingress_source_identity_, sni)) {
        ENVOY_CONN_LOG(debug,
                       "Ingress network policy {} DROP for source identity and destination "
                       "reserved ingress identity: {} proxy_id: {} port: {} sni: \"{}\"",
                       conn, ingress_policy_name_, ingress_source_identity_, proxy_id_, port_, sni);
        return false;
      }
    }

    // Enforce egress policy for Ingress
    auto egress_port_policy = policy.findPortPolicy(false, destination_port);
    if (!egress_port_policy.allowed(proxy_id_, destination_identity, sni)) {
      ENVOY_CONN_LOG(debug,
                     "Egress network policy {} DROP for reserved ingress identity and destination "
                     "identity: {} proxy_id: {} port: {} sni: \"{}\"",
                     conn, ingress_policy_name_, destination_identity, proxy_id_, destination_port,
                     sni);
      return false;
    }
  }

  // Connection allowed by policy
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
