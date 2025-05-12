#include "cilium/filter_state_cilium_policy.h"

#include <asm-generic/socket.h>
#include <netinet/in.h>

#include <cerrno>
#include <string>

#include "source/common/common/macros.h"

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
  const auto resolver = policy_resolver_.lock();
  use_proxy_lib = false;
  l7_proto = "";

  if (!resolver) {
    // No policy resolver
    ENVOY_CONN_LOG(debug, "No policy resolver", conn);
    return false;
  }

  // enforce pod policy first, if any
  if (pod_ip_.length() > 0) {
    const auto& policy = resolver->getPolicy(pod_ip_);
    auto remote_id = ingress_ ? source_identity_ : destination_identity;
    auto port = ingress_ ? port_ : destination_port;

    auto portPolicy = policy.findPortPolicy(ingress_, port);

    if (!portPolicy.allowed(proxy_id_, remote_id, sni)) {
      ENVOY_CONN_LOG(debug, "Pod policy DENY on proxy_id: {} id: {} port: {} sni: \"{}\"", conn,
                     proxy_id_, remote_id, destination_port, sni);
      return false;
    }

    // populate l7proto_ if available
    use_proxy_lib = portPolicy.useProxylib(proxy_id_, remote_id, l7_proto);
  }

  // enforce Ingress policy 2nd, if any
  if (ingress_policy_name_.length() > 0) {
    log_entry.entry_.set_policy_name(ingress_policy_name_);
    const auto& policy = resolver->getPolicy(ingress_policy_name_);

    // Enforce ingress policy for Ingress, on the original destination port
    if (ingress_source_identity_ != 0) {
      auto ingressPortPolicy = policy.findPortPolicy(true, port_);
      if (!ingressPortPolicy.allowed(proxy_id_, ingress_source_identity_, sni)) {
        ENVOY_CONN_LOG(debug,
                       "Ingress network policy {} DROP for source identity and destination "
                       "reserved ingress identity: {} proxy_id: {} port: {} sni: \"{}\"",
                       conn, ingress_policy_name_, ingress_source_identity_, proxy_id_,
                       destination_port, sni);
        return false;
      }
    }

    // Enforce egress policy for Ingress
    auto egressPortPolicy = policy.findPortPolicy(false, destination_port);
    if (!egressPortPolicy.allowed(proxy_id_, destination_identity, sni)) {
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

bool CiliumPolicyFilterState::enforceHTTPPolicy(const Network::Connection& conn, bool is_downstream,
                                                uint32_t destination_identity,
                                                uint16_t destination_port,
                                                /* INOUT */ Http::RequestHeaderMap& headers,
                                                /* INOUT */ AccessLog::Entry& log_entry) const {
  const auto resolver = policy_resolver_.lock();

  if (!resolver) {
    // No policy resolver
    ENVOY_CONN_LOG(debug, "No policy resolver", conn);
    return false;
  }

  // enforce pod policy first, if any.
  // - ingress enforcement in downstream
  // - egress enforcement in upstream
  // - unless !L7LB, where both are done on downstream filter (only)
  // =>
  // - is_l7lb_: ingress_ == is_downstream
  // - !is_l7lb_: is_downstream
  if (pod_ip_.length() > 0 && (is_l7lb_ ? is_downstream == ingress_ : is_downstream)) {
    const auto& policy = resolver->getPolicy(pod_ip_);
    auto remote_id = ingress_ ? source_identity_ : destination_identity;
    auto port = ingress_ ? port_ : destination_port;
    if (!policy.allowed(ingress_, proxy_id_, remote_id, port, headers, log_entry)) {
      ENVOY_CONN_LOG(debug, "Pod HTTP policy DENY on proxy_id: {} id: {} port: {}", conn, proxy_id_,
                     remote_id, port);
      return false;
    }
  }

  // enforce Ingress policy 2nd, if any, always on the upstream
  if (!is_downstream && ingress_policy_name_.length() > 0) {
    log_entry.entry_.set_policy_name(ingress_policy_name_);
    const auto& policy = resolver->getPolicy(ingress_policy_name_);

    // Enforce ingress policy for Ingress, on the original destination port
    if (ingress_source_identity_ != 0) {
      if (!policy.allowed(true, proxy_id_, ingress_source_identity_, port_, headers, log_entry)) {
        ENVOY_CONN_LOG(debug,
                       "Ingress HTTP policy {} DROP for source identity: {} proxy_id: {} port: {}",
                       conn, ingress_policy_name_, ingress_source_identity_, proxy_id_, port_);
        return false;
      }
    }

    // Enforce egress policy for Ingress
    if (!policy.allowed(false, proxy_id_, destination_identity, destination_port, headers,
                        log_entry)) {
      ENVOY_CONN_LOG(
          debug, "Egress HTTP policy {} DROP for destination identity: {} proxy_id: {} port: {}",
          conn, ingress_policy_name_, destination_identity, proxy_id_, destination_port);
      return false;
    }
  }

  // Connection allowed by policy
  return true;
}

} // namespace Cilium
} // namespace Envoy
