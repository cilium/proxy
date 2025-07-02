#include "cilium/filter_state_cilium_policy.h"

#include <cstdint>
#include <string>

#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"

#include "source/common/common/logger.h"
#include "source/common/common/macros.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/accesslog.h"

namespace Envoy {
namespace Cilium {

const std::string& CiliumPolicyFilterState::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "cilium.policy");
}

bool CiliumPolicyFilterState::enforcePodNetworkPolicy(const Network::Connection& conn,
                                                      uint32_t destination_identity,
                                                      uint16_t destination_port,
                                                      const absl::string_view sni,
                                                      /* OUT */ bool& use_proxy_lib,
                                                      /* OUT */ std::string& l7_proto) const {
  auto remote_id = ingress_ ? source_identity_ : destination_identity;
  const auto& policy = policy_resolver_->getPolicy(pod_ip_);
  auto port = ingress_ ? port_ : destination_port;
  auto port_policy = policy.findPortPolicy(ingress_, port);

  use_proxy_lib = false;
  l7_proto = "";

  if (!port_policy.allowed(proxy_id_, remote_id, sni)) {
    ENVOY_CONN_LOG(debug,
                   "cilium.network: Pod {} network {} policy DENY on proxy_id: {} id: {} port: {} "
                   "sni: \"{}\"",
                   conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id,
                   destination_port, sni);
    return false;
  }

  // populate l7proto_ if available
  use_proxy_lib = port_policy.useProxylib(proxy_id_, remote_id, l7_proto);

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
                                                   /* INOUT */ LastNetworkPolicyCache& policy_cache,
                                                   /* INOUT */ AccessLog::Entry& log_entry) const {
  const auto& policy = policy_resolver_->getPolicy(pod_ip_);
  auto remote_id = ingress_ ? source_identity_ : destination_identity;
  auto port = ingress_ ? port_ : destination_port;

  uint64_t version = policy.version();
  const auto port_policy = policy.findPortPolicy(ingress_, port);
  bool has_http_rules = port_policy.hasHttpRules();

  if (!has_http_rules) {
    absl::optional<bool> opt = policy_cache.previousVerdict(version, remote_id, port);
    if (opt.has_value()) {
      bool verdict = opt.value();
      ENVOY_CONN_LOG(debug,
                     "cilium.l7policy: Pod {} HTTP {} policy enforcement using cached verdict {} "
                     "(no HTTP rules) on "
                     "proxy_id: {} id: {} port: {}",
                     conn, pod_ip_, ingress_ ? "ingress" : "egress", verdict ? "ALLOW" : "DENY",
                     proxy_id_, remote_id, port);
      return verdict;
    } else {
      ENVOY_CONN_LOG(debug,
                     "cilium.l7policy: Pod {} HTTP {} policy cache MISS "
                     "(version: {}/{}, id: {}/{}, port: {}/{}), not skipping.",
                     conn, pod_ip_, ingress_ ? "ingress" : "egress", version, policy_cache.version_,
                     remote_id, policy_cache.identity_, port, policy_cache.port_);
    }
  } else {
    ENVOY_CONN_LOG(debug, "cilium.l7policy: Pod {} HTTP {} policy has HTTP rules, not skipping.",
                   conn, pod_ip_, ingress_ ? "ingress" : "egress");
  }

  bool verdict = port_policy.allowed(proxy_id_, remote_id, headers, log_entry);
  if (!has_http_rules) {
    policy_cache.update(version, remote_id, port, verdict);
  }
  if (verdict == false) {
    ENVOY_CONN_LOG(debug,
                   "cilium.l7policy: Pod {} HTTP {} policy DENY on proxy_id: {} id: {} port: {}",
                   conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id, port);
  } else {
    ENVOY_CONN_LOG(debug,
                   "cilium.l7policy: Pod {} HTTP {} policy ALLOW on proxy_id: {} id: {} port: {}",
                   conn, pod_ip_, ingress_ ? "ingress" : "egress", proxy_id_, remote_id, port);
  }
  return verdict;
}

bool CiliumPolicyFilterState::enforceIngressHTTPPolicy(
    const Network::Connection& conn, uint32_t destination_identity, uint16_t destination_port,
    /* INOUT */ Http::RequestHeaderMap& headers,
    /* INOUT */ LastNetworkPolicyCache policy_cache[2],
    /* INOUT */ AccessLog::Entry& log_entry) const {
  log_entry.entry_.set_policy_name(ingress_policy_name_);
  log_entry.request_logged_ = false; // we reuse the same entry we used for the pod policy

  const auto& policy = policy_resolver_->getPolicy(ingress_policy_name_);
  uint64_t version = policy.version();

  // Enforce ingress policy for Ingress, on the original destination port
  if (ingress_source_identity_ != 0) {
    const auto port_policy = policy.findPortPolicy(true, port_);
    bool has_http_rules = port_policy.hasHttpRules();

    bool have_verdict = false;
    bool verdict;
    if (!has_http_rules) {
      absl::optional<bool> opt =
          policy_cache[0].previousVerdict(version, ingress_source_identity_, port_);
      if (opt.has_value()) {
        have_verdict = true;
        verdict = opt.value();
        ENVOY_CONN_LOG(debug,
                       "cilium.l7policy: Ingress {} HTTP ingress policy enforcement using using "
                       "cached verdict (no HTTP rules)",
                       conn, ingress_policy_name_);
      }
    }

    if (!have_verdict) {
      verdict = port_policy.allowed(proxy_id_, ingress_source_identity_, headers, log_entry);
      if (!has_http_rules) {
        policy_cache[0].update(version, ingress_source_identity_, port_, verdict);
      }
    }

    if (verdict == false) {
      ENVOY_CONN_LOG(
          debug,
          "cilium.l7policy: Ingress {} HTTP ingress policy DROP on proxy_id: {} id: {} port: {}",
          conn, ingress_policy_name_, proxy_id_, ingress_source_identity_, port_);
      return false;
    }
  }

  // Enforce egress policy for Ingress on the upstream destination identity and port
  const auto port_policy = policy.findPortPolicy(false, destination_port);
  bool has_http_rules = port_policy.hasHttpRules();

  bool have_verdict = false;
  bool verdict;
  if (!has_http_rules) {
    absl::optional<bool> opt =
        policy_cache[1].previousVerdict(version, destination_identity, destination_port);
    if (opt.has_value()) {
      have_verdict = true;
      verdict = opt.value();
      ENVOY_CONN_LOG(debug,
                     "cilium.l7policy: Ingress {} HTTP egress policy enforcement using using "
                     "cached verdict (no HTTP rules)",
                     conn, ingress_policy_name_);
    }
  }

  if (!have_verdict) {
    verdict = port_policy.allowed(proxy_id_, destination_identity, headers, log_entry);
    if (!has_http_rules) {
      policy_cache[1].update(version, destination_identity, destination_port, verdict);
    }
  }

  if (verdict == false) {
    ENVOY_CONN_LOG(
        debug,
        "cilium.l7policy: Ingress {} HTTP egress policy DROP on proxy_id: {} id: {}  port: {}",
        conn, ingress_policy_name_, proxy_id_, destination_identity, destination_port);
    return false;
  }

  // Connection allowed by policy
  ENVOY_CONN_LOG(debug,
                 "cilium.l7policy: Ingress {} HTTP policy ALLOW on proxy_id: {} id: {}  port: {}",
                 conn, ingress_policy_name_, proxy_id_, destination_identity, destination_port);
  return true;
}

} // namespace Cilium
} // namespace Envoy
