#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/api/io_error.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/network/listener_filter_buffer.h"
#include "envoy/server/factory_context.h"

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/conntrack.h"
#include "cilium/filter_state_cilium_destination.h"
#include "cilium/filter_state_cilium_policy.h"
#include "cilium/host_map.h"
#include "cilium/ipcache.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option_cilium_mark.h"
#include "cilium/socket_option_source_address.h"

namespace Envoy {
namespace Cilium {
namespace BpfMetadata {

struct SocketMetadata : public Logger::Loggable<Logger::Id::filter> {
  SocketMetadata(uint32_t mark, uint32_t ingress_source_identity, uint32_t source_identity,
                 bool ingress, bool l7lb, uint16_t port, std::string&& pod_ip,
                 std::string&& ingress_policy_name,
                 Network::Address::InstanceConstSharedPtr original_source_address,
                 Network::Address::InstanceConstSharedPtr source_address_ipv4,
                 Network::Address::InstanceConstSharedPtr source_address_ipv6,
                 Network::Address::InstanceConstSharedPtr original_dest_address,
                 const std::weak_ptr<PolicyResolver>& policy_resolver, uint32_t proxy_id,
                 std::string&& proxylib_l7_proto, absl::string_view sni)
      : ingress_source_identity_(ingress_source_identity), source_identity_(source_identity),
        ingress_(ingress), is_l7lb_(l7lb), port_(port), pod_ip_(std::move(pod_ip)),
        ingress_policy_name_(std::move(ingress_policy_name)), proxy_id_(proxy_id),
        proxylib_l7_proto_(std::move(proxylib_l7_proto)), sni_(sni),
        policy_resolver_(policy_resolver), mark_(mark),
        original_source_address_(std::move(original_source_address)),
        source_address_ipv4_(std::move(source_address_ipv4)),
        source_address_ipv6_(std::move(source_address_ipv6)),
        original_dest_address_(std::move(original_dest_address)) {}

  std::shared_ptr<Envoy::Cilium::CiliumPolicyFilterState> buildCiliumPolicyFilterState() {
    return std::make_shared<Envoy::Cilium::CiliumPolicyFilterState>(
        ingress_source_identity_, source_identity_, ingress_, is_l7lb_, port_, std::move(pod_ip_),
        std::move(ingress_policy_name_), policy_resolver_, proxy_id_, sni_);
  };

  std::shared_ptr<Envoy::Cilium::CiliumDestinationFilterState> buildCiliumDestinationFilterState() {
    return std::make_shared<Envoy::Cilium::CiliumDestinationFilterState>(nullptr);
  };

  std::shared_ptr<Envoy::Cilium::CiliumMarkSocketOption> buildCiliumMarkSocketOption() {
    return std::make_shared<Envoy::Cilium::CiliumMarkSocketOption>(mark_);
  };

  std::shared_ptr<Envoy::Cilium::SourceAddressSocketOption> buildSourceAddressSocketOption(
      int linger_time, const std::shared_ptr<CiliumDestinationFilterState>& dest_fs = nullptr) {
    return std::make_shared<Envoy::Cilium::SourceAddressSocketOption>(
        source_identity_, linger_time, original_source_address_, source_address_ipv4_,
        source_address_ipv6_, dest_fs);
  };

  // Add ProxyLib L7 protocol as requested application protocol on the socket.
  void configureProxyLibApplicationProtocol(Network::ConnectionSocket& socket) {
    if (!proxylib_l7_proto_.empty()) {
      const auto& old_protocols = socket.requestedApplicationProtocols();
      std::vector<absl::string_view> protocols;
      for (const auto& old_protocol : old_protocols) {
        protocols.emplace_back(old_protocol);
      }
      protocols.emplace_back(proxylib_l7_proto_);
      socket.setRequestedApplicationProtocols(protocols);
      ENVOY_LOG(info, "cilium.bpf_metadata: setRequestedApplicationProtocols(..., {})",
                proxylib_l7_proto_);
    }
  }

  void configureOriginalDstAddress(Network::ConnectionSocket& socket) {
    if (!original_dest_address_) {
      return;
    }

    if (*original_dest_address_ == *socket.connectionInfoProvider().localAddress()) {
      // Only set the local address if it really changed, and mark it as address being restored.
      return;
    }

    // Restoration of the original destination address lets the OriginalDstCluster know the
    // destination address that can be used.
    ENVOY_LOG(trace, "Restoring local address (original destination) on socket {} ({} -> {})",
              socket.ioHandle().fdDoNotUse(),
              socket.connectionInfoProvider().localAddress()->asString(),
              original_dest_address_->asString());

    socket.connectionInfoProvider().restoreLocalAddress(original_dest_address_);
  }

  uint32_t ingress_source_identity_;
  uint32_t source_identity_;
  bool ingress_;
  bool is_l7lb_;
  uint16_t port_;
  std::string pod_ip_;              // pod policy to enforce, if any
  std::string ingress_policy_name_; // Ingress policy to enforce, if any
  uint32_t proxy_id_;
  std::string proxylib_l7_proto_;
  std::string sni_;
  std::weak_ptr<PolicyResolver> policy_resolver_;

  uint32_t mark_;

  Network::Address::InstanceConstSharedPtr original_source_address_;
  Network::Address::InstanceConstSharedPtr source_address_ipv4_;
  Network::Address::InstanceConstSharedPtr source_address_ipv6_;
  Network::Address::InstanceConstSharedPtr original_dest_address_;
};

/**
 * Global configuration for Bpf Metadata listener filter. This
 * represents all global state shared among the working thread
 * instances of the filter.
 */
class Config : public Cilium::PolicyResolver,
               public std::enable_shared_from_this<Config>,
               Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::BpfMetadata& config,
         Server::Configuration::ListenerFactoryContext& context);
  virtual ~Config() {}

  // PolicyResolver
  uint32_t resolvePolicyId(const Network::Address::Ip*) const override;
  const PolicyInstance& getPolicy(const std::string&) const override;

  virtual absl::optional<SocketMetadata> extractSocketMetadata(Network::ConnectionSocket& socket);

  // Possibility to prevent socket options that require
  // NET_ADMIN privileges from being applied. Used by tests.
  virtual bool addPrivilegedSocketOptions() { return true; };

  int so_linger_; // negative if disabled
  uint32_t proxy_id_;
  bool is_ingress_;
  bool use_original_source_address_;
  bool is_l7lb_;
  Network::Address::InstanceConstSharedPtr ipv4_source_address_;
  Network::Address::InstanceConstSharedPtr ipv6_source_address_;
  bool enforce_policy_on_l7lb_;
  std::string l7lb_policy_name_;

  std::shared_ptr<const Cilium::NetworkPolicyMap> npmap_{};
  Cilium::CtMapSharedPtr ct_maps_{};
  Cilium::IPCacheSharedPtr ipcache_{};
  std::shared_ptr<const Cilium::PolicyHostMap> hosts_{};

private:
  uint32_t resolveSourceIdentity(const PolicyInstance& policy, const Network::Address::Ip* sip,
                                 const Network::Address::Ip* dip, bool ingress, bool isL7LB);

  IPAddressPair getIPAddressPairFrom(const Network::Address::InstanceConstSharedPtr sourceAddress,
                                     const IPAddressPair& addresses);

  const Network::Address::Ip* selectIPVersion(const Network::Address::IpVersion version,
                                              const IPAddressPair& sourceAddresses);
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a bpf metadata listener filter.
 */
class Instance : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Instance(const ConfigSharedPtr& config) : config_(config) {}

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;

  // Network::ListenerFilter
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;

  // Network::ListenerFilter
  size_t maxReadBytes() const override;

private:
  const ConfigSharedPtr config_;
};

/**
 * Implementation of a UDP bpf metadata listener filter.
 */
class UdpInstance : public Network::UdpListenerReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  UdpInstance(const ConfigSharedPtr& config, Network::UdpReadFilterCallbacks& callbacks)
      : UdpListenerReadFilter(callbacks), config_(config) {}

  // Network::UdpListenerReadFilter
  Network::FilterStatus onData(Network::UdpRecvData& data) override;

  // Network::UdpListenerReadFilter
  Network::FilterStatus onReceiveError(Api::IoError::IoErrorCode error_code) override;

private:
  const ConfigSharedPtr config_;
};

} // namespace BpfMetadata
} // namespace Cilium
} // namespace Envoy
