#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/api/io_error.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/network/listener_filter_buffer.h"
#include "envoy/server/factory_context.h"

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/conntrack.h"
#include "cilium/host_map.h"
#include "cilium/ipcache.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option_bpf_metadata.h"
#include "socket_option_cilium_mark.h"
#include "socket_option_ip_transparent.h"
#include "socket_option_reuse_addr.h"
#include "socket_option_reuse_port.h"
#include "socket_option_source_address.h"

namespace Envoy {
namespace Cilium {
namespace BpfMetadata {

struct SocketInformation {
  SocketInformation(uint32_t ingress_source_identity, uint32_t source_identity, bool ingress,
                    bool l7lb, uint16_t port, std::string&& pod_ip,
                    const std::weak_ptr<PolicyResolver>& policy_resolver, uint32_t proxy_id,
                    absl::string_view sni, uint32_t mark,
                    Network::Address::InstanceConstSharedPtr original_source_address,
                    Network::Address::InstanceConstSharedPtr source_address_ipv4,
                    Network::Address::InstanceConstSharedPtr source_address_ipv6)
      : ingress_source_identity_(ingress_source_identity), source_identity_(source_identity),
        ingress_(ingress), is_l7lb_(l7lb), port_(port), pod_ip_(std::move(pod_ip)),
        proxy_id_(proxy_id), sni_(sni), policy_resolver_(policy_resolver), mark_(mark),
        original_source_address_(std::move(original_source_address)),
        source_address_ipv4_(std::move(source_address_ipv4)),
        source_address_ipv6_(std::move(source_address_ipv6)) {}

  std::shared_ptr<Envoy::Cilium::BpfMetadataSocketOption> buildBpfMetadataSocketOption() {
    return std::make_shared<Envoy::Cilium::BpfMetadataSocketOption>(
        ingress_source_identity_, source_identity_, ingress_, is_l7lb_, port_, std::move(pod_ip_),
        policy_resolver_, proxy_id_, sni_);
  };

  std::shared_ptr<Envoy::Cilium::CiliumMarkSocketOption> buildCiliumMarkSocketOption() {
    return std::make_shared<Envoy::Cilium::CiliumMarkSocketOption>(mark_, source_identity_);
  };

  std::shared_ptr<Envoy::Cilium::SourceAddressSocketOption> buildSourceAddressSocketOption() {
    return std::make_shared<Envoy::Cilium::SourceAddressSocketOption>(
        original_source_address_, source_address_ipv4_, source_address_ipv6_);
  };

  std::shared_ptr<Envoy::Cilium::IpTransparentSocketOption> buildIPTransparentSocketOption() {
    return std::make_shared<Envoy::Cilium::IpTransparentSocketOption>();
  };

  std::shared_ptr<Envoy::Cilium::ReuseAddrSocketOption> buildReuseAddrSocketOption() {
    return std::make_shared<Envoy::Cilium::ReuseAddrSocketOption>();
  };

  std::shared_ptr<Envoy::Cilium::ReusePortSocketOption> buildReusePortSocketOption() {
    return std::make_shared<Envoy::Cilium::ReusePortSocketOption>();
  };

  // Additional ingress policy enforcement is performed if ingress_source_identity is non-zero
  uint32_t ingress_source_identity_;
  uint32_t source_identity_;
  bool ingress_;
  bool is_l7lb_;
  uint16_t port_;
  std::string pod_ip_;
  uint32_t proxy_id_;
  std::string sni_;
  std::weak_ptr<PolicyResolver> policy_resolver_;

  uint32_t mark_;

  Network::Address::InstanceConstSharedPtr original_source_address_;
  Network::Address::InstanceConstSharedPtr source_address_ipv4_;
  Network::Address::InstanceConstSharedPtr source_address_ipv6_;
};

using SocketInformationSharedPtr = std::shared_ptr<SocketInformation>;

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
  const PolicyInstanceConstSharedPtr getPolicy(const std::string&) const override;

  virtual Cilium::BpfMetadata::SocketInformationSharedPtr
  extractSocketInformation(Network::ConnectionSocket& socket);

  virtual bool addPrivilegedSocketOptions() { return true; };

  uint32_t proxy_id_;
  bool is_ingress_;
  bool use_original_source_address_;
  bool is_l7lb_;
  Network::Address::InstanceConstSharedPtr ipv4_source_address_;
  Network::Address::InstanceConstSharedPtr ipv6_source_address_;
  bool enforce_policy_on_l7lb_;

  std::shared_ptr<const Cilium::NetworkPolicyMap> npmap_{};
  Cilium::CtMapSharedPtr ct_maps_{};
  Cilium::IPCacheSharedPtr ipcache_{};
  std::shared_ptr<const Cilium::PolicyHostMap> hosts_{};
  std::chrono::milliseconds policy_update_warning_limit_ms_;

private:
  uint32_t resolveSourceIdentity(const PolicyInstanceConstSharedPtr policy,
                                 const Network::Address::Ip* sip, const Network::Address::Ip* dip,
                                 bool ingress, bool isL7LB);

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
