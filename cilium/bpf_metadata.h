#pragma once

#include "envoy/api/io_error.h"
#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"

#include "source/common/common/logger.h"

#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/conntrack.h"
#include "cilium/host_map.h"
#include "cilium/ipcache.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option.h"

namespace Envoy {
namespace Cilium {
namespace BpfMetadata {

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

  virtual Cilium::SocketOptionSharedPtr getMetadata(Network::ConnectionSocket& socket);

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
