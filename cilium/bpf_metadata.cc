#include "cilium/bpf_metadata.h"

#include <fmt/format.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/api/io_error.h"
#include "envoy/common/exception.h"
#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"
#include "envoy/network/listener_filter_buffer.h"
#include "envoy/network/socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_option_factory.h"
#include "source/common/network/socket_option_impl.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/api/bpf_metadata.pb.validate.h" // IWYU pragma: keep
#include "cilium/conntrack.h"
#include "cilium/filter_state_cilium_destination.h"
#include "cilium/filter_state_cilium_policy.h"
#include "cilium/host_map.h"
#include "cilium/ipcache.h"
#include "cilium/network_policy.h"
#include "cilium/policy_id.h"
#include "cilium/socket_option_cilium_mark.h"
#include "cilium/socket_option_ip_transparent.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class BpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message& proto_config,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Configuration::ListenerFactoryContext& context) override {

    auto config = std::make_shared<Cilium::BpfMetadata::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(
            proto_config, context.messageValidationVisitor()),
        context);

    // Set the SO_MARK (Cilium Mark), IP_TRANSPARENT & SO_REUSEADDR for the listen socket.
    std::shared_ptr<Envoy::Network::Socket::Options> options =
        std::make_shared<Envoy::Network::Socket::Options>();

    // For the listener socket, the BPF datapath is only interested
    // in whether the proxy is ingress, egress, or if there is no proxy at all.
    uint32_t mark = (config->is_ingress_) ? 0x0A00 : 0x0B00;
    options->push_back(std::make_shared<Cilium::CiliumMarkSocketOption>(mark));

    options->push_back(std::make_shared<Cilium::IpTransparentSocketOption>());

    options->push_back(std::make_shared<Envoy::Network::SocketOptionImpl>(
        envoy::config::core::v3::SocketOption::STATE_PREBIND,
        Envoy::Network::SocketOptionName(SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR"), 1));

    // SO_REUSEPORT for the listener socket is set via Envoy config

    context.addListenSocketOptions(options);

    return [listener_filter_matcher,
            config](Network::ListenerFilterManager& filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(listener_filter_matcher,
                                     std::make_unique<Cilium::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() const override { return "cilium.bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 * Versioning started from 1.1.0 for Cilium version 1.12.0.
 */
REGISTER_FACTORY(BpfMetadataConfigFactory,
                 NamedListenerFilterConfigFactory){FACTORY_VERSION(1, 1, 0, {{}})};

/**
 * Config registration for the UDP bpf metadata filter. @see
 * NamedUdpListenerFilterConfigFactory.
 */
class UdpBpfMetadataConfigFactory : public NamedUdpListenerFilterConfigFactory {
public:
  // NamedUdpListenerFilterConfigFactory
  Network::UdpListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               Configuration::ListenerFactoryContext& context) override {

    auto config = std::make_shared<Cilium::BpfMetadata::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(
            proto_config, context.messageValidationVisitor()),
        context);

    // Set the SO_MARK (Cilium Mark), IP_TRANSPARENT & SO_REUSEADDR for the listen socket.
    std::shared_ptr<Envoy::Network::Socket::Options> options =
        std::make_shared<Envoy::Network::Socket::Options>();

    // For the listener socket, the BPF datapath is only interested
    // in whether the proxy is ingress, egress, or if there is no proxy at all.
    uint32_t mark = (config->is_ingress_) ? 0x0A00 : 0x0B00;
    options->push_back(std::make_shared<Cilium::CiliumMarkSocketOption>(mark));

    options->push_back(std::make_shared<Cilium::IpTransparentSocketOption>());

    options->push_back(std::make_shared<Envoy::Network::SocketOptionImpl>(
        envoy::config::core::v3::SocketOption::STATE_PREBIND,
        Envoy::Network::SocketOptionName(SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR"), 1));

    // SO_REUSEPORT for the listener socket is set via Envoy config

    context.addListenSocketOptions(options);

    return [config](Network::UdpListenerFilterManager& udp_listener_filter_manager,
                    Network::UdpReadFilterCallbacks& callbacks) mutable -> void {
      udp_listener_filter_manager.addReadFilter(
          std::make_unique<Cilium::BpfMetadata::UdpInstance>(config, callbacks));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() const override { return "cilium.bpf_metadata"; }
};

/**
 * Static registration for the UDP bpf metadata filter. @see RegisterFactory.
 */
REGISTER_FACTORY(UdpBpfMetadataConfigFactory,
                 NamedUdpListenerFilterConfigFactory){FACTORY_VERSION(1, 1, 0, {{}})};

} // namespace Configuration
} // namespace Server

namespace Cilium {
namespace BpfMetadata {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(cilium_bpf_conntrack);
SINGLETON_MANAGER_REGISTRATION(cilium_host_map);
SINGLETON_MANAGER_REGISTRATION(cilium_network_policy);

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(Server::Configuration::ListenerFactoryContext& context) {
  return context.serverFactoryContext().singletonManager().getTyped<const Cilium::PolicyHostMap>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_host_map), [&context] {
        auto map = std::make_shared<Cilium::PolicyHostMap>(context.serverFactoryContext());
        map->startSubscription(context.serverFactoryContext());
        return map;
      });
}

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(Server::Configuration::FactoryContext& context, Cilium::CtMapSharedPtr& ct) {
  return context.serverFactoryContext().singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_network_policy),
      [&context, &ct] { return std::make_shared<Cilium::NetworkPolicyMap>(context, ct); });
}

} // namespace

Config::Config(const ::cilium::BpfMetadata& config,
               Server::Configuration::ListenerFactoryContext& context)
    : so_linger_(config.has_original_source_so_linger_time()
                     ? config.original_source_so_linger_time()
                     : -1),
      proxy_id_(config.proxy_id()), is_ingress_(config.is_ingress()),
      use_original_source_address_(config.use_original_source_address()),
      is_l7lb_(config.is_l7lb()),
      ipv4_source_address_(
          Network::Utility::parseInternetAddressNoThrow(config.ipv4_source_address())),
      ipv6_source_address_(
          Network::Utility::parseInternetAddressNoThrow(config.ipv6_source_address())),
      enforce_policy_on_l7lb_(config.enforce_policy_on_l7lb()),
      l7lb_policy_name_(config.l7lb_policy_name()),
      ipcache_entry_ttl_(
          PROTOBUF_GET_MS_OR_DEFAULT(config, cache_entry_ttl, DEFAULT_CACHE_ENTRY_TTL_MS)),
      random_(context.serverFactoryContext().api().randomGenerator()) {
  if (is_l7lb_ && is_ingress_) {
    throw EnvoyException("cilium.bpf_metadata: is_l7lb may not be set with is_ingress");
  }
  if ((ipv4_source_address_ &&
       ipv4_source_address_->ip()->version() != Network::Address::IpVersion::v4) ||
      (!ipv4_source_address_ && config.ipv4_source_address().length() > 0)) {
    throw EnvoyException(
        fmt::format("cilium.bpf_metadata: ipv4_source_address is not an IPv4 address: {}",
                    config.ipv4_source_address()));
  }
  if ((ipv6_source_address_ &&
       ipv6_source_address_->ip()->version() != Network::Address::IpVersion::v6) ||
      (!ipv6_source_address_ && config.ipv6_source_address().length() > 0)) {
    throw EnvoyException(
        fmt::format("cilium.bpf_metadata: ipv6_source_address is not an IPv6 address: {}",
                    config.ipv6_source_address()));
  }

  if (config.use_nphds()) {
    hosts_ = createHostMap(context);
  }

  // Note: all instances use the bpf root of the first filter with non-empty
  // bpf_root instantiated! Only try opening bpf maps if bpf root is explicitly
  // configured
  std::string bpf_root = config.bpf_root();
  if (bpf_root.length() > 0) {
    ct_maps_ = context.serverFactoryContext().singletonManager().getTyped<Cilium::CtMap>(
        SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_conntrack), [&bpf_root] {
          // Even if opening the global maps fail, local maps may still succeed
          // later.
          return std::make_shared<Cilium::CtMap>(bpf_root);
        });

    if (bpf_root != ct_maps_->bpfRoot()) {
      // bpf root may not change during runtime
      throw EnvoyException(fmt::format("cilium.bpf_metadata: Invalid bpf_root: {}", bpf_root));
    }

    if (!hosts_) {
      std::string ipcache_name = "cilium_ipcache";
      if (config.ipcache_name().length() > 0) {
        ipcache_name = config.ipcache_name();
      }
      ipcache_ = IpCache::newIpCache(
          context.serverFactoryContext(), bpf_root + "/tc/globals/" + ipcache_name,
          std::chrono::milliseconds(PROTOBUF_GET_MS_OR_DEFAULT(config, cache_gc_interval,
                                                               10 * DEFAULT_CACHE_ENTRY_TTL_MS)));
    }
  }

  // Get the shared policy provider, or create it if not already created.
  // Note that the API config source is assumed to be the same for all filter
  // instances!
  // Only created if either ipcache_ or hosts_ map exists
  if (ipcache_ || hosts_) {
    npmap_ = createPolicyMap(context, ct_maps_);
  }
}

uint32_t Config::resolvePolicyId(const Network::Address::Ip* ip) const {
  uint32_t id = 0;

  if (hosts_ != nullptr) {
    id = hosts_->resolve(ip);
  } else if (ipcache_ != nullptr) {
    std::chrono::microseconds ttl = ipcache_entry_ttl_;
    // subtract random jitter (0-1ms) if configured as at least 1ms
    if (ttl >= std::chrono::milliseconds(1)) {
      ttl -= std::chrono::microseconds(random_.random() % 1000);
    }
    id = ipcache_->resolve(ip, ttl);
  }

  // default destination identity to the world if needed
  if (id == 0) {
    id = Cilium::ID::WORLD;
    ENVOY_LOG(trace, "bpf_metadata: Identity for IP defaults to WORLD", ip->addressAsString());
  }

  return id;
}

uint32_t Config::resolveSourceIdentity(const PolicyInstance& policy,
                                       const Network::Address::Ip* sip,
                                       const Network::Address::Ip* dip, bool ingress,
                                       bool is_l7_lb) {
  uint32_t source_identity = 0;

  // Resolve the source security ID from conntrack map, or from ip cache
  if (ct_maps_ != nullptr) {
    const std::string& ct_name = policy.conntrackName();
    if (ct_name.length() > 0) {
      source_identity = ct_maps_->lookupSrcIdentity(ct_name, sip, dip, ingress);
    } else if (is_l7_lb) {
      // non-local source should be in the global conntrack
      source_identity = ct_maps_->lookupSrcIdentity("global", sip, dip, ingress);
    }
  }
  // Fall back to ipcache lookup if conntrack entry can not be located
  if (source_identity == 0) {
    source_identity = resolvePolicyId(sip);
  }

  return source_identity;
}

// Returns a new IpAddressPair that fills the port from 'source_address'.
IpAddressPair Config::getIpAddressPairWithPort(uint16_t port, const IpAddressPair& addresses) {
  auto address_pair = IpAddressPair();

  if (addresses.ipv6_) {
    sockaddr_in6 sa6 = *reinterpret_cast<const sockaddr_in6*>(addresses.ipv6_->sockAddr());
    sa6.sin6_port = htons(port);
    address_pair.ipv6_ = std::make_shared<Network::Address::Ipv6Instance>(sa6);
  }
  if (addresses.ipv4_) {
    sockaddr_in sa4 = *reinterpret_cast<const sockaddr_in*>(addresses.ipv4_->sockAddr());
    sa4.sin_port = htons(port);
    address_pair.ipv4_ = std::make_shared<Network::Address::Ipv4Instance>(&sa4);
  }

  return address_pair;
}

const Network::Address::Ip* Config::selectIpVersion(const Network::Address::IpVersion version,
                                                    const IpAddressPair& source_addresses) {
  switch (version) {
  case Network::Address::IpVersion::v4:
    if (source_addresses.ipv4_) {
      return source_addresses.ipv4_->ip();
    }
    break;
  case Network::Address::IpVersion::v6:
    if (source_addresses.ipv6_) {
      return source_addresses.ipv6_->ip();
    }
    break;
  }

  return nullptr;
}

const PolicyInstance& Config::getPolicy(const std::string& pod_ip) const {
  // Allow all traffic for egress without a policy when 'is_l7lb_' is true,
  // or if configured without bpf (npmap_ == nullptr).
  // This is the case for L7 LB listeners only. This is needed to allow traffic forwarded by Cilium
  // Ingress (which is implemented as an egress listener!).
  bool allow_egress = !enforce_policy_on_l7lb_ && !is_ingress_ && is_l7lb_;
  if (npmap_ == nullptr) {
    return allow_egress ? NetworkPolicyMap::getAllowAllEgressPolicy()
                        : NetworkPolicyMap::getDenyAllPolicy();
  }

  return npmap_->getPolicyInstance(pod_ip, allow_egress);
}

bool Config::exists(const std::string& pod_ip) const { return npmap_->exists(pod_ip); }

absl::optional<Cilium::BpfMetadata::SocketMetadata>
Config::extractSocketMetadata(Network::ConnectionSocket& socket) {
  Network::Address::InstanceConstSharedPtr src_address =
      socket.connectionInfoProvider().remoteAddress();
  const auto sip = src_address->ip();
  const auto dst_address = THROW_OR_RETURN_VALUE(socket.ioHandle().localAddress(),
                                                 Network::Address::InstanceConstSharedPtr);
  const auto dip = dst_address->ip();
  auto sni = socket.requestedServerName();

  if (!sip || !dip) {
    ENVOY_LOG(debug, "Non-IP addresses: src: {} dst: {}", src_address->asString(),
              dst_address->asString());
    return absl::nullopt;
  }

  std::string pod_ip, other_ip, ingress_policy_name;
  if (is_ingress_) {
    pod_ip = dip->addressAsString();
    other_ip = sip->addressAsString();
    ENVOY_LOG(debug, "INGRESS POD IP: {}, source IP: {}, sni: \"{}\"", pod_ip, other_ip, sni);
  } else {
    pod_ip = sip->addressAsString();
    other_ip = dip->addressAsString();
    ENVOY_LOG(debug, "EGRESS POD IP: {}, destination IP: {} sni: \"{}\"", pod_ip, other_ip, sni);
  }

  // Load the policy for the Pod that sends or receives traffic.
  // Might change later on for North/South L7LB traffic.
  // Use a pointer as we may need to change the policy in the case of "North/South L7 LB" below.
  const auto* policy = &getPolicy(pod_ip);

  // Resolve the source security ID from conntrack map, or from ip cache
  uint32_t source_identity = resolveSourceIdentity(*policy, sip, dip, is_ingress_, is_l7lb_);

  // Resolve the destination security ID for egress traffic
  uint32_t destination_identity = is_ingress_ ? 0 : resolvePolicyId(dip);

  // ingress_source_identity is non-zero when the egress path l7 LB should also enforce
  // the ingress path policy using the original source identity.
  uint32_t ingress_source_identity = 0;

  // Use the configured IPv4/IPv6 Ingress IPs as starting point for the sources addresses
  IpAddressPair source_addresses(ipv4_source_address_, ipv6_source_address_);

  // NOTE: As L7 LB does not use the original destination, there is a possibility of a 5-tuple
  // collision if the same source pod is communicating with the same backends on same destination
  // port directly, maybe via some other, non-L7 LB service. We keep the original source port number
  // to not allocate random source ports for the source pod in the host networking namespace that
  // could then blackhole existing connections between the source pod and the backend. This means
  // that the L7 LB backend connection may fail in case of a 5-tuple collision that the host
  // networking namespace is aware of.

  if (is_l7lb_ && use_original_source_address_ /* East/West L7LB */) {
    // In case of east/west, L7 LB is only used for egress, so the local
    // endpoint is the source, and the other node is the destination.
    if (policy->getEndpointID() == 0) {
      // Local pod not found. Original source address can only be used for local pods.
      ENVOY_LOG(warn,
                "cilium.bpf_metadata (east/west L7 LB): Non-local pod can not use original "
                "source address: {}",
                pod_ip);
      return absl::nullopt;
    }
    // Use original source address with L7 LB for local endpoint sources if requested, as policy
    // enforcement after the proxy depends on it (i.e., for "east/west" LB).
    source_addresses =
        getIpAddressPairWithPort(src_address->ip()->port(), policy->getEndpointIPs());
  } else if (is_l7lb_ && !use_original_source_address_ /* North/South L7 LB */) {
    // North/south L7 LB, assume the source security identity of the configured source addresses,
    // if any and policy for this identity exists.

    // Pick the local ingress source address of the same family as the incoming connection
    const Network::Address::Ip* ingress_ip = selectIpVersion(sip->version(), source_addresses);

    if (!ingress_ip) {
      // IP family of the connection has no configured local ingress source address
      ENVOY_LOG(
          warn,
          "cilium.bpf_metadata (north/south L7 LB): No local Ingress IP source address configured "
          "for the family of {}",
          sip->addressAsString());
      return absl::nullopt;
    }

    // Enforce pod policy only for local pods.
    if (policy->getEndpointID() == 0) {
      pod_ip = ""; // source is not a local pod
    }

    // Enforce Ingress policy?
    if (enforce_policy_on_l7lb_) {
      ingress_source_identity = source_identity;
      ingress_policy_name =
          l7lb_policy_name_.empty() ? ingress_ip->addressAsString() : l7lb_policy_name_;
    }

    // Resolve source identity for the Ingress address
    source_identity = resolvePolicyId(ingress_ip);
    if (source_identity == Cilium::ID::WORLD) {
      // No security ID available for the configured source IP
      ENVOY_LOG(warn,
                "cilium.bpf_metadata (north/south L7 LB): Unknown local Ingress IP source address "
                "configured: {}",
                ingress_ip->addressAsString());
      return absl::nullopt;
    }

    // Original source address is never used for north/south LB
    src_address = nullptr;
  } else if (!use_original_source_address_ || (npmap_ != nullptr && npmap_->exists(other_ip))) {
    // Otherwise only use the original source address if permitted and the destination is not
    // in the same node.
    //
    // If bpf root is not configured (npmap_ == nullptr) we assume all destinations are non-local!
    //
    // Original source address is not used
    src_address = nullptr;
  }

  // Evaluating proxylib L7 protocol for later usage in filter chain matching.
  // This requires the TLS inspector, if used, to run before us.
  // Note: This requires egress policy be known before upstream host selection,
  // so this feature only works with the original destination cluster.
  // This means that L7 LB does not work with the experimental Envoy Metadata
  // based policies (e.g., with MongoDB or MySQL filters).
  std::string proxylib_l7proto;
  uint32_t remote_id = is_ingress_ ? source_identity : destination_identity;
  if (policy->useProxylib(is_ingress_, proxy_id_, remote_id, dip->port(), proxylib_l7proto)) {
    ENVOY_LOG(trace, "cilium.bpf_metadata: detected proxylib l7 proto: {}", proxylib_l7proto);
  }

  // Pass the metadata to an Envoy socket option we can retrieve later in other
  // Cilium filters.
  uint32_t mark = 0;

  if (is_l7lb_ && use_original_source_address_ /* E/W L7LB */) {
    // Mark with source endpoint ID for east/west l7 LB. This causes the upstream packets to be
    // processed by the the source endpoint's policy enforcement in the datapath.
    mark = 0x0900 | policy->getEndpointID() << 16;
  } else {
    // Mark with source identity
    uint32_t cluster_id = (source_identity >> 16) & 0xFF;
    uint32_t identity_id = (source_identity & 0xFFFF) << 16;
    mark = ((is_ingress_) ? 0x0A00 : 0x0B00) | cluster_id | identity_id;
  }

  ENVOY_LOG(trace,
            "cilium.bpf_metadata: mark {}, ingress_source_identity {}, source_identity {}, "
            "is_ingress {}, is_l7lb_ {}, ingress_policy_name {}, port {}, pod_ip {}",
            mark, ingress_source_identity, source_identity, is_ingress_, is_l7lb_,
            ingress_policy_name, dip->port(), pod_ip);
  return {Cilium::BpfMetadata::SocketMetadata(
      mark, ingress_source_identity, source_identity, is_ingress_, is_l7lb_, dip->port(),
      std::move(pod_ip), std::move(ingress_policy_name), std::move(src_address),
      std::move(source_addresses.ipv4_), std::move(source_addresses.ipv6_), std::move(dst_address),
      shared_from_this(), proxy_id_, std::move(proxylib_l7proto), sni)};
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks& cb) {
  Network::ConnectionSocket& socket = cb.socket();
  ENVOY_LOG(trace, "onAccept (socket={})", socket.ioHandle().fdDoNotUse());

  Network::Socket::OptionsSharedPtr socket_options =
      std::make_shared<std::vector<Network::Socket::OptionConstSharedPtr>>();

  // Cilium socket option is not set if this fails, which causes 500 response from our l7policy
  // filter. Our integration tests depend on this.
  auto socket_metadata = config_->extractSocketMetadata(socket);
  if (socket_metadata) {

    // Setting proxy lib application protocol on downstream socket
    socket_metadata->configureProxyLibApplicationProtocol(socket);

    // Restoring original destination address on downstream socket
    socket_metadata->configureOriginalDstAddress(socket);

    // Make Cilium Policy data available to filters and upstream connection (Cilium TLS Wrapper) as
    // filter state.
    const auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
    cb.filterState().setData(
        Cilium::CiliumPolicyFilterState::key(), policy_fs,
        StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection,
        StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnection);

    const auto dest_fs = socket_metadata->buildCiliumDestinationFilterState();
    cb.filterState().setData(
        Cilium::CiliumDestinationFilterState::key(), dest_fs,
        StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection,
        StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnection);

    // Restoring original source address on the upstream socket
    socket_options->push_back(
        socket_metadata->buildSourceAddressSocketOption(config_->so_linger_, dest_fs, policy_fs));

    if (config_->addPrivilegedSocketOptions()) {
      // adding SO_MARK (Cilium mark) on the upstream socket
      socket_options->push_back(socket_metadata->buildCiliumMarkSocketOption());
    }
  }

  if (config_->addPrivilegedSocketOptions()) {
    // Setting IP_TRANSPARENT on upstream socket to be able to restore original source address
    socket_options->push_back(std::make_shared<Envoy::Cilium::IpTransparentSocketOption>());
  }

  // allow reuse of the original source address by setting SO_REUSEADDR.
  // This may by needed for retries to not fail on "address already in use"
  // when using a specific source address and port.
  socket_options->push_back(std::make_shared<Envoy::Network::SocketOptionImpl>(
      envoy::config::core::v3::SocketOption::STATE_PREBIND,
      Envoy::Network::SocketOptionName(SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR"), 1));

  // reuse port for forwarded client connections (SO_REUSEPORT)
  Network::Socket::appendOptions(socket_options,
                                 Network::SocketOptionFactory::buildReusePortOptions());

  // Adding SocketOptions to the downstream socket. The function `setOption` is NOT executed
  // on the downstream socket itself - it's executed later on the corresponding upstream socket!
  socket.addOptions(socket_options);

  // set keep alive socket options on accepted connection socket
  // (SO_KEEPALIVE, TCP_KEEPINTVL, TCP_KEEPIDLE)
  int keepalive = true;
  int secs = 5 * 60; // Five minutes

  auto status = socket.setSocketOption(SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
  if (status.return_value_ < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_KEEPALIVE: {}",
              Envoy::errorDetails(status.errno_));
    return Network::FilterStatus::StopIteration;
  }

  status = socket.setSocketOption(IPPROTO_TCP, TCP_KEEPINTVL, &secs, sizeof(secs));
  if (status.return_value_ < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPINTVL: {}",
              Envoy::errorDetails(status.errno_));
    return Network::FilterStatus::StopIteration;
  }

  status = socket.setSocketOption(IPPROTO_TCP, TCP_KEEPIDLE, &secs, sizeof(secs));
  if (status.return_value_ < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPIDLE: {}",
              Envoy::errorDetails(status.errno_));
    return Network::FilterStatus::StopIteration;
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Network::ListenerFilterBuffer&) {
  return Network::FilterStatus::Continue;
};

size_t Instance::maxReadBytes() const { return 0; }

Network::FilterStatus UdpInstance::onData([[maybe_unused]] Network::UdpRecvData& data) {
  return Network::FilterStatus::Continue;
}

Network::FilterStatus
UdpInstance::onReceiveError([[maybe_unused]] Api::IoError::IoErrorCode error_code) {
  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Cilium
} // namespace Envoy
