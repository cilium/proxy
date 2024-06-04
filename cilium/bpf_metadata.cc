#include "cilium/bpf_metadata.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/common/utility.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_option_factory.h"

#include "cilium/api/bpf_metadata.pb.validate.h"
#include "cilium/socket_option.h"
#include "network_policy.h"

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
    // Set the socket mark option for the listen socket.
    // Can use identity 0 on the listen socket option, as the bpf datapath is only interested
    // in whether the proxy is ingress, egress, or if there is no proxy at all.
    std::shared_ptr<Envoy::Network::Socket::Options> options =
        std::make_shared<Envoy::Network::Socket::Options>();
    uint32_t mark = (config->is_ingress_) ? 0x0A00 : 0x0B00;
    options->push_back(std::make_shared<Cilium::SocketMarkOption>(mark, 0));
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
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_host_map), [&context] {
        auto map = std::make_shared<Cilium::PolicyHostMap>(context);
        map->startSubscription(context);
        return map;
      });
}

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(Server::Configuration::FactoryContext& context, Cilium::CtMapSharedPtr& ct) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_network_policy), [&context, &ct] {
        auto map = std::make_shared<Cilium::NetworkPolicyMap>(context, ct);
        map->startSubscription();
        return map;
      });
}

} // namespace

Config::Config(const ::cilium::BpfMetadata& config,
               Server::Configuration::ListenerFactoryContext& context)
    : proxy_id_(config.proxy_id()), is_ingress_(config.is_ingress()),
      use_original_source_address_(config.use_original_source_address()),
      is_l7lb_(config.is_l7lb()),
      ipv4_source_address_(
          Network::Utility::parseInternetAddressNoThrow(config.ipv4_source_address())),
      ipv6_source_address_(
          Network::Utility::parseInternetAddressNoThrow(config.ipv6_source_address())),
      enforce_policy_on_l7lb_(config.enforce_policy_on_l7lb()) {
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
  // Note: all instances use the bpf root of the first filter with non-empty
  // bpf_root instantiated! Only try opening bpf maps if bpf root is explicitly
  // configured
  std::string bpf_root = config.bpf_root();
  if (bpf_root.length() > 0) {
    ct_maps_ = context.singletonManager().getTyped<Cilium::CtMap>(
        SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_conntrack), [&bpf_root] {
          // Even if opening the global maps fail, local maps may still succeed
          // later.
          return std::make_shared<Cilium::CtMap>(bpf_root);
        });
    ipcache_ = IPCache::NewIPCache(context.getServerFactoryContext(), bpf_root);
    if (bpf_root != ct_maps_->bpfRoot()) {
      // bpf root may not change during runtime
      throw EnvoyException(fmt::format("cilium.bpf_metadata: Invalid bpf_root: {}", bpf_root));
    }
  }
  // Only create the hosts map if ipcache can't be opened
  if (ipcache_ == nullptr) {
    hosts_ = createHostMap(context);
  }

  // Get the shared policy provider, or create it if not already created.
  // Note that the API config source is assumed to be the same for all filter
  // instances!
  npmap_ = createPolicyMap(context, ct_maps_);
}

uint32_t Config::resolvePolicyId(const Network::Address::Ip* ip) const {
  uint32_t id = 0;

  if (ipcache_ != nullptr) {
    id = ipcache_->resolve(ip);
  } else if (hosts_ != nullptr) {
    id = hosts_->resolve(ip);
  }

  // default destination identity to the world if needed
  if (id == 0) {
    id = Cilium::ID::WORLD;
    ENVOY_LOG(trace, "bpf_metadata: Identity for IP defaults to WORLD", ip->addressAsString());
  }

  return id;
}

uint32_t Config::resolveSourceIdentity(const PolicyInstanceConstSharedPtr policy,
                                       const Network::Address::Ip* sip,
                                       const Network::Address::Ip* dip, bool ingress, bool isL7LB) {
  uint32_t source_identity = 0;

  // Resolve the source security ID from conntrack map, or from ip cache
  if (ct_maps_ != nullptr) {
    if (policy) {
      const std::string& ct_name = policy->conntrackName();
      if (ct_name.length() > 0) {
        source_identity = ct_maps_->lookupSrcIdentity(ct_name, sip, dip, ingress);
      }
    } else if (isL7LB) {
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

// Returns a new IPAddressPair that keeps the source address and fills in the other address version
// from the given IPAddressPair.
IPAddressPair
Config::getIPAddressPairFrom(const Network::Address::InstanceConstSharedPtr sourceAddress,
                             const IPAddressPair& addresses) {
  auto addressPair = IPAddressPair();

  switch (sourceAddress->ip()->version()) {
  case Network::Address::IpVersion::v4:
    addressPair.ipv4_ = sourceAddress;
    if (addresses.ipv6_) {
      sockaddr_in6 sa6 = *reinterpret_cast<const sockaddr_in6*>(addresses.ipv6_->sockAddr());
      sa6.sin6_port = htons(sourceAddress->ip()->port());
      addressPair.ipv6_ = std::make_shared<Network::Address::Ipv6Instance>(sa6);
    }
    break;
  case Network::Address::IpVersion::v6:
    addressPair.ipv6_ = sourceAddress;
    if (addresses.ipv4_) {
      sockaddr_in sa4 = *reinterpret_cast<const sockaddr_in*>(addresses.ipv4_->sockAddr());
      sa4.sin_port = htons(sourceAddress->ip()->port());
      addressPair.ipv4_ = std::make_shared<Network::Address::Ipv4Instance>(&sa4);
    }
    break;
  }

  return addressPair;
}

const Network::Address::Ip* Config::selectIPVersion(const Network::Address::IpVersion version,
                                                    const IPAddressPair& source_addresses) {
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

const PolicyInstanceConstSharedPtr Config::getPolicy(const std::string& pod_ip) const {
  auto& policy = npmap_->GetPolicyInstance(pod_ip);
  if (policy == nullptr) {
    // Allow all traffic for egress without a policy when 'is_l7lb_' is true.
    // This is the case for L7 LB listeners only. This is needed to allow traffic forwarded by k8s
    // Ingress (which is implemented as an egress listener!).
    if (!enforce_policy_on_l7lb_ && !is_ingress_ && is_l7lb_) {
      return npmap_->AllowAllEgressPolicy;
    }
  }
  return policy;
}

bool Config::getMetadata(Network::ConnectionSocket& socket) {
  Network::Address::InstanceConstSharedPtr src_address =
      socket.connectionInfoProvider().remoteAddress();
  const auto sip = src_address->ip();
  const auto dst_address = socket.ioHandle().localAddress();
  const auto dip = dst_address->ip();

  if (!sip || !dip) {
    ENVOY_LOG_MISC(debug, "Non-IP addresses: src: {} dst: {}", src_address->asString(),
                   dst_address->asString());
    return false;
  }

  // We do this first as this likely restores the destination address and
  // lets the OriginalDstCluster know the destination address can be used.
  socket.connectionInfoProvider().restoreLocalAddress(dst_address); // mark as `restored`

  std::string pod_ip, other_ip;
  if (is_ingress_) {
    pod_ip = dip->addressAsString();
    other_ip = sip->addressAsString();
    ENVOY_LOG_MISC(debug, "INGRESS POD IP: {}, source IP: {}", pod_ip, other_ip);
  } else {
    pod_ip = sip->addressAsString();
    other_ip = dip->addressAsString();
    ENVOY_LOG_MISC(debug, "EGRESS POD IP: {}, destination IP: {}", pod_ip, other_ip);
  }

  // Load the policy for the Pod that sends or receives traffic.
  // Might change later on for North/South L7LB traffic.
  auto policy = getPolicy(pod_ip);

  // Resolve the source security ID from conntrack map, or from ip cache
  uint32_t source_identity = resolveSourceIdentity(policy, sip, dip, is_ingress_, is_l7lb_);

  // Resolve the destination security ID for egress traffic
  uint32_t destination_identity = is_ingress_ ? 0 : resolvePolicyId(dip);

  // ingress_source_identity is non-zero when the egress path l7 LB should also enforce
  // the ingress path policy using the original source identity.
  uint32_t ingress_source_identity = 0;

  // Use the configured IPv4/IPv6 Ingress IPs as starting point for the sources addresses
  IPAddressPair source_addresses(ipv4_source_address_, ipv6_source_address_);

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
    if (policy == nullptr || policy->getEndpointID() == 0) {
      // Local pod not found. Original source address can only be used for local pods.
      ENVOY_LOG(warn,
                "cilium.bpf_metadata (east/west L7 LB): Non-local pod can not use original "
                "source address: {}",
                pod_ip);
      return false;
    }

    // Use original source address with L7 LB for local endpoint sources if requested, as policy
    // enforcement after the proxy depends on it (i.e., for "east/west" LB).
    // Keep the original source address for the matching IP version, create a new source IP for
    // the other version (with the same source port number) in case an upstream of a different
    // IP version is chosen.
    source_addresses = getIPAddressPairFrom(src_address, policy->getEndpointIPs());

    // Original source address is now in one of 'ipv[46]_source_address'
    src_address = nullptr;
  } else if (is_l7lb_ && !use_original_source_address_ /* North/South L7 LB */) {
    // North/south L7 LB, assume the source security identity of the configured source addresses,
    // if any and policy for this identity exists.

    // Pick the local source address of the same family as the incoming connection
    const Network::Address::Ip* ip = selectIPVersion(sip->version(), source_addresses);

    if (!ip) {
      // IP family of the connection has no configured local source address
      ENVOY_LOG(warn,
                "cilium.bpf_metadata (north/south L7 LB): No local IP source address configured "
                "for the family of {}",
                pod_ip);
      return false;
    }

    pod_ip = ip->addressAsString();

    auto new_source_id = resolvePolicyId(ip);
    if (new_source_id == Cilium::ID::WORLD) {
      // No security ID available for the configured source IP
      ENVOY_LOG(warn,
                "cilium.bpf_metadata (north/south L7 LB): Unknown local IP source address "
                "configured: {}",
                pod_ip);
      return false;
    }

    // Enforce ingress policy on the incoming Ingress traffic?
    if (enforce_policy_on_l7lb_)
      ingress_source_identity = source_identity;

    source_identity = new_source_id;

    // AllowAllEgressPolicy will be returned if no explicit Ingress policy exists
    policy = getPolicy(pod_ip);

    // Original source address is never used for north/south LB
    // This means that a local host IP is used if no IP is configured to be used instead of it
    // ('ip' above is null).
    src_address = nullptr;
  } else if (!use_original_source_address_ || npmap_->exists(other_ip)) {
    // Otherwise only use the original source address if permitted and the destination is not
    // in the same node.

    // Original source address is not used
    src_address = nullptr;
  }

  // policy must exist at this point
  if (policy == nullptr) {
    ENVOY_LOG(warn, "cilium.bpf_metadata ({}): No policy found for {}",
              is_ingress_ ? "ingress" : "egress", pod_ip);
    return false;
  }

  // Add metadata for policy based listener filter chain matching.
  // This requires the TLS inspector, if used, to run before us.
  // Note: This requires egress policy be known before upstream host selection,
  // so this feature only works with the original destination cluster.
  // This means that L7 LB does not work with the experimental Envoy Metadata
  // based policies (e.g., with MongoDB or MySQL filters).
  std::string l7proto;
  uint32_t remote_id = is_ingress_ ? source_identity : destination_identity;
  if (policy->useProxylib(is_ingress_, remote_id, dip->port(), l7proto)) {
    const auto& old_protocols = socket.requestedApplicationProtocols();
    std::vector<absl::string_view> protocols;
    for (const auto& old_protocol : old_protocols) {
      protocols.emplace_back(old_protocol);
    }
    protocols.emplace_back(l7proto);
    socket.setRequestedApplicationProtocols(protocols);
    ENVOY_LOG(info, "cilium.bpf_metadata: setRequestedApplicationProtocols(..., {})", l7proto);
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
  socket.addOption(std::make_shared<Cilium::SocketOption>(
      policy, mark, ingress_source_identity, source_identity, is_ingress_, is_l7lb_, dip->port(),
      std::move(pod_ip), std::move(src_address), std::move(source_addresses.ipv4_),
      std::move(source_addresses.ipv6_), shared_from_this(), proxy_id_));

  return true;
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks& cb) {
  Network::ConnectionSocket& socket = cb.socket();
  // Cilium socket option is not set if this fails, which causes 500 response from our l7policy
  // filter. Our integration tests depend on this.
  config_->getMetadata(socket);

  // Set socket options for linger and keepalive (5 minutes).
  struct ::linger lin {
    true, 10
  };
  int keepalive = true;
  int secs = 5 * 60; // Five minutes

  auto status = socket.setSocketOption(SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
  if (status.return_value_ < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_LINGER: {}",
              Envoy::errorDetails(status.errno_));
  }
  status = socket.setSocketOption(SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
  if (status.return_value_ < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_KEEPALIVE: {}",
              Envoy::errorDetails(status.errno_));
  } else {
    status = socket.setSocketOption(IPPROTO_TCP, TCP_KEEPINTVL, &secs, sizeof(secs));
    if (status.return_value_ < 0) {
      ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPINTVL: {}",
                Envoy::errorDetails(status.errno_));
    } else {
      status = socket.setSocketOption(IPPROTO_TCP, TCP_KEEPIDLE, &secs, sizeof(secs));
      if (status.return_value_ < 0) {
        ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPIDLE: {}",
                  Envoy::errorDetails(status.errno_));
      }
    }
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Network::ListenerFilterBuffer&) {
  return Network::FilterStatus::Continue;
};

size_t Instance::maxReadBytes() const { return 0; }

} // namespace BpfMetadata
} // namespace Cilium
} // namespace Envoy
