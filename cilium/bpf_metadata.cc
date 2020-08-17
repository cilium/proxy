#include "cilium/bpf_metadata.h"
#include "cilium/api/bpf_metadata.pb.validate.h"

#include <string>

#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "common/network/socket_option_factory.h"
#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "cilium/socket_option.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

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
    auto config = std::make_shared<Filter::BpfMetadata::Config>(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config, context.messageValidationVisitor()), context);
    return [listener_filter_matcher, config](Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(listener_filter_matcher, std::make_unique<Filter::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() const override { return "cilium.bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<BpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace BpfMetadata {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(cilium_bpf_conntrack);
SINGLETON_MANAGER_REGISTRATION(cilium_bpf_proxymap);
SINGLETON_MANAGER_REGISTRATION(cilium_host_map);
SINGLETON_MANAGER_REGISTRATION(cilium_ipcache);
SINGLETON_MANAGER_REGISTRATION(cilium_network_policy);

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(Server::Configuration::ListenerFactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
    SINGLETON_MANAGER_REGISTERED_NAME(cilium_host_map), [&context] {
      auto map = std::make_shared<Cilium::PolicyHostMap>(
          context.localInfo(), context.clusterManager(),
	  context.dispatcher(), context.random(), context.scope(),
	  context.threadLocal());
      map->startSubscription();
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

Config::Config(const ::cilium::BpfMetadata &config, Server::Configuration::ListenerFactoryContext& context)
    : is_ingress_(config.is_ingress()),
      may_use_original_source_address_(config.may_use_original_source_address()) {
  // Note: all instances use the bpf root of the first filter with non-empty bpf_root instantiated!
  // Only try opening bpf maps if bpf root is explicitly configured
  std::string bpf_root = config.bpf_root();
  if (bpf_root.length() > 0) {
    maps_ = context.singletonManager().getTyped<Cilium::ProxyMap>(
	SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_proxymap), [&bpf_root] {
	  auto maps = std::make_shared<Cilium::ProxyMap>(bpf_root);
	  if (!maps->Open()) {
	    maps.reset();
	  }
	  return maps;
	});
    ct_maps_ = context.singletonManager().getTyped<Cilium::CtMap>(
	SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_conntrack), [&bpf_root] {
	  // Even if opening the global maps fail, local maps may still succeed later.
	  return std::make_shared<Cilium::CtMap>(bpf_root);
	});
    ipcache_ = context.singletonManager().getTyped<Cilium::IPCache>(
	SINGLETON_MANAGER_REGISTERED_NAME(cilium_ipcache), [&bpf_root] {
	  auto ipcache = std::make_shared<Cilium::IPCache>(bpf_root);
	  if (!ipcache->Open()) {
	    ipcache.reset();
	  }
	  return ipcache;
	});
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
  // Note that the API config source is assumed to be the same for all filter instances!

  npmap_ = createPolicyMap(context, ct_maps_);
}

bool Config::getMetadata(Network::ConnectionSocket& socket) {
  uint32_t source_identity = 0, destination_identity = 0;
  uint16_t orig_dport = 0, proxy_port = 0;
  Network::Address::InstanceConstSharedPtr src_address = socket.remoteAddress();
  const auto sip = src_address->ip();
  auto dip = socket.localAddress()->ip();

  if (!sip || !dip) {
    ENVOY_LOG_MISC(debug, "Non-IP addresses: src: {} dst: {}",
		   src_address->asString(), socket.localAddress()->asString());
    return false;
  }

  // Cilium < 1.6 uses REDIRECT, which NATs the destination address
  // and port. Proxymap is used to retrieve the originals, as well as
  // the source security ID.
  // Cilium >= 1.6 and sidecars use TPROXY, so the destination address
  // is not NATted.
  bool with_tproxy = (maps_ == nullptr);
  
  // We do this first as this likely restores the destination address
  if (with_tproxy) {
    // Let the OriginalDstCluster know the destination address can be used.
    socket.restoreLocalAddress(socket.localAddress()); // mark as `restored`
    orig_dport = dip->port();
  } else {
    // Proxymap ('maps_') use will be deprecated when Cilium 1.6 is the oldest
    // supported version.
    maps_->getBpfMetadata(socket, &source_identity, &orig_dport, &proxy_port);
    dip = socket.localAddress()->ip();
  }

  // Sidecars may get incorrect "ingress" config, override.
  bool is_ingress = is_ingress_;
  
  std::string pod_ip, other_ip;
  if (is_ingress) {
    pod_ip = dip->addressAsString();
    other_ip = sip->addressAsString();
  } else {
    pod_ip = sip->addressAsString();
    other_ip = dip->addressAsString();
  }

  if (npmap_->is_sidecar_ && npmap_->local_ip_str_ == other_ip) {
    is_ingress = !is_ingress;
    other_ip = pod_ip;
    pod_ip = npmap_->local_ip_str_;
  }

  if (is_ingress) {
    ENVOY_LOG_MISC(debug, "INGRESS POD IP: {}, source IP: {}", pod_ip, other_ip);
  } else {
    ENVOY_LOG_MISC(debug, "EGRESS POD IP: {}, destination IP: {}", pod_ip, other_ip);
  }

  const auto& policy = npmap_->GetPolicyInstance(pod_ip);
  if (policy == nullptr) {
    ENVOY_LOG(warn,
	      "cilium.bpf_metadata ({}): No policy found for {}",
	      is_ingress ? "ingress" : "egress", pod_ip);
    return false;
  }

  // Resolve the source security ID, if not already resolved
  if (source_identity == 0) {
    if (ct_maps_ != nullptr) {
      // Cilium >= 1.6 provides the conntrack name in the policy
      auto ct_name = policy->conntrackName();
      if (ct_name.length() > 0) {
	source_identity = ct_maps_->lookupSrcIdentity(ct_name, sip, dip, is_ingress);
      }
    }
    if (source_identity == 0) {
      if (ipcache_ != nullptr) {
	// Resolve the source security ID from the IPCache
	source_identity = ipcache_->resolve(sip);
      } else if (hosts_ != nullptr) {
	// Resolve the source security ID from xDS hosts map
	source_identity = hosts_->resolve(sip);
      }

      // default source identity to the world if needed
      if (source_identity == 0) {
	source_identity = Cilium::ID::WORLD;
	ENVOY_LOG(trace,
		  "cilium.bpf_metadata ({}): Source identity defaults to WORLD",
		  is_ingress ? "ingress" : "egress");
      }
    }
  }

  // Resolve the destination security ID for egress
  if (!is_ingress) {
    if (ipcache_ != nullptr) {
      destination_identity = ipcache_->resolve(dip);
    } else if (hosts_ != nullptr) {
      destination_identity = hosts_->resolve(dip);
    }
    // default destination identity to the world if needed
    if (destination_identity == 0) {
      destination_identity = Cilium::ID::WORLD;
      ENVOY_LOG(trace, "cilium.bpf_metadata (egress): Destination identity defaults to WORLD");
    }
  }

  // Only use the original source address if permitted and the other node is not in
  // the same node and is not classified as WORLD.
  if (may_use_original_source_address_ && destination_identity != Cilium::ID::WORLD
      && !npmap_->exists(other_ip)) {
    socket.addOptions(Network::SocketOptionFactory::buildIpTransparentOptions());
  } else {
    src_address = nullptr;
  }

  // Add metadata for policy based listener filter chain matching.
  // This requires the TLS inspector to be run before us.
  std::string l7proto;
  if (policy->useProxylib(is_ingress, orig_dport, is_ingress ? source_identity : destination_identity, l7proto)) {
    const auto& old_protocols = socket.requestedApplicationProtocols();
    std::vector<absl::string_view> protocols;
    for (const auto& old_protocol : old_protocols) {
      protocols.emplace_back(old_protocol);
    }
    protocols.emplace_back(l7proto);
    socket.setRequestedApplicationProtocols(protocols);
    ENVOY_LOG(info, "cilium.bpf_metadata: setRequestedApplicationProtocols(..., {})", l7proto);
  }

  // Pass the metadata to an Envoy socket option we can retrieve
  // later in other Cilium filters.
  socket.addOption(std::make_shared<Cilium::SocketOption>(policy, maps_, source_identity, destination_identity,
      is_ingress, orig_dport, proxy_port, std::move(pod_ip), src_address));
  return true;
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks &cb) {
  Network::ConnectionSocket &socket = cb.socket();
  config_->getMetadata(socket);

  // Set socket options for linger and keepalive (5 minutes).
  int rc;
  struct ::linger lin{ true, 10 };
  int keepalive = true;
  int secs = 5*60; // Five minutes

  rc = setsockopt(socket.ioHandle().fd(), SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
  if (rc < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_LINGER: {}", strerror(errno));
  }
  rc = setsockopt(socket.ioHandle().fd(), SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
  if (rc < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_KEEPALIVE: {}", strerror(errno));
  } else {
    rc = setsockopt(socket.ioHandle().fd(), IPPROTO_TCP, TCP_KEEPINTVL, &secs, sizeof(secs));
    if (rc < 0) {
      ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPINTVL: {}",
		strerror(errno));
    } else {
      rc = setsockopt(socket.ioHandle().fd(), IPPROTO_TCP, TCP_KEEPIDLE, &secs, sizeof(secs));
      if (rc < 0) {
	ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPIDLE: {}",
		  strerror(errno));
      }
    }
  }

  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
