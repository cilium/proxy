#include "cilium/bpf_metadata.h"
#include "cilium/api/bpf_metadata.pb.validate.h"

#include <string>

#include "common/common/assert.h"
#include "common/common/fmt.h"
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
  Network::ListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
			       Configuration::ListenerFactoryContext& context) override {
    auto config = std::make_shared<Filter::BpfMetadata::Config>(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config), context);
    // Set the socket mark option for the listen socket.
    // Can use identity 0 on the listen socket option, as the bpf datapath is only interested
    // in whether the proxy is ingress, egress, or if there is no proxy at all.
    context.addListenSocketOption(std::make_shared<Cilium::SocketMarkOption>(0, config->is_ingress_));

    return [config](Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(std::make_unique<Filter::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() override { return "cilium.bpf_metadata"; }
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
      auto map = std::make_shared<Cilium::NetworkPolicyMap>(
	  context.localInfo(), context.clusterManager(),
	  context.dispatcher(), context.random(), context.scope(),
	  context.threadLocal());
      map->startSubscription();
      map->setPolicyNotifier(ct);
      return map;
    });
}

} // namespace

Config::Config(const ::cilium::BpfMetadata &config, Server::Configuration::ListenerFactoryContext& context)
    : is_ingress_(config.is_ingress()) {
  // Note: all instances use the bpf root of the first filter with non-empty bpf_root instantiated!
  std::string bpf_root = config.bpf_root();
  if (bpf_root.length() == 0) {
    bpf_root = "/sys/fs/bpf"; // Cilium default bpf root
  }
  maps_ = context.singletonManager().getTyped<Cilium::ProxyMap>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_proxymap), [&bpf_root] {
	auto maps = std::make_shared<Cilium::ProxyMap>(bpf_root);
	if (!maps->Open()) {
	  maps.reset();
	  ENVOY_LOG_MISC(warn, "proxymap bpf map open failed.");
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
	  ENVOY_LOG_MISC(warn, "ipcache bpf map open failed.");
	}
	return ipcache;
      });
  if (bpf_root != ct_maps_->bpfRoot()) {
    // bpf root may not change during runtime
    throw EnvoyException(fmt::format("cilium.bpf_metadata: Invalid bpf_root: {}", bpf_root));
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
  uint16_t orig_dport, proxy_port;
  bool ok = false;
  const auto sip = socket.remoteAddress()->ip();
  const auto dip = socket.localAddress()->ip();

  if (!sip || !dip) {
    ENVOY_LOG_MISC(debug, "Non-IP addresses: src: {} dst: {}",
		   socket.remoteAddress()->asString(), socket.localAddress()->asString());
    return false;
  }
  
  std::string pod_ip;
  if (is_ingress_) {
    pod_ip = dip->addressAsString();
    ENVOY_LOG_MISC(debug, "INGRESS POD_IP: {}", pod_ip);
  } else {
    pod_ip = sip->addressAsString();
    ENVOY_LOG_MISC(debug, "EGRESS POD_IP: {}", pod_ip);
  }

  // Cilium >= 1.6 uses TPROXY for redirection, without NATting the
  // destination addresses. In this case we only need the source
  // security ID, which we can get from the conntrack map, but only if
  // the map name is configured (via the network policy for the pod).
  //
  // Cilium < 1.6 uses REDIRECT, which NATs the destination address
  // and port. Proxymap is used to retrieve the originals, as well as
  // the source security ID.
  //
  // Proxymap use will be deprecated when Cilium 1.6 is the oldest
  // supported version.
  //
  // The source identity is needed for both ingress and egress.
  proxy_port = 0;
  orig_dport = dip->port();
  auto ct_name = npmap_->conntrackName(pod_ip);
  if (ct_name.length() > 0) {
    ok = ct_maps_->getBpfMetadata(ct_name, socket, is_ingress_, &source_identity);
  } else if (maps_) {
    ok = maps_->getBpfMetadata(socket, &source_identity, &orig_dport, &proxy_port);
  }
  if (!ok) {
    // Mark the local address as restored, so that the original dst cluster will forward
    // without complaining. This happens only when the destination address is already correct
    // (TPROXY or sidecar).
    socket.restoreLocalAddress(socket.localAddress()); // mark as `restored`
    ENVOY_LOG_MISC(debug, "Set Local address {}, restored: {}", socket.localAddress()->asString(),
		   socket.localAddressRestored());    
  }

  // Resolve the source security ID, if not already resolved
  if (source_identity == 0) {
    if (ipcache_ != nullptr) {
      // Resolve the source security ID from the IPCache
      source_identity = ipcache_->resolve(sip);
    } else if (hosts_ != nullptr) {
      // Resolve the source security ID
      source_identity = hosts_->resolve(sip);
    }
  }
  // default source identity to the world if needed
  if (source_identity == 0) {
    source_identity = Cilium::ID::WORLD;
    ENVOY_LOG(debug,
              "cilium.bpf_metadata ({}): Source identity defaults to WORLD",
              is_ingress_ ? "ingress" : "egress");
  }

  // Resolve the destination security ID for egress
  if (!is_ingress_) {
    if (ipcache_ != nullptr) {
      destination_identity = ipcache_->resolve(dip);
    } else if (hosts_ != nullptr) {
      destination_identity = hosts_->resolve(dip);
    }
    // default destination identity to the world if needed
    if (destination_identity == 0) {
      destination_identity = Cilium::ID::WORLD;
      ENVOY_LOG(debug, "cilium.bpf_metadata (egress): Destination identity defaults to WORLD");
    }
  }

  // Pass the metadata to an Envoy socket option we can retrieve
  // later in other Cilium filters.
  socket.addOption(std::make_shared<Cilium::SocketOption>(npmap_, maps_, source_identity, destination_identity, is_ingress_, orig_dport, proxy_port, std::move(pod_ip)));

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
