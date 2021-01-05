#pragma once

#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/network/listen_socket.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/filter_config.h"

#include "cilium/bpf_metadata.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"

namespace Envoy {

extern std::string host_map_config;
extern std::shared_ptr<const Cilium::PolicyHostMap> hostmap;

extern Network::Address::InstanceConstSharedPtr original_dst_address;
extern std::shared_ptr<const Cilium::NetworkPolicyMap> npmap;

extern std::string policy_config;

namespace Filter {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::BpfMetadata& config, Server::Configuration::ListenerFactoryContext& context);
  ~TestConfig();

  bool getMetadata(Network::ConnectionSocket &socket) override;
};

class TestInstance : public Instance {
public:
  TestInstance(const ConfigSharedPtr& config);
};

} // namespace BpfMetadata
} // namespace Filter

namespace Server {
namespace Configuration {

class TestBpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb
  createListenerFilterFactoryFromProto(const Protobuf::Message& proto_config,
				       const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
				       ListenerFactoryContext &context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override;
};

} // namespace Configuration
} // namespace Server

}
