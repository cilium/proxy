#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/network/address.h"
#include "envoy/network/listen_socket.h"
#include "envoy/server/factory_context.h"

#include "cilium/bpf_metadata.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"
#include "tests/bpf_metadata.pb.h"

namespace Envoy {

extern std::string host_map_config;
extern std::shared_ptr<const Cilium::PolicyHostMap> hostmap;

extern Network::Address::InstanceConstSharedPtr original_dst_address;
extern std::shared_ptr<const Cilium::NetworkPolicyMap> npmap;

extern std::string policy_config;
extern std::string policy_path;
extern std::vector<std::pair<std::string, std::string>> sds_configs;

extern void initTestMaps(Server::Configuration::ListenerFactoryContext& context);

namespace Cilium {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::TestBpfMetadata& config,
             Server::Configuration::ListenerFactoryContext& context);
  ~TestConfig();

  Cilium::BpfMetadata::SocketInformationSharedPtr
  extractSocketInformation(Network::ConnectionSocket& socket) override;

  bool addPrivilegedSocketOptions() override { return false; };
};

} // namespace BpfMetadata
} // namespace Cilium
} // namespace Envoy
