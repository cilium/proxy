#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/network/address.h"
#include "envoy/network/listen_socket.h"
#include "envoy/server/factory_context.h"

#include "absl/types/optional.h"
#include "cilium/bpf_metadata.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"
#include "tests/bpf_metadata.pb.h"

namespace Envoy {

extern std::string host_map_config;
extern std::shared_ptr<Cilium::PolicyHostMap> hostmap;

extern Network::Address::InstanceConstSharedPtr original_dst_address;
extern std::shared_ptr<Cilium::NetworkPolicyMap> npmap;

extern std::string policy_config;
extern std::string policy_path;
extern std::vector<std::pair<std::string, std::string>> sds_configs;

namespace Cilium {

struct TestHelper {
  static std::shared_ptr<Cilium::PolicyHostMap>
  createHostMap(const std::string& config, Server::Configuration::ListenerFactoryContext&);
  static std::shared_ptr<Cilium::NetworkPolicyMap>
  createPolicyMap(const std::string& config,
                  const std::vector<std::pair<std::string, std::string>>& secret_configs,
                  Server::Configuration::FactoryContext&);
  static void initTestMaps(Server::Configuration::ListenerFactoryContext&);
};

namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::TestBpfMetadata& config,
             Server::Configuration::ListenerFactoryContext& context);
  ~TestConfig() override;

  absl::optional<Cilium::BpfMetadata::SocketMetadata>
  extractSocketMetadata(Network::ConnectionSocket& socket) override;

  // Prevent socket options that require NET_ADMIN privileges from being applied during test
  // execution.
  bool addPrivilegedSocketOptions() override { return false; };
};

} // namespace BpfMetadata
} // namespace Cilium
} // namespace Envoy
