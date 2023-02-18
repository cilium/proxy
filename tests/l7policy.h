#pragma once

#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Cilium {

class TestConfigFactory : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Http::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;

  std::string name() const override;
};

} // namespace Cilium
} // namespace Envoy
