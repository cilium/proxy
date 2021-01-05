#include "cilium/l7policy.h"
#include "cilium/api/l7policy.pb.validate.h"

#include "tests/l7policy.h"

namespace Envoy {
namespace Cilium {

Http::FilterFactoryCb
TestConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& proto_config, const std::string&,
    Server::Configuration::FactoryContext& context) {
  auto config = std::make_shared<Cilium::Config>(
      MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(proto_config, context.messageValidationVisitor()), context);
  return [config](
      Http::FilterChainFactoryCallbacks &callbacks) mutable -> void {
    callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
  };
}

ProtobufTypes::MessagePtr TestConfigFactory::createEmptyConfigProto() {
  return std::make_unique<::cilium::L7Policy>();
}

std::string TestConfigFactory::name() const { return "test_l7policy"; }

/**
 * Static registration for this filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    TestConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace Cilium
}
