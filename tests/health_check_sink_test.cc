#include "envoy/registry/registry.h"

#include "source/common/common/logger.h"
#include "source/common/protobuf/message_validator_impl.h"

#include "test/mocks/access_log/mocks.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/server/health_checker_factory_context.h"
#include "test/test_common/utility.h"

#include "cilium/api/health_check_sink.pb.h"
#include "cilium/api/health_check_sink.pb.validate.h"
#include "cilium/health_check_sink.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tests/health_check_sink_server.h"

using testing::SaveArg;

namespace Envoy {
namespace Cilium {

TEST(HealthCheckEventPipeSinkFactory, createHealthCheckEventSink) {
  auto factory =
      Envoy::Registry::FactoryRegistry<Upstream::HealthCheckEventSinkFactory>::getFactory(
          "cilium.health_check.event_sink.pipe");
  EXPECT_NE(factory, nullptr);

  cilium::HealthCheckEventPipeSink config;
  config.set_path("test_path");
  Envoy::ProtobufWkt::Any typed_config;
  typed_config.PackFrom(config);

  NiceMock<Server::Configuration::MockHealthCheckerFactoryContext> context;
  EXPECT_NE(factory->createHealthCheckEventSink(typed_config, context), nullptr);
}

TEST(HealthCheckEventPipeSinkFactory, createEmptyHealthCheckEventSink) {
  auto factory =
      Envoy::Registry::FactoryRegistry<Upstream::HealthCheckEventSinkFactory>::getFactory(
          "cilium.health_check.event_sink.pipe");
  EXPECT_NE(factory, nullptr);
  auto empty_proto = factory->createEmptyConfigProto();
  auto config = *dynamic_cast<cilium::HealthCheckEventPipeSink*>(empty_proto.get());
  EXPECT_TRUE(config.path().empty());
}

TEST(HealthCheckEventPipeSink, logTest) {
  for (Logger::Logger& logger : Logger::Registry::loggers()) {
    logger.setLevel(spdlog::level::trace);
  }

  // Set up server
  std::string normal_path("test_path");
  HealthCheckSinkServer eventSink(normal_path);

  // Set up client
  cilium::HealthCheckEventPipeSink config;
  config.set_path(normal_path);
  HealthCheckEventPipeSink pipe_sink(config);

  envoy::data::core::v3::HealthCheckEvent eject_event;
  TestUtility::loadFromYaml(R"EOF(
  health_checker_type: HTTP
  host:
    socket_address:
      protocol: TCP
      address: 10.0.0.1
      resolver_name: ''
      ipv4_compat: false
      port_value: 443
  cluster_name: fake_cluster
  eject_unhealthy_event:
    failure_type: ACTIVE
  timestamp: '2009-02-13T23:31:31.234Z'
  )EOF",
                            eject_event);

  pipe_sink.log(eject_event);
  EXPECT_TRUE(
      eventSink.expectEventTo([&](const envoy::data::core::v3::HealthCheckEvent& observed_event) {
        return Protobuf::util::MessageDifferencer::Equals(observed_event, eject_event);
      }));

  // Set up 2nd client on the same socket
  HealthCheckEventPipeSink pipe_sink2(config);

  envoy::data::core::v3::HealthCheckEvent add_event;
  TestUtility::loadFromYaml(R"EOF(
  health_checker_type: HTTP
  host:
    socket_address:
      protocol: TCP
      address: 10.0.0.1
      resolver_name: ''
      ipv4_compat: false
      port_value: 443
  cluster_name: fake_cluster
  add_healthy_event:
    first_check: false
  timestamp: '2009-02-13T23:31:31.234Z'
  )EOF",
                            add_event);

  pipe_sink2.log(add_event);
  EXPECT_TRUE(
      eventSink.expectEventTo([&](const envoy::data::core::v3::HealthCheckEvent& observed_event) {
        return Protobuf::util::MessageDifferencer::Equals(observed_event, add_event);
      }));

  // Set up another server on a different socket in an abstract namespace
  // Set up server
#define ABSTRACT_PATH "@another\0test_path"
  std::string abstract_name(ABSTRACT_PATH, sizeof(ABSTRACT_PATH) - 1);
  HealthCheckSinkServer eventSink3(abstract_name);

  // Set up 3rd client on a different socket
  cilium::HealthCheckEventPipeSink config3;
  config3.set_path(abstract_name);
  HealthCheckEventPipeSink pipe_sink3(config3);

  pipe_sink3.log(eject_event);
  EXPECT_TRUE(
      eventSink3.expectEventTo([&](const envoy::data::core::v3::HealthCheckEvent& observed_event) {
        return Protobuf::util::MessageDifferencer::Equals(observed_event, eject_event);
      }));
}

} // namespace Cilium
} // namespace Envoy
