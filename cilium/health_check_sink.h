#pragma once

#include "envoy/upstream/health_check_event_sink.h"

#include "cilium/api/health_check_sink.pb.h"
#include "cilium/api/health_check_sink.pb.validate.h"
#include "cilium/uds_client.h"

namespace Envoy {
namespace Cilium {

class HealthCheckEventPipeSinkFactory;

class HealthCheckEventPipeSink : public Upstream::HealthCheckEventSink {
public:
  void log(envoy::data::core::v3::HealthCheckEvent event) override;

protected:
  friend class HealthCheckEventPipeSinkFactory;
  friend class HealthCheckEventPipeSink_logTest_Test;
  explicit HealthCheckEventPipeSink(const cilium::HealthCheckEventPipeSink& config);

private:
  static Thread::MutexBasicLockable udss_mutex;
  static std::map<std::string, std::weak_ptr<UDSClient>> udss ABSL_GUARDED_BY(udss_mutex);

  std::shared_ptr<UDSClient> uds_client_;
};

class HealthCheckEventPipeSinkFactory : public Upstream::HealthCheckEventSinkFactory {
public:
  HealthCheckEventPipeSinkFactory() = default;

  Upstream::HealthCheckEventSinkPtr
  createHealthCheckEventSink(const ProtobufWkt::Any& config,
                             Server::Configuration::HealthCheckerFactoryContext& context) override;

  std::string name() const override { return "cilium.health_check.event_sink.pipe"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new cilium::HealthCheckEventPipeSink()};
  }
};

} // namespace Cilium
} // namespace Envoy
