#include "cilium/health_check_sink.h"

#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Cilium {

Thread::MutexBasicLockable HealthCheckEventPipeSink::udss_mutex;
std::map<std::string, std::weak_ptr<UDSClient>> HealthCheckEventPipeSink::udss;

HealthCheckEventPipeSink::HealthCheckEventPipeSink(const cilium::HealthCheckEventPipeSink& config,
                                                   TimeSource& time_source)
    : uds_client_(nullptr) {
  auto path = config.path();
  Thread::LockGuard guard(udss_mutex);
  auto it = udss.find(path);
  if (it != udss.end()) {
    uds_client_ = it->second.lock();
    if (!uds_client_)
      // expired, remove
      udss.erase(path);
  }
  if (!uds_client_) {
    // Not found, allocate and store as a weak_ptr
    uds_client_ = std::make_shared<UDSClient>(path, time_source);
    udss.emplace(path, uds_client_);
  }
}

void HealthCheckEventPipeSink::log(envoy::data::core::v3::HealthCheckEvent event) {
  if (!uds_client_) {
    ENVOY_LOG_MISC(warn, "HealthCheckEventPipeSink: no connection, skipping event: {}",
                   event.DebugString());
    return;
  }
  std::string msg;
  event.SerializeToString(&msg);
  uds_client_->Log(msg);
};

Upstream::HealthCheckEventSinkPtr HealthCheckEventPipeSinkFactory::createHealthCheckEventSink(
    const ProtobufWkt::Any& config, Server::Configuration::HealthCheckerFactoryContext& context) {
  const auto& validator_config =
      Envoy::MessageUtil::anyConvertAndValidate<cilium::HealthCheckEventPipeSink>(
          config, context.messageValidationVisitor());
  Upstream::HealthCheckEventSinkPtr uds;
  uds.reset(
      new HealthCheckEventPipeSink(validator_config, context.serverFactoryContext().timeSource()));
  return uds;
}

REGISTER_FACTORY(HealthCheckEventPipeSinkFactory, Upstream::HealthCheckEventSinkFactory);

} // namespace Cilium
} // namespace Envoy
