#include "cilium/health_check_sink.h"

#include <map>
#include <memory>
#include <string>

#include "envoy/common/time.h"
#include "envoy/data/core/v3/health_check_event.pb.h"
#include "envoy/registry/registry.h"
#include "envoy/server/health_checker_config.h"
#include "envoy/upstream/health_check_event_sink.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep
#include "source/common/protobuf/utility.h"

#include "cilium/api/health_check_sink.pb.h"
#include "cilium/uds_client.h"

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
    if (!uds_client_) {
      // expired, remove
      udss.erase(path);
    }
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
  uds_client_->log(msg);
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
