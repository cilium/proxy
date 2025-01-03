#include "tests/health_check_sink_server.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <string>

#include "envoy/data/core/v3/health_check_event.pb.h"

#include "source/common/common/logger.h"

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "tests/uds_server.h"

namespace Envoy {

HealthCheckSinkServer::HealthCheckSinkServer(const std::string path)
    : UDSServer(path, std::bind(&HealthCheckSinkServer::msgCallback, this, std::placeholders::_1)) {
}

HealthCheckSinkServer::~HealthCheckSinkServer() {}

void HealthCheckSinkServer::clear() {
  absl::MutexLock lock(&mutex_);
  events_.clear();
}

absl::optional<envoy::data::core::v3::HealthCheckEvent>
HealthCheckSinkServer::waitForEvent(std::chrono::milliseconds timeout) {
  absl::MutexLock lock(&mutex_);
  auto predicate = [this]() ABSL_SHARED_LOCKS_REQUIRED(mutex_) {
    mutex_.AssertHeld();
    return !events_.empty();
  };
  mutex_.AwaitWithTimeout(absl::Condition(&predicate), absl::Milliseconds(timeout.count()));
  auto event = events_.front();
  events_.pop_front();
  return event;
}

void HealthCheckSinkServer::msgCallback(const std::string& data) {
  envoy::data::core::v3::HealthCheckEvent event;
  if (!event.ParseFromString(data)) {
    ENVOY_LOG(warn, "Health check event parse failed!");
  } else {
    ENVOY_LOG(info, "Health check event: {}", event.DebugString());
    absl::MutexLock lock(&mutex_);
    events_.emplace_back(event);
  }
}

} // namespace Envoy
