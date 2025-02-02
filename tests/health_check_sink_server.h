#pragma once

#include <chrono>
#include <list>
#include <string>

#include "envoy/data/core/v3/health_check_event.pb.h"
#include "envoy/data/core/v3/health_check_event.pb.validate.h" // IWYU pragma: keep

#include "test/test_common/utility.h"

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tests/uds_server.h"

namespace Envoy {

class HealthCheckSinkServer : public UDSServer {
public:
  HealthCheckSinkServer(const std::string path);
  ~HealthCheckSinkServer();

  void clear();
  absl::optional<envoy::data::core::v3::HealthCheckEvent>
  waitForEvent(std::chrono::milliseconds timeout = TestUtility::DefaultTimeout);

  template <typename P>
  bool expectEventTo(P&& pred, std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    auto maybe_event = waitForEvent(timeout);
    if (maybe_event.has_value()) {
      return pred(maybe_event.value());
    }
    return false;
  }

private:
  void msgCallback(const std::string& data);

  absl::Mutex mutex_;
  std::list<envoy::data::core::v3::HealthCheckEvent> events_ ABSL_GUARDED_BY(mutex_);
};

} // namespace Envoy
