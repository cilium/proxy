#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "envoy/common/time.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/thread.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep

#include "absl/base/thread_annotations.h"
#include "absl/strings/string_view.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/uds_client.h"

namespace Envoy {
namespace Cilium {

constexpr absl::string_view AccessLogKey = "cilium.accesslog.entry";

class AccessLog : public UDSClient {
public:
  static std::shared_ptr<AccessLog> open(const std::string& path, TimeSource& time_source);
  ~AccessLog();

  // wrapper for protobuf
  class Entry : public StreamInfo::FilterState::Object {
  public:
    void initFromRequest(const std::string& policy_name, uint16_t proxy_id, bool ingress,
                         uint32_t source_identity,
                         const Network::Address::InstanceConstSharedPtr& source_address,
                         uint32_t destination_identity,
                         const Network::Address::InstanceConstSharedPtr& destination_address,
                         const StreamInfo::StreamInfo&, const Http::RequestHeaderMap&);
    void updateFromRequest(uint32_t destination_identity,
                           const Network::Address::InstanceConstSharedPtr& destination_address,
                           const Http::RequestHeaderMap&);
    void updateFromResponse(const Http::ResponseHeaderMap&, TimeSource&);

    void initFromConnection(const std::string& policy_name, uint16_t proxy_id, bool ingress,
                            uint32_t source_identity,
                            const Network::Address::InstanceConstSharedPtr& source_address,
                            uint32_t destination_identity,
                            const Network::Address::InstanceConstSharedPtr& destination_address,
                            TimeSource* time_source);
    bool updateFromMetadata(const std::string& l7proto, const Protobuf::Struct& metadata);
    void addRejected(absl::string_view key, absl::string_view value);
    void addMissing(absl::string_view key, absl::string_view value);

    ::cilium::LogEntry entry_{};
    bool request_logged_ = false;
  };

  void log(Entry& entry, ::cilium::EntryType);

private:
  explicit AccessLog(const std::string& path, TimeSource& time_source)
      : UDSClient(path, time_source), path_(path) {}

  static Thread::MutexBasicLockable logs_mutex;
  static std::map<std::string, std::weak_ptr<AccessLog>> logs ABSL_GUARDED_BY(logs_mutex);

  const std::string path_;
};
using AccessLogSharedPtr = std::shared_ptr<AccessLog>;

} // namespace Cilium
} // namespace Envoy
