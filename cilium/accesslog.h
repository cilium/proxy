#pragma once

#include <map>
#include <string>

#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"
#include "envoy/router/router.h"
#include "envoy/stream_info/stream_info.h"

#include "cilium/api/accesslog.pb.h"
#include "cilium/uds_client.h"

namespace Envoy {
namespace Cilium {

class AccessLog : public UDSClient {
public:
  static std::shared_ptr<AccessLog> Open(const std::string& path);
  ~AccessLog();

  // wrapper for protobuf
  class Entry {
  public:
    void InitFromRequest(const std::string& policy_name, uint32_t proxy_id, bool ingress,
                         uint32_t source_identity,
                         const Network::Address::InstanceConstSharedPtr& source_address,
                         uint32_t destination_identity,
                         const Network::Address::InstanceConstSharedPtr& destination_address,
                         const StreamInfo::StreamInfo&, const Http::RequestHeaderMap&);
    void UpdateFromRequest(uint32_t destination_identity,
                           const Network::Address::InstanceConstSharedPtr& destination_address,
                           const Http::RequestHeaderMap&);
    void UpdateFromResponse(const Http::ResponseHeaderMap&, TimeSource&);

    void InitFromConnection(const std::string& policy_name, uint32_t proxy_id, bool ingress,
                            uint32_t source_identity,
                            const Network::Address::InstanceConstSharedPtr& source_address,
                            uint32_t destination_identity,
                            const Network::Address::InstanceConstSharedPtr& destination_address,
                            TimeSource* time_source);
    bool UpdateFromMetadata(const std::string& l7proto, const ProtobufWkt::Struct& metadata);
    void AddRejected(absl::string_view key, absl::string_view value);
    void AddMissing(absl::string_view key, absl::string_view value);

    ::cilium::LogEntry entry_{};
  };

  void Log(Entry& entry, ::cilium::EntryType);

private:
  explicit AccessLog(const std::string& path) : UDSClient(path), path_(path) {}

  static Thread::MutexBasicLockable logs_mutex;
  static std::map<std::string, std::weak_ptr<AccessLog>> logs ABSL_GUARDED_BY(logs_mutex);

  const std::string path_;
};
typedef std::shared_ptr<AccessLog> AccessLogSharedPtr;

} // namespace Cilium
} // namespace Envoy
