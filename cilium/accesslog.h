#pragma once

#include <map>
#include <string>

#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"
#include "envoy/router/router.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"

#include "cilium/api/accesslog.pb.h"

namespace Envoy {
namespace Cilium {

class AccessLog : Logger::Loggable<Logger::Id::router> {
public:
  static AccessLog* Open(std::string path);
  void Close();

  // wrapper for protobuf
  class Entry {
  public:
    void InitFromRequest(const std::string& policy_name, bool ingress, uint32_t source_identity,
                         const Network::Address::InstanceConstSharedPtr& source_address,
                         uint32_t destination_identity,
                         const Network::Address::InstanceConstSharedPtr& destination_address,
                         const StreamInfo::StreamInfo&, const Http::RequestHeaderMap&);
    void UpdateFromRequest(uint32_t destination_identity,
                           const Network::Address::InstanceConstSharedPtr& destination_address,
                           const Http::RequestHeaderMap&);
    void UpdateFromResponse(const Http::ResponseHeaderMap&, TimeSource&);

    void InitFromConnection(const std::string& policy_name, bool ingress, uint32_t source_identity,
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

  ~AccessLog();

private:
  static Thread::MutexBasicLockable logs_mutex;
  static std::map<std::string, std::unique_ptr<AccessLog>> logs;

  AccessLog(std::string path);

  bool Connect();
  bool guarded_connect() ABSL_EXCLUSIVE_LOCKS_REQUIRED(fd_mutex_);

  const std::string path_;
  Thread::MutexBasicLockable fd_mutex_;
  int fd_ ABSL_GUARDED_BY(fd_mutex_);
  int open_count_ ABSL_GUARDED_BY(fd_mutex_);
  int errno_ ABSL_GUARDED_BY(fd_mutex_);
};

typedef std::unique_ptr<AccessLog> AccessLogPtr;

} // namespace Cilium
} // namespace Envoy
