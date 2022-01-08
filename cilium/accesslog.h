#pragma once

#include <map>
#include <string>

#include "cilium/api/accesslog.pb.h"
#include "cilium/socket_option.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"
#include "envoy/router/router.h"
#include "envoy/stream_info/stream_info.h"

namespace Envoy {
namespace Cilium {

class AccessLog : Logger::Loggable<Logger::Id::router> {
 public:
  static AccessLog* Open(std::string path);
  void Close();

  // wrapper for protobuf
  class Entry {
   public:
    void InitFromRequest(const std::string& policy_name,
                         const Cilium::SocketOption& option,
                         const StreamInfo::StreamInfo&,
                         const Http::RequestHeaderMap&);
    void UpdateFromResponse(const Http::ResponseHeaderMap&, TimeSource&);

    void InitFromConnection(const std::string& policy_name,
                            const Cilium::SocketOption& option,
                            const StreamInfo::StreamInfo&);
    bool UpdateFromMetadata(const std::string& l7proto,
                            const ProtobufWkt::Struct& metadata,
                            TimeSource& time_source);

    ::cilium::LogEntry entry_{};
  };
  void Log(Entry& entry, ::cilium::EntryType);

  ~AccessLog();

 private:
  static Thread::MutexBasicLockable logs_mutex;
  static std::map<std::string, std::unique_ptr<AccessLog>> logs;

  AccessLog(std::string path);

  bool Connect();

  const std::string path_;
  Thread::MutexBasicLockable fd_mutex_;
  int fd_ ABSL_GUARDED_BY(fd_mutex_);
  int open_count_ ABSL_GUARDED_BY(fd_mutex_);
};

typedef std::unique_ptr<AccessLog> AccessLogPtr;

}  // namespace Cilium
}  // namespace Envoy
