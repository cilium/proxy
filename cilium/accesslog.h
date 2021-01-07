#pragma once

#include <map>
#include <mutex>
#include <string>

#include "cilium/api/accesslog.pb.h"
#include "common/common/logger.h"
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
    void InitFromRequest(const std::string& policy_name, bool ingress,
                         const Network::Connection*,
                         const Http::RequestHeaderMap&,
                         const StreamInfo::StreamInfo&);
    void UpdateFromResponse(const Http::ResponseHeaderMap&, TimeSource&);

    void InitFromConnection(const std::string& policy_name, bool ingress,
                            const Network::Connection&);
    bool UpdateFromMetadata(const std::string& l7proto,
                            const ProtobufWkt::Struct& metadata,
                            TimeSource& time_source);

    ::cilium::LogEntry entry_{};
  };
  void Log(Entry& entry, ::cilium::EntryType);

  ~AccessLog();

 private:
  static std::mutex logs_mutex;
  static std::map<std::string, std::unique_ptr<AccessLog>> logs;

  AccessLog(std::string path);

  bool Connect();

  const std::string path_;
  std::mutex fd_mutex_;
  int fd_;
  int open_count_;
};

typedef std::unique_ptr<AccessLog> AccessLogPtr;

}  // namespace Cilium
}  // namespace Envoy
