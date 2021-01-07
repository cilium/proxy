#include "accesslog.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/common/lock_guard.h"
#include "common/common/utility.h"
#include "socket_option.h"

namespace Envoy {
namespace Cilium {

Thread::MutexBasicLockable AccessLog::logs_mutex;
std::map<std::string, AccessLogPtr> AccessLog::logs;

AccessLog* AccessLog::Open(std::string path) {
  Thread::LockGuard guard1(logs_mutex);
  AccessLog* log;
  auto it = logs.find(path);
  if (it != logs.end()) {
    log = it->second.get();
    Thread::LockGuard guard2(log->fd_mutex_);
    log->open_count_++;
    return log;
  }
  // Not found, open
  log = new AccessLog(path);
  if (!log->Connect()) {
    delete log;
    return nullptr;
  }
  logs.emplace(path, AccessLogPtr{log});
  return log;
}

void AccessLog::Close() {
  // Can't use Thread::LockGuard as it will result in calling a pure virtual
  // function in integration test teardown.
  logs_mutex.lock();
  fd_mutex_.lock();
  open_count_--;

  if (open_count_ == 0) {
    if (fd_ != -1) {
      ::close(fd_);
      fd_ = -1;
    }

    logs.erase(path_);
  }
  fd_mutex_.unlock();
  logs_mutex.unlock();
}

AccessLog::AccessLog(std::string path) : path_(path), fd_(-1), open_count_(1) {}

AccessLog::~AccessLog() {}

#define CONST_STRING_VIEW(NAME, STR) \
  const absl::string_view NAME = {STR, sizeof(STR) - 1}

CONST_STRING_VIEW(pathSV, ":path");
CONST_STRING_VIEW(methodSV, ":method");
CONST_STRING_VIEW(authoritySV, ":authority");
CONST_STRING_VIEW(xForwardedProtoSV, "x-forwarded-proto");

void AccessLog::Entry::InitFromConnection(const std::string& policy_name,
                                          bool ingress,
                                          const Network::Connection& conn) {
  entry_.set_policy_name(policy_name);

  const auto option = Cilium::GetSocketOption(conn.socketOptions());
  if (option) {
    entry_.set_source_security_id(option->identity_);
    entry_.set_destination_security_id(option->destination_identity_);
  } else {
    ENVOY_CONN_LOG(warn, "accesslog: Cilium Socket Option not found", conn);
  }
  auto source_address = conn.remoteAddress();
  if (source_address != nullptr) {
    entry_.set_source_address(source_address->asString());
  }
  auto destination_address = conn.localAddress();
  if (destination_address != nullptr) {
    entry_.set_destination_address(destination_address->asString());
  }

  entry_.set_is_ingress(ingress);
}

bool AccessLog::Entry::UpdateFromMetadata(const std::string& l7proto,
                                          const ProtobufWkt::Struct& metadata,
                                          TimeSource& time_source) {
  bool changed = false;

  auto time = time_source.systemTime();
  entry_.set_timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(
                           time.time_since_epoch())
                           .count());

  auto l7entry = entry_.mutable_generic_l7();
  if (l7entry->proto() != l7proto) {
    l7entry->set_proto(l7proto);
    changed = true;
  }
  // remove non-existing fields, update existing values
  auto* old_fields = l7entry->mutable_fields();
  const auto& new_fields = metadata.fields();
  for (const auto& pair : *old_fields) {
    const auto it = new_fields.find(pair.first);
    if (it == new_fields.cend()) {
      old_fields->erase(pair.first);
      changed = true;
    } else {
      auto new_value =
          MessageUtil::getJsonStringFromMessage(it->second, false, true);
      if (new_value != pair.second) {
        (*old_fields)[pair.first] = new_value;
        changed = true;
      }
    }
  }
  // Insert new values
  for (const auto& pair : new_fields) {
    auto it = old_fields->find(pair.first);
    if (it == old_fields->cend()) {
      (*old_fields)[pair.first] =
          MessageUtil::getJsonStringFromMessage(pair.second, false, true);
      changed = true;
    }
  }
  return changed;
}

void AccessLog::Entry::InitFromRequest(const std::string& policy_name,
                                       bool ingress,
                                       const Network::Connection* conn,
                                       const Http::RequestHeaderMap& headers,
                                       const StreamInfo::StreamInfo& info) {
  InitFromConnection(policy_name, ingress, *conn);

  auto time = info.startTime();
  entry_.set_timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(
                           time.time_since_epoch())
                           .count());

  ::cilium::HttpProtocol proto;
  switch (info.protocol() ? info.protocol().value() : Http::Protocol::Http11) {
    case Http::Protocol::Http10:
      proto = ::cilium::HttpProtocol::HTTP10;
      break;
    case Http::Protocol::Http11:
    default:  // Just to make compiler happy
      proto = ::cilium::HttpProtocol::HTTP11;
      break;
    case Http::Protocol::Http2:
      proto = ::cilium::HttpProtocol::HTTP2;
      break;
  }
  ::cilium::HttpLogEntry* http_entry = entry_.mutable_http();
  http_entry->set_http_protocol(proto);

  // request headers
  headers.iterate(
      [](const Http::HeaderEntry& header,
         void* entry__) -> Http::HeaderMap::Iterate {
        const absl::string_view key = header.key().getStringView();
        const absl::string_view value = header.value().getStringView();
        auto entry = static_cast<::cilium::HttpLogEntry*>(entry__);

        if (key == pathSV) {
          entry->set_path(value.data(), value.size());
        } else if (key == methodSV) {
          entry->set_method(value.data(), value.size());
        } else if (key == authoritySV) {
          entry->set_host(value.data(), value.size());
        } else if (key == xForwardedProtoSV) {
          // Envoy sets the ":scheme" header later in the router filter
          // according to the upstream protocol (TLS vs. clear), but we want to
          // get the downstream scheme, which is provided in
          // "x-forwarded-proto".
          entry->set_scheme(value.data(), value.size());
        } else {
          ::cilium::KeyValue* kv = entry->add_headers();
          kv->set_key(key.data(), key.size());
          kv->set_value(value.data(), value.size());
        }
        return Http::HeaderMap::Iterate::Continue;
      },
      http_entry);
}

void AccessLog::Entry::UpdateFromResponse(
    const Http::ResponseHeaderMap& headers, TimeSource& time_source) {
  auto time = time_source.systemTime();
  entry_.set_timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(
                           time.time_since_epoch())
                           .count());

  ::cilium::HttpLogEntry* http_entry = entry_.mutable_http();
  const Http::HeaderEntry* status_entry = headers.Status();
  if (status_entry) {
    uint64_t status;
    if (absl::SimpleAtoi(status_entry->value().getStringView(), &status)) {
      http_entry->set_status(status);
    }
  }
}

void AccessLog::Log(AccessLog::Entry& entry__, ::cilium::EntryType entry_type) {
  ::cilium::LogEntry& entry = entry__.entry_;

  entry.set_entry_type(entry_type);

  if (Connect()) {
    // encode protobuf
    std::string msg;
    entry.SerializeToString(&msg);
    ssize_t length = msg.length();
    ssize_t sent =
        ::send(fd_, msg.data(), length, MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL);
    if (sent == length) {
      ENVOY_LOG(trace, "Cilium access log msg sent: {}", entry.DebugString());
      return;
    }
    if (sent == -1) {
      ENVOY_LOG(debug, "Cilium access log send failed: {}",
                Envoy::errorDetails(errno));
    } else {
      ENVOY_LOG(debug, "Cilium access log send truncated by {} bytes.",
                length - sent);
    }
  }
  // Log the message in Envoy logs if it could not be sent to Cilium
  ENVOY_LOG(debug, "Cilium access log msg: {}", entry.DebugString());
}

bool AccessLog::Connect() {
  if (fd_ != -1) {
    return true;
  }
  if (path_.length() == 0) {
    return false;
  }
  Thread::LockGuard guard(fd_mutex_);

  fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ == -1) {
    ENVOY_LOG(error, "Can't create socket: {}", Envoy::errorDetails(errno));
    return false;
  }

  struct sockaddr_un addr = {AF_UNIX, {}};
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) ==
      -1) {
    ENVOY_LOG(warn, "Connect to {} failed: {}", path_,
              Envoy::errorDetails(errno));
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  return true;
}

}  // namespace Cilium
}  // namespace Envoy
