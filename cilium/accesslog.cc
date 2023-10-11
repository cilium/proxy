#include "accesslog.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "source/common/common/lock_guard.h"
#include "source/common/common/utility.h"

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

AccessLog::AccessLog(std::string path) : path_(path), fd_(-1), open_count_(1), errno_(0) {}

AccessLog::~AccessLog() {}

#define CONST_STRING_VIEW(NAME, STR) const absl::string_view NAME = {STR, sizeof(STR) - 1}

CONST_STRING_VIEW(pathSV, ":path");
CONST_STRING_VIEW(methodSV, ":method");
CONST_STRING_VIEW(authoritySV, ":authority");
CONST_STRING_VIEW(xForwardedProtoSV, "x-forwarded-proto");
CONST_STRING_VIEW(xRequestIdSV, "x-request-id");
CONST_STRING_VIEW(statusSV, ":status");

void AccessLog::Entry::InitFromConnection(
    const std::string& policy_name, uint32_t proxy_id, bool ingress, uint32_t source_identity,
    const Network::Address::InstanceConstSharedPtr& source_address, uint32_t destination_identity,
    const Network::Address::InstanceConstSharedPtr& destination_address, TimeSource* time_source) {
  entry_.set_policy_name(policy_name);
  entry_.set_proxy_id(proxy_id);
  entry_.set_is_ingress(ingress);
  entry_.set_source_security_id(source_identity);
  entry_.set_destination_security_id(destination_identity);

  if (source_address != nullptr) {
    entry_.set_source_address(source_address->asString());
  }

  if (destination_address != nullptr) {
    entry_.set_destination_address(destination_address->asString());
  }

  if (time_source) {
    auto time = time_source->systemTime();
    entry_.set_timestamp(
        std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count());
  }
}

bool AccessLog::Entry::UpdateFromMetadata(const std::string& l7proto,
                                          const ProtobufWkt::Struct& metadata) {
  bool changed = false;

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
      auto new_value = MessageUtil::getJsonStringFromMessage(it->second, false, true);
      if (new_value.ok() && new_value.value() != pair.second) {
        (*old_fields)[pair.first] = new_value.value();
        changed = true;
      }
    }
  }
  // Insert new values
  for (const auto& pair : new_fields) {
    auto it = old_fields->find(pair.first);
    if (it == old_fields->cend()) {
      (*old_fields)[pair.first] =
          MessageUtil::getJsonStringFromMessageOrError(pair.second, false, true);
      changed = true;
    }
  }
  return changed;
}

void AccessLog::Entry::InitFromRequest(const std::string& policy_name, uint32_t proxy_id,
                                       bool ingress, uint32_t source_identity,
                                       const Network::Address::InstanceConstSharedPtr& src_address,
                                       uint32_t destination_identity,
                                       const Network::Address::InstanceConstSharedPtr& dst_address,
                                       const StreamInfo::StreamInfo& info,
                                       const Http::RequestHeaderMap& headers) {
  InitFromConnection(policy_name, proxy_id, ingress, source_identity, src_address,
                     destination_identity, dst_address, nullptr);

  auto time = info.startTime();
  entry_.set_timestamp(
      std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count());

  ::cilium::HttpProtocol proto;
  switch (info.protocol() ? info.protocol().value() : Http::Protocol::Http11) {
  case Http::Protocol::Http10:
    proto = ::cilium::HttpProtocol::HTTP10;
    break;
  case Http::Protocol::Http11:
  default: // Just to make compiler happy
    proto = ::cilium::HttpProtocol::HTTP11;
    break;
  case Http::Protocol::Http2:
    proto = ::cilium::HttpProtocol::HTTP2;
    break;
  }
  ::cilium::HttpLogEntry* http_entry = entry_.mutable_http();
  http_entry->set_http_protocol(proto);

  UpdateFromRequest(destination_identity, dst_address, headers);
}

void AccessLog::Entry::UpdateFromRequest(
    uint32_t destination_identity, const Network::Address::InstanceConstSharedPtr& dst_address,
    const Http::RequestHeaderMap& headers) {
  // Destination may have changed
  if (destination_identity != 0) {
    entry_.set_destination_security_id(destination_identity);
  }
  if (dst_address != nullptr) {
    entry_.set_destination_address(dst_address->asString());
  }

  ::cilium::HttpLogEntry* http_entry = entry_.mutable_http();
  // Remove headers logged for the request, as they may have changed
  http_entry->clear_headers();

  // request headers
  headers.iterate([http_entry](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    const absl::string_view key = header.key().getStringView();
    const absl::string_view value = header.value().getStringView();

    if (key == pathSV) {
      http_entry->set_path(value.data(), value.size());
    } else if (key == methodSV) {
      http_entry->set_method(value.data(), value.size());
    } else if (key == authoritySV) {
      http_entry->set_host(value.data(), value.size());
    } else if (key == xForwardedProtoSV) {
      // Envoy sets the ":scheme" header later in the router filter
      // according to the upstream protocol (TLS vs. clear), but we want to
      // get the downstream scheme, which is provided in
      // "x-forwarded-proto".
      http_entry->set_scheme(value.data(), value.size());
    } else {
      ::cilium::KeyValue* kv = http_entry->add_headers();
      kv->set_key(key.data(), key.size());
      kv->set_value(value.data(), value.size());
    }
    return Http::HeaderMap::Iterate::Continue;
  });
}

void AccessLog::Entry::UpdateFromResponse(const Http::ResponseHeaderMap& headers,
                                          TimeSource& time_source) {
  auto time = time_source.systemTime();
  entry_.set_timestamp(
      std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count());

  ::cilium::HttpLogEntry* http_entry = entry_.mutable_http();

  // Find existing x-request-id before clearing headers
  std::string request_id;
  for (int i = 0; i < http_entry->headers_size(); i++) {
    if (http_entry->headers(i).key() == xRequestIdSV) {
      request_id = http_entry->headers(i).value();
      break;
    }
  }

  // Remove headers logged for the request
  http_entry->clear_headers();

  // Add back the x-request-id, if any
  if (request_id.length() > 0) {
    ::cilium::KeyValue* kv = http_entry->add_headers();
    kv->set_key(xRequestIdSV.data(), xRequestIdSV.size());
    kv->set_value(request_id);
  }

  // response headers
  headers.iterate(
      [http_entry, &request_id](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
        const absl::string_view key = header.key().getStringView();
        const absl::string_view value = header.value().getStringView();

        if (key == statusSV) {
          uint64_t status;
          if (absl::SimpleAtoi(value, &status)) {
            http_entry->set_status(status);
          }
        } else if (key == xRequestIdSV && value == request_id) {
          // We already have the request id, do not repeat it if the value is still the same
        } else {
          ::cilium::KeyValue* kv = http_entry->add_headers();
          kv->set_key(key.data(), key.size());
          kv->set_value(value.data(), value.size());
        }
        return Http::HeaderMap::Iterate::Continue;
      });
}

void AccessLog::Entry::AddRejected(absl::string_view key, absl::string_view value) {
  for (auto entry : entry_.http().rejected_headers())
    if (entry.key() == key && entry.value() == value)
      return;
  ::cilium::KeyValue* kv = entry_.mutable_http()->add_rejected_headers();
  kv->set_key(key.data(), key.size());
  kv->set_value(value.data(), value.size());
}

void AccessLog::Entry::AddMissing(absl::string_view key, absl::string_view value) {
  for (auto entry : entry_.http().missing_headers())
    if (entry.key() == key && entry.value() == value)
      return;
  ::cilium::KeyValue* kv = entry_.mutable_http()->add_missing_headers();
  kv->set_key(key.data(), key.size());
  kv->set_value(value.data(), value.size());
}

void AccessLog::Log(AccessLog::Entry& entry__, ::cilium::EntryType entry_type) {
  ::cilium::LogEntry& entry = entry__.entry_;
  int tries = 2;

  entry.set_entry_type(entry_type);

  // encode protobuf
  std::string msg;
  entry.SerializeToString(&msg);
  ssize_t length = msg.length();

  Thread::LockGuard guard(fd_mutex_);
  while (tries-- > 0 && guarded_connect()) {
    ssize_t sent = ::send(fd_, msg.data(), length, MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL);

    if (sent == -1) {
      errno_ = errno;
      continue; // retry
    }
    if (sent < length) {
      ENVOY_LOG(debug, "Cilium access log send truncated by {} bytes.", length - sent);
    }
    return;
  }
}

bool AccessLog::Connect() {
  Thread::LockGuard guard(fd_mutex_);
  return guarded_connect();
}

bool AccessLog::guarded_connect() {
  if (fd_ != -1) {
    if (errno_ == 0) {
      return true;
    }
    ENVOY_LOG(debug, "Cilium access log resetting socket due to error: {}",
              Envoy::errorDetails(errno_));
    ::close(fd_);
    fd_ = -1;
  }

  if (path_.length() == 0) {
    return false;
  }

  errno_ = 0;
  fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ == -1) {
    errno_ = errno;
    ENVOY_LOG(error, "Can't create socket: {}", Envoy::errorDetails(errno_));
    return false;
  }

  struct sockaddr_un addr = {AF_UNIX, {}};
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
    errno_ = errno;
    ENVOY_LOG(warn, "Connect to {} failed: {}", path_, Envoy::errorDetails(errno_));
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  return true;
}

} // namespace Cilium
} // namespace Envoy
