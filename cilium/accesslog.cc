#include "accesslog.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "envoy/common/time.h"
#include "envoy/http/header_map.h"
#include "envoy/http/protocol.h"
#include "envoy/network/address.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/protobuf/utility.h"

#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/uds_client.h"

namespace Envoy {
namespace Cilium {

Thread::MutexBasicLockable AccessLog::logs_mutex;
std::map<std::string, std::weak_ptr<AccessLog>> AccessLog::logs;

AccessLogSharedPtr AccessLog::open(const std::string& path, TimeSource& time_source) {
  Thread::LockGuard guard(logs_mutex);
  auto it = logs.find(path);
  if (it != logs.end()) {
    auto log = it->second.lock();
    if (log) {
      return log;
    }
    // expired, remove
    logs.erase(path);
  }
  // Not found, open and store as a weak_ptr
  AccessLogSharedPtr log;
  log.reset(new AccessLog(path, time_source));
  logs.emplace(path, log);
  return log;
}

AccessLog::~AccessLog() {
  // last reference going out of scope
  Thread::LockGuard guard1(logs_mutex);
  logs.erase(path_);
}

void AccessLog::log(AccessLog::Entry& log_entry, ::cilium::EntryType entry_type) {
  ::cilium::LogEntry& entry = log_entry.entry_;
  entry.set_entry_type(entry_type);

  if (entry_type != ::cilium::EntryType::Response) {
    if (log_entry.request_logged_) {
      ENVOY_LOG_MISC(warn, "cilium.AccessLog: Request is logged twice");
    }
    log_entry.request_logged_ = true;
  }

  // encode protobuf
  std::string msg;
  entry.SerializeToString(&msg);

  UDSClient::log(msg);
}

#define CONST_STRING_VIEW(NAME, STR) const absl::string_view NAME = {STR, sizeof(STR) - 1}

CONST_STRING_VIEW(pathSV, ":path");
CONST_STRING_VIEW(methodSV, ":method");
CONST_STRING_VIEW(authoritySV, ":authority");
CONST_STRING_VIEW(xForwardedProtoSV, "x-forwarded-proto");
CONST_STRING_VIEW(xRequestIdSV, "x-request-id");
CONST_STRING_VIEW(statusSV, ":status");

void AccessLog::Entry::initFromConnection(
    const std::string& policy_name, uint32_t proxy_id, bool ingress, uint32_t source_identity,
    const Network::Address::InstanceConstSharedPtr& source_address, uint32_t destination_identity,
    const Network::Address::InstanceConstSharedPtr& destination_address, TimeSource* time_source) {
  request_logged_ = false;

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

bool AccessLog::Entry::updateFromMetadata(const std::string& l7proto,
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

void AccessLog::Entry::initFromRequest(const std::string& policy_name, uint32_t proxy_id,
                                       bool ingress, uint32_t source_identity,
                                       const Network::Address::InstanceConstSharedPtr& src_address,
                                       uint32_t destination_identity,
                                       const Network::Address::InstanceConstSharedPtr& dst_address,
                                       const StreamInfo::StreamInfo& info,
                                       const Http::RequestHeaderMap& headers) {
  initFromConnection(policy_name, proxy_id, ingress, source_identity, src_address,
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

  updateFromRequest(destination_identity, dst_address, headers);
}

void AccessLog::Entry::updateFromRequest(
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

void AccessLog::Entry::updateFromResponse(const Http::ResponseHeaderMap& headers,
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

void AccessLog::Entry::addRejected(absl::string_view key, absl::string_view value) {
  for (const auto& entry : entry_.http().rejected_headers()) {
    if (entry.key() == key && entry.value() == value) {
      return;
    }
  }
  ::cilium::KeyValue* kv = entry_.mutable_http()->add_rejected_headers();
  kv->set_key(key.data(), key.size());
  kv->set_value(value.data(), value.size());
}

void AccessLog::Entry::addMissing(absl::string_view key, absl::string_view value) {
  for (const auto& entry : entry_.http().missing_headers()) {
    if (entry.key() == key && entry.value() == value) {
      return;
    }
  }
  ::cilium::KeyValue* kv = entry_.mutable_http()->add_missing_headers();
  kv->set_key(key.data(), key.size());
  kv->set_value(value.data(), value.size());
}

} // namespace Cilium
} // namespace Envoy
