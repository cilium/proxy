#include "cilium/websocket_codec.h"

#include <http_parser.h>

#include <string>

#include "envoy/registry/registry.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/base64.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/hex.h"
#include "source/common/crypto/crypto_impl.h"
#include "source/common/crypto/utility.h"
#include "source/common/http/codes.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "source/common/network/filter_manager_impl.h"
#include "source/common/network/utility.h"

#include "cilium/api/websocket.pb.validate.h"
#include "cilium/socket_option.h"
#include "cilium/websocket_protocol.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

namespace {

Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    origin_handle(Http::CustomHeaders::get().Origin);
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    original_dst_host_handle(Http::Headers::get().EnvoyOriginalDstHost);
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_key_handle(Http::LowerCaseString{"sec-websocket-key"});
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_version_handle(Http::LowerCaseString{"sec-websocket-version"});
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_protocol_handle(Http::LowerCaseString{"sec-websocket-protocol"});
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_extensions_handle(Http::LowerCaseString{"sec-websocket-extensions"});

Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::ResponseHeaders>
    sec_websocket_accept_handle(Http::LowerCaseString{"sec-websocket-accept"});

class HttpParser : public Logger::Loggable<Logger::Id::filter> {
public:
  virtual ~HttpParser() = default;
  HttpParser(http_parser_type type) : type_(type) {}

  bool parse(absl::string_view msg) {
    http_parser_init(&parser_, type_);
    parser_.data = this;
    http_parser_settings settings = {
        nullptr, /* on_message_begin */
        nullptr, /* on_URL */
        nullptr, /* on_status */
        [](http_parser* parser, const char* at, size_t length) -> int {
          return static_cast<HttpParser*>(parser->data)->onHeaderField(at, length);
        }, /* on_header_field */
        [](http_parser* parser, const char* at, size_t length) -> int {
          return static_cast<HttpParser*>(parser->data)->onHeaderValue(at, length);
        }, /* on_header_value */
        [](http_parser* parser) -> int {
          return static_cast<HttpParser*>(parser->data)->onHeadersComplete();
        },       /* on_headers_complete */
        nullptr, /* on_body */
        [](http_parser* parser) -> int {
          static_cast<HttpParser*>(parser->data)->message_complete_ = true;
          return 0;
        },       /* on_message_complete */
        nullptr, /* chunk header, chunk length in parser->content_length */
        nullptr, /* chunk complete */
    };

    ssize_t rc = http_parser_execute(&parser_, &settings, msg.data(), msg.length());
    ENVOY_LOG(trace, "websocket: http_parser parsed {} chars, error code: {}", rc,
              HTTP_PARSER_ERRNO(&parser_));

    // Errors in parsing HTTP.
    if (HTTP_PARSER_ERRNO(&parser_) != HPE_OK) {
      return false;
    }

    return message_complete_;
  }

  bool versionIsHttp1_1() {
    ENVOY_LOG(trace, "websocket: http_parser got version major: {} minor: {}", parser_.http_major,
              parser_.http_minor);
    return parser_.http_major == 1 && parser_.http_minor == 1;
  }

  uint32_t size() { return parser_.nread; }

protected:
  int completeLastHeader() {
    if (Http::HeaderUtility::headerNameContainsUnderscore(current_header_field_.getStringView())) {
      ENVOY_LOG(debug, "websocket: Rejecting invalid header: key={} value={}",
                current_header_field_.getStringView(), current_header_value_.getStringView());
      return -1;
    }
    ENVOY_LOG(trace, "websocket: completed header: key={} value={}",
              current_header_field_.getStringView(), current_header_value_.getStringView());

    if (!current_header_field_.empty()) {
      // Strip trailing whitespace of the current header value if any. Leading whitespace was
      // trimmed in onHeaderValue. http_parser does not strip leading or trailing whitespace as the
      // spec requires: https://tools.ietf.org/html/rfc7230#section-3.2.4
      current_header_value_.rtrim();

      current_header_field_.inlineTransform([](char c) { return absl::ascii_tolower(c); });

      addHeader(std::move(current_header_field_), std::move(current_header_value_));
    }
    return 0;
  }

  int onHeaderField(const char* data, size_t length) {
    if (parsing_value_) {
      auto code = completeLastHeader();
      if (code != 0) {
        return code;
      }
    }
    parsing_value_ = false;
    current_header_field_.append(data, length);
    return 0;
  }

  int onHeaderValue(const char* data, size_t length) {
    parsing_value_ = true;
    absl::string_view header_value{data, length};
    if (!Http::HeaderUtility::headerValueIsValid(header_value)) {
      ENVOY_LOG(debug, "websocket: invalid header value: {}", header_value);
      return -1;
    }

    if (current_header_value_.empty()) {
      // Strip leading whitespace if the current header value input contains the first bytes of the
      // encoded header value. Trailing whitespace is stripped once the full header value is known
      // in completeLastHeader. http_parser does not strip leading or trailing
      // whitespace as the spec requires: https://tools.ietf.org/html/rfc7230#section-3.2.4 .
      header_value = StringUtil::ltrim(header_value);
    }
    current_header_value_.append(header_value.data(), header_value.length());
    return 0;
  }

  virtual int onHeadersComplete() { return completeLastHeader(); }

  virtual void addHeader(Http::HeaderString&& key, Http::HeaderString&& value) PURE;

  http_parser_type type_;
  http_parser parser_;

  Http::HeaderString current_header_field_;
  Http::HeaderString current_header_value_;
  bool parsing_value_{false};
  bool message_complete_{false};
};

class RequestParser : public HttpParser {
public:
  RequestParser() : HttpParser(HTTP_REQUEST), headers_(Http::RequestHeaderMapImpl::create()) {}

  const Http::RequestHeaderMap& headers() { return *(headers_.get()); }

protected:
  int onHeadersComplete() override {
    headers_->setMethod(http_method_str(static_cast<http_method>(parser_.method)));
    return HttpParser::onHeadersComplete();
  }

  void addHeader(Http::HeaderString&& key, Http::HeaderString&& value) override {
    headers_->addViaMove(std::move(key), std::move(value));
  }

private:
  Http::RequestHeaderMapPtr headers_;
};

class ResponseParser : public HttpParser {
public:
  ResponseParser() : HttpParser(HTTP_RESPONSE), headers_(Http::ResponseHeaderMapImpl::create()) {}

  const Http::ResponseHeaderMap& headers() { return *(headers_.get()); }

  unsigned int status() {
    ENVOY_LOG(trace, "websocket: http_parser got status: {}",
              static_cast<unsigned int>(parser_.status_code));
    return parser_.status_code;
  }

protected:
  int onHeadersComplete() override {
    headers_->setStatus(parser_.status_code);
    return HttpParser::onHeadersComplete();
  }

  void addHeader(Http::HeaderString&& key, Http::HeaderString&& value) override {
    headers_->addViaMove(std::move(key), std::move(value));
  }

private:
  Http::ResponseHeaderMapPtr headers_;
};

#define CRLF "\r\n"
static const char REQUEST_POSTFIX[] = " HTTP/1.1" CRLF;
static const std::string request_prefix = "GET ";
static const std::string response_prefix = "HTTP/1.1 ";
static const absl::string_view header_separator = {CRLF CRLF, sizeof(CRLF CRLF) - 1};

void encodeHeader(Buffer::Instance& buffer, absl::string_view key, absl::string_view value) {
  buffer.add(key);
  buffer.add(": ", 2);
  buffer.add(value);
  buffer.add(CRLF, 2);
}

void encodeHeaders(Buffer::Instance& buffer, Http::RequestOrResponseHeaderMap& headers) {
  const Http::HeaderValues& header_values = Http::Headers::get();
  headers.iterate(
      [&buffer, &header_values](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
        absl::string_view key = header.key().getStringView();
        if (key[0] == ':') {
          // Translate :authority -> host so that upper layers do not need to deal with this.
          if (key.size() > 1 && key[1] == 'a') {
            key = absl::string_view(header_values.HostLegacy.get());
          } else {
            // Skip all headers starting with ':' that make it here.
            return Http::HeaderMap::Iterate::Continue;
          }
        }
        encodeHeader(buffer, key, header.value().getStringView());
        return Http::HeaderMap::Iterate::Continue;
      });
  encodeHeader(buffer, header_values.ContentLength.get(), "0");
}

void encodeRequest(Buffer::Instance& buffer, Http::RequestHeaderMap& headers) {
  const Http::HeaderEntry* method = headers.Method();
  const Http::HeaderEntry* path = headers.Path();

  buffer.add(method->value().getStringView());
  buffer.add(" ", 1);
  buffer.add(path->value().getStringView());
  buffer.add(REQUEST_POSTFIX, sizeof(REQUEST_POSTFIX) - 1);

  encodeHeaders(buffer, headers);

  buffer.add(CRLF, 2);
}

void encodeResponse(Buffer::Instance& buffer, Http::ResponseHeaderMap& headers) {
  const Http::HeaderEntry* status = headers.Status();
  uint64_t numeric_status = Http::Utility::getResponseStatus(headers);
  const char* status_string = Http::CodeUtility::toString(static_cast<Http::Code>(numeric_status));

  buffer.add(response_prefix);
  buffer.add(status->value().getStringView());
  buffer.add(" ", 1);
  buffer.add(status_string, strlen(status_string));
  buffer.add(CRLF, 2);

  encodeHeaders(buffer, headers);

  buffer.add(CRLF, 2);
}

} // namespace

//
// Codec
//

Codec::Codec(CodecCallbacks* parent, Network::Connection& conn)
    : parent_(parent), connection_(conn), encoder_(*this), decoder_(*this) {
  ENVOY_CONN_LOG(trace, "Enabling websocket handshake timeout at {} ms", connection_,
                 parent_->config()->handshake_timeout_.count());
  handshake_timer_ = connection_.dispatcher().createTimer([this]() {
    parent_->config()->stats_.handshake_timeout_.inc();
    closeOnError("websocket handshake timed out");
  });
  handshake_timer_->enableTimer(parent_->config()->handshake_timeout_);
}

namespace {

size_t maskData(uint8_t* buf, size_t n_bytes, uint8_t mask[4], size_t payload_offset = 0) {
  for (size_t i = 0; i < n_bytes; i++) {
    buf[i] ^= mask[payload_offset % 4];
    payload_offset++;
  }
  return payload_offset;
}

} // namespace

void Codec::closeOnError(const char* msg) {
  if (msg) {
    ENVOY_LOG(debug, "websocket: Closing connection: {}", msg);
  }
  // Close downstream, this should result also in the upstream getting closed (if any).
  connection_.close(Network::ConnectionCloseType::NoFlush, fmt::format("websocket error: {}", msg));
}

void Codec::closeOnError(Buffer::Instance& data, const char* msg) {
  closeOnError(msg);
  // Test infra insists on data being drained
  data.drain(data.length());
}

void Codec::handshake() {
  ENVOY_LOG(debug, "websocket: handshake");

  auto& config = parent_->config();

  if (!config->client_) {
    ENVOY_LOG(warn, "websocket: skipping handshake on a server");
    return;
  }

  const Network::Address::InstanceConstSharedPtr& dst_address =
      connection_.connectionInfoProvider().localAddress();

  // Create WebSocket Handshake
  const Http::HeaderValues& header_values = Http::Headers::get();
  Envoy::Http::RequestHeaderMapPtr headers = Http::RequestHeaderMapImpl::create();
  headers->setReferenceMethod(header_values.MethodValues.Get);
  headers->setReferencePath(config->path_);
  headers->setReferenceHost(config->host_);
  headers->setReferenceUpgrade(header_values.UpgradeValues.WebSocket);
  headers->setReferenceConnection(header_values.ConnectionValues.Upgrade);
  headers->setReferenceInline(sec_websocket_key_handle.handle(), config->key_);
  headers->setReferenceInline(sec_websocket_version_handle.handle(), config->version_);
  if (!config->origin_.empty()) {
    headers->setReferenceInline(origin_handle.handle(), config->origin_);
  }
  // Set original destination address header
  headers->setReferenceInline(original_dst_host_handle.handle(), dst_address->asStringView());
  // Set 'x-request-id' header
  config->request_id_extension_->set(*headers, false);

  parent_->onHandshakeCreated(*headers);

  Buffer::OwnedImpl handshake_buffer{};
  encodeRequest(handshake_buffer, *headers);
  parent_->injectEncoded(handshake_buffer, false);
  // Check that the buffer was drained
  ASSERT(handshake_buffer.length() == 0, "Handshake buffer not drained");
  parent_->onHandshakeSent();
}

void Codec::encode(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(debug, "websocket: encode {} bytes, end_stream: {}", data.length(), end_stream);

  encoder_.encode(data, end_stream, OPCODE_BIN);

  // Only forward data if handshake has completed
  if (accepted_) {
    // Reset idle timer on data
    if (encoder_.hasData()) {
      resetPingTimer();
    }
    parent_->injectEncoded(encoder_.data(), encoder_.endStream());
  }
}

void Codec::encodeHandshakeResponse(Http::ResponseHeaderMap& headers, uint32_t status,
                                    absl::string_view hash,
                                    const Http::RequestHeaderMap* request_headers) {
  if (status == 200) {
    ENVOY_LOG(debug, "websocket: Using hash {}", hash);
    headers.setStatus(enumToInt(Http::Code::SwitchingProtocols)); // 101
    headers.setReferenceConnection(Http::Headers::get().ConnectionValues.Upgrade);
    headers.setReferenceUpgrade(Http::Headers::get().UpgradeValues.WebSocket);
    headers.addCopy(Envoy::Http::LowerCaseString("sec-websocket-accept"), hash);
  } else {
    headers.setStatus(enumToInt(Http::Code::Forbidden)); // 403
  }
  if (request_headers != nullptr && request_headers->RequestId()) {
    headers.setRequestId(request_headers->getRequestIdValue());
  }
}

Network::Address::InstanceConstSharedPtr
Codec::decodeHandshakeRequest(const ConfigSharedPtr& config,
                              const Http::RequestHeaderMap& headers) {

  auto method = headers.getMethodValue();
  auto path = absl::AsciiStrToLower(headers.getPathValue());
  auto host = absl::AsciiStrToLower(headers.getHostValue());
  auto connection = absl::AsciiStrToLower(headers.getConnectionValue());
  auto upgrade = absl::AsciiStrToLower(headers.getUpgradeValue());
  auto version =
      absl::AsciiStrToLower(headers.getInlineValue(sec_websocket_version_handle.handle()));
  auto origin = headers.getInline(origin_handle.handle());
  auto protocol = headers.getInline(sec_websocket_protocol_handle.handle());
  auto extensions = headers.getInline(sec_websocket_extensions_handle.handle());
  auto override_header = headers.getInline(original_dst_host_handle.handle());
  auto key = headers.getInlineValue(sec_websocket_key_handle.handle());

  Network::Address::InstanceConstSharedPtr orig_dst{nullptr};
  if (override_header != nullptr && !override_header->value().empty()) {
    const std::string request_override_host(override_header->value().getStringView());
    orig_dst = Network::Utility::parseInternetAddressAndPortNoThrow(request_override_host, false);
  }
  bool valid =
      (method == Http::Headers::get().MethodValues.Get &&
       connection == Http::Headers::get().ConnectionValues.Upgrade &&
       upgrade == Http::Headers::get().UpgradeValues.WebSocket &&
       // path must be present with non-empty value, and must match expected if configured
       ((config->path_.empty() && path.length() > 0) || (path == config->path_)) &&
       // host must be present with non-empty value, and must match expected if configured
       ((config->host_.empty() && host.length() > 0) || (host == config->host_)) &&
       // key must be present with non-empty value, and must match expected if configured
       ((config->key_.empty() && key.length() > 0) || (key == config->key_)) &&
       // version must be present with non-empty value, and must match expected if configured
       ((config->version_.empty() && version.length() > 0) || (version == config->version_)) &&
       // origin must be present with non-empty value and must match expected if configured,
       // origin may not be present if not configured
       (config->origin_.empty()
            ? origin == nullptr
            : (origin != nullptr &&
               absl::AsciiStrToLower(origin->value().getStringView()) == config->origin_)) &&
       // protocol and extensions are not allowed for now
       protocol == nullptr && extensions == nullptr &&
       // override header must be present and have a valid value
       orig_dst != nullptr);
  ENVOY_LOG(debug,
            "websocket: valid = {}, method: {}/{}, path: \"{}\"/\"{}\", host: {}/{}, connection: "
            "{}/{}, upgrade: {}/{}, key: {}/{}, version: {}/{}, origin: {}/{}, protocol: {}, "
            "extensions: {}, override: {}",
            valid, method, Http::Headers::get().MethodValues.Get, path, config->path_, host,
            config->host_, connection, Http::Headers::get().ConnectionValues.Upgrade, upgrade,
            Http::Headers::get().UpgradeValues.WebSocket, key, config->key_, version,
            config->version_, origin ? origin->value().getStringView() : "<NONE>", config->origin_,
            protocol ? protocol->value().getStringView() : "<NONE>",
            extensions ? extensions->value().getStringView() : "<NONE>",
            override_header ? override_header->value().getStringView() : "<NONE>");

  return valid ? orig_dst : nullptr;
}

void Codec::startPingTimer() {
  auto& config = parent_->config();

  // Start ping timer if enabled
  if (config->ping_interval_.count()) {
    ENVOY_CONN_LOG(trace, "Enabling websocket PING timer at {} ms", connection_,
                   config->ping_interval_.count());
    ping_timer_ = connection_.dispatcher().createTimer([this]() {
      auto& config = parent_->config();
      char count_buffer[StringUtil::MIN_ITOA_OUT_LEN];
      const uint32_t count_len =
          StringUtil::itoa(count_buffer, StringUtil::MIN_ITOA_OUT_LEN, ++ping_count_);
      if (ping(count_buffer, count_len)) {
        ENVOY_CONN_LOG(trace, "Injected websocket PING {}", connection_, ping_count_);
        // Randomize ping inverval with jitter when idle
        if (ping_timer_ != nullptr) {
          uint64_t interval_ms = config->ping_interval_.count();
          const uint64_t jitter_percent_mod = ping_interval_jitter_percent_ * interval_ms / 100;
          if (jitter_percent_mod > 0) {
            interval_ms += config->random_.random() % jitter_percent_mod;
          }
          ping_timer_->enableTimer(std::chrono::milliseconds(interval_ms));
        }
      }
    });
    ping_timer_->enableTimer(config->ping_interval_);
  }
}

bool Codec::checkPrefix(Buffer::Instance& data, const std::string& prefix) {
  // Sanity check the first chars to catch non-HTTP messages
  auto cmp_len = std::min(data.length(), prefix.length());
  const char* cmp_data = reinterpret_cast<char*>(data.linearize(cmp_len));
  return absl::string_view(cmp_data, cmp_len) == absl::string_view(prefix.data(), cmp_len);
}

void Codec::decode(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "websocket: decode {} bytes, end_stream: {}", data.length(), end_stream);

  auto& config = parent_->config();

  if (!accepted_) {
    // Buffer incoming data in case it arrives in parts
    handshake_buffer_.move(data);

    if (handshake_buffer_.length() > WEBSOCKET_HANDSHAKE_MAX_SIZE) {
      config->stats_.handshake_too_large_.inc();
      return closeOnError(handshake_buffer_, "handshake message too long.");
    }
    // Client needs to wait for a valid handshake response before accepting any data
    if (config->client_) {
      // Sanity check the first chars to catch non HTTP responses
      if (!checkPrefix(handshake_buffer_, response_prefix)) {
        config->stats_.handshake_not_http_.inc();
        return closeOnError(handshake_buffer_, "response not http.");
      }
    } else {
      // Server needs to see the handshake request as the first message.
      // Sanity check the first chars to catch non HTTP requests
      if (!checkPrefix(handshake_buffer_, request_prefix)) {
        config->stats_.handshake_not_http_.inc();
        return closeOnError(handshake_buffer_, "request not http.");
      }
    }

    // Find the header separator that marks the end of the handshake request/response.
    ssize_t pos =
        handshake_buffer_.search(header_separator.data(), header_separator.length(), 0, 0);
    if (pos == -1) {
      if (end_stream) {
        config->stats_.protocol_error_.inc();
        return closeOnError(handshake_buffer_, "no request/response.");
      }
      return; // Header separator not found, Need more data
    }

    // Got the request/response, can disable the handshake timer.
    handshake_timer_->disableTimer();

    // Include the header separator in message size
    size_t msg_size = pos + header_separator.length();
    absl::string_view message = {reinterpret_cast<char*>(handshake_buffer_.linearize(msg_size)),
                                 msg_size};

    if (config->client_) {
      ResponseParser parser;
      bool ok = parser.parse(message);
      if (!ok) {
        config->stats_.handshake_parse_error_.inc();
        return closeOnError(handshake_buffer_, "response parse failed.");
      }
      handshake_buffer_.drain(msg_size);

      const Http::ResponseHeaderMap& headers = parser.headers();
      parent_->onHandshakeResponse(headers);

      if (!parser.versionIsHttp1_1()) {
        config->stats_.handshake_invalid_http_version_.inc();
        return closeOnError(handshake_buffer_, "unsupported HTTP protocol");
      }

      if (parser.status() != 101) {
        config->stats_.handshake_invalid_http_status_.inc();
        return closeOnError(handshake_buffer_, "Invalid HTTP status code for websocket");
      }

      // Validate response headers
      auto connection = absl::AsciiStrToLower(headers.getConnectionValue());
      auto upgrade = absl::AsciiStrToLower(headers.getUpgradeValue());
      auto key_accept = headers.getInlineValue(sec_websocket_accept_handle.handle());

      auto key_response = config->keyResponse(config->key_);
      accepted_ = connection == Http::Headers::get().ConnectionValues.Upgrade &&
                  upgrade == Http::Headers::get().UpgradeValues.WebSocket &&
                  key_accept == key_response;

      ENVOY_LOG(debug,
                "websocket: accepted_ = {}, connection: {}, upgrade: {}, accept: {} (expected {})",
                accepted_, connection, upgrade, key_accept, key_response);

      if (!accepted_) {
        config->stats_.handshake_invalid_websocket_response_.inc();
        return closeOnError(handshake_buffer_, "Invalid WebSocket response");
      }

      // Kick write on the other direction
      parent_->injectEncoded(encoder_.data(), encoder_.endStream());

    } else {
      // Server needs to wait for a valid handshake request before accepting any data
      RequestParser parser;
      bool ok = parser.parse(message);
      if (!ok) {
        // Consider issuing HTTP response instead?
        config->stats_.handshake_parse_error_.inc();
        return closeOnError(handshake_buffer_, "request parse failed.");
      }
      handshake_buffer_.drain(msg_size);

      const Http::RequestHeaderMap& headers = parser.headers();
      parent_->onHandshakeRequest(headers);

      if (!parser.versionIsHttp1_1()) {
        config->stats_.handshake_invalid_http_version_.inc();
        return closeOnError(handshake_buffer_, "unsupported HTTP protocol");
      }

      // Validate request headers
      auto response_headers = Http::ResponseHeaderMapImpl::create();
      Buffer::OwnedImpl response_buffer{};
      auto orig_dst = decodeHandshakeRequest(config, headers);
      accepted_ = (orig_dst != nullptr);
      if (!accepted_) {
        config->stats_.handshake_invalid_websocket_request_.inc();

        // Create handshake error response
        encodeHandshakeResponse(*response_headers, 403, "", &headers);
        encodeResponse(response_buffer, *response_headers);
        parent_->injectEncoded(response_buffer, true);
        // Check if the buffer was not drained
        if (response_buffer.length() > 0) {
          config->stats_.handshake_write_error_.inc();
        } else {
          parent_->onHandshakeResponseSent(*response_headers);
        }
        return closeOnError(handshake_buffer_, "Invalid WebSocket request");
      }

      // Create handshake response
      auto hash = Config::keyResponse(headers.getInlineValue(sec_websocket_key_handle.handle()));
      encodeHandshakeResponse(*response_headers, 200, hash, &headers);
      encodeResponse(response_buffer, *response_headers);
      parent_->injectEncoded(response_buffer, false);
      // Check if the buffer was not drained
      if (response_buffer.length() > 0) {
        config->stats_.handshake_write_error_.inc();
        return closeOnError(handshake_buffer_, "error writing handshake response");
      }
      // Set destination address for the original destination filter.
      parent_->setOriginalDestinationAddress(orig_dst);

      parent_->onHandshakeResponseSent(*response_headers);
    }

    startPingTimer();

    // Move any remaining data back to 'data'
    data.move(handshake_buffer_);
  }

  // Handshake done, process data.
  decoder_.decode(data, end_stream);

  // Reset idle timer on data
  if (decoder_.hasData()) {
    resetPingTimer();
  }

  parent_->injectDecoded(decoder_.data(), decoder_.endStream());
}

bool Codec::ping(const void* payload, size_t len) {
  if (encoder_.endStream()) {
    return false;
  }
  Buffer::OwnedImpl buf(payload, len);
  encoder_.encode(buf, false, OPCODE_PING);
  parent_->config()->stats_.ping_sent_count_.inc();
  parent_->injectEncoded(encoder_.data(), encoder_.endStream());
  return true;
}

bool Codec::pong(const void* payload, size_t len) {
  if (encoder_.endStream()) {
    return false;
  }
  Buffer::OwnedImpl buf(payload, len);
  encoder_.encode(buf, false, OPCODE_PONG);
  parent_->injectEncoded(encoder_.data(), encoder_.endStream());
  return true;
}

// Encoder

// Encode 'data' and 'end_stream' as websocket frames into 'encoded_'. Uses 'opcode' as the
// websocket frame type for the data frames.
void Codec::Encoder::encode(Buffer::Instance& data, bool end_stream, uint8_t opcode) {
  auto hex_len = std::min(data.length(), 20UL);
  const uint8_t* hex_data = reinterpret_cast<uint8_t*>(data.linearize(hex_len));
  ENVOY_LOG(debug, "websocket encoder: {} bytes: 0x{}, end_stream: {}, opcode: {}", data.length(),
            Hex::encode(hex_data, hex_len), end_stream, opcode);

  auto& config = parent_.config();
  //
  // Encode data as a single WebSocket frame
  //
  if (data.length() > 0) {
    uint8_t frame_header[14];
    size_t frame_header_length = 2;
    size_t payload_len = data.length();

    frame_header[0] = FIN_MASK | opcode;
    if (payload_len < 126) {
      frame_header[1] = payload_len;
    } else if (payload_len < 65536) {
      uint16_t len16;

      frame_header[1] = 126;
      len16 = htobe16(payload_len);
      memcpy(frame_header + frame_header_length, &len16, 2); // NOLINT(safe-memcpy)
      frame_header_length += 2;
    } else {
      uint64_t len64;

      frame_header[1] = 127;
      len64 = htobe64(payload_len);
      memcpy(frame_header + frame_header_length, &len64, 8); // NOLINT(safe-memcpy)
      frame_header_length += 8;
    }

    // Client must mask the payload
    if (config->client_) {
      frame_header[1] |= MASK_MASK;

      union {
        uint8_t bytes[4];
        uint32_t word;
      } mask;

      mask.word = config->random_.random();
      memcpy(frame_header + frame_header_length, &mask, 4); // NOLINT(safe-memcpy)
      frame_header_length += 4;
      uint8_t* buf = reinterpret_cast<uint8_t*>(data.linearize(payload_len));
      maskData(buf, payload_len, mask.bytes);
    }

    // Add frame header and (masked) data
    encoded_.add(absl::string_view{reinterpret_cast<char*>(frame_header), frame_header_length});
    encoded_.move(data, payload_len);
  }

  //
  // Append closing frame if 'end_stream'
  //
  if (end_stream) {
    uint8_t frame_header[14];
    size_t frame_header_length = 2;
    size_t payload_len = 0;

    frame_header[0] = FIN_MASK | OPCODE_CLOSE;
    frame_header[1] = payload_len;
    // Client must mask the payload
    if (config->client_) {
      frame_header[1] |= MASK_MASK;

      uint32_t mask = config->random_.random();
      memcpy(frame_header + frame_header_length, &mask, 4); // NOLINT(safe-memcpy)
      frame_header_length += 4;
      // No data to mask
    }
    encoded_.add(reinterpret_cast<void*>(frame_header), frame_header_length);
    end_stream_ = true;

    ENVOY_LOG(debug, "websocket encoder: sent WebSocket CLOSE message, end_stream: {}", end_stream);
  }
}

// Decoder

/*
 * TRY_READ_NETWORK reads sizeof(*(DATA)) bytes from 'buffer_' if available.
 * Does not drain anything from the buffer,
 * draining has to be done separately.
 */
#define TRY_READ_NETWORK(DATA)                                                                     \
  {                                                                                                \
    if (buffer_.length() < frame_offset + sizeof(*(DATA))) {                                       \
      /* Try again when we have more data */                                                       \
      return;                                                                                      \
    }                                                                                              \
    ENVOY_LOG(trace, "websocket: copyOut {} bytes at offset {}", sizeof(*(DATA)), frame_offset);   \
    buffer_.copyOut(frame_offset, sizeof(*(DATA)), (DATA));                                        \
    frame_offset += sizeof(*(DATA));                                                               \
  }

// Decode 'data' into 'decoded_'.
void Codec::Decoder::decode(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "websocket decoder: {} bytes, end_stream: {}", data.length(), end_stream);

  buffer_.move(data);

  if (end_stream_ && buffer_.length() > 0) {
    ENVOY_LOG(debug, "websocket decoder: data received after CLOSE: {} bytes", buffer_.length());
    buffer_.drain(buffer_.length());
    return;
  }

  if (end_stream) {
    end_stream_ = true;
  }

  while (buffer_.length() > 0) {
    // Try finish any frame in progress
    while (payload_remaining_ > 0) {
      auto slice = buffer_.frontSlice();
      size_t n_bytes = std::min(slice.len_, payload_remaining_);

      // Unmask data in place
      uint8_t* buf = static_cast<uint8_t*>(slice.mem_);
      auto hex_len = std::min(n_bytes, 20UL);
      if (unmasking_) {
        ENVOY_LOG(
            trace,
            "websocket decoder: unmasking payload remaining: {}, offset: {}, processing: {}: 0x{}",
            payload_remaining_, payload_offset_, n_bytes, Hex::encode(buf, hex_len));
        payload_offset_ = maskData(buf, n_bytes, mask_, payload_offset_);
      }
      ENVOY_LOG(trace, "websocket decoder: payload remaining: {}, offset: {}, processing: {}: 0x{}",
                payload_remaining_, payload_offset_, n_bytes, Hex::encode(buf, hex_len));

      decoded_.move(buffer_, n_bytes);
      payload_remaining_ -= n_bytes;

      if (buffer_.length() == 0) {
        return;
      }
    }
    //
    // Now at a frame boundary, reset state for a new frame.
    //
    unmasking_ = false;
    payload_offset_ = 0;
    RELEASE_ASSERT(payload_remaining_ == 0, "internal websocket framing error");

    uint8_t frame_header[2];
    size_t frame_offset = 0;
    uint8_t opcode;
    uint64_t payload_len;

    ENVOY_LOG(trace, "websocket decoder: remaining buffer: {} bytes", buffer_.length());

    TRY_READ_NETWORK(&frame_header);
    opcode = frame_header[0] & OPCODE_MASK;
    payload_len = frame_header[1] & PAYLOAD_LEN_MASK;

    if (payload_len == 126) {
      uint16_t len16;

      TRY_READ_NETWORK(&len16);
      payload_len = be16toh(len16);
    } else if (payload_len == 127) {
      uint64_t len64;

      TRY_READ_NETWORK(&len64);
      payload_len = be64toh(len64);
    }
    if (frame_header[1] & MASK_MASK) {
      TRY_READ_NETWORK(&mask_);
      unmasking_ = true;
    }

    //
    // Whole header received and decoded
    //

    // Terminate and respond to any control frames
    if (opcode >= OPCODE_CLOSE) {
      // Protect against too large control frames that could happen if the decoder ever loses
      // sync with the data stream.
      if (payload_len > WEBSOCKET_CONTROL_FRAME_MAX_SIZE) {
        ENVOY_LOG(debug, "websocket decoder: too large control frame: {} bytes", payload_len);
        buffer_.drain(buffer_.length());
        end_stream_ = true;
        return;
      }

      // Buffer until whole control frame has been received
      if (buffer_.length() < frame_offset + payload_len) {
        return;
      }

      // Drain control frame header, get the payload
      buffer_.drain(frame_offset);
      uint8_t* payload = reinterpret_cast<uint8_t*>(buffer_.linearize(payload_len));

      // Unmask the control frame payload
      if (unmasking_) {
        maskData(payload, payload_len, mask_);
      }

      switch (opcode) {
      case OPCODE_CLOSE:
        ENVOY_LOG(trace, "websocket decoder: CLOSE received");
        end_stream_ = true;
        break;
      case OPCODE_PING: {
        ENVOY_LOG(trace, "websocket decoder: PING received");
        // Reply with a PONG with the same payload
        parent_.pong(payload, payload_len);
        break;
      }
      case OPCODE_PONG:
        ENVOY_LOG(trace, "websocket decoder: PONG received");
        break;
      }
      // Drain control plane payload
      buffer_.drain(payload_len);
    } else {
      // Unframe and forward all non-control frames
      ENVOY_LOG(trace, "websocket decoder: received websocket data: header {} bytes, data {} bytes",
                frame_offset, payload_len);

      buffer_.drain(frame_offset);
      payload_remaining_ = payload_len;
    }
  }
}

} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
