#include "cilium/websocket.h"

#include <string>

#include <http_parser.h>

#include "cilium/api/websocket.pb.validate.h"
#include "cilium/socket_option.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/base64.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/hex.h"
#include "source/common/crypto/utility.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "envoy/registry/registry.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

namespace {

  /*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
  */

#define FIN_MASK 0x80
#define OPCODE_MASK 0x0F
#define MASK_MASK 0x80
#define PAYLOAD_LEN_MASK 0x7F

  /*
   Opcode:  4 bits

      Defines the interpretation of the "Payload data".  If an unknown
      opcode is received, the receiving endpoint MUST _Fail the
      WebSocket Connection_.  The following values are defined.

      *  %x0 denotes a continuation frame

      *  %x1 denotes a text frame

      *  %x2 denotes a binary frame

      *  %x3-7 are reserved for further non-control frames

      *  %x8 denotes a connection close

      *  %x9 denotes a ping

      *  %xA denotes a pong

      *  %xB-F are reserved for further control frames
      */
#define OPCODE_CONTINUE 0
#define OPCODE_TEXT 1
#define OPCODE_BIN 2
#define OPCODE_CLOSE 8
#define OPCODE_PING 9
#define OPCODE_PONG 10

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

} // namespace

/**
 * Config registration for the WebSocket HTTP filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumHttpConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
 public:
  Http::FilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& proto_config, const std::string&,
      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocket&>(
            proto_config, context.messageValidationVisitor()),
        context, false /* server */);
    return [config](
               Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::WebSocket::Filter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::WebSocket>();
  }

  std::string name() const override { return "cilium.http.websocket"; }
};

/**
 * Static registration for this filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumHttpConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory);

/**
 * Config registration for the WebSocket network filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumNetworkConfigFactory : public Server::Configuration::NamedNetworkFilterConfigFactory {
 public:
  // NamedNetworkFilterConfigFactory
  Network::FilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& proto_config,
      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocket&>(
            proto_config, context.messageValidationVisitor()),
        context, true /* client */);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addFilter(
          std::make_shared<Cilium::WebSocket::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::WebSocket>();
  }

  std::string name() const override { return "cilium.network.websocket"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumNetworkConfigFactory,
		 Server::Configuration::NamedNetworkFilterConfigFactory);

Config::Config(const ::cilium::WebSocket& config,
               Server::Configuration::FactoryContext& context, bool client)
  : time_source_(context.timeSource()),
    dispatcher_(context.mainThreadDispatcher()),
    stats_{ALL_WEBSOCKET_STATS(POOL_COUNTER_PREFIX(context.scope(), "websocket"))},
    random_(context.api().randomGenerator()),
    client_(client), data_opcode_(OPCODE_BIN),
    expected_host_(absl::AsciiStrToLower(config.host())),
    expected_path_(absl::AsciiStrToLower(config.path())),
    expected_version_(absl::AsciiStrToLower(config.version())),
    expected_origin_(absl::AsciiStrToLower(config.origin())),
    access_log_(nullptr) {
  // Default values for client
  if (client_) {
    if (expected_path_.empty()) {
      expected_path_ = "/";
    }
    if (expected_version_.empty()) {
      expected_version_ = "13";
    }
  }
  // Base64 encode the given/expected key
  if (config.key().length() > 0) {
    expected_key_ = Base64::encode(config.key().data(), config.key().length());
  }
  // Compute expected key response
  Buffer::OwnedImpl buf(expected_key_.data(), expected_key_.length());
  buf.add("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"); // RFC 6455
  auto sha1 = Envoy::Common::Crypto::UtilitySingleton::get().getSha1Digest(buf);
  expected_key_accept_ = Base64::encode(reinterpret_cast<char*>(sha1.data()), sha1.size());

  // Init access logging
  auto access_log_path = config.access_log_path();
  if (!access_log_path.empty()) {
    access_log_ = AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium websocket filter can not open access log socket at '{}'",
                access_log_path);
    }
  }
}

Config::~Config() {
  if (access_log_) {
    access_log_->Close();
  }
}

void Config::Log(AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

void Filter::onDestroy() {}

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  auto method = headers.getMethodValue();
  auto path = absl::AsciiStrToLower(headers.getPathValue());
  auto host = absl::AsciiStrToLower(headers.getHostValue());
  auto connection = absl::AsciiStrToLower(headers.getConnectionValue());
  auto upgrade = absl::AsciiStrToLower(headers.getUpgradeValue());
  auto key = headers.getInlineValue(sec_websocket_key_handle.handle());
  auto version = absl::AsciiStrToLower(headers.getInlineValue(sec_websocket_version_handle.handle()));
  auto origin = headers.getInline(origin_handle.handle());
  auto protocol = headers.getInline(sec_websocket_protocol_handle.handle());
  auto extensions = headers.getInline(sec_websocket_extensions_handle.handle());
  auto override_header = headers.getInline(original_dst_host_handle.handle());
  upgrade_ = (method == Http::Headers::get().MethodValues.Get &&
	      connection == Http::Headers::get().ConnectionValues.Upgrade &&
	      upgrade == Http::Headers::get().UpgradeValues.WebSocket &&
	      // path must be present with non-empty value, and must match expected if configured
	      ((config_->expected_path_.empty() && path.length() > 0) ||
	       (path == config_->expected_path_)) &&
	      // host must be present with non-empty value, and must match expected if configured
	      ((config_->expected_host_.empty() && host.length() > 0) ||
	       (host == config_->expected_host_)) &&
	      // key must be present with non-empty value, and must match expected if configured
	      ((config_->expected_key_.empty() && key.length() > 0) ||
	       (key == config_->expected_key_)) &&
	      // version must be present with non-empty value, and must match expected if configured
	      ((config_->expected_version_.empty() && version.length() > 0) ||
	       (version == config_->expected_version_)) &&
	      // origin must be present with non-empty value and must match expected if configured,
	      // origin may not be present if not configured
	      (config_->expected_origin_.empty() ?
	       origin == nullptr :
	       (origin != nullptr &&
		absl::AsciiStrToLower(origin->value().getStringView()) == config_->expected_origin_)) &&
	      // protocol and extensions are not allowed for now
	      protocol == nullptr && extensions == nullptr &&
	      // override header must be present and have a value
	      override_header != nullptr && !override_header->value().empty());
  ENVOY_LOG(info, "cilium.http.websocket: upgrade_ = {}, method: {}/{}, path: \"{}\"/\"{}\", host: {}/{}, connection: {}/{}, upgrade: {}/{}, key: {}/{}, version: {}/{}, origin: {}/{}, protocol: {}, extensions: {}, override: {}",
	    upgrade_,
	    method, Http::Headers::get().MethodValues.Get,
	    path, config_->expected_path_,
	    host, config_->expected_host_,
	    connection, Http::Headers::get().ConnectionValues.Upgrade,
	    upgrade, Http::Headers::get().UpgradeValues.WebSocket,
	    key, config_->expected_key_,
	    version, config_->expected_version_,
	    origin ? origin->value().getStringView() : "<NONE>", config_->expected_origin_,
	    protocol ? protocol->value().getStringView() : "<NONE>",
	    extensions ? extensions->value().getStringView() : "<NONE>",
	    override_header ? override_header->value().getStringView(): "<NONE>");

  std::string pod_ip;
  bool is_ingress;
  uint32_t identity, destination_identity;

  const Network::Address::InstanceConstSharedPtr& dst_address =
    callbacks_->streamInfo().downstreamAddressProvider().localAddress();
  const Network::Address::Ip* dip = dst_address ? dst_address->ip() : nullptr;
  const auto& conn = callbacks_->connection();
  const Network::Socket::OptionsSharedPtr socketOptions = conn->socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);
  if (option) {
    pod_ip = option->pod_ip_;
    is_ingress = option->ingress_;
    identity = option->identity_;
    destination_identity = dip ? option->resolvePolicyId(dip) : 0;
  } else {
    // Default to ingress to destination address, but no security identities.
    pod_ip = dip ? dip->addressAsString() : "";
    is_ingress = true;
    identity = 0;
    destination_identity = 0;
  }

  // Initialize the log entry
  log_entry_.InitFromRequest(pod_ip, is_ingress, identity,
			     callbacks_->streamInfo().downstreamAddressProvider().remoteAddress(),
			     destination_identity, dst_address,
			     callbacks_->streamInfo(), headers);

  if (upgrade_) {
    // Log as a forwarded request
    config_->Log(log_entry_, ::cilium::EntryType::Request);
  } else {
    // Return a 403 response
    callbacks_->sendLocalReply(Http::Code::Forbidden, "Access denied\r\n",
			       nullptr, absl::nullopt, absl::string_view());
    return Http::FilterHeadersStatus::StopIteration;
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  accepted_ = headers.Status() && headers.getStatusValue() == "101";
  ENVOY_LOG(info, "cilium.http.websocket: accepted_ = {}", accepted_);

  auto logType = ::cilium::EntryType::Response;
  if (!upgrade_) {
    logType = ::cilium::EntryType::Denied;
    config_->stats_.access_denied_.inc();
  } else {
    log_entry_.UpdateFromResponse(headers, config_->time_source_);
  }
  config_->Log(log_entry_, logType);

  return Http::FilterHeadersStatus::Continue;
}

void Filter::maskData(uint8_t *buf, size_t n_bytes) {
  for (size_t i = 0; i < n_bytes; i++) {
    buf[i] ^= mask_.bytes[payload_offset_ % 4];
    payload_offset_++;
  }
}

/*
 * TRY_READ reads sizeof(*(DATA)) bytes from 'buffer_' if available.
 * Does not drain anything from the buffer,
 * draining has to be done separately.
 */
#define TRY_READ(DATA)						\
  {								\
    if (buffer_.length() < frame_offset+sizeof(*(DATA))) {	\
      /* Try again when we have more data */			\
      return Http::FilterDataStatus::Continue;			\
    }								\
    buffer_.copyOut(frame_offset, sizeof(*(DATA)), (DATA));	\
    frame_offset += sizeof(*(DATA));				\
  }

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& data, bool end_stream) {
  size_t frame_offset = 0;
  uint8_t frame_header[2];
  uint8_t opcode;
  uint64_t payload_len;

  buffer_.move(data);

  if (end_stream) {
    decode_end_stream_ = true;
  }

  // Buffer data until accepted
  if (!(upgrade_ && accepted_)) {
    return Http::FilterDataStatus::Continue;
  }

  while (buffer_.length() > 0) {
    // Try finish any frame in progress
    while (payload_remaining_ > 0) {
      auto slice = buffer_.frontSlice();
      size_t n_bytes = std::min(slice.len_, payload_remaining_);

      // Unmask data in place
      uint8_t* buf = static_cast<uint8_t*>(slice.mem_);
      maskData(buf, n_bytes);
      data.add(buf, n_bytes);
      payload_remaining_ -= n_bytes;
      buffer_.drain(n_bytes);

      if (buffer_.length() == 0) {
	return Http::FilterDataStatus::Continue;
      }
    }
    //
    // Now at a frame boundary, reset state for a new frame.
    //
    payload_offset_ = 0;
    RELEASE_ASSERT(payload_remaining_ == 0, "internal websocket framing error");

    TRY_READ(&frame_header);
    opcode = frame_header[0] & OPCODE_MASK;
    payload_len = frame_header[1] & PAYLOAD_LEN_MASK;

    if (payload_len == 126) {
      uint16_t len16;

      TRY_READ(&len16);
      payload_len = be16toh(len16);
    } else if (payload_len == 127) {
      uint64_t len64;

      TRY_READ(&len64);
      payload_len = be64toh(len64);
    }
    if (frame_header[1] & MASK_MASK) {
      TRY_READ(&mask_);
    }
    
    //
    // Whole header received and decoded
    //

    // Terminate and respond to any control frames
    if (opcode >= OPCODE_CLOSE) {
      // Buffer until whole control frame has been received
      if (buffer_.length() < frame_offset + payload_len) {
	return Http::FilterDataStatus::Continue;
      }
      // Drain control frame header, get the payload
      buffer_.drain(frame_offset);
      uint8_t *payload = reinterpret_cast<uint8_t *>(buffer_.linearize(payload_len));

      // Unmask the control frame payload
      if (frame_header[1] & MASK_MASK) {
	maskData(payload, payload_len);
      }

      switch (opcode) {
      case OPCODE_CLOSE:
	ENVOY_LOG(trace, "cilium.http.websocket: CLOSE received with payload: {}",
		  Hex::encode(payload, payload_len));
	closed_ = true;
	// TODO: Half-close upstream TCP connection??
	// Do not trigger CLOSE on the other direction as it may still stream data.
	break;
      case OPCODE_PING: {
	ENVOY_LOG(trace, "cilium.http.websocket: PING received with payload {}",
		  Hex::encode(payload, payload_len));
	Buffer::OwnedImpl reply(reinterpret_cast<void*>(payload), payload_len);
	encode_opcode_ = OPCODE_PONG;
	callbacks_->encodeData(reply, false);
	encode_opcode_ = config_->data_opcode_; // back to default opcode for data
	break;
      }
      case OPCODE_PONG:
	ENVOY_LOG(trace, "cilium.http.websocket: PONG received with payload {}",
		  Hex::encode(payload, payload_len));
	break;
      }
      // Drain control plane payload
      buffer_.drain(payload_len);
    } else {
      // Unframe and forward all non-control frames
      buffer_.drain(frame_offset);
      payload_remaining_ = payload_len;
    }
  }
  return Http::FilterDataStatus::Continue;
}

Http::FilterDataStatus Filter::encodeData(Buffer::Instance& data, bool end_stream) {
  //
  // Encode data as a single WebSocket frame
  //
  if (data.length() > 0) {
    uint8_t frame_header[14];
    size_t frame_header_length = 2;
    size_t payload_len = data.length();

    frame_header[0] = FIN_MASK | encode_opcode_;
    if (payload_len < 126) {
      frame_header[1] = payload_len;
    } else if (payload_len < 65536) {
      uint16_t len16;

      frame_header[1] = 126;
      len16 = htobe16(payload_len);
      memcpy(frame_header+frame_header_length, &len16, 2);
      frame_header_length += 2;
    } else {
      uint64_t len64;

      frame_header[1] = 127;
      len64 = htobe64(payload_len);
      memcpy(frame_header+frame_header_length, &len64, 8);
      frame_header_length += 8;
    }

    // mask if 'client'
    if (config_->client_) {
      frame_header[1] |= MASK_MASK;

      mask_.word = config_->random_.random();
      memcpy(frame_header+frame_header_length, &mask_, 4);
      frame_header_length += 4;
      uint8_t *buf = reinterpret_cast<uint8_t *>(data.linearize(payload_len));
      maskData(buf, payload_len);
    }

    // Prepend frame header to data
    data.prepend(absl::string_view{reinterpret_cast<char *>(frame_header), frame_header_length});
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
    // mask if 'client'
    if (config_->client_) {
      frame_header[1] |= MASK_MASK;

      uint32_t mask = config_->random_.random();
      memcpy(frame_header+frame_header_length, &mask, 4);
      frame_header_length += 4;
      // No data to mask
    }
    data.add(reinterpret_cast<void*>(frame_header), frame_header_length);
    encode_end_stream_ = true;
  }
  return Http::FilterDataStatus::Continue;
}

//
// Network filter implementation
//

namespace {

size_t maskData(uint8_t *buf, size_t n_bytes, uint8_t mask[4], size_t payload_offset = 0) {
  for (size_t i = 0; i < n_bytes; i++) {
    buf[i] ^= mask[payload_offset % 4];
    payload_offset++;
  }
  return payload_offset;
}

static const char REQUEST_POSTFIX[] = " HTTP/1.1\r\n";
#define CRLF "\r\n"

void encodeHeader(Buffer::Instance& buffer, absl::string_view key, absl::string_view value) {
  buffer.add(key);
  buffer.add(": ", 2);
  buffer.add(value);
  buffer.add(CRLF, 2);
}

void encodeHeaders(Buffer::Instance& buffer, Http::RequestHeaderMap& headers) {
  const Http::HeaderEntry* method = headers.Method();
  const Http::HeaderEntry* path = headers.Path();

  buffer.add(method->value().getStringView());
  buffer.add(" ", 1);
  buffer.add(path->value().getStringView());
  buffer.add(REQUEST_POSTFIX, sizeof(REQUEST_POSTFIX) - 1);

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
  buffer.add(CRLF, 2);
}

} // namespace

Network::FilterStatus Instance::onNewConnection() {
  ENVOY_LOG(debug, "cilium.network.websocket: onNewConnection");

  std::string pod_ip;
  bool is_ingress;
  uint32_t identity, destination_identity;

  auto& conn = callbacks_->connection();
  const Network::Address::InstanceConstSharedPtr& dst_address =
    conn.connectionInfoProvider().localAddress();
  const Network::Address::Ip* dip = dst_address ? dst_address->ip() : nullptr;
  const Network::Socket::OptionsSharedPtr socketOptions = conn.socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);
  if (option) {
    pod_ip = option->pod_ip_;
    is_ingress = option->ingress_;
    identity = option->identity_;
    destination_identity = dip ? option->resolvePolicyId(dip) : 0;
  } else {
    // Default to ingress to destination address, but no security identities.
    pod_ip = dip ? dip->addressAsString() : "";
    is_ingress = true;
    identity = 0;
    destination_identity = 0;
  }
  // Initialize the log entry
  log_entry_.InitFromConnection(pod_ip, is_ingress, identity,
				callbacks_->connection().connectionInfoProvider().remoteAddress(),
				destination_identity, dst_address, &config_->time_source_);

  // Create WebSocket Handshake
  const Http::HeaderValues& header_values = Http::Headers::get();
  Envoy::Http::RequestHeaderMapPtr headers = Http::RequestHeaderMapImpl::create();
  headers->setReferenceMethod(header_values.MethodValues.Get);
  headers->setReferencePath(config_->expected_path_);
  headers->setReferenceHost(config_->expected_host_);
  headers->setReferenceUpgrade(header_values.UpgradeValues.WebSocket);
  headers->setReferenceConnection(header_values.ConnectionValues.Upgrade);
  headers->setReferenceInline(sec_websocket_key_handle.handle(), config_->expected_key_);
  headers->setReferenceInline(sec_websocket_version_handle.handle(), config_->expected_version_);
  if (!config_->expected_origin_.empty()) {
      headers->setReferenceInline(origin_handle.handle(), config_->expected_origin_);
  }
  headers->setReferenceInline(original_dst_host_handle.handle(), dst_address->asStringView());

  encodeHeaders(handshake_buffer_, *headers);
  log_entry_.UpdateFromRequest(0, nullptr, *headers);
#if 0
  // Inject handshake to the next filter in the filter chain
  handshake_cb_ = conn.dispatcher().createSchedulableCallback([this]() {
    callbacks_->injectReadDataToFilterChain(handshake_buffer_, false);
    handshake_sent_ = true;
    config_->Log(log_entry_, ::cilium::EntryType::Request);
  });
#else
  //  callbacks_->injectReadDataToFilterChain(handshake_buffer_, false);
  //  handshake_sent_ = true;
  //  config_->Log(log_entry_, ::cilium::EntryType::Request);
#endif
  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(debug, "cilium.network.websocket: onData");

  //
  // Encode data as a single WebSocket frame
  //
  if (data.length() > 0) {
    uint8_t frame_header[14];
    size_t frame_header_length = 2;
    size_t payload_len = data.length();

    frame_header[0] = FIN_MASK | encode_opcode_;
    if (payload_len < 126) {
      frame_header[1] = payload_len;
    } else if (payload_len < 65536) {
      uint16_t len16;

      frame_header[1] = 126;
      len16 = htobe16(payload_len);
      memcpy(frame_header+frame_header_length, &len16, 2);
      frame_header_length += 2;
    } else {
      uint64_t len64;

      frame_header[1] = 127;
      len64 = htobe64(payload_len);
      memcpy(frame_header+frame_header_length, &len64, 8);
      frame_header_length += 8;
    }

    // mask if 'client'
    if (config_->client_) {
      frame_header[1] |= MASK_MASK;

      union {
	uint8_t bytes[4];
	uint32_t word;
      } mask;
      
      mask.word = config_->random_.random();
      memcpy(frame_header+frame_header_length, &mask, 4);
      frame_header_length += 4;
      uint8_t *buf = reinterpret_cast<uint8_t *>(data.linearize(payload_len));
      maskData(buf, payload_len, mask.bytes);
    }

    // Prepend frame header to data
    data.prepend(absl::string_view{reinterpret_cast<char *>(frame_header), frame_header_length});
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
    // mask if 'client'
    if (config_->client_) {
      frame_header[1] |= MASK_MASK;

      uint32_t mask = config_->random_.random();
      memcpy(frame_header+frame_header_length, &mask, 4);
      frame_header_length += 4;
      // No data to mask
    }
    data.add(reinterpret_cast<void*>(frame_header), frame_header_length);
    encode_end_stream_ = true;
  }

  // Swap in the handshake if not sent yet
  if (!accepted_) {
    encoded_buffer_.move(data);
    if (!handshake_sent_) {
      data.move(handshake_buffer_);
      handshake_sent_ = true;
      config_->Log(log_entry_, ::cilium::EntryType::Request);

      ENVOY_CONN_LOG(trace, "Enabling websocket handshake timeout at {} ms",
		     callbacks_->connection(), handshake_timeout_.count());
      handshake_timer_ = callbacks_->connection().dispatcher().createTimer([this]() {
	closeOnError("websocket handshake timed out");
      });
      handshake_timer_->enableTimer(handshake_timeout_);
    }
    return Network::FilterStatus::Continue;
  }

  // Prepend buffered data if any
  if (encoded_buffer_.length() > 0) {
    data.prepend(encoded_buffer_);
  }

  return Network::FilterStatus::Continue;
}

class ResponseParser : public Logger::Loggable<Logger::Id::filter> {
public:
  ResponseParser() : headers_(Http::ResponseHeaderMapImpl::create()) {}

  int completeLastHeader() {
    if (Http::HeaderUtility::headerNameContainsUnderscore(current_header_field_.getStringView())) {
      ENVOY_LOG(debug, "cilium.network.websocket: Rejecting invalid header: key={} value={}",
		current_header_field_.getStringView(), current_header_value_.getStringView());
      return -1;
    }
    ENVOY_LOG(trace, "cilium.network.websocket: completed header: key={} value={}",
	      current_header_field_.getStringView(), current_header_value_.getStringView());
    
    if (!current_header_field_.empty()) {
      // Strip trailing whitespace of the current header value if any. Leading whitespace was
      // trimmed in onHeaderValue. http_parser does not strip leading or trailing whitespace as the
      // spec requires: https://tools.ietf.org/html/rfc7230#section-3.2.4
      current_header_value_.rtrim();

      current_header_field_.inlineTransform([](char c) { return absl::ascii_tolower(c); });

      headers_->addViaMove(std::move(current_header_field_),
			   std::move(current_header_value_));
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
      ENVOY_LOG(debug, "cilium.network.websocket: invalid header value: {}", header_value);
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

  int onHeadersComplete() {
    headers_->setStatus(parser_.status_code);
    return completeLastHeader();
  }

  bool parseHttpResponse(absl::string_view msg) {
    http_parser_init(&parser_, HTTP_RESPONSE);
    parser_.data = this;
    http_parser_settings settings = {
      nullptr, /* on_message_begin */
      nullptr, /* on_URL */
      nullptr, /* on_status */
      [](http_parser* parser, const char* at, size_t length) -> int {
	return static_cast<ResponseParser*>(parser->data)->onHeaderField(at, length);
      }, /* on_header_field */
      [](http_parser* parser, const char* at, size_t length) -> int {
	return static_cast<ResponseParser*>(parser->data)->onHeaderValue(at, length);
      }, /* on_header_value */
      [](http_parser* parser) -> int {
	return static_cast<ResponseParser*>(parser->data)->onHeadersComplete();
      }, /* on_headers_complete */
      nullptr, /* on_body */
      [](http_parser* parser) -> int {
	static_cast<ResponseParser*>(parser->data)->response_complete_ = true;
	return 0;
      }, /* on_message_complete */
      nullptr, /* chunk header, chunk length in parser->content_length */
      nullptr, /* chunk complete */
    };

    ssize_t rc = http_parser_execute(&parser_, &settings, msg.data(), msg.length());
    ENVOY_LOG(trace, "cilium.network.websocket: http_parser parsed {} chars, error code: {}", rc,
	      HTTP_PARSER_ERRNO(&parser_));

    // Errors in parsing HTTP.
    if (HTTP_PARSER_ERRNO(&parser_) != HPE_OK) {
      return false;
    }

    return response_complete_;
  }

  const Http::ResponseHeaderMap& headers() {
    return *(headers_.get());
  }

  unsigned int status() {
    ENVOY_LOG(trace, "cilium.network.websocket: http_parser got status: {}",
	      parser_.status_code);
    return parser_.status_code;
  }

  bool versionIsHttp1_1() {
    ENVOY_LOG(trace, "cilium.network.websocket: http_parser got version major: {} minor: {}",
	      parser_.http_major, parser_.http_minor);
    return parser_.http_major == 1 && parser_.http_minor == 1;
  }

  uint32_t size() {
    return parser_.nread;
  }

private:
  Http::ResponseHeaderMapPtr headers_;
  http_parser parser_;

  Http::HeaderString current_header_field_;
  Http::HeaderString current_header_value_;
  bool parsing_value_{false};
  bool response_complete_{false};
};

static const absl::string_view header_separator = {CRLF CRLF, sizeof(CRLF CRLF) - 1};

Network::FilterStatus Instance::closeOnError(const char *msg) {
  callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
  if (msg) {
    ENVOY_LOG(debug, "cilium.network.websocket: Closing connection: {}", msg);
  }
  return Network::FilterStatus::StopIteration;
}

/*
 * TRY_READ_NETWORK reads sizeof(*(DATA)) bytes from 'decode_buffer_' if available.
 * Does not drain anything from the buffer,
 * draining has to be done separately.
 */
#define TRY_READ_NETWORK(DATA)						\
  {									\
    if (decode_buffer_.length() < frame_offset+sizeof(*(DATA))) {	\
      /* Try again when we have more data */				\
      return Network::FilterStatus::Continue;				\
    }									\
    decode_buffer_.copyOut(frame_offset, sizeof(*(DATA)), (DATA));	\
    frame_offset += sizeof(*(DATA));					\
  }

Network::FilterStatus Instance::onWrite(Buffer::Instance& data, bool end_stream) {
  size_t frame_offset = 0;
  uint8_t frame_header[2];
  uint8_t opcode;
  uint64_t payload_len;

  decode_buffer_.move(data);

  if (end_stream) {
    decode_end_stream_ = true;
  }

  // Decode for the handshake response until accepted
  if (!accepted_) {
    // Kill the connection if any data is received before the handshake is sent
    if (!handshake_sent_) {
      return closeOnError("data received before handshake was sent");
    }
    if (decode_buffer_.length() > HTTP_MAX_HEADER_SIZE) {
      return closeOnError("response message too long.");
    }
    ssize_t pos = decode_buffer_.search(header_separator.data(), header_separator.length(), 0, 0);
    if (pos == -1) {
      return Network::FilterStatus::Continue; // Need more data
    }

    handshake_timer_->disableTimer();

    // Include the header separator
    size_t msg_size = pos + header_separator.length();
    ResponseParser parser;
    absl::string_view response = { reinterpret_cast<char*>(decode_buffer_.linearize(msg_size)), msg_size };
    bool ok = parser.parseHttpResponse(response);
    if (!ok) {
      return closeOnError("response parse failed.");
    }

    const Http::ResponseHeaderMap& headers = parser.headers();
    log_entry_.UpdateFromResponse(headers, config_->time_source_);
    config_->Log(log_entry_, ::cilium::EntryType::Response);

    if (!parser.versionIsHttp1_1()) {
      return closeOnError("unsupported HTTP protocol");
    }

    if (parser.status() != 101) {
      return closeOnError("Invalid HTTP status code for websocket");
    }

    // Validate response headers
    auto connection = absl::AsciiStrToLower(headers.getConnectionValue());
    auto upgrade = absl::AsciiStrToLower(headers.getUpgradeValue());
    auto key_accept = headers.getInlineValue(sec_websocket_accept_handle.handle());

    accepted_ =
      connection == Http::Headers::get().ConnectionValues.Upgrade &&
      upgrade == Http::Headers::get().UpgradeValues.WebSocket &&
      key_accept == config_->expected_key_accept_;
  
    ENVOY_LOG(info, "cilium.network.websocket: accepted_ = {}, connection: {}, upgrade: {}, accept: {}",
	      accepted_, connection, upgrade, key_accept);

    if (!accepted_) {
      return closeOnError("Invalid WebSocket response");
    }
    decode_buffer_.drain(msg_size);

    // Kick write on the other direction
    callbacks_->injectReadDataToFilterChain(encoded_buffer_, encode_end_stream_);

    // Start ping timer
    ENVOY_CONN_LOG(trace, "Enabling websocket PING timer at {} ms",
		   callbacks_->connection(), ping_interval_.count());
    ping_timer_ = callbacks_->connection().dispatcher().createTimer([this]() {
      if (!encode_end_stream_) {
	char count_buffer[StringUtil::MIN_ITOA_OUT_LEN];
	const uint32_t count_len = StringUtil::itoa(count_buffer, StringUtil::MIN_ITOA_OUT_LEN,
						    ping_count_++);

	Buffer::OwnedImpl ping(reinterpret_cast<void*>(count_buffer), count_len);
	encode_opcode_ = OPCODE_PING;
	auto ret = onData(ping, false);
	if (ret == Network::FilterStatus::Continue) {
	  ENVOY_CONN_LOG(trace, "Injecting websocket PING {}",
			 callbacks_->connection(), ping_count_);
	  callbacks_->injectReadDataToFilterChain(ping, false);
	} else {
	  ENVOY_CONN_LOG(trace, "Encoding websocket PING failed",
			 callbacks_->connection());
	}
	encode_opcode_ = config_->data_opcode_; // back to default opcode for data

	if (ping_timer_ != nullptr && ping_interval_.count()) {
	  uint64_t interval_ms = ping_interval_.count();
	  const uint64_t jitter_percent_mod = ping_interval_jitter_percent_ * interval_ms / 100;
	  if (jitter_percent_mod > 0) {
	    interval_ms += config_->random_.random() % jitter_percent_mod;
	  }
	  ping_timer_->enableTimer(std::chrono::milliseconds(interval_ms));
	}
      }
    });
    ping_timer_->enableTimer(ping_interval_);

    return Network::FilterStatus::Continue;
  }

  while (decode_buffer_.length() > 0) {
    // Try finish any frame in progress
    while (payload_remaining_ > 0) {
      auto slice = decode_buffer_.frontSlice();
      size_t n_bytes = std::min(slice.len_, payload_remaining_);

      // Unmask data in place
      uint8_t* buf = static_cast<uint8_t*>(slice.mem_);
      if (decoder_unmasking_) {
	payload_offset_ = maskData(buf, n_bytes, mask_.bytes, payload_offset_);
      }
      data.add(buf, n_bytes);
      payload_remaining_ -= n_bytes;
      decode_buffer_.drain(n_bytes);

      if (decode_buffer_.length() == 0) {
	return Network::FilterStatus::Continue;
      }
    }
    //
    // Now at a frame boundary, reset state for a new frame.
    //
    decoder_unmasking_ = false;
    payload_offset_ = 0;
    RELEASE_ASSERT(payload_remaining_ == 0, "internal websocket framing error");

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
    }
    
    //
    // Whole header received and decoded
    //

    // Terminate and respond to any control frames
    if (opcode >= OPCODE_CLOSE) {
      // Buffer until whole control frame has been received
      if (decode_buffer_.length() < frame_offset + payload_len) {
	return Network::FilterStatus::Continue;
      }
      // Drain control frame header, get the payload
      decode_buffer_.drain(frame_offset);
      uint8_t *payload = reinterpret_cast<uint8_t *>(decode_buffer_.linearize(payload_len));

      // Unmask the control frame payload
      if (frame_header[1] & MASK_MASK) {
	decoder_unmasking_ = true;
	payload_offset_ = maskData(payload, payload_len, mask_.bytes, payload_offset_);
      }

      switch (opcode) {
      case OPCODE_CLOSE:
	ENVOY_LOG(trace, "cilium.http.websocket: CLOSE received with payload: {}",
		  Hex::encode(payload, payload_len));
	closed_ = true;
	// TODO: Half-close upstream TCP connection??
	// Do not trigger CLOSE on the other direction as it may still stream data.
	break;
      case OPCODE_PING: {
	ENVOY_LOG(trace, "cilium.http.websocket: PING received with payload {}",
		  Hex::encode(payload, payload_len));
#if 0
	Buffer::OwnedImpl reply(reinterpret_cast<void*>(payload), payload_len);
	encode_opcode_ = OPCODE_PONG;
	callbacks_->encodeData(reply, false);
	encode_opcode_ = config_->data_opcode_; // back to default opcode for data
#endif
	break;
      }
      case OPCODE_PONG:
	ENVOY_LOG(trace, "cilium.http.websocket: PONG received with payload {}",
		  Hex::encode(payload, payload_len));
	break;
      }
      // Drain control plane payload
      decode_buffer_.drain(payload_len);
    } else {
      // Unframe and forward all non-control frames
      decode_buffer_.drain(frame_offset);
      payload_remaining_ = payload_len;
    }
  }

  return Network::FilterStatus::Continue;
}

}  // namespace WebSocket
}  // namespace Cilium
}  // namespace Envoy
