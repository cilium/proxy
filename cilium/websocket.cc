#include "cilium/websocket.h"

#include <string>

#include "cilium/api/websocket.pb.validate.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/hex.h"
#include "source/common/http/header_map_impl.h"
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

} // namespace

class ConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
 public:
  Http::FilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& proto_config, const std::string&,
      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocket&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](
               Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::WebSocket::Filter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::WebSocket>();
  }

  std::string name() const override { return "cilium.websocket"; }
};

/**
 * Static registration for this filter. @see RegisterFactory.
 */
REGISTER_FACTORY(ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory);

Config::Config(const ::cilium::WebSocket& config,
               Server::Configuration::FactoryContext& context)
  : time_source_(context.timeSource()),
    stats_{ALL_WEBSOCKET_STATS(POOL_COUNTER_PREFIX(context.scope(), "websocket"))},
    random_(context.api().randomGenerator()),
    client_(false), data_opcode_(OPCODE_BIN),
    expected_host_(absl::AsciiStrToLower(config.host())),
    expected_path_(absl::AsciiStrToLower(config.path())),
    expected_key_(config.key()), // base64 format, case is significant
    expected_version_(absl::AsciiStrToLower(config.version())),
    expected_origin_(absl::AsciiStrToLower(config.origin())) {}

Config::~Config() {}

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
	      ((config_->expected_path_ == "" && path.length() > 0) ||
	       (path == config_->expected_path_)) &&
	      // host must be present with non-empty value, and must match expected if configured
	      ((config_->expected_host_ == "" && host.length() > 0) ||
	       (host == config_->expected_host_)) &&
	      // key must be present with non-empty value, and must match expected if configured
	      ((config_->expected_key_ == "" && key.length() > 0) ||
	       (key == config_->expected_key_)) &&
	      // version must be present with non-empty value, and must match expected if configured
	      ((config_->expected_version_ == "" && version.length() > 0) ||
	       (version == config_->expected_version_)) &&
	      // origin must be present with non-empty value and must match expected if configured,
	      // origin may not be present if not configured
	      (config_->expected_origin_ == "" ?
	       origin == nullptr :
	       (origin != nullptr &&
		absl::AsciiStrToLower(origin->value().getStringView()) == config_->expected_origin_)) &&
	      // protocol and extensions are not allowed for now
	      protocol == nullptr && extensions == nullptr &&
	      // override header must be present and have a value
	      override_header != nullptr && !override_header->value().empty());
  ENVOY_LOG(info, "cilium.websocket: upgrade_ = {}, method: {}, path: {}, host: {}, connection: {}, upgrade: {}. key: {}, version: {}, origin: {}, protocol: {}, extensions: {}",
	    upgrade_, method, path, host, connection, upgrade, key, version, origin ? origin->value().getStringView() : "<NONE>", protocol ? protocol->value().getStringView() : "<NONE>", extensions ? extensions->value().getStringView() : "<NONE>");

  if (!upgrade_) {
    // Return a 403 response
    callbacks_->sendLocalReply(Http::Code::Forbidden, "Access denied\r\n",
			       nullptr, absl::nullopt, absl::string_view());
    return Http::FilterHeadersStatus::StopIteration;
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  accepted_ = headers.Status() && headers.getStatusValue() == "101";
  ENVOY_LOG(info, "cilium.websocket: accepted_ = {}", accepted_);
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
	ENVOY_LOG(trace, "cilium.websocket: CLOSE received with payload: {}",
		  Hex::encode(payload, payload_len));
	closed_ = true;
	// TODO: Half-close upstream TCP connection??
	// Do not trigger CLOSE on the other direction as it may still stream data.
	break;
      case OPCODE_PING: {
	ENVOY_LOG(trace, "cilium.websocket: PING received with payload {}",
		  Hex::encode(payload, payload_len));
	Buffer::OwnedImpl reply(reinterpret_cast<void*>(payload), payload_len);
	encode_opcode_ = OPCODE_PONG;
	callbacks_->encodeData(reply, false);
	encode_opcode_ = config_->data_opcode_; // back to default opcode for data
	break;
      }
      case OPCODE_PONG:
	ENVOY_LOG(trace, "cilium.websocket: PONG received with payload {}",
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

}  // namespace WebSocket
}  // namespace Cilium
}  // namespace Envoy
