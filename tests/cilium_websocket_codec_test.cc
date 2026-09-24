#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"

#include "source/common/buffer/buffer_impl.h"

#include "test/mocks/network/connection.h"
#include "test/mocks/server/factory_context.h"

#include "absl/strings/string_view.h"
#include "cilium/websocket_codec.h"
#include "cilium/websocket_config.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {
namespace {

using testing::Return;

class TestBuffer : public Buffer::OwnedImpl {
public:
  void* linearize(uint32_t size) override {
    linearize_sizes_.push_back(size);
    return Buffer::OwnedImpl::linearize(size);
  }

  std::vector<uint32_t> linearize_sizes_;
};

class TestCodecCallbacks : public CodecCallbacks {
public:
  explicit TestCodecCallbacks(ConfigSharedPtr config) : config_(std::move(config)) {}

  const ConfigSharedPtr& config() override { return config_; }

  void injectEncoded(Buffer::Instance& data, bool) override { encoded_.move(data); }
  void injectDecoded(Buffer::Instance& data, bool) override { data.drain(data.length()); }

  void setOriginalDestinationAddress(const Network::Address::InstanceConstSharedPtr&) override {}
  void onHandshakeCreated(const Http::RequestHeaderMap&) override {}
  void onHandshakeSent() override {}
  void onHandshakeRequest(const Http::RequestHeaderMap&) override {}
  void onHandshakeResponse(const Http::ResponseHeaderMap&) override {}
  void onHandshakeResponseSent(const Http::ResponseHeaderMap&) override {}

  Buffer::OwnedImpl encoded_;

private:
  ConfigSharedPtr config_;
};

void addSeparateSlice(Buffer::OwnedImpl& buffer, absl::string_view data) {
  auto reservation = buffer.reserveSingleSlice(data.size(), true);
  auto slice = reservation.slice();
  std::copy(data.begin(), data.end(), static_cast<char*>(slice.mem_));
  reservation.commit(data.size());
}

TEST(WebSocketCodecTest, ClientMaskContinuesAcrossBufferSlices) {
  testing::NiceMock<Server::Configuration::MockFactoryContext> factory_context;
  ON_CALL(factory_context.server_factory_context_.api_.random_, random())
      .WillByDefault(Return(0x04030201));

  Protobuf::Duration duration;
  auto config = std::make_shared<Config>(factory_context, true, "", "example.com", "/", "key", "13",
                                         "", duration, duration, false);
  TestCodecCallbacks callbacks(config);
  testing::NiceMock<Network::MockConnection> connection;
  Codec codec(&callbacks, connection);

  const std::string payload = "abcdefghijklmnopqrstuvwxyz";
  TestBuffer data;
  addSeparateSlice(data, absl::string_view(payload).substr(0, 21));
  addSeparateSlice(data, absl::string_view(payload).substr(21));
  ASSERT_EQ(2, data.getRawSlices().size());

  // Encoding before the handshake completes buffers the frame internally.
  codec.encode(data, false);
  EXPECT_EQ(0, data.length());
  EXPECT_EQ(0, callbacks.encoded_.length());
  // The encoder may linearize its 20-byte debug preview, but must not linearize the whole payload.
  EXPECT_THAT(data.linearize_sizes_, testing::ElementsAre(20));

  const std::string handshake_response = "HTTP/1.1 101 Switching Protocols\r\n"
                                         "connection: upgrade\r\n"
                                         "upgrade: websocket\r\n"
                                         "sec-websocket-accept: " +
                                         Config::keyResponse(config->key_) + "\r\n\r\n";
  Buffer::OwnedImpl response(handshake_response);
  codec.decode(response, false);

  std::string frame = callbacks.encoded_.toString();
  ASSERT_EQ(payload.size() + 6, frame.size());
  EXPECT_EQ(0x82, static_cast<uint8_t>(frame[0]));
  EXPECT_EQ(0x80 | static_cast<uint8_t>(payload.size()), static_cast<uint8_t>(frame[1]));
  EXPECT_EQ(0x01, static_cast<uint8_t>(frame[2]));
  EXPECT_EQ(0x02, static_cast<uint8_t>(frame[3]));
  EXPECT_EQ(0x03, static_cast<uint8_t>(frame[4]));
  EXPECT_EQ(0x04, static_cast<uint8_t>(frame[5]));

  for (size_t i = 0; i < payload.size(); ++i) {
    frame[i + 6] ^= frame[i % 4 + 2];
  }
  EXPECT_EQ(payload, frame.substr(6));
}

} // namespace
} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
