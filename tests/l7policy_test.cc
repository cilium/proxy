#include <memory>

#include "envoy/http/protocol.h"

#include "source/common/network/address_impl.h"
#include "source/common/stats/isolated_store_impl.h"
#include "source/common/stream_info/stream_info_impl.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/network/connection.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "cilium/l7policy.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Cilium {
namespace {

class L7PolicyResponseTest : public testing::Test {
protected:
  L7PolicyResponseTest()
      : config_(std::make_shared<Config>("", "", time_system_, *stats_.rootScope(), false)),
        filter_(config_) {
    ON_CALL(callbacks_, connection())
        .WillByDefault(testing::Return(OptRef<const Network::Connection>{connection_}));
    callbacks_.stream_info_.protocol_ = Http::Protocol::Http11;
    callbacks_.stream_info_.upstream_info_ = upstream_info_;
    filter_.setDecoderFilterCallbacks(callbacks_);
  }

  void expectLocalReplyWithoutDraining() {
    EXPECT_CALL(callbacks_.stream_info_, setShouldDrainConnectionUponCompletion(true)).Times(0);
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_.encodeHeaders(headers_, true));
    EXPECT_EQ("503", headers_.getStatusValue());
    const auto* log_entry =
        callbacks_.stream_info_.filter_state_->getDataReadOnly<AccessLog::Entry>(AccessLogKey);
    ASSERT_NE(nullptr, log_entry);
    EXPECT_EQ(503, log_entry->entry_.http().status());
  }

  Event::SimulatedTimeSystem time_system_;
  Stats::IsolatedStoreImpl stats_;
  testing::NiceMock<Network::MockConnection> connection_;
  testing::NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  std::shared_ptr<StreamInfo::UpstreamInfoImpl> upstream_info_ =
      std::make_shared<StreamInfo::UpstreamInfoImpl>();
  ConfigSharedPtr config_;
  AccessFilter filter_;
  Http::TestResponseHeaderMapImpl headers_{{":status", "503"}, {"connection", "close"}};
};

TEST_F(L7PolicyResponseTest, LocalReplyWithoutUpstreamSocketAddresses) {
  // A local reply can have upstream info even though no upstream socket was established.
  expectLocalReplyWithoutDraining();
}

TEST_F(L7PolicyResponseTest, LocalReplyWithoutUpstreamLocalAddress) {
  upstream_info_->setUpstreamRemoteAddress(
      callbacks_.stream_info_.downstreamAddressProvider().localAddress());
  expectLocalReplyWithoutDraining();
}

TEST_F(L7PolicyResponseTest, LocalReplyWithoutUpstreamRemoteAddress) {
  upstream_info_->setUpstreamLocalAddress(
      callbacks_.stream_info_.downstreamAddressProvider().remoteAddress());
  expectLocalReplyWithoutDraining();
}

TEST_F(L7PolicyResponseTest, MatchingAddressesDrainDownstreamConnection) {
  const auto& downstream = callbacks_.stream_info_.downstreamAddressProvider();
  upstream_info_->setUpstreamRemoteAddress(downstream.localAddress());
  upstream_info_->setUpstreamLocalAddress(downstream.remoteAddress());
  EXPECT_CALL(callbacks_.stream_info_, setShouldDrainConnectionUponCompletion(true));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_.encodeHeaders(headers_, true));
}

TEST_F(L7PolicyResponseTest, DifferentAddressesDoNotDrainDownstreamConnection) {
  upstream_info_->setUpstreamRemoteAddress(
      std::make_shared<Network::Address::Ipv4Instance>("192.0.2.1", 80));
  upstream_info_->setUpstreamLocalAddress(
      callbacks_.stream_info_.downstreamAddressProvider().remoteAddress());
  expectLocalReplyWithoutDraining();
}

} // namespace
} // namespace Cilium
} // namespace Envoy
