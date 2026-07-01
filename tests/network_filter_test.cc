#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cilium/accesslog.h"
#include "cilium/api/network_filter.pb.h"
#include "cilium/filter_state_cilium_policy.h"
#include "cilium/network_filter.h"
#include "cilium/network_policy.h"

#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/stream_info/stream_info.h"
#include "envoy/upstream/host_description.h"

#include "source/common/buffer/buffer_impl.h"

#include "test/mocks/network/mocks.h"
#include "test/mocks/server/listener_factory_context.h"

namespace Envoy {
namespace Filter {
namespace CiliumL3 {

class NetworkFilterTestPeer {
public:
  static void setL7Proto(Instance& instance, std::string l7proto) {
    instance.l7proto_ = std::move(l7proto);
  }

  static const Cilium::AccessLog::Entry& logEntry(const Instance& instance) {
    return instance.log_entry_;
  }
};

} // namespace CiliumL3
} // namespace Filter

namespace {

using testing::NiceMock;

class TestReadFilterCallbacks : public Network::MockReadFilterCallbacks {
public:
  TestReadFilterCallbacks() {
    ON_CALL(*this, addUpstreamCallback(testing::_))
        .WillByDefault(testing::Invoke([](const Network::UpstreamCallback&) {}));
    ON_CALL(*this, iterateUpstreamCallbacks(testing::_, testing::_))
        .WillByDefault(testing::Return(true));
  }

  MOCK_METHOD(void, addUpstreamCallback, (const Network::UpstreamCallback& cb), (override));
  MOCK_METHOD(bool, iterateUpstreamCallbacks,
              (Upstream::HostDescriptionConstSharedPtr, StreamInfo::StreamInfo&), (override));
};

class DenyAllPolicyResolver : public Cilium::PolicyResolver {
public:
  uint32_t resolvePolicyId(const Network::Address::Ip*) const override { return 123; }

  const Cilium::PolicyInstance& getPolicy(const std::string&) const override {
    return Cilium::NetworkPolicyMap::getDenyAllPolicy();
  }

  bool exists(const std::string&) const override { return true; }
};

TEST(CiliumNetworkFilterTest, MissingMetadataNamespaceDoesNotCrash) {
  NiceMock<Server::Configuration::MockListenerFactoryContext> context;
  ::cilium::NetworkFilter proto_config;
  auto config = std::make_shared<Filter::CiliumL3::Config>(proto_config, context);
  Filter::CiliumL3::Instance instance(config);

  NiceMock<TestReadFilterCallbacks> callbacks;
  callbacks.connection_.stream_info_.filter_state_->setData(
      Cilium::CiliumPolicyFilterState::key(),
      std::make_shared<Cilium::CiliumPolicyFilterState>(
          0, 456, false, false, 80, std::string("pod"), std::string(""),
          std::make_shared<DenyAllPolicyResolver>(), 7, ""),
      StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);
  instance.initializeReadFilterCallbacks(callbacks);
  Filter::CiliumL3::NetworkFilterTestPeer::setL7Proto(instance, "test.l7");

  Buffer::OwnedImpl data("hello");
  EXPECT_NO_THROW(instance.onData(data, false));
  EXPECT_EQ(Filter::CiliumL3::NetworkFilterTestPeer::logEntry(instance).entry_.generic_l7().proto(),
            "test.l7");
}

} // namespace
} // namespace Envoy
