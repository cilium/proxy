#include <gtest/gtest.h>

#define private public
#include "cilium/network_filter.h"
#undef private

#include "envoy/buffer/buffer.h"

#include "source/common/buffer/buffer_impl.h"

#include "test/mocks/network/connection.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/listener_factory_context.h"

namespace Envoy {
namespace {

using testing::NiceMock;

class AllowAllPolicyResolver : public Cilium::PolicyResolver {
public:
  uint32_t resolvePolicyId(const Network::Address::Ip*) const override { return 123; }

  const Cilium::PolicyInstance& getPolicy(const std::string&) const override {
    return Cilium::NetworkPolicyMap::getAllowAllEgressPolicy();
  }

  bool exists(const std::string&) const override { return true; }
};

TEST(CiliumNetworkFilterTest, MissingMetadataNamespaceDoesNotCrash) {
  NiceMock<Server::Configuration::MockListenerFactoryContext> context;
  ::cilium::NetworkFilter proto_config;
  auto config = std::make_shared<Filter::CiliumL3::Config>(proto_config, context);
  Filter::CiliumL3::Instance instance(config);

  NiceMock<Network::MockReadFilterCallbacks> callbacks;
  callbacks.connection_.stream_info_.filter_state_->setData(
      Cilium::CiliumPolicyFilterState::key(),
      std::make_shared<Cilium::CiliumPolicyFilterState>(
          0, 456, false, false, 80, std::string("pod"), std::string(""),
          std::make_shared<AllowAllPolicyResolver>(), 7, ""),
      StreamInfo::FilterState::LifeSpan::Connection);
  instance.initializeReadFilterCallbacks(callbacks);
  instance.l7proto_ = "test.l7";

  Buffer::OwnedImpl data("hello");
  EXPECT_EQ(instance.onData(data, false), Network::FilterStatus::Continue);
  EXPECT_EQ(callbacks.connection_.state_, Network::Connection::State::Open);
  EXPECT_EQ(instance.log_entry_.entry_.generic_l7().proto(), "test.l7");
}

} // namespace
} // namespace Envoy
