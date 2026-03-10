// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafkalib

import (
	"testing"
	"time"

	"github.com/cilium/kafka/proto"
	"github.com/stretchr/testify/require"

	"github.com/cilium/proxy/pkg/policy/api/kafka"
)

type kafkaTestSuite struct{}

var messages = make([]*proto.Message, 100)

func setUpKafkaTestSuite(tb testing.TB) *kafkaTestSuite {
	tb.Helper()
	for i := range messages {
		messages[i] = &proto.Message{
			Offset: int64(i),
			Crc:    uint32(i),
			Key:    nil,
			Value:  []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur.`),
		}
	}
	return &kafkaTestSuite{}
}

// MatchesRule validates the Kafka request message against the provided list of
// rules. The function will return true if the policy allows the message,
// otherwise false is returned.
func (req *RequestMessage) MatchesRule(rules []Rule) bool {
	for _, rule := range rules {
		if rule.Matches(req) {
			return true
		}
	}
	return false
}

func TestProduceRequest(c *testing.T) {
	setUpKafkaTestSuite(c)
	req := &proto.ProduceReq{
		CorrelationID: 241,
		ClientID:      "test",
		Compression:   proto.CompressionNone,
		RequiredAcks:  proto.RequiredAcksAll,
		Timeout:       time.Second,
		Topics: []proto.ProduceReqTopic{
			{
				Name: "foo",
				Partitions: []proto.ProduceReqPartition{
					{
						ID:       0,
						Messages: messages,
					},
				},
			},
			{
				Name: "bar",
				Partitions: []proto.ProduceReqPartition{
					{
						ID:       0,
						Messages: messages,
					},
				},
			},
		},
	}

	reqMsg := RequestMessage{
		request: req,
	}

	// empty rules should match nothing
	reqMsg.setTopics()
	require.False(c, reqMsg.MatchesRule([]Rule{}))

	// wildcard rule matches everything
	reqMsg.setTopics()
	require.True(c, reqMsg.MatchesRule([]Rule{{}}))

	reqMsg.setTopics()
	require.False(c, reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "foo"),
	}))

	reqMsg.setTopics()
	require.True(c, reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "foo"), NewRule(-1, nil, "", "bar"),
	}))

	reqMsg.setTopics()
	require.False(c, reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "foo"), NewRule(-1, nil, "", "baz"),
	}))

	reqMsg.setTopics()
	require.False(c, reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "baz"), NewRule(-1, nil, "", "foo2"),
	}))

	reqMsg.setTopics()
	require.True(c, reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "bar"), NewRule(-1, nil, "", "foo"),
	}))

	reqMsg.setTopics()
	require.True(c, reqMsg.MatchesRule([]Rule{
		NewRule(-1, nil, "", "bar"), NewRule(-1, nil, "", "foo"), NewRule(-1, nil, "", "baz"),
	}))
}

func TestUnknownRequest(t *testing.T) {
	setUpKafkaTestSuite(t)
	reqMsg := RequestMessage{kind: 18} // ApiVersions request

	// Empty rule should disallow
	require.False(t, reqMsg.MatchesRule([]Rule{}))

	// Whitelisting of unknown message
	rule1 := NewRule(-1, []int32{int32(kafka.MetadataKey)}, "", "")
	rule2 := NewRule(-1, []int32{int32(kafka.APIVersionsKey)}, "", "")
	require.True(t, reqMsg.MatchesRule([]Rule{rule1, rule2}))

	reqMsg = RequestMessage{kind: 19}
	require.False(t, reqMsg.MatchesRule([]Rule{rule1, rule2}))
}
