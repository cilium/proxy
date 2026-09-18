// Copyright 2026 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cilium

import (
	"math"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var networkPolicyEqualitySink bool

func TestNetworkPolicyEqualVT(t *testing.T) {
	var nilPolicyA *NetworkPolicy
	var nilPolicyB *NetworkPolicy
	assertNetworkPolicyEqual(t, nilPolicyA, nilPolicyB, true)
	assertNetworkPolicyEqual(t, nilPolicyA, &NetworkPolicy{}, false)

	same := testNetworkPolicy(8)
	assertNetworkPolicyEqual(t, same, same, true)

	tests := []struct {
		name   string
		left   *NetworkPolicy
		mutate func(*NetworkPolicy)
		want   bool
	}{
		{
			name: "independently allocated equal policies",
			left: testNetworkPolicy(8),
			want: true,
		},
		{
			name: "top-level scalar",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				policy.EndpointId++
			},
		},
		{
			name: "endpoint IP",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				policy.EndpointIps[1] = "f00d::2"
			},
		},
		{
			name: "ingress PortNetworkPolicy",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				policy.IngressPerPortPolicies[0].Port++
			},
		},
		{
			name: "egress PortNetworkPolicy",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				policy.EgressPerPortPolicies[0].EndPort++
			},
		},
		{
			name: "nested PortNetworkPolicyRule",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				policy.IngressPerPortPolicies[0].Rules[0].Name = "changed"
			},
		},
		{
			name: "nested HTTP rule",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				http := policy.IngressPerPortPolicies[0].Rules[0].GetHttpRules()
				http.HttpRules[0].HeaderMatches[0].Value = "changed"
			},
		},
		{
			name: "large RemotePolicies list",
			left: testNetworkPolicy(1530),
			want: true,
		},
		{
			name: "change near end of large RemotePolicies list",
			left: testNetworkPolicy(1530),
			mutate: func(policy *NetworkPolicy) {
				remotes := policy.IngressPerPortPolicies[0].Rules[0].RemotePolicies
				remotes[len(remotes)-1]++
			},
		},
		{
			name: "different repeated-field ordering",
			left: testNetworkPolicy(8),
			mutate: func(policy *NetworkPolicy) {
				remotes := policy.IngressPerPortPolicies[0].Rules[0].RemotePolicies
				remotes[0], remotes[1] = remotes[1], remotes[0]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			right := proto.Clone(tt.left).(*NetworkPolicy)
			if tt.mutate != nil {
				tt.mutate(right)
			}
			assertNetworkPolicyEqual(t, tt.left, right, tt.want)
		})
	}

	t.Run("nil and empty repeated fields", func(t *testing.T) {
		left := &NetworkPolicy{}
		right := &NetworkPolicy{
			EndpointIps:            []string{},
			IngressPerPortPolicies: []*PortNetworkPolicy{},
			EgressPerPortPolicies:  []*PortNetworkPolicy{},
		}
		assertNetworkPolicyEqual(t, left, right, true)
	})
}

func TestNetworkPolicyEqualVTOneofs(t *testing.T) {
	tests := []struct {
		name   string
		left   *NetworkPolicy
		mutate func(*PortNetworkPolicyRule)
		want   bool
	}{
		{
			name: "pass precedence equal",
			left: policyWithRule(&PortNetworkPolicyRule{
				Verdict: &PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 7},
			}),
			want: true,
		},
		{
			name: "pass precedence value",
			left: policyWithRule(&PortNetworkPolicyRule{
				Verdict: &PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 7},
			}),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.Verdict = &PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 8}
			},
		},
		{
			name: "deny equal",
			left: policyWithRule(&PortNetworkPolicyRule{
				Verdict: &PortNetworkPolicyRule_Deny{Deny: true},
			}),
			want: true,
		},
		{
			name: "deny value",
			left: policyWithRule(&PortNetworkPolicyRule{
				Verdict: &PortNetworkPolicyRule_Deny{Deny: true},
			}),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.Verdict = &PortNetworkPolicyRule_Deny{Deny: false}
			},
		},
		{
			name: "verdict alternative",
			left: policyWithRule(&PortNetworkPolicyRule{
				Verdict: &PortNetworkPolicyRule_Deny{Deny: true},
			}),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.Verdict = &PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 1}
			},
		},
		{
			name: "HTTP equal",
			left: policyWithRule(httpOneofRule("GET")),
			want: true,
		},
		{
			name: "HTTP value",
			left: policyWithRule(httpOneofRule("GET")),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.GetHttpRules().HttpRules[0].HeaderMatches[0].Value = "POST"
			},
		},
		{
			name: "Kafka equal",
			left: policyWithRule(kafkaOneofRule("events")),
			want: true,
		},
		{
			name: "Kafka value",
			left: policyWithRule(kafkaOneofRule("events")),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.GetKafkaRules().KafkaRules[0].Topic = "audit"
			},
		},
		{
			name: "generic L7 equal",
			left: policyWithRule(genericL7OneofRule("public")),
			want: true,
		},
		{
			name: "generic L7 map value",
			left: policyWithRule(genericL7OneofRule("public")),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.GetL7Rules().L7AllowRules[0].Rule["zone"] = "private"
			},
		},
		{
			name: "L7 alternative",
			left: policyWithRule(httpOneofRule("GET")),
			mutate: func(rule *PortNetworkPolicyRule) {
				rule.L7 = kafkaOneofRule("events").L7
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			right := proto.Clone(tt.left).(*NetworkPolicy)
			if tt.mutate != nil {
				tt.mutate(right.IngressPerPortPolicies[0].Rules[0])
			}
			assertNetworkPolicyEqual(t, tt.left, right, tt.want)
		})
	}
}

func TestNetworkPolicyEqualVTImportedMessages(t *testing.T) {
	t.Run("Envoy HeaderMatcher", func(t *testing.T) {
		left := policyWithRule(&PortNetworkPolicyRule{
			L7: &PortNetworkPolicyRule_HttpRules{HttpRules: &HttpNetworkPolicyRules{
				HttpRules: []*HttpNetworkPolicyRule{{
					Headers: []*routev3.HeaderMatcher{{
						Name: ":method",
						HeaderMatchSpecifier: &routev3.HeaderMatcher_ExactMatch{
							ExactMatch: "GET",
						},
					}},
				}},
			}},
		})
		right := proto.Clone(left).(*NetworkPolicy)
		assertNetworkPolicyEqual(t, left, right, true)

		right.IngressPerPortPolicies[0].Rules[0].GetHttpRules().HttpRules[0].Headers[0].
			HeaderMatchSpecifier = &routev3.HeaderMatcher_ExactMatch{ExactMatch: "POST"}
		assertNetworkPolicyEqual(t, left, right, false)
	})

	t.Run("Envoy MetadataMatcher", func(t *testing.T) {
		left := policyWithMetadataMatcher(metadataDoubleMatcher(42))
		right := proto.Clone(left).(*NetworkPolicy)
		assertNetworkPolicyEqual(t, left, right, true)

		rightMatcher := right.IngressPerPortPolicies[0].Rules[0].GetL7Rules().
			L7AllowRules[0].MetadataRule[0]
		rightMatcher.Value.MatchPattern = &matcherv3.ValueMatcher_DoubleMatch{
			DoubleMatch: &matcherv3.DoubleMatcher{
				MatchPattern: &matcherv3.DoubleMatcher_Exact{Exact: 43},
			},
		}
		assertNetworkPolicyEqual(t, left, right, false)
	})
}

func TestNetworkPolicyEqualVTNaN(t *testing.T) {
	// DoubleMatcher is reachable through L7NetworkPolicyRule.MetadataRule. The
	// generated NPDS equality method delegates imported Envoy messages to
	// proto.Equal, which preserves protobuf's rule that corresponding NaNs are
	// equal even when their payload bits differ.
	left := policyWithMetadataMatcher(metadataDoubleMatcher(
		math.Float64frombits(0x7ff8000000000001),
	))
	right := policyWithMetadataMatcher(metadataDoubleMatcher(
		math.Float64frombits(0x7ff8000000000002),
	))
	assertNetworkPolicyEqual(t, left, right, true)

	right = policyWithMetadataMatcher(metadataDoubleMatcher(1))
	assertNetworkPolicyEqual(t, left, right, false)
}

func TestNetworkPolicyEqualVTUnknownFields(t *testing.T) {
	// Cilium's ADS server constructs NetworkPolicy resources locally, so their
	// protobuf unknown fields (including those of nested NPDS messages) are
	// empty. EqualVT is equivalent to proto.Equal under that precondition.
	//
	// The pinned generator does compare unknown fields, but compares each local
	// message's raw bytes. proto.Equal additionally treats different ordering of
	// distinct unknown field numbers as equal. The reordered cases below record
	// this intentional difference and guard the empty-unknown precondition.
	t.Run("same root unknown field", func(t *testing.T) {
		left := testNetworkPolicy(2)
		right := proto.Clone(left).(*NetworkPolicy)
		unknown := appendUnknown(nil, 1000, 1)
		left.ProtoReflect().SetUnknown(unknown)
		right.ProtoReflect().SetUnknown(append([]byte(nil), unknown...))
		assertNetworkPolicyEqual(t, left, right, true)
	})

	t.Run("different root unknown field", func(t *testing.T) {
		left := testNetworkPolicy(2)
		right := proto.Clone(left).(*NetworkPolicy)
		left.ProtoReflect().SetUnknown(appendUnknown(nil, 1000, 1))
		right.ProtoReflect().SetUnknown(appendUnknown(nil, 1000, 2))
		assertNetworkPolicyEqual(t, left, right, false)
	})

	t.Run("reordered root unknown fields", func(t *testing.T) {
		left := testNetworkPolicy(2)
		right := proto.Clone(left).(*NetworkPolicy)
		leftUnknown := appendUnknown(appendUnknown(nil, 1000, 1), 1001, 2)
		rightUnknown := appendUnknown(appendUnknown(nil, 1001, 2), 1000, 1)
		left.ProtoReflect().SetUnknown(leftUnknown)
		right.ProtoReflect().SetUnknown(rightUnknown)
		if !proto.Equal(left, right) {
			t.Fatal("proto.Equal unexpectedly rejected reordered root unknown fields")
		}
		if left.EqualVT(right) {
			t.Fatal("EqualVT unexpectedly accepted reordered root unknown fields")
		}
	})

	t.Run("reordered nested unknown fields", func(t *testing.T) {
		left := testNetworkPolicy(2)
		right := proto.Clone(left).(*NetworkPolicy)
		leftUnknown := appendUnknown(appendUnknown(nil, 1000, 1), 1001, 2)
		rightUnknown := appendUnknown(appendUnknown(nil, 1001, 2), 1000, 1)
		left.IngressPerPortPolicies[0].Rules[0].ProtoReflect().SetUnknown(leftUnknown)
		right.IngressPerPortPolicies[0].Rules[0].ProtoReflect().SetUnknown(rightUnknown)
		if !proto.Equal(left, right) {
			t.Fatal("proto.Equal unexpectedly rejected reordered nested unknown fields")
		}
		if left.EqualVT(right) {
			t.Fatal("EqualVT unexpectedly accepted reordered nested unknown fields")
		}
	})
}

func BenchmarkNetworkPolicyEquality(b *testing.B) {
	equalLeft := testNetworkPolicy(1530)
	equalRight := proto.Clone(equalLeft).(*NetworkPolicy)
	changedLeft := testNetworkPolicy(1530)
	changedRight := proto.Clone(changedLeft).(*NetworkPolicy)
	changedRemotes := changedRight.IngressPerPortPolicies[0].Rules[0].RemotePolicies
	changedRemotes[len(changedRemotes)-1]++

	b.Run("equal", func(b *testing.B) {
		b.Run("proto.Equal", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				networkPolicyEqualitySink = proto.Equal(equalLeft, equalRight)
			}
		})
		b.Run("EqualVT", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				networkPolicyEqualitySink = equalLeft.EqualVT(equalRight)
			}
		})
	})

	b.Run("changed", func(b *testing.B) {
		b.Run("proto.Equal", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				networkPolicyEqualitySink = proto.Equal(changedLeft, changedRight)
			}
		})
		b.Run("EqualVT", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				networkPolicyEqualitySink = changedLeft.EqualVT(changedRight)
			}
		})
	})
}

func assertNetworkPolicyEqual(t *testing.T, left, right *NetworkPolicy, want bool) {
	t.Helper()
	if got := proto.Equal(left, right); got != want {
		t.Fatalf("proto.Equal() = %t, want %t", got, want)
	}
	if got := left.EqualVT(right); got != want {
		t.Fatalf("EqualVT() = %t, want %t", got, want)
	}
}

func testNetworkPolicy(remotePolicyCount int) *NetworkPolicy {
	remotePolicies := make([]uint32, remotePolicyCount)
	for i := range remotePolicies {
		remotePolicies[i] = uint32(10000 + i)
	}

	return &NetworkPolicy{
		EndpointIps: []string{"10.0.0.1", "f00d::1"},
		EndpointId:  1234,
		IngressPerPortPolicies: []*PortNetworkPolicy{{
			Port:     8080,
			EndPort:  8081,
			Protocol: corev3.SocketAddress_TCP,
			Rules: []*PortNetworkPolicyRule{{
				Precedence:     100,
				Verdict:        &PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 90},
				ProxyId:        15000,
				Name:           "allow-api",
				RemotePolicies: remotePolicies,
				DownstreamTlsContext: &TLSContext{
					ValidationContextSdsSecret: "downstream-ca",
					TlsSdsSecret:               "downstream-cert",
					ServerNames:                []string{"api.example.com"},
					AlpnProtocols:              []string{"h2", "http/1.1"},
				},
				UpstreamTlsContext: &TLSContext{
					ValidationContextSdsSecret: "upstream-ca",
					TlsSdsSecret:               "upstream-cert",
					ServerNames:                []string{"backend.example.com"},
				},
				ServerNames: []string{"*.example.com"},
				L7: &PortNetworkPolicyRule_HttpRules{HttpRules: &HttpNetworkPolicyRules{
					HttpRules: []*HttpNetworkPolicyRule{{
						HeaderMatches: []*HeaderMatch{{
							Name:           "x-tenant",
							Value:          "engineering",
							MatchAction:    HeaderMatch_CONTINUE_ON_MATCH,
							MismatchAction: HeaderMatch_FAIL_ON_MISMATCH,
						}},
					}},
				}},
			}},
		}},
		EgressPerPortPolicies: []*PortNetworkPolicy{{
			Port:     9090,
			EndPort:  9091,
			Protocol: corev3.SocketAddress_TCP,
			Rules: []*PortNetworkPolicyRule{{
				Precedence: 200,
				Verdict:    &PortNetworkPolicyRule_Deny{Deny: true},
				Name:       "deny-private",
				L7Proto:    "test.parser",
				L7: &PortNetworkPolicyRule_L7Rules{L7Rules: &L7NetworkPolicyRules{
					L7DenyRules: []*L7NetworkPolicyRule{{
						Name: "private-zone",
						Rule: map[string]string{"zone": "private"},
					}},
				}},
			}},
		}},
	}
}

func policyWithRule(rule *PortNetworkPolicyRule) *NetworkPolicy {
	return &NetworkPolicy{
		EndpointIps: []string{"10.0.0.1"},
		EndpointId:  1234,
		IngressPerPortPolicies: []*PortNetworkPolicy{{
			Port:     80,
			Protocol: corev3.SocketAddress_TCP,
			Rules:    []*PortNetworkPolicyRule{rule},
		}},
	}
}

func httpOneofRule(value string) *PortNetworkPolicyRule {
	return &PortNetworkPolicyRule{
		L7: &PortNetworkPolicyRule_HttpRules{HttpRules: &HttpNetworkPolicyRules{
			HttpRules: []*HttpNetworkPolicyRule{{
				HeaderMatches: []*HeaderMatch{{Name: ":method", Value: value}},
			}},
		}},
	}
}

func kafkaOneofRule(topic string) *PortNetworkPolicyRule {
	return &PortNetworkPolicyRule{
		L7: &PortNetworkPolicyRule_KafkaRules{KafkaRules: &KafkaNetworkPolicyRules{
			KafkaRules: []*KafkaNetworkPolicyRule{{
				ApiVersion: 1,
				ApiKeys:    []int32{1, 2},
				ClientId:   "client",
				Topic:      topic,
			}},
		}},
	}
}

func genericL7OneofRule(zone string) *PortNetworkPolicyRule {
	return &PortNetworkPolicyRule{
		L7: &PortNetworkPolicyRule_L7Rules{L7Rules: &L7NetworkPolicyRules{
			L7AllowRules: []*L7NetworkPolicyRule{{
				Name: "zone",
				Rule: map[string]string{"zone": zone},
			}},
		}},
	}
}

func policyWithMetadataMatcher(matcher *matcherv3.MetadataMatcher) *NetworkPolicy {
	return policyWithRule(&PortNetworkPolicyRule{
		L7: &PortNetworkPolicyRule_L7Rules{L7Rules: &L7NetworkPolicyRules{
			L7AllowRules: []*L7NetworkPolicyRule{{
				MetadataRule: []*matcherv3.MetadataMatcher{matcher},
			}},
		}},
	})
}

func metadataDoubleMatcher(value float64) *matcherv3.MetadataMatcher {
	return &matcherv3.MetadataMatcher{
		Filter: "envoy.filters.http.rbac",
		Path: []*matcherv3.MetadataMatcher_PathSegment{{
			Segment: &matcherv3.MetadataMatcher_PathSegment_Key{Key: "score"},
		}},
		Value: &matcherv3.ValueMatcher{
			MatchPattern: &matcherv3.ValueMatcher_DoubleMatch{
				DoubleMatch: &matcherv3.DoubleMatcher{
					MatchPattern: &matcherv3.DoubleMatcher_Exact{Exact: value},
				},
			},
		},
	}
}

func appendUnknown(dst []byte, field protowire.Number, value uint64) []byte {
	dst = protowire.AppendTag(dst, field, protowire.VarintType)
	return protowire.AppendVarint(dst, value)
}
