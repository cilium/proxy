// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	cilium "github.com/cilium/proxy/go/cilium/api"
)

var LogFatal = func(format string, args ...interface{}) {
	logrus.Fatalf(format, args...)
}

func (ins *Instance) CheckInsertPolicyText(tb testing.TB, version string, policies []string) {
	err := ins.InsertPolicyText(version, policies, "")
	require.NoError(tb, err)
}

func (ins *Instance) InsertPolicyText(version string, policies []string, expectFail string) error {
	typeUrl := "type.googleapis.com/cilium.NetworkPolicy"
	resources := make([]*any.Any, 0, len(policies))

	for _, policy := range policies {
		pb := new(cilium.NetworkPolicy)
		err := proto.UnmarshalText(policy, pb)
		if err != nil {
			if expectFail != "unmarshal" {
				LogFatal("Policy UnmarshalText failed: %v", err)
			}
			return err
		}
		logrus.Debugf("Text -> proto.Message: %s -> %v", policy, pb)
		data, err := proto.Marshal(pb)
		if err != nil {
			if expectFail != "marshal" {
				LogFatal("Policy marshal failed: %v", err)
			}
			return err
		}

		resources = append(resources, &any.Any{
			TypeUrl: typeUrl,
			Value:   data,
		})
	}

	msg := &envoy_service_discovery.DiscoveryResponse{
		VersionInfo: version,
		Canary:      false,
		TypeUrl:     typeUrl,
		Nonce:       "randomNonce1",
		Resources:   resources,
	}

	err := ins.PolicyUpdate(msg)
	if err != nil {
		if expectFail != "update" {
			LogFatal("Policy Update failed: %v", err)
		}
	}
	return err
}

var connectionID uint64

func (ins *Instance) CheckNewConnectionOK(tb testing.TB, proto string, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string) *Connection {
	err, conn := ins.CheckNewConnection(proto, ingress, srcId, dstId, srcAddr, dstAddr, policyName)
	require.NoError(tb, err)
	require.NotNil(tb, conn)
	return conn
}

func (ins *Instance) CheckNewConnection(proto string, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string) (error, *Connection) {
	connectionID++
	bufSize := 1024
	origBuf := make([]byte, 0, bufSize)
	replyBuf := make([]byte, 0, bufSize)

	return NewConnection(ins, proto, connectionID, ingress, srcId, dstId, srcAddr, dstAddr, policyName, &origBuf, &replyBuf)
}

func (conn *Connection) CheckOnDataOK(tb testing.TB, reply, endStream bool, data *[][]byte, expReplyBuf []byte, expOps ...interface{}) {
	conn.CheckOnData(tb, reply, endStream, data, OK, expReplyBuf, expOps...)
}

func (conn *Connection) CheckOnData(tb testing.TB, reply, endStream bool, data *[][]byte, expResult FilterResult, expReplyBuf []byte, expOps ...interface{}) {
	ops := make([][2]int64, 0, len(expOps)/2)

	res := conn.OnData(reply, endStream, data, &ops)
	require.Equal(tb, expResult, res)
	require.Equal(tb, len(expOps)/2, len(ops), "Unexpected number of filter operations")

	for i, op := range ops {
		if i*2+1 < len(expOps) {
			expOp, ok := expOps[i*2].(OpType)
			require.Truef(tb, ok, "Invalid expected operation type")
			require.Equal(tb, int64(expOp), op[0], "Unexpected filter operation")
			expN, ok := expOps[i*2+1].(int)
			require.Truef(tb, ok, "Invalid expected operation length (must be int)")
			require.Equal(tb, int64(expN), op[1], "Unexpected operation length")
		}
	}

	buf := conn.ReplyBuf
	require.ElementsMatch(tb, expReplyBuf, *buf)
	*buf = (*buf)[:0] // make empty again

	// Clear the same-direction inject buffer, simulating the datapath forwarding the injected data
	injectBuf := conn.getInjectBuf(reply)
	*injectBuf = (*injectBuf)[:0]
	logrus.Debugf("proxylib test helper: Cleared inject buf, used %d/%d", len(*injectBuf), cap(*injectBuf))
}
