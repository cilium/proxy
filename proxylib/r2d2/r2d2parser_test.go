// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package r2d2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/proxy/proxylib/accesslog"
	"github.com/cilium/proxy/proxylib/proxylib"
	"github.com/cilium/proxy/proxylib/test"
)

type R2d2Suite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

// Set up access log server and Library instance for all the test cases
func setUpR2d2Suite(tb testing.TB) *R2d2Suite {
	s := &R2d2Suite{}
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	require.NotNil(tb, s.logServer)
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	require.NotNil(tb, s.ins)
	tb.Cleanup(func() {
		s.logServer.Clear()
		s.logServer.Close()
	})
	return s
}

func TestR2d2OnDataIncomplete(t *testing.T) {
	s := setUpR2d2Suite(t)
	conn := s.ins.CheckNewConnectionOK(t, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy")
	data := [][]byte{[]byte("READ xssss")}
	conn.CheckOnDataOK(t, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func TestR2d2OnDataBasicPass(t *testing.T) {
	s := setUpR2d2Suite(t)
	// allow all rule
	s.ins.CheckInsertPolicyText(t, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(t, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1 := "READ sssss\r\n"
	msg2 := "WRITE sssss\r\n"
	msg3 := "HALT\r\n"
	msg4 := "RESET\r\n"
	data := [][]byte{[]byte(msg1 + msg2 + msg3 + msg4)}
	conn.CheckOnDataOK(t, false, false, &data, []byte{},
		proxylib.PASS, len(msg1),
		proxylib.PASS, len(msg2),
		proxylib.PASS, len(msg3),
		proxylib.PASS, len(msg4),
		proxylib.MORE, 1)
}

func TestR2d2OnDataMultipleReq(t *testing.T) {
	s := setUpR2d2Suite(t)
	// allow all rule
	s.ins.CheckInsertPolicyText(t, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(t, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1Part1 := "RE"
	msg1Part2 := "SET\r\n"
	data := [][]byte{[]byte(msg1Part1), []byte(msg1Part2)}
	conn.CheckOnDataOK(t, false, false, &data, []byte{},
		proxylib.PASS, len(msg1Part1+msg1Part2),
		proxylib.MORE, 1)
}

func TestR2d2OnDataAllowDenyCmd(t *testing.T) {
	s := setUpR2d2Suite(t)
	s.ins.CheckInsertPolicyText(t, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "cmd"
			  value: "READ"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(t, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1 := "READ xssss\r\n"
	msg2 := "WRITE xssss\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(t, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}

func (s *R2d2Suite) TestR2d2OnDataAllowDenyRegex(t *testing.T) {

	s.ins.CheckInsertPolicyText(t, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "file"
			  value: "s.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(t, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1 := "READ ssss\r\n"
	msg2 := "WRITE yyyyy\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(t, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}
