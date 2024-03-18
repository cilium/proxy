// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	cilium "github.com/cilium/proxy/go/cilium/api"
	core "github.com/cilium/proxy/go/envoy/config/core/v3"
	"github.com/cilium/proxy/pkg/flowdebug"
)

// L7NetworkPolicyRule is the interface, which each L7 rule implements this interface
type L7NetworkPolicyRule interface {
	Matches(interface{}) bool
}

// L7RuleParser takes the protobuf and converts the one of relevant for the given L7 to an array
// of L7 rules. A packet matches if the 'Matches' method of any of these rules matches the
// 'l7' interface passed by the L7 implementation to PolicyMap.Matches() as the last parameter.
type L7RuleParser func(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule

// const after initialization
var l7RuleParsers map[string]L7RuleParser = make(map[string]L7RuleParser)

// RegisterL7RuleParser adds a l7 policy protocol parser to the map of known l7 policy parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterL7RuleParser(l7PolicyTypeName string, parserFunc L7RuleParser) {
	if flowdebug.Enabled() {
		logrus.Debugf("NPDS: Registering L7 rule parser: %s", l7PolicyTypeName)
	}
	l7RuleParsers[l7PolicyTypeName] = parserFunc
}

// ParseError may be issued by Policy parsing code. The policy configuration change will
// be graciously rejected by recovering from the panic.
func ParseError(reason string, config interface{}) {
	panic(fmt.Errorf("NPDS: %s (config: %v)", reason, config))
}

type PortNetworkPolicyRule struct {
	Deny    bool
	Remotes map[uint32]struct{}
	L7Rules []L7NetworkPolicyRule // only used when not denied
}

func newPortNetworkPolicyRule(config *cilium.PortNetworkPolicyRule) (PortNetworkPolicyRule, string, bool) {
	rule := PortNetworkPolicyRule{
		Deny:    config.GetDeny(),
		Remotes: make(map[uint32]struct{}, len(config.RemotePolicies)),
	}
	action := "Allowing"
	if rule.Deny {
		action = "Denying"
	}
	for _, remote := range config.GetRemotePolicies() {
		if flowdebug.Enabled() {
			logrus.Debugf("NPDS::PortNetworkPolicyRule: %s remote %d", action, remote)
		}
		rule.Remotes[remote] = struct{}{}
	}
	// TODO: Remove when Cilium 1.14 is no longer supported:
	for _, remote := range config.GetDeprecatedRemotePolicies_64() {
		if flowdebug.Enabled() {
			logrus.Debugf("NPDS::PortNetworkPolicyRule: %s remote %d", action, remote)
		}
		rule.Remotes[uint32(remote)] = struct{}{}
	}

	// Each parser registers a parsing function to parse it's L7 rules
	// The registered name must match 'l7_proto', if included in the message,
	// or one of the oneof type names
	l7Name := config.L7Proto
	if l7Name == "" {
		typeOf := reflect.TypeOf(config.L7)
		if typeOf != nil {
			l7Name = typeOf.Elem().Name()
		}
	}
	if strings.HasPrefix(l7Name, "envoy.") {
		return rule, "", false // Silently drop Envoy filter traffic to this port if forwarded to proxylib
	}
	if l7Name != "" {
		l7Parser, ok := l7RuleParsers[l7Name]
		if ok {
			if flowdebug.Enabled() {
				logrus.Debugf("NPDS::PortNetworkPolicyRule: Calling L7Parser %s on %v", l7Name, config.String())
			}
			rule.L7Rules = l7Parser(config)
		} else if flowdebug.Enabled() {
			logrus.Debugf("NPDS::PortNetworkPolicyRule: Unknown L7 (%s), should drop everything.", l7Name)
		}
		// Unknown parsers are expected, but will result in drop-all policy
		return rule, l7Name, ok
	}
	return rule, "", true // No L7 is ok
}

func (p *PortNetworkPolicyRule) Matches(remoteId uint32, l7 interface{}) (allowed, denied bool) {
	// Remote ID must match if we have any.
	if len(p.Remotes) > 0 {
		_, found := p.Remotes[remoteId]
		if !found {
			if flowdebug.Enabled() {
				logrus.Debugf("NPDS::PortNetworkPolicyRule: No L3 match on (%v)", *p)
			}
			// no remote ID match, does not allow or deny explicitly
			return false, false
		}
		if p.Deny {
			// Explicit deny, not allowed even if another rule would allow.
			return false, true
		}
	} else if p.Deny {
		// Deny with empty remotes denies all remotes explicitly
		return false, true
	}
	if len(p.L7Rules) > 0 {
		for _, rule := range p.L7Rules {
			if rule.Matches(l7) {
				if flowdebug.Enabled() {
					logrus.Debugf("NPDS::PortNetworkPolicyRule: L7 rule matches (%v)", *p)
				}
				return true, false
			}
		}
		return false, false
	}
	// Empty set matches any payload
	if flowdebug.Enabled() {
		logrus.Debugf("NPDS::PortNetworkPolicyRule: Empty L7Rules matches (%v)", *p)
	}
	return true, false
}

type PortNetworkPolicyRules struct {
	Rules []PortNetworkPolicyRule
}

func newPortNetworkPolicyRules(config []*cilium.PortNetworkPolicyRule, port uint32) (PortNetworkPolicyRules, bool) {
	rules := PortNetworkPolicyRules{
		Rules: make([]PortNetworkPolicyRule, 0, len(config)),
	}
	if len(config) == 0 && flowdebug.Enabled() {
		logrus.Debugf("NPDS::PortNetworkPolicyRules: No rules, will allow everything.")
	}
	var firstTypeName string
	for _, rule := range config {
		newRule, typeName, ok := newPortNetworkPolicyRule(rule)
		if !ok {
			// Unknown L7 parser, must drop all traffic
			return PortNetworkPolicyRules{}, false
		}
		if typeName != "" {
			if firstTypeName == "" {
				firstTypeName = typeName
			} else if typeName != firstTypeName {
				ParseError("Mismatching L7 types on the same port", config)
			}
		}
		rules.Rules = append(rules.Rules, newRule)
	}
	return rules, true
}

func (p *PortNetworkPolicyRules) Matches(remoteId uint32, l7 interface{}) bool {
	// Empty set matches any payload from anyone
	if len(p.Rules) == 0 {
		if flowdebug.Enabled() {
			logrus.Debugf("NPDS::PortNetworkPolicyRules: No Rules; matches (%v)", p)
		}
		return true
	}
	var allowed bool
	for _, rule := range p.Rules {
		allow, deny := rule.Matches(remoteId, l7)
		if deny {
			// explicit deny
			return false
		}
		if allow {
			// allowed if no other rule denies
			allowed = true
		}
	}
	if allowed {
		if flowdebug.Enabled() {
			logrus.Debugf("NPDS::PortNetworkPolicyRules(remoteId=%d): rule matches (%v)", remoteId, p)
		}
		return true
	}
	return false
}

type PortNetworkPolicies struct {
	Rules map[uint32]PortNetworkPolicyRules
}

func newPortNetworkPolicies(config []*cilium.PortNetworkPolicy, dir string) PortNetworkPolicies {
	policy := PortNetworkPolicies{
		Rules: make(map[uint32]PortNetworkPolicyRules, len(config)),
	}
	for _, rule := range config {
		// Ignore UDP policies
		if rule.GetProtocol() == core.SocketAddress_UDP {
			continue
		}

		port := rule.GetPort()
		if _, found := policy.Rules[port]; found {
			ParseError(fmt.Sprintf("Duplicate port number %d in (rule: %v)", port, rule), config)
		}

		if rule.GetProtocol() != core.SocketAddress_TCP {
			ParseError(fmt.Sprintf("Invalid transport protocol %v", rule.GetProtocol()), config)
		}

		// Skip the port if not 'ok'
		rules, ok := newPortNetworkPolicyRules(rule.GetRules(), port)
		if ok {
			if flowdebug.Enabled() {
				logrus.Debugf("NPDS::PortNetworkPolicies(): installed %s TCP policy for port %d", dir, port)
			}
			policy.Rules[port] = rules
		} else if flowdebug.Enabled() {
			logrus.Debugf("NPDS::PortNetworkPolicies(): Skipped %s port due to unsupported L7: %d", dir, port)
		}
	}
	return policy
}

func (p *PortNetworkPolicies) Matches(port, remoteId uint32, l7 interface{}) bool {
	rules, found := p.Rules[port]
	if found {
		if rules.Matches(remoteId, l7) {
			if flowdebug.Enabled() {
				logrus.Debugf("NPDS::PortNetworkPolicies(port=%d, remoteId=%d): rule matches (%v)", port, remoteId, p)
			}
			return true
		}
	}
	// No exact port match, try wildcard
	rules, foundWc := p.Rules[0]
	if foundWc {
		if rules.Matches(remoteId, l7) {
			if flowdebug.Enabled() {
				logrus.Debugf("NPDS::PortNetworkPolicies(port=*, remoteId=%d): rule matches (%v)", remoteId, p)
			}
			return true
		}
	}

	// No policy for the port was found. Cilium always creates a policy for redirects it
	// creates, so the host proxy never gets here.
	// TODO: Change back to false only when non-bpf datapath is supported?

	//	logrus.Debugf("NPDS::PortNetworkPolicies(port=%d, remoteId=%d): allowing traffic on port for which there is no policy, assuming L3/L4 has passed it! (%v)", port, remoteId, p)
	//	return !(found || foundWc)
	if !(found || foundWc) {
		logrus.Debugf("NPDS::PortNetworkPolicies(port=%d, remoteId=%d): Dropping traffic on port for which there is no policy! (%v)", port, remoteId, p)
	}
	return false
}

type PolicyInstance struct {
	protobuf *cilium.NetworkPolicy
	Ingress  PortNetworkPolicies
	Egress   PortNetworkPolicies
}

func newPolicyInstance(config *cilium.NetworkPolicy) *PolicyInstance {
	if flowdebug.Enabled() {
		logrus.Debugf("NPDS::PolicyInstance: Inserting policy for %v", config.EndpointIps)
	}
	return &PolicyInstance{
		protobuf: config,
		Ingress:  newPortNetworkPolicies(config.GetIngressPerPortPolicies(), "ingress"),
		Egress:   newPortNetworkPolicies(config.GetEgressPerPortPolicies(), "egress"),
	}
}

func (p *PolicyInstance) Matches(ingress bool, port, remoteId uint32, l7 interface{}) bool {
	if flowdebug.Enabled() {
		logrus.Debugf("NPDS::PolicyInstance::Matches(ingress: %v, port: %d, remoteId: %d, l7: %v (policy: %s)", ingress, port, remoteId, l7, p.protobuf.String())
	}
	if ingress {
		return p.Ingress.Matches(port, remoteId, l7)
	}
	return p.Egress.Matches(port, remoteId, l7)
}

// Network policies keyed by endpoint IPs
type PolicyMap map[string]*PolicyInstance

func newPolicyMap() PolicyMap {
	return make(PolicyMap)
}
