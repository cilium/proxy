// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package backoff

import (
	"fmt"
	"math"
	"testing"
	"time"

	check "github.com/cilium/checkmate"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type BackoffSuite struct{}

var _ = check.Suite(&BackoffSuite{})

func (b *BackoffSuite) TestJitter(c *check.C) {
	var prev time.Duration
	for i := 0; i < 100; i++ {
		current := CalculateDuration(time.Second, time.Minute, 2.0, true, 1)
		c.Assert(current, check.Not(check.Equals), prev)
		prev = current
	}
}

type fakeNodeManager struct {
	nodes *int
}

func (f *fakeNodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	numNodes := *f.nodes

	if numNodes == 0 {
		return baseInterval
	}

	waitNanoseconds := float64(baseInterval.Nanoseconds()) * math.Log1p(float64(numNodes))
	return time.Duration(int64(waitNanoseconds))
}

func (b *BackoffSuite) TestJitterDistribution(c *check.C) {
	nodeBackoff := &Exponential{
		Min:    time.Second,
		Factor: 2.0,
	}

	for attempt := 1; attempt <= 8; attempt++ {
		current := nodeBackoff.Duration(attempt).Round(time.Second / 10)
		fmt.Printf("%d: %s\n", attempt, current)
	}
}
