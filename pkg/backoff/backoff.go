// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package backoff

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/sirupsen/logrus"
)

// Exponential implements an exponential backoff
type Exponential struct {
	// Min is the minimal backoff time, if unspecified, 1 second will be
	// used
	Min time.Duration

	// Max is the maximum backoff time, if unspecified, no maximum time is
	// applied
	Max time.Duration

	// Name is a free form string describing the operation subject to the
	// backoff, if unspecified, a UUID is generated. This string is used
	// for logging purposes.
	Name string

	lastBackoffStart time.Time

	attempt int
}

// calculateDuration calculates the backoff duration based on minimum base
// interval, exponential factor and number of failures.
func calculateDuration(min, max time.Duration, factor float64, failures int) time.Duration {
	minFloat := float64(min)
	maxFloat := float64(max)

	t := minFloat * math.Pow(factor, float64(failures))
	if max != time.Duration(0) && t > maxFloat {
		t = maxFloat
	}

	return time.Duration(t)
}

// Reset backoff attempt counter
func (b *Exponential) Reset() {
	b.attempt = 0
}

// Wait waits for the required time using an exponential backoff
func (b *Exponential) Wait(ctx context.Context) error {
	if b.Name == "" {
		panic("no name provided")
	}

	b.lastBackoffStart = time.Now()
	b.attempt++
	t := b.duration(b.attempt)

	logrus.WithFields(logrus.Fields{
		"subsys":  "backoff",
		"time":    t,
		"attempt": b.attempt,
		"name":    b.Name,
	}).Debug("Sleeping with exponential backoff")

	select {
	case <-ctx.Done():
		return fmt.Errorf("exponential backoff cancelled via context: %s", ctx.Err())
	case <-time.After(t):
	}

	return nil
}

// duration returns the wait duration for the nth attempt
func (b *Exponential) duration(attempt int) time.Duration {
	min := time.Duration(1) * time.Second
	if b.Min != time.Duration(0) {
		min = b.Min
	}

	t := calculateDuration(min, b.Max, 2, attempt)

	if b.Max != time.Duration(0) && t > b.Max {
		t = b.Max
	}

	return t
}
