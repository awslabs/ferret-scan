// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"strings"
	"testing"
	"time"
)

// fakeClock replaces timeCall with a scripted sequence of wall readings, one per call, so Measure's
// handling of a clock that did not advance can be tested on any platform. Every CPU reading is zero,
// as on a Windows runner for small work, so Measure measures on the wall clock.
func fakeClock(t *testing.T, walls []time.Duration) *int {
	t.Helper()
	calls := 0
	saved := timeCall
	timeCall = func(fn func()) (Reading, error) {
		w := walls[len(walls)-1]
		if calls < len(walls) {
			w = walls[calls]
		}
		calls++
		return Reading{Wall: w}, nil
	}
	t.Cleanup(func() { timeCall = saved })
	return &calls
}

// One zero sample used to fail the whole measurement. It is re-taken instead, and the measurement
// uses the readings that resolved.
func TestMeasureRetakesAWallReadingThatDidNotAdvance(t *testing.T) {
	ms := time.Millisecond
	// Pair 1: base reads 0 once, then 2ms; big 8ms. Pairs 2-4: 2ms and 8ms.
	calls := fakeClock(t, []time.Duration{0, 2 * ms, 8 * ms, 2 * ms, 8 * ms, 2 * ms, 8 * ms, 2 * ms, 8 * ms})
	g, err := Measure(4, func() {}, func() {})
	if err != nil {
		t.Fatalf("Measure failed on a single zero sample: %v", err)
	}
	if g.Clock != "wall" || g.BaseMin != 2*ms || g.BigMin != 8*ms || g.Ratio != 4 {
		t.Errorf("got clock %s base %v big %v ratio %.2f, want wall 2ms 8ms 4.00", g.Clock, g.BaseMin, g.BigMin, g.Ratio)
	}
	if *calls != 9 {
		t.Errorf("timed %d calls, want 9: 8 readings plus one re-take", *calls)
	}
}

// A zero on the BIG side is the dangerous direction: it reads as no growth at all, a pass for a
// quadratic. It is re-taken the same way.
func TestMeasureRetakesAZeroBigReading(t *testing.T) {
	ms := time.Millisecond
	fakeClock(t, []time.Duration{2 * ms, 0, 0, 32 * ms, 2 * ms, 32 * ms, 2 * ms, 32 * ms, 2 * ms, 32 * ms})
	g, err := Measure(4, func() {}, func() {})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if g.BigMin != 32*ms || g.Ratio != 16 {
		t.Errorf("got big %v ratio %.2f, want 32ms 16.00: a zero big reading must not count", g.BigMin, g.Ratio)
	}
}

// A clock that never advances for this workload is still refused, and the retries are bounded.
func TestMeasureStillRefusesAWorkloadTheWallClockCannotResolve(t *testing.T) {
	calls := fakeClock(t, []time.Duration{0})
	_, err := Measure(4, func() {}, func() {})
	if err == nil || !strings.Contains(err.Error(), "wall") {
		t.Fatalf("got err %v, want the wall-clock refusal", err)
	}
	if *calls != 4*2*(1+maxZeroWallRetries) {
		t.Errorf("timed %d calls, want %d: each reading tried once plus %d re-takes", *calls, 4*2*(1+maxZeroWallRetries), maxZeroWallRetries)
	}
}
