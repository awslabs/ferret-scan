// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"strings"
	"testing"
	"time"
)

// TestTicksRefusesAWindowsTickReading is the whole point of the resolution gate, checked against the
// numbers windows-latest actually produced rather than invented ones.
//
// Every CPU reading in that run was an exact multiple of 15.625ms, so the complexity guard was
// dividing integer tick counts and reporting the quotient as a growth ratio:
//
//	linear control  base=15.625ms  big=31.25ms     -> "2.00x"   (2 ticks / 1 tick)
//	ssn             base=46.875ms  big=234.375ms   -> "5.00x"   (15 ticks / 3 ticks)
//
// Both must be refused. The old gate could not refuse them: MinMeasurableCPU is 2ms, which is 0.128
// of a single tick on that platform, so a 1-tick reading sailed through it.
func TestTicksRefusesAWindowsTickReading(t *testing.T) {
	const windowsTick = 15625 * time.Microsecond

	// Every case goes through ticksAt, the real decision. An earlier version of this test computed the
	// tick count itself and compared THAT to MinTicks, which verified the test's own arithmetic — a
	// mutant making the gate always report "sufficient" survived it.
	cases := []struct {
		name           string
		base, res      time.Duration
		wantTicks      float64
		wantSufficient bool
	}{
		// The two readings windows-latest actually produced. Both must be refused.
		{"linear control on windows (reported a bogus 2.00x)", 15625 * time.Microsecond, windowsTick, 1, false},
		{"ssn on windows (reported a bogus 5.00x)", 46875 * time.Microsecond, windowsTick, 3, false},
		{"7 ticks, still under the floor", 7 * windowsTick, windowsTick, 7, false},
		{"8 ticks, exactly at the floor", 8 * windowsTick, windowsTick, 8, true},
		{"16 ticks, comfortably over", 16 * windowsTick, windowsTick, 16, true},
		// A fine clock: the same 3.4ms base that reads ~1 tick on Windows is ample at 1µs.
		{"a darwin-like 1µs tick", 3400 * time.Microsecond, time.Microsecond, 3400, true},
		// Degenerate inputs must not report sufficiency. base/0 is +Inf and +Inf >= MinTicks is TRUE,
		// so an unguarded version would call an unmeasurable reading ample.
		{"unmeasured resolution", 15 * time.Millisecond, 0, 0, false},
		{"zero base", 0, windowsTick, 0, false},
		{"both zero", 0, 0, 0, false},
	}
	for _, c := range cases {
		n, sufficient := ticksAt(c.base, c.res)
		if n != c.wantTicks || sufficient != c.wantSufficient {
			t.Errorf("%s: ticksAt(%v, %v) = (%.1f, %v), want (%.1f, %v)",
				c.name, c.base, c.res, n, sufficient, c.wantTicks, c.wantSufficient)
		}
	}

	// NON-VACUITY on the constant itself: too low and a 1-tick reading qualifies, too high and no
	// fixture in this repo can ever qualify so every assertion is silently skipped.
	if _, ok := ticksAt(windowsTick, windowsTick); ok {
		t.Errorf("MinTicks=%d admits a 1-tick reading, where one tick of quantisation is 100%% error", MinTicks)
	}
	if _, ok := ticksAt(64*windowsTick, windowsTick); !ok {
		t.Errorf("MinTicks=%d rejects even a 64-tick base (%v on Windows); no fixture could qualify",
			MinTicks, 64*windowsTick)
	}
}

// TestTicksIsSufficientOnThisPlatformForATypicalFixture keeps the gate from silently disabling every
// assertion on the platforms where it DOES work.
//
// The danger of a resolution gate is that it converts a loud wrong answer into a quiet absent one. On
// a machine whose clock is fine, a normal fixture must clear the floor — measured on darwin/arm64, a
// ~3.4ms base against a 1µs tick is ~3,400 ticks, so there is enormous headroom. If this ever fails,
// the guards in goldencorpus and svgtextlib have stopped asserting on THIS platform and the CI log is
// the only place that would say so.
func TestTicksIsSufficientOnThisPlatformForATypicalFixture(t *testing.T) {
	cpu, wall := ClockResolution()
	t.Logf("measured tick on this platform: cpu=%v wall=%v", cpu, wall)

	g, err := Measure(DefaultPairs, func() { spin(4) }, func() { spin(16) })
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	n, sufficient := g.Ticks()
	t.Logf("%s", g)
	t.Logf("%s", g.ResolutionNote())
	if !sufficient {
		t.Errorf("a typical fixture spans only %.1f ticks here, so every growth assertion in this repo "+
			"is being SKIPPED on this platform. Either the fixtures need to grow or MinTicks (%d) is wrong",
			n, MinTicks)
	}
}

// TestResolutionNoteAlwaysStatesTheTickCount: a ratio and a ratio-from-a-1-tick-base are different
// claims, and only one is evidence. The note is what a reader uses to tell them apart, so it must
// always carry the number.
func TestResolutionNoteAlwaysStatesTheTickCount(t *testing.T) {
	g, err := Measure(DefaultPairs, func() { spin(4) }, func() { spin(16) })
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	note := g.ResolutionNote()
	for _, want := range []string{"ticks", g.Clock, "tick="} {
		if !strings.Contains(note, want) {
			t.Errorf("ResolutionNote() = %q, missing %q", note, want)
		}
	}
	// And a zero-base Growth must not claim sufficiency or divide by zero.
	var empty Growth
	if n, ok := empty.Ticks(); ok || n != 0 {
		t.Errorf("empty Growth reported ticks=%v sufficient=%v; want 0/false", n, ok)
	}
}

// TestClockResolutionIsCachedAndStable: the tick is a property of the platform, and the CPU probe
// burns real CPU, so re-measuring it per call would make every guard slower and could report a
// different figure under load.
func TestClockResolutionIsCachedAndStable(t *testing.T) {
	c1, w1 := ClockResolution()
	c2, w2 := ClockResolution()
	if c1 != c2 || w1 != w2 {
		t.Errorf("ClockResolution is not stable across calls: (%v,%v) then (%v,%v)", c1, w1, c2, w2)
	}
	if c1 <= 0 || w1 <= 0 {
		t.Errorf("measured a non-positive tick (cpu=%v wall=%v); every gate built on it would refuse "+
			"every reading and silently disable all growth assertions", c1, w1)
	}
}
