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

// reasonableFixtureBudget is the largest base CPU reading this repo is willing to spend on one growth
// measurement, and therefore the line between "this fixture has drifted too cheap" (a regression) and
// "this platform's clock cannot support the gate at all" (a tracked platform fact).
//
// 50ms, centred on the measured populations rather than picked. The 18 goldencorpus targets have base
// readings of 3.3ms-98ms, so 50ms is a fixture size the repo demonstrably already ships. And it
// separates the two cases widely in both directions: ubuntu-latest and darwin/arm64 resolve finely
// enough that MinTicks costs them under 4ms — 12x below this — while windows-latest advances its CPU
// clock in 15.625ms steps, so MinTicks costs it 125ms, 2.5x above. Nothing sits near the line.
const reasonableFixtureBudget = 50 * time.Millisecond

// TestTicksIsSufficientOnThisPlatformForATypicalFixture keeps the gate from silently disabling every
// assertion on the platforms where it CAN work.
//
// The danger of a resolution gate is that it converts a loud wrong answer into a quiet absent one. On
// a machine whose clock is fine, a normal fixture must clear the floor — measured on darwin/arm64, a
// ~3.4ms base against a 1µs tick is ~3,400 ticks, so there is enormous headroom.
//
// WHY THIS IS NOW CONDITIONAL. As first written it asserted that of EVERY platform, and windows-latest
// cannot satisfy it: MinTicks*15.625ms is a 125ms base, against a fixture built for ~4ms. It therefore
// failed roughly a third of the time on that runner — 6 of 20 consecutive main runs — and the
// intermittency had a precise cause. Windows reports a CPU reading of either 0 or 15.625ms for this
// fixture, so whether Measure picks the CPU clock (1 tick, fails) or falls back to the wall clock
// (tick 722.7µs, ~8 ticks, passes) is close to a coin flip per run.
//
// Failing every third run does not make the finding more true; it makes it easier to ignore, and it
// blocks unrelated merges. The platform-level cause is #619 and its fix is a finer clock, not a bigger
// fixture. So this now separates the two failures the original conflated:
//
//	the platform's tick makes MinTicks unaffordable  -> report it, with numbers. Tracked in #619
//	the tick is fine and the fixture went cheap      -> FAIL, which is what this test is for
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

	// Feasibility is judged against the clock Measure ACTUALLY used, not always the CPU one. On Windows
	// the wall clock is 20x finer than the CPU clock, so which one was chosen decides whether MinTicks
	// is affordable — and that choice is exactly what varies from run to run there.
	tick := cpu
	if g.Clock == "wall" {
		tick = wall
	}
	required := time.Duration(MinTicks) * tick

	if required > reasonableFixtureBudget {
		t.Logf("NOT ASSERTED — this platform's %s tick is %v, so MinTicks (%d) needs a base of %v, over "+
			"the %v this repo spends on a fixture. Every growth assertion in the repo is being SKIPPED "+
			"here, which is real and is tracked in #619: the fix is a finer clock, not a bigger fixture. "+
			"Asserting it anyway failed about one run in three on windows-latest (6 of 20 consecutive "+
			"main runs) and blocked unrelated merges.",
			g.Clock, tick, MinTicks, required, reasonableFixtureBudget)
		return
	}

	if !sufficient {
		t.Errorf("a typical fixture spans only %.1f ticks here, and this platform's %s tick of %v makes "+
			"MinTicks (%d) affordable at %v — so this is NOT the #619 platform limitation. Every growth "+
			"assertion in this repo is being SKIPPED: either the fixtures have drifted too cheap or "+
			"MinTicks is wrong", n, g.Clock, tick, MinTicks, required)
	}
}

// TestMinTicksAffordableCoversTheWindowsCases is the must-still-bite half, and it is a table over the
// PURE function so the cases that only occur on windows-latest are exercised on every platform.
//
// Both halves matter. An escape hatch wide enough to cover a working platform would silently retire the
// sufficiency test everywhere; one that ignores which clock was used would call Windows infeasible even
// on the wall-clock runs where MinTicks is perfectly affordable, and those are the runs that used to
// pass. Every tick below is measured, not assumed.
func TestMinTicksAffordableCoversTheWindowsCases(t *testing.T) {
	const (
		windowsCPUTick  = 15625 * time.Microsecond // measured: every reading an exact multiple
		windowsWallTick = 722700 * time.Nanosecond // measured on the same runner
		darwinCPUTick   = time.Microsecond         // measured on darwin/arm64
		darwinWallTick  = 41 * time.Nanosecond     // measured on darwin/arm64
		ubuntuCPUTick   = 490 * time.Microsecond   // inferred: a 3.9ms base asserts, so tick <= base/8
	)

	for _, tc := range []struct {
		name           string
		clock          string
		cpu, wall      time.Duration
		wantAffordable bool
		wantTick       time.Duration
	}{
		// The two Windows rows are the whole point: same platform, opposite verdicts, decided only by
		// which clock the measurement landed on. Conflating them is what made the test a coin flip.
		{"windows on its CPU clock — 125ms needed, unaffordable",
			"cpu", windowsCPUTick, windowsWallTick, false, windowsCPUTick},
		{"windows fell back to wall — 5.8ms needed, affordable",
			"wall", windowsCPUTick, windowsWallTick, true, windowsWallTick},

		{"darwin CPU clock", "cpu", darwinCPUTick, darwinWallTick, true, darwinCPUTick},
		{"darwin wall clock", "wall", darwinCPUTick, darwinWallTick, true, darwinWallTick},
		{"ubuntu CPU clock", "cpu", ubuntuCPUTick, 0, true, ubuntuCPUTick},

		// A clock as coarse as the whole budget: MinTicks makes it 8x too expensive.
		{"a clock as coarse as the budget", "cpu", MinTicksBudget, 0, false, MinTicksBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tick, required, affordable := MinTicksAffordable(tc.clock, tc.cpu, tc.wall)
			if tick != tc.wantTick {
				t.Errorf("judged against a %v tick, want %v — the verdict is about the wrong clock, so "+
					"a Windows wall-clock run would be declared infeasible when MinTicks is affordable "+
					"on it", tick, tc.wantTick)
			}
			if affordable != tc.wantAffordable {
				t.Errorf("MinTicks needs %v against the %v budget: affordable=%v, want %v",
					required, MinTicksBudget, affordable, tc.wantAffordable)
			}
		})
	}

	// The boundary sits where it is claimed to, so the measured platforms are not on the right side of
	// it by luck. Both directions, because a budget that drifts either way retires a real check.
	if _, windowsNeeds, _ := MinTicksAffordable("cpu", windowsCPUTick, 0); windowsNeeds <= MinTicksBudget {
		t.Errorf("windows needs %v, which the %v budget calls affordable — the hatch would never open "+
			"and the sufficiency test would keep flaking there", windowsNeeds, MinTicksBudget)
	}
	if _, ubuntuNeeds, _ := MinTicksAffordable("cpu", ubuntuCPUTick, 0); ubuntuNeeds*4 > MinTicksBudget {
		t.Errorf("ubuntu needs %v, within 4x of the %v budget — too close to the line for a threshold "+
			"meant to separate a platform limit from a fixture regression", ubuntuNeeds, MinTicksBudget)
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
