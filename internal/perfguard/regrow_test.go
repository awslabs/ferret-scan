// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// regrowMargin is how far past MinTicks a regrown fixture aims, so one more tick of coarsening between
// the regrow and the remeasure does not put it back under. 1.25 = 10 ticks when 8 are required; the
// observed readings that failed (5.1 and 6.1 ticks) are 21-36% short, so 25% over the target covers a
// second move of the same size, and it costs a fixture at most ~17ms at the coarsest tick on record.
const regrowMargin = 1.25

// maxRegrowFactor bounds one regrowth. A base that spans almost no ticks (a wall clock that read one
// tick over the whole call) gives a ratio that is mostly noise, and growing by it blindly could turn a
// 4-unit fixture into a minute of CPU. 16x of the calibrated size is ~100ms at the observed windows
// unit cost, which is the most this repo is willing to spend to find out.
const maxRegrowFactor = 16

// regrownUnits is the decision behind option 2 of #840, separated from the measurement so it can be
// checked against another platform's numbers. It is pure and takes the tick as a parameter for the same
// reason clockForRatio and ticksAt do: windows-latest's wall tick moves between 320µs and 1.71ms from
// run to run, and no local run on another OS can reproduce that.
//
// It returns the fixture size to remeasure with and whether that is a regrowth at all. A base that
// already spans MinTicks of the tick in effect is left alone, and so is one whose span or tick cannot
// be judged (a zero is not a verdict, and ticksAt already refuses to divide by one).
//
// The size is units x MinTicks x regrowMargin / observed ticks, rounded UP, because a fraction of a
// unit buys no ticks and under-sizing is the failure being fixed. Cost is linear in units, so scaling
// the units by the ratio of needed to observed ticks scales the span by the same ratio.
func regrownUnits(units int, baseSpan, tick time.Duration) (newUnits int, grew bool) {
	n, ok := ticksAt(baseSpan, tick)
	if ok || n <= 0 || units < 1 {
		return units, false
	}
	factor := float64(MinTicks) * regrowMargin / n
	if factor > maxRegrowFactor {
		factor = maxRegrowFactor
	}
	newUnits = int(math.Ceil(float64(units) * factor))
	if newUnits <= units {
		return units, false
	}
	return newUnits, true
}

// regrowResult is a measurement that was judged against the tick in effect when it finished.
type regrowResult struct {
	Growth Growth
	Units  int
	// Tick is the granularity of Growth.Clock re-read AFTER the measurement; Ticks is the base span in
	// units of it, and Sufficient is Ticks >= MinTicks.
	Tick       time.Duration
	Ticks      float64
	Sufficient bool
	// Regrown is set when the first measurement fell short and the fixture was grown once.
	Regrown bool
	// FirstTicks is the first measurement's span; equal to Ticks when nothing was regrown.
	FirstTicks float64
}

// measureWithRegrowth runs measure(units), re-reads the tick of the clock it used, and when the base
// spans fewer than MinTicks of that tick grows the fixture ONCE and measures again (#840 option 2).
// The first measurement's shortfall is logged, never swallowed: a fixture that needs regrowing is
// information about the runner.
//
// measure and tickFor are parameters so a test can simulate the shortfall (calibrate against a fine
// tick, measure against a coarse one). Production use is measureCalibrated.
func measureWithRegrowth(units int, measure func(units int) (Growth, error),
	tickFor func(clock string) time.Duration, logf func(format string, args ...any)) (regrowResult, error) {

	g, err := measure(units)
	if err != nil {
		return regrowResult{}, err
	}
	tick := tickFor(g.Clock)
	n, ok := ticksAt(g.BaseMin, tick)
	r := regrowResult{Growth: g, Units: units, Tick: tick, Ticks: n, Sufficient: ok, FirstTicks: n}
	if ok {
		return r, nil
	}
	newUnits, grew := regrownUnits(units, g.BaseMin, tick)
	logf("base of %d units spans only %.1f ticks of the %s clock (tick=%v), under the %d required; "+
		"regrowing once (grew=%v, %d units) and remeasuring", units, n, g.Clock, tick, MinTicks, grew, newUnits)
	if !grew {
		return r, nil
	}
	g, err = measure(newUnits)
	if err != nil {
		return regrowResult{}, err
	}
	tick = tickFor(g.Clock)
	n, ok = ticksAt(g.BaseMin, tick)
	return regrowResult{Growth: g, Units: newUnits, Tick: tick, Ticks: n, Sufficient: ok,
		Regrown: true, FirstTicks: r.FirstTicks}, nil
}

// tickInEffect re-reads the granularity of the clock a measurement used. The wall tick is polled afresh
// because it is the one that moves on windows-latest; it never goes below the cached reading, so a
// quiet moment cannot argue the fixture back down. The CPU tick is a fixed property of the platform
// and probing it costs real CPU, so the cached value stands.
func tickInEffect(clock string) time.Duration {
	cpu, wall := ClockResolution()
	if clock != "wall" {
		return cpu
	}
	for i := 0; i < 3; i++ {
		if d := oneWallTick(); d > wall {
			wall = d
		}
	}
	return wall
}

// measureCalibrated is the Measure(base, 4x base) every sufficiency test here uses, with option 2
// applied: size from calibratedBaseUnits, remeasure once if the tick in effect says it was too small.
func measureCalibrated(t *testing.T) (regrowResult, error) {
	t.Helper()
	return measureWithRegrowth(calibratedBaseUnits(), func(u int) (Growth, error) {
		return Measure(DefaultPairs, func() { spin(u) }, func() { spin(4 * u) })
	}, tickInEffect, t.Logf)
}

// TestRegrownUnitsTable covers the arithmetic that no darwin run exercises. The two CI rows are the
// readings of runs 44621545600 (5.1 ticks at 325.3µs) and 40889501743 (6.1 ticks at 1.2547ms);
// the fixture was 4 units in both.
func TestRegrownUnitsTable(t *testing.T) {
	cases := []struct {
		name      string
		units     int
		span, tck time.Duration
		want      int
		wantGrew  bool
	}{
		{"CI 44621545600: 5.1 ticks at 325.3us", 4, 5100 * 325300 / 1000 * time.Nanosecond, 325300 * time.Nanosecond, 8, true},
		{"CI 40889501743: 6.1 ticks at 1.2547ms", 4, 7673500 * time.Nanosecond, 1254700 * time.Nanosecond, 7, true},
		{"exactly MinTicks is enough", 4, 8 * time.Millisecond, time.Millisecond, 4, false},
		{"above MinTicks is untouched", 4, 40 * time.Millisecond, time.Millisecond, 4, false},
		{"coarsest observed tick (1.7107ms), 7.3ms base", 4, 7300 * time.Microsecond, 1710700 * time.Nanosecond, 10, true},
		{"half a tick over the whole call is capped at 16x", 4, 500 * time.Microsecond, time.Millisecond, 64, true},
		{"zero span is not judged", 4, 0, time.Millisecond, 4, false},
		{"zero tick is not judged", 4, time.Millisecond, 0, 4, false},
		{"no units is not judged", 0, time.Millisecond, 2 * time.Millisecond, 0, false},
	}
	for _, c := range cases {
		got, grew := regrownUnits(c.units, c.span, c.tck)
		n, _ := ticksAt(c.span, c.tck)
		t.Logf("%s: %d units, %.2f ticks -> %d units (grew=%v)", c.name, c.units, n, got, grew)
		if got != c.want || grew != c.wantGrew {
			t.Errorf("%s: regrownUnits(%d, %v, %v) = %d, %v; want %d, %v",
				c.name, c.units, c.span, c.tck, got, grew, c.want, c.wantGrew)
		}
	}
}

// TestRegrowthClearsMinTicksAtEveryObservedWindowsWallTick checks the closed loop: whatever the tick in
// effect, a fixture that fell short grows once to a span that clears MinTicks of that tick, from every
// starting size the calibration can produce. Unit cost is windows-latest's own 1.836ms.
func TestRegrowthClearsMinTicksAtEveryObservedWindowsWallTick(t *testing.T) {
	const winUnitCost = 1836 * time.Microsecond
	observed := []time.Duration{
		320_000, 332_500, 335_900, 336_100, 372_600, 383_100, 399_400, 473_800, 482_100, 484_500,
		505_300, 513_700, 518_900, 522_200, 532_200, 546_600, 622_500, 764_800, 951_000, 1_710_700,
	}
	for _, tick := range observed {
		tick *= time.Nanosecond
		for _, units := range []int{historicalBaseUnits, 5, 6} {
			span := time.Duration(units) * winUnitCost
			got, grew := regrownUnits(units, span, tick)
			if _, ok := ticksAt(span, tick); ok {
				if grew {
					t.Errorf("tick %v units %d: already sufficient but regrown to %d", tick, units, got)
				}
				continue
			}
			if !grew {
				t.Errorf("tick %v units %d: %.2f ticks, not regrown", tick, units, float64(span)/float64(tick))
				continue
			}
			if n, ok := ticksAt(time.Duration(got)*winUnitCost, tick); !ok {
				t.Errorf("tick %v units %d: regrown to %d units spans %.2f ticks, still under %d",
					tick, units, got, n, MinTicks)
			}
		}
	}
}

// TestAShortfallIsRegrownAndRemeasuredNotReported simulates the #840 failure on any OS: the fixture is
// sized against a fine tick and the tick has coarsened by the time it is judged. Before this change the
// sufficiency tests Errorf'd on exactly this input; now the first measurement is logged as a shortfall
// and the second one asserts.
func TestAShortfallIsRegrownAndRemeasuredNotReported(t *testing.T) {
	const unitCost = 1918 * time.Microsecond // 4 units = 7.67ms, the run-40889501743 base
	calls := 0
	measure := func(units int) (Growth, error) {
		calls++
		span := time.Duration(units) * unitCost
		return Growth{Clock: "wall", BaseMin: span, BigMin: 4 * span, Ratio: 4}, nil
	}
	tick := 1254700 * time.Nanosecond // coarsened from the fine reading the fixture was sized on
	var logged []string
	logf := func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }

	r, err := measureWithRegrowth(4, measure, func(string) time.Duration { return tick }, logf)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Regrown || !r.Sufficient || calls != 2 {
		t.Fatalf("regrown=%v sufficient=%v calls=%d; want a single regrowth that clears the gate: %+v",
			r.Regrown, r.Sufficient, calls, r)
	}
	if r.FirstTicks >= MinTicks || r.Ticks < MinTicks {
		t.Errorf("first=%.2f ticks final=%.2f ticks; want first under and final at or above %d",
			r.FirstTicks, r.Ticks, MinTicks)
	}
	if len(logged) != 1 {
		t.Errorf("logged %d shortfall lines, want 1: %q", len(logged), logged)
	}
	t.Logf("simulated: %d units -> %.1f ticks at %v; regrown to %d units -> %.1f ticks. log: %s",
		4, r.FirstTicks, tick, r.Units, r.Ticks, logged[0])
}

// TestRegrowthHappensAtMostOnce pins "once": a runner whose clock keeps moving must end as an honest
// shortfall the caller reports, not as an unbounded loop of ever bigger fixtures.
func TestRegrowthHappensAtMostOnce(t *testing.T) {
	calls := 0
	measure := func(units int) (Growth, error) {
		calls++
		return Growth{Clock: "wall", BaseMin: time.Millisecond, BigMin: 4 * time.Millisecond}, nil
	}
	r, err := measureWithRegrowth(4, measure, func(string) time.Duration { return time.Millisecond },
		func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || r.Sufficient || !r.Regrown {
		t.Errorf("calls=%d regrown=%v sufficient=%v; want 2 calls, regrown, still insufficient", calls, r.Regrown, r.Sufficient)
	}
}

// TestASufficientFirstMeasurementIsNotRegrown keeps the common case at one measurement.
func TestASufficientFirstMeasurementIsNotRegrown(t *testing.T) {
	calls := 0
	measure := func(int) (Growth, error) {
		calls++
		return Growth{Clock: "cpu", BaseMin: 9 * time.Millisecond}, nil
	}
	r, err := measureWithRegrowth(4, measure, func(string) time.Duration { return time.Millisecond },
		func(string, ...any) { t.Error("nothing to log when the first measurement clears the gate") })
	if err != nil || calls != 1 || r.Regrown || !r.Sufficient {
		t.Errorf("err=%v calls=%d regrown=%v sufficient=%v", err, calls, r.Regrown, r.Sufficient)
	}
}
