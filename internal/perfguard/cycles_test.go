// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// report logs a line and, when running under GitHub Actions, also appends it to the job summary.
//
// The second half is the point. `go test` hides t.Logf for a PASSING package unless -v is set, and
// fmt.Println is hidden too — both measured — which is precisely why #619 could not be answered for
// so long: the complexity guard has logged its ratios all along and no CI log ever contained one.
//
// $GITHUB_STEP_SUMMARY is a file every step can append markdown to, so a probe can publish its
// numbers WITHOUT a workflow change. That matters here beyond convenience: .github/workflows is held
// by another open PR, and this is a measurement that cannot be taken on any developer's machine, so
// the alternative was waiting on a merge to learn anything.
//
// A no-op locally, since the variable is unset outside Actions.
func report(t *testing.T, format string, args ...any) {
	t.Helper()
	line := fmt.Sprintf(format, args...)
	t.Log(line)

	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// Never fail a measurement because its reporting channel was unavailable.
		t.Logf("could not append to the job summary: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, "- `%s/%s` %s\n", runtime.GOOS, runtime.GOARCH, line); err != nil {
		t.Logf("could not write to the job summary: %v", err)
	}
}

// TestCyclesUnsupportedIsAnErrorNotAZero pins the stub's contract on the platforms that do not have
// the counter.
//
// A stub returning (0, nil) is the failure mode worth guarding: a caller would divide zeros, or read
// "0 cycles" as a genuine measurement of instantaneous work. Both look like a passing guard.
func TestCyclesUnsupportedIsAnErrorNotAZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows has the counter; its behaviour is covered by the tests below")
	}
	if CyclesSupported() {
		t.Fatalf("CyclesSupported() is true on %s, but only windows implements it", runtime.GOOS)
	}
	n, err := ProcessCPUCycles()
	if !errors.Is(err, ErrCyclesUnsupported) {
		t.Errorf("ProcessCPUCycles() error = %v, want ErrCyclesUnsupported — a caller must not be "+
			"able to mistake the stub for a measurement", err)
	}
	if n != 0 {
		t.Errorf("ProcessCPUCycles() = %d on an unsupported platform, want 0", n)
	}
}

// TestWindowsCycleCounterIsUsableForRatios is the evidence #619 asks for, and it must come from a
// Windows CI run because no part of it can be measured on darwin or linux.
//
// It establishes the four properties a switch away from GetProcessTimes would depend on, and reports
// them whether or not it passes, so one CI run settles the design question. It does NOT change what
// any guard measures.
func TestWindowsCycleCounterIsUsableForRatios(t *testing.T) {
	if !CyclesSupported() {
		t.Skipf("no process-wide cycle counter on %s", runtime.GOOS)
	}

	// PROPERTY 1: it advances, and it never goes backwards. A counter that wraps or resets mid-run
	// would produce a negative delta read as a huge unsigned one.
	first, err := ProcessCPUCycles()
	if err != nil {
		t.Fatalf("ProcessCPUCycles: %v", err)
	}
	previous := first
	var deltas []uint64
	for i := 0; i < 200; i++ {
		burnCycles(2000)
		now, err := ProcessCPUCycles()
		if err != nil {
			t.Fatalf("ProcessCPUCycles: %v", err)
		}
		if now < previous {
			t.Fatalf("the counter went BACKWARDS: %d -> %d at iteration %d", previous, now, i)
		}
		if now > previous {
			deltas = append(deltas, now-previous)
		}
		previous = now
	}
	if len(deltas) == 0 {
		t.Fatalf("the counter never advanced across 200 samples of real work (start %d, end %d); "+
			"every property below would be measuring nothing", first, previous)
	}

	// PROPERTY 2: resolution. The smallest non-zero delta bounds how fine a reading can be. On
	// GetProcessTimes this is 15.625ms, which is what makes the complexity guard unusable on this
	// platform; a cycle counter should be many orders of magnitude finer.
	smallest := deltas[0]
	for _, d := range deltas {
		if d < smallest {
			smallest = d
		}
	}
	report(t, "PROPERTY 1+2: counter advanced on %d of 200 samples; smallest non-zero delta = %d cycles",
		len(deltas), smallest)

	// PROPERTY 3: descheduled time is NOT charged. This is the property the whole CPU-clock
	// statistic exists for (#579) and the one that would be lost by reading a raw invariant TSC,
	// which keeps advancing while a thread is not running. Sleeping must cost far less than doing
	// real work for the same wall duration.
	const nap = 200 * time.Millisecond

	beforeSleep, _ := ProcessCPUCycles()
	time.Sleep(nap)
	afterSleep, _ := ProcessCPUCycles()
	sleptCycles := afterSleep - beforeSleep

	beforeWork, _ := ProcessCPUCycles()
	burnFor(nap)
	afterWork, _ := ProcessCPUCycles()
	workCycles := afterWork - beforeWork

	report(t, "PROPERTY 3: %v asleep charged %d cycles; %v of real work charged %d cycles",
		nap, sleptCycles, nap, workCycles)
	if workCycles == 0 {
		t.Fatalf("busy work for %v charged zero cycles, so the comparison below is vacuous", nap)
	}
	// A generous bound: sleeping must cost under a tenth of working. If the counter charged
	// descheduled time the two would be within a few percent of each other.
	if sleptCycles*10 >= workCycles {
		t.Errorf("sleeping charged %d cycles against %d for equal wall time — the counter appears to "+
			"advance while descheduled, which would reintroduce the wall-clock defect the CPU "+
			"statistic exists to remove (#579)", sleptCycles, workCycles)
	}

	// PROPERTY 4: a 4x workload reads ~4x, and a quadratic one reads ~16x. This is the only property
	// the complexity guard actually needs, and it is unitless, so Microsoft's prohibition on
	// converting cycles to elapsed time does not apply to it.
	linear := cycleRatio(t, func(n int) { burnCycles(n) }, 4_000_000)
	quadratic := cycleRatio(t, burnQuadratic, 4_000_000)

	report(t, "PROPERTY 4: 4x input on the cycle counter — linear %.2fx, quadratic %.2fx "+
		"(want ~4x and ~16x; the guard's threshold is %.1f)", linear, quadratic, 8.0)

	if linear < 2.0 || linear > 8.0 {
		t.Errorf("a linear 4x workload measured %.2fx on the cycle counter; a guard with an 8.0 "+
			"bound would %s", linear,
			map[bool]string{true: "fail correct code", false: "be measuring something else"}[linear > 8.0])
	}
	if quadratic <= linear {
		t.Errorf("the quadratic workload measured %.2fx, at or below the linear %.2fx — the counter "+
			"cannot separate them and is no use to this guard", quadratic, linear)
	}
}

// cycleRatio measures work(base) and work(4*base) and returns the ratio of the minimum of two pairs,
// the same statistic Measure uses, so the number is comparable to the guard's own output.
func cycleRatio(t *testing.T, work func(n int), base int) float64 {
	t.Helper()

	minCycles := func(n int) uint64 {
		best := ^uint64(0)
		for i := 0; i < DefaultPairs; i++ {
			before, err := ProcessCPUCycles()
			if err != nil {
				t.Fatalf("ProcessCPUCycles: %v", err)
			}
			work(n)
			after, err := ProcessCPUCycles()
			if err != nil {
				t.Fatalf("ProcessCPUCycles: %v", err)
			}
			if d := after - before; d < best {
				best = d
			}
		}
		return best
	}

	var b, g uint64
	WithGCOff(func() {
		b = minCycles(base)
		g = minCycles(base * 4)
	})
	if b == 0 {
		t.Fatalf("the base workload charged zero cycles; the ratio would be undefined")
	}
	return float64(g) / float64(b)
}

// burnCycles does n units of arithmetic whose result escapes through a package-level sink.
//
// The sink is NOT what stops the loop being eliminated — measured, Go keeps the loop either way. What
// it does is keep each iteration EXPENSIVE: with `_ = acc` instead, the base reading fell from
// 5.094ms to 1.047ms, and with the body reduced to a constant store it fell to 1.625ms. Both are
// under MinMeasurableCPU, so perfguard silently fell back to the WALL clock — on a probe whose whole
// subject is a CPU clock.
//
// That fallback, not the ratio, is what TestTheCycleProbesOwnFixturesScaleAsClaimed asserts. The
// ratios stayed at 3.67x-4.41x and 14.75x-15.54x through both mutations, because a ratio is invariant
// to how expensive the work is: scaling every reading by the same factor leaves the quotient
// unchanged. A bound on the ratio can therefore never detect a fixture that became too cheap to
// measure.
func burnCycles(n int) {
	acc := uint64(1)
	for i := 0; i < n; i++ {
		acc = acc*2862933555777941757 + 3037000493
	}
	cycleSink += acc
}

// burnFor does real work for at least d of wall time, for the descheduling comparison.
func burnFor(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		burnCycles(50_000)
	}
}

var cycleSink uint64

// TestTheCycleProbesOwnFixturesScaleAsClaimed runs on EVERY platform, on the ordinary CPU clock,
// and exists because PROPERTY 4 above is Windows-only.
//
// Nothing else exercises burnCycles or the quadratic shape, so on darwin and linux they are dead
// code — and if the optimiser elided the accumulator loop, PROPERTY 4 would measure removed work and
// report a clean 4x/16x from nothing at all. A fixture must be shown to scale before a measurement
// taken with it means anything, and that check must not itself be Windows-only.
func TestTheCycleProbesOwnFixturesScaleAsClaimed(t *testing.T) {
	// 8M, not 4M: at 4M the base read 4.9-5.1ms against the 4ms floor asserted below, only 1.2x of
	// margin. A faster CPU than this one lowers the base, and the floor exists precisely to catch a
	// base that has drifted down, so it must not sit within noise of the honest value.
	linear, err := Measure(DefaultPairs,
		func() { burnCycles(8_000_000) },
		func() { burnCycles(32_000_000) })
	if err != nil {
		t.Fatalf("measuring the linear fixture: %v", err)
	}
	report(t, "linear fixture: %.2fx on the %s clock (base=%v big=%v)",
		linear.Ratio, linear.Clock, linear.BaseMin, linear.BigMin)
	if linear.Ratio < 2.5 || linear.Ratio > 6.0 {
		t.Errorf("burnCycles at 4x input measured %.2fx, want ~4x — the workload is not proportional "+
			"to n, so PROPERTY 4 on Windows would not be measuring a linear shape", linear.Ratio)
	}

	// The assertion that actually catches a fixture gone cheap. A ratio cannot: dropping the sink took
	// the base from 9.09ms to 2.15ms and the ratio stayed at 4.41x, because scaling every reading by the
	// same factor leaves their quotient alone. Judged on the WALL base, because requiring the CPU clock
	// is unsatisfiable on windows-latest — see assertFixtureIsMeasurable.
	assertFixtureIsMeasurable(t, "linear", linear, 4*time.Millisecond)

	// 12M rather than the linear fixture's 4M. burnQuadratic spends most of its budget in loop
	// bookkeeping rather than in burnCycles, so at 4M its base read 3.635ms — above MinMeasurableCPU
	// but UNDER the 2x floor asserted below, which failed this test on the commit that introduced the
	// floor. Sized from the measurement rather than by symmetry with the linear case.
	quadratic, err := Measure(DefaultPairs,
		func() { burnQuadratic(12_000_000) },
		func() { burnQuadratic(48_000_000) })
	if err != nil {
		t.Fatalf("measuring the quadratic fixture: %v", err)
	}
	report(t, "quadratic fixture: %.2fx on the %s clock (base=%v big=%v)",
		quadratic.Ratio, quadratic.Clock, quadratic.BaseMin, quadratic.BigMin)
	if quadratic.Ratio < 10.0 {
		t.Errorf("the quadratic fixture measured %.2fx at 4x input, want ~16x — PROPERTY 4 would "+
			"report that the cycle counter cannot separate quadratic from linear when the fault is "+
			"in the fixture", quadratic.Ratio)
	}
	if quadratic.Ratio <= linear.Ratio {
		t.Errorf("the quadratic fixture (%.2fx) does not read above the linear one (%.2fx); the two "+
			"fixtures are not distinguishable and PROPERTY 4 is vacuous",
			quadratic.Ratio, linear.Ratio)
	}
	assertFixtureIsMeasurable(t, "quadratic", quadratic, 16*time.Millisecond)
}

// assertFixtureIsMeasurable checks the thing a ratio bound cannot: that the base reading is large
// enough for the measurement to be about the code.
//
// JUDGED ON THE WALL BASE, not on which clock Measure chose. The first version required
// Clock == "cpu", and that failed on windows-latest with base=10.077ms while printing a message that
// was flatly untrue there — "its base of 10.077ms did not clear MinMeasurableCPU (2ms)". Windows
// reports process CPU time in 15.625ms steps, so a 10ms workload reads as 0 and Measure correctly
// falls back to wall; the fixture was fine and the assertion was unsatisfiable. That is the same
// defect this repo is fixing elsewhere — an assertion a platform cannot meet — reproduced by me in
// the change meant to characterise it.
//
// BaseWallMin is available on every platform and finely resolved on all of them (41ns on
// darwin/arm64, 722.7µs on windows-latest), so it is the portable proxy for "did enough work happen".
//
// The floor is PER FIXTURE, sized from each one's own measurement, because a single shared number
// goes vacuous against the cheaper one. Measured on darwin/arm64, wall base:
//
//	                 correct    sink dropped   body a constant store
//	linear (8M)      9.09ms     2.15ms         2.48ms      -> floor 4ms
//	quadratic (12M)  32.71ms    8.26ms         8.03ms      -> floor 16ms
//
// Each floor sits at roughly half the honest value and above both mutations, and both are cleared on
// windows-latest (linear 10.077ms, quadratic ~31ms).
func assertFixtureIsMeasurable(t *testing.T, name string, g Growth, floor time.Duration) {
	t.Helper()

	if g.BaseWallMin < floor {
		t.Errorf("the %s fixture's base is %v of wall time, under the %v floor: the work has become "+
			"too cheap for the measurement to be about the code. This is the failure a ratio bound "+
			"cannot see — dropping the sink took this base from 9.09ms to 2.15ms while the ratio stayed "+
			"at 4.41x, because scaling every reading by the same factor leaves the quotient alone. "+
			"(measured on the %s clock, cpu base %v)", name, g.BaseWallMin, floor, g.Clock, g.BaseMin)
		return
	}

	// Not an assertion: which clock was chosen is a property of the platform, and on windows-latest
	// the CPU clock cannot resolve a 10ms workload at all. Reported so a reader can tell a wall
	// fallback from a CPU reading when interpreting the ratio.
	if g.Clock != "cpu" {
		t.Logf("the %s fixture was measured on the %s clock (cpu base %v, wall base %v): this "+
			"platform's CPU accounting is too coarse for a fixture this size — see #619",
			name, g.Clock, g.BaseMin, g.BaseWallMin)
	}
}

// burnQuadratic does work proportional to n^2, in the same shape the complexity guard's own control
// uses: a pass proportional to n for each of a number of steps proportional to n.
func burnQuadratic(n int) {
	steps := n / 200_000
	for i := 0; i < steps; i++ {
		burnCycles(n / 20)
	}
}
