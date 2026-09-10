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
	// Gated on the clock, like every other ratio assertion in this repo. windows-latest FAILED here
	// with "2.00x on the cpu clock (base=15.625ms big=31.25ms)" -- one tick over two ticks, a quotient
	// of small integers and not a measurement of code. That is precisely what MinTicks exists to
	// refuse, and this test was the one ratio assertion in the package that never asked.
	// A NUMERIC WINDOW ON A GROWTH RATIO BELONGS TO THE CPU CLOCK ONLY.
	//
	// This package exists because a wall-clock ratio is not a measure of complexity on a shared runner:
	// under 28 busy-loops the wall statistic scored a quadratic at 9.94x and a linear one at 10.20x,
	// INVERTED (see the package comment). Since #645 moved windows-latest onto its wall clock -- the CPU
	// clock there steps 15.625ms and cannot resolve a fixture this size -- a tight window on that reading
	// is a bound on descheduling, not on the code. It failed exactly that way: "6.07x on the wall clock
	// (base=12.4688ms big=75.707ms)" against a 6.0 ceiling, with the base spanning an ample 24.2 ticks.
	// The clock could resolve it; the number simply was not about burnCycles.
	//
	// Proportionality no longer needs the ratio to prove it -- the exact sink values below pin the work
	// at BOTH sizes, so "big does 4x the iterations of base" is arithmetic rather than a measurement.
	// What the clock still has to show is that it can SEPARATE the two shapes, and that is the ordering
	// assertion further down, which held at 2.26x even on the contended wall-clock reading.
	switch {
	case linear.Clock != "cpu":
		t.Logf("linear shape window NOT asserted — measured on the %s clock, where a numeric bound on a "+
			"ratio bounds contention rather than the code (%.2fx, %s)",
			linear.Clock, linear.Ratio, linear.ResolutionNote())
	default:
		if _, resolvable := linear.Ticks(); !resolvable {
			t.Logf("linear shape NOT asserted — %s", linear.ResolutionNote())
		} else if linear.Ratio < 2.5 || linear.Ratio > linearMaxOnCPU {
			t.Errorf("burnCycles at 4x input measured %.2fx on the cpu clock, want ~4x — the workload is "+
				"not proportional to n, so PROPERTY 4 on Windows would not be measuring a linear shape. %s",
				linear.Ratio, linear.ResolutionNote())
		}
	}

	// The assertion that actually catches a fixture gone cheap. A ratio cannot: dropping the sink took
	// the base from 9.09ms to 2.15ms and the ratio stayed at 4.41x, because scaling every reading by the
	// same factor leaves their quotient alone. Judged on the WALL base, because requiring the CPU clock
	// is unsatisfiable on windows-latest — see assertFixtureIsMeasurable.
	assertFixtureDidTheWork(t, "linear", linear,
		func() { burnCycles(8_000_000) }, wantLinearBaseSink,
		func() { burnCycles(32_000_000) }, wantLinearBigSink)

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
	// Same reasoning, same clock restriction. The observed wall-clock reading was 13.69x against this
	// 10.0 floor -- only 1.37x of margin, under the 1.5x this repo asks of a guard -- so asserting it on
	// the wall clock would be the next failure rather than a bound anyone had measured.
	switch {
	case quadratic.Clock != "cpu":
		t.Logf("quadratic shape floor NOT asserted — measured on the %s clock (%.2fx, %s)",
			quadratic.Clock, quadratic.Ratio, quadratic.ResolutionNote())
	default:
		if _, resolvable := quadratic.Ticks(); !resolvable {
			t.Logf("quadratic shape NOT asserted — %s", quadratic.ResolutionNote())
		} else if quadratic.Ratio < 10.0 {
			t.Errorf("the quadratic fixture measured %.2fx at 4x input on the cpu clock, want ~16x — "+
				"PROPERTY 4 would report that the cycle counter cannot separate quadratic from linear "+
				"when the fault is in the fixture. %s", quadratic.Ratio, quadratic.ResolutionNote())
		}
	}
	// Compares two measurements, so it needs BOTH to be divisible -- on a clock that resolves neither,
	// "16 ticks > 4 ticks" is arithmetic about the clock rather than about the fixtures.
	_, linOK := linear.Ticks()
	_, quadOK := quadratic.Ticks()
	if !linOK || !quadOK {
		t.Logf("shape ORDERING not asserted — linear: %s; quadratic: %s",
			linear.ResolutionNote(), quadratic.ResolutionNote())
	} else if quadratic.Ratio <= linear.Ratio {
		t.Errorf("the quadratic fixture (%.2fx) does not read above the linear one (%.2fx); the two "+
			"fixtures are not distinguishable and PROPERTY 4 is vacuous",
			quadratic.Ratio, linear.Ratio)
	}
	assertFixtureDidTheWork(t, "quadratic", quadratic,
		func() { burnQuadratic(12_000_000) }, wantQuadBaseSink,
		func() { burnQuadratic(48_000_000) }, wantQuadBigSink)
}

// wantLinearSink and wantQuadraticSink are the fixtures' exact observable results, and they replace
// the absolute millisecond floors this file used to assert.
//
// burnCycles is an LCG: acc = acc*2862933555777941757 + 3037000493, from acc=1, accumulated into
// cycleSink. Its value after n steps therefore has a CLOSED FORM -- binary exponentiation of the affine
// map x -> a*x + c, composing (a1,c1) then (a2,c2) as (a1*a2, c1*a2 + c2) -- computed independently of
// the loop and verified against it for n in {0, 1, 2, 3, 10, 1000}. So the honest result of each fixture
// is a compile-time constant, and checking it needs no clock, no calibration and no knowledge of the
// machine.
//
// burnQuadratic(12_000_000) is 60 calls of burnCycles(600_000) (steps = n/200_000, each burning n/20),
// so its contribution is 60 * f(600_000) taken mod 2^64. uint64 overflow is defined as wrapping by the
// Go spec on every GOARCH, so these constants are portable.
// linearMaxOnCPU is the upper end of the linear shape's window, and it is 7.0 rather than 6.0 because
// 6.0 did not carry this repo's own >=1.5x margin.
//
// Every CPU-clock reading of this fixture observed anywhere: 3.67, 3.69, 3.87, 3.95, 3.98, 3.99, 4.00,
// 4.02, 4.05, 4.14, 4.26, 4.41 (darwin/arm64, plain and -race) and 4.57 (macos-latest, -race). The worst
// is 4.57, so a ceiling needs to sit at or above 4.57 x 1.5 = 6.86. At 6.0 the margin was 1.31x, which is
// how a ceiling gets breached by a slightly slower runner rather than by a defect. 7.0 keeps 1.53x above
// the worst reading while staying 2.3x below the quadratic population (15.4-16.9x on the same clock), so
// the two shapes remain unambiguously separated.
const linearMaxOnCPU = 7.0

const (
	wantLinearBaseSink uint64 = 16024774407366977025 // burnCycles(8_000_000)
	wantLinearBigSink  uint64 = 4120727529216841729  // burnCycles(32_000_000)
	wantQuadBaseSink   uint64 = 15005894239974959932 // burnQuadratic(12_000_000) = 60 x f(600_000)
	wantQuadBigSink    uint64 = 15698372006874624240 // burnQuadratic(48_000_000) = 240 x f(2_400_000)
)

// assertFixtureDidTheWork checks what an absolute duration floor was trying to check, without being a
// claim about any particular machine.
//
// WHY THE FLOORS ARE GONE. This file used to assert `floor <= g.BaseWallMin <= 4*floor` with floors of
// 4ms and 16ms, each set at "roughly half" one developer machine's reading. Both bounds are statements
// about hardware speed, and the fleet is wider than the band:
//
//	                    dev darwin/arm64   macos-latest        verdict
//	quadratic base      33.3-37.5ms        66.98ms, 72.78ms    FAILED, ceiling is 64ms
//	linear base         7.8-8.6ms          ~13-15ms            1.05-1.21x under a 16ms ceiling
//
// Re-centring cannot fix it: the ceiling is 4x the floor, and placing the floor at half one machine's
// reading spends half the window before any other machine is considered. The 16ms linear ceiling is
// already breached on the derivation machine itself (17.2ms observed). And judging BaseWallMin -- chosen
// so the check is satisfiable on Windows -- imports contention on top of hardware spread.
//
// WHAT REPLACES THEM. The floors existed to catch a fixture gone cheap, tabulated as: dropping the sink
// took the linear base 9.09ms -> 2.15ms, and a constant-store body -> 2.48ms, with the RATIO unmoved.
// An exact result catches both of those and more, exactly:
//
//	honest                      16024774407366977025
//	sink dropped                0
//	body a constant store       3037000493
//	loop shortened 8x           8372428151581377729
//	multiplier or increment changed   any other value
//
// KNOWN GAP, stated rather than hidden: a semantics-preserving STRENGTH REDUCTION is not caught. Folding
// the affine map k-wise and iterating n/k times returns a bit-identical result for k=8 and k=64 (checked)
// while doing 1/k of the work. That is accepted deliberately, because such a fixture is still
// PROPORTIONAL -- 4x input still costs 4x -- so the shape assertions above still hold, and the only
// residual risk is a reading too small for the clock, which is a tick question and is checked below.
func assertFixtureDidTheWork(t *testing.T, name string, g Growth,
	runBase func(), wantBase uint64, runBig func(), wantBig uint64) {
	t.Helper()

	// BOTH sizes, which is what makes this a proportionality check and not merely an elision check.
	// Pinning base and big separately says "base did exactly its n iterations and big did exactly its
	// 4n" -- so "big is 4x base" becomes arithmetic on two exact constants instead of a timing ratio a
	// contended wall clock can distort. That is what lets the numeric ratio windows above be restricted
	// to the CPU clock without losing the property they were asserting.
	for _, c := range []struct {
		size string
		run  func()
		want uint64
	}{{"base", runBase, wantBase}, {"big", runBig, wantBig}} {
		// Run OUTSIDE the measured region -- adding it to a timed call would charge the measurement.
		before := cycleSink
		c.run()
		if got := cycleSink - before; got != c.want {
			t.Errorf("the %s fixture's %s size produced %d, want %d: it is not doing the work it claims, "+
				"so any ratio measured with it describes something else. 0 means the sink write was "+
				"dropped or the loop was elided; %d means the body became a constant store.",
				name, c.size, got, c.want, 3037000493)
		}
	}

	// The measurability half, in TICKS of the clock that took the reading rather than in milliseconds.
	// Self-scaling: the tick is measured on the same machine, so this says the same thing on a runner
	// three times slower without naming a duration.
	if n, ok := g.Ticks(); !ok {
		t.Logf("the %s fixture's base spans %.1f ticks — %s", name, n, g.ResolutionNote())
	}

	// Not an assertion: which clock was chosen is a property of the platform, and on windows-latest the
	// CPU clock cannot resolve a 10ms workload at all. Reported so a reader can tell a wall fallback
	// from a CPU reading when interpreting the ratio.
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

// cycleProbeVerdict is the decision this test makes for one fixture reading, extracted so it can be
// replayed against readings taken on machines a developer does not have.
type cycleProbeVerdict string

const (
	verdictAssertWindow cycleProbeVerdict = "assert the numeric window"   // cpu clock, enough ticks
	verdictWallDisclose cycleProbeVerdict = "disclose: not the cpu clock" // wall clock -> no numeric bound
	verdictTooFewTicks  cycleProbeVerdict = "disclose: too few ticks"     // cpu clock, unresolvable
)

// cycleProbeDecision mirrors the control flow in TestTheCycleProbesOwnFixturesScaleAsClaimed exactly.
//
// Kept as one function so the table below exercises the REAL branch order rather than a paraphrase of it.
// The first version of that table asserted only tick sufficiency, and it therefore passed while the test
// itself failed on windows-latest at "6.07x on the wall clock" -- the reading resolved fine, so the tick
// question was the wrong one to ask. The branch taken is what matters.
func cycleProbeDecision(clock string, base, tick time.Duration) cycleProbeVerdict {
	if clock != "cpu" {
		return verdictWallDisclose
	}
	if _, sufficient := ticksAt(base, tick); !sufficient {
		return verdictTooFewTicks
	}
	return verdictAssertWindow
}

// TestTheCycleProbeDecisionAgainstRecordedCIReadings replays every reading this test has produced on
// every OS through the branch that now handles it.
//
// This exists because the machine that fixes a timing test is never the machine that broke it. This dev
// Mac runs these fixtures 3.6x faster than macos-latest and has a 1us CPU tick where windows-latest has
// 15.625ms, so it reproduces none of the failures. Every row below is quoted from a job that ran.
//
// Two rounds of failure are recorded here deliberately, because the second was caused by fixing the first:
//
//	round 1, pre-#645   windows chose the CPU clock, base = ONE 15.625ms tick, "2.00x" -> FAILED <2.5
//	round 2, post-#645  windows moved to the WALL clock, base = 24.2 ticks, "6.07x" -> FAILED >6.0
//
// #645 made the clock resolvable, so the tick gate correctly opened and the numeric window then ran
// against a contended wall-clock ratio. That is why the window is now CPU-clock-only and why this table
// asserts the BRANCH rather than the tick count.
func TestTheCycleProbeDecisionAgainstRecordedCIReadings(t *testing.T) {
	const (
		winCPUTickLocal = 15625 * time.Microsecond // measured, windows-latest
		macCPUTickLocal = 1 * time.Microsecond     // measured, macos-latest and darwin/arm64
	)

	cases := []struct {
		platform, job, fixture string
		clock                  string
		base, tick             time.Duration
		ratio                  float64
		want                   cycleProbeVerdict
		why                    string
	}{{
		platform: "windows-latest", job: "102647224117 (pre-#645)", fixture: "linear",
		clock: "cpu", base: 15625 * time.Microsecond, tick: winCPUTickLocal, ratio: 2.00,
		want: verdictTooFewTicks,
		why:  "ONE tick; 2.00x is 2 ticks over 1. Round-1 failure",
	}, {
		platform: "windows-latest", job: "102647224117 (pre-#645)", fixture: "quadratic",
		clock: "cpu", base: 46875 * time.Microsecond, tick: winCPUTickLocal, ratio: 16.00,
		want: verdictTooFewTicks,
		why:  "3 ticks; 16.00x is an exact 48/3. Passed by luck then, refused now",
	}, {
		platform: "windows-latest", job: "102704815935 (post-#645)", fixture: "linear",
		clock: "wall", base: 124688 * time.Microsecond / 10, tick: 5142 * time.Microsecond / 10, ratio: 6.07,
		want: verdictWallDisclose,
		why:  "24.2 ticks, amply resolvable — but a wall ratio bounds descheduling. ROUND-2 FAILURE",
	}, {
		platform: "windows-latest", job: "102704815935 (post-#645)", fixture: "quadratic",
		clock: "wall", base: 682999 * time.Microsecond / 10, tick: 5142 * time.Microsecond / 10, ratio: 13.69,
		want: verdictWallDisclose,
		why:  "13.69x against the old 10.0 floor was only 1.37x of margin, under this repo's 1.5x",
	}, {
		platform: "macos-latest", job: "102647366691", fixture: "linear",
		clock: "cpu", base: 12150 * time.Microsecond, tick: macCPUTickLocal, ratio: 4.57,
		want: verdictAssertWindow,
		why:  "12,150 ticks on the cpu clock; 4.57x is the worst cpu reading anywhere and sets the ceiling",
	}, {
		platform: "macos-latest", job: "102647366691", fixture: "quadratic",
		clock: "cpu", base: 60484 * time.Microsecond, tick: macCPUTickLocal, ratio: 15.36,
		want: verdictAssertWindow,
		why:  "60,484 ticks; 15.36x clears the 10.0 floor with 1.54x",
	}, {
		platform: "macos-latest", job: "102647271956", fixture: "quadratic",
		clock: "cpu", base: 57710 * time.Microsecond, tick: macCPUTickLocal, ratio: 15.97,
		want: verdictAssertWindow,
		why:  "the second macos failure, whose 72.78ms WALL base tripped the deleted 4x vacuity ceiling",
	}, {
		platform: "darwin/arm64 (dev)", job: "local, plain and -race", fixture: "linear",
		clock: "cpu", base: 8766 * time.Microsecond, tick: macCPUTickLocal, ratio: 4.02,
		want: verdictAssertWindow,
		why:  "the derivation machine must still assert, or the gate has gone vacuous everywhere",
	}, {
		platform: "darwin/arm64 (dev)", job: "local, plain and -race", fixture: "quadratic",
		clock: "cpu", base: 39018 * time.Microsecond, tick: macCPUTickLocal, ratio: 16.17,
		want: verdictAssertWindow,
		why:  "same, quadratic side",
	}}

	asserted := 0
	for _, c := range cases {
		got := cycleProbeDecision(c.clock, c.base, c.tick)
		if got != c.want {
			t.Errorf("%s %s (%s): decision = %q, want %q — %s",
				c.platform, c.fixture, c.job, got, c.want, c.why)
			continue
		}
		if got != verdictAssertWindow {
			continue // disclosed, not asserted: the ratio is not evidence on that branch
		}
		asserted++

		var failed bool
		switch c.fixture {
		case "linear":
			failed = c.ratio < 2.5 || c.ratio > linearMaxOnCPU
		case "quadratic":
			failed = c.ratio < 10.0
		}
		if failed {
			t.Errorf("%s %s (%s): %.2fx would FAIL the %s window on the cpu clock — %s",
				c.platform, c.fixture, c.job, c.ratio, c.fixture, c.why)
		}
	}

	// Non-vacuity in two directions. Every recorded reading disclosing would mean the windows assert on
	// no platform at all -- the failure #619 documents for the whole complexity guard.
	if asserted == 0 {
		t.Error("every recorded reading was DISCLOSED, so the numeric windows are asserted on no " +
			"platform and this table proves nothing")
	}
	if asserted == len(cases) {
		t.Error("every recorded reading was ASSERTED, including the windows wall-clock rows — the " +
			"cpu-clock restriction is not in effect and round-2 would repeat")
	}
}

// TestTheOrderingAssertionHoldsOnEveryRecordedPair covers the one assertion that still runs on the wall
// clock, and therefore on windows-latest.
//
// After the numeric windows became CPU-only, ordering plus the exact sink values are all that windows
// asserts. Ordering is a comparison of two readings from the same machine in the same run, which is the
// most contention-robust form available -- but it is not free, so its margin is checked rather than
// assumed.
func TestTheOrderingAssertionHoldsOnEveryRecordedPair(t *testing.T) {
	pairs := []struct {
		platform, clock string
		linear, quad    float64
	}{
		{"windows-latest (post-#645)", "wall", 6.07, 13.69},
		{"windows-latest (pre-#645)", "cpu", 2.00, 16.00},
		{"macos-latest", "cpu", 4.57, 15.36},
		{"darwin/arm64 (dev)", "cpu", 4.02, 16.17},
		{"darwin/arm64 (dev, -race)", "cpu", 4.41, 16.08},
	}

	worst := 999.0
	for _, p := range pairs {
		if p.quad <= p.linear {
			t.Errorf("%s (%s clock): quadratic %.2fx does not read above linear %.2fx — the two shapes "+
				"are indistinguishable and PROPERTY 4 is vacuous there", p.platform, p.clock, p.quad, p.linear)
			continue
		}
		if sep := p.quad / p.linear; sep < worst {
			worst = sep
		}
	}

	// 2.0x, against a worst observed separation of 2.26x on the contended windows wall clock. Stated as a
	// floor so a future change that narrows the shapes is visible here rather than as a red CI job.
	if worst < 2.0 {
		t.Errorf("the closest recorded shape separation is %.2fx, under the 2.0x this assertion needs to "+
			"stay meaningful under contention", worst)
	}
	t.Logf("worst recorded shape separation: %.2fx (windows wall clock)", worst)
}
