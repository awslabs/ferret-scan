// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// spin burns CPU for roughly the given number of units, without allocating.
//
// Deliberately not time.Sleep: this package measures CPU time, and a sleeping goroutine consumes none,
// so a sleep-based fixture would measure zero and every assertion here would pass vacuously.
func spin(units int) {
	x := 0
	for i := 0; i < units*2_000_000; i++ {
		x += i % 7
	}
	if x < 0 {
		panic("unreachable, keeps the loop from being optimised away")
	}
}

// historicalBaseUnits is the fixture size every ratio test in this file used when it was written, and
// the floor below which baseUnitsFor will not shrink one.
const historicalBaseUnits = 4

// baseUnitsFor sizes a base fixture so its reading spans at least MinTicks of the clock that will
// measure it. It is the difference between a ratio and a quotient of two small integers.
//
// A single constant cannot serve both platforms, which is why this is computed. Measured: 4 units costs
// ~3.9ms, which is ~3,900 ticks of darwin's 1µs CPU clock and 0.25 of ONE tick of windows-latest's
// 15.625ms CPU clock — ample by 494x on one platform and short by 32x on the other. That is what made
// TestTheRatioUsesMinimumsNotTheFirstReading fail on windows with "1.00x" from a base and a big that had
// both quantised onto the same single tick.
//
// Sized against the FINER of the two clocks, because clockForRatio will move to the wall clock when the
// CPU clock cannot resolve the workload. On windows that is the 722.7µs wall tick rather than the
// 15.625ms CPU tick, so MinTicks costs 5.78ms and this returns 6 units instead of 127.
//
// PURE, taking the measured costs as parameters, for the reason ticksAt and clockForRatio are: on darwin
// the floor is returned every time, so no local run exercises the arithmetic that matters.
func baseUnitsFor(cpuRes, wallRes, oneUnit time.Duration) int {
	// A failed tick probe or an unmeasurable unit cost gives nothing to compute from. Keep the fixture
	// the tests were written against rather than invent a size from a zero.
	if oneUnit <= 0 || cpuRes <= 0 || wallRes <= 0 {
		return historicalBaseUnits
	}
	finer := cpuRes
	if wallRes < finer {
		finer = wallRes
	}
	need := time.Duration(MinTicks) * finer
	// Round UP: a fraction of a spin unit buys no ticks, and under-sizing is the failure being fixed.
	units := int((need + oneUnit - 1) / oneUnit)
	if units < historicalBaseUnits {
		return historicalBaseUnits
	}
	return units
}

// calibratedBaseUnits measures what one spin unit costs on the machine running the test and sizes the
// base fixture from it.
//
// The minimum of several samples, not the first: contamination only ever adds, so a descheduled probe
// would over-state the unit cost and under-size the fixture — the one direction that reintroduces the
// bug. Under-stating it merely buys a slightly larger fixture, which is harmless.
func calibratedBaseUnits() int {
	oneUnit := time.Duration(0)
	for i := 0; i < 5; i++ {
		start := time.Now()
		spin(1)
		if d := time.Since(start); d > 0 && (oneUnit == 0 || d < oneUnit) {
			oneUnit = d
		}
	}
	cpuRes, wallRes := ClockResolution()
	return baseUnitsFor(cpuRes, wallRes, oneUnit)
}

// TestMeasureSeparatesLinearFromQuadratic is the reason this package exists, asserted directly.
//
// The wall-clock statistic it replaces failed at exactly this: under load it scored a genuine O(n^2)
// function at 9.94x and a linear one at 10.20x — inverted. If this test ever fails, the estimator has
// stopped discriminating and every guard built on it is decoration.
func TestMeasureSeparatesLinearFromQuadratic(t *testing.T) {
	base := calibratedBaseUnits()

	lin, err := Measure(DefaultPairs, func() { spin(base) }, func() { spin(4 * base) })
	if err != nil {
		t.Fatalf("linear: %v", err)
	}
	quad, err := Measure(DefaultPairs, func() { spin(base) }, func() { spin(16 * base) })
	if err != nil {
		t.Fatalf("quadratic: %v", err)
	}
	t.Logf("linear-shaped:    %s (%s)", lin, lin.ResolutionNote())
	t.Logf("quadratic-shaped: %s (%s)", quad, quad.ResolutionNote())

	// The gate this package defines, applied to this package's own tests. Without it these assertions
	// divide whatever the clock happened to report: on windows-latest both readings quantised onto a
	// single 15.625ms tick and the "ratio" was one integer over another. calibratedBaseUnits is what
	// should keep this branch untaken; it is here so that a fixture which drifts too cheap reports that
	// instead of failing on a number it never had the resolution to produce.
	if _, ok := lin.Ticks(); !ok {
		t.Logf("linear control NOT asserted — %s", lin.ResolutionNote())
	} else if lin.Ratio > 8.0 {
		t.Errorf("a 4x workload measured %.2fx, which a bound of 8.0 would call quadratic", lin.Ratio)
	}
	if _, ok := quad.Ticks(); !ok {
		t.Logf("quadratic control NOT asserted — %s", quad.ResolutionNote())
		return
	}
	if quad.Ratio < 8.0 {
		t.Errorf("a 16x workload measured %.2fx, which a bound of 8.0 would call linear — the "+
			"estimator is not discriminating", quad.Ratio)
	}
	// Compares the two measurements, so it needs BOTH to be resolvable, not just the quadratic one.
	if _, ok := lin.Ticks(); ok && quad.Ratio <= lin.Ratio {
		t.Errorf("ORDERING INVERTED: linear %.2fx >= quadratic %.2fx. This is the exact failure the "+
			"wall-clock statistic had and the whole reason for this package", lin.Ratio, quad.Ratio)
	}
}

// TestTheRatioUsesMinimumsNotTheFirstReading pins the estimator's core choice.
//
// Contamination is one-signed — it only ever adds — so one deliberately slow reading must not move the
// result. A median would give that sample a vote; a minimum discards it.
func TestTheRatioUsesMinimumsNotTheFirstReading(t *testing.T) {
	base := calibratedBaseUnits()
	calls := 0
	// The FIRST base reading pays 8x extra, standing in for a cold cache or a descheduled sample.
	g, err := Measure(4,
		func() {
			calls++
			if calls == 1 {
				spin(8 * base)
			} else {
				spin(base)
			}
		},
		func() { spin(4 * base) })
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	t.Logf("with one 8x-inflated base sample: %s (%s)", g, g.ResolutionNote())

	// This is the assertion that failed on windows-latest with "1.00x from [0.33x 3.00x 3.00x 3.00x]":
	// base and big had both quantised onto the same single 15.625ms CPU tick, so the minimum was working
	// perfectly and the clock simply could not show it.
	if _, ok := g.Ticks(); !ok {
		t.Logf("minimum-taking NOT asserted — %s", g.ResolutionNote())
	} else if g.Ratio < 2.0 {
		t.Errorf("ratio collapsed to %.2fx — the inflated first sample reached the result, so this is "+
			"not taking a minimum. Samples: %s", g.Ratio, FormatRatios(g.Samples))
	}
	if len(g.Samples) < 2 {
		t.Errorf("only %d samples recorded; a failure message needs the spread", len(g.Samples))
	}
}

// TestAnInflatedBigSampleDoesNotFakeAQuadratic is the base test's mirror, and it covers the direction
// that actually broke CI.
//
// Contamination on the BIG side pushes the ratio UP, which is a false O(n^2) report on correct code —
// #579, #509, #504 and #546 were all that failure. A minimum on the base alone does not prevent it;
// both sides have to discard their contaminated samples. A mutation that took bigs[0] instead of the
// minimum survived every other test in this file.
func TestAnInflatedBigSampleDoesNotFakeAQuadratic(t *testing.T) {
	base := calibratedBaseUnits()
	calls := 0
	g, err := Measure(4,
		func() { spin(base) },
		func() {
			calls++
			// The FIRST big reading pays 4x extra, standing in for a descheduled or GC-hit sample.
			if calls == 1 {
				spin(16 * base)
			} else {
				spin(4 * base)
			}
		})
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	t.Logf("with one 4x-inflated big sample: %s (%s)", g, g.ResolutionNote())

	// Quantisation COMPRESSES a ratio, so this direction is the safer of the two — but a 1-tick base can
	// still land anywhere, and an assertion that cannot fail is not evidence either way.
	if _, ok := g.Ticks(); !ok {
		t.Logf("contamination rejection NOT asserted — %s", g.ResolutionNote())
	} else if g.Ratio > 8.0 {
		t.Errorf("a linear workload measured %.2fx, over a bound of 8.0 — the contaminated big sample "+
			"reached the result, so this is a false quadratic report on correct code. Samples: %s",
			g.Ratio, FormatRatios(g.Samples))
	}
}

// TestGCIsRestoredAfterWithGCOff: leaving GC off would silently change every test that runs after.
func TestGCIsRestoredAfterWithGCOff(t *testing.T) {
	before := debug.SetGCPercent(-1)
	debug.SetGCPercent(before) // put it back before measuring anything

	var innerSawItOff bool
	WithGCOff(func() {
		cur := debug.SetGCPercent(-1)
		innerSawItOff = cur == -1
		debug.SetGCPercent(-1)
	})

	after := debug.SetGCPercent(before)
	if !innerSawItOff {
		t.Error("GC was not disabled inside WithGCOff, so the measurement includes collection cost")
	}
	if after != before {
		t.Errorf("GC percent is %d after WithGCOff, was %d before — every later test now runs under a "+
			"different collector setting", after, before)
	}
}

// TestTheClockIsAlwaysNamed: the wall fallback is exactly when a failure is least trustworthy, so a
// guard whose output does not say which clock produced the number cannot be diagnosed.
func TestTheClockIsAlwaysNamed(t *testing.T) {
	g, err := Measure(DefaultPairs, func() { spin(4) }, func() { spin(16) })
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if g.Clock != "cpu" && g.Clock != "wall" {
		t.Errorf("Clock = %q, want cpu or wall", g.Clock)
	}
	if s := g.String(); !strings.Contains(s, g.Clock) {
		t.Errorf("String() = %q, which does not name the clock", s)
	}
}

// TestATinyWorkloadDoesNotDivideAQuantisedCPUReading covers the coarse-clock path.
//
// A workload far below MinMeasurableCPU cannot be divided on a clock that accumulates at tick
// granularity, so the estimator must fall back to wall and SAY so, rather than divide two quantised
// readings and present the quotient as a growth ratio.
//
// # Why this asserts on the clock NAME and tolerates an error
//
// The first version of this test required the measurement to SUCCEED on the wall clock, on the
// reasoning that a tiny-but-non-empty workload is always measurable there. That is false, and it
// broke the build on windows-latest -- deterministically, in two consecutive runs:
//
//	perfguard_test.go:182: a tiny but non-empty workload should still measure on the wall clock:
//	                       perfguard: every base reading was zero on the wall clock
//
// A ~90us workload reads ZERO on BOTH clocks there. Windows accumulates process CPU time at timer-tick
// granularity, and the runners' wall clock is coarse enough that sub-millisecond work rounds to nothing
// as well. So on Windows the window this test was aiming at -- "long enough to measure on the wall
// clock, short enough to be under MinMeasurableCPU" -- can be EMPTY, because the wall granularity is
// not necessarily finer than the 2ms threshold. No choice of iteration count fixes that; the premise
// itself was platform-dependent.
//
// What is actually being asserted is the FALLBACK DECISION, and that decision is made before either
// outcome is known. So both of these are correct behaviour:
//
//	the workload is measurable on wall  -> Growth.Clock == "wall"
//	it is measurable on neither clock   -> an error that names the WALL clock
//
// and exactly one thing is a defect: reporting or erroring on the CPU clock, which would mean a
// quantised reading was about to be divided. Asserting on the name in both branches keeps the test
// non-vacuous -- verified by mutation, forcing useCPU true still fails it, because the error then
// names "cpu" -- while making it independent of any platform's clock resolution.
func TestATinyWorkloadDoesNotDivideAQuantisedCPUReading(t *testing.T) {
	tiny := func() {
		x := 0
		for i := 0; i < 200_000; i++ {
			x += i % 7
		}
		if x < 0 {
			panic("unreachable, keeps the loop from being optimised away")
		}
	}

	g, err := Measure(DefaultPairs, tiny, tiny)
	if err != nil {
		// Measurable on neither clock, which a coarse-clock platform is entitled to report. The
		// error still has to say the estimator had FALLEN BACK, or the CPU clock was chosen for a
		// reading too small to divide.
		if strings.Contains(err.Error(), "cpu") {
			t.Errorf("a workload below MinMeasurableCPU (%v) was measured on the CPU clock: %v. The "+
				"fallback did not happen, so a quantised reading would have been divided", MinMeasurableCPU, err)
		}
		if !strings.Contains(err.Error(), "wall") {
			t.Errorf("error names no clock, so a failure here cannot be diagnosed: %v", err)
		}
		t.Logf("both clocks too coarse for this workload; correctly refused on the wall clock: %v", err)
		return
	}

	if g.Clock != "wall" {
		t.Errorf("Clock = %q for a workload below MinMeasurableCPU (%v), want wall (base=%v). Dividing "+
			"two tick-quantised CPU readings produces a ratio that is an artefact of the clock",
			g.Clock, MinMeasurableCPU, g.BaseMin)
	}
	if g.BaseWallMin <= 0 {
		t.Error("reported success with a zero wall reading; the ratio cannot mean anything")
	}
}

// TestProcessCPUTimeAdvancesWithWork is the non-vacuity floor for the whole package: if the clock does
// not move, every ratio above is measuring nothing.
func TestProcessCPUTimeAdvancesWithWork(t *testing.T) {
	before, err := ProcessCPUTime()
	if err != nil {
		t.Fatalf("ProcessCPUTime: %v", err)
	}
	spin(20)
	after, err := ProcessCPUTime()
	if err != nil {
		t.Fatalf("ProcessCPUTime: %v", err)
	}
	if d := after - before; d <= 0 {
		t.Fatalf("CPU clock did not advance across measurable work (delta %v); every measurement in "+
			"this package is vacuous on this platform", d)
	} else {
		t.Logf("CPU clock advanced %v across the fixture", d)
	}
}

// TestClockGranularityIsReportedAndCPUTimeIsMonotonic measures each platform's actual clock
// granularity instead of assuming it, and pins the one invariant ProcessCPUTime must have.
//
// This exists because a granularity ASSUMPTION in this package's own doc comment went unchecked and
// then broke the build on windows-latest. MinMeasurableCPU is 2ms, while the comment above it says
// Windows accumulates at "15.6ms by default" -- so if that figure is right, a Windows reading between
// 2ms and 15.6ms CLEARS the gate while still being a single quantised tick, and is divided anyway.
// Nobody had measured which it is, on any platform.
//
// Granularity is measured by POLLING THE CLOCK IN A TIGHT LOOP until it changes, and taking the
// smallest non-zero increment. That measures the CLOCK. An earlier version timed workloads of
// increasing size and took the smallest non-zero delta, which measures the smallest WORKLOAD instead
// -- it reported 866us with one set of fixtures and 1.912ms with another, on the same machine, which
// is how you can tell it was not measuring the clock at all.
//
// The granularity is logged rather than asserted, because the right threshold is a judgement about
// the machine and not something this test can decide. But the number now arrives free with every CI
// run on all three platforms, so #596 can be settled from a log instead of a guess.
//
// The ASSERTION here is MONOTONICITY, which is not a judgement call: process CPU time accumulates, so
// a later reading can never be smaller than an earlier one. If it ever is, every delta in this package
// is untrustworthy -- and a ratio of MINIMUMS would preferentially select the corrupted sample,
// precisely because a corrupted sample is the smallest one.
func TestClockGranularityIsReportedAndCPUTimeIsMonotonic(t *testing.T) {
	// cpuTick polls ProcessCPUTime in a tight CPU-burning loop until the value changes, and returns
	// the increment. Burning CPU is required: the clock only advances while this process runs, so a
	// sleeping poll would spin forever on a coarse clock.
	cpuTick := func() (time.Duration, error) {
		start, err := ProcessCPUTime()
		if err != nil {
			return 0, err
		}
		last := start
		x := 0
		for i := 0; i < 200_000_000; i++ {
			x += i % 7
			if i%512 != 0 {
				continue
			}
			now, err := ProcessCPUTime()
			if err != nil {
				return 0, err
			}
			// MONOTONICITY, checked on every one of these reads rather than once at the end.
			if now < last {
				return 0, fmt.Errorf("ProcessCPUTime went BACKWARDS: %v then %v", last, now)
			}
			last = now
			if now > start {
				return now - start, nil
			}
		}
		if x < 0 {
			panic("unreachable")
		}
		return 0, fmt.Errorf("clock did not advance in 200M iterations")
	}

	wallTick := func() time.Duration {
		start := time.Now()
		for {
			if d := time.Since(start); d > 0 {
				return d
			}
		}
	}

	// Smallest increment over a few attempts: one tick, by definition.
	var cpuGran, wallGran time.Duration
	for i := 0; i < 5; i++ {
		d, err := cpuTick()
		if err != nil {
			t.Fatalf("measuring cpu granularity: %v. Every delta this package computes is now "+
				"untrustworthy, and a ratio of minimums would preferentially select the corrupted sample", err)
		}
		if cpuGran == 0 || d < cpuGran {
			cpuGran = d
		}
		if w := wallTick(); wallGran == 0 || w < wallGran {
			wallGran = w
		}
	}

	t.Logf("clock granularity on %s/%s: cpu=%v wall=%v", runtime.GOOS, runtime.GOARCH, cpuGran, wallGran)
	// The number that matters is how many TICKS the gate is worth. Many ticks means a reading that
	// clears MinMeasurableCPU carries real resolution; a handful means the ratio is mostly clock.
	ticks := float64(MinMeasurableCPU) / float64(cpuGran)
	t.Logf("MinMeasurableCPU (%v) is %.0f cpu ticks on this platform", MinMeasurableCPU, ticks)
	if ticks < 10 {
		t.Logf("NOTE: the gate is worth fewer than 10 ticks here, so a reading it admits is coarsely " +
			"quantised and the ratio built from it is substantially an artefact of the clock. " +
			"MinMeasurableCPU may need to be platform-dependent — see #596.")
	}

	// Non-vacuity: a zero granularity means the loop never observed the clock move.
	if cpuGran <= 0 || wallGran <= 0 {
		t.Errorf("granularity measured as cpu=%v wall=%v; a non-positive tick means nothing was "+
			"observed and the granularity figures above are meaningless", cpuGran, wallGran)
	}

	// MONOTONICITY, over a LONG ENOUGH SPAN to be worth asserting.
	//
	// The granularity loop above exits after a single tick -- a microsecond on this platform -- so a
	// clock that advances correctly for a while and then jumps backwards would never be seen by it.
	// Verified: a mutant returning (user+sys) %% 3ms, which wraps to zero every 3ms of CPU, SURVIVED
	// the short check and is caught only here. So this deliberately burns tens of milliseconds of CPU
	// and reads the clock throughout.
	var samples int
	last, err := ProcessCPUTime()
	if err != nil {
		t.Fatalf("ProcessCPUTime: %v", err)
	}
	start := last
	x := 0
	for i := 0; i < 400_000_000 && last-start < 60*time.Millisecond; i++ {
		x += i % 7
		if i%4096 != 0 {
			continue
		}
		now, err := ProcessCPUTime()
		if err != nil {
			t.Fatalf("ProcessCPUTime: %v", err)
		}
		samples++
		if now < last {
			t.Fatalf("ProcessCPUTime went BACKWARDS after %v of CPU: %v then %v (a drop of %v). Every "+
				"delta this package computes is untrustworthy, and a ratio of MINIMUMS would "+
				"preferentially select the corrupted sample because it is the smallest",
				last-start, last, now, last-now)
		}
		last = now
	}
	if x < 0 {
		panic("unreachable, keeps the loop from being optimised away")
	}

	// Non-vacuity for the monotonicity check itself: it must have compared many real readings across a
	// meaningful span, or a backwards jump could simply have been missed.
	span := last - start
	t.Logf("monotonicity: %d readings over %v of CPU, never decreasing", samples, span)
	if samples < 100 || span < 10*time.Millisecond {
		t.Errorf("only %d readings over %v of CPU; too short to have observed a backwards jump, so this "+
			"assertion proves little", samples, span)
	}
}

// TestAssertNoParallelTestsFindsAPlantedCall proves the invariant guard is not decoration.
func TestAssertNoParallelTestsFindsAPlantedCall(t *testing.T) {
	dir := t.TempDir()
	clean := "package x\n\nfunc TestA(t *testing.T) {}\n"
	for i, body := range []string{clean, clean, clean, clean, clean} {
		if err := os.WriteFile(filepath.Join(dir, "a"+string(rune('a'+i))+"_test.go"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	offenders, scanned, err := AssertNoParallelTests(dir)
	if err != nil {
		t.Fatalf("AssertNoParallelTests: %v", err)
	}
	if scanned != 5 {
		t.Errorf("scanned %d files, want 5", scanned)
	}
	if len(offenders) != 0 {
		t.Errorf("clean tree reported %v", offenders)
	}

	// Assembled so this source file does not contain the literal, exactly as the checker does.
	planted := "package x\n\nfunc TestB(t *testing.T) {\n\tt.Paralle" + "l()\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "bad_test.go"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	offenders, _, err = AssertNoParallelTests(dir)
	if err != nil {
		t.Fatalf("AssertNoParallelTests: %v", err)
	}
	if len(offenders) != 1 || !strings.HasPrefix(offenders[0], "bad_test.go:") {
		t.Errorf("planted call not found; got %v", offenders)
	}

	// A commented-out call is not a call.
	commented := "package x\n\n// t.Paralle" + "l() would break the measurement\nfunc TestC(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "cmt_test.go"), []byte(commented), 0o600); err != nil {
		t.Fatal(err)
	}
	offenders, _, err = AssertNoParallelTests(dir)
	if err != nil {
		t.Fatalf("AssertNoParallelTests: %v", err)
	}
	if len(offenders) != 1 {
		t.Errorf("a commented-out call was counted; got %v", offenders)
	}
}

// TestThisPackageRunsSequentially applies the guard to perfguard itself.
func TestThisPackageRunsSequentially(t *testing.T) {
	offenders, scanned, err := AssertNoParallelTests(".")
	if err != nil {
		t.Fatalf("AssertNoParallelTests: %v", err)
	}
	if scanned == 0 {
		t.Fatal("scanned no test files; the check is not reading this package")
	}
	if len(offenders) > 0 {
		t.Errorf("t.Parallel at %s — ProcessCPUTime is process-wide, so a concurrent test is charged "+
			"to whatever is being measured: 28 busy goroutines inflated a base reading 4.374ms to "+
			"39.559ms and turned a 4.07x scan into 11.62x", strings.Join(offenders, ", "))
	}
}
