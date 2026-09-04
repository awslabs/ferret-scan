// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
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

// TestMeasureSeparatesLinearFromQuadratic is the reason this package exists, asserted directly.
//
// The wall-clock statistic it replaces failed at exactly this: under load it scored a genuine O(n^2)
// function at 9.94x and a linear one at 10.20x — inverted. If this test ever fails, the estimator has
// stopped discriminating and every guard built on it is decoration.
func TestMeasureSeparatesLinearFromQuadratic(t *testing.T) {
	const base = 4

	lin, err := Measure(DefaultPairs, func() { spin(base) }, func() { spin(4 * base) })
	if err != nil {
		t.Fatalf("linear: %v", err)
	}
	quad, err := Measure(DefaultPairs, func() { spin(base) }, func() { spin(16 * base) })
	if err != nil {
		t.Fatalf("quadratic: %v", err)
	}
	t.Logf("linear-shaped:    %s", lin)
	t.Logf("quadratic-shaped: %s", quad)

	if lin.Ratio > 8.0 {
		t.Errorf("a 4x workload measured %.2fx, which a bound of 8.0 would call quadratic", lin.Ratio)
	}
	if quad.Ratio < 8.0 {
		t.Errorf("a 16x workload measured %.2fx, which a bound of 8.0 would call linear — the "+
			"estimator is not discriminating", quad.Ratio)
	}
	if quad.Ratio <= lin.Ratio {
		t.Errorf("ORDERING INVERTED: linear %.2fx >= quadratic %.2fx. This is the exact failure the "+
			"wall-clock statistic had and the whole reason for this package", lin.Ratio, quad.Ratio)
	}
}

// TestTheRatioUsesMinimumsNotTheFirstReading pins the estimator's core choice.
//
// Contamination is one-signed — it only ever adds — so one deliberately slow reading must not move the
// result. A median would give that sample a vote; a minimum discards it.
func TestTheRatioUsesMinimumsNotTheFirstReading(t *testing.T) {
	const base = 4
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
	t.Logf("with one 8x-inflated base sample: %s", g)

	if g.Ratio < 2.0 {
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
	const base = 4
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
	t.Logf("with one 4x-inflated big sample: %s", g)

	if g.Ratio > 8.0 {
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

// TestATinyWorkloadFallsBackToWallClock covers the coarse-clock path.
//
// A workload far below MinMeasurableCPU cannot be divided on a clock that accumulates at tick
// granularity, so the estimator must fall back and SAY so rather than divide quantised readings.
//
// The fixture does real but tiny work rather than nothing at all. An empty function makes every
// reading zero on BOTH clocks, which Measure reports as an error — so the test would pass without the
// fallback ever being exercised, and a mutation that forces the CPU clock survived exactly that way.
func TestATinyWorkloadFallsBackToWallClock(t *testing.T) {
	tiny := func() {
		x := 0
		for i := 0; i < 200_000; i++ {
			x += i % 7
		}
		if x < 0 {
			panic("unreachable")
		}
	}
	g, err := Measure(DefaultPairs, tiny, tiny)
	if err != nil {
		t.Fatalf("a tiny but non-empty workload should still measure on the wall clock: %v", err)
	}
	if g.Clock != "wall" {
		t.Errorf("Clock = %q for a workload below MinMeasurableCPU (%v), want wall (base=%v)",
			g.Clock, MinMeasurableCPU, g.BaseMin)
	}
	if g.BaseWallMin <= 0 {
		t.Error("wall reading was zero, so the fallback clock is not measuring either")
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
