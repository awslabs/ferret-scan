// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package perfguard measures how a function's cost grows with its input, for complexity guards.
//
// It exists because a wall-clock ratio is not a measure of algorithmic complexity on a shared CI
// runner, and this repository has now paid for that four separate times.
//
// # Why not wall clock
//
// Measured under 28 external busy-loop processes on 14 CPUs with -race (#579, #581):
//
//	quadratic median  9.94x
//	linear median    10.20x   <- HIGHER than the quadratic
//	separation        0.98x
//
// The populations did not merely overlap, they INVERTED, and at 10.20x the linear reading sat above
// the guard's own threshold — so the guard could fail on correct code and pass a real regression in
// the same configuration. No choice of threshold fixes a statistic whose ordering is wrong, which is
// why #509, #504, #546 and #568 each retuned the same test without settling it.
//
// Three candidate fixes were measured and rejected before this one:
//
//	fitting an exponent over >=3 sizes   degrades with the ratio, 1.970 idle -> 1.656 loaded
//	enlarging the base reading           WORSE: the largest size gave the LOWEST median
//	normalising against a linear control separation 0.98x
//	runtime/metrics CPU classes          9 of 9 zero-delta; 2.18x where ~16x was expected
//
// # The three properties that make this work
//
//  1. CPU TIME, not wall clock. Contention steals wall time without changing cycle count, and
//     getrusage(RUSAGE_SELF) excludes other processes — `go test` runs one binary per package, so
//     the packages competing for a runner are separate processes and do not enter the reading.
//
//  2. GC DISABLED across the measured region. GC is real CPU work that scales with heap, so it
//     survives the change of clock: an ALLOCATING linear function read 10.04x with GC on and 3.95x
//     with it off. Production code allocates and cannot be rewritten to avoid it, so the
//     measurement excludes GC rather than the code avoiding allocation.
//
//  3. A ratio of MINIMUMS, not a median. Contamination is strictly one-signed — it only ever adds —
//     so the minimum cannot overshoot the true cost and converges fast: the minimum base reading was
//     3.727ms under load against 3.703ms idle, a 0.6% difference, where the median of ratios moved
//     9% and its worst sample halved.
//
// # The assumption this rests on
//
// RUSAGE_SELF is process-wide, so a reading is only about the function under test while nothing else
// in the process burns CPU concurrently. Two facts make that true: `go test` builds one binary per
// package, and tests within a package run sequentially unless they call t.Parallel. The second is
// fragile, so AssertNoParallelTests exists to pin it — measured, 28 busy GOROUTINES inflated a base
// reading 4.374ms -> 39.559ms and turned a 4.07x linear scan into 11.62x.
package perfguard

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"time"
)

// MinMeasurableCPU is the floor for CHOOSING THE CLOCK, and no longer the gate on whether a ratio
// means anything. Growth.Ticks and MinTicks are that gate — see resolution.go.
//
// getrusage reports microseconds and GetProcessTimes 100ns ticks, but both accumulate at timer-tick
// granularity. The "15.6ms on Windows" this comment used to assert without evidence is now MEASURED
// and exact: windows-latest advances the CPU clock in steps of 15.625ms, so every reading there is an
// integer multiple of it (15.625, 31.25, 46.875, 78.125, 93.75, 125, 140.625, 156.25, 234.375,
// 546.875 all observed in one run).
//
// Which makes the problem with this constant plain: 2ms is 0.128 of a SINGLE TICK on that platform,
// so it admitted 1-tick readings and divided them. The complexity guard's Windows output was
// therefore a ratio of small integers — a linear control reported "2.00x" from 2 ticks over 1.
//
// It is kept because it still answers a different and narrower question: below it a CPU reading is
// certainly useless, so the wall clock is worth trying instead. Whether the reading that survives is
// worth DIVIDING is decided by tick count, not by this.
const MinMeasurableCPU = 2 * time.Millisecond

// DefaultPairs is how many base/big pairs Growth measures.
//
// 2, chosen against measured stability rather than guessed. Minimums converge fast because
// contamination only ever adds, so the marginal sample buys little while each costs a full big
// reading. On the 18-target complexity guard: 1 pair 22.4s, 2 pairs 45.8s with a worst correct-code
// reading of 4.60x, 3 pairs 69.8s at 4.54x. Going from 2 to 3 moves the worst reading by 0.06x for
// another 24 seconds. Two is still strictly more than one bad sample can defeat.
const DefaultPairs = 2

// Reading is one timed call.
//
// Both clocks are kept because a guard usually needs both: an absolute ceiling is a claim about how
// long a user waits, which is wall clock by definition, while a growth ratio is a claim about
// algorithmic complexity, which wall clock cannot carry on a contended machine.
type Reading struct {
	Wall time.Duration
	CPU  time.Duration
}

// Growth is the result of comparing a base and a larger input.
type Growth struct {
	// Ratio is BigMin/BaseMin on the chosen clock.
	Ratio float64

	BaseMin, BigMin         time.Duration
	BaseWallMin, BigWallMin time.Duration

	// Clock is "cpu" or "wall". Report it: a guard whose output does not name the clock cannot be
	// diagnosed when it fails, and the wall fallback is exactly when a failure is least trustworthy.
	Clock string

	// Samples is the per-pair ratio for every pair measured, so a failure message can show the
	// spread rather than one number.
	Samples []float64
}

// Time runs fn once and returns both clocks.
//
// GC is NOT disabled here. It is disabled by WithGCOff across a whole group of readings, because
// SetGCPercent triggers a collection when it restores and paying that between a base and a big
// reading would land inside the interval being measured.
func Time(fn func()) (Reading, error) {
	before, err := ProcessCPUTime()
	if err != nil {
		return Reading{}, fmt.Errorf("perfguard: reading CPU time: %w", err)
	}
	start := time.Now()
	fn()
	wall := time.Since(start)
	after, err := ProcessCPUTime()
	if err != nil {
		return Reading{}, fmt.Errorf("perfguard: reading CPU time: %w", err)
	}
	return Reading{Wall: wall, CPU: after - before}, nil
}

// WithGCOff runs fn with the garbage collector disabled, then restores it and forces a collection.
//
// The collection on the way out is not tidiness: the heap that accumulated while GC was off would
// otherwise be carried into whatever runs next, which on a guard iterating many targets turns a
// bounded measurement into growing memory pressure.
func WithGCOff(fn func()) {
	previous := debug.SetGCPercent(-1)
	defer func() {
		debug.SetGCPercent(previous)
		runtime.GC()
	}()
	fn()
}

// Measure runs base and big pairs times and returns the ratio of their minimum readings.
//
// There is deliberately no trigger-then-confirm split. Taking ONE pair and re-measuring only when it
// exceeds a threshold is a false-negative hole: a genuine quadratic whose single reading was
// contaminated down to 7.17x never entered confirmation and the guard passed it. Measuring the same
// way every time costs a few seconds and removes that.
//
// Measured with -race, quadratic against linear synthetics, idle and under 28 busy-loops:
//
//	                     median of ratios          ratio of minimums
//	quadratic, idle      13.66x (13.05-14.17)      14.17x
//	quadratic, loaded    12.48x ( 7.24-15.19)      14.00x
//	linear, idle          3.65x ( 2.41- 4.11)       3.75x
//	linear, loaded        2.92x ( 1.67- 3.73)       3.18x
//
// The ratio of minimums moves 1.2% between idle and loaded on the quadratic, where the median of
// ratios moves 9% and its worst sample halves. That gap is what makes a single threshold viable.
//
// Both sides take a minimum, not just the base. Contamination on the BASE inflates it and drives the
// ratio DOWN toward a false pass; contamination on the BIG side drives it UP into a false O(n^2)
// report on correct code, which is what #509, #504, #546 and #579 actually were.
//
// A cold reading needs no separate warm-up, because a minimum discards it for free: a first-touch
// cost that inflates a sample makes it the maximum, not the minimum. The wall-clock version of this
// needed an explicit warm-up only because a median gives the cold sample a vote.
func Measure(pairs int, base, big func()) (Growth, error) {
	if pairs < 1 {
		pairs = DefaultPairs
	}

	bases := make([]Reading, 0, pairs)
	bigs := make([]Reading, 0, pairs)
	var err error
	WithGCOff(func() {
		for i := 0; i < pairs; i++ {
			var b, g Reading
			if b, err = Time(base); err != nil {
				return
			}
			if g, err = Time(big); err != nil {
				return
			}
			bases = append(bases, b)
			bigs = append(bigs, g)
		}
	})
	if err != nil {
		return Growth{}, err
	}

	// Choose the clock from EVERY base reading, not one: a single unlucky sample below the
	// granularity would otherwise decide the clock for the whole measurement.
	useCPU := true
	for _, b := range bases {
		if b.CPU < MinMeasurableCPU {
			useCPU = false
			break
		}
	}
	pick := func(r Reading) time.Duration {
		if useCPU {
			return r.CPU
		}
		return r.Wall
	}

	g := Growth{Clock: "wall"}
	if useCPU {
		g.Clock = "cpu"
	}
	g.BaseMin, g.BigMin = pick(bases[0]), pick(bigs[0])
	g.BaseWallMin, g.BigWallMin = bases[0].Wall, bigs[0].Wall
	for i := range bases {
		if d := pick(bases[i]); d < g.BaseMin {
			g.BaseMin = d
		}
		if d := pick(bigs[i]); d < g.BigMin {
			g.BigMin = d
		}
		if bases[i].Wall < g.BaseWallMin {
			g.BaseWallMin = bases[i].Wall
		}
		if bigs[i].Wall < g.BigWallMin {
			g.BigWallMin = bigs[i].Wall
		}
		if db := pick(bases[i]); db > 0 {
			g.Samples = append(g.Samples, float64(pick(bigs[i]))/float64(db))
		}
	}
	if g.BaseMin <= 0 {
		return Growth{}, fmt.Errorf("perfguard: every base reading was zero on the %s clock", g.Clock)
	}
	g.Ratio = float64(g.BigMin) / float64(g.BaseMin)
	return g, nil
}

// String renders a Growth for a log or a failure message, naming the clock.
func (g Growth) String() string {
	return fmt.Sprintf("%.2fx on the %s clock (min base=%v big=%v over %d pairs %s)",
		g.Ratio, g.Clock, g.BaseMin, g.BigMin, len(g.Samples), FormatRatios(g.Samples))
}

// FormatRatios renders per-pair ratios at the precision that matters for a failure message.
func FormatRatios(rs []float64) string {
	if len(rs) == 0 {
		return "[]"
	}
	out := "["
	for i, r := range rs {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%.2fx", r)
	}
	return out + "]"
}
