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
// 4, from 22 CI runs of #649's instrumentation (go-test.yml runs 35916152576 to 37529169889,
// 2026-09-23 to 2026-10-06, every one on the same macos-26-arm64 image, so the comparison is not
// confounded by an image change). It was 2, chosen on a developer machine where the worst correct
// reading moved 0.06x from 2 pairs to 3 — true there, and the wrong population: a stable machine is
// exactly the one where more samples buy nothing. macos-latest is not stable. Its readings are
// inflated in bursts, and in both headline readings below BOTH samples of one side were inflated
// together — both bigs for the linear 7.99x, both bases for the quadratic 9.72x — so a 2-sample
// minimum had no clean reading to pick. Across the 22 runs, worst reading on macos-latest, against
// the 8.0 bound (margin in brackets, rule ≥1.5x):
//
//	                                  2 pairs         4 pairs
//	linear control, max               7.99x (1.00x)   4.68x (1.71x)
//	genuine quadratic, min            9.72x (1.22x)   14.90x (1.86x)
//	18 correct validators, max        7.06x (1.13x)   (first measured by this change)
//
// ubuntu-latest and windows-latest barely move (linear max 4.19x and 4.68x at either count), which
// is the signature of runner instability rather than an estimator defect: more pairs fix the
// unstable runner and cost nothing on the stable ones. #731's first reading was "the spread persists
// at 4 pairs, so more pairs is refuted". The 22 runs confirm the first half and refute the second:
// spread is max/min, a range, and widens with samples (2.29x worst at 2 pairs, 2.99x at 4), while
// the minimum — which is what Ratio uses — still improves.
//
// The cost is small because the fixtures are: the whole complexity step took 9-16s per runner at
// 2 pairs. ReportMargin reports every asserted reading's margin from here on, so if 4 stops being
// enough it says so before a build goes red.
const DefaultPairs = 4

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

	// BaseReadings and BigReadings are every raw per-pair reading on the chosen clock, in
	// measurement order. Ratio, the minima and Samples can all be derived from them; they are
	// carried anyway because #649's diagnosis needed the BASE SPREAD (max/min across pairs) and
	// had to reconstruct it by arithmetic from a log line: macos-latest's linear control read
	// 6.40x not because either side was slow but because its two base readings were 1.7x apart
	// while its big readings agreed within 3%. A spread that has to be reverse-engineered from a
	// ratio is evidence nobody collects; these fields make it a log line.
	BaseReadings, BigReadings []time.Duration
}

// BaseSpread and BigSpread report max/min across the per-pair readings of one side — 1.0 means
// perfectly repeatable samples. The spread is the statistic that distinguishes "this runner is
// slow" (both sides scale, ratio unaffected) from "this runner is UNSTABLE" (one side scatters,
// ratio is an artefact of which sample the minimum picked). Zero-valued readings return 0 rather
// than dividing by zero; the caller's resolution gate already refuses those measurements.
func (g Growth) BaseSpread() float64 { return spread(g.BaseReadings) }
func (g Growth) BigSpread() float64  { return spread(g.BigReadings) }

func spread(rs []time.Duration) float64 {
	if len(rs) == 0 {
		return 0
	}
	lo, hi := rs[0], rs[0]
	for _, r := range rs[1:] {
		if r < lo {
			lo = r
		}
		if r > hi {
			hi = r
		}
	}
	if lo <= 0 {
		return 0
	}
	return float64(hi) / float64(lo)
}

// FormatDurations renders raw per-pair readings for a log line.
func FormatDurations(rs []time.Duration) string {
	if len(rs) == 0 {
		return "[]"
	}
	out := "["
	for i, r := range rs {
		if i > 0 {
			out += " "
		}
		out += r.String()
	}
	return out + "]"
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
			// Collect BETWEEN readings, never inside one.
			//
			// GC stays disabled for the duration of every timed call, which is the property #581
			// established: an ALLOCATING linear validator read 10.04x with GC on and 3.95x with it off,
			// because collection cost scales with heap and so hits the big reading harder. Nothing here
			// changes that -- runtime.GC() is called only in the gaps, where nothing is being measured.
			//
			// What it fixes is unbounded growth ACROSS readings. With GC off for the whole loop, the
			// Matches from all 2*pairs calls stayed reachable at once, and that killed CI: measured on
			// ubuntu-latest, goldencorpus.test grew 1.2GB -> 14.4GB in 45 seconds, exhausted 16GB of RAM
			// and all 3GB of swap, and the runner was SIGTERM'd mid-suite. One target, socialmedia,
			// accounted for 4.0GB of the 4.6GB local peak on its own -- 4,800 matches per big reading,
			// four readings, every Match race-instrumented. Its fixture cannot shrink: both sizes must
			// stay above maxClusterMatches (1000) or the two sizes measure different code paths, and its
			// non-vacuity floor needs 1,100 matches.
			//
			// So the peak is now ONE reading's working set rather than four, at the cost of a collection
			// in each gap, which nothing times.
			runtime.GC()
			if g, err = Time(big); err != nil {
				return
			}
			runtime.GC()
			bases = append(bases, b)
			bigs = append(bigs, g)
		}
	})
	if err != nil {
		return Growth{}, err
	}

	// Choose the clock from EVERY base reading, not one: a single unlucky sample below the
	// granularity would otherwise decide the clock for the whole measurement.
	cpuMeasurable := true
	for _, b := range bases {
		if b.CPU < MinMeasurableCPU {
			cpuMeasurable = false
			break
		}
	}

	// Both clocks' base minima have to be known BEFORE the clock can be chosen, because the choice
	// depends on whether each clock can RESOLVE this workload and not merely on a fixed floor. These
	// are the same minima taken below; computing them here costs nothing and keeps clockForRatio pure.
	minBaseCPU, minBaseWall := bases[0].CPU, bases[0].Wall
	for _, b := range bases[1:] {
		if b.CPU < minBaseCPU {
			minBaseCPU = b.CPU
		}
		if b.Wall < minBaseWall {
			minBaseWall = b.Wall
		}
	}
	cpuRes, wallRes := ClockResolution()
	useCPU := clockForRatio(minBaseCPU, minBaseWall, cpuRes, wallRes, cpuMeasurable) == "cpu"
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
		g.BaseReadings = append(g.BaseReadings, pick(bases[i]))
		g.BigReadings = append(g.BigReadings, pick(bigs[i]))
	}
	if g.BaseMin <= 0 {
		// One zero sample is enough: the minimum is then zero, and a ratio over it is meaningless. A
		// zero means the clock did not advance across the call, not that the call took no time.
		return Growth{}, fmt.Errorf("perfguard: a base reading was zero on the %s clock — it did not resolve this workload", g.Clock)
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
