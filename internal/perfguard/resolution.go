// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"fmt"
	"sync"
	"time"
)

// MinTicks is how many clock ticks a base reading must span before a ratio built on it means
// anything.
//
// A ratio of two quantised readings is a ratio of small integers, not a measurement. Measured on
// windows-latest, where the CPU clock advances 15.625ms at a time, the complexity guard produced
// exactly that:
//
//	linear control  base=15.625ms  big=31.25ms     ->  1 tick / 2 ticks   reported as "2.00x"
//	ssn             base=46.875ms  big=234.375ms   ->  3 ticks / 15 ticks reported as "5.00x"
//
// Those are not measurements of code. Both numbers are integer tick counts, and every other Windows
// reading in the same run was an exact multiple of 15.625ms too (78.125, 93.75, 125, 140.625,
// 156.25, 546.875). The guard was comparing tick counts against a threshold of 8.0.
//
// 8 ticks, so one tick of quantisation on each side moves the ratio by at most ~1/8. The
// alternatives were considered against the numbers rather than picked: at 2 ticks a single tick of
// error is 50% and the 4x-versus-16x decision is coin-flipping; at 32 ticks a Windows base would
// have to run half a second and every fixture in the repo would need resizing. 8 keeps the
// quantisation error well under the 1.5x margin this repo asks of a guard.
const MinTicks = 8

var (
	tickOnce sync.Once
	cpuTick  time.Duration
	wallTick time.Duration
)

// ClockResolution returns the measured granularity of each clock: the smallest non-zero increment
// the clock will report.
//
// Measured by POLLING IN A TIGHT LOOP until the value changes, which measures the CLOCK. Timing a
// small workload instead measures the WORKLOAD -- that mistake reported 866µs and then 1.912ms on
// the same machine depending on the fixture, which is how it was caught.
//
// Measured once per process and cached: the tick is a property of the platform, and the CPU probe
// has to burn real CPU to make the clock advance at all.
func ClockResolution() (cpu, wall time.Duration) {
	tickOnce.Do(func() {
		cpuTick, wallTick = measureTicks()
	})
	return cpuTick, wallTick
}

func measureTicks() (cpu, wall time.Duration) {
	// Smallest increment over a few attempts. Burning CPU is required for the CPU clock: it only
	// advances while this process runs, so a sleeping poll would spin forever on a coarse clock.
	for i := 0; i < 3; i++ {
		if d, ok := oneCPUTick(); ok && (cpu == 0 || d < cpu) {
			cpu = d
		}
		if d := oneWallTick(); wall == 0 || d < wall {
			wall = d
		}
	}
	return cpu, wall
}

func oneCPUTick() (time.Duration, bool) {
	start, err := ProcessCPUTime()
	if err != nil {
		return 0, false
	}
	x := 0
	for i := 0; i < 400_000_000; i++ {
		x += i % 7
		if i%512 != 0 {
			continue
		}
		now, err := ProcessCPUTime()
		if err != nil {
			return 0, false
		}
		if now > start {
			return now - start, true
		}
	}
	if x < 0 {
		panic("unreachable, keeps the loop from being optimised away")
	}
	return 0, false
}

func oneWallTick() time.Duration {
	start := time.Now()
	for {
		if d := time.Since(start); d > 0 {
			return d
		}
	}
}

// Ticks reports how many ticks of the chosen clock the base reading spans, and whether that is
// enough for the ratio to mean anything.
//
// This is what a guard should consult before asserting on Growth.Ratio. It is deliberately a
// QUESTION the caller asks rather than an error Measure returns: a caller may legitimately want the
// absolute wall readings (an "is it slow for a user" ceiling) even where the growth ratio is
// unusable, and conflating the two would throw away a measurement that is still valid.
func (g Growth) Ticks() (n float64, sufficient bool) {
	return ticksAt(g.BaseMin, g.resolution())
}

// resolution returns the measured granularity of whichever clock this Growth used.
func (g Growth) resolution() time.Duration {
	cpu, wall := ClockResolution()
	if g.Clock == "wall" {
		return wall
	}
	return cpu
}

// ticksAt is the decision, separated from the measurement so it can be tested against another
// platform's numbers.
//
// It exists because the first version of this test computed the tick count with its own arithmetic and
// compared that to MinTicks — so it verified the test's arithmetic and not this function, and a mutant
// making Ticks always report "sufficient" SURVIVED it. Taking the resolution as a parameter is what
// lets the real decision be exercised with windows-latest's 15.625ms tick from a darwin host.
func ticksAt(base, res time.Duration) (n float64, sufficient bool) {
	// res can be zero if tick measurement failed; base can be zero on a clock too coarse for the
	// workload. Dividing in either case yields +Inf or NaN, and `NaN >= MinTicks` is false while
	// `+Inf >= MinTicks` is TRUE — which would report a completely unmeasurable reading as ample.
	if res <= 0 || base <= 0 {
		return 0, false
	}
	n = float64(base) / float64(res)
	return n, n >= MinTicks
}

// ResolutionNote renders why a ratio is or is not trustworthy, for a log line or a failure message.
//
// Always includes the tick count, because "4.02x" and "4.02x from a 1-tick base" are very different
// claims and only one of them is evidence.
func (g Growth) ResolutionNote() string {
	n, ok := g.Ticks()
	res := g.resolution()
	if ok {
		return fmt.Sprintf("base spans %.1f ticks of the %s clock (tick=%v), at or above the %d required",
			n, g.Clock, res, MinTicks)
	}
	return fmt.Sprintf("base spans only %.1f ticks of the %s clock (tick=%v), under the %d required — the "+
		"ratio is substantially an artefact of the clock and must not be asserted on",
		n, g.Clock, res, MinTicks)
}
