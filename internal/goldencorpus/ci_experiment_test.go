// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"fmt"
	"os"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// TestCIExperiment649ControlMargins answers #649 with data no developer machine can produce.
//
// Two of the four maxGrowthRatio controls sit under this repo's own >=1.5x margin convention on
// macos-latest, and the linear control's 6.40x there is unexplained: this dev Mac reads a stable ~4.0x,
// runs the fixtures 3.6x faster, and has 14 cores against that runner's 3-4.
//
// #649 names the experiment that would settle it, and this is it: per-pair samples for every control, on
// every runner, at pairs=2 AND pairs=4. The question the pair count answers is directional and cannot be
// reasoned out -- Ratio = min(big)/min(base), so more samples shrink BOTH minima and the net direction is
// undetermined. Measured on the dev Mac the worst-of-4-trials went 4.61x at 2 pairs, 4.13x at 4, 4.39x at
// 8: no trend, inside the noise, and on a machine that reproduces none of the problem.
//
// MEASUREMENT ONLY. Nothing is asserted, so this cannot redden CI. Gated on FERRET_CI_EXPERIMENT.
func TestCIExperiment649ControlMargins(t *testing.T) {
	if os.Getenv("FERRET_CI_EXPERIMENT") == "" {
		t.Skip("set FERRET_CI_EXPERIMENT=1 to run the #649 measurement")
	}

	cpuTick, wallTick := perfguard.ClockResolution()
	t.Logf("EXP649 platform: cpuTick=%v wallTick=%v maxGrowthRatio=%.1f raceDetector=%v",
		cpuTick, wallTick, maxGrowthRatio, raceDetectorEnabled)

	rescans := 0
	controls := []struct {
		name string
		// direction: +1 means the reading must EXCEED maxGrowthRatio, -1 means it must stay at or below.
		direction int
		reps      int
		newV      func() validatorUnderTest
		unit      string
		gen       func(int) string
	}{
		{"quadratic(catches)", +1, 3000, func() validatorUnderTest { return quadraticValidator{} }, "", quadraticUnit},
		{"linear(stays-low)", -1, 40000, func() validatorUnderTest { return linearValidator{} }, linearUnit, nil},
		{"emit-per-match(catches)", +1, 3000, func() validatorUnderTest { return emittingQuadraticValidator{} }, "", quadraticUnit},
		{"sparse-4096(misses)", -1, 48000, func() validatorUnderTest {
			return sparseQuadraticValidator{every: 4096, rescans: &rescans}
		}, "", quadraticUnit},
	}

	const trials = 5
	for _, c := range controls {
		unit := c.unit
		gen := c.gen
		if unit == "" {
			unit = gen(0)
			gen = nil
		}
		base := buildComplexityInput(unit, gen, c.reps)
		big := buildComplexityInput(unit, gen, c.reps*4)

		for _, pairs := range []int{2, 4} {
			var worst float64
			var bestMargin = 9999.0
			for trial := 0; trial < trials; trial++ {
				g, err := perfguard.Measure(pairs,
					func() { _, _ = c.newV().ValidateContent(base, "exp.txt") },
					func() { _, _ = c.newV().ValidateContent(big, "exp.txt") })
				if err != nil {
					t.Logf("EXP649 %-24s pairs=%d trial=%d Measure error: %v", c.name, pairs, trial, err)
					continue
				}
				// The margin, in the direction this control asserts. Below 1.5 is the #649 finding.
				margin := maxGrowthRatio / g.Ratio
				if c.direction > 0 {
					margin = g.Ratio / maxGrowthRatio
				}
				if margin < bestMargin {
					bestMargin = margin
				}
				if (c.direction < 0 && g.Ratio > worst) || (c.direction > 0 && (worst == 0 || g.Ratio < worst)) {
					worst = g.Ratio
				}
				n, suff := g.Ticks()
				// The CONTENTION SIGNAL: wall/cpu on the base reading. Under contention the wall clock
				// keeps running while the process is descheduled, so this ratio rises; the CPU clock
				// itself also inflates through cache and scheduler effects, which is what depresses the
				// growth ratio. If this tracks the depressed ratios, it is a usable trustworthiness gate
				// -- Growth already carries both numbers, so no new measurement would be needed.
				inflation := 0.0
				if g.BaseMin > 0 {
					inflation = float64(g.BaseWallMin) / float64(g.BaseMin)
				}
				t.Logf("EXP649 %-24s pairs=%d trial=%d ratio=%6.2fx margin=%4.2fx clock=%-4s base=%-11v big=%-11v baseWall=%-11v wall/cpu=%5.2f ticks=%.0f(%v) per-pair %s",
					c.name, pairs, trial, g.Ratio, margin, g.Clock, g.BaseMin, g.BigMin, g.BaseWallMin,
					inflation, n, suff, perfguard.FormatRatios(g.Samples))
			}
			verdict := "OK"
			if bestMargin < 1.5 {
				verdict = fmt.Sprintf("UNDER 1.5x (%.2fx)", bestMargin)
			}
			t.Logf("EXP649 SUMMARY %-24s pairs=%d worstRatio=%6.2fx worstMargin=%4.2fx %s",
				c.name, pairs, worst, bestMargin, verdict)
		}
	}
	_ = detector.Match{}
}
