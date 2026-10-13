// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// TestGrowthRatioSpreadInstrumentationForIssue649 collects, on every CI runner, the evidence #649
// says is the only thing that can settle it. It asserts nothing about timing — it is a measuring
// instrument with non-vacuity checks, not a gate.
//
// THE QUESTION IT EXISTS TO ANSWER. On macos-latest the linear control read 6.40x against ~4.0x
// everywhere else, with a margin of only 1.25x under the 8.0 threshold — the next #546-class false
// alarm waiting to happen. Reconstructing that run's arithmetic showed the mechanism: its two BASE
// readings were 1.7x apart while its big readings agreed within 3%, so Ratio = min(big)/min(base)
// divided the one clean base into a consistently-inflated big.
//
// SETTLED, by #731, from 22 runs: perfguard.DefaultPairs is 4. The decision rule this comment first
// proposed was wrong, and is kept here so nobody re-applies it. It said "if the base spread
// collapses at 4 pairs, more pairs is the fix; if it persists, more pairs cannot remove it". But
// spread is max/min — a RANGE — and a range widens as samples are added: macos's worst base spread
// went from 2.29x at 2 pairs to 2.99x at 4. Ratio does not use the range, it uses the per-side
// MINIMUM, and the minimum improves with samples even while the range grows: the linear control's
// worst reading fell from 7.99x to 4.68x and the quadratic's rose from 9.72x to 14.90x. Both
// headline readings were one side's two samples inflated TOGETHER, which a 2-sample minimum cannot
// escape and a 4-sample one usually does. Read the ratio tails at pairs=2 vs pairs=4, not the spread.
//
// #620, #643 and #648 all came from tuning these bounds against local measurements; this test is
// the refusal to do that a fourth time.
//
// WHERE THE NUMBERS SURFACE. The go-test.yml step "Report the complexity guard's measured ratios"
// runs `-v -run '...|TestGrowthRatio'` on all three runners, every push — this test's name matches
// that pattern on purpose, so the readings appear in that step's log with no workflow change.
//
// WHAT TO READ OFF A RUN, per runner: the ratio at pairs=2 vs pairs=4 for the two thin-margin
// controls — the evidence that 4 is still enough — and the quad/linear line, which is scale-invariant by construction — both controls run
// in the same process on the same runner in the same minute, so a uniformly slow or uniformly
// inflated runner cancels out of the quotient. #649 measured it once by accident (2.45x on macos,
// 3.95x on ubuntu from unrelated runs); this logs it deliberately so its own margin study can
// accumulate before anyone proposes pinning it.
func TestGrowthRatioSpreadInstrumentationForIssue649(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement instrument, ~10s of deliberate re-measuring; skipped in -short")
	}

	// The controls, at their shipped sizes so readings stay comparable with the table in #649 and
	// with the assertions in complexity_confirmation_test.go.
	linear := func() (func(), func()) {
		base := buildComplexityInput(linearUnit, nil, 40000)
		big := buildComplexityInput(linearUnit, nil, 40000*4)
		return func() { _ = mustValidate(t, linearValidator{}, base) },
			func() { _ = mustValidate(t, linearValidator{}, big) }
	}
	sparse := func() (func(), func()) {
		rescans := 0
		base := buildComplexityInput(quadraticUnit(0), nil, 48000)
		big := buildComplexityInput(quadraticUnit(0), nil, 48000*4)
		v := sparseQuadraticValidator{every: 4096, rescans: &rescans}
		return func() { _ = mustValidate(t, v, base) },
			func() { _ = mustValidate(t, v, big) }
	}
	quad := func() (func(), func()) {
		base := buildComplexityInput(quadraticUnit(0), nil, 3000)
		big := buildComplexityInput(quadraticUnit(0), nil, 3000*4)
		return func() { _ = mustValidate(t, quadraticValidator{}, base) },
			func() { _ = mustValidate(t, quadraticValidator{}, big) }
	}

	for _, pairs := range []int{2, 4} {
		ratios := map[string]float64{}
		for _, c := range []struct {
			name       string
			mk         func() (func(), func())
			thinMargin bool
		}{
			{"linear", linear, true},
			{"sparse-quadratic", sparse, true},
			{"genuine-quadratic", quad, false},
		} {
			base, big := c.mk()
			g, err := perfguard.Measure(pairs, base, big)
			if err != nil {
				// An instrument, not a gate: a measurement the clock could not resolve is reported and
				// skipped. Failing here turned a windows-latest timer quirk ("a base reading was zero on
				// the wall clock", genuine-quadratic at pairs=4, ~1.5ms base) into a red build.
				t.Logf("ISSUE-649 pairs=%d %-17s NOT measured — %v  runner=%s", pairs, c.name, err, perfguard.Runner())
				continue
			}
			// Non-vacuity: an instrument whose readings are empty or zero is reporting the
			// measurement harness, not the runner.
			if len(g.BaseReadings) != pairs || len(g.BigReadings) != pairs {
				t.Fatalf("%s at pairs=%d: captured %d/%d raw readings, want %d of each",
					c.name, pairs, len(g.BaseReadings), len(g.BigReadings), pairs)
			}
			if g.BaseSpread() <= 0 || g.BigSpread() <= 0 {
				t.Fatalf("%s at pairs=%d: zero-valued readings reached the spread; the resolution "+
					"gate should have refused this measurement (clock=%s base=%s)",
					c.name, pairs, g.Clock, perfguard.FormatDurations(g.BaseReadings))
			}
			ratios[c.name] = g.Ratio
			t.Logf("ISSUE-649 pairs=%d %-17s ratio=%5.2fx clock=%-4s base spread=%.2fx big spread=%.2fx  bases=%s bigs=%s  runner=%s",
				pairs, c.name, g.Ratio, g.Clock, g.BaseSpread(), g.BigSpread(),
				perfguard.FormatDurations(g.BaseReadings), perfguard.FormatDurations(g.BigReadings), perfguard.Runner())
		}
		if ratios["linear"] > 0 && ratios["genuine-quadratic"] > 0 {
			t.Logf("ISSUE-649 pairs=%d quad/linear=%.2fx sparse/linear=%.2fx  (same-run, scale-invariant)",
				pairs, ratios["genuine-quadratic"]/ratios["linear"], ratios["sparse-quadratic"]/ratios["linear"])
		}
	}
}

// mustValidate is validateOnce without the match-count plumbing the assertions need; the
// instrumentation only has to drive the same code the controls drive.
func mustValidate(t *testing.T, v validatorUnderTest, content string) int {
	t.Helper()
	matches, err := v.ValidateContent(content, "<complexity>")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("fixture produced no matches; the reading below would time a reject path")
	}
	return len(matches)
}
