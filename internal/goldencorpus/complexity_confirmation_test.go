// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #546: the growth-ratio guard failed on CORRECT code. Five readings this guard produced on
// unmodified validators sat in (8.0, 12.0] — dob 8.60x under -race, medicalid 9.68x plain —
// every one of which passes at the pre-#535 threshold of 12.0 and none of which is a defect.
// Host load average was 143-175 on 14 CPUs, and CI runs this suite with -race on shared
// runners, so that is the configuration that matters.
//
// The cause is the STATISTIC, not the threshold. A single pair of wall-clock readings is not
// stable under contention. Measured on the four flakiest targets at load average 160, 24
// trials each:
//
//	single pair                1.20 - 6.82x
//	min of independent mins    2.87 - 6.07x
//	MEDIAN of paired readings  3.58 - 6.03x
//
// Note single-shot's 1.20x on linear code: contention inflates the BASE term too, which drives
// the ratio DOWN. That is why the minimum is unsafe — it is biased toward passing and could
// mask a real quadratic — and why the median, robust in both directions, is the right choice.
//
// The threshold could not be fixed instead. A reproduced quadratic reads 15.4-15.6x plain but
// only 12.4-12.7x under -race, so the bound must stay well below 12.4 while contended correct
// code reached 9.68x. No single number has margin at both ends.

// quadraticValidator is deliberately O(n^2): for every match it rescans the whole input.
//
// A synthetic validator rather than a mutated real one, because #535's own note reproduced a
// quadratic by defeating dob's keyword hoist — an invasive edit to production code that cannot
// live in a test. This shape is the pattern the guard exists to catch (per-match full-input
// rescan), so it exercises the same failure mode without touching a shipped validator.
type quadraticValidator struct{}

func (quadraticValidator) ValidateContent(content, _ string) ([]detector.Match, error) {
	var out []detector.Match
	for i := 0; i+3 <= len(content); i++ {
		if content[i:i+3] != "XQZ" {
			continue
		}
		// The quadratic step: a full-input scan per match.
		n := strings.Count(content, "a")
		out = append(out, detector.Match{Text: "XQZ", Type: "TEST", Confidence: float64(50 + n%2)})
	}
	return out, nil
}

func quadraticUnit(i int) string { return "XQZ aaaaaaaaaaaaaaaa " }

// TestConfirmationStillCatchesAGenuineQuadratic is the half that protects the guard's purpose.
//
// Re-measuring on failure must not become a way to retry until the machine is quiet enough to
// pass. A real quadratic exceeds the threshold on EVERY pair, so its median exceeds it too —
// asserted here rather than assumed, because a confirmation step that softened detection would
// be strictly worse than the flake it replaces.
func TestConfirmationStillCatchesAGenuineQuadratic(t *testing.T) {
	newV := func() validatorUnderTest { return quadraticValidator{} }

	// Sized so the BASE reading is milliseconds, not microseconds. A first version used
	// reps = 300, giving a 45µs base, and the samples then spanned 8.46x-20.33x — noise, in
	// the very regime this change exists to escape. The guard itself only evaluates a ratio
	// when the base exceeds 2ms, so a control below that measures nothing the guard would.
	const reps = 3000
	base := buildComplexityInput(quadraticUnit(0), nil, reps)
	big := buildComplexityInput(quadraticUnit(0), nil, reps*4)

	tb, nb := timeValidate(t, newV(), base)
	tg, ng := timeValidate(t, newV(), big)
	if nb == 0 || ng <= nb {
		t.Fatalf("fixture is not exercising the quadratic path: base=%d big=%d matches", nb, ng)
	}
	first := float64(tg) / float64(tb)
	t.Logf("synthetic quadratic first reading: %.2fx (base=%v big=%v)", first, tb, tg)
	if first <= maxGrowthRatio {
		t.Fatalf("the synthetic quadratic read %.2fx, at or below the %.1f threshold — the "+
			"fixture is too small to be a meaningful control", first, maxGrowthRatio)
	}

	median, samples := medianGrowthRatio(t, newV, base, big, first)
	t.Logf("synthetic quadratic median: %.2fx over %d pairs %s", median, len(samples), formatRatios(samples))
	if median <= maxGrowthRatio {
		t.Errorf("a genuine O(n^2) validator's MEDIAN ratio is %.2fx, at or below the %.1f "+
			"threshold — the confirmation step has turned the guard into a retry-until-quiet "+
			"loop and would no longer detect the regression it exists for. samples %v",
			median, maxGrowthRatio, formatRatios(samples))
	}
	// Deliberately NOT asserting that every sample exceeds the threshold. An earlier version
	// did, and it failed under load 84: a genuine quadratic produced
	// [13.38x 22.06x 5.96x 20.13x 7.54x 13.12x 12.31x] — median 13.12x, correct, but two
	// individual samples below 8.0. That is the same base-inflation effect documented on
	// medianGrowthRatio (contention can push a single ratio DOWN), so per-sample stability is
	// exactly what this design does not rely on. The median is the contract; asserting more
	// than the contract is how a test fails on correct code, which is the defect being fixed.
	if len(samples) != confirmationPairs {
		t.Errorf("got %d confirmation samples, want %d", len(samples), confirmationPairs)
	}

	// The returned value must be the MEDIAN of the samples, asserted structurally rather than
	// inferred from it being "low enough". A mutation returning the MAXIMUM instead survived the
	// checks above: on an idle machine the largest sample is still under the threshold, so the
	// test passed while the statistic was wrong — and under load the maximum is exactly what
	// reinstates the flake this change removes.
	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)
	wantMedian := sorted[len(sorted)/2]
	if median != wantMedian {
		t.Errorf("medianGrowthRatio returned %.4fx, but the median of its own samples is %.4fx "+
			"(sorted %v) — the statistic must be the median: the minimum is biased toward "+
			"passing and could mask a quadratic, the maximum reinstates the contention flake",
			median, wantMedian, formatRatios(sorted))
	}
}

// TestConfirmationIsSkippedOnTheHappyPath.
//
// The re-measurement must cost nothing when the first reading is fine, or this change makes
// every CI run slower to fix a flake. medianGrowthRatio is called only inside the
// `ratio > maxGrowthRatio` branch; this pins that by asserting a linear validator's first
// reading is comfortably under the bound, so the branch is not entered.
func TestConfirmationIsSkippedOnTheHappyPath(t *testing.T) {
	// A linear validator: one pass, no per-match rescan.
	linear := func() validatorUnderTest { return linearValidator{} }
	// Same sizing discipline as the quadratic control above: a 375µs base read 5.70x, which
	// is noise rather than the ~4x a linear scan actually costs.
	const reps = 40000
	base := buildComplexityInput(linearUnit, nil, reps)
	big := buildComplexityInput(linearUnit, nil, reps*4)

	tb, nb := timeValidate(t, linear(), base)
	tg, ng := timeValidate(t, linear(), big)
	if nb == 0 || ng <= nb {
		t.Fatalf("fixture not exercising the scan: base=%d big=%d", nb, ng)
	}
	ratio := float64(tg) / float64(tb)
	t.Logf("linear control: %.2fx (base=%v big=%v)", ratio, tb, tg)
	if ratio > maxGrowthRatio {
		t.Errorf("a linear validator read %.2fx, above the %.1f threshold — either the "+
			"fixture is too small to measure or the threshold is wrong", ratio, maxGrowthRatio)
	}
}

// linearUnit is one repetition of the linear control's input.
//
// Deliberately ONE match per ~200 bytes. A first version used "XQZ aaaa " -- a match every 9
// bytes, 160k matches at the big size -- and the slice growth and GC that caused made the
// control noisier than any real validator: it read [4.02x 14.18x 3.85x 15.64x] where the 18
// real targets read 3.20-4.51x. A control must be at least as stable as the thing it models.
const linearUnit = "XQZ " + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "

// linearValidator scans the input once.
type linearValidator struct{}

func (linearValidator) ValidateContent(content, _ string) ([]detector.Match, error) {
	var out []detector.Match
	for i := 0; i+3 <= len(content); i++ {
		if content[i:i+3] == "XQZ" {
			out = append(out, detector.Match{Text: "XQZ", Type: "TEST", Confidence: 50})
		}
	}
	return out, nil
}

// TestConfirmationClearsAContendedOutlierOnLinearCode models #546 directly.
//
// The reported failure was a SINGLE contended reading on correct code — dob 8.60x under -race,
// medicalid 9.68x plain — where every re-measurement of the same code is ~4x. This feeds
// medianGrowthRatio exactly that situation: a linear validator plus a first reading above the
// threshold, standing in for the contended outlier. The median must come back below the
// threshold, or the confirmation step does not fix the flake it was added for.
//
// This is the complement of TestConfirmationStillCatchesAGenuineQuadratic: together they pin
// both directions — a real quadratic must survive confirmation, a contended outlier must not.
func TestConfirmationClearsAContendedOutlierOnLinearCode(t *testing.T) {
	newV := func() validatorUnderTest { return linearValidator{} }
	const reps = 40000
	base := buildComplexityInput(linearUnit, nil, reps)
	big := buildComplexityInput(linearUnit, nil, reps*4)

	// The worst correct-code reading #546 recorded. Higher than anything linear code costs.
	const contendedOutlier = 9.68

	median, samples := medianGrowthRatio(t, newV, base, big, contendedOutlier)
	t.Logf("contended-outlier first=%.2fx -> median %.2fx over %d pairs %s",
		contendedOutlier, median, len(samples), formatRatios(samples))

	if median > maxGrowthRatio {
		t.Errorf("a linear validator whose FIRST reading was a contended %.2fx still has median "+
			"%.2fx, above the %.1f threshold — the confirmation step does not clear the flake "+
			"#546 reported. samples %v", contendedOutlier, median, maxGrowthRatio, formatRatios(samples))
	}
	// The trigger must NOT be one of the samples. It is in the set only by virtue of having
	// been high, so letting it vote biases the median upward — measured, that is how a first
	// version produced median 9.68x from [9.68x 4.02x 14.18x 3.85x 15.64x] and failed linear
	// code. Asserted so nobody "helpfully" adds it back.
	for _, s := range samples {
		if s == contendedOutlier {
			t.Errorf("the triggering reading %.2fx appears in the confirmation samples %v — the "+
				"suspect measurement must not vote on its own confirmation",
				contendedOutlier, formatRatios(samples))
		}
	}
	if len(samples) != confirmationPairs {
		t.Errorf("got %d confirmation samples, want %d", len(samples), confirmationPairs)
	}
}
