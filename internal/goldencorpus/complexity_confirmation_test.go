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

	// Warm up and DISCARD. The trigger reading is the first thing this package times, so on a
	// cold or contended runner it absorbs one-off cost that the `big` reading does not pay in
	// proportion — which inflates the base and collapses the ratio. Measured on CI, where the base
	// read 11.7-15.2ms against 2.9-4.7ms locally while `big` was only ~2.3x its local value: the
	// ratio fell to 6.46x-7.71x on ubuntu and windows purely from that asymmetry. Allocation is not
	// the cause (pre-sizing the output slice moves the ratio 15.79x -> 15.90x and the loop makes
	// only 12 allocations), so the fix is to stop MEASURING cold, not to change the fixture.
	timeValidate(t, newV(), base)
	timeValidate(t, newV(), big)

	tb, nb := timeValidate(t, newV(), base)
	tg, ng := timeValidate(t, newV(), big)
	if nb == 0 || ng <= nb {
		t.Fatalf("fixture is not exercising the quadratic path: base=%d big=%d matches", nb, ng)
	}
	first := float64(tg) / float64(tb)
	t.Logf("synthetic quadratic first reading: %.2fx (base=%v big=%v)", first, tb, tg)

	// The first reading is ONE wall-clock pair, and this file's own guard exists because a single
	// pair is not a statistic. It is logged, not asserted: a contended sample used to fail here
	// with Fatalf BEFORE the median was ever computed, so the control reported "the fixture is too
	// small" on a fixture whose median is 14.3x-15.9x. The median assertion below is the real one,
	// and it is strictly stronger — it is what the guard under test actually judges.
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
// `ratio > maxGrowthRatio` branch, and this asserts a linear validator's ratio stays under the
// bound so that branch is not entered on correct code.
//
// It judges the MEDIAN, not one reading, and that correction came from CI failing this very test:
// macos-latest under -race reported
//
//	linear control: 8.17x (base=34.762375ms big=284.058167ms)
//
// on a validator that does one pass. The base was 34ms, so this was not the small-measurement
// noise the fixtures were already sized against — it is that an allocation-heavy loop is not
// linear in WALL CLOCK under -race, where every access is instrumented and GC cost grows with the
// heap. A first version asserted a single reading and therefore contradicted the premise of the
// change it accompanies: that one wall-clock pair is not a statistic. Using medianGrowthRatio here
// makes the test judge correct code exactly as production does.
func TestConfirmationIsSkippedOnTheHappyPath(t *testing.T) {
	// A linear validator: one pass, no per-match rescan.
	linear := func() validatorUnderTest { return linearValidator{} }
	// Sized so the base is several times the guard's own 2ms ratio floor. 12000 was tried first
	// and gave a 1.5ms base — below that floor, i.e. back in the noise regime the fixtures exist
	// to escape, which would have made this control meaningless in the other direction.
	const reps = 40000
	base := buildComplexityInput(linearUnit, nil, reps)
	big := buildComplexityInput(linearUnit, nil, reps*4)

	tb, nb := timeValidate(t, linear(), base)
	tg, ng := timeValidate(t, linear(), big)
	if nb == 0 || ng <= nb {
		t.Fatalf("fixture not exercising the scan: base=%d big=%d", nb, ng)
	}
	first := float64(tg) / float64(tb)
	t.Logf("linear control first reading: %.2fx (base=%v big=%v)%s", first, tb, tg, raceNote())

	// Under the threshold on the first reading is the common case and needs nothing further.
	if first <= maxGrowthRatio {
		return
	}
	median, samples := medianGrowthRatio(t, linear, base, big, first)
	t.Logf("linear control median: %.2fx over %d pairs %s", median, len(samples), formatRatios(samples))
	if median > maxGrowthRatio {
		t.Errorf("a linear validator's MEDIAN ratio is %.2fx over %d pairs, above the %.1f "+
			"threshold. Either the threshold is wrong for this configuration or this fixture is "+
			"not actually linear in wall clock — under -race an allocation-heavy loop is not. "+
			"samples %v", median, len(samples), maxGrowthRatio, formatRatios(samples))
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
	// Pre-sized from the input, so repeated slice growth is not part of what is timed. detector.Match
	// is a large struct and -race instruments every copy, which is what made an append-driven
	// version read 8.17x on a CI runner for a single-pass scan.
	out := make([]detector.Match, 0, 1+len(content)/len(linearUnit))
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
