// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"fmt"
	"os"
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

// TestGrowthRatioStillCatchesAGenuineQuadratic is the half that protects the guard's purpose.
//
// The estimator must not be so noise-tolerant that it stops detecting the thing it exists for.
// A real quadratic must exceed the threshold, and asserting it here is what stops a future
// robustness change from quietly buying stability with blindness.
func TestGrowthRatioStillCatchesAGenuineQuadratic(t *testing.T) {
	newV := func() validatorUnderTest { return quadraticValidator{} }

	// Sized so the base CPU reading clears minMeasurableCPU. A first version used reps = 300,
	// giving a 45µs base, which is below the resolution the ratio is computed at.
	const reps = 3000
	base := buildComplexityInput(quadraticUnit(0), nil, reps)
	big := buildComplexityInput(quadraticUnit(0), nil, reps*4)

	g := growthRatio(t, newV, base, big)
	t.Logf("synthetic quadratic: %.2fx on the %s clock (min base=%v big=%v, per-pair %s)",
		g.ratio, g.clock, g.baseMin, g.bigMin, formatRatios(g.samples))

	// Non-vacuity: the fixture must actually be driving the quadratic path. A reject path is
	// fast and its ratio is noise, which would make the assertion below meaningless. The counts
	// come from the same measurement, so they describe the readings being judged.
	if g.baseMatches == 0 || g.bigMatches <= g.baseMatches {
		t.Fatalf("fixture is not exercising the quadratic path: base=%d big=%d matches",
			g.baseMatches, g.bigMatches)
	}

	if g.ratio <= maxGrowthRatio {
		t.Errorf("a genuine O(n^2) validator measured %.2fx on the %s clock, at or below the %.1f "+
			"threshold — the guard would no longer detect the regression it exists for. "+
			"min base=%v big=%v, per-pair %s",
			g.ratio, g.clock, maxGrowthRatio, g.baseMin, g.bigMin, formatRatios(g.samples))
	}
}

// TestGrowthRatioStaysLowOnLinearCode is the must-NOT-fire half.
//
// #546 was this direction failing: correct code read 8.60x and 9.68x on a contended runner and
// the guard reported an O(n^2) regression that did not exist. The validator here allocates a
// Match per finding exactly as production ones do, because allocation was the specific thing that
// made a single-pass scan read 8.17x — see withGCOff.
func TestGrowthRatioStaysLowOnLinearCode(t *testing.T) {
	newV := func() validatorUnderTest { return linearValidator{} }
	const reps = 40000
	base := buildComplexityInput(linearUnit, nil, reps)
	big := buildComplexityInput(linearUnit, nil, reps*4)

	g := growthRatio(t, newV, base, big)
	t.Logf("linear control: %.2fx on the %s clock (min base=%v big=%v, per-pair %s)",
		g.ratio, g.clock, g.baseMin, g.bigMin, formatRatios(g.samples))

	if g.ratio > maxGrowthRatio {
		t.Errorf("a single-pass validator measured %.2fx on the %s clock, above the %.1f "+
			"threshold — this is #546, the guard failing on correct code. min base=%v big=%v, "+
			"per-pair %s", g.ratio, g.clock, maxGrowthRatio, g.baseMin, g.bigMin, formatRatios(g.samples))
	}
}

// TestNothingInThisPackageRunsInParallel protects the assumption the CPU clock depends on.
//
// getrusage(RUSAGE_SELF) reports CPU for the WHOLE PROCESS, so it is only a measure of the
// validator under test while nothing else in this process is burning CPU concurrently. Two facts
// make that true today, and this test pins the one that a future edit could break:
//
//  1. `go test` builds and runs one binary PER PACKAGE, so the other packages competing for the
//     machine are separate processes and their CPU does not enter this reading. That is why the
//     estimator survives a loaded runner — measured with 28 external busy-loop processes on 14
//     CPUs, the minimum base reading was 3.727ms against 3.703ms idle.
//  2. No test in this package runs concurrently with another. This is the fragile half.
//
// Measured, so this is not a theoretical worry: running the linear control with 28 busy
// GOROUTINES in-process made it read 11.62x with the base inflated from 4.374ms to 39.559ms —
// a false O(n^2) report on a single-pass scan. Adding t.Parallel() anywhere in this package would
// do exactly that to whichever measurement happened to overlap.
func TestNothingInThisPackageRunsInParallel(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	// Assembled from fragments so this file does not contain the literal it searches for. A
	// first version matched its own search string and its own error message, and "exempt the
	// guard's own file" would have been the wrong fix: this file measures too, so it has to be
	// policed like the rest.
	needle := "t.Paralle" + "l()"

	var scanned int
	var offenders []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name()) // #nosec G304 -- a test file in this package
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			if strings.Contains(code, needle) {
				offenders = append(offenders, fmt.Sprintf("%s:%d", e.Name(), i+1))
			}
		}
	}

	// Non-vacuity: if the directory walk stopped finding test files, the assertion below would
	// pass on an empty set.
	if scanned < 5 {
		t.Fatalf("scanned only %d _test.go files in this package; the check is not reading the "+
			"sources it is meant to police", scanned)
	}
	if len(offenders) > 0 {
		t.Errorf("%s found at %s. The complexity guard measures process-wide CPU time "+
			"(getrusage RUSAGE_SELF), so a test running concurrently with a measurement is "+
			"charged to the validator being measured: in-process load inflated a base reading "+
			"4.374ms -> 39.559ms and turned a 4.07x linear scan into 11.62x, above the %.1f "+
			"threshold. Either keep this package sequential or move the complexity guard to a "+
			"clock that is not process-wide.", needle, strings.Join(offenders, ", "), maxGrowthRatio)
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
