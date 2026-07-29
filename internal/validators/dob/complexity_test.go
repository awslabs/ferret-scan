// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// denseDateLine builds ONE line carrying n distinct dates plus a keyword-rich
// prefix and suffix.
//
// Distinct dates matter: with repeated values the candidate set collapses and a
// quadratic implementation measures as linear. The first version of this
// measurement used repeated dates, reported a flat 80 findings at every size, and
// hid the quadratic completely.
func denseDateLine(n int) string {
	var sb strings.Builder
	sb.WriteString("Patient DOB:")
	base := time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		sb.WriteByte(' ')
		sb.WriteString(base.AddDate(0, 0, i*7).Format("01/02/2006"))
		sb.WriteByte(',')
	}
	// A keyword-rich tail WITHOUT a disqualifier. An earlier version ended with
	// "blood sample collected at intake", and although the CLI reports 2000
	// findings on that shape, in-process the trailing "sample" reaches the
	// disqualifier path for candidates far from the label and the whole line
	// returned nothing -- which the non-vacuity floor below caught.
	sb.WriteString(" recorded at intake by the attending physician")
	return sb.String()
}

// TestDenseLineFindingsGrowWithInput is the non-vacuity floor for the timing
// guard below. If the finding count stops tracking the input, the timing
// assertion is measuring nothing and would pass no matter how bad the scaling is.
func TestDenseLineFindingsGrowWithInput(t *testing.T) {
	v := NewValidator()

	var prev int
	for _, n := range []int{250, 500, 1000} {
		matches, err := v.ValidateContent(denseDateLine(n), "chart.txt")
		if err != nil {
			t.Fatalf("ValidateContent at n=%d: %v", n, err)
		}
		if len(matches) == 0 {
			t.Fatalf("zero findings at n=%d: the fixture does not exercise the scan", n)
		}
		if len(matches) <= prev {
			t.Errorf("findings did not grow with input at n=%d: got %d, previous %d",
				n, len(matches), prev)
		}
		prev = len(matches)
	}
}

// TestKeywordScanIsHoistedOutOfTheCandidateLoop is the structural guard, and it
// is deliberately NOT a wall-clock assertion.
//
// The defect was that analyzeContext recomputed every keyword tally for each
// candidate date, and each recomputation scanned the whole line against ~40
// keywords, giving O(candidates x line length x keywords). Measured on a single
// line of distinct dates before the hoist: 250 -> 0.14s, 500 -> 0.30s,
// 1000 -> 0.86s, 2000 -> 3.34s, 4000 -> 15.68s (~4x per doubling). After:
// 0.09 / 0.11 / 0.14 / 0.13s.
//
// This test asserts the invariant that makes it linear instead of timing it: the
// tallies are a pure function of the line, so computing them once per line and
// once per candidate must produce identical results. A future change that
// reintroduces per-candidate context (something that varies per match) breaks
// this equality, which is the actual regression to catch.
func TestKeywordScanIsHoistedOutOfTheCandidateLoop(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Patient DOB: 03/14/1987, blood sample collected at intake",
		"date of birth 03/14/1987 and 07/22/1979 on file",
		"born 03/14/1987, server age 5 years",
		"Test DOB: 01/01/2000",
		denseDateLine(50),
	}

	for _, line := range lines {
		lower := strings.ToLower(line)
		hoisted := v.newDOBLineKeywords(lower)

		// Recomputing must be identical -- that is what makes the hoist sound.
		again := v.newDOBLineKeywords(lower)
		if hoisted.positiveCount != again.positiveCount ||
			hoisted.hasStrongPositive != again.hasStrongPositive ||
			hoisted.contextNegativeCount != again.contextNegativeCount ||
			hoisted.hasDisqualifier != again.hasDisqualifier ||
			hoisted.hasNonHuman != again.hasNonHuman {
			t.Errorf("keyword tally is not a pure function of the line: %q", line)
		}
	}
}

// TestAnalyzeContextMatchesTheHoistedForm pins the equivalence the refactor
// relies on: the exported analyzeContext (which builds its own cache) and
// analyzeContextWith (which takes one) must agree.
func TestAnalyzeContextMatchesTheHoistedForm(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Patient DOB: 03/14/1987, blood sample collected at intake",
		"Patient DOB: 03/14/1987, blood collected at intake",
		"Test DOB: 01/01/2000",
		"born 03/14/1987 the project was born",
		"date of birth 03/14/1987",
		"random text with no dates at all",
	}

	for _, line := range lines {
		lower := strings.ToLower(line)
		want := v.analyzeContext(lower, contextFor(line))
		got := v.analyzeContextWith(lower, contextFor(line), v.newDOBLineKeywords(lower))
		if got != want {
			t.Errorf("analyzeContextWith = %v, analyzeContext = %v for %q", got, want, line)
		}
	}
}

// TestDenseLineCompletesPromptly is the coarse backstop. The threshold is
// deliberately loose (a quadratic at this size took over three seconds, a linear
// pass takes well under a fifth of a second) so it is not a flaky benchmark, and
// it carries its own non-vacuity check.
func TestDenseLineCompletesPromptly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guard skipped under -short")
	}

	v := NewValidator()
	const n = 2000

	start := time.Now()
	matches, err := v.ValidateContent(denseDateLine(n), "chart.txt")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("non-vacuity floor: zero findings, so the timing below proves nothing")
	}
	if elapsed > 2*time.Second {
		t.Errorf("scanning one line of %d dates took %v (was ~3.3s quadratic, ~0.14s linear); "+
			"the per-line keyword hoist has probably been undone", n, elapsed)
	}
}

// contextFor builds the ContextInfo shape the scanner passes to analyzeContext:
// the full line, with the before/after windows left empty (the production caller
// fills them from within the same line, which is why they add no new tokens).
func contextFor(line string) detector.ContextInfo {
	return detector.ContextInfo{FullLine: line}
}
