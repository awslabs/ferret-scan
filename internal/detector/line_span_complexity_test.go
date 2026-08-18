// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// AssignLineColumns runs on EVERY scan, so its growth is a scan-path concern.
//
// The occurrence cursor it inherits from the redaction overlap pass used to run only
// when redacting. Wiring it into parallel.RunValidators put it on the path of every
// scan, including read-only ones, which changes who pays for it: a dense
// single-line document is now this function's worst case on every run.
//
// Writing these tests found a quadratic that was NOT the one expected, which is the
// reason they exist in isolation rather than end-to-end.
//
// The assumption going in was that the cursor made the repeated-value case linear and
// that only distinct values were superlinear. Measured, it was the opposite way round:
// ONE repeated value cost 18.5x for 4x input (19.5ms at K=8000), worse than distinct
// values at 14.2x. The cursor was never the cost. The line-id map key contains the
// whole line TEXT, so every lookup hashed the line — O(line length) per match, i.e.
// O(matches x line length) — and the interning it documents removes quadratic string
// COMPARISON from the containment loop while leaving that hashing in place.
//
// A one-entry memo for the preceding line fixed it: matches from a line arrive
// together and share the identical FullLine string, so the common case became a length
// check and a pointer compare. K=8000 went 19.5ms -> 0.69ms, a 28x improvement, and
// growth 18.5x -> 8.1x at times small enough that noise dominates.
//
// What remains, and is a RATCHET rather than a target:
//
//   - MANY OCCURRENCES OF ONE VALUE is now near-linear. The cursor advances past each
//     occurrence and the memo removes the per-match hash.
//   - MANY DISTINCT VALUES is still O(K x line length): each value owns a cursor
//     starting at zero, so each strings.Index scans from the line start to that value.
//     Measured 16.2x for 4x input, 148ms at K=8000 — which the arithmetic corroborates
//     (8000 values x ~64KB average scan is ~512MB). Making it linear needs a
//     multi-pattern single pass over the line, not a tweak, and per-validator execution
//     budgets already bound pathological single-line input.
//
// None of this is visible end-to-end, because validator cost dominates a real scan:
// through the CLI on a dense single-line file the whole change measured +1.7% to +8.9%
// and the scan stayed linear. That masking is exactly why the shape is measured here.

// columnsAbsoluteCeiling bounds the largest sample.
//
// Sized from measurement with real headroom: the biggest fixture here costs single-digit
// milliseconds locally, so this catches an order-of-magnitude regression while
// tolerating a heavily loaded shared runner. It is not a micro-benchmark.
const columnsAbsoluteCeiling = 4 * time.Second

// buildDistinctOnOneLine returns k matches for k DISTINCT values that all sit on one
// line, which is the worst case for a per-value cursor.
func buildDistinctOnOneLine(k int) []Match {
	var sb strings.Builder
	sb.Grow(k * 20)
	vals := make([]string, 0, k)
	for i := 0; i < k; i++ {
		v := fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000)
		vals = append(vals, v)
		sb.WriteString("SSN ")
		sb.WriteString(v)
		sb.WriteString(" ")
	}
	line := sb.String()

	out := make([]Match, 0, k)
	for _, v := range vals {
		out = append(out, Match{
			Text:       v,
			Type:       "SSN",
			LineNumber: 1,
			Context:    ContextInfo{FullLine: line},
		})
	}
	return out
}

// buildRepeatedOnOneLine returns k matches for the SAME value repeated k times on one
// line — the case the cursor is designed for, which must stay linear.
func buildRepeatedOnOneLine(k int) []Match {
	const v = "449-87-4100"
	line := strings.Repeat("SSN "+v+" ", k)
	out := make([]Match, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, Match{
			Text:       v,
			Type:       "SSN",
			LineNumber: 1,
			Context:    ContextInfo{FullLine: line},
		})
	}
	return out
}

// timeAssign runs AssignLineColumns and asserts the assignment actually happened.
//
// The floor is the non-vacuity signal: a function that stopped assigning columns would
// be fast and would leave every consumer back on a first-occurrence search, which is
// the defect this machinery exists to remove. Distinctness is checked too, because
// assigning every match the SAME column is also fast and also wrong.
func timeAssign(t *testing.T, matches []Match, wantDistinct bool) time.Duration {
	t.Helper()

	start := time.Now()
	AssignLineColumns(matches)
	elapsed := time.Since(start)

	seen := make(map[int]struct{}, len(matches))
	for i := range matches {
		if matches[i].StartColumn <= 0 {
			t.Fatalf("match %d of %d has no column — a timing target must never accept an "+
				"assignment that silently stopped happening", i, len(matches))
		}
		if matches[i].EndColumn <= matches[i].StartColumn {
			t.Fatalf("match %d has columns %d-%d", i, matches[i].StartColumn, matches[i].EndColumn)
		}
		if wantDistinct {
			if _, dup := seen[matches[i].StartColumn]; dup {
				t.Fatalf("column %d assigned twice — collapsing every match onto one column "+
					"is fast and is the exact bug this replaces", matches[i].StartColumn)
			}
			seen[matches[i].StartColumn] = struct{}{}
		}
	}
	return elapsed
}

// TestAssignLineColumnsComplexityRepeatedValue: the cursor's own case must be linear.
func TestAssignLineColumnsComplexityRepeatedValue(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	const baseK, bigK = 2000, 8000 // 4x

	tBase := timeAssign(t, buildRepeatedOnOneLine(baseK), true)
	tBig := timeAssign(t, buildRepeatedOnOneLine(bigK), true)

	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x input, ONE repeated value: %.1fx (base=%v big=%v) — the cursor advances past "+
		"each occurrence and the line-id memo removes the per-match line hash, so this "+
		"walks the line once. Was 18.5x before the memo.", ratio, tBase, tBig)

	if tBig > columnsAbsoluteCeiling {
		t.Errorf("assigning columns for %d repeated occurrences took %v (> %v) — the cursor "+
			"is no longer advancing, or the per-match line hash is back",
			bigK, tBig, columnsAbsoluteCeiling)
	}
}

// TestAssignLineColumnsComplexityDistinctValues is the ratchet on the known shape.
func TestAssignLineColumnsComplexityDistinctValues(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	const baseK, bigK = 2000, 8000 // 4x

	tBase := timeAssign(t, buildDistinctOnOneLine(baseK), true)
	tBig := timeAssign(t, buildDistinctOnOneLine(bigK), true)

	// LOGGED, not asserted. Each distinct value owns its cursor and therefore scans
	// from the line start, so 4x input is expected to cost well over 4x here. The
	// number is recorded so a human can see the shape move.
	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x input, K DISTINCT values on one line: %.1fx (base=%v big=%v) — informational. "+
		"Each value owns a cursor starting at zero, so this is O(K x line length); linear "+
		"would be 4x.", ratio, tBase, tBig)

	if tBig > columnsAbsoluteCeiling {
		t.Errorf("assigning columns for %d distinct values on one line took %v (> %v) — a "+
			"regression of this size means the per-value scan got worse than a single pass "+
			"over the line", bigK, tBig, columnsAbsoluteCeiling)
	}
}

// A file of MANY LINES must be linear in the number of lines: interning keys each line
// separately, so no cross-line work should accumulate. This is the ordinary-document
// shape, as opposed to the pathological single line above.
func TestAssignLineColumnsComplexityManyLines(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	build := func(lines int) []Match {
		out := make([]Match, 0, lines)
		for i := 0; i < lines; i++ {
			v := fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000)
			line := fmt.Sprintf("row %d SSN %s end", i, v)
			out = append(out, Match{
				Text: v, Type: "SSN", LineNumber: i + 1,
				Context: ContextInfo{FullLine: line},
			})
		}
		return out
	}

	const baseN, bigN = 5000, 20000 // 4x

	tBase := timeAssign(t, build(baseN), false)
	tBig := timeAssign(t, build(bigN), false)

	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x input, one match per line across many lines: %.1fx (base=%v big=%v)",
		ratio, tBase, tBig)

	if tBig > columnsAbsoluteCeiling {
		t.Errorf("assigning columns across %d lines took %v (> %v) — the ordinary document "+
			"shape must stay linear in the number of lines", bigN, tBig, columnsAbsoluteCeiling)
	}
}
