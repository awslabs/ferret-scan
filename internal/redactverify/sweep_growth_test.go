// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactverify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// growthFixture is n lines, each carrying one distinct email (and a second distinct one on every third
// line), and the matches a scan reports for them: 4n/3 distinct values, every one still present in the
// text, which is the case the sweep exists for.
func growthFixture(n int) (string, []detector.Match) {
	var doc strings.Builder
	var ms []detector.Match
	for i := 0; i < n; i++ {
		a := fmt.Sprintf("user%06d.x%d@corp%d.example.org", i, (i*7919)%100000, i%97)
		line := fmt.Sprintf("line %d contact %s for details", i, a)
		vals := []string{a}
		if i%3 == 0 {
			b := fmt.Sprintf("second%06d@other.example.net", i)
			line += " cc " + b
			vals = append(vals, b)
		}
		doc.WriteString(line + "\n")
		for _, v := range vals {
			ms = append(ms, detector.Match{Text: v, Type: "EMAIL"})
		}
	}
	return doc.String(), ms
}

// growthBound is the ratio 4x the values may cost: linear reads about 4x, the per-value scan about 16x.
const growthBound = 9.0

// SweepRemaining must cost one pass over the document however many distinct values are reported.
// It used to scan the whole document once per value, and per spelling of each value (occurrenceKinds,
// redactverify.go:234, :239, :278, :305 on 3b9780b), so the cost was values x document and 90% of
// RedactString at 4,000 values and up (#1005; 0.10 / 0.20 / 0.70 / 2.76 s at 4k / 8k / 16k / 32k values).
//
// The instrument is the CPU clock through internal/perfguard (CPU time, GC off, minimum of 4 pairs),
// not allocated bytes: the defect copies nothing (the document is converted to []byte once, above the
// loop), so it has no allocation signature, and a count of bytes allocated reads the same for the
// regressed code. The document grows with the values, so correct code reads 4x, not 1x; what separates
// the two is 4x against 16x, and the bound sits between them.
//
// Readings, linux/amd64, Go 1.27.4, 1,000 -> 4,000 distinct values (base ~9 ms, big ~42 ms for the
// one-pass code; ~32 ms and ~470 ms for the per-value one), ratio of minimum CPU readings. Both
// margins, as TEST_PLAN requires (bound / worst correct reading, best regressed reading / bound):
//
//	                          correct, 4 pairs     regressed (control), 2 pairs   margins at bound 9.0
//	no -race, 6 runs          4.55 - 5.35x         15.00 - 16.19x                 9.0/5.35 = 1.68x, 15.00/9.0 = 1.67x
//	-race,    4 runs          4.49 - 5.40x         15.36 - 15.97x                 9.0/5.40 = 1.67x, 15.36/9.0 = 1.71x
//	alone at host load 43-58  4.55 - 5.67x         15.19 - 15.64x                 9.0/5.67 = 1.59x, 15.19/9.0 = 1.69x
//
// Inside a whole-module `go test ./...` at host load 75 on 16 CPUs the correct code read 9.08x once
// (pairs 4.72 8.09 10.37 9.06x) while the control read 14.97x: the CPU clock of a 40 ms fixture moves
// with its neighbours. The test name carries "ScalesLinearly" so the load skip list the wave scripts
// already use (BRIEF section 6) skips it there, and it is run alone afterwards.
//
// Correct code reads above 4x because the automaton and the result map outgrow the cache; the bound
// is the geometric middle of the worst correct and best regressed readings, so neither side is thin.
//
// The regressed side is the per-value implementation kept in reference_test.go, run on the same
// fixture as a control: if it ever reads under the bound the guard has gone blind, and the control
// fails rather than the guard passing for the wrong reason. -race does not preserve a growth ratio
// (TEST_PLAN: it compresses it), but here it moves both populations the same way and the bound holds
// under it, so there is no race/!race split; the readings under -race are recorded in the PR.
func TestSweepRemainingScalesLinearlyInDistinctValues(t *testing.T) {
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}
	const base, big = 750, 3000 // lines: 1,000 and 4,000 distinct values
	d0, m0 := growthFixture(base)
	d1, m1 := growthFixture(big)

	// Non-vacuity: every value is distinct, present, and swept, at both sizes. A ratio over a sweep
	// that removed nothing times nothing.
	for _, tc := range []struct {
		doc string
		ms  []detector.Match
	}{{d0, m0}, {d1, m1}} {
		out, swept, err := SweepRemaining(tc.doc, tc.ms, maskFor)
		if err != nil || len(swept) != len(tc.ms) || strings.Contains(out, "@corp") || strings.Contains(out, "@other") {
			t.Fatalf("fixture of %d values: swept %d, err %v, values left: %v", len(tc.ms), len(swept), err,
				strings.Contains(out, "@corp") || strings.Contains(out, "@other"))
		}
	}
	if len(m1) != 4*len(m0) {
		t.Fatalf("fixture sizes are %d and %d values, want a 4x step", len(m0), len(m1))
	}

	g, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { _, _, _ = SweepRemaining(d0, m0, maskFor) },
		func() { _, _, _ = SweepRemaining(d1, m1, maskFor) })
	if err != nil {
		t.Fatalf("measuring: %v", err)
	}
	t.Logf("4x values cost %s", g)
	if _, ok := g.Ticks(); !ok {
		t.Logf("growth ratio NOT asserted: %s", g.ResolutionNote())
		return
	}
	perfguard.ReportMargin(t, "redactverify sweep, correct", g, growthBound, perfguard.StayBelow)
	if g.Ratio > growthBound {
		t.Errorf("4x the distinct values cost %s: linear is ~4x and one scan per value ~16x", g)
	}

	// The control: the same fixture through the implementation this one replaced must read ABOVE the
	// bound. Two pairs, because each regressed reading is ~0.5 s and it sits far from the bound.
	c, err := perfguard.Measure(2,
		func() { _, _, _ = sweepRemainingReference(d0, m0, maskFor) },
		func() { _, _, _ = sweepRemainingReference(d1, m1, maskFor) })
	if err != nil {
		t.Fatalf("measuring the control: %v", err)
	}
	t.Logf("control (one scan per value) %s", c)
	perfguard.ReportMargin(t, "redactverify sweep, per-value control", c, growthBound, perfguard.StayAbove)
	if c.Ratio <= growthBound {
		t.Errorf("the per-value implementation reads %s, not above %.1f: this guard cannot tell it from linear", c, growthBound)
	}
}
