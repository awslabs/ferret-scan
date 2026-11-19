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

// perValueBound is how many times the per-value implementation (kept in reference_test.go) must cost
// what the one-pass sweep costs on the SAME 4,000-value input. Measured 15x; a sweep that went back to
// one scan per value would read 1x.
const perValueBound = 3.0

// SweepRemaining must cost one pass over the document however many distinct values are reported.
// It used to scan the whole document once per value, and per spelling of each value (occurrenceKinds,
// redactverify.go:234, :239, :278, :305 on 3b9780b), so the cost was values x document and 90% of
// RedactString at 4,000 values and up (#1005; 0.10 / 0.20 / 0.70 / 2.76 s at 4k / 8k / 16k / 32k values).
//
// What is ASSERTED is the one-pass sweep's cost against the per-value implementation on one input,
// 4,000 distinct values, both timed within the same measurement on the CPU clock (internal/perfguard:
// GC off, minimum of 4 interleaved pairs). The two see the same machine at the same moment, so host
// load, a runner image or the cache moves both and the ratio stays put; a growth ratio of the one-pass
// code alone does not have that property here, and that is why it is logged and not asserted:
//
//   - The defect copies nothing (the document is converted to []byte once, above the loop), so
//     allocated bytes read the same for the regressed code and cannot be the unit.
//   - A fixed document with 1k -> 4k values does not separate the populations either: the one-pass
//     code's per-value work (XML spellings, the automaton, the result map) reads 4.3-4.7x for 4x the
//     values, the same as the per-value scan's 4.3x.
//   - Growing the document with the values (1k -> 4k, the shape the first version of this guard
//     asserted at bound 9.5) reads 4x ideal for linear and 16x for the per-value scan, but the correct
//     code's reading moves with the host: 5.1-6.3x at load 45-60, 6.2-7.1x at load 25-32, 9.08x once
//     inside a whole-module run at load 75, 4.5-5.4x quiet, because the 4k automaton (~3 MB of tables)
//     outgrows the cache that the 1k one fits. #1034's CPU-clock guard went red on macos-latest for the
//     same reason (2.67x correct against a 2.6 bound), so this guard does not stake its assertion on it.
//
// Readings, linux/amd64 (16 CPUs, load 25-32), Go 1.27.4, 4,000 distinct values (3,000 lines):
//
//	                     one-pass (base)   per-value reference (big)   ratio           margin at bound 3.0
//	no -race, 3 runs     31.5 - 31.9 ms      457 - 464 ms              14.45 - 14.65x  4.8x (StayAbove)
//	-race,    2 runs     154 - 156 ms        2.39 - 2.45 s             15.5 - 15.7x    5.2x
//	regressed (the one-pass arm replaced by the reference, overlay)     1.00x           0.33x: FAILS
//
// Per-pair samples sit within 12.5-16x on every run; the one-pass growth logged beside them on the same
// runs read 6.1-6.5x (pairs 2.3-7.7x) plain and 5.2-5.4x under -race.
//
// The growth of the one-pass code alone (1k -> 4k values, document growing with them) is logged on
// every run so the curve stays visible in CI's -v output; it is not asserted.
//
// perfguard declines the assertion where the CPU tick is too coarse for the base reading (Windows:
// 15.6 ms ticks against a ~30 ms base), as every guard in this repository does; the skip is logged.
func TestSweepRemainingScalesLinearlyInDistinctValues(t *testing.T) {
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}
	const base, big = 750, 3000 // lines: 1,000 and 4,000 distinct values
	d0, m0 := growthFixture(base)
	d1, m1 := growthFixture(big)

	// Non-vacuity: every value is distinct, present, and swept, at both sizes, by both implementations.
	// A ratio over a sweep that removed nothing times nothing.
	for _, tc := range []struct {
		doc string
		ms  []detector.Match
	}{{d0, m0}, {d1, m1}} {
		for name, sweep := range map[string]func(string, []detector.Match, func(detector.Match) (string, error)) (string, []string, error){
			"one-pass": SweepRemaining, "per-value reference": sweepRemainingReference,
		} {
			out, swept, err := sweep(tc.doc, tc.ms, maskFor)
			if err != nil || len(swept) != len(tc.ms) || strings.Contains(out, "@corp") || strings.Contains(out, "@other") {
				t.Fatalf("%s, fixture of %d values: swept %d, err %v, values left: %v", name, len(tc.ms), len(swept), err,
					strings.Contains(out, "@corp") || strings.Contains(out, "@other"))
			}
		}
	}
	if len(m1) != 4*len(m0) {
		t.Fatalf("fixture sizes are %d and %d values, want a 4x step", len(m0), len(m1))
	}

	// Logged, not asserted: the one-pass code's own growth for 4x the values.
	g, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { _, _, _ = SweepRemaining(d0, m0, maskFor) },
		func() { _, _, _ = SweepRemaining(d1, m1, maskFor) })
	if err != nil {
		t.Fatalf("measuring growth: %v", err)
	}
	t.Logf("one-pass sweep, 4x values: %s (logged, not asserted; linear is ~4x, one scan per value ~16x)", g)

	// Asserted: at 4,000 values the per-value implementation must cost at least perValueBound times
	// the one-pass sweep. "base" is the one-pass sweep and "big" the reference, so Ratio is
	// reference / one-pass.
	r, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { _, _, _ = SweepRemaining(d1, m1, maskFor) },
		func() { _, _, _ = sweepRemainingReference(d1, m1, maskFor) })
	if err != nil {
		t.Fatalf("measuring the two implementations: %v", err)
	}
	t.Logf("per-value reference / one-pass sweep at %d values: %s", len(m1), r)
	if _, ok := r.Ticks(); !ok {
		t.Logf("ratio NOT asserted: %s", r.ResolutionNote())
		return
	}
	perfguard.ReportMargin(t, "redactverify sweep, per-value reference over one-pass", r, perValueBound, perfguard.StayAbove)
	if r.Ratio < perValueBound {
		t.Errorf("the one-pass sweep costs %s of one scan per value at %d values; want the per-value code at least %.1fx dearer (it reads ~15x): the sweep has a per-value pass again",
			r, len(m1), perValueBound)
	}
}
