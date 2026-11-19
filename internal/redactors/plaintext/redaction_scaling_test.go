// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// scalingFixture is n lines, each holding one distinct email (and a second on every 3rd line, so
// writes also land left of an earlier write on the same line), with the matches a scan reports.
func scalingFixture(n int) (string, []detector.Match) {
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
			ms = append(ms, detector.Match{Text: v, Type: "EMAIL", LineNumber: i + 1, Confidence: 90,
				Context: detector.ContextInfo{FullLine: line}})
		}
	}
	return doc.String(), ms
}

// minAllocatedBytes is the fewest heap bytes one call of f allocated over reps calls. TotalAlloc is
// cumulative and never decreases with GC, so it counts work done rather than reading a clock; the
// minimum discards the few KB the test runner's own goroutine may allocate concurrently.
func minAllocatedBytes(reps int, f func()) uint64 {
	var best uint64
	for i := 0; i < reps; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		if d := after.TotalAlloc - before.TotalAlloc; i == 0 || d < best {
			best = d
		}
	}
	return best
}

// Redacting N distinct values must cost about twice what N/2 costs. The pass used to rebuild the whole
// document string and re-copy it into the position correlator for every match, so doubling the values
// roughly tripled the time (#1005: 0.31, 0.60, 1.68, 4.29 s at 1k, 2k, 4k, 8k values; the in-process
// ratio from 4k to 8k was 2.7 to 3.0 and rose with N).
//
// What is timed is redactPositional, the pass this package owns. The completeness sweep that follows
// it (redactverify.SweepRemaining) is not measured here: it is 90% of the time from 4k values up and
// would hide the pass (measured in the PR for #1005).
//
// The unit is allocated bytes (runtime.MemStats.TotalAlloc across one call), not CPU time. Each of
// the three removed costs copied bytes once per match (the document rebuilt, strings.Split over the
// document, the document converted to []byte for the correlator), so the defect has an allocation
// signature, and allocation is a count no scheduler or runner image can move: the CPU clock read
// 2.67x for the CORRECT code on the macos-latest runner against a 2.6 bound, where the same code
// read 1.62-2.43x on linux/amd64. Readings, Go 1.27.4, linux/amd64, 8k -> 16k values (the three
// fixes reverted in place for the regressed rows); identical to 3 significant figures under -race,
// so there is no race/!race split, and repeated readings differ by under 1 KB:
//
//	                         8,000 values       16,000 values       ratio
//	correct, correlation      46,641,672 B        94,631,736 B       2.03x
//	correct, text search      33,037,872 B        67,417,464 B       2.04x
//	regressed, correlation    20,552,210,504 B    82,190,428,968 B   4.00x
//	regressed, text search    5,685,474,144 B     22,746,369,272 B   4.00x
//
// Bound 2.85 is the geometric midpoint. Margins, both recorded: bound / worst correct reading =
// 2.85 / 2.04 = 1.40x, and least regressed reading / bound = 4.00 / 2.85 = 1.40x. The 4k -> 8k step
// reads 2.04-2.06x correct and 3.95x regressed, so the bound holds one size down as well. The
// fixture's value-count is a MINIMUM, not a ceiling: findings must be > 0 and distinct at both
// sizes or the ratio measures nothing.
//
// shortcut: redactverify.SweepRemaining scans the document once per value (redactverify.go:234, :239,
// :278, :305) and is still quadratic; it is outside this package, so no guard here can cover it. When
// it is made linear, add a whole-RedactString row at 16k/32k beside this one.
func TestRedactionAllocationIsLinearInDistinctValues(t *testing.T) {
	const small, big = 8000, 16000
	const maxRatio = 2.85
	for _, tc := range []struct {
		name        string
		correlation bool
	}{{"position-correlation", true}, {"text-search", false}} {
		t.Run(tc.name, func(t *testing.T) {
			ptr := NewPlainTextRedactor(nil, nil)
			ptr.SetPositionCorrelationEnabled(tc.correlation)
			run := func(n int) uint64 {
				doc, ms := scalingFixture(n)
				distinct := map[string]bool{}
				for _, m := range ms {
					distinct[m.Text] = true
				}
				if len(distinct) != len(ms) || len(ms) < n {
					t.Fatalf("fixture: %d matches, %d distinct for n=%d", len(ms), len(distinct), n)
				}
				text, _, mapping, err := ptr.redactPositional(doc, ms, redactors.RedactionSimple, nil)
				if err != nil {
					t.Fatal(err)
				}
				out := text.String()
				if len(mapping) != len(ms) || strings.Contains(out, "@corp") || strings.Contains(out, "@other") {
					t.Fatalf("n=%d: %d of %d redacted, values left: %v", n, len(mapping), len(ms), strings.Contains(out, "@corp"))
				}
				return minAllocatedBytes(3, func() { _, _, _, _ = ptr.redactPositional(doc, ms, redactors.RedactionSimple, nil) })
			}
			a, b := run(small), run(big)
			ratio := float64(b) / float64(a)
			t.Logf("%d values: %d B allocated, %d values: %d B, ratio %.2f (bound %.2f)", small, a, big, b, ratio, maxRatio)
			t.Logf("margin %s: %.2fx, must stay below %.2f — margin %.2fx (rule %.1fx), allocated bytes, %s",
				tc.name, ratio, maxRatio, perfguard.Margin(ratio, maxRatio, perfguard.StayBelow), perfguard.ThinMargin, perfguard.Runner())
			if ratio > maxRatio {
				t.Fatalf("allocated bytes grew %.2fx for %dx the values; want <= %.2f (linear is 2.0)", ratio, big/small, maxRatio)
			}
		})
	}
}
