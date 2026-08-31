// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestCorrelationMethodInventory pins the set of correlation methods that exist.
//
// A CorrelationContextual value and a tryContextualMatch step between fuzzy and
// heuristic used to live here and could never be returned as a success: its scorer's
// analytic ceiling was 0.75 against the 0.8 confidenceThreshold it was measured
// against, and the step was only reachable in the one state where its own helper
// returned nil (#383). Deleting it changed no behaviour, which is why it was deleted
// rather than repaired.
//
// This test is what stops it coming back by accident. Re-adding a value to the enum
// re-adds a name to this inventory, and a name that is not in the live set fails
// here — before anyone has to rediscover that it can never fire. Adding a method
// deliberately means changing this list and saying, in the same change, which gate it
// is measured against and how it can clear it.
func TestCorrelationMethodInventory(t *testing.T) {
	// The live methods, in declaration order. The numeric values matter only in that
	// they must be contiguous from zero: CorrelationMethod is an iota enum, so a gap
	// would mean a value was removed without removing its slot.
	want := []struct {
		m    CorrelationMethod
		name string
	}{
		{CorrelationExact, "exact"},
		{CorrelationFuzzy, "fuzzy"},
		{CorrelationHeuristic, "heuristic"},
	}

	for i, w := range want {
		if int(w.m) != i {
			t.Errorf("%s has value %d, want %d: the enum is no longer contiguous from zero",
				w.name, int(w.m), i)
		}
		if got := w.m.String(); got != w.name {
			t.Errorf("CorrelationMethod(%d).String() = %q, want %q", int(w.m), got, w.name)
		}
	}

	// Every value outside the live set must be "unknown". Scanning past the end is the
	// point: a reintroduced contextual value would occupy one of these slots, and its
	// String() would name it.
	for v := len(want); v < len(want)+8; v++ {
		if got := CorrelationMethod(v).String(); got != "unknown" {
			t.Errorf("CorrelationMethod(%d).String() = %q, want %q. A correlation method has been "+
				"added; if it is meant to be returned, prove it can clear confidenceThreshold "+
				"(%.2f) and add it to this inventory. The contextual method removed in #383 "+
				"could not: its ceiling was 0.75.",
				v, got, "unknown", NewDefaultPositionCorrelator().confidenceThreshold)
		}
	}
}

// TestCorrelatePositionReturnsOnlyLiveMethods asserts the closed set of methods that
// can actually come out of CorrelatePosition, in the shape the only production caller
// uses.
//
// PlainTextRedactor.correlateMatchPosition passes the same string as extractedText and
// originalContent and derives the target from a line of it, so the target always occurs
// verbatim in the original. Every case below reproduces that shape.
//
// The test also requires that BOTH exact and fuzzy actually occur. That is not padding:
// a fixture that has stopped reaching one of them would let this test pass while
// asserting nothing about it, and the fuzzy path is the one that resolves any value
// repeated on its own line.
func TestCorrelatePositionReturnsOnlyLiveMethods(t *testing.T) {
	const ssn = "449-87-4100"
	dpc := NewDefaultPositionCorrelator()

	cases := []struct {
		name string
		doc  string
		line int
		want CorrelationMethod
		why  string
	}{
		{
			name: "unique value resolves exactly",
			doc:  "ssn " + ssn + " here\ntrailing",
			line: 1,
			want: CorrelationExact,
			why:  "one occurrence in scope scores 0.95, clearing the 0.8 gate",
		},
		{
			name: "value repeated on a LATER line still resolves exactly",
			doc:  "ssn " + ssn + " here\nagain " + ssn + " there",
			line: 1,
			want: CorrelationExact,
			why: "since #519 the occurrence count is taken within the reported line, so a copy " +
				"elsewhere no longer de-rates this one",
		},
		{
			name: "value repeated on the SAME line falls through to fuzzy",
			doc:  "ssn " + ssn + " and again " + ssn + " here\ntrailing",
			line: 1,
			want: CorrelationFuzzy,
			why: "two occurrences in scope score 0.95*(0.5+0.5/2) = 0.7125, below the gate; " +
				"calculateFuzzyMatchConfidence returns 0.8*1.0 for edit distance 0, which clears " +
				"a >= 0.8 gate exactly. This is the live fallback the contextual step sat behind",
		},
		{
			name: "three occurrences on one line also resolve as fuzzy",
			doc:  "a " + ssn + " b " + ssn + " c " + ssn + " d",
			line: 1,
			want: CorrelationFuzzy,
			why:  "0.95*(0.5+0.5/3) = 0.633, below the gate",
		},
	}

	seen := map[CorrelationMethod]int{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, ok := lineAt(tc.doc, tc.line)
			if !ok {
				t.Fatalf("fixture line %d does not exist", tc.line)
			}
			start := strings.Index(line, ssn)
			if start < 0 {
				t.Fatalf("fixture line %d does not hold the value, so this is not the caller's shape", tc.line)
			}
			pos := redactors.TextPosition{Line: tc.line, StartChar: start, EndChar: start + len(ssn)}

			got, err := dpc.CorrelatePosition(pos, tc.doc, []byte(tc.doc), "text")
			if err != nil {
				t.Fatalf("CorrelatePosition: %v", err)
			}
			seen[got.Method]++
			if got.Method != tc.want {
				t.Errorf("method = %s, want %s (%s)", got.Method, tc.want, tc.why)
			}
			// The offset must actually locate the value, or the redactor overwrites the
			// wrong bytes and the reported value ships in cleartext (#519).
			off := got.OriginalPosition.CharOffset
			if off < 0 || off+len(ssn) > len(tc.doc) || tc.doc[off:off+len(ssn)] != ssn {
				t.Errorf("offset %d does not point at the value", off)
			}
		})
	}

	if seen[CorrelationExact] == 0 || seen[CorrelationFuzzy] == 0 {
		t.Errorf("the table exercised exact=%d fuzzy=%d: a path that is never reached is not being "+
			"asserted about. The fuzzy branch in particular must stay live -- it resolves every "+
			"value repeated on its own line",
			seen[CorrelationExact], seen[CorrelationFuzzy])
	}

	// Breadth: a seeded sweep over the same shape must never produce anything outside
	// the live set, and must keep reaching both live paths.
	rng := rand.New(rand.NewSource(383))
	vals := []string{ssn, "4532015112830366", "(555) 867-5309", "jane.doe@example.com"}
	sweep := map[string]int{}
	for i := 0; i < 2000; i++ {
		var b strings.Builder
		for l := 0; l < 1+rng.Intn(4); l++ {
			v := vals[rng.Intn(len(vals))]
			b.WriteString(fmt.Sprintf("f%d %s ", l, v))
			if rng.Intn(2) == 0 {
				// Repeat on the same line: the only shape that de-rates the exact score.
				b.WriteString("and " + v + " ")
			}
			b.WriteString("tail\n")
		}
		doc := strings.TrimSuffix(b.String(), "\n")
		ln := 1 + rng.Intn(countLines(doc))
		line, _ := lineAt(doc, ln)
		v := vals[rng.Intn(len(vals))]
		start := strings.Index(line, v)
		if start < 0 {
			continue
		}
		pos := redactors.TextPosition{Line: ln, StartChar: start, EndChar: start + len(v)}
		got, err := dpc.CorrelatePosition(pos, doc, []byte(doc), "text")
		if err != nil {
			sweep["error"]++
			continue
		}
		sweep[got.Method.String()]++
		switch got.Method {
		case CorrelationExact, CorrelationFuzzy, CorrelationHeuristic:
		default:
			t.Fatalf("CorrelatePosition returned method %q (value %d), which is not a live method; "+
				"doc=%q pos=%+v", got.Method, int(got.Method), doc, pos)
		}
	}
	t.Logf("sweep method distribution: %v", sweep)
	if sweep["exact"] == 0 || sweep["fuzzy"] == 0 {
		t.Errorf("sweep reached exact=%d fuzzy=%d; it is no longer exercising both live paths, so "+
			"the closed-set assertion above is weaker than it looks",
			sweep["exact"], sweep["fuzzy"])
	}
}

// TestSurvivingScorersCanClearTheGate records, executably, the arithmetic that decided
// #383: a correlation method is only worth having if its scorer can reach the threshold
// it is measured against.
//
// Both surviving scorers can, by exactly the margins named here. The deleted contextual
// scorer could not — it was 0.75 * contextSimilarity * (0.8 + 0.2*lengthBonus) with both
// factors bounded by 1, so 0.75 was its maximum, and maximising it over 20,001 inputs
// returned 0.75 exactly against a gate of 0.8.
func TestSurvivingScorersCanClearTheGate(t *testing.T) {
	dpc := NewDefaultPositionCorrelator()
	gate := dpc.confidenceThreshold

	if gate != 0.8 {
		t.Fatalf("confidenceThreshold is %v, not 0.8; every margin below was measured against 0.8", gate)
	}

	// A uniquely-located exact match: 0.95, clears with room to spare.
	if got := exactMatchConfidence(1); got < gate {
		t.Errorf("exactMatchConfidence(1) = %v, below the %v gate: the primary path cannot resolve "+
			"anything", got, gate)
	}

	// A verbatim fuzzy match: 0.8*(1 - 0/maxLen) = 0.8, which clears a `>=` gate by
	// exactly nothing. The margin being zero is why this is asserted rather than assumed:
	// any downward nudge to the 0.8 base, or a `>` gate, silently retires the fallback
	// that resolves every value repeated on its own line.
	const v = "449-87-4100"
	if got := dpc.calculateFuzzyMatchConfidence(v, v, 0); got < gate {
		t.Errorf("calculateFuzzyMatchConfidence for edit distance 0 = %v, below the %v gate: the "+
			"fuzzy fallback can no longer succeed, so any value repeated on its own line now "+
			"falls through to the 0.6-or-less heuristic", got, gate)
	}

	// And a repeated exact match must NOT clear it, since that fall-through is what makes
	// the fuzzy path load-bearing.
	if got := exactMatchConfidence(2); got >= gate {
		t.Errorf("exactMatchConfidence(2) = %v, which now clears the %v gate; the fuzzy path is no "+
			"longer reached for same-line duplicates", got, gate)
	}
}
