// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestSearchScopeLocatesTheReportedLine covers the boundary cases of the line lookup, because every
// one of them decides which bytes a redactor will overwrite.
func TestSearchScopeLocatesTheReportedLine(t *testing.T) {
	const doc = "first line\nsecond line\nthird"

	for _, tc := range []struct {
		name string
		line int
		want string
		ok   bool
	}{
		{"first line", 1, "first line", true},
		{"middle line", 2, "second line", true},
		{"last line with no trailing newline", 3, "third", true},
		{"line past the end", 4, "", false},
		{"line zero", 0, "", false},
		{"negative line", -1, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := searchScope(redactors.TextPosition{Line: tc.line}, doc)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if got := doc[start:end]; got != tc.want {
				t.Errorf("scope = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSearchScopeHandlesAnEmptyLine: a blank line is a legitimate scope of zero length, and must not
// be reported as absent — that would silently push resolution back to the document-wide search.
func TestSearchScopeHandlesAnEmptyLine(t *testing.T) {
	const doc = "a\n\nc"
	start, end, ok := searchScope(redactors.TextPosition{Line: 2}, doc)
	if !ok {
		t.Fatal("an empty line was reported as absent")
	}
	if start != end {
		t.Errorf("scope [%d,%d) is not empty", start, end)
	}
}

// TestExactMatchResolvesToTheReportedLine is the unit-level regression for #519.
//
// The value occurs on two lines. Resolution must return the occurrence on the line the match was
// REPORTED on, not the first occurrence in the document — the latter sent a redactor to overwrite the
// wrong bytes and left the reported value in cleartext.
func TestExactMatchResolvesToTheReportedLine(t *testing.T) {
	const value = "0151 1283 0366"
	doc := "card 4532 " + value + " here\ncall " + value + " now"

	first := strings.Index(doc, value)
	second := strings.Index(doc[first+1:], value) + first + 1
	if first == second || second <= first {
		t.Fatalf("fixture does not hold two occurrences (first=%d second=%d)", first, second)
	}

	// Reported on line 2: must resolve to the SECOND occurrence.
	idx, count, ok := exactMatchInScope(redactors.TextPosition{Line: 2}, value, doc)
	if !ok {
		t.Fatal("the value was not resolved at all")
	}
	if idx != second {
		t.Errorf("resolved to offset %d (the occurrence on line %d); want %d, the occurrence on the "+
			"reported line 2. Resolving document-wide returns the first occurrence whatever line the "+
			"match came from, which is the #519 leak.",
			idx, 1+strings.Count(doc[:idx], "\n"), second)
	}
	// One occurrence on that line, so it is unambiguous there however many copies the document holds.
	if count != 1 {
		t.Errorf("occurrence count in scope = %d, want 1; the count feeds the confidence that decides "+
			"whether this resolution is trusted at all", count)
	}

	// And reported on line 1: the FIRST occurrence.
	idx, _, ok = exactMatchInScope(redactors.TextPosition{Line: 1}, value, doc)
	if !ok || idx != first {
		t.Errorf("line 1 resolved to %d, want %d", idx, first)
	}
}

// TestTryExactMatchUsesTheScopedResolution tests the CALLER, not just the helper.
//
// It exists because a mutation reverting tryExactMatch to a document-wide strings.Index survived:
// exactMatchInScope was still correct and TestExactMatchResolvesToTheReportedLine called it directly,
// so nothing observed that tryExactMatch had stopped using it. The same shape as testing a method
// while nothing asserts its caller invokes it.
//
// Note what makes that mutation survivable end to end: with the exact path unscoped, a value occurring
// twice scores 0.95*(0.5+0.5/2) = 0.7125, the caller's 0.8 gate rejects it, and the scoped FUZZY path
// answers correctly instead. So the leak stays closed by accident. That is precisely why both paths are
// scoped and both are asserted — relying on the gate to reject the wrong answer is what produced #519.
func TestTryExactMatchUsesTheScopedResolution(t *testing.T) {
	const value = "0151 1283 0366"
	doc := "card 4532 " + value + " here\ncall " + value + " now"
	first := strings.Index(doc, value)
	second := strings.Index(doc[first+1:], value) + first + 1

	dpc := NewDefaultPositionCorrelator()
	got := dpc.tryExactMatch(redactors.TextPosition{Line: 2}, value, doc, "text")
	if got == nil {
		t.Fatal("tryExactMatch returned nothing")
	}
	if got.OriginalPosition.CharOffset != second {
		t.Errorf("tryExactMatch resolved a line-2 report to offset %d (line 1); want %d. It is no "+
			"longer using the line-scoped resolution.", got.OriginalPosition.CharOffset, second)
	}
	// One occurrence on the reported line, so it is unambiguous there and must earn the unique-match
	// confidence. A document-wide count would de-rate it to 0.7125 and the caller's 0.8 gate would
	// reject a resolution that is in fact exactly right.
	if got.ConfidenceScore < 0.8 {
		t.Errorf("confidence %.4f is below the 0.8 gate the caller applies, so this correct "+
			"resolution would be thrown away", got.ConfidenceScore)
	}
}

// TestExactMatchFallsBackWhenTheLineDoesNotHoldTheValue pins the fallback.
//
// A bounded or consolidated match, or line-number drift from an extractor, leaves a match whose
// recorded line does not contain its text. Without the fallback such a match would stop being
// located, and a value that is never located is never redacted — trading one leak for another.
func TestExactMatchFallsBackWhenTheLineDoesNotHoldTheValue(t *testing.T) {
	const value = "0151 1283 0366"
	doc := "header\ncall " + value + " now\nfooter"

	want := strings.Index(doc, value)

	// Reported on line 1, which does not hold it.
	idx, count, ok := exactMatchInScope(redactors.TextPosition{Line: 1}, value, doc)
	if !ok {
		t.Fatal("the fallback did not locate the value; it would never be redacted")
	}
	if idx != want {
		t.Errorf("fallback resolved to %d, want the document occurrence at %d", idx, want)
	}
	if count != 1 {
		t.Errorf("document occurrence count = %d, want 1", count)
	}

	// And a line beyond the document falls back the same way.
	if idx, _, ok = exactMatchInScope(redactors.TextPosition{Line: 99}, value, doc); !ok || idx != want {
		t.Errorf("out-of-range line resolved to %d ok=%v, want %d true", idx, ok, want)
	}
}

// TestExactMatchReportsAbsence: a value that is nowhere in the document must be reported as
// unresolvable rather than resolved to offset 0, which would overwrite the start of the file.
func TestExactMatchReportsAbsence(t *testing.T) {
	if idx, _, ok := exactMatchInScope(redactors.TextPosition{Line: 1}, "absent", "some other text"); ok {
		t.Errorf("a value absent from the document resolved to offset %d", idx)
	}
}

// TestFuzzyMatchIsAlsoScopedToTheLine closes the path the leak actually travelled.
//
// For a value occurring twice, exactMatchConfidence de-rates to 0.95*(0.5+0.5/2) = 0.7125 and the
// caller's 0.8 gate rejects it — correctly. But calculateFuzzyMatchConfidence returns 0.8*1.0 = 0.8
// for an edit distance of 0, which clears a `>=` 0.8 gate by exactly nothing and admitted the same
// document-wide offset the exact path had just refused. Scoping the fuzzy search too is what stops
// that being a way back in.
func TestFuzzyMatchIsAlsoScopedToTheLine(t *testing.T) {
	const value = "0151 1283 0366"
	doc := "card 4532 " + value + " here\ncall " + value + " now"
	second := strings.Index(doc[strings.Index(doc, value)+1:], value) + strings.Index(doc, value) + 1

	dpc := NewDefaultPositionCorrelator()
	got := dpc.tryFuzzyMatch(redactors.TextPosition{Line: 2}, value, doc, "text")
	if got == nil {
		t.Fatal("the fuzzy matcher returned nothing")
	}
	if got.OriginalPosition.CharOffset != second {
		t.Errorf("fuzzy resolved to offset %d, want %d on the reported line 2",
			got.OriginalPosition.CharOffset, second)
	}
	// The offset is absolute, not relative to the scoped slice: a relative one would point into the
	// wrong place in the document and is the obvious way to get this wrong.
	if !strings.HasPrefix(doc[got.OriginalPosition.CharOffset:], value) {
		t.Errorf("offset %d does not point at the value; it looks relative to the scoped slice rather "+
			"than to the document", got.OriginalPosition.CharOffset)
	}
}

// TestScopedResolutionCostsFewerWholeDocumentPasses records why this is not a correctness/performance
// trade.
//
// Resolving document-wide took TWO whole passes per match — one strings.Index plus one strings.Count.
// The scoped form makes one pass to find the line and then works within it. Asserted as a property of
// the result rather than by timing: the count returned is the in-scope count, which is only possible
// if the Count ran over the line rather than the document.
func TestScopedResolutionCostsFewerWholeDocumentPasses(t *testing.T) {
	const value = "x9"
	// The value appears 50 times across the document but once on line 2.
	var b strings.Builder
	b.WriteString("head " + value + "\n")
	b.WriteString("line2 " + value + "\n")
	for i := 0; i < 48; i++ {
		b.WriteString("filler " + value + "\n")
	}
	doc := b.String()

	if total := strings.Count(doc, value); total != 50 {
		t.Fatalf("fixture holds %d occurrences, want 50", total)
	}

	_, count, ok := exactMatchInScope(redactors.TextPosition{Line: 2}, value, doc)
	if !ok {
		t.Fatal("not resolved")
	}
	if count != 1 {
		t.Errorf("count = %d; a document-wide Count would return 50, so this is still scanning the "+
			"whole document", count)
	}
}
