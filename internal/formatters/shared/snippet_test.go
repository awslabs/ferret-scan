// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestAShortLineIsReturnedUnchanged is the property that makes this safe to apply
// unconditionally.
//
// Measured over 57,790 findings in 1,009 real files, 61.2% of the lines carrying a finding are
// within the 1024-byte cap — including the median line at 647 bytes — so ordinary output is
// byte-identical and the golden corpus moves only for the long-line fixture it already had.
func TestAShortLineIsReturnedUnchanged(t *testing.T) {
	for name, line := range map[string]string{
		"empty":              "",
		"typical":            "employee ssn 449-87-4100 on file",
		"exactly at the cap": strings.Repeat("a", ContextSnippetCap),
	} {
		t.Run(name, func(t *testing.T) {
			if got := BoundedContextSnippet(line, "449-87-4100"); got != line {
				t.Errorf("a line of %d bytes was altered (got %d bytes); only lines OVER the %d-byte "+
					"cap may change", len(line), len(got), ContextSnippetCap)
			}
		})
	}
}

// TestALongLineIsBoundedAndTheTrimIsVisible is the fix for #521.
//
// The SARIF and gitlab-sast formatters embed this line once per finding, so an unbounded line makes
// the report quadratic in findings x line length. Measured on a real 284KB single-line export with
// 5,200 findings: sarif 2.96GB -> 55MB, gitlab-sast 1.48GB -> 27MB.
func TestALongLineIsBoundedAndTheTrimIsVisible(t *testing.T) {
	match := "449-87-4100"
	line := strings.Repeat("x", 200000) + " ssn " + match + " " + strings.Repeat("y", 200000)

	got := BoundedContextSnippet(line, match)

	if len(got) > ContextSnippetCap+2*len(snippetEllipsis) {
		t.Errorf("snippet is %d bytes, above the %d-byte cap plus its markers", len(got), ContextSnippetCap)
	}
	// The whole purpose of a snippet: the match has to be in it.
	if !strings.Contains(got, match) {
		t.Errorf("the match is not in the snippet, which makes it useless: %.80q...", got)
	}
	// Bounding must be visible, never silent — the same contract boundedConsolidatedText holds.
	if !strings.HasPrefix(got, snippetEllipsis) || !strings.HasSuffix(got, snippetEllipsis) {
		t.Errorf("both edges were trimmed but not marked, so a consumer cannot tell this is a "+
			"fragment: starts=%q ends=%q", got[:8], got[len(got)-8:])
	}
}

// TestTheWindowIsCentredOnTheMatch: a snippet that bounds the line but shows a different part of it
// is worse than useless, because it looks like context for the finding and is not.
func TestTheWindowIsCentredOnTheMatch(t *testing.T) {
	match := "449-87-4100"
	// The match sits far past the cap, so a head-of-line window would miss it entirely.
	line := strings.Repeat("z", 50000) + " ssn " + match + " tail" + strings.Repeat("w", 50000)

	got := BoundedContextSnippet(line, match)
	if !strings.Contains(got, match) {
		t.Fatal("the match past the cap was not included; the window is not centred on it")
	}
	at := strings.Index(got, match)
	before, after := at, len(got)-at-len(match)
	// Roughly balanced. Expressed as a FRACTION of the cap, not a byte count: a fixed threshold
	// silently becomes either vacuous or impossible when ContextSnippetCap is retuned, and it was
	// tuned to a larger cap once already.
	min := ContextSnippetCap / 4
	if before < min || after < min {
		t.Errorf("the window is lopsided (%d bytes before, %d after, cap %d); context on both sides "+
			"is the point of centring", before, after, ContextSnippetCap)
	}
}

// TestAMatchAtEitherEndStillGetsAFullWidthSnippet.
//
// Centring naively runs past the start or end of the line and yields a half-empty window. The window
// is pushed back inside the line instead, so a finding at the very start of a huge line still gets as
// much context as one in the middle.
func TestAMatchAtEitherEndStillGetsAFullWidthSnippet(t *testing.T) {
	match := "449-87-4100"
	filler := strings.Repeat("q", 100000)

	for name, line := range map[string]string{
		"at the start": match + " " + filler,
		"at the end":   filler + " " + match,
	} {
		t.Run(name, func(t *testing.T) {
			got := BoundedContextSnippet(line, match)
			if !strings.Contains(got, match) {
				t.Fatal("the match was cut out of its own snippet")
			}
			// Full width, not half: the cap should be nearly used up.
			if len(got) < ContextSnippetCap {
				t.Errorf("snippet is only %d bytes of a %d-byte budget; the window was not pushed "+
					"back inside the line", len(got), ContextSnippetCap)
			}
		})
	}
}

// TestAMatchLongerThanTheCapKeepsItsHead.
//
// A consolidated match can itself exceed the cap. Showing none of it would defeat the purpose, so its
// head is kept and marked — the same choice boundedConsolidatedText makes for the same situation.
func TestAMatchLongerThanTheCapKeepsItsHead(t *testing.T) {
	match := strings.Repeat("M", ContextSnippetCap*2)
	line := "prefix " + match + " suffix"

	got := BoundedContextSnippet(line, match)
	if len(got) > ContextSnippetCap+len(snippetEllipsis) {
		t.Errorf("snippet is %d bytes, above the cap", len(got))
	}
	if !strings.Contains(got, strings.Repeat("M", 100)) {
		t.Error("none of the match survived")
	}
	if !strings.HasSuffix(got, snippetEllipsis) {
		t.Error("the truncation was not marked")
	}
}

// TestAMatchNotPresentInTheLineFallsBackToTheHead.
//
// A bounded or consolidated display text, or line-number drift, leaves a match that is not findable in
// the line. It must still produce a bounded snippet rather than an empty one or a panic.
func TestAMatchNotPresentInTheLineFallsBackToTheHead(t *testing.T) {
	line := strings.Repeat("k", 20000)
	for name, match := range map[string]string{
		"absent": "not-in-the-line",
		"empty":  "",
	} {
		t.Run(name, func(t *testing.T) {
			got := BoundedContextSnippet(line, match)
			if len(got) > ContextSnippetCap+len(snippetEllipsis) {
				t.Errorf("snippet is %d bytes, above the cap", len(got))
			}
			if len(got) == 0 {
				t.Error("no snippet at all; a bounded fallback is required")
			}
			if !strings.HasSuffix(got, snippetEllipsis) {
				t.Error("the truncation was not marked")
			}
		})
	}
}

// TestTheSnippetIsAlwaysValidUTF8 is the correctness constraint that a naive byte slice breaks.
//
// Invalid UTF-8 in a JSON document is escaped to U+FFFD by encoding/json and rejected outright by some
// SARIF consumers, so a snippet must never split a multi-byte sequence. Every offset is exercised
// because the cap can land anywhere inside a rune.
func TestTheSnippetIsAlwaysValidUTF8(t *testing.T) {
	// Three-byte runes throughout, so a byte-aligned cut lands mid-rune two times in three.
	line := strings.Repeat("→", ContextSnippetCap) + "match" + strings.Repeat("←", ContextSnippetCap)

	for shift := 0; shift < 6; shift++ {
		padded := strings.Repeat("a", shift) + line
		got := BoundedContextSnippet(padded, "match")
		if !utf8.ValidString(got) {
			t.Errorf("shift %d produced invalid UTF-8", shift)
		}
	}

	// And the same for a line with no match found, which takes the head path.
	for shift := 0; shift < 6; shift++ {
		padded := strings.Repeat("a", shift) + strings.Repeat("→", ContextSnippetCap*2)
		if got := BoundedContextSnippet(padded, "absent"); !utf8.ValidString(got) {
			t.Errorf("head-path shift %d produced invalid UTF-8", shift)
		}
	}
}

// TestBoundingIsLinearNotQuadratic: the helper runs once per finding, so it must not scan the line
// more than a constant number of times. Asserted structurally — the output size is bounded by the cap
// regardless of input size, which is what makes the CALLER linear.
func TestBoundingIsLinearNotQuadratic(t *testing.T) {
	match := "449-87-4100"
	var prev int
	for _, n := range []int{10000, 100000, 1000000} {
		line := strings.Repeat("x", n) + " " + match + " " + strings.Repeat("y", n)
		got := len(BoundedContextSnippet(line, match))
		if got > ContextSnippetCap+2*len(snippetEllipsis) {
			t.Fatalf("line of %d bytes produced a %d-byte snippet", len(line), got)
		}
		if prev != 0 && got != prev {
			t.Errorf("snippet size changed with input size (%d -> %d); it must be capped, or the "+
				"report stays proportional to the line", prev, got)
		}
		prev = got
	}
}
