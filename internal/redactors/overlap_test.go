// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func mkMatch(dataType, text, fullLine string, line int) detector.Match {
	return detector.Match{
		Text:       text,
		Type:       dataType,
		LineNumber: line,
		Context:    detector.ContextInfo{FullLine: fullLine},
	}
}

func types(ms []detector.Match) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Type
	}
	return out
}

func TestResolveOverlaps_DropsContainedMatch(t *testing.T) {
	line := "spaced 4532 0151 1283 0366"
	matches := []detector.Match{
		mkMatch("VISA", "4532 0151 1283 0366", line, 1),
		mkMatch("PHONE", "0151 1283 0366", line, 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 1 || got[0].Type != "VISA" {
		t.Fatalf("expected only the wider VISA match to survive, got %v", types(got))
	}
}

func TestResolveOverlaps_DropWinsRegardlessOfInputOrder(t *testing.T) {
	line := "spaced 4532 0151 1283 0366"
	// Contained match listed first.
	matches := []detector.Match{
		mkMatch("PHONE", "0151 1283 0366", line, 1),
		mkMatch("VISA", "4532 0151 1283 0366", line, 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 1 || got[0].Type != "VISA" {
		t.Fatalf("expected only VISA to survive regardless of order, got %v", types(got))
	}
}

func TestResolveOverlaps_KeepsNonOverlapping(t *testing.T) {
	line := "call 212-555-0142 or card 4532-0151-1283-0366"
	matches := []detector.Match{
		mkMatch("PHONE", "212-555-0142", line, 1),
		mkMatch("VISA", "4532-0151-1283-0366", line, 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 2 {
		t.Fatalf("expected both disjoint matches to survive, got %v", types(got))
	}
}

func TestResolveOverlaps_DifferentLinesNeverSubsume(t *testing.T) {
	// Identical text on different lines must not subsume each other.
	matches := []detector.Match{
		mkMatch("VISA", "4532 0151 1283 0366", "card 4532 0151 1283 0366", 1),
		mkMatch("PHONE", "0151 1283 0366", "phone 0151 1283 0366", 2),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 2 {
		t.Fatalf("matches on different lines must both survive, got %v (len %d)", types(got), len(got))
	}
}

func TestResolveOverlaps_SameLineNumberDifferentSourceNeverSubsume(t *testing.T) {
	// Regression: an Office package numbers lines per part, so a metadata match
	// in docProps/core.xml and a body match in word/document.xml both arrive as
	// "line 1" with offsets measured against DIFFERENT strings. Comparing those
	// offsets is meaningless. Here the body SSN's span [9,20) falls numerically
	// inside the author's [8,20), and the SSN was dropped before redaction was
	// ever attempted — leaving it in cleartext in the "redacted" output.
	//
	// The two matches are on different lines despite sharing a line NUMBER, so
	// neither may subsume the other.
	matches := []detector.Match{
		mkMatch("SSN", "449-87-4100", "body ssn 449-87-4100", 1),
		mkMatch("AUTHOR_INFO", "Jane Analyst", "Author: Jane Analyst", 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 2 {
		t.Fatalf("matches from different source text must both survive; got %v (len %d) — a dropped match is never redacted, so this is a cleartext leak", types(got), len(got))
	}
	var sawSSN bool
	for _, m := range got {
		if m.Type == "SSN" {
			sawSSN = true
		}
	}
	if !sawSSN {
		t.Fatalf("the body SSN must survive: it lives in a different part than the metadata match, got %v", types(got))
	}
}

func TestResolveOverlaps_SameLineNumberSameTextStillSubsumes(t *testing.T) {
	// The complement of the case above: when the FullLine really is the same
	// line, containment must still collapse to the widest span. This is what
	// keeps the original card/phone fix working.
	line := "card 4532 0151 1283 0366"
	matches := []detector.Match{
		mkMatch("VISA", "4532 0151 1283 0366", line, 1),
		mkMatch("PHONE", "0151 1283 0366", line, 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 1 || got[0].Type != "VISA" {
		t.Fatalf("identical FullLine must still collapse to the widest span, got %v", types(got))
	}
}

func TestResolveOverlaps_PartialOverlapKeepsBoth(t *testing.T) {
	// Overlapping but neither fully contains the other: keep both (dropping
	// either would leave part of it exposed).
	line := "aaabbbccc"
	matches := []detector.Match{
		mkMatch("A", "aaabbb", line, 1),
		mkMatch("B", "bbbccc", line, 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 2 {
		t.Fatalf("partial overlap must keep both, got %v", types(got))
	}
}

func TestResolveOverlaps_UnresolvablePositionKept(t *testing.T) {
	// No FullLine context: position can't be resolved, so keep as-is and don't
	// subsume anything.
	matches := []detector.Match{
		{Text: "4532 0151 1283 0366", Type: "VISA", LineNumber: 1},
		{Text: "0151 1283 0366", Type: "PHONE", LineNumber: 1},
	}
	got := ResolveOverlaps(matches)
	if len(got) != 2 {
		t.Fatalf("unresolvable matches must be kept unchanged, got %v", types(got))
	}
}

func TestResolveOverlaps_ThreeNested(t *testing.T) {
	line := "xx 4532 0151 1283 0366 yy"
	matches := []detector.Match{
		mkMatch("VISA", "4532 0151 1283 0366", line, 1),
		mkMatch("PHONE", "0151 1283 0366", line, 1),
		mkMatch("OTHER", "1283 0366", line, 1),
	}
	got := ResolveOverlaps(matches)
	if len(got) != 1 || got[0].Type != "VISA" {
		t.Fatalf("expected only widest VISA to survive nested containment, got %v", types(got))
	}
}

func TestResolveOverlaps_EmptyAndSingle(t *testing.T) {
	if got := ResolveOverlaps(nil); got != nil {
		t.Errorf("nil in -> nil out, got %v", got)
	}
	one := []detector.Match{mkMatch("VISA", "x", "x", 1)}
	if got := ResolveOverlaps(one); len(got) != 1 {
		t.Errorf("single match must pass through, got %v", types(got))
	}
}
