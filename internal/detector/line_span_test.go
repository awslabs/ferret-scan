// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import "testing"

// Two findings for the same value on one line must get DIFFERENT columns.
//
// Without a per-line occurrence cursor every consumer that needed a position fell
// back to strings.Index, which always returns the FIRST occurrence. Both findings
// then claimed the same characters: SARIF annotated those twice and never annotated
// the second occurrence's, and gitlab-sast hashed the two into one id and had half
// its findings dropped on ingest.
func TestAssignLineColumnsGivesRepeatedValuesDistinctColumns(t *testing.T) {
	const line = "Contact a@b.com or a@b.com for access."
	matches := []Match{
		{Text: "a@b.com", LineNumber: 1, Context: ContextInfo{FullLine: line}},
		{Text: "a@b.com", LineNumber: 1, Context: ContextInfo{FullLine: line}},
	}
	AssignLineColumns(matches)

	if matches[0].StartColumn == matches[1].StartColumn {
		t.Fatalf("both matches got column %d; they are different occurrences",
			matches[0].StartColumn)
	}
	// Columns are 1-based and must actually address the value in the line.
	for i, m := range matches {
		if m.StartColumn <= 0 {
			t.Fatalf("match %d has no column", i)
		}
		start, end := m.StartColumn-1, m.EndColumn-1
		if end > len(line) || line[start:end] != m.Text {
			t.Errorf("match %d columns %d-%d address %q, want %q",
				i, m.StartColumn, m.EndColumn, line[start:min(end, len(line))], m.Text)
		}
	}
	// Left to right, so the reported order matches reading order.
	if matches[0].StartColumn > matches[1].StartColumn {
		t.Errorf("columns %d then %d are out of order", matches[0].StartColumn, matches[1].StartColumn)
	}
}

// Three occurrences must each get their own column — an off-by-one in the cursor
// would pair up the last two.
func TestAssignLineColumnsHandlesThreeOccurrences(t *testing.T) {
	const line = "x 42 y 42 z 42"
	matches := []Match{
		{Text: "42", LineNumber: 3, Context: ContextInfo{FullLine: line}},
		{Text: "42", LineNumber: 3, Context: ContextInfo{FullLine: line}},
		{Text: "42", LineNumber: 3, Context: ContextInfo{FullLine: line}},
	}
	AssignLineColumns(matches)

	seen := map[int]bool{}
	for i, m := range matches {
		if m.StartColumn == 0 {
			t.Fatalf("match %d has no column", i)
		}
		if seen[m.StartColumn] {
			t.Errorf("column %d assigned twice", m.StartColumn)
		}
		seen[m.StartColumn] = true
		if line[m.StartColumn-1:m.EndColumn-1] != "42" {
			t.Errorf("column %d does not address the value", m.StartColumn)
		}
	}
}

// A match with no resolvable position must keep column 0, meaning "absent".
//
// A synthesised match text — a social-media cluster, a consolidated
// intellectual-property span — never occurs literally in the line, so there is no
// honest column for it. Reporting a guessed one would annotate characters that are
// not the finding.
func TestAssignLineColumnsLeavesUnresolvableMatchesAtZero(t *testing.T) {
	matches := []Match{
		{Text: "value", LineNumber: 1, Context: ContextInfo{FullLine: ""}},                    // no line
		{Text: "", LineNumber: 1, Context: ContextInfo{FullLine: "some line"}},                // no text
		{Text: "not-in-the-line", LineNumber: 1, Context: ContextInfo{FullLine: "some line"}}, // synthesised
		{Text: "line", LineNumber: 1, Context: ContextInfo{FullLine: "some line"}},            // resolvable
	}
	AssignLineColumns(matches)

	for i := 0; i < 3; i++ {
		if matches[i].StartColumn != 0 || matches[i].EndColumn != 0 {
			t.Errorf("match %d got columns %d-%d, want 0 (absent) — a guessed position "+
				"annotates the wrong characters", i, matches[i].StartColumn, matches[i].EndColumn)
		}
	}
	if matches[3].StartColumn != 6 {
		t.Errorf("resolvable match got column %d, want 6", matches[3].StartColumn)
	}
}

// A producer that already knows its own offset must not be overwritten. Most
// validators compute an offset and discard it; this is the seam that lets them keep
// it without this pass second-guessing them.
func TestAssignLineColumnsPreservesAnExistingColumn(t *testing.T) {
	const line = "aa bb aa"
	matches := []Match{
		{Text: "aa", LineNumber: 1, StartColumn: 7, EndColumn: 9, Context: ContextInfo{FullLine: line}},
	}
	AssignLineColumns(matches)
	if matches[0].StartColumn != 7 || matches[0].EndColumn != 9 {
		t.Errorf("columns became %d-%d, want the producer's 7-9",
			matches[0].StartColumn, matches[0].EndColumn)
	}
}

// Offsets must never be shared across lines that merely have the same NUMBER.
//
// An Office package numbers lines per part, so a metadata match in
// docProps/core.xml and a body match in word/document.xml both arrive as "line 1"
// with offsets measured against different strings. Treating them as one line would
// let one consume the other's occurrence and hand back a column that addresses the
// wrong text.
func TestAssignLineColumnsSeparatesSameNumberedLinesWithDifferentText(t *testing.T) {
	bodyLine := "SSN 449-87-4100 in the body"
	propLine := "Title: record for 449-87-4100"
	matches := []Match{
		{Text: "449-87-4100", LineNumber: 1, Context: ContextInfo{FullLine: bodyLine}},
		{Text: "449-87-4100", LineNumber: 1, Context: ContextInfo{FullLine: propLine}},
	}
	AssignLineColumns(matches)

	if got := bodyLine[matches[0].StartColumn-1 : matches[0].EndColumn-1]; got != "449-87-4100" {
		t.Errorf("body match column addresses %q", got)
	}
	if got := propLine[matches[1].StartColumn-1 : matches[1].EndColumn-1]; got != "449-87-4100" {
		t.Errorf("property match column addresses %q — the two lines share a number but not a "+
			"coordinate system, so neither may consume the other's occurrence", got)
	}
}

// The assignment must be a pure function of the input order, so the same scan
// reports the same columns every run.
func TestAssignLineColumnsIsDeterministic(t *testing.T) {
	build := func() []Match {
		const line = "a 7 b 7 c 7 d 7"
		out := make([]Match, 0, 4)
		for i := 0; i < 4; i++ {
			out = append(out, Match{Text: "7", LineNumber: 2, Context: ContextInfo{FullLine: line}})
		}
		return out
	}
	first := build()
	AssignLineColumns(first)
	for run := 0; run < 20; run++ {
		next := build()
		AssignLineColumns(next)
		for i := range first {
			if first[i].StartColumn != next[i].StartColumn {
				t.Fatalf("run %d: match %d column %d != %d", run, i, next[i].StartColumn, first[i].StartColumn)
			}
		}
	}
}

// ResolveLineSpans is shared with the redaction overlap pass, so its contract is
// pinned here too: spans on different lines must carry different LineIDs, and an
// unresolvable match must report OK=false rather than offset 0.
func TestResolveLineSpansContract(t *testing.T) {
	matches := []Match{
		{Text: "aa", LineNumber: 1, Context: ContextInfo{FullLine: "aa bb"}},
		{Text: "bb", LineNumber: 2, Context: ContextInfo{FullLine: "xx bb"}},
		{Text: "zz", LineNumber: 3, Context: ContextInfo{FullLine: "nothing here"}},
	}
	spans := ResolveLineSpans(matches)
	if len(spans) != len(matches) {
		t.Fatalf("got %d spans for %d matches", len(spans), len(matches))
	}
	if !spans[0].OK || !spans[1].OK {
		t.Fatal("resolvable matches reported OK=false")
	}
	if spans[0].LineID == spans[1].LineID {
		t.Error("matches on different lines share a LineID; their offsets would be compared")
	}
	if spans[2].OK {
		t.Error("a match whose text is absent from its line must not report a span")
	}
	if spans[2].Start != 0 || spans[2].End != 0 {
		t.Error("an unresolved span must be the zero value")
	}
	if spans[0].Start != 0 || spans[0].End != 2 {
		t.Errorf("span[0] = %d-%d, want 0-2", spans[0].Start, spans[0].End)
	}
}

// Empty input must not panic and must return an empty parallel slice.
func TestResolveLineSpansEmpty(t *testing.T) {
	if got := ResolveLineSpans(nil); len(got) != 0 {
		t.Errorf("ResolveLineSpans(nil) = %v, want empty", got)
	}
	AssignLineColumns(nil) // must not panic
}
