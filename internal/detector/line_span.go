// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import "strings"

// LineSpan is where a match sits within its own line.
//
// LineID identifies the containing line by BOTH its reported number and its text.
// Offsets carrying different LineIDs are in different coordinate systems and must
// never be compared: an Office package numbers lines per part, so a metadata match
// in docProps/core.xml and a body match in word/document.xml both arrive as
// "line 1" with offsets measured against different strings. Comparing those once
// dropped a body match whose span happened to fall numerically inside a metadata
// span, leaving an SSN in cleartext.
type LineSpan struct {
	LineID int // 0 when unresolved; only compare offsets within one LineID
	Start  int // 0-based byte offset within the line
	End    int // 0-based, exclusive
	OK     bool
}

// ResolveLineSpans assigns every match to a concrete occurrence of its text within
// its line.
//
// Repeated (line, text) pairs consume successive occurrences left to right, so two
// identical values on one line resolve to DIFFERENT offsets instead of both
// claiming the first. A bare strings.Index cannot do this, which is why two
// findings for the same value on one line were indistinguishable in every reported
// field and why SARIF pointed both at the first occurrence.
//
// A match whose position cannot be resolved (empty line, empty text, text absent)
// gets OK=false rather than a guessed offset. When the cursor has consumed every
// occurrence the first one is reused, so a match is never dropped for want of a
// position — but the cursor is deliberately NOT advanced in that case, matching the
// long-standing behaviour of the redaction overlap pass.
//
// The returned slice is parallel to matches.
func ResolveLineSpans(matches []Match) []LineSpan {
	spans := make([]LineSpan, len(matches))
	if len(matches) == 0 {
		return spans
	}

	// The line id is interned rather than carried as a string: callers run O(n²)
	// containment loops over these spans, and comparing full line strings there
	// made a dense single-line document 48x slower. Interning pays the string hash
	// once per match and reduces the hot comparison to an int.
	type lineKey struct {
		number int
		text   string
	}
	lineIDs := make(map[lineKey]int, len(matches))
	cursor := make(map[int]map[string]int, len(matches))

	for i := range matches {
		m := &matches[i]
		line := m.Context.FullLine
		if line == "" || m.Text == "" {
			continue
		}

		k := lineKey{number: m.LineNumber, text: line}
		lineID, ok := lineIDs[k]
		if !ok {
			lineID = len(lineIDs) + 1 // 1-based; 0 is the zero value of LineSpan.LineID
			lineIDs[k] = lineID
		}

		byText, ok := cursor[lineID]
		if !ok {
			byText = make(map[string]int)
			cursor[lineID] = byText
		}

		from := byText[m.Text]
		idx := strings.Index(line[from:], m.Text)
		if idx < 0 {
			// Fall back to the first occurrence rather than losing the position.
			idx = strings.Index(line, m.Text)
			if idx < 0 {
				continue
			}
			spans[i] = LineSpan{LineID: lineID, Start: idx, End: idx + len(m.Text), OK: true}
			continue
		}
		start := from + idx
		spans[i] = LineSpan{LineID: lineID, Start: start, End: start + len(m.Text), OK: true}
		byText[m.Text] = start + len(m.Text)
	}

	return spans
}

// AssignLineColumns records each match's position on its line as 1-based byte
// columns, for every match that does not already carry one.
//
// This is what makes two findings for the same value on one line distinguishable.
// Without it they differ in no reported field, so:
//
//   - SARIF gave both the FIRST occurrence's region, double-annotating those
//     characters and never annotating the second occurrence's (see #321);
//   - gitlab-sast hashed (file, line, type) into its vulnerability id, so the two
//     collapsed to one id and GitLab dropped half the findings on ingest (#328).
//
// Matches that already have a StartColumn are left alone, so a validator that knows
// its own offset — most already compute one and discard it — can set it directly and
// this becomes a no-op for that match.
func AssignLineColumns(matches []Match) {
	spans := ResolveLineSpans(matches)
	for i := range matches {
		if matches[i].StartColumn > 0 {
			continue // already positioned by the producer
		}
		if !spans[i].OK {
			continue // no position is better than a wrong one
		}
		matches[i].StartColumn = spans[i].Start + 1
		matches[i].EndColumn = spans[i].End + 1
	}
}
