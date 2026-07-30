// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package tabular recognises delimited tabular content and maps a byte offset
// within a data row back to the header cell naming its column.
//
// It exists to close a detection gap, not to parse CSV in general. The
// label-gated validators (passport, otp, driverslicense, bankaccount, medicalid)
// report nothing without a context label, and their label search stops at the
// newline — so a document whose label lives in a header row and whose value lives
// in a data row produces NO findings at all:
//
//	Passport Number: 987654321          -> reported, HIGH
//	passport_number \n 987654321        -> nothing
//	name,email,passport_number,country
//	Jane,jane@corp.example,987654321,US -> only the email is reported
//
// A value that is never reported is never handed to the redactor either, so the
// redacted output of that third case still contains the passport number in
// cleartext. Header-row-plus-data-row is the normal shape of a CSV export, so this
// is not an edge case.
//
// Design constraints that shaped the API:
//
//   - No file re-reads. internal/detector's multi-line ExtractContext already
//     builds cross-line context and has zero live callers, because it re-opens the
//     file per match. Analyze takes the content string the validator already has.
//   - Analyze runs ONCE per document, Bounds ONCE per line, HeaderAt is a binary
//     search per match. A match-dense line therefore stays linear; this package
//     must not reintroduce the O(matches x lineLen) shape the validators were
//     already audited for.
//   - Conservative detection. A false "this is a table" costs mislabelled columns,
//     so the tests below are deliberately strict and any ambiguity (unbalanced
//     quotes, ragged rows, no header-ish cells) means "not a table" and the
//     caller's existing behavior is unchanged.
package tabular

import (
	"sort"
	"strings"
)

const (
	// minFields is the smallest field count treated as tabular. Two fields is
	// commonly ordinary prose containing one comma ("Smith, John"), so requiring
	// three keeps that out.
	minFields = 3

	// sampleRows is how many data rows after the header are checked for a
	// consistent field count. Enough to reject prose that happens to start with a
	// comma-rich line, cheap enough to stay O(1) per document.
	sampleRows = 20

	// consistentFraction is the share of sampled rows that must have exactly the
	// header's field count. Not 100%: real exports carry the occasional short
	// trailing row or a blank-ish line, and rejecting the whole file for one
	// ragged row would forfeit the fix on otherwise ordinary data.
	consistentFraction = 0.8

	// maxHeaderCellLen bounds a header cell. A "header" cell far longer than this
	// is prose, not a column name — this is what stops a comma-heavy sentence from
	// being read as a header row.
	maxHeaderCellLen = 64

	// minLetterCells is how many header cells must contain a letter. A row of pure
	// numbers is data, not a header.
	minLetterCells = 2
)

// candidateDelimiters is fixed-order on purpose: when two delimiters tie on count
// the first wins, so the chosen delimiter is deterministic rather than dependent
// on map iteration order.
var candidateDelimiters = []byte{'\t', ',', ';', '|'}

// Table describes recognised tabular content.
type Table struct {
	// delimiter is the byte separating fields. Zero when this is not a table.
	delimiter byte
	// headers holds the lowercased, trimmed header cells, index-aligned to columns.
	headers []string
	// headerLine is the 0-based index of the header row within the content, so a
	// caller can avoid treating the header row itself as data.
	headerLine int
	// ok reports whether the content was recognised as tabular.
	ok bool
}

// IsTable reports whether the content was recognised as delimited tabular data.
func (t *Table) IsTable() bool { return t != nil && t.ok }

// Delimiter returns the detected field delimiter, or 0 when not a table.
func (t *Table) Delimiter() byte {
	if !t.IsTable() {
		return 0
	}
	return t.delimiter
}

// Headers returns the lowercased header cells. The slice must not be mutated.
func (t *Table) Headers() []string {
	if !t.IsTable() {
		return nil
	}
	return t.headers
}

// HeaderLine returns the 0-based index of the header row.
func (t *Table) HeaderLine() int {
	if !t.IsTable() {
		return -1
	}
	return t.headerLine
}

// LineBounds holds the field-start byte offsets for one line, so a match offset
// can be mapped to a column without re-splitting the line per match.
type LineBounds struct {
	// starts[i] is the byte offset where field i begins. Always starts with 0.
	starts []int
}

// Fields returns the number of fields found on the line.
func (b *LineBounds) Fields() int {
	if b == nil {
		return 0
	}
	return len(b.starts)
}

// Analyze inspects content once and returns the recognised table, or a non-table
// Table when the content is not delimited data.
//
// Failure modes are deliberate returns, not errors: every rejection leaves the
// caller with IsTable() == false and therefore unchanged behavior.
func Analyze(content string) *Table {
	if content == "" {
		return &Table{}
	}
	lines := strings.Split(content, "\n")

	// Find the header candidate: the first line that is not blank and not a
	// comment. A preamble of "#"-commented lines is common in exported data.
	headerIdx := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, ";") {
			continue
		}
		headerIdx = i
		break
	}
	if headerIdx < 0 {
		return &Table{}
	}
	header := lines[headerIdx]

	// An unbalanced quote count means a field spans lines; this package does not
	// attempt multi-line records, so bail rather than mis-split.
	if strings.Count(header, `"`)%2 != 0 {
		return &Table{}
	}

	delim := pickDelimiter(header)
	if delim == 0 {
		return &Table{}
	}

	cells := splitFields(header, delim)
	if len(cells) < minFields {
		return &Table{}
	}

	// Header cells must look like column names.
	letters := 0
	for _, c := range cells {
		c = strings.TrimSpace(strings.Trim(strings.TrimSpace(c), `"`))
		if len(c) > maxHeaderCellLen {
			return &Table{}
		}
		if strings.IndexFunc(c, isLetter) >= 0 {
			letters++
		}
	}
	if letters < minLetterCells {
		return &Table{}
	}

	// The following rows must mostly agree with the header's field count,
	// otherwise this is prose that happens to contain delimiters.
	want := len(cells)
	sampled, matching := 0, 0
	for i := headerIdx + 1; i < len(lines) && sampled < sampleRows; i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Count(line, `"`)%2 != 0 {
			return &Table{}
		}
		sampled++
		if len(splitFields(line, delim)) == want {
			matching++
		}
	}
	if sampled == 0 || float64(matching)/float64(sampled) < consistentFraction {
		return &Table{}
	}

	headers := make([]string, want)
	for i, c := range cells {
		headers[i] = strings.ToLower(strings.Trim(strings.TrimSpace(c), `"`))
	}
	return &Table{delimiter: delim, headers: headers, headerLine: headerIdx, ok: true}
}

// Bounds computes the field-start offsets for one line. Call once per line and
// reuse for every match on it.
func (t *Table) Bounds(line string) *LineBounds {
	if !t.IsTable() {
		return nil
	}
	starts := []int{0}
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == t.delimiter && !inQuote {
			starts = append(starts, i+1)
		}
	}
	return &LineBounds{starts: starts}
}

// HeaderAt returns the lowercased header cell for the column containing byte
// offset off, or "" when there is none (offset outside the line, more fields on
// the data row than in the header, or not a table).
//
// Binary search rather than a linear walk so a line carrying many matches stays
// linear overall.
func (t *Table) HeaderAt(b *LineBounds, off int) string {
	if !t.IsTable() || b == nil || off < 0 || len(b.starts) == 0 {
		return ""
	}
	// The column is the last field whose start is <= off.
	idx := sort.Search(len(b.starts), func(i int) bool { return b.starts[i] > off }) - 1
	if idx < 0 || idx >= len(t.headers) {
		return ""
	}
	return t.headers[idx]
}

// pickDelimiter chooses the delimiter with the highest count outside quotes,
// requiring at least minFields-1 occurrences. Ties go to the earliest candidate,
// so the result never depends on iteration order.
func pickDelimiter(header string) byte {
	best := byte(0)
	bestCount := 0
	for _, d := range candidateDelimiters {
		n := countOutsideQuotes(header, d)
		if n > bestCount {
			best, bestCount = d, n
		}
	}
	if bestCount < minFields-1 {
		return 0
	}
	return best
}

func countOutsideQuotes(s string, d byte) int {
	n := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			inQuote = !inQuote
		case c == d && !inQuote:
			n++
		}
	}
	return n
}

// splitFields splits on the delimiter, ignoring delimiters inside double quotes.
// A quoted field containing the delimiter — "60.10, -149.44" in a coordinates
// column — is one field, which is what makes column mapping correct on real
// exports.
func splitFields(s string, d byte) []string {
	var out []string
	start := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == d && !inQuote {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
