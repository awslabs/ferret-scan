// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package csv

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// #381: RFC 4180 quoting passes a control byte through unchanged — it lives happily inside
// the quotes. So a csv report of a directory containing a hostile filename carried the same
// raw bytes as the text report: measured on three such files, ESC=4 and CR=2 in both.
//
// A csv report is read in a terminal (`cat`, `less`, a CI log) at least as often as in a
// spreadsheet, so the row-erasure attack lands here too.

func csvMatch(filename string) detector.Match {
	return detector.Match{
		Text:       "449-87-4100",
		LineNumber: 1,
		Type:       "SSN",
		Confidence: 100,
		Filename:   filename,
		Validator:  "ssn",
		Context:    detector.ContextInfo{FullLine: "SSN: 449-87-4100"},
	}
}

func formatCSV(t *testing.T, matches []detector.Match) string {
	t.Helper()
	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		NoColor:         true,
		Limit:           0,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	// Non-vacuity: a report with no data rows would satisfy every assertion below.
	if strings.Count(strings.TrimSpace(out), "\n") < 1 {
		t.Fatalf("the csv report has no data rows, so nothing here is tested:\n%q", out)
	}
	return out
}

// TestTheCSVReportEmitsNoBorrowedControlBytes.
func TestTheCSVReportEmitsNoBorrowedControlBytes(t *testing.T) {
	payloads := []string{
		"quarterly-report.txt\x1b[2K\r",
		"ok.txt\n\nNo sensitive information found. Scan complete: 0 findings.",
		"evil\x1b[31mRED\x1b[0m.txt",
		"tabbed\tname.txt",
		"del\x7fname.txt",
	}
	for _, payload := range payloads {
		t.Run(strings.SplitN(payload, "\x1b", 2)[0], func(t *testing.T) {
			out := formatCSV(t, []detector.Match{csvMatch(payload)})
			for i := 0; i < len(out); i++ {
				if c := out[i]; c != '\n' && (c < 0x20 || c == 0x7F) {
					t.Fatalf("byte 0x%02x at offset %d is a borrowed control byte; RFC 4180 "+
						"quoting does not neutralise it.\nsurrounding: %q",
						c, i, out[maxInt(0, i-40):minInt(len(out), i+20)])
				}
			}
		})
	}
}

// TestTheCSVReportStaysParseable is the half that keeps the escaping from breaking
// consumers. encoding/csv is the reference parser; if it cannot read the output, the fix
// traded one defect for another.
func TestTheCSVReportStaysParseable(t *testing.T) {
	out := formatCSV(t, []detector.Match{
		csvMatch("quarterly-report.txt\x1b[2K\r"),
		csvMatch("with,comma.txt"),
		csvMatch(`with"quote.txt`),
		csvMatch("ok.txt\n\nfabricated"),
		csvMatch("rapport-café.txt"),
	})

	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1 // the report has a header block plus rows
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("encoding/csv could not parse the report: %v\n%q", err, out)
	}
	if len(records) < 5 {
		t.Errorf("parsed %d records, expected at least the 5 findings", len(records))
	}
	// The escaped payload must still identify its file.
	joined := out
	if !strings.Contains(joined, "quarterly-report.txt") {
		t.Error("the escaped filename no longer contains the original readable stem")
	}
	if !strings.Contains(joined, "rapport-café.txt") {
		t.Error("a legitimate non-ASCII filename was altered")
	}
}

// TestControlBytesAndTheFormulaGuardBothApply.
//
// A first draft of this test claimed the two are order-dependent — that escaping had to run
// before sanitizeFormulaInjection, because that guard reads field[0] and would not recognise
// an ESC-then-"=" field. A mutation swapping the order SURVIVED, and enumerating the cases
// showed the claim was simply wrong: escaping can only ever produce a field beginning with a
// backslash, which is not a formula trigger, so it cannot create one either way. The orders
// differ only on a tab/CR/LF-prefixed field, where running the guard first adds a leading
// quote that is redundant once the prefix has become an escape sequence.
//
// So this asserts what is actually true and load-bearing: both protections apply, neither was
// disturbed by the other.
func TestControlBytesAndTheFormulaGuardBothApply(t *testing.T) {
	// A control-byte prefix in front of a formula: the ESC must go, and what remains cannot
	// be a formula because "=" is no longer the first character.
	out := formatCSV(t, []detector.Match{csvMatch("\x1b=cmd|'/c calc'!A0")})
	if strings.Contains(out, "\x1b") {
		t.Error("a raw ESC survived in front of the '='")
	}
	if !strings.Contains(out, `\x1b=cmd`) {
		t.Errorf("expected the ESC to appear as a visible escape before the '=':\n%q", out)
	}

	// And the pre-existing guard must still prefix a bare formula field, so this change did
	// not weaken it.
	for _, trigger := range []string{"=cmd|'/c calc'!A0", "+1+1", "@SUM(1)", "-2+3"} {
		plain := formatCSV(t, []detector.Match{csvMatch(trigger)})
		if !strings.Contains(plain, "'"+trigger[:2]) {
			t.Errorf("the formula guard no longer prefixes %q:\n%q", trigger, plain)
		}
	}
}

// TestAnOrdinaryCSVFieldIsUnquotedAsBefore. escapeCSVField only quotes when it must, and
// this fix must not make every field quoted — that would churn the output of every scan.
func TestAnOrdinaryCSVFieldIsUnquotedAsBefore(t *testing.T) {
	f := NewFormatter()
	for _, in := range []string{"report.txt", "SSN", "HIGH", "rapport-café.txt", "報告書.txt"} {
		if got := f.escapeCSVField(in); got != in {
			t.Errorf("escapeCSVField(%q) = %q, want it unchanged and unquoted", in, got)
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
