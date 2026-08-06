// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

func makeMatch(typ string, confidence float64, line int) detector.Match {
	return detector.Match{
		Type:       typ,
		Validator:  strings.ToLower(typ),
		Confidence: confidence,
		LineNumber: line,
		Text:       "REDACTED",
		Filename:   "test.txt",
	}
}

func defaultOpts() formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		NoColor:         true,
	}
}

// --- Limit tests ---

func TestLimit_Zero_ShowsAll(t *testing.T) {
	matches := []detector.Match{
		makeMatch("SSN", 100, 1),
		makeMatch("EMAIL", 50, 2),
		makeMatch("PHONE", 30, 3),
	}
	opts := defaultOpts()
	opts.Limit = 0 // unlimited

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	// All 3 should be present, no truncation footer
	if strings.Count(result, "test.txt") != 3 {
		t.Errorf("limit=0 should show all 3 findings, got:\n%s", result)
	}
	if strings.Contains(result, "more findings") {
		t.Error("limit=0 should NOT show truncation footer")
	}
}

func TestLimit_One_ShowsOnlyTop(t *testing.T) {
	matches := []detector.Match{
		makeMatch("EMAIL", 50, 2),
		makeMatch("SSN", 100, 1), // highest confidence
		makeMatch("PHONE", 30, 3),
	}
	opts := defaultOpts()
	opts.Limit = 1

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Only the highest confidence (SSN, 100) should appear
	if !strings.Contains(result, "SSN") {
		t.Error("limit=1 should show the highest-confidence finding (SSN)")
	}
	if strings.Contains(result, "EMAIL") || strings.Contains(result, "PHONE") {
		t.Error("limit=1 should not show lower-confidence findings")
	}
	if !strings.Contains(result, "2 more findings") {
		t.Error("should show '2 more findings' footer")
	}
}

func TestLimit_ExceedsTotal_ShowsAll(t *testing.T) {
	matches := []detector.Match{
		makeMatch("SSN", 100, 1),
		makeMatch("EMAIL", 50, 2),
	}
	opts := defaultOpts()
	opts.Limit = 999 // way more than 2 findings

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "more findings") {
		t.Error("limit > total should NOT show truncation footer")
	}
	if strings.Count(result, "test.txt") != 2 {
		t.Errorf("should show all 2 findings")
	}
}

func TestLimit_EmptyInput(t *testing.T) {
	opts := defaultOpts()
	opts.Limit = 200

	f := NewFormatter()
	result, err := f.Format(nil, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "more findings") {
		t.Error("empty input should not show truncation footer")
	}
}

// --- Sort order tests ---

func TestSort_ConfidenceDescThenTypeAsc(t *testing.T) {
	matches := []detector.Match{
		makeMatch("PHONE", 30, 3),
		makeMatch("EMAIL", 80, 2),
		makeMatch("SSN", 100, 1),
		makeMatch("CREDIT_CARD", 100, 4), // same confidence as SSN, but type sorts after
	}
	opts := defaultOpts()
	opts.Limit = 0

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(result, "\n")
	var findingLines []string
	for _, l := range lines {
		if strings.Contains(l, "test.txt") {
			findingLines = append(findingLines, l)
		}
	}
	if len(findingLines) != 4 {
		t.Fatalf("expected 4 finding lines, got %d", len(findingLines))
	}
	// First should be CREDIT_CARD or SSN (both 100, type-sorted: C < S)
	if !strings.Contains(findingLines[0], "CREDIT_CARD") {
		t.Errorf("first finding should be CREDIT_CARD (100%%, type 'C' < 'S'), got: %s", findingLines[0])
	}
	if !strings.Contains(findingLines[1], "SSN") {
		t.Errorf("second finding should be SSN (100%%), got: %s", findingLines[1])
	}
	// Last should be PHONE (lowest confidence)
	if !strings.Contains(findingLines[3], "PHONE") {
		t.Errorf("last finding should be PHONE (30%%), got: %s", findingLines[3])
	}
}

// --- Summary stats tests ---

func TestSummaryStats_Rendered(t *testing.T) {
	matches := []detector.Match{makeMatch("SSN", 100, 1)}
	opts := defaultOpts()
	opts.Stats = &formatters.ScanStats{
		TotalFiles:     10,
		FilesProcessed: 8,
		FilesSkipped:   2,
		TotalFindings:  1,
		High:           1,
		Medium:         0,
		Low:            0,
		Suppressed:     0,
		Duration:       1.234,
	}

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "Scan Summary") {
		t.Error("should contain 'Scan Summary' header")
	}
	// "scanned", not "processed": a file that FAILED was previously counted as
	// processed, so the old wording described a failure as a completed scan.
	if !strings.Contains(result, "8 scanned") {
		t.Error("should show files scanned")
	}
	if !strings.Contains(result, "2 skipped") {
		t.Error("should show files skipped")
	}
	if !strings.Contains(result, "1 high") {
		t.Error("should show HIGH count")
	}
}

// TestSummaryStats_NotExaminedIsReported — a file whose contents were never seen
// must appear in the summary.
//
// Before FilesNotExamined existed, a directory of 7 files where 2 were unreadable
// and 4 unparseable rendered as "Files: 2 processed, 0 skipped": five files vanished
// from the accounting and one FAILURE was reported as processed. A summary that reads
// clean over unexamined files is the same class of harm as a missed detection, so the
// count is asserted here rather than left to the stderr warning.
func TestSummaryStats_NotExaminedIsReported(t *testing.T) {
	matches := []detector.Match{makeMatch("SSN", 100, 1)}
	opts := defaultOpts()
	opts.Stats = &formatters.ScanStats{
		TotalFiles:       7,
		FilesProcessed:   2,
		FilesNotExamined: 5,
		TotalFindings:    1,
		High:             1,
	}

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "5 NOT examined") {
		t.Errorf("summary must report the 5 unexamined files; got:\n%s", result)
	}
	if strings.Contains(result, "0 skipped") {
		t.Error("a zero skipped-count must not be printed: it is noise on every clean " +
			"run, and it was what made the old summary read as complete")
	}
}

// TestSummaryStats_CleanRunIsQuiet — no zero-valued categories.
//
// The counters only appear when they are non-zero, so an ordinary clean scan reads
// "Files: 12 scanned | Findings: 0" instead of carrying two zeroes the reader has to
// check every time to confirm they are zero.
func TestSummaryStats_CleanRunIsQuiet(t *testing.T) {
	opts := defaultOpts()
	opts.Stats = &formatters.ScanStats{TotalFiles: 12, FilesProcessed: 12}

	f := NewFormatter()
	result, err := f.Format([]detector.Match{makeMatch("SSN", 100, 1)}, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "12 scanned") {
		t.Errorf("want '12 scanned'; got:\n%s", result)
	}
	for _, unwanted := range []string{"NOT examined", "skipped"} {
		if strings.Contains(result, unwanted) {
			t.Errorf("a clean run must not mention %q; got:\n%s", unwanted, result)
		}
	}
}

func TestSummaryStats_NilStats_NoHeader(t *testing.T) {
	matches := []detector.Match{makeMatch("SSN", 100, 1)}
	opts := defaultOpts()
	opts.Stats = nil

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "Scan Summary") {
		t.Error("nil Stats should NOT produce a summary header")
	}
}

// --- StreamWriter tests ---

func TestStreamWriter_WritesDirectly(t *testing.T) {
	matches := []detector.Match{
		makeMatch("SSN", 100, 1),
		makeMatch("EMAIL", 50, 2),
	}
	opts := defaultOpts()
	opts.Limit = 0
	var buf bytes.Buffer
	opts.StreamWriter = &buf

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	// When streaming, result should be empty (content went to writer)
	if result != "" {
		t.Errorf("streaming should return empty string, got %d bytes", len(result))
	}
	// The buffer should have the content
	if !strings.Contains(buf.String(), "SSN") {
		t.Error("StreamWriter should receive the findings")
	}
	if !strings.Contains(buf.String(), "EMAIL") {
		t.Error("StreamWriter should receive all findings")
	}
}

func TestStreamWriter_Nil_ReturnsString(t *testing.T) {
	matches := []detector.Match{makeMatch("SSN", 100, 1)}
	opts := defaultOpts()
	opts.StreamWriter = nil

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if result == "" {
		t.Error("nil StreamWriter should return content as string")
	}
	if !strings.Contains(result, "SSN") {
		t.Error("returned string should contain findings")
	}
}

// --- Edge cases ---

func TestLimit_NegativeValue_TreatedAsUnlimited(t *testing.T) {
	matches := []detector.Match{
		makeMatch("SSN", 100, 1),
		makeMatch("EMAIL", 50, 2),
	}
	opts := defaultOpts()
	opts.Limit = -1 // invalid, should behave as unlimited

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "more findings") {
		t.Error("negative limit should not truncate")
	}
}

func TestSummaryStats_ZeroFindings_NoSummary(t *testing.T) {
	opts := defaultOpts()
	opts.Stats = &formatters.ScanStats{
		TotalFiles:     5,
		FilesProcessed: 5,
		FilesSkipped:   0,
		TotalFindings:  0,
		High:           0,
		Medium:         0,
		Low:            0,
	}

	f := NewFormatter()
	result, err := f.Format(nil, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	// When there are zero findings, the formatter short-circuits to
	// "No matches found." — no summary header is rendered (not useful).
	if !strings.Contains(result, "No matches found") {
		t.Errorf("zero findings should show 'No matches found', got:\n%s", result)
	}
}

func TestPrecommitMode_NoSummaryOrLimit(t *testing.T) {
	matches := []detector.Match{
		makeMatch("SSN", 100, 1),
		makeMatch("EMAIL", 50, 2),
		makeMatch("PHONE", 30, 3),
	}
	opts := defaultOpts()
	opts.PrecommitMode = true
	opts.Limit = 1
	opts.Stats = &formatters.ScanStats{TotalFindings: 3, High: 1}

	f := NewFormatter()
	result, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-commit mode uses its own output format — should not include
	// summary headers or be affected by --limit (it has its own contract).
	if strings.Contains(result, "Scan Summary") {
		t.Error("pre-commit mode should NOT show summary header")
	}
}

// TestSummaryFrameShape — double rule top and bottom, single rule dividing the
// summary counts from the not-examined detail.
//
// The frame is load-bearing: the two sections are one block with a divider, not two
// stacked boxes on (previously) two different streams. An earlier version emitted a
// double rule in the middle and a single at the bottom, which read as the summary
// ending and an unrelated box beginning.
func TestSummaryFrameShape(t *testing.T) {
	opts := defaultOpts()
	opts.Stats = &formatters.ScanStats{
		TotalFiles: 7, FilesProcessed: 2, FilesNotExamined: 5,
		TotalFindings: 1, Medium: 1,
	}
	opts.NotExaminedFooter = "NOT EXAMINED: 5 of 7 files\n  cannot read (5)\n"

	out, err := NewFormatter().Format([]detector.Match{makeMatch("SSN", 80, 1)}, nil, opts)
	if err != nil {
		t.Fatal(err)
	}

	var rules []rune
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		r := []rune(trimmed)[0]
		if (r == '═' || r == '─') && !strings.Contains(line, "Scan Summary") {
			rules = append(rules, r)
		} else if strings.Contains(line, "Scan Summary") {
			rules = append(rules, '═')
		}
	}

	// top ═, divider ─, bottom ═
	want := []rune{'═', '─', '═'}
	if len(rules) != len(want) {
		t.Fatalf("frame has %d rules, want %d (top/divider/bottom):\n%s", len(rules), len(want), out)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d is %q, want %q — the divider must be single and the outer "+
				"rules double, or the block reads as two separate boxes:\n%s",
				i, string(rules[i]), string(want[i]), out)
		}
	}
}

// TestSummaryRulesReachTheirContent — a rule must not be shorter than the text it
// frames, and must not run away on a long path.
//
// Measured before the fix: "Files: 276 scanned, 24 NOT examined | Findings: 4631
// (1131 high, 2535 medium, 965 low)" is 86 characters inside an 80-character frame,
// so the summary line visibly overhung its own box.
func TestSummaryRulesReachTheirContent(t *testing.T) {
	opts := defaultOpts()
	opts.Stats = &formatters.ScanStats{
		TotalFiles: 299, FilesProcessed: 276, FilesNotExamined: 24,
		TotalFindings: 4631, High: 1131, Medium: 2535, Low: 965,
	}

	out, err := NewFormatter().Format([]detector.Match{makeMatch("SSN", 80, 1)}, nil, opts)
	if err != nil {
		t.Fatal(err)
	}

	widest, ruleWidth := 0, 0
	for _, line := range strings.Split(out, "\n") {
		n := len([]rune(line))
		if strings.HasPrefix(line, "Files:") && n > widest {
			widest = n
		}
		if strings.HasPrefix(line, "════") {
			ruleWidth = n
		}
	}

	if widest == 0 || ruleWidth == 0 {
		t.Fatalf("could not find the summary line and its rule:\n%s", out)
	}
	if ruleWidth < widest {
		t.Errorf("rule is %d wide but the summary line is %d: the text overhangs its own "+
			"frame", ruleWidth, widest)
	}
	if ruleWidth > 120 {
		t.Errorf("rule is %d wide; over 120 it wraps in a normal terminal, which looks "+
			"worse than a slight overhang", ruleWidth)
	}
}

// TestSummaryCountsReconcile — scanned + NOT examined + skipped must not exceed the
// file count.
//
// An empty-extraction file (opened fine, no readable text) is counted PROCESSED by
// the worker pool and ALSO appears in the not-examined set, because both statements
// are true from their own vantage point. Printed side by side they double-count it:
// measured on 2 files where one was a valid but empty .docx, the summary read
// "2 scanned, 1 NOT examined" — 3 of 2. On a 301-file run it surfaced as 278 + 24 =
// 302, which a reader has to reconcile and cannot.
func TestSummaryCountsReconcile(t *testing.T) {
	cases := []struct {
		name                                   string
		total, processed, notExamined, skipped int
	}{
		{"all clean", 10, 10, 0, 0},
		{"some unexamined", 7, 2, 5, 0},
		{"unexamined and skipped", 10, 4, 3, 3},
		{"single file unexamined", 1, 0, 1, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultOpts()
			opts.Stats = &formatters.ScanStats{
				TotalFiles: tc.total, FilesProcessed: tc.processed,
				FilesNotExamined: tc.notExamined, FilesSkipped: tc.skipped,
				TotalFindings: 1, Medium: 1,
			}

			out, err := NewFormatter().Format([]detector.Match{makeMatch("SSN", 80, 1)}, nil, opts)
			if err != nil {
				t.Fatal(err)
			}

			if sum := tc.processed + tc.notExamined + tc.skipped; sum > tc.total {
				t.Fatalf("the fixture itself over-counts (%d > %d total); the caller must "+
					"not hand the formatter overlapping categories", sum, tc.total)
			}

			// The rendered line must carry each non-zero category exactly once.
			if !strings.Contains(out, fmt.Sprintf("%d scanned", tc.processed)) {
				t.Errorf("summary does not report %d scanned:\n%s", tc.processed, out)
			}
			if tc.notExamined > 0 && !strings.Contains(out, fmt.Sprintf("%d NOT examined", tc.notExamined)) {
				t.Errorf("summary does not report %d NOT examined:\n%s", tc.notExamined, out)
			}
		})
	}
}
