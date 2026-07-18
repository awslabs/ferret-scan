// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"bytes"
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
	if !strings.Contains(result, "8 processed") {
		t.Error("should show files processed")
	}
	if !strings.Contains(result, "2 skipped") {
		t.Error("should show files skipped")
	}
	if !strings.Contains(result, "1 high") {
		t.Error("should show HIGH count")
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
