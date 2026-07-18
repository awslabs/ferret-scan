// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"strings"
	"testing"
)

// --- Positive cases ---

func TestRedactText_MasksFindings(t *testing.T) {
	text := "card 5500-0000-0000-0004 email jordan@example.com"
	findings := []Finding{
		{Text: "5500-0000-0000-0004", Type: "CREDIT_CARD", Confidence: 100},
		{Text: "jordan@example.com", Type: "EMAIL", Confidence: 75},
	}
	result, err := RedactText(text, findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result.Text, "5500-0000-0000-0004") {
		t.Error("redacted text still contains raw card number")
	}
	if strings.Contains(result.Text, "jordan@example.com") {
		t.Error("redacted text still contains raw email")
	}
	if result.Count != 2 {
		t.Errorf("expected count=2, got %d", result.Count)
	}
}

func TestRedactText_SimpleStrategy(t *testing.T) {
	text := "SSN 856-45-6789"
	findings := []Finding{{Text: "856-45-6789", Type: "SSN", Confidence: 100}}
	result, err := RedactText(text, findings, StrategySimple)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Text, "856-45-6789") {
		t.Error("simple strategy did not redact")
	}
}

func TestRedactText_SyntheticStrategy(t *testing.T) {
	text := "email jordan@example.com"
	findings := []Finding{{Text: "jordan@example.com", Type: "EMAIL", Confidence: 80}}
	result, err := RedactText(text, findings, StrategySynthetic)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Text, "jordan@example.com") {
		t.Error("synthetic strategy did not redact")
	}
	if !strings.Contains(result.Text, "@") {
		t.Error("synthetic strategy should produce a fake email with @ sign")
	}
}

func TestRedactText_PreservesNonSensitiveContent(t *testing.T) {
	text := "Hello world, card 5500-0000-0000-0004, goodbye"
	findings := []Finding{{Text: "5500-0000-0000-0004", Type: "CREDIT_CARD", Confidence: 100}}
	result, err := RedactText(text, findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Text, "Hello world") {
		t.Error("non-sensitive prefix was altered")
	}
	if !strings.Contains(result.Text, "goodbye") {
		t.Error("non-sensitive suffix was altered")
	}
}

// --- Negative cases ---

func TestRedactText_EmptyFindings(t *testing.T) {
	text := "nothing sensitive here"
	result, err := RedactText(text, nil, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != text {
		t.Errorf("with no findings, text should pass through unchanged; got %q", result.Text)
	}
	if result.Count != 0 {
		t.Errorf("expected count=0, got %d", result.Count)
	}
}

func TestRedactText_FindingsWithEmptyText(t *testing.T) {
	text := "some content"
	findings := []Finding{
		{Text: "", Type: "SSN", Confidence: 100},  // no matched text — can't redact
		{Text: "", Type: "EMAIL", Confidence: 80}, // same
	}
	result, err := RedactText(text, findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != text {
		t.Error("findings without Text should be skipped; text should be unchanged")
	}
	if result.Count != 0 {
		t.Errorf("expected count=0 for empty-text findings, got %d", result.Count)
	}
}

func TestRedactText_FindingNotInText(t *testing.T) {
	text := "the quick brown fox"
	findings := []Finding{{Text: "DOES-NOT-EXIST", Type: "SSN", Confidence: 100}}
	// The redactor should handle gracefully (not crash) when a finding's text
	// isn't found in the input — it just can't redact what isn't there.
	result, err := RedactText(text, findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	_ = result // doesn't crash
}

// --- Edge cases ---

func TestRedactText_EmptyInput(t *testing.T) {
	result, err := RedactText("", []Finding{{Text: "x", Type: "SSN"}}, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "" {
		t.Error("empty input should return empty output")
	}
}

func TestRedactText_OverlappingFindings(t *testing.T) {
	// Two findings that overlap in the source text (phone inside a card-like string).
	text := "5500 0000 0000 0004"
	findings := []Finding{
		{Text: "5500 0000 0000 0004", Type: "CREDIT_CARD", Confidence: 100},
		{Text: "0000 0000", Type: "PHONE", Confidence: 50}, // overlaps with card
	}
	result, err := RedactText(text, findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	// Should not crash; the wider match should win.
	if strings.Contains(result.Text, "5500") {
		t.Error("overlapping findings: wider match should still be redacted")
	}
}

func TestRedactText_MultipleIdenticalFindings(t *testing.T) {
	// Same value appears multiple times in the text.
	text := "SSN 856-45-6789 and again 856-45-6789"
	findings := []Finding{
		{Text: "856-45-6789", Type: "SSN", Confidence: 100},
		{Text: "856-45-6789", Type: "SSN", Confidence: 100},
	}
	result, err := RedactText(text, findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Text, "856-45-6789") {
		t.Error("both occurrences should be redacted")
	}
}

// --- Integration: ScanText -> RedactText (the full detect-then-redact path) ---

func TestScanThenRedact_EndToEnd(t *testing.T) {
	text := "Contact: 856-45-6789, card 5500-0000-0000-0004\n"

	// Step 1: Detect
	result, err := ScanText(context.Background(), text, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}

	// Step 2: Redact using the findings from step 1
	redacted, err := RedactText(text, result.Findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted.Text, "856-45-6789") {
		t.Error("SSN should be redacted")
	}
	if strings.Contains(redacted.Text, "5500-0000-0000-0004") {
		t.Error("card should be redacted")
	}
	if redacted.Count < 2 {
		t.Errorf("expected at least 2 redactions, got %d", redacted.Count)
	}
}

func TestScanThenRedact_CleanTextPassesThrough(t *testing.T) {
	text := "nothing sensitive at all\n"
	result, err := ScanText(context.Background(), text, TextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := RedactText(text, result.Findings, StrategyFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.Text != text {
		t.Error("clean text should pass through unchanged after redact")
	}
	if redacted.Count != 0 {
		t.Errorf("expected 0 redactions for clean text, got %d", redacted.Count)
	}
}
