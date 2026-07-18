// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanText_DetectsSSNAndEmail(t *testing.T) {
	result, err := ScanText(context.Background(),
		"Contact jordan@example.com, SSN 856-45-6789\n",
		TextOptions{Explain: true})
	if err != nil {
		t.Fatalf("ScanText error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings for SSN + email")
	}
	types := map[string]bool{}
	for _, f := range result.Findings {
		types[f.Type] = true
		if f.Text == "" {
			t.Errorf("finding %s has empty Text", f.Type)
		}
	}
	if !types["SSN"] {
		t.Error("expected SSN finding")
	}
}

func TestScanText_CleanInputNoFindings(t *testing.T) {
	result, err := ScanText(context.Background(),
		"the quick brown fox jumps over the lazy dog\n",
		TextOptions{})
	if err != nil {
		t.Fatalf("ScanText error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for clean text, got %d", len(result.Findings))
	}
}

func TestScanText_ExplainPopulatesRationale(t *testing.T) {
	result, err := ScanText(context.Background(),
		"SSN 856-45-6789\n",
		TextOptions{Explain: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Type == "SSN" && f.Rationale == "" {
			t.Error("Explain=true should populate Rationale for SSN")
		}
	}
}

func TestScanText_ChecksFilterValidators(t *testing.T) {
	result, err := ScanText(context.Background(),
		"SSN 856-45-6789, email jordan@example.com\n",
		TextOptions{Checks: []string{"SSN"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Validator != "ssn" && f.Type != "SSN" {
			t.Errorf("with Checks=[SSN], got finding from validator %s type %s", f.Validator, f.Type)
		}
	}
}

func TestScanFile_DetectsInDocx(t *testing.T) {
	// Use a simple text file; DOCX would need a real fixture.
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("card 5500-0000-0000-0004\n"), 0o644)

	result, err := ScanFile(context.Background(), f, FileOptions{})
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding for a credit card")
	}
}

func TestCheckNames_ReturnsValidators(t *testing.T) {
	names := CheckNames()
	if len(names) < 10 {
		t.Errorf("expected at least 10 validators, got %d", len(names))
	}
	found := false
	for _, n := range names {
		if n == "SSN" {
			found = true
		}
	}
	if !found {
		t.Error("CheckNames should include SSN")
	}
}

func TestScanFile_RejectsUnsupportedType(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "archive.zip")
	os.WriteFile(f, []byte("PK\x03\x04fake"), 0o644)

	_, err := ScanFile(context.Background(), f, FileOptions{})
	if err == nil {
		t.Error("expected error for unsupported file type (.zip)")
	}
	if err != nil && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should mention 'unsupported', got: %v", err)
	}
}

func TestCanProcessFile_TextOK_ZipRejected(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "notes.txt")
	os.WriteFile(txt, []byte("hello"), 0o644)
	zip := filepath.Join(dir, "archive.zip")
	os.WriteFile(zip, []byte("PK\x03\x04fake"), 0o644)

	ok, _ := CanProcessFile(txt)
	if !ok {
		t.Error("expected .txt to be processable")
	}
	ok, reason := CanProcessFile(zip)
	if ok {
		t.Error("expected .zip to be rejected")
	}
	if reason == "" {
		t.Error("rejection should include a reason")
	}
}

func TestConfidenceOf_Bands(t *testing.T) {
	cases := []struct {
		score float64
		want  Confidence
	}{
		{100, ConfidenceHigh},
		{90, ConfidenceHigh},
		{89.9, ConfidenceMedium},
		{60, ConfidenceMedium},
		{59.9, ConfidenceLow},
		{0, ConfidenceLow},
	}
	for _, c := range cases {
		if got := ConfidenceOf(c.score); got != c.want {
			t.Errorf("ConfidenceOf(%v) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestConfidenceOf_EdgeCases(t *testing.T) {
	// NaN — must not panic, should classify as LOW (safest default).
	nan := math.NaN()
	if got := ConfidenceOf(nan); got != ConfidenceLow {
		t.Errorf("ConfidenceOf(NaN) = %s, want LOW", got)
	}
	// Negative — should be LOW.
	if got := ConfidenceOf(-5); got != ConfidenceLow {
		t.Errorf("ConfidenceOf(-5) = %s, want LOW", got)
	}
	// >100 — should be HIGH (valid but capped).
	if got := ConfidenceOf(150); got != ConfidenceHigh {
		t.Errorf("ConfidenceOf(150) = %s, want HIGH", got)
	}
	// +Inf — should be HIGH (treated as > 90).
	if got := ConfidenceOf(math.Inf(1)); got != ConfidenceHigh {
		t.Errorf("ConfidenceOf(+Inf) = %s, want HIGH", got)
	}
}

func TestClampScore(t *testing.T) {
	cases := []struct {
		in   float64
		want int
	}{
		{95.7, 95},
		{0, 0},
		{100, 100},
		{-10, 0},
		{200, 100},
		{math.NaN(), 0},
		{math.Inf(1), 100},
		{math.Inf(-1), 0},
	}
	for _, c := range cases {
		if got := ClampScore(c.in); got != c.want {
			t.Errorf("ClampScore(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestScanFile_TextExtensionWithBinaryData(t *testing.T) {
	dir := t.TempDir()
	// A .txt file filled with binary garbage (NUL bytes, non-UTF8).
	f := filepath.Join(dir, "fake.txt")
	binary := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x89, 'P', 'N', 'G', 0x00, 0x00}
	os.WriteFile(f, binary, 0o644)

	// Should NOT panic. May find nothing or may error — either is acceptable;
	// the contract is it doesn't crash on garbage input.
	result, err := ScanFile(context.Background(), f, FileOptions{})
	if err != nil {
		t.Logf("binary-in-txt correctly errored: %v", err)
		return
	}
	t.Logf("binary-in-txt returned %d findings (no crash)", len(result.Findings))
}

func TestScanFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.txt")
	os.WriteFile(f, []byte{}, 0o644)

	result, err := ScanFile(context.Background(), f, FileOptions{})
	if err != nil {
		t.Logf("empty file errored (acceptable): %v", err)
		return
	}
	if len(result.Findings) != 0 {
		t.Error("empty file should produce 0 findings")
	}
}

func TestScanFile_MissingFile(t *testing.T) {
	_, err := ScanFile(context.Background(), "/nonexistent/path.txt", FileOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRedactFile_UnsupportedType(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "movie.mkv")
	os.WriteFile(f, []byte("\x00\x00video"), 0o644)

	_, err := RedactFile(f, RedactFileOptions{OutputDir: t.TempDir()})
	if err == nil {
		t.Error("expected error for unsupported file type")
	}
}

func TestParseStrategy(t *testing.T) {
	if ParseStrategy("simple") != StrategySimple {
		t.Error("parse 'simple'")
	}
	if ParseStrategy("synthetic") != StrategySynthetic {
		t.Error("parse 'synthetic'")
	}
	if ParseStrategy("format_preserving") != StrategyFormatPreserving {
		t.Error("parse 'format_preserving'")
	}
	if ParseStrategy("unknown") != StrategyFormatPreserving {
		t.Error("unknown should default to format_preserving")
	}
}
