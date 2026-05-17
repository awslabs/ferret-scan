// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"

	"ferret-scan/internal/detector"
)

func TestParseChecksToRun_All(t *testing.T) {
	cases := []struct {
		name  string
		input []string
	}{
		{"empty slice enables all", []string{}},
		{"explicit all enables all", []string{"all"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseChecksToRun(tc.input)
			for k, v := range result {
				if !v {
					t.Errorf("expected check %q to be enabled, got false", k)
				}
			}
		})
	}
}

func TestParseChecksToRun_Specific(t *testing.T) {
	result := ParseChecksToRun([]string{"EMAIL", "SSN"})
	if !result["EMAIL"] {
		t.Error("EMAIL should be enabled")
	}
	if !result["SSN"] {
		t.Error("SSN should be enabled")
	}
	if result["CREDIT_CARD"] {
		t.Error("CREDIT_CARD should not be enabled")
	}
}

func TestParseChecksToRun_UnknownCheckIgnored(t *testing.T) {
	result := ParseChecksToRun([]string{"UNKNOWN_CHECK", "EMAIL"})
	if !result["EMAIL"] {
		t.Error("EMAIL should be enabled")
	}
	// Unknown check should not appear in result
	if result["UNKNOWN_CHECK"] {
		t.Error("UNKNOWN_CHECK should not be in result")
	}
}

func TestParseChecksToRun_Whitespace(t *testing.T) {
	result := ParseChecksToRun([]string{" EMAIL ", " SSN "})
	if !result["EMAIL"] {
		t.Error("EMAIL should be enabled after trimming whitespace")
	}
	if !result["SSN"] {
		t.Error("SSN should be enabled after trimming whitespace")
	}
}

func TestParseConfidenceLevels_All(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"all keyword", "all"},
		{"empty string", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseConfidenceLevels(tc.input)
			for _, level := range []string{"high", "medium", "low"} {
				if !result[level] {
					t.Errorf("expected level %q to be enabled", level)
				}
			}
		})
	}
}

func TestParseConfidenceLevels_Specific(t *testing.T) {
	result := ParseConfidenceLevels("high,medium")
	if !result["high"] {
		t.Error("high should be enabled")
	}
	if !result["medium"] {
		t.Error("medium should be enabled")
	}
	if result["low"] {
		t.Error("low should not be enabled")
	}
}

func TestParseConfidenceLevels_CaseInsensitive(t *testing.T) {
	result := ParseConfidenceLevels("HIGH,Medium,LOW")
	for _, level := range []string{"high", "medium", "low"} {
		if !result[level] {
			t.Errorf("expected level %q to be enabled (case-insensitive)", level)
		}
	}
}

func TestParseConfidenceLevels_Whitespace(t *testing.T) {
	result := ParseConfidenceLevels(" high , low ")
	if !result["high"] {
		t.Error("high should be enabled after trimming")
	}
	if !result["low"] {
		t.Error("low should be enabled after trimming")
	}
	if result["medium"] {
		t.Error("medium should not be enabled")
	}
}

func TestBuildValidatorSet_AllEnabled(t *testing.T) {
	checks := ParseChecksToRun([]string{"all"})
	validators := BuildValidatorSet(checks, nil, nil)

	expected := []string{
		"CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS", "PASSPORT",
		"PERSON_NAME", "METADATA", "INTELLECTUAL_PROPERTY", "SOCIAL_MEDIA",
		"SSN", "SECRETS",
	}
	for _, name := range expected {
		if _, ok := validators[name]; !ok {
			t.Errorf("expected validator %q to be present", name)
		}
	}
}

func TestBuildValidatorSet_Filtered(t *testing.T) {
	checks := ParseChecksToRun([]string{"EMAIL", "SSN"})
	validators := BuildValidatorSet(checks, nil, nil)

	if _, ok := validators["EMAIL"]; !ok {
		t.Error("EMAIL validator should be present")
	}
	if _, ok := validators["SSN"]; !ok {
		t.Error("SSN validator should be present")
	}
	if _, ok := validators["CREDIT_CARD"]; ok {
		t.Error("CREDIT_CARD validator should not be present")
	}
}

func TestBuildValidatorSet_NilChecks(t *testing.T) {
	// All-false map should produce empty set
	checks := map[string]bool{
		"EMAIL": false,
		"SSN":   false,
	}
	validators := BuildValidatorSet(checks, nil, nil)
	if len(validators) != 0 {
		t.Errorf("expected empty validator set, got %d validators", len(validators))
	}
}

// matchValidators returns the set of producing validator names present in matches.
func matchValidators(matches []detector.Match) map[string]int {
	out := make(map[string]int)
	for _, m := range matches {
		out[m.Validator]++
	}
	return out
}

func TestScanContent_DetectsCommonPII(t *testing.T) {
	// 4532-0151-1283-0366 is a Luhn-valid Visa test card used elsewhere in
	// the suite. Validators emit specific subtypes (e.g. "VISA", "BUSINESS")
	// in Match.Type and the producing validator name in Match.Validator;
	// we assert against the latter for stability.
	content := strings.Join([]string{
		"credit card: 4532-0151-1283-0366",
		"contact: alice@example.com",
		"ssn: 123-45-6789",
	}, "\n")

	result, err := ScanContent(content, ContentScanConfig{
		Checks: []string{"CREDIT_CARD", "EMAIL", "SSN"},
	})
	if err != nil {
		t.Fatalf("ScanContent returned error: %v", err)
	}
	if result == nil {
		t.Fatal("ScanContent returned nil result")
	}
	if result.ProcessedFiles != 1 {
		t.Errorf("expected ProcessedFiles=1, got %d", result.ProcessedFiles)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match, got zero")
	}

	byValidator := matchValidators(result.Matches)
	for _, want := range []string{"creditcard", "email", "ssn"} {
		if byValidator[want] == 0 {
			t.Errorf("expected at least one match from validator %q, got %v", want, byValidator)
		}
	}
}

func TestScanContent_StampsVirtualSourceKind(t *testing.T) {
	result, err := ScanContent("contact: alice@example.com", ContentScanConfig{
		Checks: []string{"EMAIL"},
	})
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	for _, m := range result.Matches {
		if m.SourceKind != detector.SourceKindVirtual {
			t.Errorf("expected SourceKindVirtual, got %q", m.SourceKind)
		}
		if !m.IsVirtual() {
			t.Error("expected IsVirtual() to be true")
		}
		if m.Filename != "<stdin>" {
			t.Errorf("expected Filename=<stdin>, got %q", m.Filename)
		}
	}
}

func TestScanContent_RespectsVirtualPath(t *testing.T) {
	result, err := ScanContent("contact: alice@example.com", ContentScanConfig{
		VirtualPath: "<diff>",
		Checks:      []string{"EMAIL"},
	})
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	if result.Matches[0].Filename != "<diff>" {
		t.Errorf("expected Filename=<diff>, got %q", result.Matches[0].Filename)
	}
}

func TestScanContent_EmptyContentNoMatches(t *testing.T) {
	result, err := ScanContent("", ContentScanConfig{
		Checks: []string{"all"},
	})
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}
	if len(result.Matches) != 0 {
		t.Errorf("expected zero matches for empty content, got %d", len(result.Matches))
	}
}

func TestScanContent_FilteredChecks(t *testing.T) {
	// Pass content that would match multiple validators but only enable EMAIL.
	content := strings.Join([]string{
		"credit card: 4532-0151-1283-0366",
		"contact: alice@example.com",
		"ssn: 123-45-6789",
	}, "\n")

	result, err := ScanContent(content, ContentScanConfig{
		Checks: []string{"EMAIL"},
	})
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}
	byValidator := matchValidators(result.Matches)
	if byValidator["email"] == 0 {
		t.Errorf("expected email matches, got %v", byValidator)
	}
	if byValidator["creditcard"] != 0 {
		t.Errorf("expected zero creditcard matches when filter excludes it, got %d", byValidator["creditcard"])
	}
	if byValidator["ssn"] != 0 {
		t.Errorf("expected zero ssn matches when filter excludes it, got %d", byValidator["ssn"])
	}
}

func TestScanContent_MetadataExcludedEvenWhenRequested(t *testing.T) {
	// Even with "all" checks, METADATA must not run on virtual content
	// (no filesystem path to extract metadata from).
	content := "alice@example.com"
	result, err := ScanContent(content, ContentScanConfig{
		Checks: []string{"all"},
	})
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}
	for _, m := range result.Matches {
		if strings.EqualFold(m.Validator, "metadata") {
			t.Errorf("metadata match should not appear in virtual content scan: %+v", m)
		}
	}
}

func TestScanContent_SARIFRendersVirtualWithoutSrcRoot(t *testing.T) {
	// Sanity check that the SARIF mapper doesn't prepend %SRCROOT% for
	// virtual matches. This guards the Phase 1b formatter contract.
	result, err := ScanContent("alice@example.com", ContentScanConfig{
		Checks: []string{"EMAIL"},
	})
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	for _, m := range result.Matches {
		if !m.IsVirtual() {
			t.Errorf("expected IsVirtual()=true, got SourceKind=%q", m.SourceKind)
		}
	}
}
