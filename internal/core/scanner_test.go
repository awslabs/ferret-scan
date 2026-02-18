// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"testing"
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
