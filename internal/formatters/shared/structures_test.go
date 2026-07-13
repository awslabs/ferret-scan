// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// Built at runtime so this synthetic test fixture does not trip the repo's
// secret scanner (matches the buildTestToken convention in the secrets validator tests).
var sensitiveValue = "sk_live_" + "51H7qYKJ2eZvKYlo2C8nKqp6"

func sampleMatches() []detector.Match {
	return []detector.Match{
		{
			Text:       sensitiveValue,
			LineNumber: 12,
			Type:       "STRIPE_KEY",
			Confidence: 95,
			Filename:   "config.go",
			Context: detector.ContextInfo{
				FullLine:   "apiKey := \"" + sensitiveValue + "\"",
				BeforeText: "apiKey := \"",
				AfterText:  "\"",
			},
		},
	}
}

// TestConvertMatchesToJSONFormat_ShowMatchFalseHidesText verifies that raw
// sensitive data is never serialized into JSON/YAML output when ShowMatch is
// false. This guards against a regression where match.Text was copied
// unconditionally, leaking PII regardless of the show_match setting.
func TestConvertMatchesToJSONFormat_ShowMatchFalseHidesText(t *testing.T) {
	resp := ConvertMatchesToJSONFormat(sampleMatches(), nil, formatters.FormatterOptions{
		ShowMatch: false,
		Verbose:   true, // Verbose must not re-leak the value via context fields.
	})

	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	r := resp.Results[0]

	if r.Text != "[HIDDEN]" {
		t.Errorf("Text = %q, want %q", r.Text, "[HIDDEN]")
	}
	if r.FullLine != "" {
		t.Errorf("FullLine should be empty when ShowMatch is false, got %q", r.FullLine)
	}
	if r.BeforeText != "" || r.AfterText != "" {
		t.Errorf("context text should be empty when ShowMatch is false, got before=%q after=%q", r.BeforeText, r.AfterText)
	}
}

// TestConvertMatchesToJSONFormat_ShowMatchTrueRevealsText verifies that the
// actual matched text and context are included when the operator opts in via
// ShowMatch.
func TestConvertMatchesToJSONFormat_ShowMatchTrueRevealsText(t *testing.T) {
	resp := ConvertMatchesToJSONFormat(sampleMatches(), nil, formatters.FormatterOptions{
		ShowMatch: true,
		Verbose:   true,
	})

	r := resp.Results[0]
	if r.Text != sensitiveValue {
		t.Errorf("Text = %q, want %q", r.Text, sensitiveValue)
	}
	if !strings.Contains(r.FullLine, sensitiveValue) {
		t.Errorf("FullLine should contain the matched value when ShowMatch is true, got %q", r.FullLine)
	}
}

// TestSanitizeMetadata_DenyByDefault verifies the fail-safe allowlist model:
// when ShowMatch is false, only known-safe keys survive and every other key
// (including unknown/future ones and value-bearing ones like name_components /
// full_field) is withheld; when ShowMatch is true, everything is returned
// (except the explain key, which is surfaced separately).
func TestSanitizeMetadata_DenyByDefault(t *testing.T) {
	meta := map[string]interface{}{
		// safe, allowlisted
		"card_type":         "VISA",
		"vendor":            "Visa",
		"validation_checks": map[string]bool{"luhn": true},
		"context_impact":    0,
		// value-bearing / PII — must be withheld when hidden
		"name_components": map[string]interface{}{"FullName": "Robert Aragon", "FirstName": "Robert"},
		"full_field":      "Author: Brian Hileman",
		"clean_number":    "4929381332664295",
		"username":        "secretuser",
		// unknown future key — must be withheld by default
		"some_new_key": "anything could be here",
	}

	// Hidden: only allowlisted keys remain.
	hidden := SanitizeMetadata(meta, "Robert Aragon", false)
	allowed := map[string]bool{"card_type": true, "vendor": true, "validation_checks": true, "context_impact": true}
	for k := range hidden {
		if !allowed[k] {
			t.Errorf("key %q leaked through deny-by-default sanitizer", k)
		}
	}
	for k := range allowed {
		if _, ok := hidden[k]; !ok {
			t.Errorf("safe key %q should be retained when hidden", k)
		}
	}
	// Explicitly confirm the PII/unknown keys are gone.
	for _, k := range []string{"name_components", "full_field", "clean_number", "username", "some_new_key"} {
		if _, ok := hidden[k]; ok {
			t.Errorf("PII/unknown key %q must be withheld when ShowMatch=false", k)
		}
	}

	// Shown: everything is returned.
	shown := SanitizeMetadata(meta, "Robert Aragon", true)
	for k := range meta {
		if _, ok := shown[k]; !ok {
			t.Errorf("key %q should be present when ShowMatch=true", k)
		}
	}
}

// TestSanitizeMetadata_DropsExplainKey confirms the explain key is never dumped
// raw (it is surfaced as a first-class field), regardless of ShowMatch.
func TestSanitizeMetadata_DropsExplainKey(t *testing.T) {
	meta := map[string]interface{}{"card_type": "VISA"}
	meta[explain.MetadataKey] = "raw explain blob"
	for _, show := range []bool{true, false} {
		out := SanitizeMetadata(meta, "x", show)
		if _, ok := out[explain.MetadataKey]; ok {
			t.Errorf("explain key must never be in sanitized metadata (showMatch=%v)", show)
		}
	}
}

// sampleSuppressed builds a suppressed match whose finding carries the matched
// value in Text, Metadata, and Context — the three places the JSON/YAML
// `suppressed` block would otherwise re-leak.
func sampleSuppressed() []detector.SuppressedMatch {
	return []detector.SuppressedMatch{{
		Match: detector.Match{
			Text:       sensitiveValue,
			LineNumber: 12,
			Type:       "STRIPE_KEY",
			Confidence: 95,
			Filename:   "config.go",
			Validator:  "secrets",
			Metadata: map[string]interface{}{
				"secret_type": "stripe",                // allowlisted, structural
				"full_field":  "key=" + sensitiveValue, // value-bearing, must drop
			},
			Context: detector.ContextInfo{
				FullLine:   "apiKey := \"" + sensitiveValue + "\"",
				BeforeText: "apiKey := \"",
				AfterText:  "\"",
			},
		},
		SuppressedBy: "SUP-00000001",
		RuleReason:   "known test key",
	}}
}

// TestSanitizeSuppressedMatches_HidesValueByDefault is a regression test for the
// `--show-suppressed` (without `--show-match`) leak: the JSON/YAML suppressed
// block embedded the raw finding. The value, metadata, and context must be
// withheld by default, while the structural and suppression fields are kept.
func TestSanitizeSuppressedMatches_HidesValueByDefault(t *testing.T) {
	out := SanitizeSuppressedMatches(sampleSuppressed(), false)
	if len(out) != 1 {
		t.Fatalf("expected 1 suppressed match, got %d", len(out))
	}
	f := out[0].Match
	if f.Text != redactionPlaceholder {
		t.Errorf("suppressed Text = %q, want %q", f.Text, redactionPlaceholder)
	}
	if f.Context.FullLine != "" || f.Context.BeforeText != "" || f.Context.AfterText != "" {
		t.Errorf("suppressed Context must be cleared when hidden: %+v", f.Context)
	}
	if _, ok := f.Metadata["full_field"]; ok {
		t.Error("value-bearing metadata key full_field leaked in suppressed block")
	}
	if _, ok := f.Metadata["secret_type"]; !ok {
		t.Error("allowlisted metadata key secret_type should be retained")
	}
	// Structural + suppression fields must survive so the entry stays useful.
	if f.Type != "STRIPE_KEY" || f.LineNumber != 12 || f.Confidence != 95 || f.Validator != "secrets" {
		t.Errorf("structural fields not preserved: %+v", f)
	}
	if out[0].SuppressedBy != "SUP-00000001" || out[0].RuleReason != "known test key" {
		t.Errorf("suppression envelope not preserved: by=%q reason=%q", out[0].SuppressedBy, out[0].RuleReason)
	}

	// The original input must not be mutated (we operate on copies).
	orig := sampleSuppressed()[0]
	_ = SanitizeSuppressedMatches([]detector.SuppressedMatch{orig}, false)
	if orig.Match.Text != sensitiveValue {
		t.Error("SanitizeSuppressedMatches mutated the caller's input")
	}
}

// TestSanitizeSuppressedMatches_RevealsWithShowMatch verifies the web UI path:
// with ShowMatch the suppressed finding is returned intact so the client-side
// reveal of suppressed findings still works.
func TestSanitizeSuppressedMatches_RevealsWithShowMatch(t *testing.T) {
	out := SanitizeSuppressedMatches(sampleSuppressed(), true)
	f := out[0].Match
	if f.Text != sensitiveValue {
		t.Errorf("suppressed Text = %q, want real value when ShowMatch=true", f.Text)
	}
	if f.Context.FullLine == "" {
		t.Error("suppressed Context.FullLine should be present when ShowMatch=true")
	}
}
