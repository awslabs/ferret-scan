// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/formatters"
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
