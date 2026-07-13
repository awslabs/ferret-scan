// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

func annotatedMatch() detector.Match {
	m := detector.Match{
		Text:       "4111111111111111",
		Type:       "VISA",
		Confidence: 30,
		Filename:   "card_test.go",
		Validator:  "creditcard",
		Metadata: map[string]any{
			"vendor":            "Visa",
			"validation_checks": map[string]bool{"luhn": true, "not_test": false},
		},
	}
	s := []detector.Match{m}
	explain.Annotate(s, explain.NewSignalSynthesizer())
	return s[0]
}

func TestJSONFormat_ExplanationIsFirstClass(t *testing.T) {
	m := annotatedMatch()
	opts := formatters.FormatterOptions{ConfidenceLevel: map[string]bool{"low": true, "medium": true, "high": true}}
	resp := ConvertMatchesToJSONFormat([]detector.Match{m}, nil, opts)

	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	r := resp.Results[0]

	// Explanation must be a first-class, populated field.
	if r.Explanation == nil {
		t.Fatal("expected first-class Explanation field, got nil")
	}
	if r.Explanation.Rationale == "" || r.Explanation.Verdict == "" {
		t.Errorf("explanation fields not populated: %+v", r.Explanation)
	}

	// And it must NOT be duplicated inside the raw metadata blob.
	if r.Metadata != nil {
		if _, dup := r.Metadata[explain.MetadataKey]; dup {
			t.Error("explanation must not also appear in the raw metadata map")
		}
	}
}

func TestJSONFormat_NoExplanationWhenAbsent(t *testing.T) {
	m := detector.Match{
		Text: "x", Type: "EMAIL", Confidence: 50, Filename: "a.go",
		Metadata: map[string]any{"vendor": "n/a"},
	}
	opts := formatters.FormatterOptions{ConfidenceLevel: map[string]bool{"low": true}}
	resp := ConvertMatchesToJSONFormat([]detector.Match{m}, nil, opts)
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	if resp.Results[0].Explanation != nil {
		t.Error("Explanation must be nil when the match was not annotated")
	}
	// Non-explanation metadata is preserved.
	if resp.Results[0].Metadata["vendor"] != "n/a" {
		t.Error("non-explanation metadata should be preserved")
	}
}
