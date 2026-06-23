// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/explain"
)

func TestSanitizeDescription_IncludesExplanation(t *testing.T) {
	s := []detector.Match{{
		Text: "4111111111111111", Type: "CREDIT_CARD", Confidence: 30,
		Filename: "card_test.go", LineNumber: 1, Validator: "creditcard",
		Metadata: map[string]any{"validation_checks": map[string]bool{"luhn": true, "not_test": false}},
	}}
	explain.Annotate(s, explain.NewSignalSynthesizer())

	desc := NewDataSanitizer().SanitizeDescription(s[0], false)
	for _, want := range []string{"**Why:**", "**Verdict:**", "**Suggested suppression reason:**"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}
}

func TestSanitizeDescription_NoExplanationWhenAbsent(t *testing.T) {
	m := detector.Match{
		Text: "x", Type: "EMAIL", Confidence: 50, Filename: "a.go", LineNumber: 1,
	}
	desc := NewDataSanitizer().SanitizeDescription(m, false)
	if strings.Contains(desc, "**Why:**") {
		t.Errorf("description should not contain explanation when unannotated:\n%s", desc)
	}
}
