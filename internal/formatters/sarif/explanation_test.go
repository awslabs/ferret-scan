// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

func annotated(t *testing.T) detector.Match {
	t.Helper()
	s := []detector.Match{{
		Text: "4111111111111111", Type: "VISA", Confidence: 30,
		Filename: "card_test.go", Validator: "creditcard",
		Metadata: map[string]any{"validation_checks": map[string]bool{"luhn": true, "not_test": false}},
	}}
	explain.Annotate(s, explain.NewSignalSynthesizer())
	return s[0]
}

func TestSARIF_ExplanationInMessageAndProperties(t *testing.T) {
	mapper := NewVulnerabilityMapper(NewRuleManager())
	res, err := mapper.MapToSARIFResult(annotated(t), formatters.FormatterOptions{})
	if err != nil {
		t.Fatalf("MapToSARIFResult: %v", err)
	}

	// Message (what GitHub code-scanning shows) must carry the rationale.
	if !strings.Contains(res.Message.Text, "Why:") || !strings.Contains(res.Message.Text, "Verdict:") {
		t.Errorf("SARIF message missing explanation: %q", res.Message.Text)
	}

	// Properties must carry a first-class, structured explanation...
	exProp, ok := res.Properties["explanation"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured explanation property, got %T", res.Properties["explanation"])
	}
	if exProp["verdict"] == "" || exProp["rationale"] == "" {
		t.Errorf("explanation property not populated: %+v", exProp)
	}

	// ...and it must NOT be duplicated in the raw metadata blob.
	if md, ok := res.Properties["metadata"].(map[string]interface{}); ok {
		if _, dup := md[explain.MetadataKey]; dup {
			t.Error("explanation must not also appear in the metadata property")
		}
	}
}

func TestSARIF_NoExplanationWhenAbsent(t *testing.T) {
	mapper := NewVulnerabilityMapper(NewRuleManager())
	m := detector.Match{Text: "x", Type: "EMAIL", Confidence: 50, Filename: "a.go", LineNumber: 1}
	res, err := mapper.MapToSARIFResult(m, formatters.FormatterOptions{})
	if err != nil {
		t.Fatalf("MapToSARIFResult: %v", err)
	}
	if strings.Contains(res.Message.Text, "Why:") {
		t.Error("message should not mention explanation when match is unannotated")
	}
	if _, present := res.Properties["explanation"]; present {
		t.Error("explanation property should be absent when match is unannotated")
	}
}
