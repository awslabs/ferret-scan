// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

var allLevelsAccum = map[string]bool{"high": true, "medium": true, "low": true}

// rulesIn extracts the tool.driver.rules[].id set from a SARIF document.
func rulesIn(t *testing.T, doc string) map[string]bool {
	t.Helper()
	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	ids := map[string]bool{}
	if len(parsed.Runs) > 0 {
		for _, r := range parsed.Runs[0].Tool.Driver.Rules {
			ids[r.ID] = true
		}
	}
	return ids
}

// TestSARIF_NoRuleAccumulationAcrossCalls is the regression test for the
// rule-accumulation bug: the formatter is a process singleton (registered in
// formatters.DefaultRegistry), and it used to cache a RuleManager that
// accumulated rules across Format() calls. As a result, formatting a report for
// one input would include rules from inputs formatted earlier in the same
// process — a cross-invocation contamination bug for long-lived embedders (the
// web server). After the fix, each Format() builds its rules fresh, so a
// report's rules array reflects ONLY that call's matches.
func TestSARIF_NoRuleAccumulationAcrossCalls(t *testing.T) {
	f := NewFormatter() // ONE formatter, reused — the singleton scenario.

	emailMatch := []detector.Match{{
		Text: "a@b.com", Type: "EMAIL", Confidence: 100, Filename: "x.txt", LineNumber: 1, Validator: "email",
	}}
	ssnMatch := []detector.Match{{
		Text: "449-87-4100", Type: "SSN", Confidence: 100, Filename: "y.txt", LineNumber: 1, Validator: "ssn",
	}}

	// First call: only EMAIL.
	first, err := f.Format(emailMatch, nil, formatters.FormatterOptions{ConfidenceLevel: allLevelsAccum})
	if err != nil {
		t.Fatalf("first Format: %v", err)
	}
	firstRules := rulesIn(t, first)
	if !firstRules["EMAIL"] || firstRules["SSN"] {
		t.Fatalf("first report rules = %v; want {EMAIL} only", firstRules)
	}

	// Second call on the SAME formatter: only SSN. Must NOT contain EMAIL
	// (which would prove leakage from the first call).
	second, err := f.Format(ssnMatch, nil, formatters.FormatterOptions{ConfidenceLevel: allLevelsAccum})
	if err != nil {
		t.Fatalf("second Format: %v", err)
	}
	secondRules := rulesIn(t, second)
	if !secondRules["SSN"] {
		t.Fatalf("second report missing SSN rule: %v", secondRules)
	}
	if secondRules["EMAIL"] {
		t.Errorf("rule accumulation regression: second report leaked EMAIL rule from the first call: %v", secondRules)
	}
}

// TestSARIF_FormatIsIdempotentAcrossCalls confirms formatting the SAME input
// twice on a reused formatter yields byte-identical output (no stateful drift).
func TestSARIF_FormatIsIdempotentAcrossCalls(t *testing.T) {
	f := NewFormatter()
	matches := []detector.Match{{
		Text: "a@b.com", Type: "EMAIL", Confidence: 100, Filename: "x.txt", LineNumber: 1, Validator: "email",
	}}
	opts := formatters.FormatterOptions{ConfidenceLevel: allLevelsAccum}

	out1, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatalf("Format 1: %v", err)
	}
	out2, err := f.Format(matches, nil, opts)
	if err != nil {
		t.Fatalf("Format 2: %v", err)
	}
	if out1 != out2 {
		t.Errorf("SARIF output not idempotent across calls on a reused formatter")
	}
}
