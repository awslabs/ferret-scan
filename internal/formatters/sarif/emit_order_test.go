// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestResults_StableOrder locks the order of the SARIF results array. The
// formatter walked the findings slice as the scanner handed it over — per-file
// worker completion order — so two SARIF reports of one unchanged scan listed
// their results in different sequences.
func TestResults_StableOrder(t *testing.T) {
	// Supplied in neither the expected order nor its reverse.
	matches := []detector.Match{
		{Text: "4929381332664295", LineNumber: 4, Type: "CREDIT_CARD", Confidence: 100, Filename: "b.txt", Validator: "creditcard"},
		{Text: "Acme Corp", LineNumber: 1, Type: "BUSINESS", Confidence: 65, Filename: "b.txt", Validator: "business"},
		{Text: "212-555-0142", LineNumber: 1, Type: "PHONE", Confidence: 92, Filename: "a.txt", Validator: "phone"},
		{Text: "AKIAIOSFODNN7EXAMPLE", LineNumber: 2, Type: "AWS_ACCESS_KEY", Confidence: 95, Filename: "a.txt", Validator: "secrets"},
		{Text: "449-87-4100", LineNumber: 3, Type: "SSN", Confidence: 100, Filename: "a.txt", Validator: "ssn"},
	}

	// Shared total order: confidence desc, then type, then line, then filename.
	want := []string{
		"CREDIT_CARD:4",
		"SSN:3",
		"AWS_ACCESS_KEY:2",
		"PHONE:1",
		"BUSINESS:1",
	}

	levels := map[string]bool{"high": true, "medium": true, "low": true}
	f := NewFormatter()
	for i := 0; i < 200; i++ {
		out, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: levels})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}

		var report SARIFReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("unmarshal SARIF: %v", err)
		}
		if len(report.Runs) != 1 {
			t.Fatalf("want 1 run, got %d", len(report.Runs))
		}

		got := make([]string, 0, len(report.Runs[0].Results))
		for _, r := range report.Runs[0].Results {
			line := 0
			if len(r.Locations) > 0 {
				line = r.Locations[0].PhysicalLocation.Region.StartLine
			}
			got = append(got, fmt.Sprintf("%s:%d", r.RuleID, line))
		}
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d results, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: result %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestGetAllRules_StableOrder locks the tool.driver.rules order. GetAllRules
// ranged the rule cache map directly, so the array was permuted between runs
// and two SARIF reports of one unchanged scan differed — a problem for any
// consumer that diffs or hashes the report, and for a human reading it as an
// artifact.
func TestGetAllRules_StableOrder(t *testing.T) {
	// Registered in neither the expected order nor its reverse.
	register := []string{"SSN", "AWS_ACCESS_KEY", "PHONE", "EMAIL", "CREDIT_CARD", "BUSINESS", "IP_ADDRESS"}
	want := []string{"AWS_ACCESS_KEY", "BUSINESS", "CREDIT_CARD", "EMAIL", "IP_ADDRESS", "PHONE", "SSN"}

	// 200 iterations: enough that a randomized map order over seven keys is
	// overwhelmingly unlikely to match the expected order every time.
	for i := 0; i < 200; i++ {
		rm := NewRuleManager()
		for _, id := range register {
			rm.GetOrCreateRule(id)
		}

		rules := rm.GetAllRules()
		if len(rules) != len(want) {
			t.Fatalf("iteration %d: got %d rules, want %d", i, len(rules), len(want))
		}
		for j := range want {
			if rules[j].ID != want[j] {
				got := make([]string, len(rules))
				for k, r := range rules {
					got[k] = r.ID
				}
				t.Fatalf("iteration %d: rule %d = %q, want %q\nfull order: %v",
					i, j, rules[j].ID, want[j], got)
			}
		}
	}
}
