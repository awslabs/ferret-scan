// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

func allLevels() map[string]bool {
	return map[string]bool{"high": true, "medium": true, "low": true}
}

// iterations is high enough that a randomized Go map order over the inputs below
// is overwhelmingly unlikely to produce the expected order every time by chance.
const iterations = 200

// TestMetadataBullets_StableOrder locks the "Additional Information" bullet
// order. The bullets were rendered by ranging match.Metadata directly, so the
// same finding produced a different description string on each run — and GitLab
// keys a vulnerability's identity partly on its description, so an unchanged
// finding could read as a new one across pipeline runs.
func TestMetadataBullets_StableOrder(t *testing.T) {
	matches := []detector.Match{{
		Text:       "4929381332664295",
		LineNumber: 3,
		Type:       "CREDIT_CARD",
		Confidence: 95,
		Filename:   "payments.csv",
		Validator:  "creditcard",
		// Every key here must be in IsSafeMetadataKey, otherwise it is
		// filtered out before ordering matters.
		Metadata: map[string]interface{}{
			"vendor":              "visa",
			"card_type":           "VISA",
			"source":              "body",
			"pattern_type":        "grouped",
			"check_type":          "CREDIT_CARD",
			"confidence_level":    "HIGH",
			"analysis_confidence": "0.95",
		},
	}}

	want := []string{
		"- analysis_confidence: 0.95",
		"- card_type: VISA",
		"- check_type: CREDIT_CARD",
		"- confidence_level: HIGH",
		"- pattern_type: grouped",
		"- source: body",
		"- vendor: visa",
	}

	f := NewFormatter()
	for i := 0; i < iterations; i++ {
		out, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: allLevels()})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}

		var report GitLabSecurityReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(report.Vulnerabilities) != 1 {
			t.Fatalf("want 1 vulnerability, got %d", len(report.Vulnerabilities))
		}

		got := bulletLines(report.Vulnerabilities[0].Description)
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d bullets, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: bullet %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// bulletLines extracts the "- key: value" lines from the Additional Information
// section of a gitlab-sast description.
func bulletLines(description string) []string {
	var out []string
	inSection := false
	for _, line := range strings.Split(description, "\n") {
		switch {
		case strings.Contains(line, "**Additional Information:**"):
			inSection = true
		case inSection && strings.HasPrefix(line, "- "):
			out = append(out, line)
		case inSection && strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "- "):
			return out
		}
	}
	return out
}

// TestVulnerabilities_StableOrder locks the order of the vulnerabilities array.
// gitlab-sast was the one formatter that never sorted its findings at all, so
// the array followed the scanner's arrival order (per-file worker completion)
// and two reports of one unchanged scan were not comparable.
func TestVulnerabilities_StableOrder(t *testing.T) {
	// Deliberately supplied in an order that is neither the expected output
	// order nor its reverse.
	matches := []detector.Match{
		{Text: "4929381332664295", LineNumber: 4, Type: "CREDIT_CARD", Confidence: 100, Filename: "b.txt", Validator: "creditcard"},
		{Text: "Acme Corp", LineNumber: 1, Type: "BUSINESS", Confidence: 65, Filename: "b.txt", Validator: "business"},
		{Text: "212-555-0142", LineNumber: 1, Type: "PHONE", Confidence: 92, Filename: "a.txt", Validator: "phone"},
		{Text: "AKIAIOSFODNN7EXAMPLE", LineNumber: 2, Type: "AWS_ACCESS_KEY", Confidence: 95, Filename: "a.txt", Validator: "secrets"},
		{Text: "449-87-4100", LineNumber: 3, Type: "SSN", Confidence: 100, Filename: "a.txt", Validator: "ssn"},
	}

	f := NewFormatter()
	var first []string
	for i := 0; i < iterations; i++ {
		out, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: allLevels()})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}
		var report GitLabSecurityReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		got := make([]string, 0, len(report.Vulnerabilities))
		for _, v := range report.Vulnerabilities {
			got = append(got, fmt.Sprintf("%s:%d", v.Location.File, v.Location.StartLine))
		}
		if len(got) != len(matches) {
			t.Fatalf("iteration %d: got %d vulnerabilities, want %d", i, len(got), len(matches))
		}

		if first == nil {
			first = got
			continue
		}
		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("iteration %d: vulnerability order changed at %d: got %q, first run had %q\nnow:   %v\nfirst: %v",
					i, j, got[j], first[j], got, first)
			}
		}
	}

	// The order must also be the shared total order rather than merely
	// repeatable within one process: descending confidence, then type, then
	// line, then filename. Hence the two confidence-100 findings lead, with
	// CREDIT_CARD before SSN on type.
	want := []string{
		"b.txt:4", // CREDIT_CARD, 100
		"a.txt:3", // SSN,         100
		"a.txt:2", // AWS_ACCESS_KEY, 95
		"a.txt:1", // PHONE,       92
		"b.txt:1", // BUSINESS,    65
	}
	for j := range want {
		if first[j] != want[j] {
			t.Errorf("position %d = %q, want %q (full: %v)", j, first[j], want[j], first)
		}
	}
}
