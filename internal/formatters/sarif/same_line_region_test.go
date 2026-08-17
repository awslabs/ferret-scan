// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// Two findings for the same value on one line must get their OWN regions.
//
// buildRegion located the match with strings.Index(FullLine, Text), which always
// returns the FIRST occurrence. Both findings therefore reported identical
// startColumn/endColumn: an IDE or GitHub annotation marked the first occurrence's
// characters twice and the second occurrence's characters never.
//
// Measured on the shipped binary for a line holding the same address twice:
//
//	BUSINESS line=1 col=9-25
//	BUSINESS line=1 col=9-25     <- the second value actually sits at 29-45
//
// So the defect is not merely "indistinguishable"; the second region is WRONG.
func TestSameLineMatchesGetDistinctRegions(t *testing.T) {
	const line = "Contact barml@example.com or barml@example.com for access."
	const value = "barml@example.com"

	first := strings.Index(line, value)
	second := strings.Index(line[first+len(value):], value) + first + len(value)

	matches := []detector.Match{
		{
			Text: value, Type: "EMAIL", Confidence: 90, LineNumber: 142,
			Filename: "notes.txt", Validator: "email",
			StartColumn: first + 1, EndColumn: first + len(value) + 1,
			Context: detector.ContextInfo{FullLine: line},
		},
		{
			Text: value, Type: "EMAIL", Confidence: 90, LineNumber: 142,
			Filename: "notes.txt", Validator: "email",
			StartColumn: second + 1, EndColumn: second + len(value) + 1,
			Context: detector.ContextInfo{FullLine: line},
		},
	}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true}})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var report struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
							EndColumn   int `json:"endColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 2 {
		t.Fatalf("got %d results, want 2", len(report.Runs[0].Results))
	}

	type reg struct{ start, end int }
	var got []reg
	for _, r := range report.Runs[0].Results {
		g := r.Locations[0].PhysicalLocation.Region
		got = append(got, reg{g.StartColumn, g.EndColumn})
	}
	if got[0] == got[1] {
		t.Fatalf("both results report region %v — the second occurrence's characters are never "+
			"annotated and the first's are annotated twice", got[0])
	}

	// Each region must address the value in the line.
	for i, g := range got {
		if g.start <= 0 || g.end <= g.start || g.end-1 > len(line) {
			t.Fatalf("result %d region %d-%d is not a valid span for a %d-byte line",
				i, g.start, g.end, len(line))
		}
		if line[g.start-1:g.end-1] != value {
			t.Errorf("result %d region %d-%d addresses %q, want %q",
				i, g.start, g.end, line[g.start-1:g.end-1], value)
		}
	}
}

// A match with no column must still get a region, from the first occurrence.
//
// Synthesised match text (a social-media cluster) has no literal position, and a
// caller building a Match by hand may not set one. That must degrade to the previous
// behaviour rather than emitting no region at all.
func TestRegionFallsBackWhenNoColumnRecorded(t *testing.T) {
	const line = "Contact ops@example.com today."
	matches := []detector.Match{{
		Text: "ops@example.com", Type: "EMAIL", Confidence: 90, LineNumber: 7,
		Filename: "notes.txt", Validator: "email",
		// StartColumn deliberately unset.
		Context: detector.ContextInfo{FullLine: line},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true}})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(out, `"startColumn"`) {
		t.Error("no startColumn emitted; a match without a recorded column must still fall back " +
			"to the first occurrence")
	}
	want := strings.Index(line, "ops@example.com") + 1
	if !strings.Contains(out, `"startColumn": `+itoa(want)) &&
		!strings.Contains(out, `"startColumn":`+itoa(want)) {
		t.Errorf("expected startColumn %d in the output", want)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
