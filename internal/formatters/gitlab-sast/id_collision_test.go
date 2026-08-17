// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// Every emitted vulnerability must carry a distinct id.
//
// The id was sha256("filename:line:type"), so two findings for the same value on
// one line hashed to ONE id. GitLab deduplicates by id, so it kept one and silently
// dropped the other — a reported finding lost at the consumer, at exit 0.
//
// Measured on the shipped binary, a file with an address twice on line 1 and an SSN
// twice on line 2: 4 vulnerabilities emitted, 2 distinct ids.
//
// The golden corpus cannot catch this: it normalizes the id to "ferret-<HASH>"
// because the raw hash varies with the per-run temp dir, so a collapse is invisible
// there by design. This test is the guard.
func TestEveryVulnerabilityIDIsDistinct(t *testing.T) {
	const line1 = "Contact ops@example.com or ops@example.com for access."
	const line2 = "SSN 449-87-4100 and SSN 449-87-4100 twice."

	levels := map[string]bool{"high": true, "medium": true, "low": true}

	matches := []detector.Match{
		{Text: "ops@example.com", Type: "EMAIL", Confidence: 90, LineNumber: 1,
			Filename: "notes.txt", Validator: "email",
			StartColumn: 9, EndColumn: 24,
			Context: detector.ContextInfo{FullLine: line1}},
		{Text: "ops@example.com", Type: "EMAIL", Confidence: 90, LineNumber: 1,
			Filename: "notes.txt", Validator: "email",
			StartColumn: 28, EndColumn: 43,
			Context: detector.ContextInfo{FullLine: line1}},
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2,
			Filename: "notes.txt", Validator: "ssn",
			StartColumn: 5, EndColumn: 16,
			Context: detector.ContextInfo{FullLine: line2}},
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2,
			Filename: "notes.txt", Validator: "ssn",
			StartColumn: 25, EndColumn: 36,
			Context: detector.ContextInfo{FullLine: line2}},
	}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: levels})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var report struct {
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(report.Vulnerabilities) != len(matches) {
		t.Fatalf("emitted %d vulnerabilities, want %d", len(report.Vulnerabilities), len(matches))
	}

	seen := map[string]int{}
	for _, v := range report.Vulnerabilities {
		seen[v.ID]++
	}
	if len(seen) != len(matches) {
		t.Errorf("%d vulnerabilities collapsed to %d distinct ids — GitLab deduplicates by id, "+
			"so %d reported finding(s) would be dropped on ingest",
			len(report.Vulnerabilities), len(seen), len(report.Vulnerabilities)-len(seen))
		for id, n := range seen {
			if n > 1 {
				t.Errorf("  id %s used %d times", id, n)
			}
		}
	}
}

// Findings with NO column must still get distinct ids.
//
// A synthesised match text — a social-media cluster, a consolidated
// intellectual-property span — has no literal position, so the column is absent and
// cannot disambiguate. The formatter's collision guard has to cover that remainder,
// or the same silent drop returns for exactly the findings that cannot carry a
// column.
func TestVulnerabilityIDsDistinctWithoutColumns(t *testing.T) {
	levels := map[string]bool{"high": true, "medium": true, "low": true}
	const line = "profiles: alice and bob"

	// Same file, line and type, no columns — previously one id for both.
	matches := []detector.Match{
		{Text: "cluster-a", Type: "SOCIAL_MEDIA_CLUSTER", Confidence: 80, LineNumber: 4,
			Filename: "notes.txt", Validator: "socialmedia",
			Context: detector.ContextInfo{FullLine: line}},
		{Text: "cluster-b", Type: "SOCIAL_MEDIA_CLUSTER", Confidence: 80, LineNumber: 4,
			Filename: "notes.txt", Validator: "socialmedia",
			Context: detector.ContextInfo{FullLine: line}},
	}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: levels})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var report struct {
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("emitted %d vulnerabilities, want 2", len(report.Vulnerabilities))
	}
	if report.Vulnerabilities[0].ID == report.Vulnerabilities[1].ID {
		t.Errorf("both position-less findings share id %s; one would be dropped on ingest",
			report.Vulnerabilities[0].ID)
	}
}

// The id must stay a pure function of the report, so a finding keeps its identity
// across scans and GitLab can track it rather than seeing it as new each run.
func TestVulnerabilityIDsAreStableAcrossRuns(t *testing.T) {
	levels := map[string]bool{"high": true, "medium": true, "low": true}
	const line = "SSN 449-87-4100 and SSN 449-87-4100 twice."
	build := func() []detector.Match {
		return []detector.Match{
			{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2,
				Filename: "notes.txt", Validator: "ssn", StartColumn: 5, EndColumn: 16,
				Context: detector.ContextInfo{FullLine: line}},
			{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2,
				Filename: "notes.txt", Validator: "ssn", StartColumn: 25, EndColumn: 36,
				Context: detector.ContextInfo{FullLine: line}},
		}
	}

	ids := func() []string {
		out, err := NewFormatter().Format(build(), nil, formatters.FormatterOptions{ConfidenceLevel: levels})
		if err != nil {
			t.Fatalf("Format: %v", err)
		}
		var report struct {
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var got []string
		for _, v := range report.Vulnerabilities {
			got = append(got, v.ID)
		}
		return got
	}

	want := ids()
	for run := 0; run < 25; run++ {
		got := ids()
		if len(got) != len(want) {
			t.Fatalf("run %d: %d ids, want %d", run, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("run %d: id[%d] = %s, want %s", run, i, got[i], want[i])
			}
		}
	}
}

// The id must not embed the matched value. It appears in a report that is routinely
// published as a CI artifact, so a hash of the secret would be a disclosure.
func TestVulnerabilityIDDoesNotDependOnTheMatchedValue(t *testing.T) {
	m := detector.Match{
		Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2,
		Filename: "notes.txt", Validator: "ssn", StartColumn: 5, EndColumn: 16,
		Context: detector.ContextInfo{FullLine: "SSN 449-87-4100"},
	}
	other := m
	other.Text = "111-22-3333"
	other.Context = detector.ContextInfo{FullLine: "SSN 111-22-3333"}

	mapper := NewVulnerabilityMapper()
	if mapper.GenerateVulnerabilityID(m) != mapper.GenerateVulnerabilityID(other) {
		t.Error("the id changed when only the matched value changed — the value is part of the " +
			"id, and the id is published in CI artifacts")
	}
}
