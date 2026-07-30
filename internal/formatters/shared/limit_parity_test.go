// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	csvfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	gitlabfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	jsonfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	junitfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	sariffmt "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	textfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/text"
	yamlfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
)

// allLevels enables every confidence band, the posture `--confidence all` gives.
func allLevels() map[string]bool {
	return map[string]bool{"high": true, "medium": true, "low": true}
}

// countFindings extracts the number of findings a format actually rendered.
// Each format needs its own counter because they nest findings differently:
// JUnit packs every finding into a single <failure> body, so counting
// <testcase> elements would report the file count instead.
type formatUnderTest struct {
	name  string
	newf  func() formatters.Formatter
	count func(t *testing.T, out string) int
}

func formatsUnderTest() []formatUnderTest {
	return []formatUnderTest{
		{
			name: "text",
			newf: func() formatters.Formatter { return textfmt.NewFormatter() },
			count: func(t *testing.T, out string) int {
				n := 0
				for _, line := range strings.Split(out, "\n") {
					if strings.HasPrefix(line, "[") && strings.Contains(line, "line ") {
						n++
					}
				}
				return n
			},
		},
		{
			name:  "json",
			newf:  func() formatters.Formatter { return jsonfmt.NewFormatter() },
			count: func(t *testing.T, out string) int { return countJSONResults(t, out) },
		},
		{
			name: "yaml",
			newf: func() formatters.Formatter { return yamlfmt.NewFormatter() },
			count: func(t *testing.T, out string) int {
				return strings.Count(out, "line_number:")
			},
		},
		{
			name: "csv",
			newf: func() formatters.Formatter { return csvfmt.NewFormatter() },
			count: func(t *testing.T, out string) int {
				lines := strings.Split(strings.TrimSpace(out), "\n")
				if len(lines) <= 1 {
					return 0
				}
				return len(lines) - 1 // drop the header row
			},
		},
		{
			name: "junit",
			newf: func() formatters.Formatter { return junitfmt.NewFormatter() },
			count: func(t *testing.T, out string) int {
				// Every finding contributes one "Line N:" detail line inside the
				// single <failure> body.
				return strings.Count(out, "Line ")
			},
		},
		{
			name: "sarif",
			newf: func() formatters.Formatter { return sariffmt.NewFormatter() },
			count: func(t *testing.T, out string) int {
				var doc struct {
					Runs []struct {
						Results []json.RawMessage `json:"results"`
					} `json:"runs"`
				}
				if err := json.Unmarshal([]byte(out), &doc); err != nil {
					t.Fatalf("sarif output is not valid JSON: %v", err)
				}
				n := 0
				for _, r := range doc.Runs {
					n += len(r.Results)
				}
				return n
			},
		},
		{
			name: "gitlab-sast",
			newf: func() formatters.Formatter { return gitlabfmt.NewFormatter() },
			count: func(t *testing.T, out string) int {
				var doc struct {
					Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
				}
				if err := json.Unmarshal([]byte(out), &doc); err != nil {
					t.Fatalf("gitlab-sast output is not valid JSON: %v", err)
				}
				return len(doc.Vulnerabilities)
			},
		},
	}
}

// countJSONResults tolerates the two shapes the JSON formatter emits: a bare
// `[]` for a zero-finding scan and an object with a results array otherwise.
func countJSONResults(t *testing.T, out string) int {
	t.Helper()
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || strings.HasPrefix(trimmed, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			t.Fatalf("json output is neither object nor array: %v", err)
		}
		return len(arr)
	}
	var doc struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		t.Fatalf("json output is not valid JSON: %v", err)
	}
	return len(doc.Results)
}

// lowMatches builds n distinct LOW-confidence findings.
func lowMatches(n int) []detector.Match {
	out := make([]detector.Match, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, detector.Match{
			Text:       fmt.Sprintf("user%02d@example.com", i),
			LineNumber: i + 1,
			Type:       "BUSINESS",
			Confidence: 48,
			Filename:   "many.txt",
			Validator:  "email",
		})
	}
	return out
}

// TestLimit_EveryFormatHonorsIt is the parity contract behind --limit: one scan
// rendered seven ways must report the same number of findings. CSV, JUnit,
// SARIF and GitLab SAST ignored the option entirely, so a CI job asking for 3
// findings received all 30 in exactly the formats CI consumes — the unbounded
// report size ba4f31d set out to bound.
func TestLimit_EveryFormatHonorsIt(t *testing.T) {
	const total, limit = 30, 3
	matches := lowMatches(total)

	for _, f := range formatsUnderTest() {
		t.Run(f.name, func(t *testing.T) {
			out, err := f.newf().Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: allLevels(),
				NoColor:         true,
				ShowMatch:       true,
				Limit:           limit,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got := f.count(t, out); got != limit {
				t.Errorf("rendered %d findings with Limit=%d, want %d", got, limit, limit)
			}
		})
	}
}

// TestLimit_ZeroMeansUnlimited pins the documented escape hatch, and doubles as
// the guard that the truncation is opt-in: at Limit 0 every format must still
// render everything, which is the posture the golden corpus is generated in.
func TestLimit_ZeroMeansUnlimited(t *testing.T) {
	const total = 30
	matches := lowMatches(total)

	for _, f := range formatsUnderTest() {
		t.Run(f.name, func(t *testing.T) {
			out, err := f.newf().Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: allLevels(),
				NoColor:         true,
				ShowMatch:       true,
				Limit:           0,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got := f.count(t, out); got != total {
				t.Errorf("rendered %d findings with Limit=0, want all %d", got, total)
			}
		})
	}
}

// TestLimit_KeepsHighestConfidence asserts the truncation happens after the
// priority sort. Truncating the caller's arrival order instead would drop the
// HIGH-confidence finding and keep noise — the worst possible subset for a tool
// whose output gates a commit.
func TestLimit_KeepsHighestConfidence(t *testing.T) {
	matches := append(lowMatches(10), detector.Match{
		Text:       "449-87-4100",
		LineNumber: 99,
		Type:       "SSN",
		Confidence: 100,
		Filename:   "many.txt",
		Validator:  "ssn",
	})

	for _, f := range formatsUnderTest() {
		t.Run(f.name, func(t *testing.T) {
			out, err := f.newf().Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: allLevels(),
				NoColor:         true,
				ShowMatch:       true,
				Limit:           1,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if !strings.Contains(out, "SSN") {
				t.Errorf("Limit=1 dropped the only HIGH finding; output kept LOW noise instead:\n%s",
					truncateForLog(out))
			}
		})
	}
}

// TestConfidenceFilter_EveryFormatHonorsIt covers the second half of the same
// parity contract. GitLab SAST was the one formatter that never applied the
// confidence filter, so `--confidence high` shipped every LOW-confidence
// finding straight into a GitLab security dashboard while every other format
// correctly rendered none.
func TestConfidenceFilter_EveryFormatHonorsIt(t *testing.T) {
	matches := lowMatches(30) // all 48% == LOW
	highOnly := map[string]bool{"high": true}

	for _, f := range formatsUnderTest() {
		t.Run(f.name, func(t *testing.T) {
			out, err := f.newf().Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: highOnly,
				NoColor:         true,
				ShowMatch:       true,
				Limit:           0,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got := f.count(t, out); got != 0 {
				t.Errorf("rendered %d LOW findings under --confidence high, want 0", got)
			}
		})
	}
}

// TestConfidenceFilter_HighSurvives is the non-vacuity partner of the test
// above: a filter that rejected everything would pass it for the wrong reason.
func TestConfidenceFilter_HighSurvives(t *testing.T) {
	matches := append(lowMatches(5), detector.Match{
		Text:       "449-87-4100",
		LineNumber: 99,
		Type:       "SSN",
		Confidence: 100,
		Filename:   "many.txt",
		Validator:  "ssn",
	})
	highOnly := map[string]bool{"high": true}

	for _, f := range formatsUnderTest() {
		t.Run(f.name, func(t *testing.T) {
			out, err := f.newf().Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: highOnly,
				NoColor:         true,
				ShowMatch:       true,
				Limit:           0,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got := f.count(t, out); got != 1 {
				t.Errorf("rendered %d findings under --confidence high, want exactly the 1 HIGH", got)
			}
		})
	}
}

func truncateForLog(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
