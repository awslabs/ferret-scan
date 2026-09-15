// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A report must never contradict its own stats block, and an unusable --confidence value must be
// refused rather than turned into a filter that matches nothing.
//
// # What it looked like
//
// An unrecognised token was dropped silently, so the filter had every level false. Measured on a file
// holding three findings, each of these produced an EMPTY results array while the SAME document's
// stats block reported total_findings 3:
//
//	--confidence nonsense    results 0, stats total 3
//	--confidence hi          results 0, stats total 3
//	--confidence ALL         results 0, stats total 3   <- the DOCUMENTED value, wrong case
//	--confidence " all "     results 0, stats total 3   <- the documented value, with spaces
//	--confidence all,high    results 1, stats total 3   <- "all" ignored inside a list
//
// A document that contradicts itself is worse than either answer alone: which half a consumer believes
// decides whether the scan looked clean. A CI job reading `results` saw a clean tree while one reading
// `stats` saw three findings, and the text formatter printed "No matches found at the specified
// confidence levels", which reads as a statement about the file. `--confidence hi` is an ordinary typo
// (#683).
//
// # Why this is a CLI test and not only a unit test
//
// The parser is unit-tested in internal/core. What this adds is the CONSEQUENCE: that the flag is
// wired to the failure, that the exit code is non-zero, and that the JSON document a consumer parses is
// self-consistent. A unit test on the parser passes with the flag unwired, which is the shape of defect
// this repository has shipped before.
func TestAnUnusableConfidenceValueIsRefused(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	fixture := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(fixture, []byte(
		"SSN: 449-87-4100\nAWS: AKIAIOSFODNN7EXAMPLE\nemail: jane.roe@corp.example\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	// Non-vacuity: the fixture must produce findings, or "results is empty" proves nothing.
	base := runConfidence(t, bin, fixture, "")
	if base.total == 0 {
		t.Fatalf("the fixture produced no findings at all; every row below would be vacuous")
	}

	t.Run("refused", func(t *testing.T) {
		for _, value := range []string{"nonsense", "hi", "high,med", "medum", "none"} {
			r := runConfidence(t, bin, fixture, value)
			if r.code == 0 {
				t.Errorf("--confidence %q exited 0. An unrecognised token used to be dropped, "+
					"producing a filter that matches nothing and a report that contradicts its own "+
					"stats block.", value)
			}
			if !strings.Contains(r.combined, "invalid confidence level") {
				t.Errorf("--confidence %q: the error should name the problem and the valid values, "+
					"got: %s", value, truncateOutput(r.combined))
			}
		}
	})

	t.Run("every spelling of all", func(t *testing.T) {
		for _, value := range []string{"all", "ALL", "All", " all ", "all,high", "high,all"} {
			r := runConfidence(t, bin, fixture, value)
			if r.code != 0 {
				t.Errorf("--confidence %q exited %d; this is the documented value and must work in "+
					"every spelling. Three of these were silently producing an EMPTY report.",
					value, r.code)
				continue
			}
			if r.results != base.total {
				t.Errorf("--confidence %q reported %d results, want all %d. A spelling of the "+
					"documented default that hides findings is the defect.", value, r.results, base.total)
			}
		}
	})

	// THE INVARIANT: whatever the filter, the document must not claim findings it does not show
	// without a level being excluded to explain it. Empty results with a filter that selects every
	// level is self-contradiction.
	t.Run("the report never contradicts its stats", func(t *testing.T) {
		for _, value := range []string{"", "all", "ALL", " all ", "all,high", "high,medium,low"} {
			r := runConfidence(t, bin, fixture, value)
			if r.code != 0 {
				t.Fatalf("--confidence %q exited %d unexpectedly", value, r.code)
			}
			if r.total > 0 && r.results == 0 {
				t.Errorf("--confidence %q: stats report %d findings and results is EMPTY, with every "+
					"confidence level selected. The document contradicts itself, so which half a "+
					"consumer believes decides whether the scan looked clean.", value, r.total)
			}
		}
	})
}

type confidenceRun struct {
	code     int
	results  int
	total    int
	combined string
}

func runConfidence(t *testing.T, bin, fixture, value string) confidenceRun {
	t.Helper()
	args := []string{"--file", fixture, "--config", os.DevNull, "--checks", "all",
		"--format", "json", "--limit", "0"}
	if value != "" {
		args = append(args, "--confidence", value)
	}
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	run := confidenceRun{code: code, combined: string(out)}
	var doc struct {
		Stats struct {
			TotalFindings int `json:"total_findings"`
		} `json:"stats"`
		Results []struct {
			Type string `json:"type"`
		} `json:"results"`
	}
	if jsonErr := json.Unmarshal(out, &doc); jsonErr == nil {
		run.results = len(doc.Results)
		run.total = doc.Stats.TotalFindings
	}
	return run
}

func truncateOutput(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
