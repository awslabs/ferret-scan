// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	jsonfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	yamlfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
	"gopkg.in/yaml.v3"
)

// The coverage disclosure must be present ON THE CLEAN REPORT, which is the only
// report where it matters.
//
// json and yaml used to return early on an empty result list and emit a bare `[]` /
// `results: []`. That bypassed shared.ConvertMatchesToJSONFormat, the only place
// `stats` — and with it files_not_examined — is attached. So the disclosure appeared
// exactly when there were findings and vanished exactly when the artifact read as a
// clean bill of health. Measured on a directory of two unreadable files:
//
//	text  ->  728 bytes, "NOT FULLY EXAMINED: 2 of 2 files"
//	json  ->    2 bytes, "[]"
//	yaml  ->   11 bytes, "results: []"
//
// stats.files_not_examined exists precisely so a machine consumer can tell an
// unexamined file from a clean one (#277), and #284 extended that to
// sarif/gitlab-sast/junit on the premise that json and yaml already disclosed. See
// #296, and #257 whose json half was closed without being fixed.
//
// NOTE ON GATING: the golden corpus cannot catch a regression here. Its harness builds
// FormatterOptions without Stats or NotExamined, so every golden passes whether the
// disclosure works or not. These tests are the gate.

// statsForTwoUnexaminedFiles is the shape the CLI produces for a directory of two
// files it could not read: nothing found, nothing examined.
func statsForTwoUnexaminedFiles() *formatters.ScanStats {
	return &formatters.ScanStats{
		TotalFiles:       2,
		FilesProcessed:   0,
		FilesNotExamined: 2,
		TotalFindings:    0,
	}
}

func TestZeroFindingScanStillDisclosesCoverage(t *testing.T) {
	opts := formatters.FormatterOptions{Stats: statsForTwoUnexaminedFiles()}

	t.Run("json", func(t *testing.T) {
		out, err := jsonfmt.NewFormatter().Format(nil, nil, opts)
		if err != nil {
			t.Fatal(err)
		}

		var got struct {
			Stats *struct {
				TotalFiles       int `json:"total_files"`
				FilesNotExamined int `json:"files_not_examined"`
			} `json:"stats"`
			Results []any `json:"results"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("a zero-finding scan produced JSON a typed consumer cannot read: %v\n"+
				"output was: %s\nThe top-level type used to flip between a bare array and "+
				"an object, so a consumer that worked on a dirty scan failed on a clean one.",
				err, out)
		}
		if got.Stats == nil {
			t.Fatalf("no stats block on a zero-finding scan; the artifact cannot distinguish "+
				"\"clean\" from \"never read\".\noutput: %s", out)
		}
		if got.Stats.FilesNotExamined != 2 {
			t.Errorf("files_not_examined = %d, want 2", got.Stats.FilesNotExamined)
		}
		if got.Stats.TotalFiles != 2 {
			t.Errorf("total_files = %d, want 2", got.Stats.TotalFiles)
		}
	})

	t.Run("yaml", func(t *testing.T) {
		out, err := yamlfmt.NewFormatter().Format(nil, nil, opts)
		if err != nil {
			t.Fatal(err)
		}

		var got struct {
			Stats *struct {
				TotalFiles       int `yaml:"total_files"`
				FilesNotExamined int `yaml:"files_not_examined"`
			} `yaml:"stats"`
			Results []any `yaml:"results"`
		}
		if err := yaml.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("a zero-finding scan produced YAML a typed consumer cannot read: %v\n"+
				"output was: %s", err, out)
		}
		if got.Stats == nil {
			t.Fatalf("no stats block on a zero-finding scan.\noutput: %s", out)
		}
		// Asserted under the SNAKE_CASE key on purpose. ScanStats carried only json
		// tags, so yaml.v3 fell back to the lower-cased Go field name and wrote
		// `filesnotexamined`. A consumer following the documented JSON schema found
		// nothing under `files_not_examined` — the field looked absent while a
		// differently-spelled one sat beside it reading zero.
		if got.Stats.FilesNotExamined != 2 {
			t.Errorf("files_not_examined = %d, want 2. The YAML key must be snake_case and "+
				"match the JSON spelling.\noutput: %s", got.Stats.FilesNotExamined, out)
		}
		if !strings.Contains(out, "files_not_examined") {
			t.Errorf("output does not contain the snake_case key at all:\n%s", out)
		}
		if strings.Contains(out, "filesnotexamined") {
			t.Errorf("output still contains the tag-less spelling `filesnotexamined`:\n%s", out)
		}
	})
}

// TestEmptyResultsIsAnArrayNotNull guards the trap that this change walked into.
//
// JSONResponse.Results carries no omitempty, so a nil slice reaches the encoder and
// becomes `null`. The SARIF formatter had exactly this shape and emitted
// `"results": null` on every clean scan — schema-INVALID, and GitHub rejected the whole
// report (#283). json/yaml never showed it only because the empty case short-circuited
// before reaching the shared conversion; now that it routes through, the nil would be
// visible.
func TestEmptyResultsIsAnArrayNotNull(t *testing.T) {
	opts := formatters.FormatterOptions{Stats: statsForTwoUnexaminedFiles()}

	out, err := jsonfmt.NewFormatter().Format(nil, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"results": null`) || strings.Contains(out, `"results":null`) {
		t.Errorf("emitted `results: null` on a zero-finding scan; that is what made GitHub "+
			"reject SARIF reports wholesale in #283.\noutput: %s", out)
	}

	// Decode into a typed struct and require a non-nil, empty slice.
	var got struct {
		Results []any `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Results == nil {
		t.Error("results decoded to nil; it must be an empty array so a consumer can " +
			"iterate it without a nil check")
	}
	if len(got.Results) != 0 {
		t.Errorf("results has %d entries on a zero-finding scan", len(got.Results))
	}
}

// TestTopLevelTypeIsStableAcrossFindingCounts.
//
// The shape used to depend on whether anything was found: a bare array for zero
// findings, an object otherwise. A typed consumer that worked all week broke the first
// time a scan came back clean, with "cannot unmarshal array into Go value of type
// struct".
func TestTopLevelTypeIsStableAcrossFindingCounts(t *testing.T) {
	opts := formatters.FormatterOptions{
		Stats:           statsForTwoUnexaminedFiles(),
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	}

	withFindings := []detector.Match{
		{Text: "452-11-9384", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: "a.txt"},
	}

	for _, tc := range []struct {
		name    string
		matches []detector.Match
	}{
		{"zero findings", nil},
		{"one finding", withFindings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := jsonfmt.NewFormatter().Format(tc.matches, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			trimmed := strings.TrimSpace(out)
			if !strings.HasPrefix(trimmed, "{") {
				t.Errorf("top-level JSON is not an object (starts with %q); the type must not "+
					"depend on the finding count.\noutput: %s", trimmed[:1], out)
			}
			// The decisive check: ONE struct decodes both.
			var got struct {
				Stats   *formatters.ScanStats `json:"stats"`
				Results []any                 `json:"results"`
			}
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("the same typed consumer cannot read both shapes: %v", err)
			}
			if got.Stats == nil {
				t.Error("stats missing")
			}
		})
	}
}

// TestPrecommitModeStaysQuiet — the fix must not turn every clean commit into noise.
//
// Pre-commit runs on a developer's every commit and signals out of band (exit code +
// stderr), so it does not depend on this artifact for the disclosure. Emitting a stats
// block there would be a regression in the opposite direction.
func TestPrecommitModeStaysQuiet(t *testing.T) {
	opts := formatters.FormatterOptions{
		PrecommitMode: true,
		Stats:         statsForTwoUnexaminedFiles(),
	}
	for name, f := range map[string]formatters.Formatter{
		"json": jsonfmt.NewFormatter(),
		"yaml": yamlfmt.NewFormatter(),
	} {
		out, err := f.Format(nil, nil, opts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out != "" {
			t.Errorf("%s in pre-commit mode emitted %d bytes for a zero-finding scan; it must "+
				"stay silent:\n%s", name, len(out), out)
		}
	}
}

// TestSuppressedOnlyScanStillReportsBoth — a scan whose only findings were suppressed
// must still carry stats AND the suppressed block. This path already worked; it is
// asserted so collapsing the branches did not lose it.
func TestSuppressedOnlyScanStillReportsBoth(t *testing.T) {
	opts := formatters.FormatterOptions{
		Stats:           statsForTwoUnexaminedFiles(),
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	}
	suppressed := []detector.SuppressedMatch{
		{
			Match:        detector.Match{Text: "452-11-9384", Type: "SSN", Confidence: 100},
			SuppressedBy: "test-rule",
			RuleReason:   "fixture",
		},
	}

	out, err := jsonfmt.NewFormatter().Format(nil, suppressed, opts)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Stats      *formatters.ScanStats `json:"stats"`
		Results    []any                 `json:"results"`
		Suppressed []any                 `json:"suppressed"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("suppressed-only output is not decodable: %v\n%s", err, out)
	}
	if got.Stats == nil {
		t.Error("stats missing on a suppressed-only scan")
	}
	if len(got.Suppressed) != 1 {
		t.Errorf("suppressed block has %d entries, want 1", len(got.Suppressed))
	}
}

// TestConfidenceFilteredToNothingStillDiscloses is the second way in, independent of
// unreadable files.
//
// --confidence medium over a directory whose findings are all HIGH or LOW used to emit
// a bare `[]`. Findings genuinely existed and the artifact said nothing at all — not
// even that a filter had been applied.
func TestConfidenceFilteredToNothingStillDiscloses(t *testing.T) {
	opts := formatters.FormatterOptions{
		Stats:           &formatters.ScanStats{TotalFiles: 1, FilesProcessed: 1, TotalFindings: 1, High: 1},
		ConfidenceLevel: map[string]bool{"medium": true}, // asks for MEDIUM only
	}
	highOnly := []detector.Match{
		{Text: "452-11-9384", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: "a.txt"},
	}

	out, err := jsonfmt.NewFormatter().Format(highOnly, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Stats   *formatters.ScanStats `json:"stats"`
		Results []any                 `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("filtered-to-empty output is not decodable: %v\n%s", err, out)
	}
	if got.Stats == nil {
		t.Fatalf("no stats when every finding was filtered out; the report claims nothing "+
			"at all.\noutput: %s", out)
	}
	if got.Stats.TotalFindings != 1 {
		t.Errorf("stats.total_findings = %d, want 1 — the scan DID find something, the "+
			"filter merely hid it", got.Stats.TotalFindings)
	}
	if len(got.Results) != 0 {
		t.Errorf("results has %d entries; the filter asked for MEDIUM only", len(got.Results))
	}
}
