// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The unit tests beside this one exercise collectDisabledDetectionTypes and
// reportDisabledDetectionTypes directly. That is not enough, for the reason buildScanner's own
// comment gives about #603: the defect that shipped was in the CALLER's gate, not in the function,
// and a unit test on the function passes with the wiring wrong or absent. These run the binary.

// TestDisabledTypesDisclosedOnStderr covers the channel a human sees, including the two ways the
// provenance note was previously silenced.
func TestDisabledTypesDisclosedOnStderr(t *testing.T) {
	bin := buildScanner(t)
	dir := projectConfigFixture(t)

	for _, tc := range []struct {
		name string
		env  []string
		args []string
	}{
		{"plain", nil, nil},
		// --quiet suppresses progress output. This is a disclosure about what governed the scan,
		// so it must survive.
		{"--quiet", nil, []string{"--quiet"}},
		// The TM-13 case: IsPrecommitEnvironment() is true from environment variables alone, so a
		// gated disclosure takes no flag to suppress.
		{"PRE_COMMIT=1", []string{"PRE_COMMIT=1"}, nil},
		{"_PRE_COMMIT_RUNNING=1", []string{"_PRE_COMMIT_RUNNING=1"}, nil},
		{"GIT_HOOK_TYPE=pre-commit", []string{"GIT_HOOK_TYPE=pre-commit"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY"}, tc.args...)
			out := runScan(t, bin, dir, tc.env, args...)
			if !strings.Contains(out, "config disabled 2 INTELLECTUAL_PROPERTY detection sub-type(s)") {
				t.Errorf("no narrowed-detection disclosure under %s. A scan that cannot report "+
					"copyright must not look like one that found none.\n%s", tc.name, out)
			}
			for _, sub := range []string{"copyright", "internal_url"} {
				if !strings.Contains(out, sub) {
					t.Errorf("disclosure does not name %q under %s:\n%s", sub, tc.name, out)
				}
			}
		})
	}
}

// TestExplicitConfigAlsoDisclosesNarrowedDetection is the case the provenance note deliberately does
// NOT cover, and the reason this work exists.
//
// #603 keeps the provenance note silent for an explicit --config, on the ground that the operator
// chose the file. Measured on the parent commit, that run emitted ZERO bytes of stderr while
// reporting zero findings.
func TestExplicitConfigAlsoDisclosesNarrowedDetection(t *testing.T) {
	bin := buildScanner(t)
	dir := projectConfigFixture(t)

	// Move the config out of the working directory so ONLY --config can find it. Otherwise the
	// discovered-config path would satisfy the assertion and the explicit path would go untested.
	discovered := filepath.Join(dir, ".ferret-scan.yaml")
	explicit := filepath.Join(t.TempDir(), "explicit.yaml")
	body, err := os.ReadFile(discovered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(explicit, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(discovered); err != nil {
		t.Fatal(err)
	}

	out := runScan(t, bin, dir, nil, "--file", "notice.txt",
		"--checks", "INTELLECTUAL_PROPERTY", "--config", explicit)

	if strings.Contains(out, "using project config") {
		t.Errorf("the provenance note fired for an explicit --config; #603 decided it should not, "+
			"and this test would then be passing for the wrong reason:\n%s", out)
	}
	if !strings.Contains(out, "config disabled 2 INTELLECTUAL_PROPERTY detection sub-type(s)") {
		t.Errorf("an explicit --config narrowed detection with no disclosure at all — the exact "+
			"gap this closes:\n%s", out)
	}
}

// TestDisabledTypesReachTheJSONReport covers the machine-readable channel, which is the one a CI
// job actually consumes: it never sees stderr.
func TestDisabledTypesReachTheJSONReport(t *testing.T) {
	bin := buildScanner(t)
	dir := projectConfigFixture(t)
	out := filepath.Join(dir, "report.json")

	runScan(t, bin, dir, nil, "--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY",
		"--format", "json", "--output", out)

	var report struct {
		Results []any `json:"results"`
		Stats   struct {
			DisabledDetectionTypes map[string][]string `json:"disabled_detection_types"`
		} `json:"stats"`
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v\n%s", err, raw)
	}

	got := report.Stats.DisabledDetectionTypes["INTELLECTUAL_PROPERTY"]
	if len(got) != 2 || got[0] != "copyright" || got[1] != "internal_url" {
		t.Errorf("stats.disabled_detection_types = %v, want [copyright internal_url] — a consumer "+
			"reading %d results has no other way to know detection was narrowed",
			report.Stats.DisabledDetectionTypes, len(report.Results))
	}
}

// TestUnnarrowedScanIsByteIdenticalInJSON is the must-NOT-fire half. A disclosure that appears on
// every run is one people learn to ignore, and a new always-present key would also break any
// consumer diffing reports.
func TestUnnarrowedScanIsByteIdenticalInJSON(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notice.txt"),
		[]byte("Copyright (c) 2026 Acme Corporation. All rights reserved.\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "report.json")
	stderr := runScan(t, bin, dir, nil, "--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY",
		"--format", "json", "--output", out)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	if strings.Contains(string(raw), "disabled_detection_types") {
		t.Errorf("the key is present in a scan with nothing disabled; omitempty is not holding:\n%s", raw)
	}
	if strings.Contains(stderr, "config disabled") {
		t.Errorf("stderr carries a narrowed-detection note for an unnarrowed scan:\n%s", stderr)
	}

	// Non-vacuity: the fixture must actually produce a finding, or "no disclosure" would be true of
	// a scan that did nothing at all.
	var report struct {
		Results []any `json:"results"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	if len(report.Results) == 0 {
		t.Fatalf("the fixture produced no findings, so this test would pass against a broken scan")
	}
}

// TestIneffectiveDisabledTypeIsWarnedEndToEnd covers the opposite failure: the operator asked for
// detection to stop and it did not.
func TestIneffectiveDisabledTypeIsWarnedEndToEnd(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notice.txt"),
		[]byte("Copyright (c) 2026 Acme Corporation. All rights reserved.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "validators:\n  intellectual_property:\n    disabled_types:\n      - copyrite\n"
	if err := os.WriteFile(filepath.Join(dir, ".ferret-scan.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	reportPath := filepath.Join(dir, "report.json")
	out := runScan(t, bin, dir, nil, "--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY",
		"--format", "json", "--output", reportPath)

	if !strings.Contains(out, "copyrite") || !strings.Contains(out, "NO effect") {
		t.Errorf("a typo'd disabled_types entry was not reported as ineffective. Measured on the "+
			"parent commit: 1 finding, rc 0, nothing said.\n%s", out)
	}
	if strings.Contains(out, "config disabled") {
		t.Errorf("a typo was reported as a suppression; it is the opposite failure and wants the "+
			"opposite remedy:\n%s", out)
	}

	// And detection really is still running, so the warning is accurate.
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Results []any `json:"results"`
		Stats   struct {
			DisabledDetectionTypes map[string][]string `json:"disabled_detection_types"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	if len(report.Results) == 0 {
		t.Errorf("the typo suppressed findings after all, so the warning is wrong")
	}
	if len(report.Stats.DisabledDetectionTypes) != 0 {
		t.Errorf("stats claims %v was disabled by a name that matches nothing",
			report.Stats.DisabledDetectionTypes)
	}
}
