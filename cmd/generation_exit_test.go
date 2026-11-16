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

// A --generate-suppressions run that refused to write (#880). Measured on main @ 3aa380e with the issue's
// reproduction: the rule file is left byte-identical (#893), and the run printed "Warning: Failed to
// generate suppression rules: … could not be parsed …" and exited 0 on --file and --stdin, text and json,
// and on the --stdin gateway.

func TestGenerationExitCode(t *testing.T) {
	for _, tc := range []struct {
		base   int
		failed bool
		want   int
	}{
		{0, false, 0},
		{0, true, 1},
		{1, true, 1},
		{2, true, 2},
		{exitCodeIncompleteCoverage, true, exitCodeIncompleteCoverage},
		{exitCodeIncompleteCoverage, false, exitCodeIncompleteCoverage},
	} {
		if got := generationExitCode(tc.base, tc.failed); got != tc.want {
			t.Errorf("generationExitCode(%d, %v) = %d, want %d", tc.base, tc.failed, got, tc.want)
		}
	}
}

// TestARefusedRegenerateExitsNonZero: every input path exits 1 with an Error line, leaves the rule file
// byte-identical and still renders its report; a rule file that does not exist yet is still created at rc 0.
func TestARefusedRegenerateExitsNonZero(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	sample := filepath.Join(work, "sample.txt")
	if err := os.WriteFile(sample, []byte(generationSample), 0o600); err != nil {
		t.Fatal(err)
	}

	// The operator's reviewed file plus one bad edit, as in the issue.
	rules := filepath.Join(work, "rules.yaml")
	if r := runCLI(t, bin, work, env, "", "--file", sample, "--config", os.DevNull,
		"--generate-suppressions", "--suppression-file", rules); r.rc != 0 {
		t.Fatalf("control: generating a new rule file: rc %d\n%s", r.rc, r.stderr)
	}
	enabled := strings.ReplaceAll(readFileForTest(t, rules), "enabled: false", "enabled: true")
	broken := enabled + "    - id: SUP-00000003\n      hash: [unclosed\n"
	if err := os.WriteFile(rules, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
	}{
		{"--file text", "", []string{"--file", sample, "--format", "text"}},
		{"--file json", "", []string{"--file", sample, "--format", "json"}},
		{"--stdin text", generationSample, []string{"--stdin", "--format", "text"}},
		{"--stdin json", generationSample, []string{"--stdin", "--format", "json"}},
		{"--stdin gateway", generationSample, []string{"--stdin", "--enable-redaction", "--format", "json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{}, tc.args...), "--config", os.DevNull,
				"--generate-suppressions", "--suppression-file", rules)
			r := runCLI(t, bin, work, env, tc.stdin, args...)
			if r.rc != 1 {
				t.Errorf("rc %d, want 1: a regenerate that wrote nothing must not exit as a success", r.rc)
			}
			if !strings.Contains(r.stderr, "Error: Failed to generate suppression rules: ") ||
				!strings.Contains(r.stderr, "could not be parsed") {
				t.Errorf("stderr does not say the regenerate was refused:\n%s", r.stderr)
			}
			if got := readFileForTest(t, rules); got != broken {
				t.Errorf("the rule file changed; a file that did not parse is never rewritten")
			}
			// The report is still rendered: where the findings document goes, it holds both findings.
			switch tc.name {
			case "--file json", "--stdin json":
				var doc struct {
					Results []json.RawMessage `json:"results"`
				}
				if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil || len(doc.Results) != 2 {
					t.Errorf("stdout is not the 2-result findings document (%v):\n%s", err, r.stdout)
				}
			case "--stdin gateway":
				if strings.Contains(r.stdout, "jane.roe") || !strings.Contains(r.stdout, "Contact: ") {
					t.Errorf("stdout is not the redacted stream:\n%s", r.stdout)
				}
			default:
				if !strings.Contains(r.stdout, "creditcard") || !strings.Contains(r.stdout, "email") {
					t.Errorf("stdout has no text report:\n%s", r.stdout)
				}
			}
		})
	}

	t.Run("control: a missing rule file is still created", func(t *testing.T) {
		fresh := filepath.Join(work, "fresh.yaml")
		r := runCLI(t, bin, work, env, generationSample, "--stdin", "--config", os.DevNull,
			"--generate-suppressions", "--suppression-file", fresh)
		if r.rc != 0 || strings.Contains(r.stderr, "Error:") {
			t.Errorf("rc %d, want 0\n%s", r.rc, r.stderr)
		}
		if n := strings.Count(readFileForTest(t, fresh), "hash:"); n != 2 {
			t.Errorf("the new rule file holds %d rules, want 2", n)
		}
	})
}
