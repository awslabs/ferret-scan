// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// --generate-suppressions on --stdin (#887): what the generating run reports, and where.
//
// Measured on main @ 2fb4719: `--stdin --enable-redaction --format json --generate-suppressions` wrote
// "Updated suppression rules: …" ahead of the findings document on stderr, so `2> findings.json` did not
// parse; the same flags through --file write a document that does.

// generationSample has two findings: an email on an invented domain and a patterned Luhn card, assembled
// from pieces so this source holds no card number whole.
var generationSample = "Contact: jane.roe@contoso-example.net\ncard number: 4539" + "000000123457\n"

const generationLinePrefix = "Updated suppression rules:"

// TestStdinGatewayGenerationKeepsTheFindingsDocument: where stderr IS the findings document, the
// generation report does not go there, and the rule file is still written.
func TestStdinGatewayGenerationKeepsTheFindingsDocument(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)

	t.Run("findings", func(t *testing.T) {
		rules := filepath.Join(work, "gateway.yaml")
		r := runCLI(t, bin, work, env, generationSample, "--stdin", "--stdin-name", "sample.txt", "--format", "json",
			"--config", os.DevNull, "--enable-redaction", "--generate-suppressions", "--suppression-file", rules)
		if r.rc != 0 {
			t.Fatalf("rc %d\n%s", r.rc, r.stderr)
		}
		var doc struct {
			Results []json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal([]byte(r.stderr), &doc); err != nil {
			t.Fatalf("stderr is not the JSON findings document (%v); `2> findings.json` breaks:\n%s", err, r.stderr)
		}
		if len(doc.Results) != 2 {
			t.Errorf("the findings document has %d results, want 2", len(doc.Results))
		}
		if n := strings.Count(readFileForTest(t, rules), "hash:"); n != 2 {
			t.Errorf("the rule file holds %d rules, want 2: generation must still write it", n)
		}
		if strings.Contains(r.stdout, "jane.roe") || strings.Contains(r.stdout, "4539"+"000000123457") {
			t.Errorf("the redacted stream on stdout still holds a reported value:\n%s", r.stdout)
		}
	})

	t.Run("no finding", func(t *testing.T) {
		r := runCLI(t, bin, work, env, "nothing to report here\n", "--stdin", "--format", "json", "--config", os.DevNull,
			"--enable-redaction", "--generate-suppressions", "--suppression-file", filepath.Join(work, "empty.yaml"))
		if r.rc != 0 || r.stderr != "" {
			t.Errorf("rc %d, stderr %q; with nothing found the gateway writes nothing to stderr", r.rc, r.stderr)
		}
		if r.stdout != "nothing to report here\n" {
			t.Errorf("stdout %q, want the input unchanged", r.stdout)
		}
	})

	// The gate is the findings document, not --stdin: where stderr is a human channel the lines stay.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"--stdin", nil},
		{"--stdin --enable-redaction --output", []string{"--enable-redaction", "--output", "report.json"}},
	} {
		t.Run("control: "+tc.name, func(t *testing.T) {
			args := append([]string{"--stdin", "--format", "json", "--config", os.DevNull, "--generate-suppressions",
				"--suppression-file", filepath.Join(work, strings.ReplaceAll(tc.name, " ", "_")+".yaml")}, tc.args...)
			r := runCLI(t, bin, work, env, generationSample, args...)
			if !strings.Contains(r.stderr, generationLinePrefix) {
				t.Errorf("stderr is a human channel here, and the generation report is missing:\n%s", r.stderr)
			}
		})
	}
}

// timestampLine matches the rule-file lines that hold a time, which differ between any two runs.
var timestampLine = regexp.MustCompile(`(?m)^\s*(created_at|last_seen_at|expires_at):.*$`)

// TestStdinGeneratingRunReportsWhatFileDoes pins the generating run's equivalence (#885's "the
// generating run matches file mode"): --stdin generates BEFORE it matches and --file after, and the
// manager defers what generation re-anchors, so both report the same findings, stats.suppressed, exit
// code and generation counts, and write the same rules. Here the rules are enabled and a line was
// inserted above every finding, so generation re-anchors both of them.
func TestStdinGeneratingRunReportsWhatFileDoes(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "sample.txt"), generationSample)
	gen := filepath.Join(work, "gen.yaml")
	if r := runCLI(t, bin, work, env, "", "--file", "sample.txt", "--config", os.DevNull, "--generate-suppressions",
		"--suppression-file", gen); r.rc != 0 {
		t.Fatalf("generating rules: rc %d\n%s", r.rc, r.stderr)
	}
	enabled := strings.ReplaceAll(readFileForTest(t, gen), "enabled: false", "enabled: true")
	moved := "Reviewed by the team\n" + generationSample
	writeFixture(t, filepath.Join(work, "sample.txt"), moved)

	type outcome struct {
		rc         int
		results    int
		suppressed float64
		generation string
		rules      string
	}
	run := func(t *testing.T, stdinMode bool) outcome {
		t.Helper()
		rules := filepath.Join(t.TempDir(), "rules.yaml")
		writeFixture(t, rules, enabled)
		args := []string{"--format", "json", "--config", os.DevNull, "--generate-suppressions", "--suppression-file", rules}
		input := ""
		if stdinMode {
			args, input = append(args, "--stdin", "--stdin-name", "sample.txt"), moved
		} else {
			args = append(args, "--file", "sample.txt")
		}
		r := runCLI(t, bin, work, env, input, args...)
		var doc struct {
			Results []json.RawMessage `json:"results"`
			Stats   struct {
				Suppressed float64 `json:"suppressed"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatalf("stdin=%v: the report does not parse: %v\n%s", stdinMode, err, r.stdout)
		}
		var line string
		for _, l := range strings.Split(r.stderr, "\n") {
			if strings.HasPrefix(l, generationLinePrefix) {
				line = l
			}
		}
		return outcome{r.rc, len(doc.Results), doc.Stats.Suppressed, line,
			timestampLine.ReplaceAllString(readFileForTest(t, rules), "")}
	}
	file, stdin := run(t, false), run(t, true)
	if !strings.Contains(file.generation, "re-anchored 2") {
		t.Fatalf("--file's generation line %q does not re-anchor the 2 rules, so this comparison is vacuous", file.generation)
	}
	if file.rc != stdin.rc || file.results != stdin.results || file.suppressed != stdin.suppressed || file.generation != stdin.generation {
		t.Errorf("the generating run differs: --file %+v, --stdin %+v", file, stdin)
	}
	if file.results != 2 || file.suppressed != 0 {
		t.Errorf("the generating run reports %d results and %v suppressed, want 2 and 0: a rule generation "+
			"re-anchors takes effect from the next load", file.results, file.suppressed)
	}
	if file.rules != stdin.rules {
		t.Errorf("the two rule files differ apart from timestamps:\n--file:\n%s\n--stdin:\n%s", file.rules, stdin.rules)
	}
}
