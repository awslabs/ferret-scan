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

// Suppression excludes a finding from REDACTION as well as from the report.
//
// # What was wrong
//
// Redaction happens inside the worker pool — deliberately, so the extracted content is not derived a
// second time — and suppression was applied AFTERWARDS, in cmd. So the redactor received every match
// and rewrote the spans of findings the user had explicitly suppressed. Measured on a file with two
// suppressed findings:
//
//	report:   results: []          suppressed: 2
//	artifact: Employee SSN: [SSN-REDACTED]
//
// The report said nothing was found while the output file had been rewritten in two places.
//
// # The two channels disagreed, and --stdin was already right
//
// cmd/stdin.go filters before redacting, so on identical input with identical rules the stdin path
// left the values intact and the file path rewrote them. That is what makes this a consistency fix
// rather than a fresh behaviour decision: the file path was brought to match the channel that already
// did the agreed thing.
//
// # The rule, and its cost
//
// Suppressing a finding excludes it from redaction; UNSUPPRESS IT to have the value rewritten. Under
// the sink rule that has a real cost — a suppressed value stays in the redacted copy in cleartext, and
// a rule that is wrong or has outlived its reason is then invisible in the report. So the count is
// disclosed on stderr, which TestARedactionRunDisclosesWhatSuppressionKept asserts.
func TestSuppressionKeepsAValueOutOfTheRedactedOutput(t *testing.T) {
	bin := buildScanner(t)
	const (
		ssn  = "219-09-9998"
		card = "4532-0151-1283-0366"
	)

	t.Run("both suppressed: both values survive", func(t *testing.T) {
		dir, file := fixtureWithBothValues(t, ssn, card)
		rules := generateEnabledSuppressions(t, bin, dir, file, "")

		report, artifact, stderr := redactWithSuppressions(t, bin, file, rules)
		if report.findings != 0 {
			t.Fatalf("%d finding(s) reported; the rules did not suppress, so this measures nothing",
				report.findings)
		}
		if report.suppressed != 2 {
			t.Fatalf("suppressed=%d, want 2 — the fixture or the rules are wrong", report.suppressed)
		}
		for _, v := range []string{ssn, card} {
			if !strings.Contains(artifact, v) {
				t.Errorf("a SUPPRESSED value was rewritten in the redacted output.\n"+
					"Suppressing a finding must exclude it from redaction as well as from the report — "+
					"unsuppressing it is how a user asks for the value to be rewritten.\nartifact:\n%s",
					artifact)
			}
		}
		if !strings.Contains(stderr, "suppressed finding") {
			t.Errorf("nothing on stderr said a suppression had kept a value in the output. A "+
				"suppressed value staying in cleartext must not be silent.\nstderr: %s", stderr)
		}
	})

	t.Run("nothing suppressed: the positive control", func(t *testing.T) {
		// Without this, a build that redacted NOTHING at all would pass the subtest above perfectly.
		_, file := fixtureWithBothValues(t, ssn, card)
		report, artifact, _ := redactWithSuppressions(t, bin, file, "")
		if report.findings == 0 {
			t.Fatalf("no findings without suppressions; the fixture is not detected at all")
		}
		for _, v := range []string{ssn, card} {
			if strings.Contains(artifact, v) {
				t.Errorf("%s survives redaction with NO suppression in force. Every assertion in the "+
					"sibling subtests would hold on a build that never redacts, so this control "+
					"failing means those results cannot be trusted.\nartifact:\n%s", v, artifact)
			}
		}
	})

	t.Run("mixed: the suppressed one survives, the other is rewritten", func(t *testing.T) {
		// The case a blanket implementation gets wrong in either direction.
		dir, file := fixtureWithBothValues(t, ssn, card)
		rules := generateEnabledSuppressions(t, bin, dir, file, "SSN")

		report, artifact, _ := redactWithSuppressions(t, bin, file, rules)
		if report.suppressed != 1 || report.findings != 1 {
			t.Fatalf("want exactly one suppressed and one reported, got suppressed=%d reported=%d; "+
				"the selective enable did not work and the subtest is not measuring the mixed case",
				report.suppressed, report.findings)
		}
		if !strings.Contains(artifact, ssn) {
			t.Errorf("the SUPPRESSED SSN was rewritten:\n%s", artifact)
		}
		if strings.Contains(artifact, card) {
			t.Errorf("the UNSUPPRESSED card was NOT rewritten. Suppressing one finding must not stop "+
				"the others being redacted — that would turn one suppression into a silent hole in "+
				"the whole file.\n%s", artifact)
		}
	})
}

// TestBothChannelsAgreeOnSuppressionAndRedaction is the consistency assertion.
//
// The file path and the --stdin path are separate implementations, and they disagreed: stdin filtered
// before redacting and the file path did not. Same input, same rules, different output — which is the
// kind of difference nobody finds by reading, because each path looks correct on its own.
func TestBothChannelsAgreeOnSuppressionAndRedaction(t *testing.T) {
	bin := buildScanner(t)
	const ssn = "219-09-9998"

	dir := t.TempDir()
	file := filepath.Join(dir, "roster.txt")
	body := "Employee SSN: " + ssn + "\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Each channel needs rules generated from ITSELF: the rule identity includes the source basename,
	// so file-generated rules do not match stdin findings. A cross-channel comparison that skips this
	// measures nothing — the rules simply fail to apply and both sides look "unsuppressed".
	fileRules := generateEnabledSuppressions(t, bin, dir, file, "")
	stdinRules := filepath.Join(dir, "stdin-rules.yaml")
	pipeStdin(t, bin, body, []string{
		"--config", os.DevNull, "--confidence", "all", "--limit", "0",
		"--generate-suppressions", "--suppression-file", stdinRules, "--format", "json",
	})
	enableAllRules(t, stdinRules, "")

	_, fileArtifact, _ := redactWithSuppressions(t, bin, file, fileRules)
	stdinOut := pipeStdin(t, bin, body, []string{
		"--config", os.DevNull, "--checks", "all", "--confidence", "all", "--limit", "0",
		"--enable-redaction", "--suppression-file", stdinRules,
	})

	fileKept := strings.Contains(fileArtifact, ssn)
	stdinKept := strings.Contains(stdinOut, ssn)
	if fileKept != stdinKept {
		t.Errorf("the two channels disagree on whether a suppressed value is redacted:\n"+
			"  --file  kept the value: %v\n  --stdin kept the value: %v\n\n"+
			"They must agree. A user who moves a command from one to the other gets a different "+
			"output file for the same input and the same rules.\n--file artifact:\n%s\n--stdin out:\n%s",
			fileKept, stdinKept, fileArtifact, stdinOut)
	}
	if !fileKept {
		t.Errorf("both channels rewrote a suppressed value; the agreed rule is that suppression " +
			"excludes a finding from redaction")
	}
}

// TestARedactionRunDisclosesWhatSuppressionKept pins the disclosure.
//
// A suppressed value left in the redacted copy is the user's own decision, but it is still a value in
// cleartext in a file they may forward. A rule that is wrong, or that has outlived its reason, is
// otherwise invisible: the report shows nothing and the output holds the value.
func TestARedactionRunDisclosesWhatSuppressionKept(t *testing.T) {
	bin := buildScanner(t)
	dir, file := fixtureWithBothValues(t, "219-09-9998", "4532-0151-1283-0366")
	rules := generateEnabledSuppressions(t, bin, dir, file, "")

	_, _, stderr := redactWithSuppressions(t, bin, file, rules)
	for _, want := range []string{"2", "suppressed finding", "redact"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the disclosure does not mention %q.\nIt has to carry the COUNT and say that "+
				"suppression excluded the value from redaction, or a reader cannot tell why their "+
				"redacted file still holds a value.\nstderr: %s", want, stderr)
		}
	}

	// And it must NOT appear when there is nothing to disclose, or it becomes noise that gets ignored.
	_, _, quiet := redactWithSuppressions(t, bin, file, "")
	if strings.Contains(quiet, "suppressed finding") {
		t.Errorf("the disclosure fired with no suppressions in force: %s", quiet)
	}
}

// ---- helpers ----

type suppressionReport struct {
	findings   int
	suppressed int
}

func fixtureWithBothValues(t *testing.T, ssn, card string) (dir, file string) {
	t.Helper()
	dir = t.TempDir()
	file = filepath.Join(dir, "roster.txt")
	body := "Employee SSN: " + ssn + "\nCard " + card + " on file\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

// generateEnabledSuppressions writes a suppression file for file's findings and enables the rules.
//
// onlyType, when non-empty, enables ONLY the rules whose block mentions it — which is how the mixed
// case is built. Rules ship `enabled: false` by design, so a test that forgets to flip them passes
// for free.
func generateEnabledSuppressions(t *testing.T, bin, dir, file, onlyType string) string {
	t.Helper()
	rules := filepath.Join(dir, "rules-"+onlyType+".yaml")
	// #nosec G204 -- bin is built by the test and every argument is a literal or a temp path
	out, err := exec.Command(bin, "--file", file, "--config", os.DevNull, "--confidence", "all",
		"--limit", "0", "--generate-suppressions", "--suppression-file", rules,
		"--format", "json").CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Fatalf("generating suppressions: %v\n%s", err, out)
	}
	enableAllRules(t, rules, onlyType)
	return rules
}

func enableAllRules(t *testing.T, path, onlyType string) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a path inside t.TempDir()
	if err != nil {
		t.Fatalf("reading the generated rules: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "enabled: false") {
		t.Fatalf("the generated file has no `enabled: false` to flip; rules ship disabled, so either "+
			"the generator changed or nothing was generated:\n%s", text)
	}
	var flipped string
	if onlyType == "" {
		flipped = strings.ReplaceAll(text, "enabled: false", "enabled: true")
	} else {
		blocks := strings.Split(text, "  - id:")
		for i, b := range blocks {
			if i > 0 && strings.Contains(b, onlyType) {
				blocks[i] = strings.ReplaceAll(b, "enabled: false", "enabled: true")
			}
		}
		flipped = strings.Join(blocks, "  - id:")
		if !strings.Contains(flipped, "enabled: true") {
			t.Fatalf("no rule mentioning %q was found to enable; the mixed case cannot be built", onlyType)
		}
	}
	if err := os.WriteFile(path, []byte(flipped), 0o600); err != nil {
		t.Fatalf("writing the enabled rules: %v", err)
	}
}

// redactWithSuppressions runs a redaction scan and returns the report, the artifact and stderr.
func redactWithSuppressions(t *testing.T, bin, file, rules string) (suppressionReport, string, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatal(err)
	}
	argv := []string{"--file", file, "--config", os.DevNull, "--checks", "all", "--confidence", "all",
		"--limit", "0", "--enable-redaction", "--redaction-strategy", "simple",
		"--redaction-output-dir", outDir, "--format", "json"}
	if rules != "" {
		argv = append(argv, "--suppression-file", rules)
	}
	cmd := exec.Command(bin, argv...) // #nosec G204 -- bin is built by the test
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	stdout, err := cmd.Output()
	if err != nil && len(stdout) == 0 {
		t.Fatalf("scan failed: %v\nstderr: %s", err, errBuf.String())
	}

	var doc struct {
		Results []map[string]any `json:"results"`
		Stats   struct {
			Suppressed int `json:"suppressed"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("the report is not valid JSON (%v): %.200s", err, stdout)
	}

	// Read the single redacted artifact, if one was written.
	var artifact string
	err = filepath.WalkDir(outDir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- under the test's own output dir
		if rerr != nil {
			return rerr
		}
		artifact += string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("reading the redacted output: %v", err)
	}
	return suppressionReport{findings: len(doc.Results), suppressed: doc.Stats.Suppressed},
		artifact, errBuf.String()
}

// pipeStdin pipes input into the built binary and returns stdout.
//
// Named apart from the package's existing runStdin, which fixes its own payload and returns stderr;
// this one needs an arbitrary payload and the redacted stdout.
func pipeStdin(t *testing.T, bin, input string, argv []string) string {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"--stdin"}, argv...)...) // #nosec G204 -- bin is built by the test
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("stdin run failed: %v", err)
	}
	return string(out)
}
