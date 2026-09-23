// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// This file pins the CLI contracts ferret-scan makes ON ITS OWN TERMS — the behaviours any
// machine consumer of this binary (a CI job, a wrapper script, a pipeline) is entitled to rely
// on, stated and tested here so a change to one is a deliberate decision instead of an accident:
//
//	exit codes    findings do NOT make the ordinary scan exit non-zero; only --pre-commit-mode
//	              turns findings into an exit code, and it is opt-in
//	SARIF shape   version 2.1.0; results is an ARRAY even when empty, never null; every result
//	              carries a ruleId (consumers key suppressions on it)
//	precedence    an explicit --format beats a config file's `format:`
//	disclosure    --show-match is the ONLY flag that puts matched values into a report
//	environment   FERRET_PRECOMMIT=0 declines pre-commit auto-detection for every signal that
//	              can trigger it (#353)
//	--exclude     a malformed pattern fails loudly before scanning; a pattern that matched
//	              nothing is reported (#729)
//
// Deliberately NOT here: compatibility checks against any specific downstream tool. Whether a
// particular consumer's integration still works is that consumer's test suite's job, not this
// repository's — this file owns only the promises ferret-scan itself makes.

func buildForCLIContract(t *testing.T) string {
	t.Helper()
	name := "ferret-scan-cli-contract"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// machineInvocation is the flag set a typical machine consumer sends: a fixed format, a named
// output file, no colour, quiet progress, no truncation.
func machineInvocation(in, sarifPath string) []string {
	return []string{
		"--file", in,
		"--config", os.DevNull,
		"--format", "sarif",
		"--output", sarifPath,
		"--no-color", "--quiet",
		"--limit", "0",
	}
}

// runContractScan runs the machine invocation under an explicit minimal environment and returns
// the exit code and sorted ruleIds. The environment is built from scratch rather than inherited:
// a developer machine with pre-commit installed exports PRE_COMMIT_HOME, which would silently
// flip the binary into pre-commit mode and make the control runs meaningless.
func runContractScan(t *testing.T, bin, in, sarifPath string, env []string) (int, []string) {
	t.Helper()
	cmd := exec.Command(bin, machineInvocation(in, sarifPath)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}, env...)
	_ = os.Remove(sarifPath)
	out, _ := cmd.CombinedOutput()
	rc := cmd.ProcessState.ExitCode()

	b, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("no SARIF written under env %v (rc=%d): %v\noutput:\n%s", env, rc, err, out)
	}
	var d sarifDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("unparseable SARIF under env %v (rc=%d): %v", env, rc, err)
	}
	if len(d.Runs) == 0 || d.Runs[0].Results == nil {
		t.Fatalf("SARIF under env %v has no runs[0].results array (rc=%d)", env, rc)
	}
	ids := make([]string, 0, len(*d.Runs[0].Results))
	for _, r := range *d.Runs[0].Results {
		ids = append(ids, r.RuleID)
	}
	sort.Strings(ids)
	return rc, ids
}

// sarifDoc is the narrow view of SARIF a machine consumer parses. Deliberately not the full
// schema: pinning fields nobody reads would make this fail on harmless additions.
type sarifDoc struct {
	Version string `json:"version"`
	Runs    []struct {
		Results *[]struct { // pointer, so [] and null are distinguishable
			RuleID string `json:"ruleId"`
		} `json:"results"`
	} `json:"runs"`
}

func readSARIF(t *testing.T, path string) sarifDoc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("SARIF output file missing: %v", err)
	}
	var d sarifDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\nfirst 400 bytes: %.400s", err, b)
	}
	if len(d.Runs) == 0 {
		t.Fatalf("SARIF has no runs[]; first 400 bytes: %.400s", b)
	}
	if d.Runs[0].Results == nil {
		t.Fatalf("runs[0].results is absent or JSON null; it must be an ARRAY even when empty — "+
			"a consumer iterating it gets a TypeError on null, and internal/formatters/sarif/"+
			"results_never_null_test.go pins the formatter half of this. first 400 bytes: %.400s", b)
	}
	return d
}

// TestFindingsDoNotFailTheOrdinaryScan pins the exit-code contract from both directions.
//
// "Found something" is the NORMAL outcome for a scanner, so the ordinary invocation exits 0 with
// findings — a CI consumer reports the findings, not a failed tool. The one mode that turns
// findings into an exit code is --pre-commit-mode, and the pairing below keeps it opt-in: if the
// two invocations ever agree, either pre-commit stopped escalating or the default started, and
// the second would fail every machine consumer whose repository contains anything at all.
func TestFindingsDoNotFailTheOrdinaryScan(t *testing.T) {
	bin := buildForCLIContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "dirty.txt")
	if err := os.WriteFile(in, []byte("aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(extra ...string) (int, int) {
		sarifPath := filepath.Join(dir, fmt.Sprintf("o%d.sarif", len(extra)))
		args := append(machineInvocation(in, sarifPath), extra...)
		c := exec.Command(bin, args...)
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		_, _ = c.CombinedOutput()
		d := readSARIF(t, sarifPath)
		return c.ProcessState.ExitCode(), len(*d.Runs[0].Results)
	}

	rcDefault, n := run()
	// Non-vacuity: exit 0 on a scan that found NOTHING would prove nothing about this contract.
	if n == 0 {
		t.Fatal("the fixture produced 0 findings; 'exit 0 WITH findings' is untested")
	}
	if rcDefault != 0 {
		t.Errorf("the ordinary invocation on a file with %d findings exited %d, want 0 — findings "+
			"are the expected outcome, not an error", n, rcDefault)
	}
	rcPrecommit, _ := run("--pre-commit-mode")
	if rcPrecommit == rcDefault {
		t.Errorf("--pre-commit-mode and the default both exit %d, so this test cannot tell them "+
			"apart — either pre-commit no longer escalates findings, or the default now does",
			rcDefault)
	}
}

// TestSARIFShapeIsStable pins the three SARIF properties consumers parse: the version string,
// results as an array (never null) even when empty, and a non-empty ruleId on every result —
// suppression systems key on (path, ruleId), so a finding without one can never be suppressed.
func TestSARIFShapeIsStable(t *testing.T) {
	bin := buildForCLIContract(t)
	for _, tc := range []struct {
		name, content, want string
	}{
		{"with findings", "aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n", "some"},
		// The empty case is the one that exercises [] vs null, unreachable from any fixture
		// that produces findings.
		{"clean file", "the quick brown fox jumps over the lazy dog\n", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "in.txt")
			if err := os.WriteFile(in, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			sarifPath := filepath.Join(dir, "out.sarif")
			c := exec.Command(bin, machineInvocation(in, sarifPath)...)
			c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
			out, _ := c.CombinedOutput()

			d := readSARIF(t, sarifPath)
			if d.Version != "2.1.0" {
				t.Errorf("sarif version is %q, want \"2.1.0\"", d.Version)
			}
			results := *d.Runs[0].Results
			switch tc.want {
			case "some":
				if len(results) == 0 {
					t.Fatalf("expected findings, got none — the ruleId check is vacuous.\n%s", out)
				}
				for i, r := range results {
					if strings.TrimSpace(r.RuleID) == "" {
						t.Errorf("results[%d] has an empty ruleId", i)
					}
				}
			case "none":
				if len(results) != 0 {
					t.Fatalf("the 'clean' fixture produced %d findings; this subtest is not "+
						"exercising the empty-results path it exists for", len(results))
				}
			}
		})
	}
}

// TestFormatFlagBeatsConfigFormat: an explicit --format wins over a config file's `format:`. A
// consumer that asks for SARIF and gets YAML loses every finding at the parse step.
func TestFormatFlagBeatsConfigFormat(t *testing.T) {
	bin := buildForCLIContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("aws key AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A config that actively contends for the format, so this cannot pass by there being
	// nothing to override.
	cfgPath := filepath.Join(dir, "contending.yaml")
	if err := os.WriteFile(cfgPath, []byte("format: text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sarifPath := filepath.Join(dir, "out.sarif")
	c := exec.Command(bin, "--file", in, "--config", cfgPath,
		"--format", "sarif", "--output", sarifPath, "--no-color", "--quiet", "--limit", "0")
	out, _ := c.CombinedOutput()
	d := readSARIF(t, sarifPath)
	if d.Version != "2.1.0" {
		t.Errorf("with `format: text` in config and --format sarif on the CLI, output is not "+
			"SARIF (version=%q).\n%s", d.Version, out)
	}
	if len(*d.Runs[0].Results) == 0 {
		t.Errorf("SARIF parsed but carries no findings — the override may have produced an "+
			"empty document.\n%s", out)
	}
}

// TestOnlyShowMatchRevealsMatchedValues pins the disclosure boundary. Machine reports are
// routinely archived as CI artifacts; which flags put RAW MATCHED VALUES into one is a security
// property, and the answer must stay: --show-match, and nothing else. --explain is the plausible
// accident — it adds per-finding rationale text — so it is probed explicitly.
func TestOnlyShowMatchRevealsMatchedValues(t *testing.T) {
	bin := buildForCLIContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	values := []string{"456-78-9012", "4532015112830366", "AKIAIOSFODNN7EXAMPLE"}
	content := "ssn " + values[0] + "\nvisa " + values[1] + "\naws " + values[2] + "\n"
	if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	leaked := func(extra ...string) (int, []string) {
		sarifPath := filepath.Join(t.TempDir(), "out.sarif")
		args := append(machineInvocation(in, sarifPath), extra...)
		c := exec.Command(bin, args...)
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		out, _ := c.CombinedOutput()
		b, err := os.ReadFile(sarifPath)
		if err != nil {
			t.Fatalf("no SARIF for flags %v: %v\n%s", extra, err, out)
		}
		var found []string
		for _, v := range values {
			if strings.Contains(string(b), v) {
				found = append(found, v)
			}
		}
		var d sarifDoc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("unparseable SARIF for flags %v: %v", extra, err)
		}
		n := 0
		if len(d.Runs) > 0 && d.Runs[0].Results != nil {
			n = len(*d.Runs[0].Results)
		}
		return n, found
	}

	// NON-VACUITY, and it is the whole test: --show-match is the positive control. If it does
	// not reveal the values, the grep cannot find a value here and every "no leak" below is
	// meaningless. A fixture producing no findings would likewise leak nothing everywhere.
	nShow, leakShow := leaked("--show-match")
	if nShow < len(values) {
		t.Fatalf("--show-match run found only %d finding(s), want >= %d", nShow, len(values))
	}
	if len(leakShow) != len(values) {
		t.Fatalf("--show-match revealed %d of %d values; the positive control failed", len(leakShow), len(values))
	}

	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"default flag set", nil},
		{"--explain", []string{"--explain"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, found := leaked(tc.extra...)
			if n < len(values) {
				t.Fatalf("only %d finding(s) with %v — cannot be compared against the control", n, tc.extra)
			}
			if len(found) > 0 {
				t.Errorf("matched value(s) reached the report WITHOUT --show-match, flags %v: "+
					"%d of %d present. Values deliberately not printed here.", tc.extra, len(found), len(values))
			}
		})
	}
}

// precommitEnvSignals are the environment variables that switch this binary into pre-commit
// behaviour (internal/precommit/detector.go detectEnvironment) — from the ENVIRONMENT ALONE,
// no flag involved. PRE_COMMIT_HOME is the one that bites in practice: pre-commit itself sets
// it, so any CI image or shell with pre-commit installed carries it into unrelated runs.
var precommitEnvSignals = []string{
	"PRE_COMMIT=1",
	"_PRE_COMMIT_RUNNING=1",
	"PRE_COMMIT_HOME=/tmp/pch",
	"PRE_COMMIT_HOOK=1",
	"GIT_HOOK_TYPE=pre-commit",
}

// TestFerretPrecommitOptOutNeutralisesEveryPrecommitSignal protects the opt-out contract from
// #353: FERRET_PRECOMMIT=0 declines pre-commit behaviour, whatever triggered it. A machine
// consumer that sets it must get the ordinary exit code and the FULL result set for every one of
// the five signals — if the opt-out silently stopped covering one, that consumer keeps believing
// it is protected while its results quietly change with the ambient environment.
func TestFerretPrecommitOptOutNeutralisesEveryPrecommitSignal(t *testing.T) {
	bin := buildForCLIContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	// One HIGH plus one LOW finding: the exit code changes because findings exist, and the
	// result SET changes because pre-commit mode applies a confidence filter. A HIGH-only
	// fixture would show the first and hide the second.
	if err := os.WriteFile(in, []byte("aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseRC, baseIDs := runContractScan(t, bin, in, filepath.Join(dir, "base.sarif"), nil)
	if baseRC != 0 || len(baseIDs) < 2 {
		t.Fatalf("control run is rc=%d with %d finding(s) %v; this test needs a clean "+
			"multi-finding baseline", baseRC, len(baseIDs), baseIDs)
	}
	if len(precommitEnvSignals) < 5 {
		t.Fatalf("only %d signals listed; detectEnvironment checks five", len(precommitEnvSignals))
	}

	for i, sig := range precommitEnvSignals {
		name := strings.SplitN(sig, "=", 2)[0]
		t.Run(name, func(t *testing.T) {
			// Non-vacuity per signal: prove THIS signal still hijacks the run before checking
			// that the opt-out undoes it — otherwise a signal that stopped working makes the
			// opt-out look effective with nothing to neutralise.
			hijackRC, hijackIDs := runContractScan(t, bin, in,
				filepath.Join(dir, fmt.Sprintf("j%d.sarif", i)), []string{sig})
			if hijackRC == baseRC && len(hijackIDs) == len(baseIDs) {
				t.Skipf("%s no longer changes anything (rc=%d, ids=%v); nothing to neutralise", sig, hijackRC, hijackIDs)
			}

			rc, ids := runContractScan(t, bin, in,
				filepath.Join(dir, fmt.Sprintf("o%d.sarif", i)), []string{sig, "FERRET_PRECOMMIT=0"})
			if rc != baseRC {
				t.Errorf("with %s set, FERRET_PRECOMMIT=0 left the exit code at %d instead of "+
					"restoring %d — the only way to decline pre-commit behaviour stopped covering "+
					"this signal. See internal/precommit/detector.go precommitOptOut and #353.",
					sig, rc, baseRC)
			}
			if strings.Join(ids, ",") != strings.Join(baseIDs, ",") {
				t.Errorf("with %s set, FERRET_PRECOMMIT=0 produced ruleIds %v instead of %v — "+
					"results would depend on ambient environment with nothing saying so", sig, ids, baseIDs)
			}
		})
	}
}

// TestExcludeFailureModesAreLoud pins the two failure directions of --exclude (#729):
//
//  1. a MALFORMED pattern (an unmatched '[' is filepath.Match's only syntax error, and it is
//     legal in a filename) aborts before scanning, with the reason naming --exclude. Failing
//     loudly is the contract: silently ignoring a bad pattern means an exclusion the user asked
//     for is not applied, and nobody is told.
//  2. a well-formed pattern that matched NOTHING by scan end is reported — one combined note —
//     because for a scanner, scanning more than intended is the safe direction only if the user
//     learns their exclusion did nothing.
func TestExcludeFailureModesAreLoud(t *testing.T) {
	bin := buildForCLIContract(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aws key AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runExclude := func(pattern string) (int, string, bool) {
		sarifPath := filepath.Join(t.TempDir(), "out.sarif")
		c := exec.Command(bin, "--file", dir, "--recursive", "--config", os.DevNull,
			"--exclude", pattern, "--format", "sarif", "--output", sarifPath,
			"--no-color", "--quiet", "--limit", "0")
		out, _ := c.CombinedOutput()
		_, statErr := os.Stat(sarifPath)
		return c.ProcessState.ExitCode(), string(out), statErr == nil
	}

	// Non-vacuity: the well-formed value must succeed, or "the bad one failed" says nothing.
	rcGood, outGood, wroteGood := runExclude(".venv,.git,*.pyc")
	if rcGood != 0 || !wroteGood {
		t.Fatalf("the well-formed --exclude value failed (rc=%d written=%v)\n%s", rcGood, wroteGood, outGood)
	}

	t.Run("malformed pattern aborts loudly", func(t *testing.T) {
		rc, out, _ := runExclude("foo[")
		if rc == 0 {
			t.Errorf("a malformed --exclude pattern was ACCEPTED (rc=0) — the user's exclusion "+
				"silently does not apply.\n%s", out)
		}
		if !strings.Contains(out, "--exclude") {
			t.Errorf("the error does not name --exclude, so the user cannot tell which input was "+
				"at fault.\n%s", out)
		}
	})

	t.Run("zero-hit pattern is reported, not silent", func(t *testing.T) {
		rc, out, wrote := runExclude("**/*.nomatch")
		if rc != 0 || !wrote {
			t.Fatalf("a zero-hit pattern must not fail the run, got rc=%d written=%v\n%s", rc, wrote, out)
		}
		if !strings.Contains(out, "matched nothing") {
			t.Errorf("a pattern that matched nothing must be reported, and was not.\n%s", out)
		}
	})
}
