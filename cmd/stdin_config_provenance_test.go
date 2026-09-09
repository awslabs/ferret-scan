// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stdinPrecommitTriggers are the environment variables that put the binary into pre-commit mode.
// Kept in sync with internal/precommit/detector.go by TestPrecommitTriggerListIsComplete.
var stdinPrecommitTriggers = []string{
	"PRE_COMMIT", "_PRE_COMMIT_RUNNING", "PRE_COMMIT_HOME", "PRE_COMMIT_HOOK", "GIT_HOOK_TYPE",
}

// hostileConfigDir writes a project config that disables the types which would otherwise find
// something, plus an empty user config dir, and returns the directory to run in.
func hostileConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := "validators:\n  intellectual_property:\n    disabled_types:\n      - copyright\n      - internal_url\n"
	if err := os.WriteFile(filepath.Join(dir, ".ferret-scan.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "emptycfg"), 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runStdin pipes one copyright line into the built binary and returns its stderr.
func runStdin(t *testing.T, bin, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"--stdin", "--checks", "INTELLECTUAL_PROPERTY"}, args...)...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("Copyright (c) 2026 Acme Corporation. All rights reserved.\n")
	cmd.Env = append(os.Environ(),
		append([]string{"FERRET_CONFIG_DIR=" + filepath.Join(dir, "emptycfg")}, env...)...)
	var errOut strings.Builder
	cmd.Stderr = &errOut
	cmd.Stdout = nil
	_ = cmd.Run() // a non-zero exit is not itself a failure here
	return errOut.String()
}

// TestStdinConfigProvenanceSurvivesQuietAndPrecommit is the guard on the residual #603 left behind.
//
// #603 un-gated the config-provenance note on the FILE path, and TM-13 recorded that it is "gated on
// neither --quiet, non-interactive, nor pre-commit". That was false on the STDIN path: a second call
// site in cmd/stdin.go sat inside shouldSuppressStdinProse, whose quiet and pre-commit arms silenced it.
//
// Measured at ea4e2f4, with a .ferret-scan.yaml in the working directory disabling copyright:
//
//	--file, any of the five triggers    109 bytes, note present   (what #603 fixed)
//	--stdin, no trigger                 145 bytes, note present
//	--stdin + PRE_COMMIT=1                0 bytes, note ABSENT
//	  ... and the same for the other four triggers, --pre-commit-mode, and --quiet
//
// That is TB-7 on a different input path: a pull request shipping a config file silences the gate
// reviewing it, with nothing on stderr and a clean exit code.
func TestStdinConfigProvenanceSurvivesQuietAndPrecommit(t *testing.T) {
	bin := buildScanner(t)

	// Baseline: the note must appear with nothing set, or this test cannot detect suppression.
	if out := runStdin(t, bin, hostileConfigDir(t), nil); !strings.Contains(out, "project config") {
		t.Fatalf("no disclosure on the stdin path even with no trigger set, so this test proves "+
			"nothing about the triggers. stderr:\n%s", out)
	}

	for _, v := range stdinPrecommitTriggers {
		out := runStdin(t, bin, hostileConfigDir(t), []string{v + "=1"})
		if !strings.Contains(out, "project config") {
			t.Errorf("%s=1 suppressed the config-provenance disclosure on the STDIN path. A config "+
				"shipped in a pull request can disable detection, and pre-commit is exactly where that "+
				"pull request is reviewed. Got %d bytes:\n%s", v, len(out), out)
		}
		if !strings.Contains(out, ".ferret-scan.yaml") {
			t.Errorf("%s=1: the disclosure does not NAME the config, so a reader cannot tell which file "+
				"governed the scan:\n%s", v, out)
		}
	}

	for _, flag := range []string{"--pre-commit-mode", "--quiet"} {
		out := runStdin(t, bin, hostileConfigDir(t), nil, flag)
		if !strings.Contains(out, "project config") {
			t.Errorf("%s suppressed the disclosure on the STDIN path. --quiet documents suppressing "+
				"PROGRESS output; which config governed the run is not progress. Got %d bytes:\n%s",
				flag, len(out), out)
		}
	}
}

// TestStdinProvenanceStaysSilentWhenStderrCarriesFindings is the other half, and it is why the fix is
// not simply "never gate this".
//
// With --enable-redaction and no --output, the redacted content goes to stdout and the findings report
// goes to STDERR. Prose there corrupts `2> findings.json`, so withholding the note is a mechanical
// necessity rather than a preference — and it is the one arm of shouldSuppressStdinProse that must
// still apply to a disclosure. Without this test, "always disclose" would look correct and would break
// that redirect.
func TestStdinProvenanceStaysSilentWhenStderrCarriesFindings(t *testing.T) {
	bin := buildScanner(t)
	dir := hostileConfigDir(t)

	out := runStdin(t, bin, dir, []string{"PRE_COMMIT=1"}, "--enable-redaction")
	if strings.Contains(out, "project config") {
		t.Errorf("the note was written to stderr while stderr carries the findings document; this "+
			"breaks `2> findings.json`:\n%s", out)
	}

	// NON-VACUITY: give stderr back by naming an --output, and the note must return. Without this the
	// test above would pass if the note were suppressed unconditionally, which is the bug.
	withOutput := runStdin(t, bin, dir, []string{"PRE_COMMIT=1"},
		"--enable-redaction", "--output", filepath.Join(dir, "findings.json"))
	if !strings.Contains(withOutput, "project config") {
		t.Errorf("with --output naming a file, stderr is a human channel again and the note must "+
			"appear; got:\n%s", withOutput)
	}
}

// TestTheHostileConfigActuallySuppressesOnStdin is the non-vacuity floor beneath both tests above.
//
// They assert on a disclosure ABOUT a config that disables detection. If the fixture's config disabled
// nothing, both would pass while guarding nothing.
func TestTheHostileConfigActuallySuppressesOnStdin(t *testing.T) {
	bin := buildScanner(t)

	withCfg := runStdinStdout(t, bin, hostileConfigDir(t))
	clean := t.TempDir()
	if err := os.MkdirAll(filepath.Join(clean, "emptycfg"), 0o750); err != nil {
		t.Fatal(err)
	}
	without := runStdinStdout(t, bin, clean)

	if !strings.Contains(without, "COPYRIGHT") {
		t.Fatalf("without a project config the stdin scan found no COPYRIGHT, so the fixture does not "+
			"exercise a suppressing config:\n%s", without)
	}
	if strings.Contains(withCfg, "COPYRIGHT") {
		t.Errorf("the project config did not suppress the finding, so the disclosure tests describe a "+
			"config with no effect:\n%s", withCfg)
	}
}

// runStdinStdout is runStdin but returning stdout, for the non-vacuity floor.
func runStdinStdout(t *testing.T, bin, dir string) string {
	t.Helper()
	cmd := exec.Command(bin, "--stdin", "--checks", "INTELLECTUAL_PROPERTY")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("Copyright (c) 2026 Acme Corporation. All rights reserved.\n")
	cmd.Env = append(os.Environ(), "FERRET_CONFIG_DIR="+filepath.Join(dir, "emptycfg"))
	out, _ := cmd.Output()
	return string(out)
}
