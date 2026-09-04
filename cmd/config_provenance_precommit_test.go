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

// precommitTriggers are the environment variables that put the binary into pre-commit mode.
//
// Kept in sync with internal/precommit/detector.go by TestPrecommitTriggerListIsComplete, which reads
// that file. Listed here because the point of this test is that a DISCLOSURE must survive every one of
// them, and enumerating them is what makes "every one" checkable.
var precommitTriggers = []string{
	"PRE_COMMIT",
	"_PRE_COMMIT_RUNNING",
	"PRE_COMMIT_HOME",
	"PRE_COMMIT_HOOK",
	"GIT_HOOK_TYPE",
}

// buildScanner compiles the CLI once for the tests below.
//
// An end-to-end binary is required rather than calling reportConfigProvenance directly: the defect was
// not in that function but in the CALLER's gate, and a unit test on the function passes with the gate
// wrong. That is exactly how this shipped.
func buildScanner(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ferret-scan-test")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the scanner: %v\n%s", err, out)
	}
	return bin
}

// projectConfigFixture writes a scannable file plus a project config that disables the types which
// would otherwise find something in it, and returns the directory.
func projectConfigFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	notice := "Copyright (c) 2026 Acme Corporation. All rights reserved.\n" +
		"Internal wiki: https://example.com/team\n"
	if err := os.WriteFile(filepath.Join(dir, "notice.txt"), []byte(notice), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "validators:\n  intellectual_property:\n    disabled_types:\n      - copyright\n      - internal_url\n"
	if err := os.WriteFile(filepath.Join(dir, ".ferret-scan.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runScan runs the binary in dir with extra environment, returning combined output.
func runScan(t *testing.T, bin, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	// An empty user config dir, so only built-in defaults and the project config are in play.
	emptyCfg := filepath.Join(dir, "emptycfg")
	if err := os.MkdirAll(emptyCfg, 0o750); err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), append([]string{"FERRET_CONFIG_DIR=" + emptyCfg}, env...)...)
	out, _ := cmd.CombinedOutput() // a non-zero exit is not itself a failure here
	return string(out)
}

// TestConfigProvenanceSurvivesPrecommitMode is the guard for TM-13.
//
// A config file inside the scanned tree can switch detection off — `FindConfigFile` checks the working
// directory BEFORE the user config dir, so a `.ferret-scan.yaml` shipped in a pull request governs the
// scan that reviews that pull request. That is THREAT_MODEL TB-7, and it reaches TM-11's outcome by a
// shorter path: shipping a config is easier than crafting suppression padding.
//
// Project-local config is deliberate and is not the defect. The defect was that the note naming a
// DISCOVERED config was gated on pre-commit mode, and IsPrecommitEnvironment() is true from environment
// variables alone — so it took no flag to silence. Measured before the fix: the same scan emitted a
// 126-byte note with no variable set, and 0 bytes at exit 0 with any one of the five set.
func TestConfigProvenanceSurvivesPrecommitMode(t *testing.T) {
	bin := buildScanner(t)

	// Baseline: with no trigger set, the note must appear. If this fails the test proves nothing about
	// the triggers, because there would be no disclosure to suppress.
	base := runScan(t, bin, projectConfigFixture(t), nil, "--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY")
	if !strings.Contains(base, "project config") {
		t.Fatalf("no disclosure even with no pre-commit trigger set, so this test cannot detect "+
			"suppression. Output:\n%s", base)
	}

	for _, v := range precommitTriggers {
		out := runScan(t, bin, projectConfigFixture(t), []string{v + "=1"},
			"--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY")
		if !strings.Contains(out, "project config") {
			t.Errorf("%s=1 suppressed the config-provenance disclosure. A config shipped in a pull "+
				"request can disable detection, and pre-commit/CI is exactly where that pull request "+
				"is being reviewed — so this is the one place the note must not be silenced. Got %d "+
				"bytes:\n%s", v, len(out), out)
		}
		if !strings.Contains(out, ".ferret-scan.yaml") {
			t.Errorf("%s=1: the disclosure does not NAME the config file, so a reader cannot tell which "+
				"file governed the scan. Got:\n%s", v, out)
		}
	}
}

// TestAnExplicitConfigFlagStaysQuiet keeps the fix from becoming noise, which is the reason the gate
// existed in the first place.
//
// The note reports only a config DISCOVERED next to the working directory. A repo that deliberately
// keeps a project config can pass --config to acknowledge it and stay silent, so the disclosure fires
// for the unexpected case and not the intended one. Without this, "always disclose" would print on
// every commit in any repo with a project config, and the pressure to re-add a suppression gate would
// come straight back.
func TestAnExplicitConfigFlagStaysQuiet(t *testing.T) {
	bin := buildScanner(t)
	dir := projectConfigFixture(t)

	out := runScan(t, bin, dir, []string{"PRE_COMMIT=1"},
		"--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY", "--config", ".ferret-scan.yaml")
	if strings.Contains(out, "project config") {
		t.Errorf("--config named the file explicitly, so there is nothing undisclosed and the note is "+
			"noise. Got:\n%s", out)
	}
}

// TestTheProjectConfigActuallySuppressesFindings is the non-vacuity floor beneath both tests above.
//
// They assert on a disclosure ABOUT a config that disables detection. If the fixture's config did not
// actually disable anything, both would still pass while guarding nothing — the disclosure would be
// describing a config with no effect. This pins that the fixture really is the dangerous case.
func TestTheProjectConfigActuallySuppressesFindings(t *testing.T) {
	bin := buildScanner(t)

	withConfig := projectConfigFixture(t)
	got := runScan(t, bin, withConfig, nil, "--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY")

	// Same fixture, config removed.
	without := projectConfigFixture(t)
	if err := os.Remove(filepath.Join(without, ".ferret-scan.yaml")); err != nil {
		t.Fatal(err)
	}
	wantFindings := runScan(t, bin, without, nil, "--file", "notice.txt", "--checks", "INTELLECTUAL_PROPERTY")

	if !strings.Contains(wantFindings, "COPYRIGHT") {
		t.Fatalf("without the project config the scan found no COPYRIGHT, so the fixture does not "+
			"exercise a config that suppresses anything. Output:\n%s", wantFindings)
	}
	if strings.Contains(got, "COPYRIGHT") {
		t.Errorf("the project config did NOT suppress the finding, so the disclosure tests are "+
			"describing a config with no effect. Output:\n%s", got)
	}
}
