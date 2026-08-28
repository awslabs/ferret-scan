// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// #353, end to end. The formatter-level tests in internal/formatters/shared cover the decision;
// these cover the WIRING, which is what an operator experiences.
//
// The distinction is not academic: a mutation setting FormatterOptions.OutputToFile to a constant
// false in cmd/main.go left every formatter test passing, because those tests construct the
// options themselves. Only a test that runs the binary can see whether cmd passes the flag
// through.

// TestAnExplicitOutputFileIsWrittenInPrecommitMode is the regression test for the second defect.
//
// Measured before the fix, on a tree with no findings:
//
//	--format json --output r.json                 237 bytes, valid JSON, results: []
//	--format json --output r.json  (PRE_COMMIT=1)   0 bytes, JSONDecodeError
//
// Quiet mode is meant to govern console chatter, not whether a requested artifact exists.
func TestAnExplicitOutputFileIsWrittenInPrecommitMode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)

	// A CLEAN tree: the empty-document path is the one that produced zero bytes.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("nothing sensitive here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"json", "yaml", "csv"} {
		t.Run(format, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report."+format)
			got := runForExit(t, bin, dir, []string{"PRE_COMMIT=1"}, "--format", format, "--output", out)

			info, err := os.Stat(out)
			if err != nil {
				t.Fatalf("--output file was not created at all: %v (rc=%d)", err, got.rc)
			}
			if info.Size() == 0 {
				t.Fatalf("--output produced a 0-byte file under PRE_COMMIT=1 (rc=%d).\n"+
					"The caller named a path and expects a parseable artifact; zero bytes reads to "+
					"a consumer as a parse error or as no findings (#353).", got.rc)
			}
			if format == "json" {
				var doc map[string]interface{}
				b, readErr := os.ReadFile(out)
				if readErr != nil {
					t.Fatalf("read: %v", readErr)
				}
				if err := json.Unmarshal(b, &doc); err != nil {
					t.Errorf("the artifact is not valid JSON: %v\n%s", err, b)
				}
				if _, ok := doc["results"]; !ok {
					t.Errorf("the JSON artifact has no results key: %s", b)
				}
			}
		})
	}
}

// TestPrecommitStillStaysQuietOnStdout is the control. The empty-document behaviour exists to keep
// a clean commit silent, and this fix must not take that away — only stop it applying to a file the
// caller named.
func TestPrecommitStillStaysQuietOnStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("nothing sensitive here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runForExit(t, bin, dir, []string{"PRE_COMMIT=1"}, "--format", "json")
	if got.stdout != "" {
		t.Errorf("pre-commit mode with no findings wrote %d bytes to stdout; it is meant to stay "+
			"silent on a developer's every commit:\n%s", len(got.stdout), got.stdout)
	}
}

// TestTheOptOutRestoresOrdinaryBehaviourEndToEnd covers the third defect: detection changed quiet
// mode, colour and exit-code semantics with no way to decline.
func TestTheOptOutRestoresOrdinaryBehaviourEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("nothing sensitive here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// PRE_COMMIT=1 is the strongest signal there is; the opt-out must beat it.
	got := runForExit(t, bin, dir, []string{"PRE_COMMIT=1", "FERRET_PRECOMMIT=0"}, "--format", "json")
	if got.stdout == "" {
		t.Fatalf("FERRET_PRECOMMIT=0 with PRE_COMMIT=1 still produced empty stdout, so the opt-out "+
			"did not take effect (rc=%d)", got.rc)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(got.stdout), &doc); err != nil {
		t.Errorf("the opted-out run did not produce valid JSON on stdout: %v\n%s", err, got.stdout)
	}

	// And the control: without the opt-out the same command is silent, so the assertion above is
	// about the opt-out rather than about pre-commit mode never being active.
	quiet := runForExit(t, bin, dir, []string{"PRE_COMMIT=1"}, "--format", "json")
	if quiet.stdout != "" {
		t.Errorf("the control run was not quiet, so this test does not demonstrate the opt-out:\n%s",
			quiet.stdout)
	}
}
