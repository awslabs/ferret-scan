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

// refusedRuleSuppressionFile writes a suppression file whose one rule carries a misspelled expiry key.
// The strict loader (#866) refuses the rule and says so on its warnings writer, so this file is the
// smallest input that makes the loader speak.
func refusedRuleSuppressionFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "typo.yaml")
	rules := "version: \"1.0\"\nrules:\n" +
		"    - id: SUP-00000001\n" +
		"      hash: 0000000000000000000000000000000000000000000000000000000000000000\n" +
		"      reason: lapsed baseline\n" +
		"      enabled: true\n" +
		"      expries_at: 2026-01-01T00:00:00Z\n"
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runStdinWithSuppressions pipes one copyright line into the built binary with the given suppression
// file and returns stderr.
func runStdinWithSuppressions(t *testing.T, bin, dir, supFile string, args ...string) string {
	t.Helper()
	all := append([]string{"--stdin", "--checks", "INTELLECTUAL_PROPERTY", "--config", os.DevNull,
		"--format", "json", "--suppression-file", supFile}, args...)
	cmd := exec.Command(bin, all...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("Copyright (c) 2026 Acme Corporation. All rights reserved.\n")
	cmd.Env = append(os.Environ(), "FERRET_CONFIG_DIR="+filepath.Join(dir, "emptycfg"))
	var errOut strings.Builder
	cmd.Stderr = &errOut
	cmd.Stdout = nil
	_ = cmd.Run() // the exit code is not what this test is about
	return errOut.String()
}

// TestStdinLoaderWarningsStayOffTheFindingsDocument guards the one mode where the suppression loader's
// warnings must be withheld: --enable-redaction with no --output, where stderr IS the findings JSON.
//
// Measured with #866's strict loader before this routing: `--stdin --enable-redaction` on a file whose
// rule carries `expries_at` wrote "WARNING: 1 suppression rule(s) in typo.yaml are NOT applied ..." and
// then the findings JSON to stderr, so `2> findings.json` no longer parsed. On main the same mode
// parsed, but applied the lapsed rule as if it were permanent.
func TestStdinLoaderWarningsStayOffTheFindingsDocument(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "emptycfg"), 0o750); err != nil {
		t.Fatal(err)
	}
	sup := refusedRuleSuppressionFile(t, dir)

	// NON-VACUITY first: with stderr a human channel, the loader must name the refused rule, or the
	// assertion below passes while guarding nothing.
	plain := runStdinWithSuppressions(t, bin, dir, sup)
	if !strings.Contains(plain, "expries_at") {
		t.Fatalf("the strict loader did not name the misspelled key on plain --stdin, so this test "+
			"cannot tell whether redaction mode withheld it. stderr:\n%s", plain)
	}

	// Stderr carries the findings document: it must be exactly one JSON value, nothing before it.
	doc := runStdinWithSuppressions(t, bin, dir, sup, "--enable-redaction")
	var parsed any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Errorf("stderr is the findings document in this mode and must parse as JSON; got %v.\n"+
			"A loader warning written here breaks `2> findings.json`. stderr:\n%s", err, doc)
	}
	if strings.Contains(doc, "expries_at") {
		t.Errorf("the loader warning reached stderr while stderr carries the findings document:\n%s", doc)
	}

	// Give stderr back by naming an --output, and the warning must return: the withholding is about
	// what stderr carries, not about redaction.
	withOutput := runStdinWithSuppressions(t, bin, dir, sup,
		"--enable-redaction", "--output", filepath.Join(dir, "findings.json"))
	if !strings.Contains(withOutput, "expries_at") {
		t.Errorf("with --output naming a file, stderr is a human channel again and the loader "+
			"warning must appear; got:\n%s", withOutput)
	}
}
