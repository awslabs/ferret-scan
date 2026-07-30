// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/tests/helpers"
)

// A config file with a misspelled option used to be indistinguishable from a
// working one: yaml.Unmarshal ignores unknown keys, so the setting was silently
// never applied. These tests pin where the resulting warning is and is not
// allowed to appear, because stderr is a human channel in some invocation shapes
// and a machine-readable data channel in others.

const unknownKeyConfig = `defaults:
  format: json
  shwo_match: true
bogus_block:
  x: 1
`

// writeUnknownKeyConfig writes a config carrying two unknown keys plus a scan
// target, and returns their paths.
func writeUnknownKeyConfig(t *testing.T) (cfgPath, targetPath string) {
	t.Helper()
	dir := t.TempDir()

	cfgPath = filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(unknownKeyConfig), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	targetPath = filepath.Join(dir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ssn 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("writing target: %v", err)
	}
	return cfgPath, targetPath
}

// TestUnknownConfigKeysWarnInCI is the important case. CI is never interactive,
// and it is exactly where a config that silently fails to apply does the most
// damage — the scan looks configured and is not. So this warning deliberately
// does NOT ride the progress-output gate, which treats non-interactive as quiet.
func TestUnknownConfigKeysWarnInCI(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	cfgPath, targetPath := writeUnknownKeyConfig(t)

	cmd := exec.Command(bin, "--file", targetPath, "--config", cfgPath, "--format", "json")
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan failed: %v\nstderr=%s", err, stderr.String())
	}

	for _, key := range []string{"shwo_match", "bogus_block"} {
		if !strings.Contains(stderr.String(), key) {
			t.Errorf("stderr does not warn about unknown key %q; a misspelled option "+
				"that is silently ignored looks exactly like one that works\nstderr=%s",
				key, stderr.String())
		}
	}

	// The warning must never contaminate the results document.
	if strings.Contains(stdout.String(), "unknown config key") {
		t.Errorf("the warning leaked onto stdout, which carries the results document:\n%s",
			stdout.String())
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &doc); err != nil {
		t.Errorf("stdout is no longer parseable JSON: %v\n%s", err, stdout.String())
	}
}

// TestUnknownConfigKeysSilentInStdinRedaction guards the shape where stderr is
// the findings document rather than a human channel: with --stdin
// --enable-redaction and no --output, redacted bytes go to stdout and the
// findings JSON goes to stderr, so any prose there breaks `2> findings.json`.
func TestUnknownConfigKeysSilentInStdinRedaction(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	cfgPath, _ := writeUnknownKeyConfig(t)

	_, stderr, code := runStdinSeparateStreams(t, bin,
		"ssn 449-87-4100\n",
		"--stdin", "--config", cfgPath, "--enable-redaction",
		"--redaction-strategy", "simple", "--confidence", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}

	trimmed := strings.TrimSpace(stderr)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Fatalf("stderr must stay a parseable document in streaming-redaction mode, "+
			"got prose first: %q", trimmed[:min(len(trimmed), 120)])
	}
	if strings.Contains(trimmed, "unknown config key") {
		t.Error("the unknown-key warning was written to stderr while stderr carries " +
			"the findings document; it must be suppressed in this mode")
	}
}

// TestUnknownConfigKeysSilentInPrecommit pins the one mode that is allowed to
// stay quiet: pre-commit output is deliberately minimal, and the same exemption
// applies to the incomplete-coverage warning.
func TestUnknownConfigKeysSilentInPrecommit(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	cfgPath, targetPath := writeUnknownKeyConfig(t)

	cmd := exec.Command(bin, "--file", targetPath, "--config", cfgPath, "--pre-commit-mode")
	cmd.Env = append(os.Environ(), "PRE_COMMIT=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// Exit code is irrelevant here: pre-commit mode returns non-zero on findings.
	_ = cmd.Run()

	if strings.Contains(stderr.String(), "unknown config key") {
		t.Errorf("pre-commit mode must not emit the unknown-key warning:\n%s", stderr.String())
	}
}

// TestStdinHonorsSuppressionsFile covers the config-file path to the suppression
// file in stdin mode. cmd/stdin.go built its suppression manager straight from
// the flag, ignoring the value resolveConfiguration had just computed two lines
// earlier — the same read-the-flag-not-the-config defect this change exists to
// remove, in the one mode that was missed.
func TestStdinHonorsSuppressionsFile(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	dir := t.TempDir()

	supPath := filepath.Join(dir, "generated-suppressions.yaml")
	cfgPath := filepath.Join(dir, "cfg.yaml")
	cfg := "defaults:\n  format: json\nsuppressions:\n  file: " +
		strconv.Quote(supPath) + "\n  generate_on_scan: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	_, stderr, code := runStdinSeparateStreams(t, bin,
		"ssn 449-87-4100\n",
		"--stdin", "--config", cfgPath, "--confidence", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}

	if _, err := os.Stat(supPath); err != nil {
		t.Errorf("suppressions.file + generate_on_scan produced no file at %s in stdin "+
			"mode: %v\nstderr=%s", supPath, err, stderr)
	}
}

// TestValidConfigWarnsAboutNothing is the false-positive guard: a warning that
// fires on a correct config trains users to ignore it.
func TestValidConfigWarnsAboutNothing(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "cfg.yaml")
	valid := "defaults:\n  format: json\n  show_match: true\n"
	if err := os.WriteFile(cfgPath, []byte(valid), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	targetPath := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ssn 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("writing target: %v", err)
	}

	cmd := exec.Command(bin, "--file", targetPath, "--config", cfgPath, "--format", "json")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan failed: %v\nstderr=%s", err, stderr.String())
	}

	if strings.Contains(stderr.String(), "unknown config key") {
		t.Errorf("a fully valid config produced an unknown-key warning:\n%s", stderr.String())
	}
}

// TestShippedConfigWarnsAboutNothing pins that the config we ship validates
// against our own schema. It did not: `audit_log_file` and the whole
// `suppressions:` block had no struct fields, so the project's own example
// documented settings that did nothing.
func TestShippedConfigWarnsAboutNothing(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	shipped, err := filepath.Abs(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatalf("resolving shipped config: %v", err)
	}
	if _, err := os.Stat(shipped); err != nil {
		t.Skipf("shipped config.yaml not found: %v", err)
	}

	bin := stdinBinary(t)
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ssn 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("writing target: %v", err)
	}

	cmd := exec.Command(bin, "--file", targetPath, "--config", shipped, "--format", "json")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scanning with the shipped config failed: %v\nstderr=%s", err, stderr.String())
	}

	if strings.Contains(stderr.String(), "unknown config key") {
		t.Errorf("the shipped config.yaml contains keys our own schema rejects:\n%s\n"+
			"Either wire the key up or drop it from the example — shipping a "+
			"documented no-op is how these went unnoticed.", stderr.String())
	}
}
