// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingExporter struct{ err error }

func (f failingExporter) ExportAuditLog(string) error { return f.err }

// TestAnAuditLogThatDoesNotValidateFailsTheRun: ExportAuditLog writes nothing when an entry does not
// validate, and that used to reach the same `Warning:` at exit 0 as an unwritable path (#865). The CLI
// cannot be made to produce an invalid entry, so the validation branch is driven through the seam.
func TestAnAuditLogThatDoesNotValidateFailsTheRun(t *testing.T) {
	invalid := errors.New("failed to export audit logs: content_redactions[0].confidence must be between 0 and 1")
	if err := exportRedactionAuditLog(failingExporter{invalid}, "audit.json", true, nil); !errors.Is(err, invalid) {
		t.Errorf("a validation failure returned %v, want it back so the caller exits 1", err)
	}
	if err := exportRedactionAuditLog(failingExporter{}, "audit.json", true, nil); err != nil {
		t.Errorf("a successful export returned %v", err)
	}
}

// TestAnAuditLogThatCannotBeWrittenFailsTheRun is #865's resolution 8 on the binary: `Error:` and exit 1,
// as for an --output that cannot be written, in every mode. Measured before the fix with
// --redaction-audit-log /dev/null/audit.json: rc 0 plain, rc 0 with --fail-on-incomplete, and a
// `Warning:` line.
func TestAnAuditLogThatCannotBeWrittenFailsTheRun(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "sample.txt"), expiredSample)
	// A regular file where the log's directory should be: the write fails on every platform.
	writeFixture(t, filepath.Join(work, "notadir"), "")
	unwritable := filepath.Join("notadir", "audit.json")

	redact := []string{"--file", "sample.txt", "--format", "json", "--enable-redaction", "--redaction-output-dir", "out"}
	for _, tc := range []struct {
		name   string
		args   []string
		prefix string
	}{
		{"plain", []string{"--redaction-audit-log", unwritable}, "Error: Failed to export redaction audit log"},
		{"--fail-on-incomplete", []string{"--redaction-audit-log", unwritable, "--fail-on-incomplete"}, "Error: Failed to export redaction audit log"},
		{"--pre-commit-mode", []string{"--redaction-audit-log", unwritable, "--pre-commit-mode"}, "ferret-scan: Failed to export redaction audit log"},
	} {
		r := runCLI(t, bin, work, env, "", append(append([]string{}, redact...), tc.args...)...)
		if r.rc != 1 || !strings.Contains(r.stderr, tc.prefix) || strings.Contains(r.stderr, "Warning: Failed to export") {
			t.Errorf("%s: want rc 1 and %q; got rc=%d stderr=%q", tc.name, tc.prefix, r.rc, r.stderr)
		}
	}

	// The config key reaches the same export, so it fails the same way.
	writeFixture(t, filepath.Join(work, "audit.yaml"), "redaction:\n  audit_log_file: "+filepath.ToSlash(unwritable)+"\n")
	if r := runCLI(t, bin, work, env, "", append(append([]string{}, redact...), "--config", "audit.yaml")...); r.rc != 1 ||
		!strings.Contains(r.stderr, "Error: Failed to export redaction audit log") {
		t.Errorf("redaction.audit_log_file: want rc 1 and the error; got rc=%d stderr=%q", r.rc, r.stderr)
	}

	// Control: a writable path still writes a JSON log at rc 0.
	ok := filepath.Join(work, "audit.json")
	r := runCLI(t, bin, work, env, "", append(append([]string{}, redact...), "--redaction-audit-log", ok)...)
	if r.rc != 0 || !strings.Contains(r.stderr, "Redaction audit log exported to:") {
		t.Fatalf("writable control: rc=%d stderr=%q", r.rc, r.stderr)
	}
	raw, err := os.ReadFile(ok) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AuditLogs map[string]any `json:"audit_logs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.AuditLogs) == 0 {
		t.Errorf("writable control: the log is not a JSON document with audit_logs (%v):\n%s", err, raw)
	}
}
