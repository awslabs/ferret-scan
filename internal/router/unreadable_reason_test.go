// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// CanProcessFile used to answer "no, unsupported file type" for a file it could not
// open. Those are opposite facts: an unsupported type has been examined and
// deliberately skipped, an unreadable file was never examined at all. Reporting the
// second as the first told the user their .txt was an unrecognized format and
// invited them to ignore it, while a file that may be full of PII went unscanned.

// writeFile creates a file with the given mode and returns its path.
func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return p
}

// TestUnreadableFileIsNotReportedAsUnsupported is the regression. A .txt is a
// supported extension; if it cannot be read, the reason must say so.
func TestUnreadableFileIsNotReportedAsUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not deny reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny reads")
	}

	dir := t.TempDir()
	p := writeFile(t, dir, "secret.txt", "ssn 449-87-4100\n", 0o000)

	fr := NewFileRouter(false)
	ok, reason := fr.CanProcessFile(p, true)

	if ok {
		t.Fatalf("a mode-000 file was reported as processable (reason %q)", reason)
	}
	if !strings.HasPrefix(reason, ReasonUnreadable) {
		t.Errorf("reason = %q, want it to start with %q.\nA supported extension that "+
			"cannot be opened must not be described as an unsupported type: the user "+
			"reads that as \"nothing to find here\" when in fact nothing was looked at.",
			reason, ReasonUnreadable)
	}
	// Check the CLASSIFICATION, not a substring of the whole message: the reason
	// embeds the file path, and a temp dir named after this test contains the word
	// "Unsupported", so a naive Contains check fails on its own fixture.
	if strings.HasPrefix(reason, "Unsupported") {
		t.Errorf("reason = %q still claims the file type is unsupported", reason)
	}
}

// TestMissingFileIsUnreadable covers the other way a file goes unexamined: it is
// gone by the time the router looks (deleted mid-scan, or a dangling symlink).
func TestMissingFileIsUnreadable(t *testing.T) {
	fr := NewFileRouter(false)
	ok, reason := fr.CanProcessFile(filepath.Join(t.TempDir(), "does-not-exist.txt"), true)

	if ok {
		t.Fatal("a nonexistent file was reported as processable")
	}
	if !strings.HasPrefix(reason, ReasonUnreadable) {
		t.Errorf("reason = %q, want the %q prefix", reason, ReasonUnreadable)
	}
}

// TestGenuinelyUnsupportedStillSaysUnsupported is the other half: the fix must not
// relabel every rejection as unreadable. A readable file of an unknown binary type
// is exactly what "Unsupported file type" is for, and pkg/scan exposes that string
// through its public CanProcessFile, so the wording is a contract.
func TestGenuinelyUnsupportedStillSaysUnsupported(t *testing.T) {
	dir := t.TempDir()
	// Readable, but binary content with an extension no preprocessor claims.
	p := writeFile(t, dir, "blob.zzz", "\x00\x01\x02\x03binary\x00\xff", 0o644)

	fr := NewFileRouter(false)
	ok, reason := fr.CanProcessFile(p, true)

	if ok {
		t.Fatalf("an unknown binary type was reported as processable (reason %q)", reason)
	}
	if strings.HasPrefix(reason, ReasonUnreadable) {
		t.Errorf("reason = %q claims the file is unreadable, but it is readable and "+
			"simply an unsupported type — the two must stay distinguishable in both "+
			"directions", reason)
	}
	if !strings.HasPrefix(reason, "Unsupported") {
		t.Errorf("reason = %q, want it to start by saying the type is unsupported", reason)
	}
}

// TestReadableTextFileIsStillAccepted is the non-vacuity floor: if the stat/read
// error handling above were too aggressive it would reject everything, and the two
// tests before this one would pass for the wrong reason.
func TestReadableTextFileIsStillAccepted(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "plain.txt", "ssn 449-87-4100\n", 0o644)

	fr := NewFileRouter(false)
	ok, reason := fr.CanProcessFile(p, true)

	if !ok {
		t.Fatalf("an ordinary readable .txt was rejected: %q", reason)
	}
	if reason != "Text file" {
		t.Errorf("reason = %q, want %q", reason, "Text file")
	}
}
