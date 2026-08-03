// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An empty file is readable, not unreadable.
//
// CanProcessFile probes, via isTextFile, a file by reading up to 512 bytes. For a zero-byte file
// Read returns (0, io.EOF), and the guard `err != nil && n == 0` reported that
// as an error — so CanProcessFile classified the file as ReasonUnreadable,
// which the CLI surfaces as:
//
//	WARNING: scan incomplete — N of M file(s) could not be opened, so they were
//	not scanned at all; any sensitive data they contain was NOT detected
//
// That sentence is false for an empty file: it contains nothing, so nothing went
// undetected and there is nothing for an operator to act on.
//
// Measured on a real source tree, ALL 25 files in that warning were zero bytes —
// build artifacts, empty .err logs, a .venv lock file, empty golden fixtures.
// The cost is not just noise: the diagnostic exists to surface files that
// genuinely could not be read (permission denied, a device node, I/O error), and
// burying those under 25 false entries defeats it. That is the regression this
// pins, in both directions.
func TestEmptyFileIsNotReportedUnreadable(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty fixture: %v", err)
	}

	// Guard the premise: a test against a non-empty file would pass vacuously.
	if info, err := os.Stat(empty); err != nil {
		t.Fatalf("stat empty fixture: %v", err)
	} else if info.Size() != 0 {
		t.Fatalf("fixture is %d bytes, want 0 — this test only means something for a zero-byte file", info.Size())
	}

	fr := &FileRouter{}
	ok, reason := fr.CanProcessFile(empty, true)

	if strings.Contains(reason, ReasonUnreadable) {
		t.Errorf("empty file reported as %q (reason %q) — a zero-byte file is readable, "+
			"and calling it unreadable tells the operator sensitive data went undetected "+
			"when there is no data at all", ReasonUnreadable, reason)
	}
	if !ok {
		t.Errorf("empty file was not accepted for processing (reason %q); it should be "+
			"scanned normally and simply yield no findings", reason)
	}
}

// The complement, and the reason the fix is narrowed to io.EOF: a file that
// genuinely cannot be read must still be reported. Without this, "silence the
// empty-file warning" could be implemented by silencing the whole diagnostic.
func TestUnreadableFileIsStillReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0o000 file is still readable, so this cannot be exercised")
	}

	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(locked, []byte("ssn 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	fr := &FileRouter{}
	ok, reason := fr.CanProcessFile(locked, true)

	if ok {
		t.Errorf("unreadable file was accepted for processing (reason %q)", reason)
	}
	if !strings.Contains(reason, ReasonUnreadable) {
		t.Errorf("unreadable file reported as %q, want a reason containing %q — this file "+
			"really does hold undetected sensitive data, which is exactly what the "+
			"diagnostic exists to surface", reason, ReasonUnreadable)
	}
}
