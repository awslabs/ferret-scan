// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// #639: the redacted copy was written with os.WriteFile, which opens O_TRUNC, so a failed write left a
// file at the output path while the run reported that no copy had been written.
//
// Measured on a deliberately filled 2MB volume, an 862KB redaction: ENOSPC, the disclosure correct
// ("no redacted copy was written; the original values remain in cleartext"), and a ZERO-BYTE file left
// behind. Not a leak — the bytes are the redacted text, so any prefix has its values masked, and the
// remnant was empty at 168KB, 400KB and 600KB of free space, never partial. The hazard is a phantom
// artefact: a pipeline globbing the output directory finds a document-shaped path where the tool says
// there is none.
//
// ENOSPC cannot be forced from a unit test without a filesystem, so these cover the properties that
// can be: a successful write's result, and — the one that matters — that a FAILED write leaves the
// destination exactly as it was.

func TestWriteRedactedOutputWritesTheData(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "redacted.txt")
	want := "SSN [SSN-REDACTED] on file\n"

	if err := writeRedactedOutput(out, []byte(want)); err != nil {
		t.Fatalf("writeRedactedOutput: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the output: %v", err)
	}
	if string(got) != want {
		t.Errorf("output = %q, want %q", got, want)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// 0600 for the same reason the destination always used it: a redacted copy is as sensitive as the
	// input. A temp-file rewrite is exactly where this is easy to lose, since CreateTemp makes 0600 on
	// most platforms but that is not guaranteed by contract.
	//
	// ASSERTED ONLY WHERE THE MODE MEANS SOMETHING. Windows has no POSIX permission bits: Go reports
	// -rw-rw-rw- for any writable file there, which is what failed windows-latest on the first version
	// of this test. The mode is not being lost on Windows, it never existed -- access is an ACL
	// question, and asserting a number that the platform does not model would be a false guarantee.
	if runtime.GOOS == "windows" {
		t.Logf("mode = %v; not asserted on windows, which has no POSIX permission bits (access is "+
			"governed by ACLs, and Go reports -rw-rw-rw- for any writable file)", info.Mode().Perm())
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %v, want 0600 — a redacted copy is as sensitive as the input", perm)
	}

	assertNoTempLeftovers(t, dir)
}

// TestAFailedWriteLeavesThePreviousCopyIntact is the property the first version of this fix got wrong.
//
// That version called os.Remove(outputPath) after a failure. When the failure is at OPEN nothing has
// been truncated, so the remove would destroy a PREVIOUS run's perfectly good copy. Writing to a
// temporary and renaming cannot do that, because the destination is only touched by a rename that has
// already succeeded.
func TestAFailedWriteLeavesThePreviousCopyIntact(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "redacted.txt")
	previous := "a PREVIOUS run's good redacted copy\n"
	if err := os.WriteFile(out, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}

	// Make the directory unwritable so CreateTemp fails — the closest a unit test can get to a write
	// that cannot proceed. Restored by t.Cleanup so TempDir can remove itself.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory unwritable here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := writeRedactedOutput(out, []byte("the NEW content that must not land\n"))
	if err == nil {
		t.Skip("the write succeeded despite a read-only directory (running as a user that bypasses " +
			"the mode, e.g. root); this property cannot be observed here")
	}
	if !strings.Contains(err.Error(), "failed to write redacted file") {
		t.Errorf("error = %v, want it to name the write failure so the caller can report the cause", err)
	}

	got, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatalf("the previous copy is GONE after a failed write: %v. That is the hazard the temp-file "+
			"approach exists to avoid — a failure must not destroy an artefact the operator already had",
			rerr)
	}
	if string(got) != previous {
		t.Errorf("the previous copy was modified by a FAILED write: got %q, want %q", got, previous)
	}
}

// TestAFailedWriteLeavesNoTemporaryFile: a temp file left in the redaction output directory is the same
// phantom-artefact problem in a different costume, and one with a stranger name.
func TestAFailedWriteLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "out")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(sub, "redacted.txt")

	if err := os.Chmod(sub, 0o500); err != nil {
		t.Skipf("cannot make the directory unwritable here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	if err := writeRedactedOutput(out, []byte("content\n")); err == nil {
		t.Skip("the write succeeded despite a read-only directory; this property cannot be observed here")
	}

	// Re-open the directory to inspect it.
	if err := os.Chmod(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	assertNoTempLeftovers(t, sub)
	if _, err := os.Stat(out); err == nil {
		t.Errorf("a file exists at %s after a failed write — the run reports that no redacted copy was "+
			"written, and a pipeline globbing this directory would find one anyway", out)
	}
}

// TestWriteRedactedOutputReplacesAnExistingFile covers the ordinary re-run: the rename must overwrite,
// not fail, or a second scan into the same output directory would break.
func TestWriteRedactedOutputReplacesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "redacted.txt")
	if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRedactedOutput(out, []byte("fresh\n")); err != nil {
		t.Fatalf("writeRedactedOutput over an existing file: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fresh\n" {
		t.Errorf("output = %q, want %q — a re-run into the same directory must replace the copy",
			got, "fresh\n")
	}
	assertNoTempLeftovers(t, dir)
}

func assertNoTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ferret-redacted-") {
			t.Errorf("temporary file %q left in %s — a stray temp in the redaction output directory is "+
				"the same phantom artefact with a stranger name", e.Name(), dir)
		}
	}
}

// TestTheTemporaryIsCreatedBesideTheDestination makes the temp file's LOCATION observable, which it
// otherwise is not — a mutation moving it to TMPDIR passed every other test in this file, because on a
// developer machine TMPDIR and the destination are usually the same filesystem.
//
// It matters in production for two reasons: a rename across filesystems fails with EXDEV, and a
// temporary holding redacted content should never land somewhere with weaker permissions than the
// destination the operator chose.
//
// Made observable by pointing TMPDIR at a directory the process cannot write. A CreateTemp("") would
// then fail; a CreateTemp(destination dir) succeeds.
func TestTheTemporaryIsCreatedBesideTheDestination(t *testing.T) {
	unwritable := filepath.Join(t.TempDir(), "no-temp-here")
	if err := os.Mkdir(unwritable, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unwritable, 0o700) })
	t.Setenv("TMPDIR", unwritable)

	// Confirm the premise: a TMPDIR-based temp really is impossible here, or this test proves nothing.
	if f, err := os.CreateTemp("", "probe-*"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skip("TMPDIR is still writable (running as a user that bypasses the mode); the location of " +
			"the temporary cannot be observed here")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "redacted.txt")
	if err := writeRedactedOutput(out, []byte("redacted\n")); err != nil {
		t.Fatalf("writeRedactedOutput failed with TMPDIR unwritable: %v. The temporary must be created "+
			"in the DESTINATION's directory — in TMPDIR it also risks EXDEV on rename and weaker "+
			"permissions than the operator chose", err)
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "redacted\n" {
		t.Errorf("output = %q err=%v, want %q", got, err, "redacted\n")
	}
	assertNoTempLeftovers(t, dir)
}

// TestARenameFailureLeavesNoTemporary forces the rename to fail by making the destination an existing
// DIRECTORY. Without this the cleanup on that path is unreachable from a test: a mutation deleting it
// survived everything else in this file.
func TestARenameFailureLeavesNoTemporary(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "redacted.txt")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory cannot be replaced by a rename on any platform this runs on.
	if err := os.WriteFile(filepath.Join(out, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := writeRedactedOutput(out, []byte("content\n"))
	if err == nil {
		t.Fatal("writing over a non-empty directory succeeded, which it must not")
	}
	if !strings.Contains(err.Error(), "failed to write redacted file") {
		t.Errorf("error = %v, want it to name the write failure", err)
	}

	assertNoTempLeftovers(t, dir)
	// And the directory it could not replace must be untouched.
	if _, serr := os.Stat(filepath.Join(out, "occupant")); serr != nil {
		t.Errorf("the destination directory's contents were disturbed by a failed write: %v", serr)
	}
}
