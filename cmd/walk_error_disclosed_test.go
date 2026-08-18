// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A path the directory walk cannot access must be DISCLOSED, not counted nowhere.
//
// The walk callback's error branch printed one stderr warning and appended the path to
// a local slice whose only consumer was a "Skipped N files or directories due to
// errors" count. The path reached no counter: absent from total_files, files_skipped,
// files_not_examined, the NOT FULLY EXAMINED block, and --fail-on-incomplete.
//
// Measured on the shipped binary, a permission-denied directory holding an SSN:
//
//	Skipped 1 files or directories due to errors     (stderr only, named nothing)
//	No matches found.
//	--fail-on-incomplete -> exit 0
//	json stats carried no files_not_examined key at all
//
// A directory of unread PII reported a clean bill of health. Same defect class as the
// oversize refusal fixed for #324, and worse: a refused DIRECTORY hides every
// descendant, and how many is unknowable. See #336 defect 3.

// requireUnreadablePathsWork skips on platforms/users where chmod cannot deny access.
//
// Both guards are necessary. On Windows the Unix permission bits are not enforced, and
// root bypasses them entirely — in either case the fixture is readable, the walk
// reports no error, and the test would pass while asserting nothing.
func requireUnreadablePathsWork(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are bypassed, so the fixture would be readable")
	}
	// Prove the fixture actually denies access before asserting on the consequence.
	if _, err := os.ReadDir(path); err == nil {
		if _, err := os.Open(path); err == nil { // #nosec G304 -- test temp dir
			t.Skipf("%s is still readable despite chmod 000; cannot exercise the error branch", path)
		}
	}
}

func TestUnreadableDirectoryIsDisclosed(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	// Real PII inside, so a silent skip is a real loss rather than a cosmetic one.
	if err := os.WriteFile(filepath.Join(secret, "pii.txt"), []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := filepath.Join(root, "readable.txt")
	if err := os.WriteFile(ok, []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })
	requireUnreadablePathsWork(t, secret)

	res, err := getFilesToProcess(root, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	// The readable file is still scanned — the fix must not abort the walk.
	var sawReadable bool
	for _, p := range res.FilesToProcess {
		if filepath.Base(p) == "readable.txt" {
			sawReadable = true
		}
	}
	if !sawReadable {
		t.Errorf("FilesToProcess = %v, want readable.txt — an access error on one entry must "+
			"not stop the rest of the walk", res.FilesToProcess)
	}

	var found *SkippedFile
	for i := range res.UnexaminedFiles {
		if strings.Contains(res.UnexaminedFiles[i].Path, "secret") {
			found = &res.UnexaminedFiles[i]
		}
	}
	if found == nil {
		t.Fatalf("the unreadable directory is not in UnexaminedFiles %v — it reaches no "+
			"counter, so a directory of unread PII reports a clean scan at exit 0",
			pathsOf(res.UnexaminedFiles))
	}
	if found.Cause != causeUnreadable {
		t.Errorf("cause = %v (%q), want causeUnreadable — this path genuinely could not be "+
			"read, unlike a size refusal or a declined symlink", found.Cause, found.Cause.String())
	}

	// A refused DIRECTORY must say its contents are unaccounted for. "cannot read" on
	// one path reads as one lost file; the real loss is every descendant, and the count
	// is unknowable.
	low := strings.ToLower(found.Reason)
	if !strings.Contains(low, "director") {
		t.Errorf("reason = %q, want it to say a DIRECTORY was refused so the reader knows "+
			"descendants are unaccounted for", found.Reason)
	}
	if !strings.Contains(low, "unknown number") {
		t.Errorf("reason = %q, want it to state the descendant count is unknown", found.Reason)
	}
	// Payload-free: the reason reaches stderr and every machine format.
	if strings.Contains(found.Reason, "452-11-9384") {
		t.Errorf("reason %q leaked file content", found.Reason)
	}
}

// An unreadable FILE must be disclosed too, and must NOT claim to be a directory.
func TestUnreadableFileIsDisclosed(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "locked.txt")
	if err := os.WriteFile(locked, []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	requireUnreadablePathsWork(t, locked)

	res, err := getFilesToProcess(root, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	// filepath.Walk can Lstat a mode-000 FILE fine, so it is handed to the scanner and
	// the read failure surfaces later through the unreadable channel. Either route is a
	// disclosure; what must never happen is the entry claiming to be a directory.
	for _, u := range res.UnexaminedFiles {
		if strings.Contains(u.Path, "locked.txt") {
			if strings.Contains(strings.ToLower(u.Reason), "director") {
				t.Errorf("a FILE was described as a directory: %q", u.Reason)
			}
			if u.Cause != causeUnreadable {
				t.Errorf("cause = %v, want causeUnreadable", u.Cause)
			}
			return
		}
	}
	// Not in UnexaminedFiles means the walk could stat it and queued it; the scanner
	// then reports the read failure. Assert it was not silently dropped.
	var queued bool
	for _, p := range res.FilesToProcess {
		if filepath.Base(p) == "locked.txt" {
			queued = true
		}
	}
	if !queued {
		t.Error("the unreadable file is in neither UnexaminedFiles nor FilesToProcess — it " +
			"was dropped with no record anywhere")
	}
}

// The misleading aggregate must be gone.
//
// "Skipped N files or directories due to errors" was a bare count on stderr that named
// nothing, reached no counter, and was fed by size refusals as well as real errors — so
// a run whose only "errors" were two oversize files reported them as errors. See #336
// defect 4.
func TestNoStderrOnlyErrorAggregateRemains(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	// The phrase may survive in a comment explaining the removal; what must not survive
	// is a Fprintf that emits it.
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(line, "files or directories due to errors") {
			t.Errorf("main.go still emits the stderr-only error aggregate: %s", trimmed)
		}
	}
}
