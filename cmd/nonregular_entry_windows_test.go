// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The Windows half of #485.
//
// The POSIX object types are covered in nonregular_entry_unix_test.go, behind a build tag because
// syscall.Mkfifo does not exist here — the Makefile records why that must be a tag and not a runtime
// GOOS check: `GOOS=windows go build ./...` skips _test.go entirely, so a cross-build reports clean and
// windows-latest then fails on the missing symbol.
//
// What Windows actually meets is different, and read from Go's own source (os/types_windows.go) rather
// than assumed:
//
//	named pipes           NOT in the filesystem namespace (\\.\pipe\*), so a walk never enumerates one
//	char/block devices    NOT in the namespace either (\\.\PhysicalDrive0)
//	AF_UNIX socket        reported as ModeSocket, same as POSIX
//	junction/mount point  reported as ModeIrregular -- NOT ModeDir, because Go skips the ModeDir
//	                      assignment for a name-surrogate reparse point, deliberately, since a mount
//	                      point can contain infinite loops
//	other reparse points  ModeIrregular (cloud placeholders, dedup is deliberately left REGULAR)
//
// So the practically common trigger here is a JUNCTION, and junctions are ordinary: C:\Users\All Users,
// C:\Documents and Settings, per-user My Documents shims, volume mount points, OneDrive roots. That
// makes this branch MORE reachable on Windows than the FIFO case is on POSIX, not less.
//
// Creating a junction from a test needs `mklink /J` (an external command) or elevated privileges for a
// symlink, so it is not attempted here. Behaviour is also GODEBUG-dependent —
// `GODEBUG=winsymlink=0` selects the pre-Go1.23 mapping, where a mount point reports as ModeSymlink
// instead of ModeIrregular — so an assertion pinned to one exact mode string would be wrong half the
// time. Either way both values are handled: ModeSymlink by the pre-existing symlink branch,
// ModeIrregular by the new one.

// TestDirectoriesAreStillTraversedOnWindows is the regression guard that matters here.
//
// The new branch is `else if !info.IsDir()`. If that guard were wrong, every directory would be
// reported as an unexamined non-regular entry, which would fire on every scan on every platform. The
// cause and mapping assertions are platform-independent and live in nonregular_entry_test.go.
func TestDirectoriesAreStillTraversedOnWindows(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	for _, u := range res.UnexaminedFiles {
		if u.Cause == causeNotRegular {
			t.Errorf("%s was recorded as a non-regular entry; directories are traversed", u.Path)
		}
	}
	if len(res.FilesToProcess) != 2 {
		t.Errorf("FilesToProcess = %v, want both files", res.FilesToProcess)
	}
}
