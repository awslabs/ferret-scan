// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The POSIX half of #485: the object types a directory walk actually meets on unix.
//
// Split by BUILD TAG rather than a runtime GOOS check, and that is not stylistic. syscall.Mkfifo does
// not exist on Windows at all, so a `runtime.GOOS == "windows"` skip would not compile there — and the
// Makefile records the trap: `GOOS=windows go build ./...` skips _test.go entirely, so a local
// cross-build reports clean and windows-latest then fails. `make vet-all` covers all three GOOS.
//
// On Windows these objects are largely unreachable from a path walk (`\\.\pipe\*` and
// `\\.\PhysicalDrive0` are not in the filesystem namespace); the equivalent there is a junction, which
// Go reports as ModeIrregular and which the same branch handles.

// makeFIFO creates a named pipe, skipping if the filesystem will not have one.
func makeFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO at %s: %v", path, err)
	}
}

// TestANamedPipeIsCountedAndDisclosed is the reported defect, and the assertion that binds is the
// DENOMINATOR: the same directory with and without the pipe must not look identical.
//
// A test asserting only "the pipe produced no findings" passes on the broken code and would pass after
// a wrong fix, which is why it is not the assertion here.
func TestANamedPipeIsCountedAndDisclosed(t *testing.T) {
	withPipe := t.TempDir()
	control := t.TempDir()
	for _, d := range []string{withPipe, control} {
		if err := os.WriteFile(filepath.Join(d, "real.txt"), []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	makeFIFO(t, filepath.Join(withPipe, "pipe.dat"))

	got, err := getFilesToProcess(withPipe, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess(withPipe): %v", err)
	}
	ctrl, err := getFilesToProcess(control, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess(control): %v", err)
	}

	// POSITIVE CONTROL: the ordinary file is scanned in both, so a zero below is about the pipe and
	// not about the walk having failed.
	for name, r := range map[string]*ProcessingResult{"withPipe": got, "control": ctrl} {
		if len(r.FilesToProcess) != 1 || filepath.Base(r.FilesToProcess[0]) != "real.txt" {
			t.Fatalf("%s: FilesToProcess = %v, want just real.txt", name, r.FilesToProcess)
		}
	}

	// THE BINDING ASSERTION: the accounting must differ.
	if len(got.UnexaminedFiles) == len(ctrl.UnexaminedFiles) {
		t.Fatalf("a directory holding a named pipe produced the same accounting as one without it "+
			"(%d unexamined either way). The entry is then indistinguishable from not existing, and "+
			"--fail-on-incomplete cannot fire.", len(got.UnexaminedFiles))
	}

	var found *SkippedFile
	for i := range got.UnexaminedFiles {
		if filepath.Base(got.UnexaminedFiles[i].Path) == "pipe.dat" {
			found = &got.UnexaminedFiles[i]
		}
	}
	if found == nil {
		t.Fatalf("the pipe is not in UnexaminedFiles: %+v", got.UnexaminedFiles)
	}
	if found.Cause != causeNotRegular {
		t.Errorf("pipe cause = %v (%q), want causeNotRegular (%q)",
			found.Cause, found.Cause.String(), causeNotRegular.String())
	}
	if found.Reason != "not a regular file (named pipe)" {
		t.Errorf("pipe reason = %q, want the kind named", found.Reason)
	}
	if found.Silent {
		t.Error("the pipe was recorded as a SILENT skip, which keeps it out of the disclosure and " +
			"out of --fail-on-incomplete -- the same invisibility this fixes, one field over")
	}
}

// TestAUnixSocketIsCountedToo covers the second POSIX object, which the earlier measurement showed was
// dropped even in a directory that DID disclose something.
//
// On main, a directory holding an ordinary file, a socket, and a symlink to /dev/null reported
// total_files=2 and files_not_examined=1 — the 1 being the symlink. The socket was in neither count, so
// the disclosure that did appear was itself understated.
func TestAUnixSocketIsCountedToo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "sock.dat")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create a unix socket at %s: %v", sockPath, err)
	}
	defer func() { _ = l.Close() }()

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(res.FilesToProcess) != 1 {
		t.Fatalf("FilesToProcess = %v, want just real.txt", res.FilesToProcess)
	}

	var seen bool
	for _, u := range res.UnexaminedFiles {
		if filepath.Base(u.Path) == "sock.dat" {
			seen = true
			if u.Cause != causeNotRegular {
				t.Errorf("socket cause = %q, want %q", u.Cause.String(), causeNotRegular.String())
			}
			if u.Reason != "not a regular file (socket)" {
				t.Errorf("socket reason = %q, want the kind named", u.Reason)
			}
		}
	}
	if !seen {
		t.Errorf("the socket is not in UnexaminedFiles: %+v", res.UnexaminedFiles)
	}
}

// TestTheWalkDoesNotOpenANonRegularEntry is the policy, asserted by the fact that the scan RETURNS.
//
// Reading a FIFO with no writer blocks indefinitely, so if the walk ever opened one this test would
// hang rather than fail. Deliberately no timing assertion — a wall-clock bound is flaky on shared CI —
// so what this pins is that the walk completes and records the entry without touching it.
func TestTheWalkDoesNotOpenANonRegularEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No writer is ever attached, so any read would block forever.
	makeFIFO(t, filepath.Join(dir, "blocking.dat"))

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(res.FilesToProcess) != 1 {
		t.Errorf("FilesToProcess = %v, want just real.txt -- a pipe must never be queued for "+
			"scanning, because reading it can block for the life of the process", res.FilesToProcess)
	}
}
