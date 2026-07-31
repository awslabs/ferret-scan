// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// CanProcessFile refuses anything that is not a regular file. The reason is
// operational rather than security: a FIFO, socket or character device has no
// meaningful size, so the MaxFileSize gate cannot bound it, and the extractors
// downstream read the whole file into memory — a FIFO with no writer blocks forever
// and /dev/zero never ends.
//
// This check replaced a path-prefix denylist that lived in the Office metadata
// extractor and named /proc/, /sys/ and /dev/. Two tests below pin the reasons a mode
// check is the right shape: it catches kinds the name-based list missed (and would
// have had to enumerate per platform), and it accepts the ordinary files that merely
// happen to live under one of those prefixes.

// TestFifoIsRejectedAsIrregular is the positive case for the mode check. A named pipe
// is the cheapest non-regular file to create portably, and it is the one that would
// actually hang a scan.
func TestFifoIsRejectedAsIrregular(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mkfifo on Windows; the mode check still applies there via ModeDevice/ModeIrregular")
	}

	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.txt")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	fr := NewFileRouter(false)

	// Deliberately named .txt: without the mode check this would be routed as a text
	// file and isTextFile would then block on the open, since a FIFO with no writer
	// never returns.
	ok, reason := fr.CanProcessFile(fifo, true)

	if ok {
		t.Fatalf("a FIFO was accepted for processing (reason %q); reading it would block "+
			"the scan indefinitely", reason)
	}
	if !strings.HasPrefix(reason, ReasonUnreadable) {
		t.Errorf("reason = %q, want the %q prefix: the file exists but could not be examined, "+
			"which is the same class as a permission error rather than an unsupported type",
			reason, ReasonUnreadable)
	}
	if !strings.Contains(reason, "named pipe") {
		t.Errorf("reason = %q, want it to name what the path actually was, so the user can tell "+
			"a mistyped path from a rejected format", reason)
	}
}

// TestDirectoryIsRejectedWithItsOwnReason covers the mistake a user is most likely to
// make — pointing --file at a directory.
func TestDirectoryIsRejectedWithItsOwnReason(t *testing.T) {
	fr := NewFileRouter(false)
	ok, reason := fr.CanProcessFile(t.TempDir(), true)

	if ok {
		t.Fatalf("a directory was accepted for processing (reason %q)", reason)
	}
	if !strings.Contains(reason, "directory") {
		t.Errorf("reason = %q, want it to say the path is a directory", reason)
	}
}

// TestRegularFileUnderDeviceLikePathIsAccepted is the non-vacuity floor and the
// regression for the denylist this replaced.
//
// The rejected version of this rule was a name-based list containing /dev/. On Linux
// /dev/shm is world-writable tmpfs that scripts and CI routinely use for temporary
// files, and its contents are ordinary regular files, so that list refused real
// documents. A mode check cannot make that mistake: the discriminator is what the
// file IS, not where it sits. Simulated here with a directory literally named "dev"
// so the test is portable.
func TestRegularFileUnderDeviceLikePathIsAccepted(t *testing.T) {
	base := t.TempDir()
	for _, dirName := range []string{"dev", "proc", "sys"} {
		dir := filepath.Join(base, dirName, "shm")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		p := filepath.Join(dir, "notes.txt")
		if err := os.WriteFile(p, []byte("ssn 449-87-4100\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		t.Run(dirName, func(t *testing.T) {
			fr := NewFileRouter(false)
			ok, reason := fr.CanProcessFile(p, true)
			if !ok {
				t.Errorf("a regular file under a directory named %q was rejected: %q.\n"+
					"The predecessor path denylist rejected these; the mode check must not, "+
					"or ordinary files in /dev/shm silently go unscanned.", dirName, reason)
			}
		})
	}
}

// TestOrdinaryFileStillAccepted is the broader floor: if the mode check were inverted
// or too aggressive it would reject everything, and the assertions above would pass
// for the wrong reason.
func TestOrdinaryFileStillAccepted(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(p, []byte("ssn 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	fr := NewFileRouter(false)
	ok, reason := fr.CanProcessFile(p, true)
	if !ok {
		t.Fatalf("an ordinary readable .txt was rejected: %q", reason)
	}
	if reason != "Text file" {
		t.Errorf("reason = %q, want %q", reason, "Text file")
	}
}
