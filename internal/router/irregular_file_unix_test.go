// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !plan9

package router

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A build tag, not a runtime GOOS check.
//
// syscall.Mkfifo is not defined on Windows, so a `if runtime.GOOS == "windows" { t.Skip() }`
// guard inside a portable test file does not help: the compiler still has to resolve the
// symbol, and `go vet` fails on windows-latest before any test body runs. Constraining
// the whole file is the only thing that works.
//
// The behavior under test is not Unix-specific — the mode check rejects Windows device
// paths through the same os.FileMode bits — only the cheapest way to CREATE a
// non-regular file is. The portable half of the coverage (directories, and regular
// files under device-like paths) lives in irregular_file_test.go and runs everywhere.

// TestFifoIsRejectedAsIrregular is the positive case for the mode check. A named pipe
// is the cheapest non-regular file to create portably, and it is the one that would
// actually hang a scan.
func TestFifoIsRejectedAsIrregular(t *testing.T) {
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
