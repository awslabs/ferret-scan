// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestHashFileMatchesTheBufferedDigest is the compatibility half: the audit trail's verification
// hash must be the same string it was before it was computed by streaming, or every previously
// written audit log disagrees with every new one for the same file.
func TestHashFileMatchesTheBufferedDigest(t *testing.T) {
	dir := t.TempDir()
	content := []byte("employee ssn 452-11-9384\ncontact jordan@example.com\n")
	p := filepath.Join(dir, "doc.txt")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	want := GenerateDocumentHash(content)
	if got := HashFile(p); got != want {
		t.Errorf("HashFile = %s, want %s (the digest of the same bytes)", got, want)
	}

	sum := sha256.Sum256(content)
	if want != hex.EncodeToString(sum[:]) {
		t.Errorf("GenerateDocumentHash is not sha256 of the content; the two must stay interchangeable")
	}
}

// TestHashFileOnAnUnreadableFileReturnsEmpty keeps the failure mode the caller already had. The
// hash is bookkeeping: a file that cannot be read records no hash rather than failing the
// redaction over its own audit entry.
func TestHashFileOnAnUnreadableFileReturnsEmpty(t *testing.T) {
	if got := HashFile(filepath.Join(t.TempDir(), "missing.txt")); got != "" {
		t.Errorf("HashFile on a missing file = %q, want empty", got)
	}
}

// TestHashFileDoesNotBufferTheFile is the reason this function exists.
//
// The audit trail used to hash the original with os.ReadFile followed by sha256.Sum256, which
// costs the file's whole size in resident memory for a value nothing keeps. Measured end to end
// on an 80 MB video: peak RSS 30 MB for a scan, 111 MB for the same scan with redaction enabled,
// back to 30 MB once this streamed. That defeated the point of a redactor that deliberately never
// loads the media.
//
// Allocation is the right instrument for a buffering bug — the cost IS the buffer. A CPU-only
// defect would need a counter instead, because it allocates nothing.
func TestHashFileDoesNotBufferTheFile(t *testing.T) {
	dir := t.TempDir()

	measure := func(size int) uint64 {
		p := filepath.Join(dir, "big.bin")
		if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if HashFile(p) == "" {
			t.Fatalf("HashFile failed at %d bytes", size)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	small := measure(64 << 10)
	large := measure(16 << 20) // 256x
	if large > small+(1<<20) {
		t.Errorf("allocation grew from %d to %d bytes for a 256x larger file; sha256 is a streaming "+
			"hash, so the cost must be the copy buffer and not the file", small, large)
	}
}
