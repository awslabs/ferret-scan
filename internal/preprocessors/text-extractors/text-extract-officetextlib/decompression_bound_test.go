// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDocx builds a minimal .docx (a zip with word/document.xml) containing the
// given document XML body, written into dir. Returns the file path.
func writeDocx(t *testing.T, dir, name, documentXML string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(documentXML)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write docx: %v", err)
	}
	return p
}

// TestExtractDocx_DecompressionAmplificationBounded is the regression test for
// v2 gap 2.4: a small .docx whose document.xml decompresses to far more than the
// per-entry cap must NOT be read in full into memory. We build a ~200MB
// (uncompressed) document.xml of highly-compressible data — the archive on disk
// is tiny — and assert extraction (a) completes quickly and (b) never produced
// more than the cap's worth of raw entry bytes.
func TestExtractDocx_DecompressionAmplificationBounded(t *testing.T) {
	dir := t.TempDir()

	// ~200MB of repetitive, highly-compressible XML text. zip/DEFLATE compresses
	// this to well under a megabyte on disk, but a naive io.ReadAll would inflate
	// it back to 200MB in memory. The cap is 50MB.
	const uncompressedSize = 200 * 1024 * 1024
	var b strings.Builder
	b.Grow(uncompressedSize + 64)
	b.WriteString("<w:document><w:body><w:p><w:t>")
	filler := strings.Repeat("A", 64*1024) // 64KB chunk
	for b.Len() < uncompressedSize {
		b.WriteString(filler)
	}
	b.WriteString("</w:t></w:p></w:body></w:document>")
	docXML := b.String()
	if len(docXML) <= MaxZipEntryBytes {
		t.Fatalf("test setup: doc XML (%d) must exceed the cap (%d)", len(docXML), MaxZipEntryBytes)
	}

	path := writeDocx(t, dir, "bomb.docx", docXML)

	// Sanity: the on-disk archive is tiny relative to the decompressed size
	// (this is the amplification the cap defends against).
	if fi, err := os.Stat(path); err == nil {
		t.Logf("on-disk .docx: %d bytes; uncompressed document.xml: %d bytes", fi.Size(), len(docXML))
	}

	start := time.Now()
	content, err := ExtractText(path)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ExtractText error: %v", err)
	}

	// The extracted text is derived from at most MaxZipEntryBytes of raw XML, so
	// it cannot exceed that. (It will be smaller after tag stripping.) The key
	// guarantee: we did not materialize the full 200MB.
	if content.CharCount > MaxZipEntryBytes {
		t.Errorf("extracted text (%d chars) exceeds the per-entry cap (%d) — decompression not bounded",
			content.CharCount, MaxZipEntryBytes)
	}

	// Bounded work also means bounded time. A full 200MB read + regex passes
	// would be far slower; generous ceiling guards against an unbounded regression.
	if elapsed > 30*time.Second {
		t.Errorf("extraction took %v on an amplification input — suggests it read past the cap", elapsed)
	}
}

// TestExtractDocx_NormalDocumentUnaffected confirms a legitimate small document
// is extracted in full (the cap does not clip real content).
func TestExtractDocx_NormalDocumentUnaffected(t *testing.T) {
	dir := t.TempDir()
	const secret = "contact alice@example.com about card 4532-0151-1283-0366"
	docXML := "<w:document><w:body><w:p><w:t>" + secret + "</w:t></w:p></w:body></w:document>"
	path := writeDocx(t, dir, "normal.docx", docXML)

	content, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText error: %v", err)
	}
	if !strings.Contains(content.Text, "alice@example.com") || !strings.Contains(content.Text, "4532-0151-1283-0366") {
		t.Errorf("normal document text was clipped or mangled; got %q", content.Text)
	}
}
