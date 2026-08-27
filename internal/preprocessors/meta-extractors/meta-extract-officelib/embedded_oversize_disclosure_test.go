// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An embedded part refused for size must be REPORTED, not skipped.
//
// The loop that extracts embedded parts discarded extractImageToTemp's error with a bare
// `continue`. When that error was the MaxEmbeddedMediaSize refusal, the part was never scanned
// and nothing said so: measured on the pair these fixtures reproduce, the over-cap container
// reported "No matches found" at exit 0 — and exit 0 again under --fail-on-incomplete, with
// nothing on stderr — while the identical inner document under the cap reported its SSN at
// HIGH 100. See #374.
//
// The fixtures are built here rather than committed, because the interesting one is 50 MB
// uncompressed and the point of the pair is that ONLY the size differs.

// zeros is an infinite reader of NUL bytes, so padding is streamed rather than buffered. A
// 50 MB []byte in a test is 50 MB of RSS for no reason, and this package's own subject is
// bounding what a container can make the tool allocate.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// innerDocx writes a minimal .docx carrying an SSN in its body, padded with `pad` STORED bytes
// so the file's own SIZE crosses whatever the caller needs.
//
// STORED, not deflated: the cap is compared against the outer entry's UncompressedSize64,
// which is this file's byte length. Compressed padding would shrink the file itself and the
// cap would never fire.
func innerDocx(t *testing.T, path string, pad int64) {
	t.Helper()

	f, err := os.Create(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create inner: %v", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	add := func(name, body string) {
		w, werr := zw.Create(name)
		if werr != nil {
			t.Fatalf("create %s: %v", name, werr)
		}
		if _, werr = io.WriteString(w, body); werr != nil {
			t.Fatalf("write %s: %v", name, werr)
		}
	}
	add("[Content_Types].xml", contentTypes)
	add("word/document.xml", documentXML("Attached record SSN: 452-11-9384"))

	if pad > 0 {
		w, werr := zw.CreateHeader(&zip.FileHeader{Name: "word/media/pad.bin", Method: zip.Store})
		if werr != nil {
			t.Fatalf("create pad: %v", werr)
		}
		if _, werr = io.CopyN(w, zeros{}, pad); werr != nil {
			t.Fatalf("write pad: %v", werr)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close inner: %v", err)
	}
}

// outerDocx wraps innerPath as word/embeddings/attachment.docx, deflated so the padding costs
// almost nothing on disk while the entry still DECLARES its full uncompressed size.
func outerDocx(t *testing.T, dir, name, innerPath string) string {
	t.Helper()

	outPath := filepath.Join(dir, name)
	f, err := os.Create(outPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create outer: %v", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	add := func(entry, body string) {
		w, werr := zw.Create(entry)
		if werr != nil {
			t.Fatalf("create %s: %v", entry, werr)
		}
		if _, werr = io.WriteString(w, body); werr != nil {
			t.Fatalf("write %s: %v", entry, werr)
		}
	}
	add("[Content_Types].xml", contentTypes)
	add("word/document.xml", documentXML("Cover letter, see attachment"))

	inner, err := os.Open(innerPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("open inner: %v", err)
	}
	defer func() { _ = inner.Close() }()

	w, err := zw.Create("word/embeddings/attachment.docx")
	if err != nil {
		t.Fatalf("create embedded entry: %v", err)
	}
	if _, err := io.Copy(w, inner); err != nil {
		t.Fatalf("copy inner: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close outer: %v", err)
	}
	return outPath
}

const contentTypes = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Default Extension="bin" ContentType="application/octet-stream"/>` +
	`<Default Extension="docx" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

func documentXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`
}

// TestOverCapEmbeddedPartIsReportedNotSkipped is the control/test pair. Only the SIZE of the
// embedded document differs, so any difference in the returned notes is attributable to the cap
// and to nothing else.
func TestOverCapEmbeddedPartIsReportedNotSkipped(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "inner_small.docx")
	innerDocx(t, small, 0)
	big := filepath.Join(dir, "inner_big.docx")
	innerDocx(t, big, MaxEmbeddedMediaSize+4096)

	control := outerDocx(t, dir, "outer_small.docx", small)
	oversize := outerDocx(t, dir, "outer_big.docx", big)

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(control, nil)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	CleanupEmbeddedMedia(media)
	if len(media) != 1 {
		t.Errorf("control extracted %d parts, want 1 — the pair is only comparable if the "+
			"under-cap part really is extracted", len(media))
	}
	if len(notExamined) != 0 {
		t.Errorf("control produced notes %v; an ordinary embedded part must stay silent, or "+
			"every document with an attachment warns and the warnings stop meaning anything",
			notExamined)
	}

	media, notExamined, err = ExtractEmbeddedMediaForProcessing(oversize, nil)
	if err != nil {
		t.Fatalf("oversize: %v", err)
	}
	CleanupEmbeddedMedia(media)
	if len(media) != 0 {
		t.Errorf("the over-cap part was extracted after all (%d parts); the cap is what this "+
			"test depends on", len(media))
	}
	if len(notExamined) != 1 {
		t.Fatalf("oversize produced %d notes, want 1: %v. A part refused for size and reported "+
			"nowhere is a container declared clean while sensitive content sits unread inside it",
			len(notExamined), notExamined)
	}

	note := notExamined[0]
	if !strings.Contains(note, "attachment.docx") {
		t.Errorf("note %q does not name the part; an operator cannot act on 'something was skipped'", note)
	}
	if !strings.Contains(note, "not examined") {
		t.Errorf("note %q does not say the part was not examined", note)
	}
	if !strings.Contains(note, "cap") {
		t.Errorf("note %q does not give the reason, so the remedy is unguessable", note)
	}

	// Payload-free and path-free: this string reaches stderr and every machine format.
	if strings.Contains(note, "452-11-9384") {
		t.Errorf("note %q leaked content from the part it is reporting", note)
	}
	if strings.Contains(note, dir) || strings.Contains(note, "word/embeddings") {
		t.Errorf("note %q carries a path; the base name is deliberately all it names (#367)", note)
	}
}

// TestUnreadableEmbeddedPartIsAlsoReported covers the other errors the same call site
// discards. The size refusals are the measured case, but a part whose bytes cannot be read is
// equally unexamined, and a fix that only special-cased the cap would leave the rest silent.
func TestUnreadableEmbeddedPartIsAlsoReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt_part.docx")

	// A zip whose embedded entry declares DEFLATE but stores bytes that are not a valid
	// deflate stream: the entry opens, and the read fails part way.
	f, err := os.Create(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("[Content_Types].xml")
	if err != nil {
		t.Fatalf("create content types: %v", err)
	}
	if _, err = io.WriteString(w, contentTypes); err != nil {
		t.Fatalf("write content types: %v", err)
	}
	w, err = zw.CreateHeader(&zip.FileHeader{Name: "word/media/broken.jpg", Method: zip.Deflate})
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	if _, err = io.WriteString(w, "not a deflate stream at all"); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err = zw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	// Corrupt the stored bytes so inflating them fails. The header still says Deflate, so
	// the entry opens and the failure happens during the read — the shape a truncated
	// download or a tampered container has.
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if i := strings.Index(string(raw), "word/media/broken.jpg"); i > 0 {
		for j := i + len("word/media/broken.jpg"); j < i+len("word/media/broken.jpg")+8 && j < len(raw); j++ {
			raw[j] = 0xFF
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(path, nil)
	CleanupEmbeddedMedia(media)
	if err != nil {
		// The whole archive failed to open, which is a different disclosure path (the file
		// is reported as unparseable). Nothing to assert here.
		t.Skipf("the archive itself became unreadable, so this case is covered elsewhere: %v", err)
	}
	if len(media) == 0 && len(notExamined) == 0 {
		t.Error("a part that could not be extracted produced neither media nor a note — that is " +
			"the silent skip this change exists to remove")
	}
}

// A container with more refused parts than the note cap must still say HOW MANY.
//
// The part count is attacker-controlled: measured on a 6 MB .docx holding 120 entries that
// each deflate from 50 MB of zeros, the unbounded form produced a single 16.8 KB stderr line.
// Truncating that silently would be the same class of defect as the silent skip this
// disclosure exists to fix, so the note that replaces the dropped names carries their count.
func TestMoreRefusalsThanTheNoteCapAreCountedNotDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many_parts.docx")

	f, err := os.Create(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("[Content_Types].xml")
	if err != nil {
		t.Fatalf("create content types: %v", err)
	}
	if _, err = io.WriteString(w, contentTypes); err != nil {
		t.Fatalf("write content types: %v", err)
	}

	// One more part than the cap, each declaring more than the embedded limit. Deflated
	// zeros, so the fixture stays small on disk while every entry is genuinely over-cap.
	const parts = maxEmbeddedNotes + 3
	for i := 0; i < parts; i++ {
		pw, cerr := zw.CreateHeader(&zip.FileHeader{
			Name:   filepath.ToSlash(filepath.Join("word", "media", "pad"+string(rune('a'+i))+".bin")),
			Method: zip.Deflate,
		})
		if cerr != nil {
			t.Fatalf("create pad %d: %v", i, cerr)
		}
		if _, cerr = io.CopyN(pw, zeros{}, MaxEmbeddedMediaSize+4096); cerr != nil {
			t.Fatalf("write pad %d: %v", i, cerr)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(path, nil)
	CleanupEmbeddedMedia(media)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(media) != 0 {
		t.Fatalf("%d parts extracted; every one of them is over the cap, so the fixture is wrong",
			len(media))
	}

	// Bounded: named refusals plus exactly one summary.
	if len(notExamined) != maxEmbeddedNotes+1 {
		t.Fatalf("notes = %d, want %d named refusals plus one summary:\n%v",
			len(notExamined), maxEmbeddedNotes+1, notExamined)
	}
	summary := notExamined[len(notExamined)-1]
	if !strings.Contains(summary, "3 more embedded part(s) were not examined") {
		t.Errorf("summary = %q, want it to count the %d refusals whose names were dropped; a cap "+
			"that truncates silently reproduces the silence it was added to remove",
			summary, parts-maxEmbeddedNotes)
	}
}
