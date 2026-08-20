// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"path/filepath"
	"strings"
	"testing"
)

// A LIST chunk's own declared size must not be what bounds the fields inside it.
//
// #350 bounded a field's declared size by the bytes left in its containing LIST, which closed the
// case where a field over-declares. But the LIST's size is a uint32 out of the same file, so one
// attacker declaration was bounding another: declaring LIST = 0xFFFFFFF0 with a child of
// 0xFFFFFFE4 satisfies that check and still reaches make([]byte, ~4GB).
//
// Measured before this: a 56-byte .wav, eight of them inside a 2.2KB .docx, drove 8.03GB of
// resident memory at exit 0 — and `--max-live-bytes 64MB` did not bound it, because that budget
// charges the on-disk size of the file being scanned (2.2KB). Availability only: the coverage loss
// was correctly disclosed and no value leaked, but any host with under ~9GB free is OOM-killed by
// a 2KB attachment on the default scan path (#375).
//
// Asserted by ALLOCATION, not wall clock: the bomb parses in 0.04s, so a timing assertion would
// pass on the broken build and flake on slow CI.
func TestWAVListSizeIsBoundedByTheFileNotItsOwnDeclaration(t *testing.T) {
	dir := t.TempDir()

	// The shape the guard could not see: the LIST claims nearly the whole uint32 range, and its
	// child claims just under that — so `header.Size > totalSize-bytesRead` is satisfied.
	path := buildWAVWithInfo(t, filepath.Join(dir, "listbomb.wav"), []infoFieldSpec{
		{id: "ICMT", value: "", pad: false, declaredSize: 0xFFFFFFE4},
	}, 0, 0xFFFFFFF0)

	meta, allocated := extractMeasuringAlloc(t, path)

	if allocated > maxExtractAlloc {
		t.Errorf("extracting a tiny file allocated %d bytes (> %d): the LIST's own declared size "+
			"is still bounding the fields inside it, so one attacker declaration is bounding "+
			"another. This is the 8.03GB-from-2.2KB path", allocated, maxExtractAlloc)
	}
	if meta.ExtractionWarning == "" {
		t.Error("a LIST declaring more data than the file contains produced no warning: the walk " +
			"was truncated and nothing said so, which is the silence these warnings exist to " +
			"prevent")
	}
}

// The clamp's OWN disclosure is load-bearing, and this is the case that proves it.
//
// When a LIST over-declares AND its fields also over-declare, parseInfoChunks warns too, so a test
// asserting merely "some warning" cannot tell which guard spoke — a mutation removing the clamp's
// disclosure survived exactly that way. Here the LIST over-declares while its single field FITS
// inside the clamped region: the field parses cleanly, parseInfoChunks has nothing to complain
// about, and the truncation is disclosed only if the clamp says so itself.
func TestWAVOverDeclaredListIsDisclosedEvenWhenItsFieldsParseCleanly(t *testing.T) {
	dir := t.TempDir()
	path := buildWAVWithInfo(t, filepath.Join(dir, "overdeclared.wav"), []infoFieldSpec{
		// A perfectly ordinary field: it fits, so the field-level guard stays quiet.
		{id: "IART", value: "Renee Mueller", pad: true},
	}, 0, 0xFFFFFFF0)

	meta, allocated := extractMeasuringAlloc(t, path)

	if allocated > maxExtractAlloc {
		t.Errorf("allocated %d bytes (> %d)", allocated, maxExtractAlloc)
	}
	if meta.ExtractionWarning == "" {
		t.Error("a LIST declaring ~4GB in a tiny file was truncated with NO warning: the field " +
			"inside it parsed cleanly, so the field-level guard had nothing to say and only the " +
			"file clamp could disclose it. A truncation nobody is told about is the failure these " +
			"warnings exist to prevent")
	}
	if !strings.Contains(meta.ExtractionWarning, "than the file contains") {
		t.Errorf("warning = %q, want the LIST-vs-file wording: the operator needs to know the "+
			"CHUNK over-declared against the file, not that some field did", meta.ExtractionWarning)
	}
	// The field must still have been read, or the disclosure is describing a total failure.
	if meta.Artist == "" {
		t.Error("the field inside the over-declared LIST was not read; the clamp should truncate " +
			"to the end of the file, not abandon the chunk")
	}
}

// The clamp must not fire on a well-formed file, or it would trade a DoS for a coverage loss on
// every valid WAV. A real INFO field still parses and still produces no warning.
func TestWAVWellFormedListIsUnaffectedByTheClamp(t *testing.T) {
	dir := t.TempDir()
	path := buildWAVWithInfo(t, filepath.Join(dir, "ok.wav"), []infoFieldSpec{
		{id: "IART", value: "Contact 452-11-9384", pad: true},
		{id: "ICMT", value: "quarterly review", pad: false},
	}, 0, 0)

	meta, allocated := extractMeasuringAlloc(t, path)

	if allocated > maxExtractAlloc {
		t.Errorf("a well-formed file allocated %d bytes (> %d)", allocated, maxExtractAlloc)
	}
	if meta.ExtractionWarning != "" {
		t.Errorf("a well-formed LIST produced a warning (%q): the clamp is firing on valid input, "+
			"which would report lost coverage on every ordinary WAV", meta.ExtractionWarning)
	}
	// And the fields must still be read, or the test above could pass on a build that simply
	// stopped parsing INFO chunks.
	if meta.Artist == "" {
		t.Error("the IART field was not read, so the clamp has broken ordinary extraction — the " +
			"bound assertions above would then be vacuous")
	}
}
