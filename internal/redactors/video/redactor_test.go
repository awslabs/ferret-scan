// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package video

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Fixtures are hand-built rather than produced by ffmpeg, which is not on every CI runner, but
// each LAYOUT below was taken from a real file: the udta>meta>ilst form from an ffmpeg .mp4, the
// ©xyz-with-text-prefix form from an ffmpeg .mov, and the moov>meta keys/ilst form from an iPhone
// recording. The end-to-end behaviour was also measured on those real files — five containers,
// values gone, ffmpeg decoding the output with no errors and the same frame count — which is a
// check a unit test cannot make.

const (
	testSSN  = "452-11-9384"
	testName = "Marcus Whitfield"
)

func atom(kind string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(8+len(body)))
	out = append(out, kind...)
	return append(out, body...)
}

// itunesTag builds the udta>meta>ilst>NAME>data shape ffmpeg writes into .mp4 and .m4v.
func itunesTag(name, value string) []byte {
	return atom(name, atom("data", []byte{0, 0, 0, 1}, []byte{0, 0, 0, 0}, []byte(value)))
}

func mp4With(t *testing.T, dir, filename string, udtaChildren ...[]byte) string {
	t.Helper()
	file := append(atom("ftyp", []byte("isomiso2mp41")),
		atom("moov", atom("mvhd", make([]byte, 100)), atom("udta", udtaChildren...))...)
	file = append(file, atom("mdat", bytes.Repeat([]byte{0xCD}, 512))...)

	p := filepath.Join(dir, filename)
	if err := os.WriteFile(p, file, 0o600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
	return p
}

func match(kind, text string) detector.Match {
	return detector.Match{Type: kind, Text: text, Confidence: 90}
}

func redact(t *testing.T, src string, matches []detector.Match) (string, *redactors.RedactionResult, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "redacted"+filepath.Ext(src))
	r := NewVideoRedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matches, redactors.RedactionFormatPreserving)
	return out, res, err
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

// TestRedactRemovesTagValuesAndLeavesTheMediaAlone is the case #358 is about: a video whose
// findings were reported and could not be removed, because no redactor handled the type.
func TestRedactRemovesTagValuesAndLeavesTheMediaAlone(t *testing.T) {
	dir := t.TempDir()
	src := mp4With(t, dir, "clip.mp4",
		atom("meta", []byte{0, 0, 0, 0}, atom("ilst",
			itunesTag("\xa9cmt", "Employee SSN "+testSSN),
			itunesTag("\xa9ART", testName))))

	out, res, err := redact(t, src, []detector.Match{match("SSN", testSSN), match("PERSON_NAME", testName)})
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if !res.Success || res.RedactedFilePath != out {
		t.Fatalf("result = %+v, want success at %s", res, out)
	}

	before, after := mustRead(t, src), mustRead(t, out)
	if len(before) != len(after) {
		t.Fatalf("size changed from %d to %d; a length change means every enclosing atom size and "+
			"every sample offset is now wrong", len(before), len(after))
	}
	for _, v := range []string{testSSN, testName} {
		if bytes.Contains(after, []byte(v)) {
			t.Errorf("a reported value is still in the redacted file; the file was reported clean")
		}
	}

	// The media payload is what makes this a video rather than a tag blob. It must be untouched
	// byte for byte: a redaction that alters it produces a file a player refuses while the audit
	// trail says the job succeeded.
	media := bytes.Repeat([]byte{0xCD}, 512)
	if !bytes.Contains(after, media) {
		t.Error("the media payload was modified")
	}
	if len(res.RedactionMap) != 2 {
		t.Errorf("RedactionMap has %d entries, want 2 (one per value actually written over)", len(res.RedactionMap))
	}
}

// TestBinaryCoordinateIsZeroedNotMasked pins the fill byte, which is not a style choice.
//
// A QuickTime ©xyz payload is fixed-point, and '*' is a perfectly valid fixed-point number:
// 0x2A2A2A2A decodes to 10794.66°. Masking a position therefore replaces it with another
// position, which the extractor still reports. Zero is the one fill the extractor drops.
func TestBinaryCoordinateIsZeroedNotMasked(t *testing.T) {
	fixed := func(v float64) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(int32(v*65536)))
		return b
	}
	dir := t.TempDir()
	src := mp4With(t, dir, "gps.mp4", atom("\xa9xyz", fixed(37.7749), fixed(-122.4194), fixed(0)))

	// The reported text is the extractor's RENDERING of those bytes and appears nowhere in the
	// file, which is exactly why a text-only redactor cannot remove it.
	out, res, err := redact(t, src, []detector.Match{match("GPS", "37.774902, -122.419403")})
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if !res.Success {
		t.Fatalf("result = %+v", res)
	}

	after := mustRead(t, out)
	at := bytes.Index(after, []byte("\xa9xyz")) + 4
	payload := after[at : at+12]
	for i, b := range payload {
		if b != 0 {
			t.Fatalf("coordinate byte %d is %#x, want 0; anything else still decodes to a position "+
				"(a '*' fill reads as 10794.66°)", i, b)
		}
	}
	if len(res.RedactionMap) != 1 {
		t.Fatalf("RedactionMap = %+v, want the position recorded", res.RedactionMap)
	}
	if got := res.RedactionMap[0].Metadata["position_method"]; got != "video_coordinate_atom_scrubbed" {
		t.Errorf("position_method = %v, want the coordinate method; the audit trail must not imply "+
			"a text replacement that never happened", got)
	}
}

// TestTextCoordinateScrubIncludesThePrefixWords is the trap a real ffmpeg .mov revealed.
//
// ffmpeg writes ©xyz as a 2-byte text length, a 2-byte language code, then the ISO 6709 string.
// This tool's extractor reads that payload as fixed-point and reported "18.335022, 11059.211639"
// for it — the length and language bytes ARE the latitude. Scrubbing only the string leaves that
// first coordinate intact, so the redacted file still reports a position.
func TestTextCoordinateScrubIncludesThePrefixWords(t *testing.T) {
	payload := append([]byte{0x00, 0x12, 0x55, 0xc4}, []byte("+36.3506-082.6985/")...)
	dir := t.TempDir()
	src := mp4With(t, dir, "ff.mov", atom("\xa9xyz", payload))

	out, _, err := redact(t, src, []detector.Match{match("GPS", "18.335022, 11059.211639")})
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	after := mustRead(t, out)
	at := bytes.Index(after, []byte("\xa9xyz")) + 4
	for i, b := range after[at : at+len(payload)] {
		if b != 0 {
			t.Fatalf("byte %d of the ©xyz payload survived (%#x). The 4-byte text length and "+
				"language prefix must be zeroed too: the extractor reads them as a latitude", i, b)
		}
	}
	if bytes.Contains(after, []byte("+36.3506")) {
		t.Error("the ISO 6709 position string is still in the file")
	}
}

// TestPositionInAKeysIlstItemIsScrubbed covers the layout a real iPhone writes, where the atom
// holding the coordinate is named "\x00\x00\x00\x01" and nothing but a keys table says what it
// is. This one is in moov>meta, so it also covers the span finder reaching outside udta.
func TestPositionInAKeysIlstItemIsScrubbed(t *testing.T) {
	const pos = "+36.3506-082.6985+447.403/"
	item := atom("\x00\x00\x00\x01", atom("data", []byte{0, 0, 0, 1}, []byte("US\x15\xc7"), []byte(pos)))
	meta := atom("meta", []byte{0, 0, 0, 0},
		atom("hdlr", []byte("\x00\x00\x00\x00\x00\x00\x00\x00mdta")),
		atom("keys", []byte{0, 0, 0, 0}, []byte{0, 0, 0, 1},
			atom("mdta", []byte("com.apple.quicktime.location.ISO6709"))),
		atom("ilst", item))

	dir := t.TempDir()
	file := append(atom("ftyp", []byte("qt  ")), atom("moov", atom("mvhd", make([]byte, 100)), meta)...)
	src := filepath.Join(dir, "device.mov")
	if err := os.WriteFile(src, file, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, err := redact(t, src, []detector.Match{match("GPS", "36.350600, -82.698500, 447.40")})
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	after := mustRead(t, out)
	if bytes.Contains(after, []byte(pos)) {
		t.Error("the position survived; a udta-only walk would miss this layout entirely")
	}
	if !bytes.Contains(after, []byte("com.apple.quicktime.location.ISO6709")) {
		t.Error("the keys table was overwritten; only the VALUE is redacted, so the container " +
			"structure and its key names must survive")
	}
	if len(after) != len(file) {
		t.Errorf("size changed from %d to %d", len(file), len(after))
	}
}

// TestSecondPositionCopyInLociIsAlsoScrubbed is a leak a corpus of real and permuted files
// caught, and a hand-written test would not have thought to look for.
//
// ffmpeg writes a location into loci for .mp4 and into ©xyz for .mov, so a file can carry the
// same position twice in two different atoms. Zeroing only ©xyz left the loci copy decoding to
// 37.7749,-122.4194 in a file the run reported as successfully redacted. Removing one copy of a
// value and reporting success is the same defect as not removing it at all.
func TestSecondPositionCopyInLociIsAlsoScrubbed(t *testing.T) {
	fixed := func(v float64) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(int32(v*65536)))
		return b
	}
	// The loci layout ffmpeg writes: version+flags, language, an empty name, a role byte, then
	// longitude, latitude and altitude as 16.16 fixed-point, then "earth".
	loci := atom("loci", []byte{0, 0, 0, 0}, []byte{0x15, 0xc7}, []byte{0}, []byte{0},
		fixed(-122.4194), fixed(37.7749), fixed(0), []byte("earth\x00"))

	dir := t.TempDir()
	src := mp4With(t, dir, "both.mp4",
		atom("\xa9xyz", fixed(37.7749), fixed(-122.4194), fixed(0)), loci)

	out, _, err := redact(t, src, []detector.Match{match("GPS", "37.774902, -122.419403")})
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	after := mustRead(t, out)
	at := bytes.Index(after, []byte("loci")) + 4
	for i, b := range after[at : at+22] {
		if b != 0 {
			t.Fatalf("byte %d of the loci payload survived (%#x); the position is stored twice in "+
				"this file and both copies have to go", i, b)
		}
	}
}

// TestUnlocatableValueIsRefused is the fail-closed rule. A value the redactor cannot find is a
// value it cannot remove, and writing the file anyway is what produces a "redacted" copy that
// still holds a reported secret while the audit trail shows no failures.
//
// Refusing costs the caller nothing that they had before: with no video redactor at all, the
// outcome for this file was already no output plus the "values remain in cleartext" disclosure.
func TestUnlocatableValueIsRefused(t *testing.T) {
	dir := t.TempDir()
	src := mp4With(t, dir, "clip.mp4", atom("meta", []byte{0, 0, 0, 0},
		atom("ilst", itunesTag("\xa9cmt", "nothing sensitive here"))))

	out, res, err := redact(t, src, []detector.Match{match("SSN", testSSN)})
	if err == nil {
		t.Fatalf("expected a refusal for a value that is not in the file; got %+v", res)
	}
	if !strings.Contains(err.Error(), "could not be located") {
		t.Errorf("error should say the value could not be located, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a file was written at the output path despite the refusal; the caller treats that " +
			"path as sanitized")
	}
	if strings.Contains(err.Error(), testSSN) {
		t.Error("the diagnostic echoes the matched value; only the TYPE may be named")
	}
}

// TestNoMetadataRegionIsRefused covers a container with nowhere to write. Returning success here
// would copy the file through unchanged and report it as redacted.
func TestNoMetadataRegionIsRefused(t *testing.T) {
	dir := t.TempDir()
	file := append(atom("ftyp", []byte("isomiso2mp41")), atom("moov", atom("mvhd", make([]byte, 100)))...)
	file = append(file, atom("uuid", append(bytes.Repeat([]byte{0x11}, 16),
		[]byte("<x:xmpmeta>SSN "+testSSN+"</x:xmpmeta>")...))...)
	src := filepath.Join(dir, "xmp.mp4")
	if err := os.WriteFile(src, file, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, err := redact(t, src, []detector.Match{match("SSN", testSSN)})
	if err == nil {
		t.Fatal("expected a refusal for a file whose values live in a uuid/XMP atom, which this " +
			"redactor does not claim to handle")
	}
	if !strings.Contains(err.Error(), "no video metadata region") {
		t.Errorf("error should name the missing metadata region, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a file was written despite the refusal")
	}
}

// TestNotAContainerIsRefused pins that the decision is made on the BYTES. The extension is the
// caller's claim; a text file named .mp4 has no atoms to walk.
func TestNotAContainerIsRefused(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "notes.mp4")
	if err := os.WriteFile(src, []byte("employee ssn "+testSSN+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, _, err := redact(t, src, []detector.Match{match("SSN", testSSN)}); err == nil {
		t.Fatal("expected a refusal for a file that is not an ISO base media container")
	} else if !strings.Contains(err.Error(), "not a recognised video container") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestOversizeMetadataIsRefusedNotTruncated covers the attacker-controlled declaration. #374 is
// an open issue about exactly the opposite behaviour — skipping the oversize part and reporting
// the container clean.
func TestOversizeMetadataIsRefusedNotTruncated(t *testing.T) {
	dir := t.TempDir()
	// A udta whose payload really is larger than the cap, so the bound is exercised against a
	// span that exists rather than one that was merely declared.
	big := make([]byte, maxTagBytes+1024)
	copy(big, "\xa9cmtSSN "+testSSN)
	src := mp4With(t, dir, "big.mp4", big)

	_, _, err := redact(t, src, []detector.Match{match("SSN", testSSN)})
	if err == nil {
		t.Fatal("expected a refusal for metadata above the cap")
	}
	if !strings.Contains(err.Error(), "refusing rather than redacting part of it") {
		t.Errorf("error should say the file was refused rather than partly handled, got: %v", err)
	}
}

// TestSyntheticStrategyIsNotAdvertised keeps the strategy list honest. Synthetic generates a
// value whose length is unrelated to the original, and this redactor cannot change a length.
func TestSyntheticStrategyIsNotAdvertised(t *testing.T) {
	for _, s := range NewVideoRedactor(nil, nil).GetSupportedStrategies() {
		if s == redactors.RedactionSynthetic {
			t.Error("synthetic is advertised; it cannot preserve length, so claiming it would " +
				"promise an output this redactor cannot produce")
		}
	}
}

// TestSupportedTypesCoverTheScannedExtensions ties the two halves together. A type the scanner
// reads and this does not claim is a reported finding that cannot be removed — the whole defect.
func TestSupportedTypesCoverTheScannedExtensions(t *testing.T) {
	claimed := map[string]bool{}
	for _, tp := range NewVideoRedactor(nil, nil).GetSupportedTypes() {
		claimed[tp] = true
	}
	// The scanner's video set is exactly these three (preprocessors.FileExtensionValidator).
	for _, ext := range []string{".mp4", ".m4v", ".mov"} {
		if !claimed[ext] || !claimed[strings.TrimPrefix(ext, ".")] {
			t.Errorf("%s is scanned but not claimed in both spellings; the manager is called with "+
				"each form in different code paths", ext)
		}
	}
}

// TestMemoryDoesNotScaleWithFileSize is the streaming claim, measured rather than asserted in a
// comment.
//
// The audio redactor reads the whole file and holds a modified copy, which for a 4 GB recording
// is ~8 GB of RAM. This one walks atom headers and reads only the tag payloads, so allocation
// must stay flat as the media grows. Allocation is the right instrument HERE because the cost
// being guarded against is a buffer — unlike a CPU-only quadratic, which allocates nothing and
// needs a counter instead.
func TestMemoryDoesNotScaleWithFileSize(t *testing.T) {
	dir := t.TempDir()
	tag := atom("meta", []byte{0, 0, 0, 0}, atom("ilst", itunesTag("\xa9cmt", "SSN "+testSSN)))

	measure := func(mediaBytes int) uint64 {
		file := append(atom("ftyp", []byte("isomiso2mp41")),
			atom("moov", atom("mvhd", make([]byte, 100)), atom("udta", tag))...)
		file = append(file, atom("mdat", bytes.Repeat([]byte{0xCD}, mediaBytes))...)
		src := filepath.Join(dir, "clip.mp4")
		if err := os.WriteFile(src, file, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if _, _, err := redact(t, src, []detector.Match{match("SSN", testSSN)}); err != nil {
			t.Fatalf("RedactDocument at %d bytes: %v", mediaBytes, err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	small := measure(64 << 10)
	large := measure(8 << 20) // 128x the media
	if large > small+(1<<20) {
		t.Errorf("allocation grew from %d to %d bytes when the media grew 128x; the whole point of "+
			"walking the file is that a movie's size is not a memory cost", small, large)
	}
}
