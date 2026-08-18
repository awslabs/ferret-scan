// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audio

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Fixtures are hand-built rather than produced by ffmpeg, which is not present on every CI
// runner, and rather than committed binaries, because the tag CONTENTS are the variable under
// test. Each builder writes the minimum structure the corresponding range finder walks.

const (
	testSSN   = "452-11-9384"
	testPhone = "415-555-0142"
)

// buildWAV writes a RIFF/WAVE file whose LIST/INFO chunk holds the given field values.
func buildWAV(t *testing.T, dir string, fields map[string]string) string {
	t.Helper()

	chunk := func(id string, payload []byte) []byte {
		out := append([]byte(id), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(out[4:], uint32(len(payload)))
		out = append(out, payload...)
		if len(payload)%2 == 1 {
			out = append(out, 0x00) // RIFF pad byte
		}
		return out
	}

	fmtPayload := make([]byte, 16)
	binary.LittleEndian.PutUint16(fmtPayload[0:], 1)
	binary.LittleEndian.PutUint16(fmtPayload[2:], 1)
	binary.LittleEndian.PutUint32(fmtPayload[4:], 8000)
	binary.LittleEndian.PutUint32(fmtPayload[8:], 8000)
	binary.LittleEndian.PutUint16(fmtPayload[12:], 1)
	binary.LittleEndian.PutUint16(fmtPayload[14:], 8)

	info := []byte("INFO")
	// Sorted for determinism: map iteration order would otherwise vary the byte layout and
	// with it the offsets this test asserts on.
	for _, id := range sortedKeys(fields) {
		v := append([]byte(fields[id]), 0x00)
		e := append([]byte(id), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(e[4:], uint32(len(v)))
		e = append(e, v...)
		if len(v)%2 == 1 {
			e = append(e, 0x00)
		}
		info = append(info, e...)
	}

	body := chunk("fmt ", fmtPayload)
	body = append(body, chunk("LIST", info)...)
	body = append(body, chunk("data", []byte{0x01, 0x02, 0x03, 0x04})...)

	payload := append([]byte("WAVE"), body...)
	riff := append([]byte("RIFF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(riff[4:], uint32(len(payload)))
	riff = append(riff, payload...)

	return writeFixture(t, dir, "tagged.wav", riff)
}

// buildMP3 writes an ID3v2.3 tag followed by a token MPEG frame sync.
func buildMP3(t *testing.T, dir string, frames map[string]string) string {
	t.Helper()

	var body bytes.Buffer
	for _, id := range sortedKeys(frames) {
		// Text frame: encoding byte 0x00 (ISO-8859-1) then the value.
		payload := append([]byte{0x00}, []byte(frames[id])...)
		body.WriteString(id)
		size := make([]byte, 4)
		binary.BigEndian.PutUint32(size, uint32(len(payload))) // ID3v2.3 frame sizes are plain
		body.Write(size)
		body.Write([]byte{0x00, 0x00}) // flags
		body.Write(payload)
	}

	tag := []byte("ID3")
	tag = append(tag, 0x03, 0x00) // v2.3
	tag = append(tag, 0x00)       // flags
	// Tag size is SYNCHSAFE: 7 bits per byte.
	n := body.Len()
	tag = append(tag,
		byte((n>>21)&0x7F), byte((n>>14)&0x7F), byte((n>>7)&0x7F), byte(n&0x7F))
	tag = append(tag, body.Bytes()...)
	tag = append(tag, 0xFF, 0xFB, 0x90, 0x00) // a plausible MPEG frame header

	return writeFixture(t, dir, "tagged.mp3", tag)
}

// buildFLAC writes a fLaC stream whose VORBIS_COMMENT block holds the given comments.
func buildFLAC(t *testing.T, dir string, comments []string) string {
	t.Helper()

	var vc bytes.Buffer
	vendor := "ferret-test"
	le := make([]byte, 4)
	binary.LittleEndian.PutUint32(le, uint32(len(vendor)))
	vc.Write(le)
	vc.WriteString(vendor)
	binary.LittleEndian.PutUint32(le, uint32(len(comments)))
	vc.Write(le)
	for _, c := range comments {
		binary.LittleEndian.PutUint32(le, uint32(len(c)))
		vc.Write(le)
		vc.WriteString(c)
	}

	out := []byte("fLaC")

	// STREAMINFO (type 0), not last. Content is irrelevant to this redactor, but the block
	// must be present and correctly sized or the walk cannot reach the comments.
	streamInfo := make([]byte, 34)
	out = append(out, 0x00, byte(len(streamInfo)>>16), byte(len(streamInfo)>>8), byte(len(streamInfo)))
	out = append(out, streamInfo...)

	// VORBIS_COMMENT (type 4), last.
	body := vc.Bytes()
	out = append(out, 0x80|0x04, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	out = append(out, body...)

	return writeFixture(t, dir, "tagged.flac", out)
}

// buildM4A writes ftyp + moov>udta>meta>ilst with one ©nam value.
func buildM4A(t *testing.T, dir string, value string) string {
	t.Helper()

	atom := func(name string, payload []byte) []byte {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(8+len(payload)))
		out = append(out, []byte(name)...)
		return append(out, payload...)
	}

	// data atom: type/locale header then the UTF-8 value.
	data := append([]byte{0, 0, 0, 1, 0, 0, 0, 0}, []byte(value)...)
	nam := atom("\xa9nam", atom("data", data))
	ilst := atom("ilst", nam)
	meta := atom("meta", append([]byte{0, 0, 0, 0}, ilst...))
	udta := atom("udta", meta)
	moov := atom("moov", udta)
	ftyp := atom("ftyp", []byte("M4A isom"))

	return writeFixture(t, dir, "tagged.m4a", append(ftyp, moov...))
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Small maps; insertion sort keeps the helper dependency-free.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func writeFixture(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func match(text, typ string) detector.Match {
	return detector.Match{Text: text, Type: typ, Confidence: 100}
}

// redact runs the redactor and returns the output bytes.
func redact(t *testing.T, src string, matches []detector.Match) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "redacted"+filepath.Ext(src))
	res, err := NewAudioRedactor(nil, nil).RedactDocument(src, out, matches, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument(%s): %v", filepath.Base(src), err)
	}
	if !res.Success {
		t.Fatalf("RedactDocument reported failure for %s", filepath.Base(src))
	}
	b, err := os.ReadFile(out) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every supported container must have its reported values removed, at an unchanged file size.
//
// Size is asserted because same-length overwrite is the entire reason these files stay
// playable: every enclosing length (RIFF chunk, ID3 synchsafe size, FLAC 24-bit block, MP4
// atom) keeps its original value only if nothing moved.
func TestReportedValuesRemovedFromEveryFormat(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		src     string
		matches []detector.Match
	}{
		{
			name:    "wav RIFF LIST/INFO",
			src:     buildWAV(t, dir, map[string]string{"IART": "Contact " + testSSN, "ICMT": "Call " + testPhone}),
			matches: []detector.Match{match(testSSN, "SSN"), match(testPhone, "PHONE")},
		},
		{
			name:    "mp3 ID3v2 frames",
			src:     buildMP3(t, dir, map[string]string{"TPE1": "Contact " + testSSN, "COMM": "Call " + testPhone}),
			matches: []detector.Match{match(testSSN, "SSN"), match(testPhone, "PHONE")},
		},
		{
			name:    "flac VORBIS_COMMENT",
			src:     buildFLAC(t, dir, []string{"ARTIST=Contact " + testSSN, "COMMENT=Call " + testPhone}),
			matches: []detector.Match{match(testSSN, "SSN"), match(testPhone, "PHONE")},
		},
		{
			name:    "m4a udta/ilst",
			src:     buildM4A(t, dir, "Recording ref "+testSSN),
			matches: []detector.Match{match(testSSN, "SSN")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, err := os.ReadFile(tc.src) // #nosec G304 -- test temp dir
			if err != nil {
				t.Fatal(err)
			}
			// The fixture must actually contain the values, or the assertion below is vacuous.
			for _, m := range tc.matches {
				if !bytes.Contains(before, []byte(m.Text)) {
					t.Fatalf("fixture does not contain %s, so removing it proves nothing", m.Type)
				}
			}

			after := redact(t, tc.src, tc.matches)

			for _, m := range tc.matches {
				if bytes.Contains(after, []byte(m.Text)) {
					t.Errorf("%s survived redaction — a reported value that cannot be removed is the "+
						"same leak as an undetected one", m.Type)
				}
			}
			if len(after) != len(before) {
				t.Errorf("file size changed %d -> %d; same-length overwrite is what keeps every "+
					"enclosing size field valid", len(before), len(after))
			}
			// The audio payload must be untouched. Only tag regions may differ.
			if idx := bytes.Index(before, []byte{0x01, 0x02, 0x03, 0x04}); idx >= 0 {
				if !bytes.Contains(after, []byte{0x01, 0x02, 0x03, 0x04}) {
					t.Error("the audio data chunk was modified; redaction must be confined to tag regions")
				}
			}
		})
	}
}

// OVERLAPPING reported values must both be removed.
//
// This is the defect the first implementation shipped with. The scan reports an AUTHOR_INFO
// field value that CONTAINS the separately reported SSN:
//
//	SSN          "452-11-9384"
//	AUTHOR_INFO  "Contact Jane Doe SSN 452-11-9384"
//
// Replacing them one at a time against the buffer being written loses the second: masking the
// SSN destroys the tail of the AUTHOR_INFO string, the search for it then finds nothing, and
// the part reported ONLY as AUTHOR_INFO — the name — stays in the file. Measured on real
// ffmpeg-written files across all four formats: SSN, phone and email removed, "Jane Doe" left
// in cleartext, exit 0, and a residue check that searched for each reported value agreed,
// because the AUTHOR_INFO string was genuinely gone.
func TestOverlappingReportedValuesAreBothRemoved(t *testing.T) {
	dir := t.TempDir()
	const author = "Contact Jane Doe SSN " + testSSN

	src := buildWAV(t, dir, map[string]string{"IART": author})
	after := redact(t, src, []detector.Match{
		// SSN first, deliberately: this is the order that broke it.
		match(testSSN, "SSN"),
		match(author, "AUTHOR_INFO"),
	})

	if bytes.Contains(after, []byte(testSSN)) {
		t.Error("the SSN survived")
	}
	if bytes.Contains(after, []byte("Jane Doe")) {
		t.Error("\"Jane Doe\" survived. It is reported only as part of the longer AUTHOR_INFO value, " +
			"so redacting the SSN first must not prevent the enclosing value from being removed.")
	}
	if bytes.Contains(after, []byte(author)) {
		t.Error("the whole AUTHOR_INFO value survived")
	}
}

// A file with no locatable tag region must be REFUSED, not reported as redacted.
//
// Writing a byte-identical copy and returning Success is the exact shape of #306: the caller
// receives a path its own documentation calls safe to share.
func TestFileWithNoMetadataRegionIsRefused(t *testing.T) {
	dir := t.TempDir()

	// A RIFF/WAVE file with fmt and data but no LIST chunk.
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	body := []byte("WAVE")
	fmtc := append([]byte("fmt "), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(fmtc[4:], 16)
	fmtc = append(fmtc, make([]byte, 16)...)
	datac := append([]byte("data"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(datac[4:], 4)
	datac = append(datac, 1, 2, 3, 4)
	body = append(body, fmtc...)
	body = append(body, datac...)
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(body)))
	buf.Write(size)
	buf.Write(body)

	src := writeFixture(t, dir, "notags.wav", buf.Bytes())
	out := filepath.Join(dir, "out.wav")

	_, err := NewAudioRedactor(nil, nil).RedactDocument(src, out, []detector.Match{match(testSSN, "SSN")},
		redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("a file with no tag region was accepted; it must be refused so the run cannot " +
			"report success over an unredacted copy")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("an output file was written for a refused redaction")
	}
}

// Synthetic cannot preserve length, so it must not be advertised.
func TestSyntheticStrategyIsDeclined(t *testing.T) {
	for _, s := range NewAudioRedactor(nil, nil).GetSupportedStrategies() {
		if s == redactors.RedactionSynthetic {
			t.Error("Synthetic is advertised, but it generates a value whose length is unrelated " +
				"to the original and this redactor cannot change a length")
		}
	}
}

// The manager resolves redactors by extension in both spellings.
func TestSupportedTypesCoverEveryScannedAudioFormat(t *testing.T) {
	got := map[string]bool{}
	for _, s := range NewAudioRedactor(nil, nil).GetSupportedTypes() {
		got[s] = true
	}
	// The read side scans exactly these four (audio_metadata_preprocessor.go).
	for _, ext := range []string{"mp3", "wav", "m4a", "flac"} {
		if !got[ext] || !got["."+ext] {
			t.Errorf("%q is scanned but not claimed in both spellings; the manager looks it up "+
				"both ways depending on the call path", ext)
		}
	}
}

// UTF-16 tag text must be found too. An ID3v2 frame may declare UTF-16, and a value invisible
// to a UTF-8 search is a value left in cleartext.
func TestUTF16TagTextIsRedacted(t *testing.T) {
	dir := t.TempDir()

	// ID3v2.3 frame with encoding byte 0x01 (UTF-16 with BOM).
	wide := append([]byte{0xFF, 0xFE}, toUTF16LE("Call "+testPhone)...)
	payload := append([]byte{0x01}, wide...)
	var body bytes.Buffer
	body.WriteString("COMM")
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(payload)))
	body.Write(size)
	body.Write([]byte{0x00, 0x00})
	body.Write(payload)

	tag := append([]byte("ID3"), 0x03, 0x00, 0x00)
	n := body.Len()
	tag = append(tag, byte((n>>21)&0x7F), byte((n>>14)&0x7F), byte((n>>7)&0x7F), byte(n&0x7F))
	tag = append(tag, body.Bytes()...)
	tag = append(tag, 0xFF, 0xFB, 0x90, 0x00)

	src := writeFixture(t, dir, "utf16.mp3", tag)
	if !bytes.Contains(tag, toUTF16LE(testPhone)) {
		t.Fatal("fixture does not hold the value UTF-16 encoded, so this proves nothing")
	}

	after := redact(t, src, []detector.Match{match(testPhone, "PHONE")})

	if bytes.Contains(after, toUTF16LE(testPhone)) {
		t.Error("the UTF-16 encoded phone number survived; a UTF-8-only search leaves wide tag " +
			"text in cleartext")
	}
	if strings.Contains(string(after), testPhone) {
		t.Error("the phone number is present as UTF-8 in the output")
	}
}

// A tag larger than 127 bytes distinguishes a SYNCHSAFE size from a plain big-endian one.
//
// Below 128 the two decodings agree — every high bit is already clear and only the last byte
// carries value — so a small fixture cannot tell a correct reader from the classic ID3 bug.
// At 200 bytes, reading the size as plain big-endian yields a different (larger) end offset,
// and the tag region is wrong.
func TestID3TagLargerThanSynchsafeBoundary(t *testing.T) {
	dir := t.TempDir()

	// A comment long enough to push the tag size past 127, with the value at the END so a
	// truncated or misplaced region misses it.
	filler := strings.Repeat("recording notes ", 12)
	comment := filler + "Call " + testPhone
	src := buildMP3(t, dir, map[string]string{"COMM": comment})

	raw, err := os.ReadFile(src) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if size := synchsafe(raw[6:10]); size < 128 {
		t.Fatalf("fixture tag is %d bytes; it must exceed 127 or synchsafe and plain big-endian "+
			"decode identically and this test proves nothing", size)
	}

	after := redact(t, src, []detector.Match{match(testPhone, "PHONE")})
	if bytes.Contains(after, []byte(testPhone)) {
		t.Error("the phone number survived in a tag larger than the synchsafe boundary — the tag " +
			"size is being decoded as a plain big-endian integer, so the computed region is wrong")
	}
}

// Overlapping spans must be masked as ONE span, not left as two format-preserving
// replacements partially overwriting each other.
//
// Without merging, both spans are still written, so nothing leaks — which is why a residue
// assertion cannot see the difference. What it changes is the OUTPUT: applying two
// format-preserving renderings to overlapping ranges leaves a hybrid whose shape belongs to
// neither value, and which differs depending on which span was written last. Pinning the
// masked form keeps the output deterministic and obviously redacted.
func TestOverlappingSpansAreMaskedAsOne(t *testing.T) {
	dir := t.TempDir()
	const author = "Contact Jane Doe SSN " + testSSN

	src := buildWAV(t, dir, map[string]string{"IART": author})
	after := redact(t, src, []detector.Match{
		match(testSSN, "SSN"),
		match(author, "AUTHOR_INFO"),
	})

	// The union of the two reported values is exactly the author string, so the whole field
	// must be a run of mask characters of that length.
	want := strings.Repeat("*", len(author))
	if !bytes.Contains(after, []byte(want)) {
		t.Errorf("overlapping reported values did not collapse to a single %d-character mask.\n"+
			"A format-preserving rendering is only meaningful for one value of one type; where two "+
			"reported spans overlap, the merged span must be masked so the result does not depend "+
			"on write order.", len(author))
	}
}

// residualValues is the fail-closed check, so its contract is pinned directly.
//
// The integration path cannot easily produce a residue — the planner searches the same
// encodings in the same regions, so anything it can find it also overwrites. That makes the
// check hard to exercise end to end and easy to disable without any test noticing, which is
// exactly why it is asserted here as a unit.
func TestResidualValuesDetectsWhatWasMissed(t *testing.T) {
	region := []byte("ARTIST=Contact " + testSSN + "\x00")
	ranges := []byteRange{{0, len(region), "test"}}
	matches := []detector.Match{match(testSSN, "SSN")}

	if got := residualValues(region, ranges, matches); got != 1 {
		t.Errorf("residualValues = %d, want 1: the value is present in the region and must be "+
			"reported as residue", got)
	}

	scrubbed := bytes.ReplaceAll(region, []byte(testSSN), []byte(strings.Repeat("*", len(testSSN))))
	if got := residualValues(scrubbed, ranges, matches); got != 0 {
		t.Errorf("residualValues = %d, want 0 after the value was overwritten", got)
	}

	// UTF-16, both byte orders. A check that only knows one of them passes while the value is
	// still readable in the other.
	for name, enc := range map[string]func(string) []byte{"LE": toUTF16LE, "BE": toUTF16BE} {
		wide := append([]byte("ARTIST="), enc(testSSN)...)
		wr := []byteRange{{0, len(wide), "test"}}
		if got := residualValues(wide, wr, matches); got != 1 {
			t.Errorf("residualValues = %d for a UTF-16%s region, want 1", got, name)
		}
	}
}

// UTF-16BE tag text must be redacted, not just UTF-16LE.
func TestUTF16BETagTextIsRedacted(t *testing.T) {
	dir := t.TempDir()

	// ID3v2.4 encoding byte 0x02: UTF-16BE, no BOM.
	payload := append([]byte{0x02}, toUTF16BE("Call "+testPhone)...)
	var body bytes.Buffer
	body.WriteString("COMM")
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(payload)))
	body.Write(size)
	body.Write([]byte{0x00, 0x00})
	body.Write(payload)

	tag := append([]byte("ID3"), 0x04, 0x00, 0x00)
	n := body.Len()
	tag = append(tag, byte((n>>21)&0x7F), byte((n>>14)&0x7F), byte((n>>7)&0x7F), byte(n&0x7F))
	tag = append(tag, body.Bytes()...)
	tag = append(tag, 0xFF, 0xFB, 0x90, 0x00)

	src := writeFixture(t, dir, "utf16be.mp3", tag)
	if !bytes.Contains(tag, toUTF16BE(testPhone)) {
		t.Fatal("fixture does not hold the value UTF-16BE encoded")
	}

	after := redact(t, src, []detector.Match{match(testPhone, "PHONE")})
	if bytes.Contains(after, toUTF16BE(testPhone)) {
		t.Error("the UTF-16BE encoded phone number survived; ID3v2.4 allows this encoding and a " +
			"little-endian-only search leaves it in cleartext")
	}
}
