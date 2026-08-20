// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package isobmff

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Fixtures are hand-built rather than committed binaries or ffmpeg output — ffmpeg is not on
// every CI runner — but every LAYOUT here was taken from a real file and is named as such.
// Guessing at these layouts is how a redactor ends up scoped to the one shape its author
// happened to have: the udta/ilst form below is what ffmpeg writes into .mp4, the moov>meta
// keys/ilst form is what an iPhone writes into .mov, and the ©xyz-with-text-prefix form is what
// ffmpeg writes into .mov.

func atom(kind string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(8+len(body)))
	out = append(out, kind...)
	return append(out, body...)
}

// TestMetadataSpansFindsUdtaAndSkipsMedia pins the offsets, not just "the value was removed".
//
// A span that is too WIDE still removes the value, so a redaction test cannot tell the
// difference — but a wide span here reaches the sample tables, and overwriting those
// desynchronises the decoder from the media while the file still parses. That failure is
// invisible to any assertion about the value.
func TestMetadataSpansFindsUdtaAndSkipsMedia(t *testing.T) {
	tag := []byte("\xa9cmtEmployee SSN 452-11-9384")
	stbl := atom("stbl", bytes.Repeat([]byte{0xAB}, 32))
	minf := atom("minf", stbl)
	mdia := atom("mdia", minf)
	trak := atom("trak", mdia)
	udta := atom("udta", tag)
	moov := atom("moov", trak, udta)
	file := append(atom("ftyp", []byte("isomiso2mp41")), moov...)
	file = append(file, atom("mdat", bytes.Repeat([]byte{0xCD}, 64))...)

	spans, err := MetadataSpansIn(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1: %+v", len(spans), spans)
	}

	udtaPayloadAt := int64(bytes.Index(file, tag))
	if spans[0].Start != udtaPayloadAt || spans[0].End != udtaPayloadAt+int64(len(tag)) {
		t.Errorf("span = [%d,%d), want [%d,%d) — the udta payload exactly",
			spans[0].Start, spans[0].End, udtaPayloadAt, udtaPayloadAt+int64(len(tag)))
	}

	stblAt := int64(bytes.Index(file, stbl))
	mdatAt := int64(bytes.Index(file, bytes.Repeat([]byte{0xCD}, 64)))
	for _, sp := range spans {
		if stblAt >= sp.Start && stblAt < sp.End {
			t.Errorf("the sample table at %d falls inside a metadata span [%d,%d); overwriting it "+
				"corrupts playback while the file still parses", stblAt, sp.Start, sp.End)
		}
		if mdatAt >= sp.Start && mdatAt < sp.End {
			t.Errorf("the media payload at %d falls inside a metadata span [%d,%d)", mdatAt, sp.Start, sp.End)
		}
	}
}

// TestMetadataSpansFindsMoovMeta is the real-device layout, and it is here because a udta-only
// walk found NOTHING in a 2.9 MB .mov straight off an iPhone: its metadata is moov>meta in the
// mdta form, with a keys table and numbered ilst items. That file reports GPS at HIGH 100, so a
// walk that misses it refuses the most common video-with-location case there is.
func TestMetadataSpansFindsMoovMeta(t *testing.T) {
	keys := atom("keys", []byte{0, 0, 0, 0}, []byte{0, 0, 0, 1},
		atom("mdta", []byte("com.apple.quicktime.location.ISO6709")))
	item := atom("\x00\x00\x00\x01", atom("data", []byte{0, 0, 0, 1}, []byte("US\x15\xc7"),
		[]byte("+36.3506-082.6985+447.403/")))
	meta := atom("meta", []byte{0, 0, 0, 0}, atom("hdlr", []byte("\x00\x00\x00\x00\x00\x00\x00\x00mdta")),
		keys, atom("ilst", item))
	file := append(atom("ftyp", []byte("qt  ")), atom("moov", meta)...)

	spans, err := MetadataSpansIn(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spans) != 1 || spans[0].Label != "MP4 meta" {
		t.Fatalf("spans = %+v, want exactly one MP4 meta span", spans)
	}
	if !bytes.Contains(file[spans[0].Start:spans[0].End], []byte("+36.3506-082.6985+447.403/")) {
		t.Error("the meta span does not cover the position it exists to reach")
	}
}

// TestMetaInsideUdtaIsNotRecordedTwice keeps the spans disjoint. Two overlapping spans are not
// wrong in themselves, but they make every count downstream — occurrences, residue — depend on
// how many spans happened to cover the same bytes.
func TestMetaInsideUdtaIsNotRecordedTwice(t *testing.T) {
	inner := atom("meta", []byte{0, 0, 0, 0}, atom("ilst", atom("\xa9cmt", atom("data",
		[]byte{0, 0, 0, 1}, []byte{0, 0, 0, 0}, []byte("SSN 452-11-9384")))))
	file := append(atom("ftyp", []byte("isom")), atom("moov", atom("udta", inner))...)

	spans, err := MetadataSpansIn(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1 (the udta payload already contains the meta): %+v", len(spans), spans)
	}
}

// TestCoordinatesCoverTheWholeXyzPayload is the measured trap, and the reason the span is not
// narrowed to the position string inside it.
//
// ffmpeg writes a .mov ©xyz payload as a 2-byte text length, a 2-byte language code, then the
// ISO 6709 string. This tool's extractor reads that payload as FIXED-POINT and reported
// "18.335022, 11059.211639" for it — the length and language bytes ARE the latitude it printed.
// So a redaction that masks only the string leaves the first coordinate byte-for-byte intact,
// and the redacted file still reports a position.
func TestCoordinatesCoverTheWholeXyzPayload(t *testing.T) {
	payload := append([]byte{0x00, 0x12, 0x55, 0xc4}, []byte("+36.3506-082.6985/")...)
	udta := atom("udta", atom("\xa9xyz", payload))

	got := Coordinates(udta[8:])
	if len(got) != 1 {
		t.Fatalf("coordinates = %+v, want 1", got)
	}
	region := udta[8:][got[0].Start:got[0].End]
	if len(region) != len(payload) {
		t.Fatalf("span covers %d bytes, want the whole %d-byte payload including the text length "+
			"and language words — those bytes are read as a latitude", len(region), len(payload))
	}
	if !bytes.Equal(region, payload) {
		t.Errorf("span is offset: covers %q", region)
	}
}

// TestCoordinatesKeepTheDataAtomHeader checks the other direction: the span must NOT swallow an
// atom header. Zeroing a size field leaves an unparseable container, which is the
// corrupt-but-looks-redacted outcome that is worse than refusing.
func TestCoordinatesKeepTheDataAtomHeader(t *testing.T) {
	value := []byte("+37.7749-122.4194/")
	data := atom("data", []byte{0, 0, 0, 1}, []byte{0, 0, 0, 0}, value)
	udta := atom("udta", atom("meta", []byte{0, 0, 0, 0}, atom("ilst", atom("\xa9xyz", data))))

	buf := udta[8:]
	got := Coordinates(buf)
	if len(got) != 1 {
		t.Fatalf("coordinates = %+v, want 1", got)
	}
	if !bytes.Equal(buf[got[0].Start:got[0].End], value) {
		t.Errorf("span = %q, want exactly the value half of the data atom (%q): the type and "+
			"locale words and every atom header must survive", buf[got[0].Start:got[0].End], value)
	}
}

// TestCoordinatesFindAPositionWithNoRecognisableKey is why the position is matched by shape.
//
// In the mdta layout the atom holding the coordinate is named "\x00\x00\x00\x01" and only the
// keys table says what it is. A finder that has to recognise the key misses every writer that
// spells it differently; the value's shape does not vary.
func TestCoordinatesFindAPositionWithNoRecognisableKey(t *testing.T) {
	item := atom("\x00\x00\x00\x01", atom("data", []byte{0, 0, 0, 1}, []byte("US\x15\xc7"),
		[]byte("+36.3506-082.6985+447.403/")))
	buf := atom("ilst", item)

	got := Coordinates(buf)
	if len(got) != 1 {
		t.Fatalf("coordinates = %+v, want 1", got)
	}
	if string(buf[got[0].Start:got[0].End]) != "+36.3506-082.6985+447.403/" {
		t.Errorf("span = %q, want the ISO 6709 run", buf[got[0].Start:got[0].End])
	}
}

// TestISO6709FormsFromTheStandard walks the forms ISO 6709 Annex H defines, using the standard's
// own examples.
//
// The first version of this pattern allowed one to three integer digits per coordinate, which
// covers the decimal-degree form a phone writes and MISSES the degrees-minutes and
// degrees-minutes-seconds forms entirely — a leak that no file on the author's machine would
// have revealed. The digit counts are 2/4/6 for latitude and 3/5/7 for longitude because the
// integer length is what distinguishes the three forms.
func TestISO6709FormsFromTheStandard(t *testing.T) {
	shouldMatch := []string{
		"+00-025/",                         // Atlantic Ocean, degrees only
		"+46+002/",                         // France
		"+48.52+002.20/",                   // Paris, fractional degrees
		"+27.5916+086.5640+8850CRSWGS_84/", // Everest: height AND a CRS identifier
		"-90+000+2800CRSWGS_84/",           // South Pole
		"+40.6894-074.0447/",               // Statue of Liberty
		"+4012.22-07500.25/",               // degrees and minutes
		"+401213.1-0750015.1/",             // degrees, minutes and seconds
		"+36.3506-082.6985+447.403/",       // what a real iPhone writes: height, no CRS
	}
	for _, s := range shouldMatch {
		loc := iso6709.FindString(s)
		if loc != s {
			t.Errorf("iso6709 on %q matched %q; the whole string is the position", s, loc)
		}
	}

	shouldNotMatch := []string{
		"415-555-0142",          // a phone number
		"449-87-4100",           // an SSN
		"2025-08-17T11:50:24Z",  // a timestamp
		"v1.2.3/release",        // a version string
		"+36.3506",              // latitude alone, no longitude and no solidus
		"36.350600, -82.698500", // the tool's OWN rendering: signs and solidus absent
	}
	for _, s := range shouldNotMatch {
		if iso6709.Match([]byte(s)) {
			t.Errorf("iso6709 matched %q; masking bytes that are not a position corrupts metadata", s)
		}
	}
}

// TestFullBoxPrefixIsProbedNotAssumed covers meta both ways. Its four version-and-flags bytes
// decode as a size of 0, which by the spec means "extends to the end of the file", so walking
// from the payload start collapses the whole tag block into one atom and finds nothing inside
// it. A QuickTime writer that omits the prefix must still walk.
func TestFullBoxPrefixIsProbedNotAssumed(t *testing.T) {
	value := []byte("+37.7749-122.4194/")
	xyz := atom("\xa9xyz", atom("data", []byte{0, 0, 0, 1}, []byte{0, 0, 0, 0}, value))

	withPrefix := atom("udta", atom("meta", []byte{0, 0, 0, 0}, atom("ilst", xyz)))
	withoutPrefix := atom("udta", atom("meta", atom("ilst", xyz)))

	for name, buf := range map[string][]byte{"with version+flags": withPrefix, "without": withoutPrefix} {
		got := Coordinates(buf[8:])
		if len(got) != 1 {
			t.Errorf("%s: coordinates = %+v, want 1", name, got)
			continue
		}
		if !bytes.Equal(buf[8:][got[0].Start:got[0].End], value) {
			t.Errorf("%s: span = %q, want %q", name, buf[8:][got[0].Start:got[0].End], value)
		}
	}
}

// TestSixtyFourBitSizesAreWalked covers the largesize form: a size word of 1 means the real
// 64-bit size follows the type. Every file over 4 GB uses it for mdat, and a walk that mishandles
// it either stops early or reads a wrong offset.
//
// The metadata extractor does NOT report values from a file built this way — measured, zero
// findings — so nothing reaches the redactor for it today. The walk still has to be right: a read
// gap that gets closed later must not find the write side unable to follow.
func TestSixtyFourBitSizesAreWalked(t *testing.T) {
	tag := []byte("\xa9cmtSSN 452-11-9384")
	large := func(kind string, payload []byte) []byte {
		out := []byte{0, 0, 0, 1}
		out = append(out, kind...)
		size := make([]byte, 8)
		binary.BigEndian.PutUint64(size, uint64(16+len(payload)))
		out = append(out, size...)
		return append(out, payload...)
	}
	file := append(atom("ftyp", []byte("isom")), large("moov", large("udta", tag))...)
	file = append(file, large("mdat", bytes.Repeat([]byte{0xCD}, 64))...)

	spans, err := MetadataSpansIn(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1: a size word of 1 defers to the 64-bit size that follows", len(spans))
	}
	if !bytes.Equal(file[spans[0].Start:spans[0].End], tag) {
		t.Errorf("span = %q, want %q", file[spans[0].Start:spans[0].End], tag)
	}
}

// TestLociIsFoundAsAPosition pins the second position atom. ffmpeg writes location into loci for
// .mp4 and into ©xyz for .mov, and a file can carry both — see the video redactor's test for the
// measured leak that followed from handling only one.
func TestLociIsFoundAsAPosition(t *testing.T) {
	buf := atom("loci", []byte{0, 0, 0, 0}, []byte{0x15, 0xc7}, []byte{0}, []byte{0},
		[]byte{0xff, 0xad, 0x4d, 0x30}, []byte{0x00, 0x24, 0x59, 0xc0}, []byte{0, 0, 0, 0},
		[]byte("earth\x00"))

	got := Coordinates(buf)
	if len(got) != 1 {
		t.Fatalf("coordinates = %+v, want the loci payload", got)
	}
	if got[0].Start != 8 || got[0].End != int64(len(buf)) {
		t.Errorf("span = [%d,%d), want the whole payload [8,%d): the position sits after a "+
			"variable-length location name, which is location data too",
			got[0].Start, got[0].End, len(buf))
	}
}

// TestAtomBudgetIsReportedNotSwallowed pins the one error this walk raises.
//
// A file of nothing but 8-byte headers describes one atom per 8 bytes, and the streaming walk
// pays a read for each. The budget bounds that work; reporting it matters because the spans
// found before it ran out are NOT a complete answer, and a caller that treats them as one would
// write a file it had only partly examined.
func TestAtomBudgetIsReportedNotSwallowed(t *testing.T) {
	// maxAtoms+1 empty container atoms, so the walk cannot finish.
	var buf []byte
	for i := 0; i <= maxAtoms; i++ {
		buf = append(buf, atom("free")...)
	}

	spans, err := MetadataSpansIn(buf)
	if err == nil {
		t.Fatal("a file declaring more atoms than the budget allows returned no error; a partial " +
			"walk reported as complete is how an unexamined region becomes a clean report")
	}
	if err != ErrAtomBudget {
		t.Errorf("err = %v, want ErrAtomBudget", err)
	}
	if spans != nil {
		t.Errorf("spans = %+v, want none for a file with no metadata", spans)
	}
}

// TestMalformedInputStopsWithoutSpinning covers the shapes a truncated or hostile file takes.
// Each must return rather than loop, and none may report a span outside the buffer.
func TestMalformedInputStopsWithoutSpinning(t *testing.T) {
	cases := map[string][]byte{
		"empty":                    {},
		"header only":              []byte("\x00\x00\x00\x08ftyp"),
		"size smaller than header": []byte("\x00\x00\x00\x02udta"),
		"size past the end":        []byte("\x00\xff\xff\xffudtaxx"),
		"truncated 64-bit size":    []byte("\x00\x00\x00\x01udta\x00\x00"),
		"64-bit size past the end": append([]byte("\x00\x00\x00\x01udta"), bytes.Repeat([]byte{0xFF}, 8)...),
		"zero size at the end":     []byte("\x00\x00\x00\x00udta"),
		"nested truncation":        atom("moov", []byte("\x00\x00\x00\x40udta")),
	}
	for name, buf := range cases {
		spans, err := MetadataSpansIn(buf)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		for _, sp := range spans {
			if sp.Start < 0 || sp.End > int64(len(buf)) || sp.Start >= sp.End {
				t.Errorf("%s: span %+v is outside the %d-byte buffer", name, sp, len(buf))
			}
		}
		// Coordinates walks the same headers; run it too so a hang shows up here.
		_ = Coordinates(buf)
	}
}

// TestHasHeaderAcceptsAClassicQuickTimeMovie covers the sniff. A .mov written without a brand
// has no ftyp at all — its first atom is wide, moov or mdat — so a check that only knows ftyp
// calls a real movie unrecognised.
func TestHasHeaderAcceptsAClassicQuickTimeMovie(t *testing.T) {
	yes := map[string][]byte{
		"ftyp": []byte("\x00\x00\x00\x14ftypqt  "),
		"wide": []byte("\x00\x00\x00\x08wide"),
		"moov": []byte("\x00\x00\x0f\x00moov"),
		"mdat": []byte("\x00\x0f\x00\x00mdat"),
		"free": []byte("\x00\x00\x00\x08free"),
	}
	for name, head := range yes {
		if !HasHeader(head) {
			t.Errorf("HasHeader rejected a container starting with %s", name)
		}
	}

	no := map[string][]byte{
		"plain text": []byte("employee ssn 452-11-9384\n"),
		"a PNG":      {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		"a ZIP":      []byte("PK\x03\x04\x14\x00\x00\x00"),
		"too short":  []byte("ftyp"),
		"an ID3 tag": []byte("ID3\x03\x00\x00\x00\x00"),
	}
	for name, head := range no {
		if HasHeader(head) {
			t.Errorf("HasHeader accepted %s; a container redactor must not claim it", name)
		}
	}
}

// TestWalkVisitsFragmentedLayouts covers moof/traf, which a fragmented MP4 uses instead of a
// single moov. ffmpeg produces this shape with -movflags frag_keyframe+empty_moov, and a real
// one was measured redacting correctly; this pins the descent that makes that work.
func TestWalkVisitsFragmentedLayouts(t *testing.T) {
	tag := []byte("\xa9cmtSSN 452-11-9384")
	file := append(atom("ftyp", []byte("iso5")), atom("moov", atom("mvhd", make([]byte, 100)))...)
	file = append(file, atom("moof", atom("traf", atom("udta", tag)))...)

	spans, err := MetadataSpansIn(file)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1 inside moof>traf: %+v", len(spans), spans)
	}
	if !bytes.Equal(file[spans[0].Start:spans[0].End], tag) {
		t.Errorf("span = %q, want %q", file[spans[0].Start:spans[0].End], tag)
	}
}
