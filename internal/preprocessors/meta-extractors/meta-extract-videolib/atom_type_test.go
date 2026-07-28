// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonicalBoxType_MatchesSourceLiterals is the root-cause test. Every "©xxx"
// case arm in this file is a FIVE-byte Go string, because the source literal "©"
// is the two-byte UTF-8 encoding c2 a9. A box type off the wire is four bytes with
// a single 0xA9. The two are never equal, so all those arms were dead code:
// ffmpeg-written titles, authors and comments fell through and the udta GPS atom
// was never parsed.
func TestCanonicalBoxType_MatchesSourceLiterals(t *testing.T) {
	// The bug, stated as an assertion so it cannot silently come back.
	if string(wireAtom("nam")) == "©nam" {
		t.Fatal("premise changed: a 4-byte wire atom now equals the 5-byte source literal")
	}

	for _, suffix := range []string{"nam", "ART", "xyz", "cmt", "inf", "ed1", "too"} {
		if got := canonicalBoxType(wireAtom(suffix)); got != "©"+suffix {
			t.Errorf("canonicalBoxType(%q) = %q, want %q", suffix, got, "©"+suffix)
		}
	}

	// Plain four-character types must pass through untouched.
	for _, plain := range []string{"meta", "ilst", "data", "desc", "udta", "moov"} {
		if got := canonicalBoxType([]byte(plain)); got != plain {
			t.Errorf("canonicalBoxType(%q) = %q, want it unchanged", plain, got)
		}
	}

	// Malformed input must not be reinterpreted.
	if got := canonicalBoxType([]byte{0xA9, 'n'}); got != string([]byte{0xA9, 'n'}) {
		t.Errorf("a short type was rewritten: %q", got)
	}
}

// TestParseStringBox_StripsQuickTimeTextHeader covers the second defect. A udta
// string box is not raw text: 2-byte big-endian length, 2-byte language, then the
// characters. Returning the whole payload prefixed every value with four bytes of
// binary, so the text handed to the validators — and to the redactor — was
// corrupted at the front.
func TestParseStringBox_StripsQuickTimeTextHeader(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
		// clean marks inputs that are well-formed text atoms, for which the
		// returned text must contain no binary. Malformed input falls back to the
		// raw payload (see below), so it is exempt.
		clean bool
	}{
		// The exact bytes ffmpeg writes for artist="Jordan Ellis".
		{"ffmpeg artist", append([]byte{0x00, 0x0c, 0x55, 0xc4}, "Jordan Ellis"...), "Jordan Ellis", true},
		{"language zero", quickTimeText("Deposition of Jordan Ellis"), "Deposition of Jordan Ellis", true},
		{"empty", nil, "", true},

		// Not every writer emits the header, so an unusable declared length falls
		// back to the raw payload. That deliberately preserves content rather than
		// truncating it — the same bytes main returned for every box — so this case
		// is about not LOSING data, not about the result being clean.
		{"bare text, no header", []byte("Jordan Ellis"), "Jordan Ellis", true},
		{"declared length overruns payload", append([]byte{0xff, 0xff, 0x00, 0x00}, "short"...), "\xff\xff\x00\x00short", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStringBox(tc.in)
			if got != strings.TrimSpace(tc.want) {
				t.Errorf("parseStringBox(% x) = %q, want %q", tc.in, got, tc.want)
			}
			if !tc.clean {
				return
			}
			// For a well-formed atom no NUL or control byte may survive into the
			// text the scanner reads and the redactor rewrites.
			for _, b := range []byte(got) {
				if b < 0x20 && b != '\t' && b != '\n' {
					t.Errorf("control byte %#x survived into %q", b, got)
					break
				}
			}
		})
	}
}

// TestExtractVideoMetadata_UdtaAtomsAreReached is the end-to-end form: a
// QuickTime file whose metadata sits in udta string boxes — the layout ffmpeg
// writes — must yield its title, author and description. On the previous code
// every one of these was dropped and the file scanned as if it had no metadata at
// all, so PII in a comment field was never reported and never redacted.
func TestExtractVideoMetadata_UdtaAtomsAreReached(t *testing.T) {
	udta := udtaTextAtom("nam", "Deposition of Jordan Ellis")
	udta = append(udta, udtaTextAtom("ART", "Jordan Ellis")...)
	udta = append(udta, udtaTextAtom("cmt", "Reach me at analyst@example.test or (415) 555-0142")...)
	udta = append(udta, udtaTextAtom("inf", "Patient record on file")...)
	udta = append(udta, udtaTextAtom("dir", "Directed by Morgan Reyes")...)
	udta = append(udta, udtaTextAtom("prd", "Produced by Example Studios")...)

	path := writeUdtaMP4(t, "clip.mov", udta)

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}

	if md.Title != "Deposition of Jordan Ellis" {
		t.Errorf("Title = %q, want the ©nam value", md.Title)
	}
	if md.Author != "Jordan Ellis" {
		t.Errorf("Author = %q, want the ©ART value", md.Author)
	}
	if !strings.Contains(md.Description, "analyst@example.test") {
		t.Errorf("Description = %q, want the ©cmt value", md.Description)
	}
	if md.Properties["Information"] != "Patient record on file" {
		t.Errorf("Information = %q, want the ©inf value", md.Properties["Information"])
	}
	if md.Properties["Director"] != "Directed by Morgan Reyes" {
		t.Errorf("Director = %q", md.Properties["Director"])
	}
	if md.Properties["Producer"] != "Produced by Example Studios" {
		t.Errorf("Producer = %q", md.Properties["Producer"])
	}

	// The emitted text is what the scanner reads and the redactor rewrites.
	out := md.ToProcessedContent()
	for _, want := range []string{
		"Title: Deposition of Jordan Ellis",
		"Author: Jordan Ellis",
		"Description: Reach me at analyst@example.test or (415) 555-0142",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("processed content missing %q; got:\n%s", want, out)
		}
	}
}

// TestExtractVideoMetadata_UdtaGPSAtomIsReached: on the udta path the ©xyz atom is
// binary fixed-point, and it is the authoritative coordinate. It was never parsed,
// so a video with a recorded location produced no GPS finding.
func TestExtractVideoMetadata_UdtaGPSAtomIsReached(t *testing.T) {
	const wantLat, wantLon = 36.3506, -82.6985

	gps := fixedPoint1616(wantLat)
	gps = append(gps, fixedPoint1616(wantLon)...)
	gps = append(gps, fixedPoint1616(0)...)

	path := writeUdtaMP4(t, "clip.mov", mp4Box(wireAtom("xyz"), gps))

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}

	// 16.16 fixed point quantizes, so compare within one unit of that grid.
	const eps = 2.0 / 65536.0
	if math.Abs(md.GPSLatitude-wantLat) > eps || math.Abs(md.GPSLongitude-wantLon) > eps {
		t.Errorf("GPS = (%.6f, %.6f), want (%.6f, %.6f)", md.GPSLatitude, md.GPSLongitude, wantLat, wantLon)
	}
	if out := md.ToProcessedContent(); !strings.Contains(out, "GPS_Coordinates:") {
		t.Errorf("no GPS_Coordinates line, so the recorded location is never reported:\n%s", out)
	}
}

// TestExtractVideoMetadata_EditDateIndex pins the index that the byte-length
// confusion also broke: boxType[3:] sliced into the middle of the five-byte
// literal and produced "d1", so the property would have been "EditDated1". Only
// harmless while the arm was unreachable.
func TestExtractVideoMetadata_EditDateIndex(t *testing.T) {
	path := writeUdtaMP4(t, "clip.mov", udtaTextAtom("ed1", "2026-03-14 09:12:00"))

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}

	if _, ok := md.Properties["EditDate1"]; !ok {
		t.Errorf("want property EditDate1, got %v", md.Properties)
	}
	if _, bad := md.Properties["EditDated1"]; bad {
		t.Error("property key still built from the wrong slice offset (EditDated1)")
	}
}

// TestParseIlstBox_UnknownTagsStillRecorded guards the recall side of the fix.
// The unknown-tag branch tested len(boxType) == 4; once types are canonicalized a
// "©too" is five bytes, so a naive fix would have silently DROPPED every
// unrecognized iTunes tag — trading one recall bug for another. The key should now
// be readable rather than mojibake, and the value must still be there.
func TestParseIlstBox_UnknownTagsStillRecorded(t *testing.T) {
	tags := mp4ItunesTag(wireAtom("too"), "Example Encoder 1.0")
	tags = append(tags, mp4ItunesTag([]byte("keyw"), "confidential")...)

	path := writeTestMP4(t, "clip.mp4", tags)

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}

	if got := md.Properties["©too"]; got != "Example Encoder 1.0" {
		t.Errorf("unknown ©-prefixed tag dropped or misfiled: Properties[\"©too\"] = %q, all = %v", got, md.Properties)
	}
	if got := md.Properties["keyw"]; got != "confidential" {
		t.Errorf("plain unknown tag regressed: %q", got)
	}
}

// TestExtractVideoMetadata_RecognizedIlstTagsFillTypedFields: on the ilst path the
// values were not lost, but they landed in Properties under an unreadable
// mojibake key instead of Title/Author/CameraMake, so field-name-driven metadata
// rules never fired on them.
func TestExtractVideoMetadata_RecognizedIlstTagsFillTypedFields(t *testing.T) {
	tags := mp4ItunesTag(wireAtom("nam"), "Quarterly review recording")
	tags = append(tags, mp4ItunesTag(wireAtom("ART"), "Jordan Ellis")...)
	tags = append(tags, mp4ItunesTag(wireAtom("mak"), "ExampleCam")...)
	tags = append(tags, mp4ItunesTag(wireAtom("mod"), "XC-1")...)

	path := writeTestMP4(t, "clip.mp4", tags)

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}

	if md.Title != "Quarterly review recording" || md.Author != "Jordan Ellis" {
		t.Errorf("Title = %q, Author = %q", md.Title, md.Author)
	}
	if md.CameraMake != "ExampleCam" || md.CameraModel != "XC-1" {
		t.Errorf("CameraMake = %q, CameraModel = %q", md.CameraMake, md.CameraModel)
	}

	// And no mojibake key survives in the emitted text.
	out := md.ToProcessedContent()
	if strings.Contains(out, "\xc2\xa9nam") || strings.Contains(out, "�") {
		t.Errorf("emitted text still carries a mangled atom key:\n%s", out)
	}
}

// TestExtractVideoMetadata_UdtaDeterministic: this fix newly populates several
// properties, and Properties is a map. Emitted text must still be stable.
//
// Unlike the tests above, this one is a forward guard rather than a regression
// test: it passes on the parent commit too, but only vacuously — the parent
// extracted none of these properties, so there was nothing whose order could
// vary. It earns its keep now that the fields are actually populated.
func TestExtractVideoMetadata_UdtaDeterministic(t *testing.T) {
	udta := udtaTextAtom("nam", "Deposition of Jordan Ellis")
	udta = append(udta, udtaTextAtom("ART", "Jordan Ellis")...)
	udta = append(udta, udtaTextAtom("cmt", "Comment field")...)
	udta = append(udta, udtaTextAtom("dir", "Morgan Reyes")...)
	udta = append(udta, udtaTextAtom("prd", "Example Studios")...)
	udta = append(udta, udtaTextAtom("src", "Camera A")...)
	udta = append(udta, udtaTextAtom("gen", "Legal")...)
	udta = append(udta, udtaTextAtom("inf", "Information field")...)

	path := writeUdtaMP4(t, "clip.mov", udta)

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}

	first := md.ToProcessedContent()
	for i := 0; i < 200; i++ {
		if got := md.ToProcessedContent(); got != first {
			t.Fatalf("iter %d: emitted text is not stable:\n--- first ---\n%s\n--- iter ---\n%s", i, first, got)
		}
	}

	// And re-extracting from the same bytes gives the same text.
	for i := 0; i < 20; i++ {
		again, err := ExtractVideoMetadata(path)
		if err != nil {
			t.Fatalf("re-extract %d: %v", i, err)
		}
		if got := again.ToProcessedContent(); got != first {
			t.Fatalf("re-extract %d differs:\n--- first ---\n%s\n--- again ---\n%s", i, first, got)
		}
	}
}

// --- helpers -----------------------------------------------------------------

// wireAtom builds a four-byte QuickTime atom type: the single byte 0xA9 followed
// by the three-character suffix. Deliberately NOT built from a Go "©" literal,
// which would be five bytes — the whole point of the bug under test.
func wireAtom(suffix string) []byte {
	return append([]byte{itunesAtomPrefix}, suffix...)
}

// quickTimeText wraps s in the udta text-atom payload: 2-byte length, 2-byte
// language, then the characters.
func quickTimeText(s string) []byte {
	p := binary.BigEndian.AppendUint16(nil, uint16(len(s)))
	p = binary.BigEndian.AppendUint16(p, 0)
	return append(p, s...)
}

// udtaTextAtom builds a complete "©xxx" udta string box.
func udtaTextAtom(suffix, text string) []byte {
	return mp4Box(wireAtom(suffix), quickTimeText(text))
}

// fixedPoint1616 encodes a coordinate the way the ©xyz udta atom stores it.
func fixedPoint1616(v float64) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(int32(v*65536)))
}

// writeUdtaMP4 writes ftyp + moov/udta(children) + a stub mdat: the classic
// QuickTime layout, with metadata directly under udta and no meta/ilst.
func writeUdtaMP4(t *testing.T, name string, udtaChildren []byte) string {
	t.Helper()

	ftyp := mp4Box([]byte("ftyp"), []byte("qt  \x00\x00\x00\x00qt  "))
	file := append(ftyp, mp4Box([]byte("moov"), mp4Box([]byte("udta"), udtaChildren))...)
	file = append(file, mp4Box([]byte("mdat"), make([]byte, 64))...)

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
