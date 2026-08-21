// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// closeTo compares positions with a tolerance that admits 16.16 fixed-point quantisation. A loci
// atom stores 36.3506 as 0x002459C0, which reads back as 36.350586 — the file genuinely holds that
// value, so an exact comparison would be asserting against the wrong thing.
func closeTo(got, want float64) bool { return math.Abs(got-want) < 0.0005 }

// fixed encodes a degree value the way an ISO base media file stores one: 16.16 signed fixed-point,
// big-endian. Written through a variable because a constant expression like int32(37.7749*65536)
// does not compile — the untyped constant is not an exact integer.
func fixed(deg float64) uint32 {
	v := deg * 65536.0
	return uint32(int32(v))
}

// realXyzTextPayload is the ©xyz payload ffmpeg 9.0.1 writes into a .mov, captured byte for byte
// from `ffmpeg -metadata location="+36.3506-082.6985/" out.mov`:
// a 2-byte text length (0x0012 = 18), a 2-byte language code (0x55C4), then the ISO 6709 string.
var realXyzTextPayload = append([]byte{0x00, 0x12, 0x55, 0xC4}, []byte("+36.3506-082.6985/")...)

// realLociPayload is the loci payload ffmpeg 9.0.1 writes into a .mp4 for the SAME -metadata
// location, also captured byte for byte: version+flags, language, an empty NUL-terminated name, a
// role byte, then LONGITUDE, LATITUDE, altitude as 16.16, then the astronomical body.
var realLociPayload = []byte{
	0x00, 0x00, 0x00, 0x00, // version + flags
	0x00, 0x00, // language
	0x00,                   // name: empty, NUL-terminated
	0x00,                   // role
	0xFF, 0xAD, 0x4D, 0x30, // longitude -82.6985
	0x00, 0x24, 0x59, 0xC0, // latitude   36.3506
	0x00, 0x00, 0x00, 0x00, // altitude
	'e', 'a', 'r', 't', 'h', 0x00,
}

// buildISOFile writes a minimal conformant ISO base media file and returns its path.
//
// mdatBytes is the SIZE the mdat declares and the file really has, created as a hole with Truncate
// rather than written out, so a fixture with a 200 MB mdat costs no test memory and (on a sparse
// filesystem) no disk. That matters because the whole point of these fixtures is that the media
// payload is never read — a builder that allocated it would make the assertion about allocation
// impossible to state.
//
// moovFirst chooses the layout: false puts moov AFTER mdat, which is what ffmpeg and every camera
// measured on this machine write by default, and which every pre-existing fixture in this package
// got wrong by always writing moov first.
func buildISOFile(t *testing.T, path string, mdatBytes int64, moovFirst bool, udtaChildren ...[]byte) string {
	t.Helper()

	moov := box(atom("moov"), box(atom("udta"), bytes.Join(udtaChildren, nil)))
	ftyp := box(atom("ftyp"), []byte("isom\x00\x00\x02\x00isomiso2mp41"))

	if mdatBytes < 0 || mdatBytes+8 > math.MaxUint32 {
		t.Fatalf("mdat size %d does not fit a 32-bit box size", mdatBytes)
	}
	mdatHeader := make([]byte, 8)
	binary.BigEndian.PutUint32(mdatHeader[0:4], uint32(8+mdatBytes))
	copy(mdatHeader[4:8], "mdat")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close %s: %v", path, err)
		}
	}()

	write := func(b []byte) {
		if _, err := f.Write(b); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	write(ftyp)
	if moovFirst {
		write(moov)
	}
	write(mdatHeader)
	// The hole: extend the file past the mdat payload without writing it.
	end, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("seek %s: %v", path, err)
	}
	if err := f.Truncate(end + mdatBytes); err != nil {
		t.Fatalf("truncate %s: %v", path, err)
	}
	if _, err := f.Seek(end+mdatBytes, io.SeekStart); err != nil {
		t.Fatalf("seek past mdat in %s: %v", path, err)
	}
	if !moovFirst {
		write(moov)
	}
	return path
}

// itunesAtom builds one of the iTunes/QuickTime metadata atom types, whose first byte is 0xA9.
//
// NOT []byte("©cmt"). The Go literal "©" is its two-byte UTF-8 encoding, so that spelling is a FIVE
// byte type which copies into a four-byte field truncated — the box then has a nonsense type and is
// silently ignored. The extractor's own canonicalBoxType comment records this same trap, and writing
// the fixtures the wrong way is what made the first run of these tests fail.
func itunesAtom(threeCC string) []byte {
	if len(threeCC) != 3 {
		panic("an iTunes atom type is 0xA9 plus exactly three characters, got " + threeCC)
	}
	return []byte{0xA9, threeCC[0], threeCC[1], threeCC[2]}
}

// textAtom encodes a QuickTime string atom the way parseStringBox reads one: a 2-byte text length,
// a 2-byte language code, then the text.
func textAtom(boxType []byte, text string) []byte {
	payload := make([]byte, 4+len(text))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(text)))
	binary.BigEndian.PutUint16(payload[2:4], 0x15C7)
	copy(payload[4:], text)
	return box(boxType, payload)
}

// The udta switch must actually route each atom to its parser.
//
// The direct unit tests above all pass with `case "loci":` deleted from the switch — a correct parser
// that nothing calls. This drives the real container so the wiring is what is under test, which is
// the same gap that let a disabled call site survive mutation elsewhere in this repo.
func TestPositionAtomsAreReachedThroughTheContainer(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]struct {
		child    []byte
		wantLat  float64
		wantLon  float64
		wantName string
	}{
		"loci in .mp4 (ffmpeg default)": {
			child: box(atom("loci"), realLociPayload), wantLat: 36.3506, wantLon: -82.6985,
		},
		"xyz text in .mov (ffmpeg default)": {
			child: box(xyzAtom, realXyzTextPayload), wantLat: 36.3506, wantLon: -82.6985,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := buildISOFile(t, filepath.Join(dir, "pos.mp4"), 4096, false, c.child)

			meta, err := ExtractVideoMetadataWithContext(context.Background(), path)
			if err != nil {
				t.Fatalf("ExtractVideoMetadataWithContext: %v", err)
			}
			if !closeTo(meta.GPSLatitude, c.wantLat) || !closeTo(meta.GPSLongitude, c.wantLon) {
				t.Errorf("got lat=%v lon=%v, want %v/%v: the parser is correct in isolation but the "+
					"udta switch does not route this atom to it, so the position is never reported "+
					"and never redacted", meta.GPSLatitude, meta.GPSLongitude, c.wantLat, c.wantLon)
			}
		})
	}
}

// A ©xyz payload carries a position in either of two encodings and the atom name does not say
// which, so the payload's shape has to decide.
//
// Reading the text form as fixed-point turns the length and language bytes into a latitude: the real
// ffmpeg payload below was reported as "18.335022, 11059.211639" at HIGH confidence — an impossible
// longitude — while the true position sat unreported in the same bytes (#399).
//
// Both encodings are asserted together on purpose. A fix that only adds a text branch and drops the
// fixed-point one trades a false positive for a leak, and either half alone looks correct.
func TestPositionAtomShapeDecidesTextVersusFixedPoint(t *testing.T) {
	t.Run("ffmpeg .mov text form", func(t *testing.T) {
		m := &VideoMetadata{Properties: map[string]string{}}
		parsePositionAtom(realXyzTextPayload, m)

		if !closeTo(m.GPSLatitude, 36.3506) || !closeTo(m.GPSLongitude, -82.6985) {
			t.Errorf("got lat=%v lon=%v, want 36.3506/-82.6985. The text payload is being read as "+
				"fixed-point, which reports the length and language bytes as a coordinate and "+
				"buries the real position that is present in the same payload",
				m.GPSLatitude, m.GPSLongitude)
		}
		// Pin the specific garbage value, so a regression is recognisable rather than merely wrong.
		if closeTo(m.GPSLatitude, 18.335022) {
			t.Error("latitude is 18.335022 — that is 0x001255C4/65536, i.e. the text length and " +
				"language code decoded as a fixed-point number")
		}
	})

	t.Run("fixed-point form still works", func(t *testing.T) {
		payload := make([]byte, 12)
		binary.BigEndian.PutUint32(payload[0:4], fixed(37.7749))
		binary.BigEndian.PutUint32(payload[4:8], fixed(-122.4194))

		m := &VideoMetadata{Properties: map[string]string{}}
		parsePositionAtom(payload, m)

		if !closeTo(m.GPSLatitude, 37.7749) || !closeTo(m.GPSLongitude, -122.4194) {
			t.Errorf("got lat=%v lon=%v, want 37.7749/-122.4194: the shape test is sending a "+
				"binary payload down the text branch, so cameras that write fixed-point lose "+
				"their position entirely", m.GPSLatitude, m.GPSLongitude)
		}
	})
}

// A zero-filled payload must yield no position.
//
// This is the property that makes video redaction verifiable: the redactor zeroes a whole ©xyz
// payload and then the output is rescanned to prove nothing survived. '*' would not do — 0x2A2A2A2A
// is a valid fixed-point 10794.66° — so zero is the one fill no reader turns back into a location.
// A shape test that read zeroes as anything reportable would make every redacted file look like it
// still carried a coordinate.
func TestZeroFilledPositionAtomYieldsNoPosition(t *testing.T) {
	for _, n := range []int{12, len(realXyzTextPayload), 64} {
		m := &VideoMetadata{Properties: map[string]string{}}
		parsePositionAtom(make([]byte, n), m)
		if m.GPSLatitude != 0 || m.GPSLongitude != 0 {
			t.Errorf("a %d-byte zero-filled payload produced lat=%v lon=%v; a redacted file would "+
				"still report a position and the residue check would fail", n,
				m.GPSLatitude, m.GPSLongitude)
		}
	}
}

// loci is the form ffmpeg writes into .mp4 BY DEFAULT, and it had no case at all: the position was
// never reported, so it was never redacted either.
//
// The word order is the trap. loci stores LONGITUDE before LATITUDE, the reverse of ©xyz. A reader
// that assumes lat/lon swaps the coordinates, and the fixture is deliberately far from the equator
// and from the 45° diagonal so a swap cannot pass.
func TestLociPositionIsReportedWithLongitudeFirst(t *testing.T) {
	m := &VideoMetadata{Properties: map[string]string{}}
	parseLociBox(realLociPayload, m)

	if !closeTo(m.GPSLatitude, 36.3506) || !closeTo(m.GPSLongitude, -82.6985) {
		t.Errorf("got lat=%v lon=%v, want 36.3506/-82.6985", m.GPSLatitude, m.GPSLongitude)
	}
	if closeTo(m.GPSLatitude, -82.6985) {
		t.Error("latitude is -82.6985, the LONGITUDE value: loci stores longitude first and the " +
			"words are being read in ©xyz order")
	}
}

// The place name inside a loci atom is location data in its own right, and it sits before the
// coordinates as a variable-length NUL-terminated string — so getting it wrong also misaligns every
// coordinate that follows.
func TestLociPlaceNameIsKeptAndDoesNotMisalignTheCoordinates(t *testing.T) {
	name := "Renee's home address"
	payload := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	payload = append(payload, name...)
	payload = append(payload, 0x00) // name terminator
	payload = append(payload, 0x00) // role
	coords := make([]byte, 12)
	binary.BigEndian.PutUint32(coords[0:4], fixed(-82.6985)) // longitude first
	binary.BigEndian.PutUint32(coords[4:8], fixed(36.3506))
	payload = append(payload, coords...)
	payload = append(payload, []byte("earth\x00")...)

	m := &VideoMetadata{Properties: map[string]string{}}
	parseLociBox(payload, m)

	if m.Location != name {
		t.Errorf("Location = %q, want %q: the place name is location data and must be reported so "+
			"it can be redacted", m.Location, name)
	}
	if !closeTo(m.GPSLatitude, 36.3506) || !closeTo(m.GPSLongitude, -82.6985) {
		t.Errorf("got lat=%v lon=%v after a %d-byte name: the coordinates are read at a fixed "+
			"offset instead of after the NUL terminator, so any named loci atom decodes to "+
			"nonsense", m.GPSLatitude, m.GPSLongitude, len(name))
	}
}

// A malformed loci atom must not be read past its end, and must not report a partial position.
func TestLociRefusesMalformedPayloads(t *testing.T) {
	cases := map[string][]byte{
		"too short for the coordinates": {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"unterminated name":             append([]byte{0, 0, 0, 0, 0, 0}, []byte("no terminator here at all")...),
		"empty":                         {},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			m := &VideoMetadata{Properties: map[string]string{}}
			parseLociBox(payload, m) // must not panic
			if m.GPSLatitude != 0 || m.GPSLongitude != 0 {
				t.Errorf("a malformed payload produced lat=%v lon=%v", m.GPSLatitude, m.GPSLongitude)
			}
		})
	}
}

// ISO 6709 Annex H has THREE integer widths, and they differ only in digit count. A plain
// ParseFloat is right for the first and silently wrong for the other two.
//
// Measured before this change: "+4012.22-07500.25/" reported latitude 4012.22 and
// "+401230.5-0750015.3/" reported 401230.5 — impossible coordinates at HIGH confidence. No local
// producer writes the sexagesimal forms (every real file measured on this machine uses decimal
// degrees), so this comes from the standard rather than from a sample, which is precisely why it
// needs a test to hold it in place.
func TestISO6709AcceptsAllThreeIntegerForms(t *testing.T) {
	cases := []struct {
		in       string
		lat, lon float64
		alt      float64
	}{
		{"+36.3506-082.6985/", 36.3506, -82.6985, 0},                        // ±DD.D±DDD.D
		{"+36.3506-082.6985+447.403/", 36.3506, -82.6985, 447.403},          // with height
		{"+4012.22-07500.25/", 40.203667, -75.004167, 0},                    // ±DDMM.M±DDDMM.M
		{"+401230.5-0750015.3/", 40.208472, -75.004250, 0},                  // ±DDMMSS.S±DDDMMSS.S
		{"-33.8688+151.2093/", -33.8688, 151.2093, 0},                       // southern and eastern
		{"+36.3506-082.6985+447.403CRSWGS_84/", 36.3506, -82.6985, 447.403}, // CRS suffix
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			m := &VideoMetadata{Properties: map[string]string{}}
			parseISO6709Location(c.in, m)
			if !closeTo(m.GPSLatitude, c.lat) || !closeTo(m.GPSLongitude, c.lon) {
				t.Errorf("got lat=%v lon=%v, want %v/%v — the integer width is being ignored, so "+
					"minutes and seconds are read as degrees", m.GPSLatitude, m.GPSLongitude,
					c.lat, c.lon)
			}
			if !closeTo(m.GPSAltitude, c.alt) {
				t.Errorf("got alt=%v, want %v", m.GPSAltitude, c.alt)
			}
		})
	}
}

// A value that cannot be a position on Earth must be dropped, not reported. This is what keeps a
// misread payload from becoming a finding — the caller relies on it when the shape is uncertain.
func TestISO6709RejectsValuesThatCannotBeAPosition(t *testing.T) {
	for _, in := range []string{
		"+91.0000-082.6985/", // latitude past the pole
		"-90.0001+010.0000/", // just past it the other way
		"+36.3506-181.0000/", // longitude past the antimeridian
		"+3699.99-07500.25/", // 99 minutes
		"+36.3506/",          // longitude missing
		"+36.35060-82.6985/", // 5 integer digits: not a legal width
		"+aa.bbbb-0cc.dddd/", // not digits
		"+36.-082.6985/",     // trailing dot with no fraction
		"",
	} {
		t.Run(in, func(t *testing.T) {
			m := &VideoMetadata{Properties: map[string]string{}}
			parseISO6709Location(in, m)
			if m.GPSLatitude != 0 || m.GPSLongitude != 0 {
				t.Errorf("%q was reported as lat=%v lon=%v; an impossible coordinate at HIGH "+
					"confidence is a false positive that also buries any real position",
					in, m.GPSLatitude, m.GPSLongitude)
			}
		})
	}
}
