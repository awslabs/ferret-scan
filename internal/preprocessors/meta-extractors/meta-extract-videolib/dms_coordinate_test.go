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
	"time"
)

const dmsEpsilon = 1e-9

// TestParseDMSCoordinate is the regression suite for the DMS parser. Every "was"
// note is the value the previous split-on-"deg" implementation produced.
func TestParseDMSCoordinate(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   float64
		wantOK bool
	}{
		// The shape the parser always handled.
		{"plain", `36 deg 21' 2.16" N`, 36.3506, true},

		// Prose prefix. exiftool labels its output ("GPS Position: ..."), and
		// searchForGPSInMetadata feeds this function ANY property value containing
		// "deg". The old code parsed everything left of "deg" as the degrees, so
		// ParseFloat("GPS Position: 36") failed, the error was discarded, degrees
		// stayed 0, and the minutes/seconds remainder was returned alone.
		// was: 0.350600 — plausible-looking and ~2400 km wrong.
		{"prose prefix", `GPS Position: 36 deg 21' 2.16" N`, 36.3506, true},
		{"sentence prefix", `Shot on location: 36 deg 21' 2.16" N`, 36.3506, true},
		{"key=value prefix", `lat=36 deg 21' 2.16" N`, 36.3506, true},

		// Hemisphere letter with no separating space. The old suffix test required
		// a literal " N"/" W", so this lost BOTH the seconds and the sign.
		// was: +82.683333 for a western longitude — the wrong hemisphere.
		{"no-space hemisphere W", `82 deg 41' 54.60"W`, -82.6985, true},
		{"no-space hemisphere N", `36 deg 21' 2.16"N`, 36.3506, true},
		{"lowercase hemisphere", `36 deg 21' 2.16" n`, 36.3506, true},
		{"lowercase w", `82 deg 41' 54.60"w`, -82.6985, true},

		// Leading minus. The old code parsed "-36" as the degrees then ADDED the
		// positive minutes and seconds. was: -35.649400.
		{"negative sign", `-36 deg 21' 2.16"`, -36.3506, true},

		// Signs are two spellings of one thing, never composed.
		{"south is negative", `36 deg 21' 2.16" S`, -36.3506, true},
		{"west is negative", `82 deg 41' 54.60" W`, -82.6985, true},
		{"no direction is positive", `36 deg 21' 2.16"`, 36.3506, true},

		// Partial precision still parses.
		{"minutes only", `36 deg 21'`, 36.35, true},
		{"degrees plus hemisphere", `36 deg N`, 36, true},
		{"no space before deg", `36deg 21' 2.16" N`, 36.3506, true},

		// Not coordinates. A bare "<n> deg" reaches this function from free-text
		// properties; returning a confident value for it overwrote the real
		// coordinate the ©xyz atom had already supplied.
		{"rotation prose", `Rotated 90 deg in post`, 0, false},
		{"field of view", `Field of view: 120 deg`, 0, false},
		{"bare degrees", `90 deg`, 0, false},
		{"temperature", `Temperature 21 degrees`, 0, false},
		{"no deg at all", `somewhere in the mountains`, 0, false},
		{"empty", ``, 0, false},

		// Window bounds. The regex runs on a bounded slice around "deg" for
		// performance, so anything the window could clip has to keep working:
		// a long prose prefix, and the widest realistic coordinate.
		{"long prefix", strings.Repeat("prefix words ", 40) + `36 deg 21' 2.16" N`, 36.3506, true},
		{"widest form", `-180 deg 59' 59.9999" W`, -180.99999997222223, true},
		{"long suffix", `36 deg 21' 2.16" N` + strings.Repeat(" trailing commentary", 40), 36.3506, true},
		{"both sides long", strings.Repeat("x", 200) + ` 36 deg 21' 2.16" N ` + strings.Repeat("y", 200), 36.3506, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDMSCoordinate(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseDMSCoordinate(%q) ok = %v, want %v (value %.6f)", tc.in, ok, tc.wantOK, got)
			}
			if math.Abs(got-tc.want) > dmsEpsilon {
				t.Errorf("parseDMSCoordinate(%q) = %.6f, want %.6f", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseGPSString_ProsePrefixKeepsDegrees is the end-to-end version: the
// coordinate written into the metadata (and therefore into the GPS_Coordinates
// line that the METADATA validator flags and the redactor rewrites) must be the
// real location, not the minutes/seconds remainder.
func TestParseGPSString_ProsePrefixKeepsDegrees(t *testing.T) {
	cases := []struct {
		in               string
		wantLat, wantLon float64
	}{
		{`36 deg 21' 2.16" N, 82 deg 41' 54.60" W, 447.403 m Above Sea Level`, 36.3506, -82.6985},
		{`GPS Position: 36 deg 21' 2.16" N, 82 deg 41' 54.60" W`, 36.3506, -82.6985},
		{`Location: 36 deg 21' 2.16" N, 82 deg 41' 54.60" W`, 36.3506, -82.6985},
	}

	for _, tc := range cases {
		vm := &VideoMetadata{Properties: map[string]string{}}
		parseGPSString(tc.in, vm)
		if math.Abs(vm.GPSLatitude-tc.wantLat) > dmsEpsilon || math.Abs(vm.GPSLongitude-tc.wantLon) > dmsEpsilon {
			t.Errorf("parseGPSString(%q) = (%.6f, %.6f), want (%.6f, %.6f)",
				tc.in, vm.GPSLatitude, vm.GPSLongitude, tc.wantLat, tc.wantLon)
		}
	}
}

// TestParseGPSString_NoiseDoesNotClobberRealCoordinate is the highest-impact
// case. By the time searchForGPSInMetadata walks the properties, the ©xyz atom
// may already have supplied the authoritative coordinate. parseDMSCoordinates
// assigned its parse result unconditionally, so a free-text property mentioning
// "deg" replaced a real latitude — the video's actual location was then never
// reported, and never redacted, because the emitted GPS line described somewhere
// else entirely.
func TestParseGPSString_NoiseDoesNotClobberRealCoordinate(t *testing.T) {
	for _, noise := range []string{
		`Rotated 90 deg in post`,
		`Field of view: 120 deg`,
		`Color rotated 45 deg`,
	} {
		vm := &VideoMetadata{
			Properties:   map[string]string{},
			GPSLatitude:  36.3506,
			GPSLongitude: -82.6985,
		}
		parseGPSString(noise, vm)
		if math.Abs(vm.GPSLatitude-36.3506) > dmsEpsilon || math.Abs(vm.GPSLongitude-(-82.6985)) > dmsEpsilon {
			t.Errorf("%q overwrote the real coordinate: got (%.6f, %.6f), want (36.350600, -82.698500)",
				noise, vm.GPSLatitude, vm.GPSLongitude)
		}
	}
}

// TestParseGPSString_PartialPairKeepsTheOtherHalf: a value carrying only a
// latitude (plus an altitude in the longitude slot) must not blank the longitude
// already known from the atom.
func TestParseGPSString_PartialPairKeepsTheOtherHalf(t *testing.T) {
	vm := &VideoMetadata{
		Properties:   map[string]string{},
		GPSLatitude:  0,
		GPSLongitude: -82.6985,
	}
	parseGPSString(`36 deg 21' 2.16" N, 447.403 m Above Sea Level`, vm)

	if math.Abs(vm.GPSLatitude-36.3506) > dmsEpsilon {
		t.Errorf("latitude = %.6f, want 36.350600", vm.GPSLatitude)
	}
	if math.Abs(vm.GPSLongitude-(-82.6985)) > dmsEpsilon {
		t.Errorf("longitude was clobbered: %.6f, want the known -82.698500", vm.GPSLongitude)
	}
}

// TestToProcessedContent_EmitsCorrectedCoordinate closes the loop on what the
// scanner actually sees: the GPS_Coordinates line is what the METADATA validator
// flags, so a wrong parse means the wrong location is reported AND the right one
// is never redacted.
func TestToProcessedContent_EmitsCorrectedCoordinate(t *testing.T) {
	vm := &VideoMetadata{Filename: "clip.mov", Properties: map[string]string{}}
	parseGPSString(`GPS Position: 36 deg 21' 2.16" N, 82 deg 41' 54.60" W`, vm)

	got := vm.ToProcessedContent()
	const want = "GPS_Coordinates: 36.350600, -82.698500"
	if !strings.Contains(got, want) {
		t.Errorf("processed content missing %q; got:\n%s", want, got)
	}
	// The old output. Assert it is gone so a regression cannot pass by emitting
	// both or by rounding into the old value.
	if strings.Contains(got, "0.350600, -82.698500") {
		t.Errorf("processed content still carries the degrees-dropped coordinate:\n%s", got)
	}
}

// --- file-level coverage -----------------------------------------------------
//
// The tests above pin the parsers directly. These build real MP4 containers so
// the whole extraction path runs: what the parser returns is what reaches the
// scanner, the report and the redactor.

// mp4Box assembles one MP4/QuickTime box.
func mp4Box(boxType []byte, payload []byte) []byte {
	if len(boxType) != 4 {
		panic("box type must be 4 bytes")
	}
	out := make([]byte, 0, 8+len(payload))
	out = binary.BigEndian.AppendUint32(out, uint32(8+len(payload)))
	out = append(out, boxType...)
	return append(out, payload...)
}

// mp4ItunesTag wraps text in the iTunes 'data' box an ilst entry carries.
func mp4ItunesTag(tag []byte, text string) []byte {
	payload := make([]byte, 0, 8+len(text))
	payload = binary.BigEndian.AppendUint32(payload, 1) // well-known type: UTF-8
	payload = binary.BigEndian.AppendUint32(payload, 0) // locale
	payload = append(payload, text...)
	return mp4Box(tag, mp4Box([]byte("data"), payload))
}

// atomType builds a QuickTime "©xxx" atom type. On the wire the prefix is the
// single byte 0xA9; the Go literal "©" is its two-byte UTF-8 encoding, so these
// types must be assembled byte-wise or they will not match a real file's atoms.
func atomType(suffix string) []byte {
	return append([]byte{0xA9}, suffix...)
}

// writeTestMP4 writes ftyp + moov/udta/meta/ilst(tags) + a stub mdat.
func writeTestMP4(t *testing.T, name string, tags []byte) string {
	t.Helper()

	ftyp := mp4Box([]byte("ftyp"), []byte("qt  \x00\x00\x00\x00qt  "))
	// 'meta' is a FullBox: one version byte plus three flag bytes precede its
	// children. Omitting them shifts every child header by four bytes and the
	// ilst is silently skipped.
	meta := mp4Box([]byte("meta"), append([]byte{0, 0, 0, 0}, mp4Box([]byte("ilst"), tags)...))
	file := append(ftyp, mp4Box([]byte("moov"), mp4Box([]byte("udta"), meta))...)
	file = append(file, mp4Box([]byte("mdat"), make([]byte, 64))...)

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestExtractVideoMetadata_DMSFromFile is the end-to-end form of the
// prose-prefix bug: a DMS coordinate in the container must be reported as the
// location the file actually names. On the previous parser both cases below
// reported 0.350600 — a real coordinate, roughly 2,400 km from the true one.
func TestExtractVideoMetadata_DMSFromFile(t *testing.T) {
	const dms = `GPS Position: 36 deg 21' 2.16" N, 82 deg 41' 54.60" W`

	for _, tc := range []struct {
		name string
		tag  []byte
	}{
		{"xyz atom", atomType("xyz")},  // the authoritative GPS atom
		{"free text", atomType("inf")}, // reaches the parser via searchForGPSInMetadata
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestMP4(t, "clip.mp4", mp4ItunesTag(tc.tag, dms))

			md, err := ExtractVideoMetadata(path)
			if err != nil {
				t.Fatalf("ExtractVideoMetadata: %v", err)
			}
			if math.Abs(md.GPSLatitude-36.3506) > 1e-6 || math.Abs(md.GPSLongitude-(-82.6985)) > 1e-6 {
				t.Errorf("extracted (%.6f, %.6f), want (36.350600, -82.698500)", md.GPSLatitude, md.GPSLongitude)
			}
			if got := md.ToProcessedContent(); !strings.Contains(got, "GPS_Coordinates: 36.350600, -82.698500") {
				t.Errorf("scanned text carries the wrong coordinate:\n%s", got)
			}
		})
	}
}

// TestExtractVideoMetadata_NoiseDoesNotSuppressCoordinate is the leak case, and
// the reason this is a correctness fix and not a precision one.
//
// Properties are walked in sorted key order, so "Information" is seen before
// "Warning". A latitude-only value in Information leaves the pair incomplete, so
// the sorted-walk early return does not fire and Warning is parsed too. Warning
// is not a coordinate — but the old parser returned 0 for it and the caller
// assigned unconditionally, zeroing the latitude. The emit gate requires a
// non-zero latitude or longitude, so the coordinate present in the file produced
// NO finding at all: nothing shown to the operator, and nothing for the redactor
// to remove. Confirmed on this exact shape built into a real .mp4.
func TestExtractVideoMetadata_NoiseDoesNotSuppressCoordinate(t *testing.T) {
	tags := append(
		mp4ItunesTag(atomType("inf"), `Camera heading 36 deg 21' 2.16" N`),
		mp4ItunesTag(atomType("wrn"), `Rotated 90 deg in post`)...,
	)
	path := writeTestMP4(t, "clip.mp4", tags)

	md, err := ExtractVideoMetadata(path)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata: %v", err)
	}
	if math.Abs(md.GPSLatitude-36.3506) > 1e-6 {
		t.Errorf("latitude = %.6f, want 36.350600 (free text zeroed it)", md.GPSLatitude)
	}
	// The emitted line is what the scanner sees. If it is missing, the location
	// in the file is never flagged and never redacted.
	if got := md.ToProcessedContent(); !strings.Contains(got, "GPS_Coordinates:") {
		t.Errorf("no GPS_Coordinates line emitted, so the coordinate in the file is never reported:\n%s", got)
	}
}

// TestParseDMSCoordinate_BoundedByWindowNotInputLength is the performance guard.
//
// dmsPattern begins with two groups that can match empty, so RE2 has no required
// first byte to prefilter on and its submatch engine walks every offset of
// whatever it is handed. Matching the raw property value measured 1.17 ms on a
// 32 KB input — 230x the string-split this replaced — on a path fed by free text
// out of the file. dmsSearchWindow bounds the slice the regex sees, which makes
// the cost of the match itself independent of how long the value is.
//
// Note on what is asserted: an unwindowed regex here is still LINEAR in the
// input, just with a per-byte constant roughly 120x worse, so comparing per-byte
// cost across two input sizes does not separate the two implementations — it
// passes either way. The assertion is instead against a baseline measured in this
// same test run: one strings.Index over the same string, which is the work the
// windowed path is supposed to reduce to. That keeps the test machine- and
// load-independent without being vacuous. Measured: ~4x the baseline windowed,
// ~6000x unwindowed.
func TestParseDMSCoordinate_BoundedByWindowNotInputLength(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}

	// Worst case for a scan: nothing matches until the very end of the value.
	const n = 64_000
	in := strings.Repeat("x", n) + ` 36 deg 21' 2.16" N`

	// Best-of-N with the minimum taken, which is the sample least polluted by
	// scheduling noise on a loaded machine.
	bestOf := func(body func()) time.Duration {
		const reps = 500
		best := time.Duration(math.MaxInt64)
		for attempt := 0; attempt < 3; attempt++ {
			start := time.Now()
			for i := 0; i < reps; i++ {
				body()
			}
			if d := time.Since(start) / reps; d < best {
				best = d
			}
		}
		return best
	}

	var sink int
	baseline := bestOf(func() { sink += strings.Index(in, "deg") })
	if sink == 0 {
		t.Fatal("baseline did not run")
	}

	var okAll bool
	got := bestOf(func() { _, okAll = parseDMSCoordinate(in) })
	if !okAll {
		t.Fatalf("setup: a %d-byte value ending in a coordinate should parse", n)
	}

	// Non-vacuity: without measurable baseline time the comparison is meaningless.
	if baseline <= 0 || got <= 0 {
		t.Fatalf("timing resolution too coarse to assert on: baseline=%v parse=%v", baseline, got)
	}

	ratio := float64(got.Nanoseconds()) / float64(baseline.Nanoseconds())
	t.Logf("%d bytes: parse %v vs strings.Index baseline %v — %.1fx", n, got, baseline, ratio)

	if ratio > 50 {
		t.Errorf("parse cost %.1fx a single strings.Index over the same %d-byte value (%v vs %v): the regex is scanning the whole value instead of the window",
			ratio, n, got, baseline)
	}
}

// TestParseDMSCoordinate_Deterministic guards against a future rewrite that
// reintroduces map iteration or another order-dependent step.
func TestParseDMSCoordinate_Deterministic(t *testing.T) {
	const in = `GPS Position: 36 deg 21' 2.16" N`
	first, firstOK := parseDMSCoordinate(in)
	for i := 0; i < 200; i++ {
		got, ok := parseDMSCoordinate(in)
		if got != first || ok != firstOK {
			t.Fatalf("iter %d: parseDMSCoordinate(%q) = (%.9f, %v), first = (%.9f, %v)",
				i, in, got, ok, first, firstOK)
		}
	}
}
