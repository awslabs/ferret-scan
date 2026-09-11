// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"strings"
	"testing"
)

// TestMetadataWindowDoesNotDependOnFoldedByteLength is the regression for #659.
//
// searchMetadataPatternsInData locates one of eleven marker words in a case-folded
// copy of the data and then cuts a +/-50 byte window out of the ORIGINAL. Unicode
// case mapping is not byte-length-preserving, so the two were different coordinate
// spaces and the window landed in the wrong place.
//
// This is the INVERSE of the shape fixed in #658: there an offset from the original
// indexed the folded copy and overshot, which panicked. Here the offset comes from
// the folded copy and indexes the original, so it can only ever be too SMALL --
// idx <= len(lowerData) <= len(data) when the fold shrinks -- and `end` is clamped.
// A panic is therefore impossible, which is exactly why this went unnoticed: the
// only symptom is a window over the wrong bytes.
//
// `data` is a 5MB chunk of RAW FILE BYTES (searchForCombinedMetadata), gated only on
// isValidUTF8Subset, so every byte of it is attacker-controlled. The window's content
// becomes a Property, and Properties are emitted as scannable text -- so a shifted
// window drops a sensitive value out of everything downstream, and because only
// reported findings reach the redactor, the value then survives redaction.
//
// The controls are byte-length-identical, which is the only comparison that isolates
// folding: simply removing the hostile runes would shift every following offset for a
// reason that has nothing to do with case mapping.
func TestMetadataWindowDoesNotDependOnFoldedByteLength(t *testing.T) {
	// U+212A KELVIN SIGN: 3 bytes, folds to 1. Visually an ASCII "K".
	const kelvin = "\u212a" // U+212A KELVIN SIGN: 3 bytes, folds to 1. Written as an
	// escape because it is visually identical to an ASCII "K" -- a first draft had one
	// of each and the ASCII one silently tested nothing.
	// U+023A: 2 bytes, folds to 3 — the GROW direction. Here it makes idx point PAST
	// the value, so the guard skips and the property is dropped entirely.
	const grow = "\u023a" // 2 bytes, folds to 3 -- the GROW direction

	// "user" is one of the eleven markers; the SSN sits inside the +/-50 window.
	const tail = " padding text user metadata SSN 219-09-9999 tail padding more"

	cases := []struct {
		name         string
		hostile      string
		bytesPerRune int
	}{
		{"shrink, U+212A", kelvin, 3},
		{"grow, U+023A", grow, 2},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, n := range []int{1, 4, 10, 20, 40} {
				hostileData := "HEADER " + strings.Repeat(c.hostile, n) + tail
				controlData := "HEADER " + strings.Repeat("q", c.bytesPerRune*n) + tail
				if len(hostileData) != len(controlData) {
					t.Fatalf("fixture bug at n=%d: hostile %d bytes vs control %d",
						n, len(hostileData), len(controlData))
				}

				hostile := &VideoMetadata{Properties: map[string]string{}}
				control := &VideoMetadata{Properties: map[string]string{}}
				searchMetadataPatternsInData(hostileData, hostile)
				searchMetadataPatternsInData(controlData, control)

				// Non-vacuity: the control must actually capture the SSN, or "same as
				// control" is satisfied by both capturing nothing.
				got := control.Properties["User_Reference"]
				if !strings.Contains(got, "219-09-9999") {
					t.Fatalf("n=%d: the CONTROL window does not contain the SSN (%q); the "+
						"fixture no longer positions the value inside the +/-50 window, so "+
						"this comparison asserts nothing", n, got)
				}

				// The assertion is CONTAINMENT, not byte-equality.
				//
				// The window is cut from the ORIGINAL data, so it necessarily includes the
				// padding bytes themselves — and those differ by construction: the hostile
				// run is U+212A, which the printable-ASCII filter turns into spaces, while
				// the control run is 'q'. A first draft compared the two windows byte for
				// byte and failed on the FIXED code for that reason. The invariant is that
				// the value is still inside the window, which is what decides whether
				// anything downstream can report it.
				if h := hostile.Properties["User_Reference"]; !strings.Contains(h, "219-09-9999") {
					t.Errorf("n=%d (%d bytes, identical to the control): the window no longer "+
						"contains the value.\n  control: %q\n  hostile: %q\n"+
						"A byte-length-changing rune must not move the window off the value. "+
						"Losing it here means nothing downstream can report it, and an "+
						"unreported value is not redacted.", n, len(hostileData), got, h)
				}
			}
		})
	}
}

// TestEveryMarkerWindowIsStable widens the same check to all eleven markers, because
// the window is cut per marker and each has a different offset in the data.
func TestEveryMarkerWindowIsStable(t *testing.T) {
	markers := []string{"EXIF", "XMP", "IPTC", "Canon", "Nikon", "Sony",
		"iPhone", "Android", "QuickTime", "user", "location"}
	const kelvin = "\u212a" // U+212A KELVIN SIGN: 3 bytes, folds to 1. Written as an
	// escape because it is visually identical to an ASCII "K" -- a first draft had one
	// of each and the ASCII one silently tested nothing.

	for _, marker := range markers {
		t.Run(marker, func(t *testing.T) {
			body := " lead " + marker + " SSN 219-09-9999 trail padding text here"
			hostileData := "HEAD " + strings.Repeat(kelvin, 12) + body
			controlData := "HEAD " + strings.Repeat("q", 36) + body
			if len(hostileData) != len(controlData) {
				t.Fatalf("fixture bug: %d vs %d bytes", len(hostileData), len(controlData))
			}

			hostile := &VideoMetadata{Properties: map[string]string{}}
			control := &VideoMetadata{Properties: map[string]string{}}
			searchMetadataPatternsInData(hostileData, hostile)
			searchMetadataPatternsInData(controlData, control)

			// Compare EVERY property, not just the one this marker names: markers
			// overlap ("user" is a substring of nothing here, but "XMP"/"IPTC" can
			// co-occur), and a shifted window for any of them is the same defect.
			if len(control.Properties) == 0 {
				t.Fatalf("control captured no properties for marker %q, so this asserts nothing", marker)
			}
			// Containment again, and only for the properties whose control window
			// actually held the value — see the note in the test above on why byte
			// equality is the wrong comparison here.
			checked := 0
			for k, want := range control.Properties {
				if !strings.Contains(want, "219-09-9999") {
					continue
				}
				checked++
				if got := hostile.Properties[k]; !strings.Contains(got, "219-09-9999") {
					t.Errorf("property %q lost the value for marker %q:\n  control: %q\n  hostile: %q",
						k, marker, want, got)
				}
			}
			if checked == 0 {
				t.Fatalf("no control property for marker %q contained the value, so this "+
					"subtest asserts nothing; the fixture no longer positions the SSN inside "+
					"the +/-50 window", marker)
			}
			if len(hostile.Properties) != len(control.Properties) {
				t.Errorf("marker %q: hostile captured %d properties, control %d — a property "+
					"was dropped entirely, which is what a GROWING rune does when the bounds "+
					"guard skips the assignment",
					marker, len(hostile.Properties), len(control.Properties))
			}
		})
	}
}

// TestTheFoldIsComputedOnce guards the performance half of the fix.
//
// The previous code called strings.ToLower(data) TWICE per pattern for eleven
// patterns — 22 full-string lowercases of a chunk up to 5MB — once for a Contains
// test and again for the Index. Folding once is not a micro-optimisation at that
// size; it is the difference between one pass and twenty-two.
//
// Asserted through allocation count rather than time, which is stable in CI.
func TestTheFoldIsComputedOnce(t *testing.T) {
	// Large enough that a per-pattern fold dominates, small enough to stay fast.
	data := strings.Repeat("some video header bytes with user and EXIF markers ", 400)
	md := &VideoMetadata{Properties: map[string]string{}}

	allocs := testing.AllocsPerRun(5, func() {
		md.Properties = map[string]string{}
		searchMetadataPatternsInData(data, md)
	})

	// One fold of the data, plus per-marker pattern folds and the window builders.
	// Twenty-two folds of a 20KB string would be far above this.
	const ceiling = 60
	if allocs > ceiling {
		t.Errorf("searchMetadataPatternsInData allocated %.0f times on a %d-byte input, "+
			"ceiling %d. The data fold is meant to happen ONCE before the marker loop; "+
			"this many allocations suggests it moved back inside it.",
			allocs, len(data), ceiling)
	}
	t.Logf("%.0f allocations for a %d-byte input", allocs, len(data))
}

// TestMarkerInAKeyPathIsNotContent pins the rule that keeps the corrected offset from
// re-exposing what #507 fixed.
//
// Correcting the window offset made TestAgainstTheRealFile fail — not because the fix
// was wrong, but because that test had been passing by ACCIDENT: the misaligned window
// happened to land off the key path, and once the offset was right it landed squarely
// on com.apple.quicktime.pixeldensity. The rule that test states ("no property may
// hold a key name") is now enforced where the property is created.
func TestMarkerInAKeyPathIsNotContent(t *testing.T) {
	cases := []struct {
		name   string
		data   string
		marker string
		want   bool
	}{
		{"reverse-DNS key path", "mdtacom.apple.quicktime.pixeldensity", "quicktime", true},
		{"key path, marker first segment", "x location.latitude y", "location", true},
		{"marker as its own word", " padding text user metadata SSN ", "user", false},
		{"marker followed by a sentence stop", "the item is located. next", "located", false},
		{"marker at the very start", "user data follows", "user", false},
		{"marker at the very end", "trailing user", "user", false},
		{"dot before AND identifier after", "a.user.b", "user", true},
		{"dot after but nothing follows", "user.", "user", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := strings.Index(c.data, c.marker)
			if idx < 0 {
				t.Fatalf("fixture bug: %q does not contain %q", c.data, c.marker)
			}
			if got := markerIsPartOfKeyPath(c.data, idx, len(c.marker)); got != c.want {
				t.Errorf("markerIsPartOfKeyPath(%q, marker %q) = %v, want %v",
					c.data, c.marker, got, c.want)
			}
		})
	}
}

// TestAKeyPathMarkerProducesNoProperty is the same rule at the function level, so a
// regression shows up as the observable behaviour rather than as a helper's verdict.
func TestAKeyPathMarkerProducesNoProperty(t *testing.T) {
	// Shaped like the real .mov: atom names and a reverse-DNS key path, no content.
	schema := "ta   8keys   (mdtacom.apple.quicktime.pixeldensity   0ilst   (   data"
	md := &VideoMetadata{Properties: map[string]string{}}
	searchMetadataPatternsInData(schema, md)
	for k, v := range md.Properties {
		if strings.Contains(strings.ToLower(v), "apple.quicktime") {
			t.Errorf("property %q = %q holds a key name; container schema is not scannable content", k, v)
		}
	}

	// And the useful case must survive: a marker standing as its own word next to a
	// real value still yields the window. Without this, "reject key paths" could be
	// satisfied by rejecting everything.
	content := "HEADER padding text user metadata SSN 219-09-9999 tail padding"
	md2 := &VideoMetadata{Properties: map[string]string{}}
	searchMetadataPatternsInData(content, md2)
	if got := md2.Properties["User_Reference"]; !strings.Contains(got, "219-09-9999") {
		t.Errorf("User_Reference = %q, want it to contain the value — the key-path rule "+
			"must not suppress a marker that stands as its own word", got)
	}
}
