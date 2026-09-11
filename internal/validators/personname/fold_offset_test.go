// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// TestGeoProximityDoesNotDependOnFoldedByteLength pins the fix at the package that
// owns it, so a regression names personname rather than only failing the
// cross-validator guard in pkg/scan.
//
// The defect: analyzeContextCached is called with patternMatch.StartIndex (a LINE
// offset — proved by c.Text = line[c.StartIndex:c.EndIndex]), matchIndex returns it
// verbatim as an offset into cache.lowerLine, and nearestWithin then compares it
// against geo/business/product indices found IN lowerLine. Two coordinate spaces.
// strings.ToLower is not byte-length-preserving, so any such rune earlier in the
// line made the proximity distance wrong.
//
// It is an integer comparison and not a slice, so nothing panicked and no
// disclosure channel could see it — which is why it survived #658.
//
// The controls are byte-length-identical on purpose. Simply removing the hostile
// rune would shift every offset after it, so a shorter control would differ for
// reasons unrelated to folding; ASCII 'q' folds to itself and is not a keyword.
func TestGeoProximityDoesNotDependOnFoldedByteLength(t *testing.T) {
	v := NewValidator()

	// U+212A KELVIN SIGN: 3 bytes, folds to 1. Visually an ASCII "K".
	const kelvin = "K"
	// U+023A: 2 bytes, folds to 3 — the GROW direction, which corrupts silently.
	const grow = "Ⱥ"

	cases := []struct {
		name           string
		hostileRune    string
		bytesPerRune   int
		repeats        int
		lineFmt        string
		wantSameAsCtrl bool
	}{
		{"shrink, 2 runes", kelvin, 3, 2, "Jonathan Whitfield %s street", true},
		{"shrink, 4 runes", kelvin, 3, 4, "Jonathan Whitfield %s street", true},
		{"shrink, 20 runes", kelvin, 3, 20, "Jonathan Whitfield %s street", true},
		{"grow, 2 runes", grow, 2, 2, "Jonathan Whitfield %s street", true},
		{"shrink before a street address", kelvin, 3, 4,
			"Ship to %s Marcus Whitfield, 1247 Oakmont Street, Springfield", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hostile := strings.Replace(c.lineFmt, "%s", strings.Repeat(c.hostileRune, c.repeats), 1)
			control := strings.Replace(c.lineFmt, "%s", strings.Repeat("q", c.bytesPerRune*c.repeats), 1)
			if len(hostile) != len(control) {
				t.Fatalf("fixture bug: hostile %d bytes vs control %d — the comparison would "+
					"attribute an offset shift to folding", len(hostile), len(control))
			}

			hm, err := v.ValidateContent(hostile+"\n", "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(hostile): %v", err)
			}
			cm, err := v.ValidateContent(control+"\n", "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(control): %v", err)
			}

			// Non-vacuity: the control must actually find the name, or "same as
			// control" is trivially satisfied by finding nothing in either.
			if len(cm) == 0 {
				t.Fatalf("control produced no findings, so this comparison asserts nothing")
			}

			if len(hm) != len(cm) {
				t.Fatalf("finding COUNT differs: hostile %d, control %d", len(hm), len(cm))
			}
			for i := range cm {
				if hm[i].Confidence != cm[i].Confidence {
					t.Errorf("confidence differs: hostile %.1f, control %.1f (same %d input bytes).\n"+
						"A byte-length-changing rune must not steer confidence: at %.1f versus %.1f "+
						"the finding can cross the band a reviewer filters on, and a demoted finding "+
						"that falls below the reporting threshold is never redacted.",
						hm[i].Confidence, cm[i].Confidence, len(hostile), hm[i].Confidence, cm[i].Confidence)
				}
			}
		})
	}
}

// TestTheDefectRequiredBothSpaces documents WHY bytefold is the fix rather than a
// bounds check: the two offsets have to agree, not merely be in range.
//
// A clamp would have turned the wrong-distance bug into a different wrong-distance
// bug, silently, because nothing here is out of range — the offsets are simply
// measured against different strings. Byte-length preservation makes them the same
// coordinate space by construction, which is the only fix that needs no further
// reasoning at each use site.
func TestTheDefectRequiredBothSpaces(t *testing.T) {
	const line = "Jonathan Whitfield KK street"
	folded := strings.ToLower(line)
	if len(folded) >= len(line) {
		t.Fatal("premise stale: strings.ToLower no longer shrinks this line, so the " +
			"desynchronisation this test describes cannot occur and it must be revisited")
	}
	// The gap is exactly what the proximity distance was wrong by.
	if gap := len(line) - len(folded); gap != 4 {
		t.Errorf("expected the fold to lose 4 bytes (2 x U+212A, 3 bytes -> 1), lost %d", gap)
	}
}
