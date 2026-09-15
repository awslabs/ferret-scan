// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textnorm

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// The offset table is the safety-critical part of this package, so it is tested as a PROPERTY over
// every mapped rune rather than with a handful of examples.
//
// Redaction locates a finding with strings.Index(text, match.Text) and asserts the bytes match before
// writing. A span recovered through OrigSpan that is off by one would mask the wrong bytes and leave
// the value in place \u2014 a leak that looks like a redaction. That failure has happened in this
// repository before, in the IBAN path, where a 2-byte rune uppercasing to 1 byte shifted every offset
// after it: the last digit stayed in cleartext and the mask covered the preceding space.
func TestOrigSpanRecoversTheOriginalBytesForEveryMappedRune(t *testing.T) {
	// Every rune the table touches, plus the fullwidth digits.
	var mapped []rune
	for r := range canonical {
		mapped = append(mapped, r)
	}
	for r := fullwidthDigitBase; r <= fullwidthDigitBase+9; r++ {
		mapped = append(mapped, r)
	}
	if len(mapped) < 30 {
		t.Fatalf("only %d mapped runes found; the table is not being read", len(mapped))
	}

	// Each rune is placed in several positions relative to a value, because an offset bug shows up at
	// a boundary rather than in the middle.
	shapes := []string{
		"449%c87%c4100",
		"%c449874100",
		"449874100%c",
		"prefix %c 449-87-4100 suffix",
		"%c%c449%c87%c4100%c%c",
	}

	checked := 0
	for _, r := range mapped {
		for _, shape := range shapes {
			n := strings.Count(shape, "%c")
			args := make([]any, n)
			for i := range args {
				args[i] = r
			}
			original := fmt.Sprintf(shape, args...)

			normalized, offsets := Normalize(original)
			if normalized == original {
				continue // nothing changed, nothing to map
			}

			// Every span in the normalized string must map to a span of the original whose fold is
			// exactly the normalized span. That is the invariant the execguard pass relies on.
			for start := 0; start <= len(normalized); start++ {
				for end := start; end <= len(normalized); end++ {
					if !utf8.RuneStart(byteAt(normalized, start)) || !utf8.RuneStart(byteAt(normalized, end)) {
						continue // only rune-aligned spans are meaningful
					}
					oStart, oEnd := OrigSpan(offsets, start, end)
					if oStart < 0 || oEnd > len(original) || oEnd < oStart {
						t.Fatalf("rune %U shape %q: OrigSpan(%d,%d) = (%d,%d), outside [0,%d]",
							r, shape, start, end, oStart, oEnd, len(original))
					}
					if got, want := Fold(original[oStart:oEnd]), normalized[start:end]; got != want {
						t.Fatalf("rune %U shape %q span [%d,%d): original[%d:%d] = %q folds to %q, "+
							"want %q \u2014 a span that does not fold back is a mask over the wrong bytes",
							r, shape, start, end, oStart, oEnd, original[oStart:oEnd], got, want)
					}
					checked++
				}
			}
		}
	}
	t.Logf("%d mapped runes x %d shapes, %d spans verified", len(mapped), len(shapes), checked)
}

// TestByteLengthNeverGrows pins the property the offset table depends on.
func TestByteLengthNeverGrows(t *testing.T) {
	if !ByteLengthNeverGrows() {
		t.Error("a mapping grows the byte length. The offset table is indexed by RESULT byte, so a " +
			"growing mapping lets a normalized offset exceed the original length and OrigSpan clamps " +
			"\u2014 silently reporting a shorter span than the value occupies.")
	}
	// And directly: no entry may produce more bytes than it consumes.
	for r, c := range canonical {
		if c == 0 {
			continue
		}
		if utf8.RuneLen(c) > utf8.RuneLen(r) {
			t.Errorf("%U -> %U grows from %d to %d bytes", r, c, utf8.RuneLen(r), utf8.RuneLen(c))
		}
	}
}

// TestNormalizeIsIdentityForASCII: the common path must allocate nothing and change nothing.
func TestNormalizeIsIdentityForASCII(t *testing.T) {
	for _, s := range []string{
		"", "plain ascii text", "449-87-4100", "4111 1111 1111 1111",
		"tabs\tand\nnewlines\r\n", "punctuation!@#$%^&*()_+-=[]{}|;':\",./<>?",
	} {
		got, offsets := Normalize(s)
		if got != s {
			t.Errorf("Normalize(%q) = %q, want unchanged", s, got)
		}
		if offsets != nil {
			t.Errorf("Normalize(%q) returned an offset table; ASCII must use the identity mapping", s)
		}
		if HasNormalizable(s) {
			t.Errorf("HasNormalizable(%q) = true for ASCII", s)
		}
		if HasNormalizableNearDigit(s) {
			t.Errorf("HasNormalizableNearDigit(%q) = true for ASCII", s)
		}
	}
}

// TestNormalizeTable pins each family's canonical form, using \u escapes so a reviewer can see which
// rune each row is about. A literal in this repository has been wrong before.
func TestNormalizeTable(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"en dash between digits", "449\u201387\u20134100", "449-87-4100"},
		{"em dash", "449\u201487\u20144100", "449-87-4100"},
		{"non-breaking hyphen", "449\u201187\u20114100", "449-87-4100"},
		{"minus sign", "449\u221287\u22124100", "449-87-4100"},
		{"fullwidth hyphen", "449\uFF0D87\uFF0D4100", "449-87-4100"},
		{"non-breaking space", "GB82\u00A0WEST", "GB82 WEST"},
		{"figure space", "1234\u20075678", "1234 5678"},
		{"narrow nbsp", "1234\u202F5678", "1234 5678"},
		{"ideographic space", "1234\u30005678", "1234 5678"},
		{"soft hyphen is DROPPED, not dashed", "449\u00AD87\u00AD4100", "449874100"},
		{"zero width space dropped", "4111\u200B1111", "41111111"},
		{"zero width joiner dropped", "4111\u200D1111", "41111111"},
		{"word joiner dropped", "4111\u20601111", "41111111"},
		{"BOM mid-document dropped", "4111\uFEFF1111", "41111111"},
		{"fullwidth digits", "\uFF14\uFF14\uFF19", "449"},
		{"mixed", "\uFF14\uFF14\uFF19\u201387\u00AD4100", "449-874100"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Fold(c.in); got != c.want {
				t.Errorf("Fold(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestTheNarrowGateSkipsProseAndCatchesValues is the precision/cost gate's own table.
//
// The broad gate fired on 56.4% of 1,506 real documents and cost +59% wall clock for 8 findings; the
// narrow one fires on 17.9% and costs +22% for the same recall. These rows are what keeps that
// distinction from eroding.
func TestTheNarrowGateSkipsProseAndCatchesValues(t *testing.T) {
	mustFire := []string{
		"SSN 449\u201387\u20134100",            // dash between digits
		"IBAN GB82\u00A0WEST 1234",             // space after a digit
		"449\u00AD87\u00AD4100",                // soft hyphen between digits
		"4111\u200B1111\u200B1111",             // zero-width space between digits
		"AKIAIOSFODNN\uFF17EXAMPLE",            // a fullwidth digit is its own trigger
		"call 415\u2013555\u20130142",          // phone
		"\uFF14\uFF14\uFF19\uFF0D\uFF18\uFF17", // all fullwidth
	}
	mustSkip := []string{
		"a long\u2010term plan",                // prose hyphen, no digits
		"MACsec\u2011encrypted links",          // prose non-breaking hyphen
		"endpoints\u2014dataplane and control", // prose em dash
		"Flushing Meadows\u2013Corona Park",    // a place name
		"Francisco,\u00A0Contact the team",     // NBSP between words
		"plain ascii with 449-87-4100",         // ASCII: nothing to normalize
	}
	for _, s := range mustFire {
		if !HasNormalizableNearDigit(s) {
			t.Errorf("gate did not fire on %q \u2014 a structured value written with substituted "+
				"characters must be reachable, or the recall this package exists for is lost", s)
		}
	}
	for _, s := range mustSkip {
		if HasNormalizableNearDigit(s) {
			t.Errorf("gate fired on %q \u2014 prose has no digit beside the substitution, and firing here "+
				"is what cost +59%% wall clock for false positives", s)
		}
	}
}

// byteAt returns s[i], or 0 one past the end so a boundary index is rune-aligned.
func byteAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}
