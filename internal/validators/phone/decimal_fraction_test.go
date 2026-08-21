// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"
)

// A decimal number's FRACTIONAL digits must not be read as the start of a phone
// number.
//
// isEmbeddedInIdentifierAt treated '[a-z] [A-Z] [0-9] - _' as evidence of
// embedding but not '.', so a match was allowed to begin immediately after a
// decimal point. "35.008 31.354" matched as "008 31.354", and because a leading
// "00" reads as an international dialing prefix it scored HIGH 100 -- higher than
// a real "Phone: 415-555-0132", which scores 15.
//
// Measured on the public AWS Architecture Icons package (1,842 .svg, 4,012 files)
// before this guard: 15,514 findings, 13,790 of them HIGH, essentially all PHONE
// claiming ".00xx" path coordinates. SVG path data carries four decimal places so
// ".00xx" turns up in about 1% of coordinates. After: 1,463 / 1,270, and the
// entire remainder is a DIFFERENT defect (a "@5x" filename read as an email
// address, #444) rather than anything this arm governs.
func TestDecimalFractionIsNotAPhoneNumber(t *testing.T) {
	v := NewValidator()

	// Every case here is a real content shape, not an invented one: bare coordinate
	// pairs as they appear in a CSV, an SVG path attribute copied from a stock icon,
	// and a GeoJSON coordinates array.
	cases := []struct {
		name string
		line string
	}{
		{"csv coordinate pair", "35.008 31.354"},
		{"csv coordinate pair, other fraction", "35.009 31.354"},
		{"four-decimal precision", "32.0078 31.3992"},
		{"svg path attribute", `<path d="M32.6982,23.9008 C33.0592,24.3698 32.0078 31.3992"/>`},
		{"geojson coordinates", `{"coordinates":[[-122.0078,31.3992],[-122.0091,31.4002]]}`},
		{"leading zero run", "1.0012 34.5678"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches, err := v.ValidateContent(c.line, "geo.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				got := make([]string, 0, len(matches))
				for _, m := range matches {
					got = append(got, m.Text)
				}
				t.Errorf("a decimal fraction was reported as a phone number: %s\n  matched %v\n"+
					"  the fractional digits of a number are not a dialing prefix, and reporting them "+
					"at HIGH means over-redaction of ordinary coordinate data", c.line, got)
			}
		})
	}
}

// The other direction, and the reason the guard is not simply "a '.' before the
// match means embedded".
//
// DOTTED PHONE NOTATION puts the match immediately after a digit and a '.' too:
// in "1.415.555.0132" the reported match is "415.555.0132", preceded by '.'
// preceded by '1'. A guard keyed on the neighbour alone would delete it, and
// because only reported findings reach the redactor that would leave a real
// number in cleartext -- trading a false positive for a leak.
//
// The discriminator is the separator after the match's first digit group: a
// dotted number continues with dots, whereas "008 31.354" changes separator
// immediately, which is what shows it has run out of one number and across a
// boundary into the next.
func TestDottedAndInternationalPhonesStillReport(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
	}{
		{"dotted, with a country code", "1.415.555.0132"},
		{"dotted, with a country code and label", "Phone: 1.415.555.0132"},
		{"dotted, bare", "415.555.0132"},
		{"dotted, mid sentence", "Tel 1.415.555.0132 ext 4"},
		{"plus international", "+44 20 7946 0958"},
		{"00 international prefix", "0044 20 7946 0958"},
		{"001 international prefix", "001 415 555 0132"},
		{"labelled NANP", "Phone: 415-555-0132"},
		{"parenthesised NANP", "Phone: (415) 555-0132"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches, err := v.ValidateContent(c.line, "directory.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("a real phone number stopped being reported: %s\n  only reported findings "+
					"reach the redactor, so suppressing this leaves the number in cleartext", c.line)
			}
		})
	}
}

// isDecimalFractionTail is unit-tested directly, because the interesting cases are
// boundary conditions that are awkward to reach through a whole validator run and
// easy to get wrong in the direction that deletes findings.
func TestIsDecimalFractionTail(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		match string
		want  bool
	}{
		// The defect: the match is the fraction of "35.008" and runs on into the next number.
		{"fraction then space", "35.008 31.354", "008 31.354", true},
		{"fraction, all digits", "35.008", "008", true},

		// Dotted phone notation: same neighbour, must NOT be treated as embedded.
		{"dotted phone after country code", "1.415.555.0132", "415.555.0132", false},

		// Not a decimal point at all.
		{"no digit before the dot", "v.4155550132", "4155550132", false},
		{"dot at line start", ".4155550132", "4155550132", false},

		// matchIndex < 2 cannot have "digit dot" before it.
		{"match at index 0", "4155550132", "4155550132", false},
		{"match at index 1", ".4155550132"[1:], "4155550132", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := strings.Index(c.line, c.match)
			if idx < 0 {
				t.Fatalf("test setup: %q does not contain %q", c.line, c.match)
			}
			if got := isDecimalFractionTail(c.line, idx, c.match); got != c.want {
				t.Errorf("isDecimalFractionTail(%q, %d, %q) = %v, want %v",
					c.line, idx, c.match, got, c.want)
			}
		})
	}
}

// The false positive outranked the true positive, which is why this is a HIGH-band
// defect and not a cosmetic one: a coordinate scored 100 while a labelled phone
// number scored 15. This pins the ordering rather than either absolute number, so
// it survives a future rebalance of the confidence table.
func TestARealPhoneOutranksNothingItShouldNot(t *testing.T) {
	v := NewValidator()

	real, err := v.ValidateContent("Phone: 415-555-0132", "directory.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(real) == 0 {
		t.Fatal("the labelled phone number is not reported at all, so there is no ordering to check")
	}

	coord, err := v.ValidateContent("35.008 31.354", "geo.csv")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(coord) != 0 {
		t.Fatalf("the coordinate is still reported at %.0f%% while the real number is at %.0f%% -- "+
			"a false positive must never outrank a true one",
			coord[0].Confidence, real[0].Confidence)
	}
}
