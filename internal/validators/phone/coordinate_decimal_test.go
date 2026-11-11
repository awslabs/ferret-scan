// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"
)

// #938: an ISO 6709 point string (the QuickTime ©xyz atom and the XMP GPS form) and a decimal
// number written after a "00" were read as international phone numbers, at HIGH 95 for the
// degrees-and-minutes form ("+4012.22-07500.25/" as "+4012.22-07500", International_Plus) and for
// a grammar reading that replaced a capped finding ("+49.78461-159.03771/", E.164 DE), and at LOW 15
// for the rest. None of them is a phone number, and every line below is now reported at NOTHING.
func TestCoordinateAndDecimalAreNotPhoneNumbers(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		// ISO 6709 Annex H: ±DD.DD±DDD.DD/, ±DDMM.MM±DDDMM.MM/, ±DDMMSS.S±DDDMMSS.S/, with an
		// altitude and a CRS, quoted the way the repository's own comments quote them.
		`// and would have missed "+4012.22-07500.25/" entirely`,
		`measured before this change, "+4012.22-07500.25/" (40°12.22′`,
		`"+3699.99-07500.25/", // 99 minutes`,
		`//     "+49.78461-159.03771/" is ISO 6709.`,
		`// writes "+36.3506-082.6985+447.403/" with no CRS at all`,
		`"xyz: +40.7128-074.0060+000.125/",`,
		`location +40.7128-074.0060/ and +4012.22-07500.25/ and +401213.1-0750015.1/`,
		`pos +51.5007-000.1246CRSWGS_84/`,
		`com.apple.quicktime.location.ISO6709: +37.3349-122.0090+010.000/`,
		// A decimal number after the "00" international prefix: one '.' between two digit runs,
		// or a '.' beside a '-'.
		`ids "00125.37" and "00074.56695-7"`,
		`total 000104.66 EUR`,
		// A '+' before a run longer than any calling code, then a fraction: time.Time's monotonic
		// clock reading, quoted.
		`reading time.Time prints as "+9252.619193895", as isDecimalFractionTail reasons`,
		// The integer part of a decimal: an unseparated run with a fraction straight after it.
		`{"+1234567891011.234", "1234567891011.234"},`,
		`x := 0000000001.1`,
		`matching coordinates like ` + "`00074.56695-7`" + ` — to none.`,
	} {
		ms, err := v.ValidateContent(line, "geo.go")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		for _, m := range ms {
			t.Errorf("%q: reported %q at %.0f; a coordinate or a decimal is not a phone number", line, m.Text, m.Confidence)
		}
	}
}

// The controls: the numbers nearest the new rule keep their findings and their scores (measured on
// main @ 2fb4719 with this test's inputs). "+49-911/1234567" and "+49-911/ 1234567" are German numbers
// written with the area code before a '/', which an ISO 6709 point's "+DD-DDD/" also is: a '/'
// followed by a digit, or a point with no fraction and two-digit degrees, is not taken as a point.
// "+1.7035550123" is the EPP (RFC 5733) form, one '.' between two digit runs after a '+': only
// "00"-led decimals are refused.
func TestCoordinateRuleKeepsPhoneControls(t *testing.T) {
	v := NewValidator()
	for _, c := range []struct {
		line, text string
		conf       float64
	}{
		{"Tel: +34 91 496 0345", "+34 91 496 0345", 100},
		{"Phone: (212) 555-1234", "(212) 555-1234", 100},
		{"Telefon: +49-911/1234567", "+49-911/1234567", 70},
		{"Phone: +1.7035550123", "+1.7035550123", 15},
		{"Phone: +44.20.7947.0958", "+44.20.7947.0958", 100},
		{"Phone: 0044 20 7947 0958", "0044 20 7947 0958", 100},
		{"Phone: 0033 1 99 00 47 18", "0033 1 99 00 47 18", 100},
		{"call +1-415-267-1234 now", "+1-415-267-1234", 100},
		{"Call 4155550132. Then hang up", "4155550132", 15},
	} {
		ms, err := v.ValidateContent(c.line, "contacts.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		found := false
		for _, m := range ms {
			if m.Text == c.text {
				found = true
				if m.Confidence != c.conf {
					t.Errorf("%q: %q scored %.2f, want %.2f (main)", c.line, c.text, m.Confidence, c.conf)
				}
			}
		}
		if !found {
			t.Errorf("%q: %q is no longer reported (got %d findings); a real number must stay reported", c.line, c.text, len(ms))
		}
	}
}

func TestISO6709End(t *testing.T) {
	for _, c := range []struct {
		s    string
		want int // end of the point string, or -1
	}{
		{"+40.7128-074.0060/", 18},
		{"+40.7128-074.0060+000.125/", 26},
		{"+4012.22-07500.25/", 18},
		{"+401213.1-0750015.1/", 20},
		{"+4012-07500/", 12},
		{"+51.5007-000.1246CRSWGS_84/", 27},
		{"+40.7128-074.0060/+51.5-000.1/", 18},
		{"+40-075/", -1},              // two-digit degrees and no fraction: "+49-911/" is a phone's area code
		{"+49-911/1234567", -1},       // a digit after the '/'
		{"+40.7128-074.0060", -1},     // no terminating '/'
		{"+40.7128-074.0060 ", -1},    // no terminating '/'
		{"+44.20.7946.0958/", -1},     // dotted number
		{"+1-415-267-1234/", -1},      // one-digit "latitude"
		{"+404.1-074.0/", -1},         // three-digit latitude
		{"+40.1-0744.0/", -1},         // four-digit longitude
		{"+40.-074.0/", -1},           // a '.' with no fraction digits
		{"40.7128-074.0060/", -1},     // no sign
		{"+40.7128-074.0060CRS/", -1}, // a CRS with no name
		{"+40.7128-074.0060+/", -1},   // an altitude sign with no digits
		{"+40.7128-074.0060/5", -1},   // a digit after the '/'
		{"+12.3456789012345678901234567890123456789012345678901234567890123456789012345678-074.0/", -1}, // longer than a point
	} {
		if got := iso6709End(c.s, 0); got != c.want {
			t.Errorf("iso6709End(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestInISO6709Point(t *testing.T) {
	line := `pos="+40.7128-074.0060+000.125/" tel +44 20 7946 0958`
	for _, c := range []struct {
		start, end int
		want       bool
	}{
		{5, 22, true},  // "+40.7128-074.0060", the whole of lat and lon
		{13, 22, true}, // "-074.0060", from the longitude's sign
		{14, 22, true}, // "074.0060", inside the longitude
		{5, 33, false}, // runs past the '/'
		{37, 53, false},
	} {
		if got := inISO6709Point(line, c.start, c.end); got != c.want {
			t.Errorf("inISO6709Point(%q) = %t, want %t", line[c.start:c.end], got, c.want)
		}
	}
}

func TestDecimalShapedZeroZero(t *testing.T) {
	for text, want := range map[string]bool{
		"00125.37":           true,
		"00074.56695-7":      true,
		"0044.20.7946.0958":  false,
		"0044 20 7946 0958":  false,
		"0033 1 99 00 47 18": false,
		"0011874":            false,
		"+1.7035550123":      true, // decimal-shaped, but only "00"-led findings of main's are refused by it
	} {
		if got := decimalShaped(text); got != want {
			t.Errorf("decimalShaped(%q) = %t, want %t", text, got, want)
		}
	}
}

func TestIntegerPartOfDecimal(t *testing.T) {
	for _, c := range []struct {
		line, match string
		want        bool
	}{
		{"x 0000000001.1", "0000000001", true},
		{"+1234567891011.234", "+1234567891011", true},
		{"Call 4155550132.", "4155550132", false},      // a sentence's full stop
		{"Call 4155550132. Then", "4155550132", false}, // likewise
		{"415.555.0132.5", "415.555.0132", false},      // separated: not this rule's
		{"4155550132.x", "4155550132", false},
	} {
		s := strings.Index(c.line, c.match)
		if got := integerPartOfDecimal(c.match, c.line, s+len(c.match)); got != c.want {
			t.Errorf("integerPartOfDecimal(%q in %q) = %t, want %t", c.match, c.line, got, c.want)
		}
	}
}

func TestDecimalNotPhone(t *testing.T) {
	for text, want := range map[string]bool{
		"00125.37":          true,
		"00074.56695-7":     true,
		"+9252.619193895":   true,
		"+4012.22-07500":    true,
		"+1.7035550123":     false, // EPP: the '.' follows the calling code
		"+44.2079460958":    false,
		"+123.4567890":      false,
		"+44.20.7946.0958":  false,
		"+44 20 7946 0958":  false,
		"0044 20 7946 0958": false,
		"0011874":           false,
		"415.555.0132":      false,
	} {
		if got := decimalNotPhone(text); got != want {
			t.Errorf("decimalNotPhone(%q) = %t, want %t", text, got, want)
		}
	}
}
