// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "testing"

// #930: Ofcom's drama numbers read PHONE 100 HIGH on main @ 2fb4719 in every form below, with a phone
// label. They are held at reservedFictionalCeiling with the ceiling published, as NANP's 555-01xx is:
// still reported, so still redacted, never MEDIUM or HIGH.
func TestOfcomDramaNumbersAreHeldAtLow(t *testing.T) {
	for _, c := range []struct{ line, text string }{
		{"Phone: 020 7946 0991", "020 7946 0991"},
		{"Phone: 020 7946 0000", "020 7946 0000"},
		{"Phone: (020) 7946 0958", "(020) 7946 0958"},
		{"Phone: 02079460958", "02079460958"},
		{"call 020-7946-0372 now", "020-7946-0372"},
		{"Phone: 01632 960123", "01632 960123"},
		{"Phone: 01632 960999", "01632 960999"},
		{"Phone: 07700 900123", "07700 900123"},
		{"Mobile: 07700900456", "07700900456"},
		{"Phone: +44 20 7946 0958", "+44 20 7946 0958"},
		{"Phone: +44 1632 960123", "+44 1632 960123"},
		{"Phone: +44 7700 900123", "+44 7700 900123"},
		{"Phone: +442079460958", "+442079460958"},
		{"Phone: 0044 20 7946 0958", "0044 20 7946 0958"},
		{"Phone: +44 (0)20 7946 0958", "+44 (0)20 7946 0958"},
		{"Tel: 020 7946 0123 ext 42", "020 7946 0123"},
	} {
		m := wantOneWhole(t, c.line, c.text)
		if m.Confidence > reservedFictionalCeiling {
			t.Errorf("%q: %q scored %.0f, want at most %.0f", c.line, c.text, m.Confidence, reservedFictionalCeiling)
		}
		if m.Metadata[confidenceCeilingKey] != reservedFictionalCeiling {
			t.Errorf("%q: confidence_ceiling = %v, want a published %.0f", c.line, m.Metadata[confidenceCeilingKey], reservedFictionalCeiling)
		}
	}
}

// The controls: one digit outside each block, and the Manchester block's "0161 496 0000", which the
// score corpus holds as a real UK number, keep the 100 they score on main.
func TestOfcomDramaNeighboursKeepTheirScore(t *testing.T) {
	for _, c := range []struct{ line, text string }{
		{"Phone: 020 7946 1991", "020 7946 1991"},
		{"Phone: 020 7947 0991", "020 7947 0991"},
		{"Phone: 01632 961123", "01632 961123"},
		{"Phone: 01632 950123", "01632 950123"},
		{"Phone: 07700 901123", "07700 901123"},
		{"Phone: 07700 800123", "07700 800123"},
		{"Phone: +44 20 7946 1958", "+44 20 7946 1958"},
		{"Phone: +44 1632 961123", "+44 1632 961123"},
		{"Phone: +44 7700 910123", "+44 7700 910123"},
		{"Phone: 0161 496 0000", "0161 496 0000"},
		{"Phone: 020 7123 4567", "020 7123 4567"},
	} {
		m := wantOneWhole(t, c.line, c.text)
		if m.Confidence != 100 {
			t.Errorf("%q: %q scored %.0f, want 100 (main)", c.line, c.text, m.Confidence)
		}
		if _, ok := m.Metadata[confidenceCeilingKey]; ok {
			t.Errorf("%q: published confidence_ceiling %v, want none", c.line, m.Metadata[confidenceCeilingKey])
		}
	}
}

func TestIsOfcomDramaNumber(t *testing.T) {
	for clean, want := range map[string]bool{
		"02079460000":    true,
		"02079460999":    true,
		"01632960000":    true,
		"07700900999":    true,
		"+442079460958":  true,
		"+4402079460958": true, // "+44 (0)20 ..."
		"00442079460958": true,
		"02079461000":    false,
		"0207946095":     false, // a digit short
		"020794609581":   false, // a digit long
		"442079460958":   false, // no "+" or "00": not an international form
		"+12079460958":   false,
		"00012079460958": false,
		"+4407700900123": true,
		"+447700900123":  true,
		"0161 496 0000":  false,
	} {
		if got := isOfcomDramaNumber(clean); got != want {
			t.Errorf("isOfcomDramaNumber(%q) = %t, want %t", clean, got, want)
		}
	}
}

func TestMayBeReservedFictional(t *testing.T) {
	for clean, want := range map[string]bool{
		"4155550142":    true,
		"02079460958":   true,
		"+441632960123": true,
		"07700900123":   true,
		"02071234567":   false,
	} {
		if got := mayBeReservedFictional(clean); got != want {
			t.Errorf("mayBeReservedFictional(%q) = %t, want %t", clean, got, want)
		}
	}
}
