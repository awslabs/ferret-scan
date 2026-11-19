// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"
)

// #1019: the sixteen blocks of Ofcom's "Telephone numbers for use in TV and radio drama programmes"
// (https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama, last updated
// 11 May 2023, read through the Internet Archive's copy of 2024-12-23) that #930 left at PHONE 100.
// Each block is head (the trunk "0" and the area or range code) + mid + lead + "000" .. lead + "999".
// main @ 3b9780b read every first and last number below at 100.
type ofcomBlock struct{ name, head, mid, lead string }

var ofcomDramaBlocks = []ofcomBlock{
	{"Leeds", "0113", "496", "0"},
	{"Sheffield", "0114", "496", "0"},
	{"Nottingham", "0115", "496", "0"},
	{"Leicester", "0116", "496", "0"},
	{"Bristol", "0117", "496", "0"},
	{"Reading", "0118", "496", "0"},
	{"Birmingham", "0121", "496", "0"},
	{"Edinburgh", "0131", "496", "0"},
	{"Glasgow", "0141", "496", "0"},
	{"Liverpool", "0151", "496", "0"},
	{"Tyneside", "0191", "498", "0"},
	{"Northern Ireland", "028", "9649", "6"},
	{"Cardiff", "029", "2018", "0"},
	{"freephone", "0808", "157", "0"},
	{"premium rate", "0909", "879", "0"},
	{"UK-wide", "0306", "999", "0"},
}

// spellings returns the number as "head mid xxxx" nationally, the same without spaces, and with +44.
func (b ofcomBlock) spellings(tail string) []string {
	nat := b.head + " " + b.mid + " " + b.lead + tail
	return []string{nat, strings.ReplaceAll(nat, " ", ""), "+44 " + nat[1:]}
}

func TestOfcomDramaBlocksAreHeldAtLow(t *testing.T) {
	for _, b := range ofcomDramaBlocks {
		for _, tail := range []string{"000", "999"} { // the first and the last number of the block
			for _, text := range b.spellings(tail) {
				t.Run(b.name+"/"+text, func(t *testing.T) {
					m := wantOneWhole(t, "Phone: "+text, text)
					if m.Confidence > reservedFictionalCeiling {
						t.Errorf("%q scored %.0f, want at most %.0f", text, m.Confidence, reservedFictionalCeiling)
					}
					if m.Metadata[confidenceCeilingKey] != reservedFictionalCeiling {
						t.Errorf("%q: confidence_ceiling = %v, want a published %.0f", text, m.Metadata[confidenceCeilingKey], reservedFictionalCeiling)
					}
				})
			}
		}
	}
}

// One digit away from each block keeps the 100 main gives it: the digit before the block's last three
// (lead + 1: "496 1000") and the last digit of its middle group ("497 0000"), at both ends.
func TestOfcomDramaBlockNeighboursKeepTheirScore(t *testing.T) {
	next := func(s string) string { return s[:len(s)-1] + string(rune(s[len(s)-1]-'0'+1)%10+'0') }
	for _, b := range ofcomDramaBlocks {
		for _, n := range []struct{ name, text string }{
			{"lead", b.head + " " + b.mid + " " + next(b.lead) + "000"},
			{"lead-last", b.head + " " + b.mid + " " + next(b.lead) + "999"},
			{"mid", b.head + " " + next(b.mid) + " " + b.lead + "000"},
			{"mid-last", b.head + " " + next(b.mid) + " " + b.lead + "999"},
		} {
			t.Run(b.name+"/"+n.name+"/"+n.text, func(t *testing.T) {
				m := wantOneWhole(t, "Phone: "+n.text, n.text)
				if m.Confidence != 100 {
					t.Errorf("%q scored %.0f, want 100 (main)", n.text, m.Confidence)
				}
				if _, ok := m.Metadata[confidenceCeilingKey]; ok {
					t.Errorf("%q: published confidence_ceiling %v, want none", n.text, m.Metadata[confidenceCeilingKey])
				}
			})
		}
	}
	// Ofcom's page no longer lists Northern Ireland's old 028 9018 0xxx block (Wikipedia still does), so
	// it is not held.
	m := wantOneWhole(t, "Phone: 028 9018 0123", "028 9018 0123")
	if m.Confidence != 100 {
		t.Errorf("028 9018 0123 scored %.0f, want 100", m.Confidence)
	}
}

// Every prefix in ofcomDramaPrefixes is 7 digits and unique, and the pre-filter accepts the first number
// of each: a block listed with a wrong length would hold nothing and fail no other test.
func TestOfcomDramaPrefixesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range ofcomDramaPrefixes {
		if len(p) != 7 || seen[p] {
			t.Errorf("prefix %q: want 7 digits and no repeat", p)
		}
		seen[p] = true
		if !mayBeReservedFictional("0" + p + "000") {
			t.Errorf("mayBeReservedFictional rejects the first number of %q", p)
		}
	}
	if want := 4 + len(ofcomDramaBlocks); len(ofcomDramaPrefixes) != want { // #930's four and #1019's sixteen
		t.Errorf("%d prefixes, want %d", len(ofcomDramaPrefixes), want)
	}
}
