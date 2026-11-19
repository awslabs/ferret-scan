// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "testing"

// #1026: ARCEP's six blocks of 10,000 numbers for audiovisual works, from the "Numéros pour œuvres
// audiovisuelles" section of its "Plan national de numérotation" (version of 1 January 2026, annex to
// decision n° 2018-0881, https://www.arcep.fr/uploads/tx_gsavis/18-0881.pdf). Its roots are
// "0ZABPQ = 01 99 00, 02 61 91, 03 53 01, 04 65 71, 05 36 49, 06 39 98"; a block is the root and any
// four digits. main @ 3b9780b read every number below at PHONE 100: "+33 1 99 00 47 18" is #1026's.
var arcepFictionBlocks = []struct{ z, ab, pq string }{
	{"1", "99", "00"},
	{"2", "61", "91"},
	{"3", "53", "01"},
	{"4", "65", "71"},
	{"5", "36", "49"},
	{"6", "39", "98"},
}

// arcepSpellings are the ways a French number is written that the phone check reports on a labelled
// line. The spaced national form ("01 99 00 47 18") is not among them: main reports no phone number
// for any French number so written ("01 23 45 67 89" too), a separate gap from this one.
func arcepSpellings(z, ab, pq, tail string) []string {
	ab4 := ab + pq + tail // the eight digits after Z
	return []string{
		"+33 " + z + " " + ab + " " + pq + " " + tail[:2] + " " + tail[2:],
		"+33" + z + ab4,
		"+33." + z + "." + ab + "." + pq + "." + tail[:2] + "." + tail[2:],
		"0033 " + z + " " + ab + " " + pq + " " + tail[:2] + " " + tail[2:],
		"+33 (0)" + z + " " + ab + " " + pq + " " + tail[:2] + " " + tail[2:],
		"0" + z + ab4, // national, compact
	}
}

func TestArcepFictionBlocksAreHeldAtLow(t *testing.T) {
	for _, b := range arcepFictionBlocks {
		for _, tail := range []string{"0000", "9999"} { // the first and the last number of the block
			for _, text := range arcepSpellings(b.z, b.ab, b.pq, tail) {
				t.Run(b.z+b.ab+b.pq+"/"+text, func(t *testing.T) {
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

// One digit away from each block keeps the 100 main gives it: the last digit of the root's last pair
// (PQ), the first digit of it, and the same two digits of the middle pair (AB), at both ends.
func TestArcepFictionNeighboursKeepTheirScore(t *testing.T) {
	bump := func(s string, i int) string { // add 1 to digit i of s, modulo 10
		b := []byte(s)
		b[i] = (b[i]-'0'+1)%10 + '0'
		return string(b)
	}
	for _, b := range arcepFictionBlocks {
		for _, n := range []struct{ name, z, ab, pq string }{
			{"pq", b.z, b.ab, bump(b.pq, 1)},
			{"ab", b.z, bump(b.ab, 1), b.pq},
			{"ab-first-digit", b.z, bump(b.ab, 0), b.pq},
			{"pq-first-digit", b.z, b.ab, bump(b.pq, 0)},
		} {
			for _, tail := range []string{"0000", "9999"} {
				for _, text := range arcepSpellings(n.z, n.ab, n.pq, tail) {
					t.Run(b.z+b.ab+b.pq+"/"+n.name+"/"+text, func(t *testing.T) {
						m := wantOneWhole(t, "Phone: "+text, text)
						if m.Confidence != 100 {
							t.Errorf("%q scored %.0f, want 100 (main)", text, m.Confidence)
						}
						if _, ok := m.Metadata[confidenceCeilingKey]; ok {
							t.Errorf("%q: published confidence_ceiling %v, want none", text, m.Metadata[confidenceCeilingKey])
						}
					})
				}
			}
		}
	}
}

func TestIsArcepFictionNumber(t *testing.T) {
	for clean, want := range map[string]bool{
		"+33199004718":   true,
		"+33199000000":   true,
		"+33199009999":   true,
		"+330199004718":  true, // "+33 (0)1 99 00 47 18"
		"0033199004718":  true,
		"0199004718":     true,
		"0639989999":     true,
		"+33639980000":   true,
		"+33199014718":   false, // a digit away
		"+33198004718":   false,
		"+33299004718":   false,
		"019900471":      false, // a digit short
		"01990047181":    false, // a digit long
		"+3319900471":    false,
		"33199004718":    false, // no "+" or "00": not an international form
		"+44199004718":   false,
		"00199004718":    false,
		"0099004718":     false,
		"+12619100000":   false,
		"+33 1 99 00 47": false, // not cleaned
	} {
		if got := isArcepFictionNumber(clean); got != want {
			t.Errorf("isArcepFictionNumber(%q) = %t, want %t", clean, got, want)
		}
	}
}

func TestMayBeReservedFictionalArcep(t *testing.T) {
	for clean, want := range map[string]bool{
		"+33199004718": true,
		"0639980000":   true,
		"+33199014718": false,
		"0123456789":   false,
	} {
		if got := mayBeReservedFictional(clean); got != want {
			t.Errorf("mayBeReservedFictional(%q) = %t, want %t", clean, got, want)
		}
	}
	for _, r := range arcepFictionRoots {
		if len(r) != 5 || !mayBeReservedFictional("0"+r+"0000") {
			t.Errorf("root %q: want 5 digits the pre-filter accepts", r)
		}
	}
}
