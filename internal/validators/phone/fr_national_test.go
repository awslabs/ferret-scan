// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "testing"

// #1052: a French national number written as a trunk 0, a digit 1-9 and four pairs with ONE
// separator. main @ a73c55d6 reported "Tel: 0142345678" and "Tel: +33 1 42 34 56 78" at PHONE 100 and
// nothing for the three spellings below.
func TestFrenchNationalPairsReadLikeTheCompactForm(t *testing.T) {
	for _, n := range []struct{ compact, pairs string }{
		{"0142345678", "01 42 34 56 78"},
		{"0612345678", "06 12 34 56 78"},
		{"0123456789", "01 23 45 67 89"}, // the compact form's sequential penalty applies to the pairs too
		{"0100000000", "01 00 00 00 00"},
	} {
		want := wantOneWhole(t, "Tel: "+n.compact, n.compact).Confidence
		for _, sep := range []string{" ", ".", "-"} {
			text := n.pairs[:2] + sep + n.pairs[3:5] + sep + n.pairs[6:8] + sep + n.pairs[9:11] + sep + n.pairs[12:]
			t.Run(text, func(t *testing.T) {
				m := wantOneWhole(t, "Tel: "+text, text)
				if m.Confidence != want {
					t.Errorf("%q scored %.0f, want %.0f (the compact %q)", text, m.Confidence, want, n.compact)
				}
			})
		}
	}
}

// A mixed separator is not one number, and a sixth pair or a missing one is not a French number.
func TestFrenchNationalPairsControlsStayUnreported(t *testing.T) {
	for _, text := range []string{
		"Tel: 01 42.34 56-78",
		"Tel: 01.42 34.56 78",
		"Tel: 01 42 34 56",
		"Tel: 01 42 34 56 78 90",
		"Tel: 01.42.34.56.78.90",
		"Tel: 01-42-34-56-78-90",
		"Tel: 00 42 34 56 78", // a trunk 0 is followed by 1-9
		"Tel: 01 42 34 56 7",
	} {
		t.Run(text, func(t *testing.T) {
			if ms := phoneFindings(t, text); len(ms) != 0 {
				t.Errorf("%q: want no finding, got %s", text, describe(ms))
			}
		})
	}
}

// The ARCEP fiction blocks (#1026, #1048) are held at LOW in the pair spellings too, every block.
func TestFrenchNationalPairsHoldTheArcepCeiling(t *testing.T) {
	for _, b := range arcepFictionBlocks {
		for _, sep := range []string{" ", ".", "-"} {
			text := "0" + b.z + sep + b.ab + sep + b.pq + sep + "47" + sep + "18"
			t.Run(text, func(t *testing.T) {
				m := wantOneWhole(t, "Tel: "+text, text)
				if m.Confidence > reservedFictionalCeiling || m.Metadata[confidenceCeilingKey] != reservedFictionalCeiling {
					t.Errorf("%q scored %.0f, ceiling %v, want at most %.0f published", text, m.Confidence, m.Metadata[confidenceCeilingKey], reservedFictionalCeiling)
				}
			})
		}
	}
}
