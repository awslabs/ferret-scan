// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

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
		"Tel: 01.42.34.56.78.90", // a sixth pair joined by a dot or a dash is a serial, not a number
		"Tel: 01-42-34-56-78-90",
		"Tel: 90.01.42.34.56.78",
		"Tel: 01:02-03-04-05-06", // a MAC address
		// a hex dump line (16 bytes, as xxd or a Go test fixture writes it): 04 17 30 15 82 is five of them
		"00000190  55 1d 11 04 17 30 15 82  13 74 65 73 74 2e 67 6f  |U....0...test.go|",
		"00000170  02 02 02 04 02 05 02 06  02                       |.........|", // the short last line of a dump
		"2006.01.02.15.04.05.0",
		"2e 65 78 61 6d 70 6c 65 00 0b 00 04 03 00 01 02 03 04 05 06",
		"Tel: 00 42 34 56 78", // a trunk 0 is followed by 1-9
		"Tel: 01 42 34 56 7",
	} {
		t.Run(text, func(t *testing.T) {
			for _, m := range phoneFindings(t, text) {
				if m.Metadata["pattern_name"] == "FR_National" {
					t.Errorf("%q: want no FR_National finding, got %s", text, describe([]detector.Match{m}))
				}
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

// Two French numbers one after the other, and a number in a sentence, are still reported: only a
// run of eleven or more pairs is a dump.
func TestFrenchNationalPairsInProseAndLists(t *testing.T) {
	ms := phoneFindings(t, "Tel: 01 42 34 56 78 06 12 34 56 78")
	if len(ms) != 2 {
		t.Fatalf("want both numbers of a two-number list, got %d: %s", len(ms), describe(ms))
	}
	wantOneWhole(t, "Appelez le 01 42 34 56 78, merci.", "01 42 34 56 78")
	wantOneWhole(t, "Tel: 01.42.34.56.78.", "01.42.34.56.78")
}
