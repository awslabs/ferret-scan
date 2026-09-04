// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strings"
	"testing"
)

// mrzTD3Line1For returns a well-formed ICAO 9303 TD3 line-1 MRZ of the given
// issuing state with a fixed holder name. The name is chosen to keep the
// overall vowel ratio ≤ 20% so the isLikelyWord heuristic in the score path
// (a SEPARATE defect from #588, filed separately) does not confound the
// country-code measurement. Fixing this test's fixture is not the fix for
// that heuristic — the heuristic misses real holders whose names have
// higher vowel ratios (SWEDISH, JAPANESE, SPANISH), and that is a leak of
// its own.
func mrzTD3Line1For(cc string) string {
	name := "GHYNSKI<<HANS"
	pad := 44 - 2 - 3 - len(name)
	return "P<" + cc + name + strings.Repeat("<", pad)
}

// TestAnMRZScoresTheSameRegardlessOfIssuingState pins the invariant behind #588: an identical MRZ
// line 1 for a Kenyan, Vietnamese, Bangladeshi, Kosovar, refugee (XXB) or Utopian (UTO/ICAO
// specimen) passport must score at the SAME confidence as an American or British one. Before this
// fix the code list held 48 of the ~262 issuing-state codes ICAO 9303 accepts, and the missing
// codes lost the +20 nudge AND the bypass — a leak, because the missing codes were disproportionately
// those least likely to appear in a Western test corpus.
func TestAnMRZScoresTheSameRegardlessOfIssuingState(t *testing.T) {
	v := NewValidator()

	// Codes from #588's probe plus the ICAO specials that most needed the bypass. Deliberately mixes
	// (a) OECD states that WERE in the old subset, (b) states that were NOT, (c) ICAO specials that
	// are not ISO 3166 codes at all — because the shape of the leak was "the ones not in the West
	// were the ones silently dropped".
	inOldSubset := []string{"USA", "GBR", "DEU", "NGA", "TUR"}
	notInOldSubset := []string{"KEN", "VNM", "BGD", "PAK", "ETH", "UZB", "AZE", "GEO"}
	icaoSpecials := []string{"UTO", "XXA", "XXB", "XXC", "XOM", "XCC", "GBD", "RKS", "EUE"}

	all := append(append(inOldSubset, notInOldSubset...), icaoSpecials...)
	confBy := make(map[string]float64, len(all))
	for _, cc := range all {
		res, err := v.ValidateContent(mrzTD3Line1For(cc), "<probe>")
		if err != nil {
			t.Fatalf("%s: %v", cc, err)
		}
		if len(res) == 0 {
			t.Errorf("%s: MRZ not reported — a well-formed line 1 for this issuing state is silently "+
				"missed, which is a cleartext leak", cc)
			continue
		}
		confBy[cc] = res[0].Confidence
	}

	// All 22 valid codes must reach the same confidence. Failure here says an issuing state's
	// three-letter code silently determines whether a passport is protected.
	var ref float64
	for _, cc := range all {
		if _, ok := confBy[cc]; !ok {
			continue
		}
		if ref == 0 {
			ref = confBy[cc]
			continue
		}
		if confBy[cc] != ref {
			t.Errorf("issuing state %s scored %v; reference (%s) scored %v — an identical MRZ must "+
				"score identically regardless of issuing state, that is the whole point of #588",
				cc, confBy[cc], all[0], ref)
		}
	}
	if t.Failed() {
		return
	}
	t.Logf("all %d issuing states scored identically at %v", len(all), ref)
}

// TestAnUnrecognisedCodeStillPaysAPenalty prevents the wider list from becoming an unconditional pass.
// Structural checks stay in force: a plausible-looking but invalid code (ZZZ) is penalised at the
// scoring gate, so a real code still beats a random one.
func TestAnUnrecognisedCodeStillPaysAPenalty(t *testing.T) {
	v := NewValidator()

	realConf := float64(0)
	if res, _ := v.ValidateContent(mrzTD3Line1For("GBR"), "<probe>"); len(res) > 0 {
		realConf = res[0].Confidence
	}
	if realConf == 0 {
		t.Fatal("GBR baseline did not report; cannot compare")
	}

	// ZZZ passes the structural fingerprint (P<, 44 chars, filler run) but the code is not real.
	// The bypass no longer gates on the code (that WAS #588), so ZZZ may report; the -10 penalty
	// at the scoring gate is what still lets a real code beat a random one.
	zzz, _ := v.ValidateContent(mrzTD3Line1For("ZZZ"), "<probe>")
	if len(zzz) == 0 {
		return // dropped below the emit threshold — also fine
	}
	if zzz[0].Confidence >= realConf {
		t.Errorf("ZZZ conf=%v >= GBR conf=%v — the -10 penalty for an unrecognised code no longer "+
			"bites, so nothing distinguishes a real code from a random one",
			zzz[0].Confidence, realConf)
	}
}

// TestTheOldSubsetsMissingCodesReportAtHighConfidence is the non-vacuity assertion for the code list
// expansion. If this test passed before the fix, the fix is doing nothing.
func TestTheOldSubsetsMissingCodesReportAtHighConfidence(t *testing.T) {
	v := NewValidator()
	// A representative selection of codes that were NOT in the 48-code subset.
	missing := []string{"KEN", "VNM", "BGD", "PAK", "ETH", "GHA", "AFG", "UGA", "TZA", "BOL", "URY"}
	for _, cc := range missing {
		res, err := v.ValidateContent(mrzTD3Line1For(cc), "<probe>")
		if err != nil {
			t.Fatalf("%s: %v", cc, err)
		}
		if len(res) == 0 || res[0].Confidence < 80 {
			var got float64
			if len(res) > 0 {
				got = res[0].Confidence
			}
			t.Errorf("code %s reports at conf=%v; must clear the 80 threshold a valid country code "+
				"reaches — before this fix it scored below by 10 points because it was absent from the subset",
				cc, got)
		}
	}
}
