// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// mailingLabelLines put the address BEFORE the name, which is what a mailing label, an "attn" line
// and a shipping row all look like.
//
// The pre-existing corpus in geo_proximity_test.go is entirely name-then-address — even
// "Deborah Callahan, 1200 State Street, Suite 300" passes today — so this ordering was untested,
// and it is the ordering where the street suffix lands within the 15-byte negative-keyword window
// of the name.
var mailingLabelLines = []struct {
	line string
	want string
}{
	{"1247 Oakmont Street, Marcus Whitfield", "Marcus Whitfield"},
	{"1247 Oakmont Drive, Marcus Whitfield", "Marcus Whitfield"},
	{"1247 Oakmont Avenue, Marcus Whitfield", "Marcus Whitfield"},
	{"88 Ridgeway Road, Marcus Whitfield", "Marcus Whitfield"},
	{"Ship to 500 Industrial Boulevard, Renee Mueller", "Renee Mueller"},
	{"Attn: 42 Lakeview Drive, Carlos Ramirez", "Carlos Ramirez"},
	{"Deliver to 9 Summit Road, Priya Anand", "Priya Anand"},
}

// A street suffix must be charged once, not once per penalty family.
//
// 13 of 19 geographic patterns and 17 business patterns are also negativeKeywords, so a single
// "Street" within 15 bytes of a name paid -35 as geography AND -15 as a negative keyword, plus -8
// for product context. Measured before this: 100 - 58 = 42, under the hardcoded 50 emit floor at
// two call sites — so the finding did not exist at ANY `--confidence` setting, and
// `--enable-redaction` wrote no output file at all. The name stayed cleartext in a file the run
// certified clean (#387).
//
// The stacking was deliberate — the comment above specificPatternProximity said so — but it was an
// asserted design choice sitting next to a measured one (#215's proximity gate). Only the assertion
// is overturned here; the 25-byte window stays exactly as #215 left it.
func TestStreetSuffixIsChargedOncePerWord(t *testing.T) {
	for _, tc := range mailingLabelLines {
		t.Run(tc.line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(tc.line, "labels.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			var got []string
			for _, m := range matches {
				got = append(got, m.Text)
				if strings.Contains(m.Text, tc.want) {
					return
				}
			}
			t.Errorf("%q was not reported (findings: %v). One word is being charged under two "+
				"penalty families, which pushes a list-surname name below the 50 emit floor — and "+
				"an unreported name is never redacted, so it stays cleartext.\n  line: %q",
				tc.want, got, tc.line)
		})
	}
}

// The other direction, and the reason the fix needs a span test rather than a simple de-duplication.
//
// In "Jordan Lake State Recreation Area" the geographic word IS the second token of the candidate:
// the "name" is the place. Both charges are then evidence about the same thing and the stack is
// correct. Measured during development: de-duplicating unconditionally returned this line as a
// PERSON_NAME at LOW 57 — a false positive on a lake.
//
// So the double charge is only dropped for a word OUTSIDE the matched span.
func TestGeographicWordInsideTheNameStillStacks(t *testing.T) {
	for _, line := range []string{
		"Jordan Lake State Recreation Area",
		"Madison Avenue advertising firm",
		"Elm Street Elementary School District",
		"Cedar Creek Road crosses Pine Valley Avenue",
		"Golden Gate Boulevard runs through the city",
	} {
		t.Run(line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(line, "doc.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) > 0 {
				var got []string
				for _, m := range matches {
					got = append(got, m.Text)
				}
				t.Errorf("reported %v as person name(s) on a line that names no person. Dropping "+
					"the second charge for a word INSIDE the candidate span turns place names into "+
					"people.\n  line: %q", got, line)
			}
		})
	}
}

// specificPatternPenalties must report offsets that are directly comparable with
// negativeKeywordIndices, because that comparison is the whole mechanism. Both are
// first-occurrence byte offsets into the same lowered line.
func TestSpecificPatternPenaltiesReportsComparableOffsets(t *testing.T) {
	v := NewValidator()
	v.ensureNamesLoaded()

	const line = "1247 oakmont street, marcus whitfield"
	cache := v.newLineContextCache(line)
	nameIndex := strings.Index(line, "marcus")
	if nameIndex < 0 {
		t.Fatal("premise broken: name not found")
	}

	penalty, charged := v.specificPatternPenalties(cache, nameIndex)
	if penalty == 0 {
		t.Fatal("no specific-pattern penalty on a line with a street suffix, so this test is vacuous")
	}
	if len(charged) == 0 {
		t.Fatal("no charged offsets returned, so the caller cannot tell which words were paid for")
	}

	// The street suffix must appear at the SAME offset in both families, or the de-duplication can
	// never fire and the fix is inert.
	streetOffset := strings.Index(line, "street")
	if _, ok := charged[streetOffset]; !ok {
		t.Errorf("charged offsets %v do not include the street suffix at %d; specificPatternIndices "+
			"and negativeKeywordIndices must agree on offsets or one word cannot be recognised as "+
			"one word", charged, streetOffset)
	}
	var inNegative bool
	for _, idx := range cache.negativeKeywordIndices {
		if idx == streetOffset {
			inNegative = true
		}
	}
	if !inNegative {
		t.Errorf("negativeKeywordIndices %v does not include %d: the premise of this fix is that "+
			"the two lists record the same offset for the same word", cache.negativeKeywordIndices,
			streetOffset)
	}
}

// A word far from the name must still be charged nothing, and a word that is only a negative
// keyword must still be charged the full negative-keyword penalty. This pins that the change did
// not widen or narrow either family's own reach.
func TestUnrelatedPenaltiesAreUnchanged(t *testing.T) {
	v := NewValidator()
	v.ensureNamesLoaded()

	t.Run("distant geographic word charges nothing", func(t *testing.T) {
		line := "marcus whitfield" + strings.Repeat(" x", specificPatternProximity) + " oak drive"
		cache := v.newLineContextCache(line)
		penalty, _ := v.specificPatternPenalties(cache, strings.Index(line, "marcus"))
		if penalty != 0 {
			t.Errorf("penalty = %.1f for a geographic word past specificPatternProximity, want 0: "+
				"the proximity gate from #215 must be untouched", penalty)
		}
	})

	t.Run("negative keyword that is not a specific pattern still charges", func(t *testing.T) {
		// A negative keyword with no geographic/business/product twin: nothing to de-duplicate
		// against, so it must pay in full.
		lower := strings.ToLower("Marcus Whitfield invoice")
		cache := v.newLineContextCache(lower)
		if !cache.hasNegativeKeyword {
			t.Skip("premise: this line carries no negative keyword in this build")
		}
		_, charged := v.specificPatternPenalties(cache, strings.Index(lower, "marcus"))
		for _, idx := range cache.negativeKeywordIndices {
			if _, ok := charged[idx]; ok {
				t.Errorf("offset %d was charged by a specific family too; pick a keyword with no "+
					"twin so this test isolates the untwinned path", idx)
			}
		}
	})
}

// The two defensive details in this fix — recording the MAXIMUM penalty per offset, and only
// skipping when that maximum is at least the negative-keyword penalty — are not reachable through
// any real line with today's pattern lists. Measured:
//
//	product ∩ negativeKeywords   0 of 15
//	product ∩ geo                0 of 15
//	product ∩ business           0 of 15
//	business ∩ geo               0 of 49
//	geo ∩ negativeKeywords      12 of 13
//	business ∩ negativeKeywords 17 of 49
//
// So only geo (-35) and business (-20) ever twin with a negative keyword, both already above the
// -15 they would displace, and no offset is ever charged by two specific families at once. Mutating
// either detail therefore changes nothing observable — they exist so that ADDING a word to a list
// cannot silently turn the de-duplication into a penalty reduction.
//
// Both are asserted directly instead, against a hand-built cache, and the list invariant that makes
// them dormant is asserted too: if someone adds a product word to negativeKeywords, that assertion
// fires and points here.
func TestPenaltyPerOffsetIsTheMaximumNotTheFirstOrSmallest(t *testing.T) {
	v := NewValidator()

	// One offset claimed by two families at once, which no real line produces today.
	const shared = 4
	cache := &lineContextCache{
		lowerLine:      "0123456789 marcus whitfield",
		productIndices: []int{shared}, // -8
		geoIndices:     []int{shared}, // -35
	}

	total, charged := v.specificPatternPenalties(cache, 11)
	if total != 43 {
		t.Errorf("total = %.1f, want 43 (both families charge; only the per-offset RECORD is "+
			"de-duplicated, not the family total)", total)
	}
	if got := charged[shared]; got != 35 {
		t.Errorf("charged[%d] = %.1f, want 35: the record must be the LARGEST penalty at that "+
			"offset. Recording the smallest would let a -8 product word displace a -15 "+
			"negative-keyword charge and REDUCE the total penalty for that word", shared, got)
	}
}

// The premise that makes the threshold dormant. If this fails, the `charged >= negativeKeywordPenalty`
// test in analyzeLineContextForMatch has become load-bearing and needs its own behavioural coverage.
func TestNoProductPatternIsAlsoANegativeKeyword(t *testing.T) {
	v := NewValidator()
	negative := make(map[string]bool, len(v.negativeKeywords))
	for _, k := range v.negativeKeywords {
		negative[k] = true
	}

	for _, p := range v.getSortedProductPatterns() {
		if negative[p] {
			t.Errorf("%q is both a product pattern (-8) and a negative keyword (-15). The "+
				"de-duplication in analyzeLineContextForMatch only skips the negative-keyword "+
				"charge when the specific-family charge is at least as large, so this word now "+
				"exercises that threshold — add a behavioural test for it rather than relying on "+
				"this invariant", p)
		}
	}
}
