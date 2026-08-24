// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"strings"
	"testing"
)

// #320. #307 demoted a BARE sensitivity marking out of HIGH; a marking carrying harmless
// decoration still saturated. Measured on shipped code, holding the property name constant:
//
//	Confidential                                    80  MEDIUM   correct after #307
//	Confidential - Draft                           100  HIGH
//	Confidential FY25                              100  HIGH
//	Confidential (Rev 3)                           100  HIGH
//	Confidential - Project Nightjar acquisition    100  HIGH     correct, this discloses
//	Confidential - Marcus Holloway                 100  HIGH     correct, this discloses
//
// So a label with a revision suffix was indistinguishable from one naming a live acquisition or a
// person. The fix removes the marking phrases and asks whether the REMAINDER has the shape of
// decoration, rather than asking whether every token is a known marking.
//
// Why the shape rule and not a longer vocabulary: adding "draft", "final", "rev", "fy25" to
// classificationMarkings is the trap that produced #307 in the first place — an unbounded list
// whose omissions are invisible, where "Confidential - Draft" being MEDIUM while
// "Confidential - Preliminary" is HIGH is more confusing than either rule alone.

// TestDecoratedMarkingIsNotHigh is the reported defect. All six values are 100 HIGH on shipped
// code.
func TestDecoratedMarkingIsNotHigh(t *testing.T) {
	for _, v := range []string{
		"Confidential - Draft",
		"Confidential FY25",
		"Confidential (Rev 3)",
		"Confidential - Final",
		"Confidential v2",
		"Restricted (Copy 1)",
	} {
		t.Run(v, func(t *testing.T) {
			got := confidenceFor(t, PreprocessorTypeOfficeMetadata, "Custom_Notice: "+v, "CUSTOM_PROPERTY")

			// A silent veto would be a different bug: it is worth knowing a document carries a
			// label, so this must stay reported.
			if got < 0 {
				t.Fatalf("%q produced NO finding; the marking must still be reported, just not "+
					"at HIGH", v)
			}
			if got >= 90 {
				t.Errorf("%q scored %.0f (HIGH). The decoration states nothing about content, so "+
					"this ranks with the bare label and not with a disclosure.", v, got)
			}
		})
	}
}

// TestOrgPrefixedLabelIsNotHigh ties the fix to the REAL distribution rather than to the issue's
// invented suffixes.
//
// Measured on 714 real Office/PDF documents: an organisation-prefixed label is the dominant
// marking shape in the wild, and it accounted for 112 of the 193 METADATA HIGH findings — far more
// than every "- Draft"-style suffix combined. The third row also proves a multi-word marking is
// consumed whole underneath a prefix.
func TestOrgPrefixedLabelIsNotHigh(t *testing.T) {
	for _, v := range []string{
		"Amazon Confidential",
		"CLIENT CONFIDENTIAL",
		"Acme Highly Confidential",
	} {
		t.Run(v, func(t *testing.T) {
			got := confidenceFor(t, PreprocessorTypeOfficeMetadata, "Custom_Notice: "+v, "CUSTOM_PROPERTY")
			if got < 0 {
				t.Fatalf("%q produced NO finding", v)
			}
			if got >= 90 {
				t.Errorf("%q scored %.0f (HIGH); an org prefix on a handling label discloses "+
					"nothing about the document's content", v, got)
			}
		})
	}
}

// TestDisclosureNextToAMarkingStaysHigh is the direction that matters most. A marking
// over-scoring is triage noise; a disclosure under-scoring is a miss, so these are the rows the
// fix must not touch.
func TestDisclosureNextToAMarkingStaysHigh(t *testing.T) {
	for _, tc := range []struct{ prop, value string }{
		{"Custom_Notice", "Confidential - Project Nightjar acquisition"},
		{"Custom_Classification", "SECRET - Project Nightjar"},
		{"Custom_Notice", "SECRET - Project Nightjar"},
		{"Custom_Notice", "Confidential - Marcus Holloway"},
		{"Custom_Notice", "Confidential - alice@example.com"},
		{"Custom_Notice", "Confidential - Nightjar acquisition"},
		{"Custom_Notice", "restricted to the acme merger team"},
		{"Custom_Notice", "Confidential - SSN 123-45-6789"},
		{"Custom_Notice", "Confidential 923456781"},
		{"Custom_Notice", `Confidential \\fileserver\hr\terminations`},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got := confidenceFor(t, PreprocessorTypeOfficeMetadata, tc.prop+": "+tc.value, "CUSTOM_PROPERTY")
			if got < 90 {
				t.Errorf("%s: %q scored %.0f, want >= 90. This value names something beyond its "+
					"own handling class, which is exactly what the classification weight is for.",
					tc.prop, tc.value, got)
			}
		})
	}
}

// TestDecorationGrammarNamesNoDecorationWords is acceptance criterion 3, made executable.
//
// The rule must recognise decoration by SHAPE, so a status word the author never thought of — in
// another language, or simply unusual — is handled by the same code path. If this ever needs a new
// vocabulary entry to pass, the fix has regressed to the design #307 rejected.
func TestDecorationGrammarNamesNoDecorationWords(t *testing.T) {
	for _, v := range []string{
		"Confidential - Preliminary",  // an English word nobody listed
		"Confidential - Vorabversion", // not English at all
		"Confidential zzqx7",          // not a word in any language
	} {
		t.Run(v, func(t *testing.T) {
			got := confidenceFor(t, PreprocessorTypeOfficeMetadata, "Custom_Notice: "+v, "CUSTOM_PROPERTY")
			if got >= 90 {
				t.Errorf("%q scored %.0f (HIGH); the shape rule should cover it without anyone "+
					"adding the word to a list", v, got)
			}
		})
	}

	// The other half of the criterion: the marking vocabulary must not grow a decoration side.
	for _, w := range []string{"draft", "final", "rev", "copy", "version", "preliminary", "fy25", "v2"} {
		if classificationMarkings[w] {
			t.Errorf("%q was added to classificationMarkings. That list is the set of things a "+
				"label IS, not the set of decorations it may carry — growing it that way is how "+
				"criterion 3 gets violated later.", w)
		}
	}
}

// TestMarkingResidualIsPhraseAwareLongestFirst pins the phrase handling. A word-at-a-time scan
// leaves "use only" behind from "internal use only" and then reads it as content.
func TestMarkingResidualIsPhraseAwareLongestFirst(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"top secret", nil},
		{"internal use only", nil},
		{"confidential / internal", nil},
		{"amazon confidential", []string{"amazon"}},
		{"acme highly confidential", []string{"acme"}},
		{"confidential - draft", []string{"draft"}},
		{"confidential (rev 3)", []string{"rev", "3"}},
		{"confidential - project nightjar acquisition", []string{"project", "nightjar", "acquisition"}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := markingResidual(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("markingResidual(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestClassificationMarkingMaxWordsCoversTheVocabulary is the decay guard, computed rather than
// fixtured.
//
// markingResidual only tries phrases up to classificationMarkingMaxWords long. If someone adds a
// four-word label, its last word would be left in the residual and the label would start reading
// as a disclosure — a silent change in the wrong direction, from an edit that looks like it only
// adds vocabulary.
func TestClassificationMarkingMaxWordsCoversTheVocabulary(t *testing.T) {
	longest := 0
	var longestEntry string
	for marking := range classificationMarkings {
		if n := len(strings.Fields(marking)); n > longest {
			longest, longestEntry = n, marking
		}
	}
	if longest == 0 {
		t.Fatal("classificationMarkings is empty, so this guard proves nothing")
	}
	if longest > classificationMarkingMaxWords {
		t.Errorf("classificationMarkings contains %q (%d words) but "+
			"classificationMarkingMaxWords is %d, so that label's last word(s) will be left in "+
			"the residual and the label will read as a disclosure",
			longestEntry, longest, classificationMarkingMaxWords)
	}
}

// TestLabelDecorationRejectsIdentifierAndContactShapes asserts the deny-by-default half directly
// on the predicate, and pins the two numeric ceilings so widening them has to be a visible edit.
func TestLabelDecorationRejectsIdentifierAndContactShapes(t *testing.T) {
	decoration := [][]string{
		{},            // nothing but markings
		{"draft"},     // a status word
		{"fy25"},      // stem fused to a year
		{"v2"},        // stem fused to a version
		{"rev", "3"},  // stem and number, separated
		{"copy", "1"}, //
		{"3"},         // a bare small number
		{"amazon"},    // an org prefix
		{"o'brien"},   // an org name with an apostrophe
	}
	for _, r := range decoration {
		if !isLabelDecoration(r) {
			t.Errorf("isLabelDecoration(%v) = false, want true", r)
		}
	}

	content := [][]string{
		{"marcus", "holloway"},          // two words: a name
		{"project", "nightjar"},         // two words: a codename
		{"alice@example.com"},           // an address, one token but not a word shape
		{`\\fileserver\hr`},             // a path
		{"923456781"},                   // 9 digits: an identifier, not a revision
		{"12345"},                       // 5 digits: past the numeral ceiling
		{"abcdefghijklmnopqrstuvwxyz"},  // 26 letters: past the word ceiling
		{"to", "the", "acme", "merger"}, // a phrase
		{"3", "rev"},                    // number before stem: not the sequence shape
	}
	for _, r := range content {
		if isLabelDecoration(r) {
			t.Errorf("isLabelDecoration(%v) = true, want false; an unrecognised shape must keep "+
				"the full weight rather than be demoted by omission", r)
		}
	}
}

// TestDecoratedMarkingStillAddsRelativeToNoMarking keeps the demotion an "add less" and never a
// "subtract".
//
// A penalty can be out-voted by enough positive context, and a value that is scored DOWN for
// carrying a label would let an attacker lower a real finding by adding the word "Confidential" —
// the TM-11 shape. A decorated marking must therefore still outrank the same property with no
// marking at all.
func TestDecoratedMarkingStillAddsRelativeToNoMarking(t *testing.T) {
	withMarking := confidenceFor(t, PreprocessorTypeOfficeMetadata,
		"Custom_Notice: Confidential - Draft", "CUSTOM_PROPERTY")
	without := confidenceFor(t, PreprocessorTypeOfficeMetadata,
		"Custom_Notice: Quarterly summary", "CUSTOM_PROPERTY")

	if withMarking < 0 || without < 0 {
		t.Fatalf("need both findings to compare: withMarking=%.0f without=%.0f", withMarking, without)
	}
	if withMarking <= without {
		t.Errorf("decorated marking scored %.0f, no higher than the same property with no marking "+
			"at %.0f. The demotion must reduce how much the marking ADDS, never subtract — "+
			"otherwise adding the word 'Confidential' becomes a way to lower a real finding.",
			withMarking, without)
	}
}
