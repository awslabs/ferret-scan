// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// A font family name satisfies the Title-Case name shape, and the surname gate then
// accepts it whenever the LAST token is a real surname — Roman, Black and Vera all are.
// Measured on shipped code before this fix:
//
//	Times New Roman -> 81   Arial Black -> 80   Bitstream Vera -> 80
//
// These arrive from the legacy .doc font table: one of 714 real documents reported
// "Times New Roman" at 81 that way.

// measuredFontFalsePositives are the three families that actually fired. They carry the
// load in these tests — the rest of fontFamiliesMap is silent already, so asserting
// against it alone would prove nothing.
var measuredFontFalsePositives = []string{
	"Times New Roman",
	"Arial Black",
	"Bitstream Vera",
}

func TestMeasuredFontNamesAreNotPeople(t *testing.T) {
	v := NewValidator()

	for _, font := range measuredFontFalsePositives {
		t.Run(font, func(t *testing.T) {
			matches, err := v.ValidateContent(font, "deck.doc")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("%q reported as PERSON_NAME: %v", font, matchTexts(matches))
			}
		})
	}
}

// TestStyledFontNameIsCoveredWithoutItsOwnEntry pins why the map needs no "... Bold"
// entries: the four-token span is rejected because the style word is not a surname, so
// the value that reaches the map is already the base family.
func TestStyledFontNameIsCoveredWithoutItsOwnEntry(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"Times New Roman Bold",
		"Arial Black Italic",
	} {
		t.Run(line, func(t *testing.T) {
			if fontFamiliesMap[strings.ToLower(line)] {
				t.Fatalf("%q has its own entry, so this test no longer proves the base "+
					"family is what gets reported", line)
			}
			matches, err := v.ValidateContent(line, "deck.doc")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("%q reported as PERSON_NAME: %v", line, matchTexts(matches))
			}
		})
	}
}

// TestFontEntriesAreMultiWord keeps dead weight out. Every pattern in this validator
// requires at least two tokens, so a single-word entry could never match anything and
// would only imply a protection that is not there.
func TestFontEntriesAreMultiWord(t *testing.T) {
	for family := range fontFamiliesMap {
		if len(strings.Fields(family)) < 2 {
			t.Errorf("%q is a single word: no pattern can produce it, so the entry has no "+
				"effect", family)
		}
	}
}

// TestNoFontEntryLooksLikeARealName is the safety gate on the vocabulary itself.
//
// Suppressing an exact phrase is only safe while that phrase is not something a person
// could be called. If both the first and last token of an entry are in the name
// databases, the entry is a plausible full name — "Grace Black" would be — and
// suppressing it would delete a real person's name from the report, which means it is
// never redacted either.
func TestNoFontEntryLooksLikeARealName(t *testing.T) {
	v := NewValidator()
	v.ensureNamesLoaded()

	for family := range fontFamiliesMap {
		words := strings.Fields(family)
		if len(words) < 2 {
			continue // reported by TestFontEntriesAreMultiWord
		}
		first, last := words[0], words[len(words)-1]
		if v.firstNames[first] && v.lastNames[last] {
			t.Errorf("%q has a known given name (%q) AND a known surname (%q): it is a "+
				"plausible person name, so suppressing the whole phrase risks deleting a "+
				"real one", family, first, last)
		}
	}
}

// TestFontSuppressionIsExactPhrase is the counterweight. The failure mode this fix had
// to avoid is a token-level list, which would silence every person named Roman or Black.
func TestFontSuppressionIsExactPhrase(t *testing.T) {
	v := NewValidator()

	// One case per measured false positive, using the exact token that made each family
	// reportable. A token that is NOT in the surname database would prove nothing here:
	// "Julia Arial" is unreported before and after this change, because "Arial" is not a
	// surname the data carries, so it never reached the font map either way.
	for _, tc := range []struct{ line, want string }{
		{"Marcus Roman signed the form.", "Marcus Roman"},
		{"Sarah Black approved it.", "Sarah Black"},
		{"Report by Daniel Vera.", "Daniel Vera"},
		{"Andrea Roman and Peter Black attended.", "Andrea Roman"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if findMatch(matches, tc.want) == nil {
				t.Errorf("want %q, got %v: a person sharing a token with a font family "+
					"must still be reported", tc.want, matchTexts(matches))
			}
		})
	}
}
