// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strings"
	"testing"
)

// mrzForHolder returns a well-formed ICAO 9303 TD3 line-1 MRZ for a holder name.
func mrzForHolder(name string) string {
	const cc = "USA"
	pad := 44 - 2 - len(cc) - len(name)
	if pad < 0 {
		name = name[:44-2-len(cc)]
		pad = 0
	}
	return "P<" + cc + name + strings.Repeat("<", pad)
}

func vowelRatio(s string) float64 {
	v := 0
	for _, r := range strings.ToUpper(s) {
		if strings.ContainsRune("AEIOU", r) {
			v++
		}
	}
	return float64(v) / float64(len(s))
}

// TestAnMRZReportsWhateverTheHolderIsCalled is the defect this fixes.
//
// The vowel-ratio heuristic was applied to the WHOLE 44-character MRZ, whose vowel content is
// decided entirely by the holder's name. Ten of these sixteen real names were silently dropped
// (60 base + 20 country code - 40 word penalty - 25 false-positive penalty = 15, under the 60
// emit threshold), and by the sink rule a silent miss is a cleartext leak: only reported
// findings reach the redactor.
//
// The names are grouped by orthography on purpose. The old behaviour did not fail at random —
// it failed on Swedish, Spanish, Japanese, German, Italian, Greek, Igbo, Finnish and Hawaiian
// names, because those use more vowels than English does.
func TestAnMRZReportsWhateverTheHolderIsCalled(t *testing.T) {
	v := NewValidator()

	// Every one of these MISSED before this change.
	previouslyMissed := []string{
		"ERIKSSON<<ANNA<MARIA",      // Swedish
		"JOHANSSON<<ANNA<ELISABETH", // Swedish
		"GARCIA<<MARIA<CARMEN",      // Spanish
		"TANAKA<<AKIKO<HIROMI",      // Japanese
		"MUELLER<<HEIDI<ANNA",       // German
		"ROSSI<<GIUSEPPE<ANTONIO",   // Italian
		"PAPADOPOULOS<<ELENI",       // Greek
		"OKONKWO<<CHIAMAKA",         // Igbo
		"AALTO<<AINO<ELINA",         // Finnish
		"KAMEHAMEHA<<LEIALOHA",      // Hawaiian
	}
	// These reported before and must continue to.
	previouslyReported := []string{
		"SMITH<<JOHN", "GHYNSKI<<HANS", "OMOLLO<<AKINYI",
		"SINGH<<RAJESH<KUMAR", "NGUYEN<<THI<HOA", "KOWALSKI<<KRZYSZTOF",
	}

	var confs []float64
	for _, group := range [][]string{previouslyMissed, previouslyReported} {
		for _, name := range group {
			mrz := mrzForHolder(name)
			res, err := v.ValidateContent(mrz, "<probe>")
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(res) == 0 {
				t.Errorf("holder %q (vowel ratio %.1f%%): MRZ NOT REPORTED — the passport is silently "+
					"missed, which by the sink rule leaves it cleartext", name, vowelRatio(mrz)*100)
				continue
			}
			confs = append(confs, res[0].Confidence)
		}
	}

	// NON-VACUITY: the point is not merely that all report, but that they all report the SAME.
	// A fix that reported the previously-missed names at a lower band would still let
	// --confidence high drop them.
	if len(confs) == len(previouslyMissed)+len(previouslyReported) {
		for i, c := range confs {
			if c != confs[0] {
				t.Errorf("confidence %v at index %d differs from %v — an identical MRZ must not score "+
					"differently because of the holder's name", c, i, confs[0])
			}
		}
		t.Logf("all %d holders reported identically at %v", len(confs), confs[0])
	}
}

// TestANationalNumberIsNotJudgedOnItsVowels is the same root cause on the other shape.
//
// A Canadian passport is two letters and six digits, so two vowels is 25% and lands inside the
// heuristic's window. Measured before this change: AE123456 scored 0 where BC123456 scored 45.
// Two letters of a document number decided whether it was reported at all.
func TestANationalNumberIsNotJudgedOnItsVowels(t *testing.T) {
	v := NewValidator()

	// Same shape, differing only in whether the two letters are vowels.
	pairs := [][2]string{
		{"AE123456", "BC123456"},   // Canada
		{"AI123456", "BD123456"},   // Canada
		{"AE1234567", "BC1234567"}, // EU
	}
	for _, p := range pairs {
		vowelly, _ := v.CalculateConfidence(p[0])
		plain, _ := v.CalculateConfidence(p[1])
		if vowelly != plain {
			t.Errorf("%s scored %v but %s scored %v — the same document-number SHAPE must score the "+
				"same regardless of which letters it happens to use", p[0], vowelly, p[1], plain)
		}
	}
}

// TestARealWordIsStillPenalised is the anti-widening guard. The heuristic exists to catch a match
// that is genuinely an English word, and that must keep working — otherwise this change trades a
// recall bug for a precision one.
func TestARealWordIsStillPenalised(t *testing.T) {
	v := NewValidator()

	// Word-shaped and vowel-balanced: exactly what the heuristic is for.
	for _, w := range []string{"PASSPORT", "DOCUMENT", "IDENTITY", "APPROVED", "RETURNED", "ORIGINAL"} {
		if !v.isLikelyWord(w) {
			t.Errorf("isLikelyWord(%q) = false; the heuristic no longer catches a plain English word, so "+
				"this change traded a recall bug for a precision one", w)
		}
	}
	// The exact-match list must stay unconditional, including a lower-case spelling.
	for _, w := range []string{"passport", "Passport", "template", "unknown"} {
		if !v.isLikelyWord(w) {
			t.Errorf("isLikelyWord(%q) = false; the common-word list must apply whatever the case", w)
		}
	}
}

// TestIsWordShapedRejectsEverythingThatIsNotAWord pins the predicate directly, including the two
// shapes that caused #591.
func TestIsWordShapedRejectsEverythingThatIsNotAWord(t *testing.T) {
	accept := []string{"Passport", "Café", "naïve", "ERIKSSON", "a"}
	for _, s := range accept {
		if !isWordShaped(s) {
			t.Errorf("isWordShaped(%q) = false, want true — an accented word is still a word", s)
		}
	}
	reject := []string{
		"",                    // undefined ratio; the old len>=5 guard was the only thing stopping it
		"P<USAERIKSSON<<ANNA", // an MRZ: "<" occurs in no English word
		"AE123456",            // a document number
		"452-11-9384",         // punctuation
		"ANNA MARIA",          // two words, not one
		"A12345678",
	}
	for _, s := range reject {
		if isWordShaped(s) {
			t.Errorf("isWordShaped(%q) = true, want false", s)
		}
	}
}
