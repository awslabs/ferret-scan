// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"strings"
	"testing"
)

// TestRegistrantLetterSetIsTheDEAs pins the constant itself, so a later edit to it is a visible,
// reviewed change rather than a side effect.
func TestRegistrantLetterSetIsTheDEAs(t *testing.T) {
	if deaRegistrantLetters != "ABCDEFGHJKLMPRSTUX" {
		t.Errorf("deaRegistrantLetters = %q", deaRegistrantLetters)
	}
	for _, c := range deaUngatedRegistrantLetters {
		if !strings.ContainsRune(deaRegistrantLetters, c) {
			t.Errorf("ungated letter %c is not a registrant letter", c)
		}
	}
}

// TestDEAPatternAndChecksumAgree is the A-Z x {letter, '9'} x {upper, lower} agreement table: reDEA
// and deaChecksumValid accept exactly the same first and second characters, and both read the one
// registrant-letter constant. They used to hard-code the seven letters separately (#858).
func TestDEAPatternAndChecksumAgree(t *testing.T) {
	const digits = "1234563" // (1+3+5) + 2*(2+4+6) = 33, check digit 3
	seconds := []byte{'9'}
	for c := byte('A'); c <= 'Z'; c++ {
		seconds = append(seconds, c, c+('a'-'A'))
	}
	for first := byte('A'); first <= 'Z'; first++ {
		registrant := strings.IndexByte(deaRegistrantLetters, first) >= 0
		for _, f := range []byte{first, first + ('a' - 'A')} {
			for _, second := range seconds {
				s := string([]byte{f, second}) + digits
				pattern := reDEA.FindString(s) == s
				checksum := deaChecksumValid(s)
				if pattern != registrant || checksum != registrant {
					t.Errorf("%s: reDEA %v, deaChecksumValid %v, registrant letter %v", s, pattern, checksum, registrant)
				}
				wantForm := deaNotValid
				if registrant {
					wantForm = deaNeedsContext
					if second != '9' && strings.IndexByte(deaUngatedRegistrantLetters, first) >= 0 {
						wantForm = deaOnValue
					}
				}
				if got := classifyDEA(s); got != wantForm {
					t.Errorf("classifyDEA(%s) = %d, want %d", s, got, wantForm)
				}
			}
		}
	}
	// A digit other than 9 is never a second character.
	for _, s := range []string{"B07654329", "B87654329", "X17654329"} {
		if reDEA.FindString(s) == s || deaChecksumValid(s) {
			t.Errorf("%s accepted", s)
		}
	}
}

// TestMBIFormsClassify pins which MBI forms need a label and that the class is ASCII-only.
func TestMBIFormsClassify(t *testing.T) {
	for s, want := range map[string]mbiForm{
		"1AC2DE3FG45":                    mbiOnValue,
		"1ac2de3fg45":                    mbiNeedsLabel,
		"1Ac2dE3fG45":                    mbiNeedsLabel,
		"1SC2DE3FG45":                    mbiNotValid, // S is not an MBI letter
		"1sc2de3fg45":                    mbiNotValid,
		"0AC2DE3FG45":                    mbiNotValid, // the first character is 1-9
		"1AC2DE3FG4":                     mbiNotValid,
		"1A" + "\u212a" + "2DE3FG45":     mbiNotValid, // KELVIN SIGN, not an ASCII K
		"1AK2DE3FG45":                    mbiOnValue,
		"1ak2de3fg45":                    mbiNeedsLabel,
		strings.Repeat("1AC2DE3FG45", 2): mbiNotValid,
	} {
		if got := classifyMBI(s); got != want {
			t.Errorf("classifyMBI(%q) = %d, want %d", s, got, want)
		}
	}
}

// TestCalculateConfidenceScoresOnlyContextFreeForms: CalculateConfidence has no line, so it scores
// as checksum-backed or format-backed only the forms the scan reports without context. Every other
// value scores 50, as it did on main.
func TestCalculateConfidenceScoresOnlyContextFreeForms(t *testing.T) {
	v := NewValidator()
	for s, want := range map[string]struct {
		conf     float64
		checksum bool
	}{
		"AB1234563":   {85, true},
		"br1234563":   {85, true},
		"XR1234563":   {50, false}, // newer registrant letter: needs DEA context
		"A97654329":   {50, false}, // business-address form: needs DEA context
		"1AC2DE3FG45": {75, false},
		"1ac2de3fg45": {50, false}, // lowercase MBI: needs a Medicare label
		"1104332188":  {80, true},
	} {
		conf, checks := v.CalculateConfidence(s)
		if conf != want.conf || checks["has_checksum"] != want.checksum {
			t.Errorf("CalculateConfidence(%s) = %.0f has_checksum %v, want %.0f %v",
				s, conf, checks["has_checksum"], want.conf, want.checksum)
		}
	}
}

// TestHelpTextReadsTheConstants: the help pattern is generated from the registrant-letter constants,
// and the MBI format it prints is the CMS one the regex implements.
func TestHelpTextReadsTheConstants(t *testing.T) {
	info := NewValidator().GetCheckInfo()
	all := strings.Join(info.Patterns, "\n") + "\n" + info.DetailedDescription
	for _, want := range []string{
		"[" + deaRegistrantLetters + "]",
		deaUngatedRegistrantLetters,
		"C-A-AN-N-A-AN-N-A-A-N-N",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("help text does not contain %q:\n%s", want, all)
		}
	}
	for _, stale := range []string{"[ABCDFGM][A-Z]", "C-A-N-N/A-A-N-A-N-N/A-A-N"} {
		if strings.Contains(all, stale) {
			t.Errorf("help text still contains %q", stale)
		}
	}
}

// TestContextListsAreLabelMatched: the concatenated spellings are reachable only through
// containsLabel, and the phone veto still is not.
func TestContextListsAreLabelMatched(t *testing.T) {
	v := NewValidator()
	for _, tc := range []struct {
		name string
		fn   func(string) bool
		line string
		want bool
	}{
		{"provider", v.hasProviderContext, `{"providernpi": 1}`, true},
		{"provider", v.hasProviderContext, `{"renderingprovider": 1}`, true},
		{"dea", v.hasDEAContext, `{"deanumber": 1}`, true},
		{"dea", v.hasDEAContext, `{"prescriberdea": 1}`, true},
		{"dea", v.hasDEAContext, `{"idea": 1}`, false},
		{"medicare", v.hasMedicareContext, `{"medicarebeneficiaryidentifier": 1}`, true},
		{"medicare", v.hasMedicareContext, `{"coverage": 1}`, true},
		{"mbi label", v.hasMBILabel, `{"medicarebeneficiaryidentifier": 1}`, true},
		{"mbi label", v.hasMBILabel, `{"mbinumber": 1}`, true},
		{"mbi label", v.hasMBILabel, "coverage report", false},
		{"mbi label", v.hasMBILabel, "cms asset", false},
		{"mbi label", v.hasMBILabel, "member identification number", false},
		{"phone veto", v.hasPhoneContext, `{"phonenumber": 1}`, false},
		{"phone veto", v.hasPhoneContext, `{"phone_number": 1}`, true},
	} {
		if got := tc.fn(tc.line); got != tc.want {
			t.Errorf("%s(%q) = %v, want %v", tc.name, tc.line, got, tc.want)
		}
	}
}
