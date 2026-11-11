// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// TestPlaceNamesAreNotPersons is the precision half of #935: lines of this repository that reported
// a place or a garbled fragment as PERSON_NAME at HIGH. Each line is quoted as it stands in the file
// named, and each "wantGone" value is what main @ 2fb4719 reported on it, at the confidence given.
//
// The lines carry "PERSON_NAME" or "person"/"name" on purpose: those words are positive context (+24),
// which is what lifted the values to HIGH, so the fixture keeps the condition that made them gate.
func TestPlaceNamesAreNotPersons(t *testing.T) {
	cases := []struct {
		where    string
		line     string
		wantGone []string
	}{
		{"ooxml_auxiliary.go:158 (100, 91)",
			`"\"Hong Kong\" and \"Middle East\" as PERSON_NAME at confidence 92-100. The values are a stale " +`,
			[]string{"Hong Kong", "Middle East"}},
		{"ooxml_auxiliary.go:37 (92, 67)",
			`//	xl/externalLinks/*      cached remote workbook labels: "Hong Kong" and "Middle East" as`,
			[]string{"Hong Kong", "Middle East"}},
		{"execguard.go:314 (91)",
			`//	PERSON_NAME     "Flushing Meadows<ENDASH>Corona" — a park, an already-known FP class`,
			[]string{"Flushing Meadows"}},
		{"execguard.go:353 (66): the hyphenated full name of the same park",
			`//	"Flushing Meadows-Corona"                       prose      -> rejected`,
			[]string{"Flushing Meadows-Corona"}},
		{"office-text-extractor.go:1368 (100)",
			`//	PERSON_NAME 30       "Hong Kong", "Saudi Arabia", "Amazon Web Services" — places and companies,`,
			[]string{"Hong Kong"}},
		{"CHANGELOG.md:1877 (91), an excerpt",
			"`Santa`, `Val`, `Isla` and `Monte` are given names, `La`, `Le`, `Fort`, `Lake` and `Villa` are surnames. `La Paz` is therefore **still reported**, deliberately: overriding the data to catch one capital city would delete every person named",
			[]string{"La Paz"}},
		{"CHANGELOG.md:1960 (92 twice), an excerpt",
			"and **9 fewer `PERSON_NAME`** — every one a false positive (`NEM MIN`, `EI LUO`) the old path produced by mis-decoding non-Latin escapes.",
			[]string{"NEM MIN", "EI LUO"}},
		{"technical_terms.go:393 (99): the comma pattern starting inside a city name",
			"\t// Iberian and Latin American: San Francisco, Santa Clara, Sao Paulo, Puerto Vallarta,",
			[]string{"Francisco, Santa Clara"}},
		{"technical_terms.go:394 (69)",
			"\t// Ciudad Juarez, Villa Nueva, Bahia Blanca, Isla Mujeres, Monte Plata.",
			[]string{"Juarez, Villa Nueva"}},
		{"public corpus (by-format/), 10 times: the three-word region",
			"Contact the Russian Far East desk.",
			[]string{"Russian Far East"}},
		{"public corpus (by-format/), 11 times: the compass region",
			"Customer region: North East",
			[]string{"North East"}},
	}
	for _, c := range cases {
		t.Run(c.where, func(t *testing.T) {
			for _, m := range scanText(t, c.line+"\n") {
				for _, gone := range c.wantGone {
					if m.Text == gone {
						t.Errorf("%q reported as PERSON_NAME at %.0f; it is a place or a garbled fragment, not a person",
							m.Text, m.Conf)
					}
				}
			}
		})
	}
}

// TestPlaceFilterKeepsRealNames is the recall half: the names that share a word, a shape or a
// position with the values above keep EXACTLY the confidence main @ 2fb4719 gives them. An unreported
// name is never handed to the redactor, so a precision fix that drops one of these is a cleartext leak.
func TestPlaceFilterKeepsRealNames(t *testing.T) {
	cases := []struct {
		why  string
		line string
		name string
		conf float64
	}{
		{"control (#935)", "Signed by Will Smith today.", "Will Smith", 92},
		{"control (#935)", "Signed by May Chen today.", "May Chen", 92},
		{"control (#935)", "Signed by Jean-Claude Van Damme today.", "Jean-Claude Van Damme", 93},
		{"control (#935)", "Signed by Dr. Sarah Johnson today.", "Dr. Sarah Johnson", 100},
		{"comma form, nothing before the surname", "Smith, John", "Smith, John", 100},
		{"comma form after a label", "Patient: Torres, Michael", "Torres, Michael", 100},
		// A word of a listed place, in a real name: the phrase list is keyed on the whole value.
		{"first word of the Chinese city", "Contact: Hong Li", "Hong Li", 100},
		{"second word of the Bolivian capital", "Contact: Paz Vega", "Paz Vega", 100},
		{"the place inside a longer name", "Signed: Maria La Paz Rodriguez", "Maria La Paz Rodriguez", 94},
		// A toponym prefix the name data knows, in front of or inside a name: no tail rejection.
		{"a prefix that is a given name", "Signed: Santa Maria Lopez", "Santa Maria Lopez", 93},
		{"a prefix that is a surname", "Signed: La Toya Jackson", "La Toya Jackson", 68},
		// Short all-caps syllables that are all in the name data, mostly written surname first.
		{"all-caps, both syllables known", "KIM LEE", "KIM LEE", 100},
		{"all-caps, surname first", "LE MAI", "LE MAI", 81},
		{"all-caps, surname first", "AN LI", "AN LI", 81},
		{"all-caps, surname first", "HO AN", "HO AN", 81},
		{"all-caps, a long token", "NGUYEN AN", "NGUYEN AN", 81},
		{"all-caps, ordinary", "JOHN SMITH", "JOHN SMITH", 100},
	}
	for _, c := range cases {
		t.Run(c.why+"/"+c.name, func(t *testing.T) {
			var got []string
			for _, m := range scanText(t, c.line+"\n") {
				got = append(got, m.Text)
				if m.Text == c.name {
					if m.Conf != c.conf {
						t.Errorf("%q confidence %.0f, want %.0f (unchanged from main)", c.name, m.Conf, c.conf)
					}
					return
				}
			}
			t.Errorf("%q not reported (got %q); it is a real name and must reach the redactor",
				c.name, strings.Join(got, " | "))
		})
	}
}

// TestToponymPhraseLengthBounds keeps isToponymPhrase's length pre-check in step with the map: an
// entry outside the bounds would never match.
func TestToponymPhraseLengthBounds(t *testing.T) {
	for phrase := range toponymPhrasesMap {
		if len(phrase) < toponymPhraseMinLen || len(phrase) > toponymPhraseMaxLen {
			t.Errorf("%q (%d bytes) is outside [%d, %d]; widen the bounds", phrase, len(phrase),
				toponymPhraseMinLen, toponymPhraseMaxLen)
		}
		if strings.ContainsRune(phrase, '-') {
			t.Errorf("%q contains a hyphen; isToponymPhrase matches a hyphenated candidate by its head only", phrase)
		}
	}
	for _, maxPrefix := range []string{"ciudad", "puerto"} {
		if !toponymPrefixMap[maxPrefix] || len(maxPrefix) > maxToponymPrefixLen {
			t.Errorf("maxToponymPrefixLen %d no longer covers %q", maxToponymPrefixLen, maxPrefix)
		}
	}
	for prefix := range toponymPrefixMap {
		if len(prefix) > maxToponymPrefixLen {
			t.Errorf("toponym prefix %q (%d bytes) is longer than maxToponymPrefixLen %d", prefix, len(prefix), maxToponymPrefixLen)
		}
	}
}

// TestPlaceFilterDoesNotAllocateOnOrdinaryNames pins the cost of the filter on the common path: a
// candidate that is no place, after a word that is no prefix, costs no allocation. The filter runs on
// every candidate of every line.
func TestPlaceFilterDoesNotAllocateOnOrdinaryNames(t *testing.T) {
	v := NewValidator()
	v.ensureNamesLoaded()
	line := "Signed by John Smith and Signed Mary Jones"
	start := strings.Index(line, "Mary Jones")
	allocs := testing.AllocsPerRun(200, func() {
		if isToponymPhrase("Mary Jones") || v.continuesToponym(line, start) {
			t.Fatal("an ordinary name was treated as a place")
		}
	})
	if allocs != 0 {
		t.Errorf("isToponymPhrase + continuesToponym allocate %.1f times per ordinary candidate, want 0", allocs)
	}
}

// TestContinuesToponymBoundaries pins the look-back: the prefix has to be the whole word directly
// before the candidate, separated by spaces only, and a word the name data does not know.
func TestContinuesToponymBoundaries(t *testing.T) {
	v := NewValidator()
	v.ensureNamesLoaded()
	cases := []struct {
		line string
		at   string // the candidate's first word
		want bool
	}{
		{"San Francisco, Santa Clara", "Francisco", true},
		{"Los Angeles, Maria Lopez", "Angeles", true},
		{"  San   Francisco", "Francisco", true},  // a run of spaces is still one gap
		{"Hasan Francisco", "Francisco", false},   // a longer word that ends in the prefix
		{"san Francisco", "Francisco", false},     // not Title-Case
		{"San,Francisco", "Francisco", false},     // not separated by spaces only
		{"Santa Maria Lopez", "Maria", false},     // "santa" is a given name in the data
		{"La Toya Jackson", "Toya", false},        // "la" is a surname in the data
		{"Ciudadela Juarez", "Juarez", false},     // longer than any prefix: not examined
		{"Francisco Ramirez", "Francisco", false}, // nothing before the candidate
	}
	for _, c := range cases {
		start := strings.Index(c.line, c.at)
		if got := v.continuesToponym(c.line, start); got != c.want {
			t.Errorf("continuesToponym(%q at %q) = %v, want %v", c.line, c.at, got, c.want)
		}
	}
}
