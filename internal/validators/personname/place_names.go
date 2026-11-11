// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Candidates that are a place or a garbled fragment rather than a person (#935).
//
// The patterns match Title-Case SHAPE and the surname gate asks only whether the last token is a
// surname, so a place whose last word is also a surname is reported. Measured on main @ 2fb4719 with
// --config /dev/null, each of these was reported at HIGH from this repository's own files:
//
//	"Hong Kong" and "Middle East"                  100 and 91   (ooxml_auxiliary.go:158)
//	"Flushing Meadows<ENDASH>Corona"                      91   (execguard.go:314)
//	`La Paz` is therefore still reported                  91   (CHANGELOG.md:1877)
//	(`NEM MIN`, `EI LUO`)                           92 twice   (CHANGELOG.md:1960)
//	the comma form across two Californian cities          99   (technical_terms.go:393)
//
// They were HIGH because those lines also discuss the check by its type name, which is two positive
// context words (+24). With no context they read 65 to 100: the Chinese city is 100 alone, its first
// word being a given name in the data and its second a surname.
//
// dropPlaceCandidates removes them before scoring, for the three reasons below. Each is a property of
// the candidate's own text or of the one word directly before it, so the filter is constant work per
// candidate and cannot drop a candidate for something said elsewhere on the line.

// toponymPhrasesMap holds whole multi-word place names that the name data would report.
//
// Keyed on the WHOLE candidate, which is what makes it a safe suppressor, as for fontFamiliesMap: the
// entire matched value has to be the place, so no token of it is silenced anywhere else. That is also
// why the Bolivian capital can be here although toponymPrefixMap deliberately defers to the data for
// its first word: deferring keeps everyone surnamed la, le or lake reportable, and an entry for the
// two-word phrase silences none of them.
//
// Deliberately NOT a gazetteer. A list of every place decays and is never complete, so this holds only
// what was measured to fire: the values above, and the region and compass names found on the public
// corpus (`by-format/`, 639 files) with the same construction, a position word that is not a given
// name in front of a word that is a surname (the three-word Russian region 10 times, the English
// compass region 11). A place that shares a real person's name stays out on purpose: no rule can tell
// that place from that person, and guessing costs a finding that would otherwise have been redacted.
//
// The far larger class of US place names that end in grove, park, hill, rock or beach is not here
// either. Their last word is a common surname, so a phrase list would be the gazetteer this one refuses
// to be, and a word rule would delete everyone surnamed park or hill.
var toponymPhrasesMap = map[string]bool{
	// measured in this repository (#935)
	"hong kong": true, "middle east": true, "flushing meadows": true, "la paz": true,
	// region and compass names: a position word that is not a given name, then a surname
	"far east": true, "near east": true, "russian far east": true,
	"north east": true, "north west": true, "south east": true, "south west": true,
}

// isToponymPhrase reports whether a candidate's whole text is one of toponymPhrasesMap, alone or as
// the head of a hyphenated compound: the park in Queens is written with its second neighbourhood
// after a hyphen, and that is still the park.
func isToponymPhrase(text string) bool {
	lower := strings.ToLower(text)
	if toponymPhrasesMap[lower] {
		return true
	}
	if i := strings.IndexByte(lower, '-'); i > 0 && toponymPhrasesMap[lower[:i]] {
		return true
	}
	return false
}

// maxToponymPrefixLen bounds how far continuesToponym looks back. The longest entry in
// toponymPrefixMap has six letters ("ciudad", "puerto"); a longer preceding word cannot be one, so the
// look-back stops there and stays constant per candidate however long the line is.
const maxToponymPrefixLen = 8

// continuesToponym reports whether the candidate starting at start is the tail of a place name: the
// word directly before it, separated by spaces only, is a toponym generator that the name data does
// not know (see toponymPrefixMap and isToponymPrefixGiven).
//
// isToponymPrefixGiven already rejects a candidate whose FIRST word is such a prefix. But Go's regexp
// takes leftmost non-overlapping matches per pattern, so in a comma-separated list of cities the comma
// pattern can start at the second word of the first city: the prefix sits outside the candidate and
// was never examined, and the tail of one city plus the next city was scored as Surname, Given at 99.
// A candidate whose first word is the second word of a place is not a name.
//
// The prefix has to be one the data does not know, exactly as in isToponymPrefixGiven, so "santa",
// "monte", "la" or "fort" in front of a candidate changes nothing: each is a given name or a surname,
// and the three words may be one person.
func (v *Validator) continuesToponym(line string, start int) bool {
	i := start
	for i > 0 && line[i-1] == ' ' {
		i--
	}
	if i == start || i == 0 {
		return false
	}
	end := i
	for i > 0 && end-i <= maxToponymPrefixLen {
		r, size := utf8.DecodeLastRuneInString(line[:i])
		if !isNameLetter(r) {
			break
		}
		i -= size
	}
	if i == end || end-i > maxToponymPrefixLen {
		return false
	}
	if i > 0 {
		// The word must start at a boundary: a longer word that merely ends in a prefix is not one.
		if r, _ := utf8.DecodeLastRuneInString(line[:i]); isNameLetter(r) {
			return false
		}
	}
	word := line[i:end]
	if r, _ := utf8.DecodeRuneInString(word); !unicode.IsUpper(r) {
		return false
	}
	return v.isToponymPrefixGiven(word)
}

// capsFragmentSyllableMax is the longest token an all-caps candidate can have and still be read as a
// run of short syllables.
const capsFragmentSyllableMax = 3

// isUnsupportedCapsFragment reports whether an all_caps_name candidate is made only of short
// syllables and one of them is no name the data knows.
//
// The two changelog fragments above are text an older extraction path recovered from a binary
// format, and both were reported at 92. The surname gate passed them because their second syllables
// are surnames, and for a two- or three-letter all-caps token that is weak evidence: the surname list
// holds many single syllables (li, wu, ng, ho, hu, xu, ma, lu, yu, min, luo), so a garbled syllable
// hits one by chance. A run of short syllables therefore needs EVERY syllable to be a name the data
// knows, as a given name or as a surname. The real names of this shape are mostly written surname
// first, and both of their syllables are in the data; the fragments' other syllable is in neither list.
//
// Only the all-caps pattern, and only when every token is short: a longer token, or the same letters
// in mixed case, is not the shape extraction garbage takes, and is left to the existing gates.
func (v *Validator) isUnsupportedCapsFragment(c PatternMatch) bool {
	if c.Pattern.Name != "all_caps_name" {
		return false
	}
	tokens := strings.Fields(c.Text)
	for _, tk := range tokens {
		if utf8.RuneCountInString(tk) > capsFragmentSyllableMax {
			return false
		}
	}
	for _, tk := range tokens {
		if !v.isKnownNameToken(tk) {
			return true
		}
	}
	return false
}

// isKnownNameToken reports whether token, in any case, is in either name list.
func (v *Validator) isKnownNameToken(token string) bool {
	lower := strings.ToLower(token)
	normalized := v.normalizeAccents(lower)
	if v.firstNames != nil && (v.firstNames[lower] || v.firstNames[normalized]) {
		return true
	}
	return v.lastNames != nil && (v.lastNames[lower] || v.lastNames[normalized])
}

// dropPlaceCandidates removes the candidates that are a place or a garbled fragment rather than a
// person: a whole toponym (toponymPhrasesMap), the tail of one (continuesToponym), or a run of short
// all-caps syllables the name data does not support (isUnsupportedCapsFragment).
//
// It runs on findPatternCandidates' result, so both findNames* paths and both the plain and the masked
// pass go through it. It filters in place: the slice is the one findPatternCandidates just built.
func (v *Validator) dropPlaceCandidates(line string, candidates []PatternMatch) []PatternMatch {
	kept := candidates[:0]
	for _, c := range candidates {
		if isToponymPhrase(c.Text) || v.continuesToponym(line, c.StartIndex) || v.isUnsupportedCapsFragment(c) {
			continue
		}
		kept = append(kept, c)
	}
	return kept
}
