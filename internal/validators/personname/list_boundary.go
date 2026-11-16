// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// A comma-form candidate taken across the comma of a list (#936).
//
// last_comma_first and its two variants read "Surname, Given" from any capitalised word, a comma and
// another capitalised word. In a list that shape sits on every comma, so the pattern joined the last
// word of one item to the next item and reported the pair as one name. Measured on main @ 2fb4719 with
// --config /dev/null, from comments of this package that list names on purpose:
//
//	technical_terms.go:340   the comma form across the first two of four listed names   100 and 93
//	technical_terms.go:379   the same across a list of five real names                    99 twice
//	technical_terms.go:357   a list of single-word cities                                 97 twice
//	validator.go:856, :878   the first two of three listed names                          99 twice
//
// The span is what the redactor rewrites, so it was also a redaction defect: the tail of one name and
// all of the next were masked as one value, and the head of the first was left.
//
// dropListBoundaryCandidates removes a comma-form candidate when the comma is shown to separate list
// items by either of two things next to the candidate. Each is read from at most one word on either
// side, so the filter is constant work per candidate.

// listWordMax bounds the word read on either side of a candidate. It is the longest token the name
// patterns accept (one capital and up to 29 lowercase letters), so nothing a pattern could match is cut.
const listWordMax = 30

// commaFormPatterns are the patterns that read "Surname, Given": the only ones that span a comma.
var commaFormPatterns = map[string]bool{
	"last_comma_first":         true,
	"last_comma_first_middle":  true,
	"last_comma_first_initial": true,
}

// titleWordBefore returns the Title-Case word that ends at the run of spaces directly before start, or
// "" when there is no such word: the byte before start is not a space, the word is not Title-Case, or it
// is longer than listWordMax.
func titleWordBefore(line string, start int) string {
	i := start
	for i > 0 && line[i-1] == ' ' {
		i--
	}
	if i == start || i == 0 {
		return ""
	}
	end := i
	n := 0
	for i > 0 {
		r, size := utf8.DecodeLastRuneInString(line[:i])
		if !isNameLetter(r) {
			break
		}
		if n++; n > listWordMax {
			return ""
		}
		i -= size
	}
	if i == end {
		return ""
	}
	return titleWord(line[i:end])
}

// titleWordAt returns the Title-Case word that starts at i, or "" when the text there is not one.
func titleWordAt(line string, i int) string {
	end := i
	n := 0
	for end < len(line) {
		r, size := utf8.DecodeRuneInString(line[end:])
		if !isNameLetter(r) {
			break
		}
		if n++; n > listWordMax {
			return ""
		}
		end += size
	}
	return titleWord(line[i:end])
}

// titleWord returns word when it is one capital followed only by lowercase letters, else "".
func titleWord(word string) string {
	if word == "" {
		return ""
	}
	for k, r := range word {
		if k == 0 && !unicode.IsUpper(r) {
			return ""
		}
		if k > 0 && !unicode.IsLower(r) {
			return ""
		}
	}
	if utf8.RuneCountInString(word) < 2 {
		return ""
	}
	return word
}

// continuesAsName reports whether the comma, conjunction or ampersand at line[i:] starts another list
// item that is ONE known name and nothing more: ", Jackson", " and Charlotte", " or Lake". A list of
// such items is a list of places or surnames, and a "Surname, Given" read across its comma is two of
// them joined.
//
// It is false when the next item is a person written Given Surname (", Stephen Redding",
// " and Stephen R. Yeaple"): a known given name followed by another capitalised word or an initial.
// A surname-first form in front of such an item is the first author of a reference list, the one
// convention that inverts only the first name ("Griffith, Rachel, Stephen Redding and Helen Simpson"),
// and the first #936 fix lost it: measured on the public corpus, 5 real first authors in one govdocs
// bibliography were no longer reported while their co-authors were. The residual ambiguity is a
// two-word place whose first word is a given name (", Jackson Hole"): it reads as a person here, so
// the form before it is kept, as it was before #936. A list in which EVERY name is inverted
// ("Griffith, Rachel, Simpson, Helen") cannot be told from a list of single words by shape, and only
// its last item is kept.
func (v *Validator) continuesAsName(line string, i int) bool {
	j := i
	switch {
	case j < len(line) && line[j] == ',':
		j++
	default:
		k := j
		for k < len(line) && line[k] == ' ' {
			k++
		}
		if k == j {
			return false
		}
		matched := false
		for _, conj := range []string{"and", "or", "&"} {
			if len(line)-k > len(conj) && line[k:k+len(conj)] == conj && line[k+len(conj)] == ' ' {
				j, matched = k+len(conj), true
				break
			}
		}
		if !matched {
			return false
		}
	}
	k := j
	for k < len(line) && line[k] == ' ' {
		k++
	}
	if k == j {
		return false
	}
	word := titleWordAt(line, k)
	if word == "" || !v.inNameData(word) {
		return false
	}
	return !(v.isGivenName(word) && nameTokenAfter(line, k+len(word)))
}

// nameTokenAfter reports whether a second name-like token follows the word that ends at line[i:],
// after one or more spaces: a Title-Case word ("Redding") or an initial ("R."). Bounded by
// listWordMax through titleWordAt.
func nameTokenAfter(line string, i int) bool {
	j := i
	for j < len(line) && line[j] == ' ' {
		j++
	}
	if j == i || j >= len(line) {
		return false
	}
	if titleWordAt(line, j) != "" {
		return true
	}
	r, size := utf8.DecodeRuneInString(line[j:])
	return unicode.IsUpper(r) && j+size < len(line) && line[j+size] == '.'
}

// isListBoundaryCommaForm reports whether a comma-form candidate takes the comma of a list.
//
//   - The surname is the LAST word of the item before it: the word directly before the candidate is a
//     capitalised name the data knows, so that word and the surname are a name of their own and the
//     comma ends it. A label in that position (patient, contact, employee) is no name, so the genuine
//     form after a label is kept.
//
//   - Or, for the single-word form only, the given name is followed by the next item: a comma, "and",
//     "or" or "&" and a capitalised name the data knows, as in a list of single-word cities. The next
//     word has to be a name for the same reason as above: a genuine form followed by a department or
//     by a suffix such as MD is kept. So is a form followed by a person written Given Surname, which
//     is how a reference list continues after its inverted first author (see continuesAsName).
//
// What the issue literally proposes, rejecting the form whenever the part after the comma reads as a
// name by itself, is not used on its own: a middle name is very often a surname too, so it would reject
// the genuine three-word form and leave its surname in cleartext beside a redacted given and middle
// name. TestGenuineCommaFormsKeepTheirConfidence pins those cases.
func (v *Validator) isListBoundaryCommaForm(line string, c PatternMatch) bool {
	if !commaFormPatterns[c.Pattern.Name] {
		return false
	}
	if before := titleWordBefore(line, c.StartIndex); before != "" && v.inNameData(before) {
		return true
	}
	return c.Pattern.Name == "last_comma_first" && v.continuesAsName(line, c.EndIndex)
}

// inNameData reports whether a Title-Case word, lowercased, is in either name list.
func (v *Validator) inNameData(word string) bool {
	lower := strings.ToLower(word)
	normalized := v.normalizeAccents(lower)
	if v.firstNames != nil && (v.firstNames[lower] || v.firstNames[normalized]) {
		return true
	}
	return v.lastNames != nil && (v.lastNames[lower] || v.lastNames[normalized])
}

// isGivenName reports whether a Title-Case word, lowercased, is in the given-name list.
func (v *Validator) isGivenName(word string) bool {
	if v.firstNames == nil {
		return false
	}
	lower := strings.ToLower(word)
	return v.firstNames[lower] || v.firstNames[v.normalizeAccents(lower)]
}

// dropListBoundaryCandidates removes the comma-form candidates that take the comma of a list (see
// isListBoundaryCommaForm). The names the list holds are still candidates of their own: dropping the
// span across the comma leaves the name on each side of it to be scored and reported on its own terms.
//
// Both findNames* paths call it on findPatternCandidates' result. It filters in place.
func (v *Validator) dropListBoundaryCandidates(line string, candidates []PatternMatch) []PatternMatch {
	kept := candidates[:0]
	for _, c := range candidates {
		if v.isListBoundaryCommaForm(line, c) {
			continue
		}
		kept = append(kept, c)
	}
	return kept
}
