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
// item whose first word is a name the data knows: ", Jackson", " and Charlotte", " or Lake".
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
	return word != "" && v.inNameData(word)
}

// isListBoundaryCommaForm reports whether a comma-form candidate takes the comma of a list.
//
//   - The surname is the LAST word of the item before it: the word directly before the candidate is a
//     capitalised name the data knows. "Will Smith, May Chen" is two items, not "Smith, May Chen" with
//     a stray "Will" in front, because "Will Smith" is itself a name. A label in that position
//     ("Patient Torres, Michael") is not a name, so the genuine form after a label is kept.
//
//   - Or, for the single-word form only, the given name is followed by the next item: a comma, "and",
//     "or" or "&" and a capitalised name the data knows. "Houston, Madison, Jackson" is three items. The
//     next word has to be a name for the same reason as above: "Torres, Michael, Finance" is a genuine
//     form followed by a department, and "Torres, Michael, MD" by a suffix, and both are kept.
//
// What the issue literally proposes, rejecting the form whenever the part after the comma reads as a
// name by itself, is not used on its own: a middle name is very often a surname too, so it would reject
// "Torres, Michael James" and leave "Torres" in cleartext beside a redacted "Michael James".
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

// dropListBoundaryCandidates removes the comma-form candidates that take the comma of a list (see
// isListBoundaryCommaForm). The names the list holds are still candidates of their own: dropping
// "Smith, May Chen" leaves "Will Smith" and "May Chen" to be scored and reported on their own terms.
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
