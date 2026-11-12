// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"regexp"
	"strings"
)

// Street names read as people (#935).
//
// A street is named after a person or a month as often as not, so the words between a house number
// and a street type are name-shaped and the name data admits them. Measured on main @ 2fb4719 with
// --config /dev/null, from this repository's own comments and docs:
//
//	the residence example of #773, a numbered lane in Idaho   92 for the street, 67-91 for the
//	                                                          street type plus the city after it
//	the legacy-redactor example, a numbered boulevard         100 for the three words before "Blvd"
//
// The address validator reports the same spans as US_STREET_ADDRESS, so the bytes stay reported and
// redacted when both checks run; the PERSON_NAME finding on top of them is the false positive.

// streetTypeAlt is the street-type vocabulary, the unambiguous subset of the address validator's
// streetSuffixAlt (internal/validators/address/validator.go). The residential suffixes there (green,
// glen, ridge, point, ...) are left out: they are given names and surnames too, and a house number in
// front of a person whose surname is one of them is not enough to call the pair a street.
const streetTypeAlt = `Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|` +
	`Place|Pl|Parkway|Pkwy|Terrace|Ter|Circle|Cir|Highway|Hwy|Square|Sq|Trail|Trl`

// streetNamePattern matches a numbered street: a house number of one to six digits, one to four
// Title-Case words, and a street type. Group 1 is the span. Bounded on both sides like the name
// patterns, so "Lane" does not match inside "Laneway". RE2, so linear in the line.
var streetNamePattern = regexp.MustCompile(`(?:^|[^0-9A-Za-z])(\d{1,6}[ ]+(?:[` + nameUpper + `][` +
	nameLower + `]+[ ]+){1,4}(?:` + streetTypeAlt + `)\.?)(?:[^` + nameLetter + `]|$)`)

// streetTypeWords is streetTypeAlt as lowercase words, for the comma-form check.
var streetTypeWords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Split(streetTypeAlt, "|") {
		m[strings.ToLower(w)] = true
	}
	return m
}()

// streetSpans returns the byte spans of every numbered street on the line. A line without a digit
// cannot hold one, so the regexp only runs where it can match.
func streetSpans(line string) [][2]int {
	if !strings.ContainsAny(line, "0123456789") {
		return nil
	}
	var spans [][2]int
	for _, loc := range streetNamePattern.FindAllStringSubmatchIndex(line, -1) {
		if len(loc) >= 4 && loc[2] >= 0 {
			spans = append(spans, [2]int{loc[2], loc[3]})
		}
	}
	return spans
}

// insideStreet reports whether [start, end) overlaps any span.
func insideStreet(spans [][2]int, start, end int) bool {
	for _, s := range spans {
		if start < s[1] && s[0] < end {
			return true
		}
	}
	return false
}

// isStreetCityCommaForm reports whether a comma-form candidate is a street type followed by a town:
// its "surname" is a street-type word and its "given name" is not a given name the data knows. That
// is the tail of an address once the house number is out of reach, not a person written surname
// first; the same street-type surname before a known given name keeps its finding.
func (v *Validator) isStreetCityCommaForm(c PatternMatch) bool {
	if !strings.HasPrefix(c.Pattern.Name, "last_comma_first") {
		return false
	}
	comma := strings.IndexByte(c.Text, ',')
	if comma <= 0 {
		return false
	}
	surname := strings.ToLower(c.Text[:comma])
	if !streetTypeWords[surname] {
		return false
	}
	given := strings.Fields(c.Text[comma+1:])
	if len(given) == 0 {
		return false
	}
	lower := strings.ToLower(given[0])
	return v.firstNames == nil || !(v.firstNames[lower] || v.firstNames[v.normalizeAccents(lower)])
}
