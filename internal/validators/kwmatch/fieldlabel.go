// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

import "strings"

// LooksLikeFieldLabel reports whether a line is a bare form-field LABEL rather than
// prose that happens to mention a keyword.
//
// # Why this exists
//
// The label-gated validators (PASSPORT, MEDICAL_ID, DRIVERS_LICENSE) report nothing
// without a nearby label, and the keyword search stops at the newline. In a form or
// two-column layout the label sits on the line ABOVE its value:
//
//	Field: Passport Number
//	Value: 512345678
//
// which produced no passport finding at all — the number was reported as an SSN at 50
// instead, so it was redacted under SSN's partial-mask rule and four digits stayed
// readable. Member IDs and licences in the same shape were reported as nothing and left
// in cleartext.
//
// # Why a keyword on the previous line is not sufficient
//
// Simply consulting the previous line for a keyword admits prose. Measured, these two
// shapes are indistinguishable on length, keyword presence and digit absence:
//
//	Please renew your driver's license soon.   <- prose; the next line is NOT a licence
//	Driver's License Number                    <- a label; the next line IS one
//
// So the test is on the SHAPE of the candidate label line, not merely on its content.
//
// # The rule
//
// A field label is short, is not a sentence, and consists of label vocabulary. Prose
// fails on at least one of those. Each condition earns its place:
//
//   - non-empty after trimming, and at most maxFieldLabelLen bytes. A bare field label
//     is short; a sentence usually is not.
//   - does not end in '.', '!' or '?'. A cheap fast path, NOT the discriminator: with it
//     removed the vocabulary rule below still rejects every prose case in the tests, so
//     it earns its place by skipping the tokenizing pass on obvious sentences rather than
//     by catching anything the purity check would miss. Verified by mutation.
//   - contains at least one of the caller's positive keywords, so an unrelated short
//     line cannot open the window.
//   - EVERY alphabetic word is either one of those keywords or generic label vocabulary.
//     This is the discriminator: "Driver's License Number" is all label words, while
//     "Please renew your driver's license soon" carries please/renew/your/soon.
//
// Digits are permitted (a label may read "ID Number (2 of 3)"), but a word containing a
// digit is not treated as label vocabulary, so a data row does not qualify.
//
// The caller supplies its own keywords, so this stays a shape test and does not become a
// second, divergent copy of any validator's vocabulary.
func LooksLikeFieldLabel(line string, keywords []string) bool {
	t := strings.TrimSpace(line)
	if t == "" || len(t) > maxFieldLabelLen {
		return false
	}
	switch t[len(t)-1] {
	case '.', '!', '?':
		return false
	}
	// Lowercased before the keyword checks: ContainsAny matches whole words but is
	// case-SENSITIVE on the text (ContainsLower is its case-folding sibling), so
	// "Driver's License Number" missed every keyword while its individual lowercased
	// words matched — the bug this ordering fixes.
	lower := strings.ToLower(t)
	if !ContainsAny(lower, keywords) {
		return false
	}
	for _, w := range strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '\''
	}) {
		if hasDigit(w) {
			// A short digit run is label decoration ("2 of 3", "line 1"). A LONG one is
			// a value, and a line that already carries its value must not open a window
			// for the next line — otherwise "member 449871234567" would vouch for
			// whatever follows it.
			if digitRun(w) >= valueDigitRun {
				return false
			}
			continue
		}
		if genericLabelWords[w] {
			continue
		}
		if keywordWord(w, keywords) {
			continue
		}
		return false
	}
	return true
}

// keywordWord reports whether w appears as one of the WORDS of any keyword.
//
// Per-word rather than ContainsAny(w, keywords), because most of these vocabularies are
// multi-word: "member id", "driver's license", "medical record". Testing the whole
// keyword against a single word can never match, so "Member ID" was rejected as
// non-label vocabulary even though "member id" is a keyword — the bug this fixes.
func keywordWord(w string, keywords []string) bool {
	for _, kw := range keywords {
		for _, part := range strings.FieldsFunc(strings.ToLower(kw), func(r rune) bool {
			return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '\''
		}) {
			if part == w {
				return true
			}
		}
	}
	return false
}

// maxFieldLabelLen bounds a candidate label line. Long enough for the real forms
// ("Driver's License Number", "Insurance Member Identification"), short enough that a
// sentence rarely fits.
const maxFieldLabelLen = 48

// genericLabelWords are the words that decorate a field label without naming the field.
// They are what lets "Field: Passport Number" and "Member ID (primary)" qualify while
// keeping the vocabulary check strict about everything else.
var genericLabelWords = map[string]bool{
	"field": true, "value": true, "number": true, "no": true, "num": true,
	"id": true, "identifier": true, "identification": true, "code": true,
	"primary": true, "secondary": true, "optional": true, "required": true,
	"of": true, "or": true, "and": true, "the": true, "a": true, "an": true,
	"details": true, "detail": true, "info": true, "information": true,
	"type": true, "name": true, "date": true, "issued": true, "expiry": true,
	"state": true, "country": true, "region": true, "status": true,
}

// valueDigitRun is the digit-run length at which a token reads as a value rather than
// as label decoration. Deliberately low: every identifier this guards is longer.
const valueDigitRun = 4

// digitRun returns the longest consecutive digit run in s.
func digitRun(s string) int {
	best, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			cur++
			if cur > best {
				best = cur
			}
			continue
		}
		cur = 0
	}
	return best
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}
