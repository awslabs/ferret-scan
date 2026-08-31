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
	// ContainsAnyLabel, not ContainsAny: a label written without separators is still that label.
	//
	// This is the gate that actually rejected a camelCase label, and it fires BEFORE the per-word
	// loop below — so teaching only that loop about concatenated spellings would have been a no-op.
	// Measured at HEAD: for "memberId:" this returned false while "member id:" and "member_id:"
	// returned true, which is why the spaced spellings opened a cross-line window and the camelCase
	// one did not (#409).
	//
	// Widening here is the safe direction: this function only ever ADMITS context that would
	// otherwise be ignored, so it can add a finding and never remove one. That is the restriction
	// ContainsLabel documents, and the per-word loop below is what still keeps a non-label line out.
	if !ContainsAnyLabel(lower, keywords) {
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

// keywordWord reports whether w appears as one of the WORDS of any keyword, or is the whole keyword
// with its separators removed.
//
// Per-word rather than ContainsAny(w, keywords), because most of these vocabularies are
// multi-word: "member id", "driver's license", "medical record". Testing the whole
// keyword against a single word can never match, so "Member ID" was rejected as
// non-label vocabulary even though "member id" is a keyword — the bug this fixes.
//
// The concatenated spelling counts because it is the same label written the way a JSON key or an ORM
// field is: "memberid" for "member id", "driverslicensenumber" for "drivers license number". Without
// it, a line consisting of exactly that one token has no qualifying word at all and is rejected as
// non-label vocabulary (#409).
//
// An APOSTROPHE is kept by the split below, so it is part of a word here rather than a separator, and
// the concatenation of "driver's license number" is "driver'slicensenumber" — NOT
// "driverslicensenumber", which this comment claimed until #438. That claim mattered: it made the
// camelCase gap look already-closed, and the gap was real (measured 0 findings for
// `driversLicenseNumber: D1234567`). Note the asymmetry with isWordByte, which treats an apostrophe
// as a word BOUNDARY — so a bare "driver" whole-word-matches inside "driver'slicensenumber" but not
// inside "driverslicensenumber". Both behaviours are load-bearing for existing callers; what is not
// safe is documenting one and relying on the other. The fix for #438 was a vocabulary one: a
// three-word keyword whose words concatenate to the field name the exports actually write.
//
// Only the FULL concatenation, deliberately. Accepting an arbitrary run of a keyword's words would
// admit "licensenumber" from "drivers license number", and this loop is the false-positive gate that
// keeps a non-label line from opening a cross-line window, so the narrowest widening that closes the
// gap is the right one.
//
// The concatenation is compared INCREMENTALLY rather than built. A strings.Builder here cost one
// allocation per keyword — measured at +1 alloc/op and +12% on a label line walked word by word —
// while consuming w as the keyword's words are visited costs none, and abandons a keyword as soon as
// its prefix diverges.
func keywordWord(w string, keywords []string) bool {
	for _, kw := range keywords {
		consumed := 0   // bytes of w matched by this keyword's words so far
		aligned := true // w is still a prefix-match of the concatenation
		for _, part := range strings.FieldsFunc(strings.ToLower(kw), func(r rune) bool {
			return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '\''
		}) {
			if part == w {
				return true
			}
			if aligned {
				if consumed+len(part) <= len(w) && w[consumed:consumed+len(part)] == part {
					consumed += len(part)
				} else {
					aligned = false
				}
			}
		}
		if aligned && consumed == len(w) && consumed > 0 {
			return true
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
