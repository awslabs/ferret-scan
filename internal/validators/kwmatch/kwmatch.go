// Package kwmatch provides the whole-word keyword matching shared by the
// validator packages' context scoring.
//
// Every validator scores a match by looking for context keywords near it
// ("ssn", "test", "invoice"). Plain substring matching is wrong for this: short
// keywords fire inside unrelated words — "hr" in "Christopher", "ein" in
// "Einstein", "park" in "parking", "arn" in "learn" — which both fabricates
// context boosts and spuriously penalizes real findings. Each validator had
// grown its own byte-identical copy of the same boundary-scanning helper; this
// package is the single implementation they all call.
//
// The scan is a plain strings.Index loop with manual boundary checks rather
// than a compiled regex on purpose. Callers invoke it on the order of a hundred
// times per match (AnalyzeContext, findKeywords, per-line context caches), and
// a regexp.MatchString per keyword measured ~13x slower on keyword-dense input.
//
// # Word bytes
//
// A "word" byte is [a-z0-9]: what a keyword may not be adjacent to. A boundary
// is the string edge or any other byte. Notably '_' is a boundary, NOT a word
// byte, so a keyword is found inside a snake_case identifier exactly as it is
// between spaces: "ssn" matches in "customer_ssn", "test" in
// "account_number_test". Identifiers in code and config are overwhelmingly
// snake_case, and those are primary scan targets — treating '_' as a word byte
// silently cost both recall (positive keywords never fired) and precision
// (test/sample markers never suppressed).
//
// This is also why the scan does not use Go's \b: RE2 defines \b on \w, which
// includes '_', so `\btest\b` cannot express this boundary and RE2 has no
// lookaround to work around it.
//
// Because boundaries are defined by the *text* bytes surrounding a match, a
// keyword whose own edges are non-word characters (for example "w-2") is still
// anchored correctly.
package kwmatch

import "strings"

// isWordByte reports whether b is a word byte. Callers pass already-lowercased
// text, so the uppercase range is intentionally absent: under ASCII lowercasing
// no byte in 'A'-'Z' can reach here.
func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// Contains reports whether text contains keyword as a whole word or phrase,
// case-insensitively. It lowercases both arguments; callers that already hold
// lowercased values should use [ContainsLower] to skip the allocations.
//
// An empty keyword never matches, so a stray "" in a keyword list cannot score
// every line.
func Contains(text, keyword string) bool {
	return ContainsLower(strings.ToLower(text), strings.ToLower(keyword))
}

// ContainsLower is [Contains] for callers that have already lowercased both
// arguments — the common case in the per-line hot paths, where hoisting the
// lowercasing out of the loop avoids re-lowercasing a potentially huge line
// once per keyword per match.
//
// Passing text or keyword that is not lowercased will simply fail to match
// uppercase bytes; it is not otherwise unsafe.
func ContainsLower(text, keyword string) bool {
	return ContainsFunc(text, keyword, nil)
}

// ContainsFunc is [ContainsLower] with an optional filter on where a match may
// land. Both arguments must already be lowercased.
//
// When accept is non-nil it is called with the [start, end) byte range of each
// whole-word occurrence, and the scan continues until accept returns true.
// This lets callers that stitch a bounded window together from several pieces
// (for example a context window joined to a line by a single space) consider
// only the occurrences that touch the junction, so slicing the text cannot
// fabricate matches that the full text would not have produced.
//
// A nil accept accepts any occurrence.
func ContainsFunc(text, keyword string, accept func(start, end int) bool) bool {
	if keyword == "" {
		return false
	}
	if fw := firstWordLen(keyword); fw != len(keyword) {
		return containsSepFlex(text, keyword, fw, true, accept)
	}
	for from := 0; from+len(keyword) <= len(text); {
		i := strings.Index(text[from:], keyword)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(keyword)
		leftOK := i == 0 || !isWordByte(text[i-1])
		rightOK := end >= len(text) || !isWordByte(text[end])
		if leftOK && rightOK && (accept == nil || accept(i, end)) {
			return true
		}
		from = i + 1
	}
	return false
}

// ContainsAny reports whether text contains any of keywords as a whole word.
// Both text and keywords must already be lowercased.
func ContainsAny(text string, keywords []string) bool {
	for _, kw := range keywords {
		if ContainsLower(text, kw) {
			return true
		}
	}
	return false
}

// ContainsLabel is [Contains] with the keyword's spaces allowed to match ZERO separator
// bytes, so "member id" also finds "memberid" and — since text is lowercased before matching
// — the camelCase "memberId". That spelling is the default key style of JSON, REST payloads
// and ORM exports.
//
// Use it ONLY for a keyword that identifies the value it labels, never for one that
// suppresses or penalizes a finding. See matchSepFlexAt for why that asymmetry is not a
// stylistic preference: widening a suppressor's reach silences real values.
//
// The outer whole-word rule still applies, so "member id" does not match inside
// "remembering", "teammemberid" or "memberidentification".
//
// A single-word keyword contains no space, so this is identical to [Contains] for one.
func ContainsLabel(text, keyword string) bool {
	return ContainsLabelLower(strings.ToLower(text), strings.ToLower(keyword))
}

// ContainsLabelLower is [ContainsLabel] for callers holding lowercased values.
func ContainsLabelLower(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	if fw := firstWordLen(keyword); fw != len(keyword) {
		return containsSepFlex(text, keyword, fw, false, nil)
	}
	return ContainsLower(text, keyword)
}

// --- PR6 separator-flexible multi-word matching -------------------------------

// isSepByte is the separator class a keyword space may match. Deliberately
// narrow: '.' and '/' produced measured false positives across sentence and URL
// boundaries.
func isSepByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '_' || b == '-'
}

// firstWordLen returns the length of the keyword prefix before its first space.
func firstWordLen(keyword string) int {
	if i := strings.IndexByte(keyword, ' '); i >= 0 {
		return i
	}
	return len(keyword)
}

// lazyPrefilterAfter bounds the repeated-anchor adversarial shape.
const lazyPrefilterAfter = 4

// allWordsPresent reports whether every space-delimited word of keyword occurs
// verbatim in text. Sound as a negative filter: separator flexibility only
// widens what a SPACE may match; non-space bytes stay literal.
func allWordsPresent(text, keyword string) bool {
	for _, w := range strings.Fields(keyword) {
		if !strings.Contains(text, w) {
			return false
		}
	}
	return true
}

// matchSepFlexAt walks keyword against text[start:], letting each space RUN in
// the keyword consume a run of separator bytes. Returns the end offset or -1.
//
// requireSep decides whether that run may be EMPTY, and it is the whole of #372.
//
// # What zero separators buys
//
// With a separator required, "member id" can never match "memberid" or "memberId" — text is
// lowercased before matching, so those two are the same string here. camelCase and
// concatenated keys are the default style of JSON, REST payloads and ORM exports. Measured on
// a JSON file holding camelCase/snake_case pairs of the same shape, the camelCase halves
// scored 0 while their twins scored 75, 80 and 100 — and in a two-key object one member ID
// sat in cleartext beside its redacted twin, because only reported findings reach the
// redactor.
//
// # Why it is OPT-IN, and asymmetric
//
// A keyword list is not one kind of thing. A POSITIVE keyword identifies the value it labels,
// so widening its reach can only add findings. A SUPPRESSOR withholds or vetoes a finding, so
// widening ITS reach silences real values — and a silenced finding is never redacted.
//
// That is not hypothetical. It shipped, briefly, when this defaulted to zero separators:
// medicalid's suppressor "ip address" began matching the ubiquitous key "ipAddress", and that
// veto is unconditional (nonInsuranceKeywordPresent), so
//
//	{"member_id": "W1234567801", "ipAddress": "10.11.12.13"}
//
// lost its INSURANCE_MEMBER_ID finding entirely and was written back with the member ID in
// CLEARTEXT while the IP was masked — a redacted file that reported success and leaked. The
// same shape threatens ssn, whose suppressor list holds "part number", "policy number",
// "order number", "employee id" and "tax id": every one of those is a common camelCase key,
// and every one of them would newly veto a real SSN on the same line.
//
// A dictionary screen does not catch this. "ipaddress" is not an English word, so checking
// concatenations against /usr/share/dict/words passed it. The property that matters is not
// "is a word" but "is a token that occurs in real text", which no word list decides.
//
// So the widening is reached only through [ContainsLabel], and only positive label lists call
// it. [Contains] and its siblings keep requiring a separator, which is what every suppressor
// in this tree gets.
//
// The outer word-boundary rule in containsSepFlex is what keeps even the widened form honest:
// a left boundary at the anchor and a right boundary at the end, so "member id" still cannot
// match inside "remembering" or "teammemberid", and "memberidentification" is rejected at the
// right edge.
//
// '.' and '/' remain excluded from the separator class in both modes, by measurement: they
// cross sentence and URL boundaries, where the two words are unrelated.
func matchSepFlexAt(text, keyword string, start int, requireSep bool) int {
	ti, ki := start, 0
	for ki < len(keyword) {
		if keyword[ki] == ' ' {
			for ki < len(keyword) && keyword[ki] == ' ' {
				ki++
			}
			n := 0
			for ti < len(text) && isSepByte(text[ti]) {
				ti++
				n++
			}
			if requireSep && n == 0 {
				return -1
			}
			continue
		}
		if ti >= len(text) || text[ti] != keyword[ki] {
			return -1
		}
		ti++
		ki++
	}
	return ti
}

// containsSepFlex anchors on the keyword's first word and verifies the rest with
// separator flexibility, applying the same outer word-boundary rule.
func containsSepFlex(text, keyword string, fw int, requireSep bool, accept func(start, end int) bool) bool {
	anchor := keyword[:fw]
	misses := 0
	for from := 0; from+fw <= len(text); {
		i := strings.Index(text[from:], anchor)
		if i < 0 {
			return false
		}
		i += from
		if i == 0 || !isWordByte(text[i-1]) {
			if end := matchSepFlexAt(text, keyword, i, requireSep); end > 0 {
				if end >= len(text) || !isWordByte(text[end]) {
					if accept == nil || accept(i, end) {
						return true
					}
				}
			}
		}
		misses++
		if misses == lazyPrefilterAfter && !allWordsPresent(text, keyword) {
			return false
		}
		from = i + 1
	}
	return false
}
