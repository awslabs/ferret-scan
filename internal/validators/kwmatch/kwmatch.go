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
		return containsSepFlex(text, keyword, fw, false, accept)
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

// ContainsPhrase is [Contains] for a keyword that is PROSE rather than an identifier: every
// space must match at least one separator byte, so "call us" matches "call us" and "call-us"
// but not "callus".
//
// Use it for a phrase whose concatenation is a different word. There are exactly two such
// keywords in this tree — see matchSepFlexAt — and only one of them wants this behaviour.
// Everything else should use [Contains], because a concatenated or camelCase spelling of an
// identifier-style keyword is the case #372 exists to recover.
//
// A single-word keyword contains no space, so this is identical to [Contains] for one.
func ContainsPhrase(text, keyword string) bool {
	return ContainsPhraseLower(strings.ToLower(text), strings.ToLower(keyword))
}

// ContainsPhraseLower is [ContainsPhrase] for callers holding lowercased values.
func ContainsPhraseLower(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	if fw := firstWordLen(keyword); fw != len(keyword) {
		return containsSepFlex(text, keyword, fw, true, nil)
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
// # Why zero separators is the default
//
// A space used to demand at least one separator byte, so "member id" could never match
// "memberid" or "memberId" — text is lowercased before matching, so those two are the
// same string here. camelCase and concatenated keys are the default style of JSON, REST
// payloads and ORM exports, and 14 validator packages match multi-word keywords, so
// every one of them lost its concatenated form. Measured on a JSON file holding
// camelCase/snake_case pairs of the same shape, all four camelCase halves scored 0 while
// their twins scored 75, 80, 90 and 100 — and in a two-key object one member ID was left
// in cleartext beside its redacted twin.
//
// The outer word-boundary rule in containsSepFlex is what keeps this honest: a left
// boundary at the anchor and a right boundary at the end, so "member id" still cannot
// match inside "remembering" or "teammemberid", and "memberidentification" is rejected
// at the right edge.
//
// # Why a phrase form still exists
//
// A concatenation can be a different word. Checked against the system dictionary
// (234,456 lowercased entries) over all 457 multi-word lowercase string literals in
// non-test validator code -- a superset of the keyword lists -- exactly 2 concatenate
// into an English word: "one time" -> "onetime" and "call us" -> "callus". The first is a
// positive OTP keyword, where matching "oneTime" is the point. The second is a phone-context
// SUPPRESSOR in bankaccount, where "callus" would newly silence a real account number on
// any line that happens to mention one — a podiatry billing line is not a hypothetical.
// So prose phrases keep the old behaviour through ContainsPhrase, and identifier-style
// keywords get the new one.
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
