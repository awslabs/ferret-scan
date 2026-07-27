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
