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
// # Word bytes and the Mode parameter
//
// A "word" byte is what a keyword may not be adjacent to; a boundary is the
// string edge or any non-word byte. Validators historically disagreed about
// whether '_' is a word byte, so Mode makes that choice explicit at the call
// site instead of hiding it in a per-package copy. See Mode's documentation for
// which to pick.
//
// Because boundaries are defined by the *text* bytes surrounding a match, a
// keyword whose own edges are non-word characters (for example "w-2") is still
// anchored correctly.
package kwmatch

import "strings"

// Mode selects which bytes count as word characters for boundary detection.
//
// The distinction matters for snake_case text: under [ModeAlnum] the keyword
// "ssn" matches in "customer_ssn" (the '_' is a boundary), while under
// [ModeAlnumUnderscore] it does not (the '_' continues the word).
type Mode uint8

const (
	// ModeAlnum treats [a-z0-9] as word bytes, so '_' acts as a word
	// boundary. Prefer this for context keywords: identifiers in code and
	// config are overwhelmingly snake_case, and a keyword should be found in
	// "customer_ssn" or "test_fixture" just as it is in "customer ssn".
	ModeAlnum Mode = iota

	// ModeAlnumUnderscore treats [a-z0-9_] as word bytes, so a keyword
	// adjacent to '_' does not match. Use only where a keyword must bind to a
	// complete underscore-delimited identifier rather than one of its parts.
	ModeAlnumUnderscore
)

// isWordByte reports whether b is a word byte under m. Callers pass
// already-lowercased text, so the uppercase range is intentionally absent:
// under ASCII lowercasing no byte in 'A'-'Z' can reach here.
func (m Mode) isWordByte(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' {
		return true
	}
	return b == '_' && m == ModeAlnumUnderscore
}

// Contains reports whether text contains keyword as a whole word or phrase,
// case-insensitively. It lowercases both arguments; callers that already hold
// lowercased values should use [ContainsLower] to skip the allocations.
//
// An empty keyword never matches, so a stray "" in a keyword list cannot score
// every line.
func Contains(text, keyword string, m Mode) bool {
	return ContainsLower(strings.ToLower(text), strings.ToLower(keyword), m)
}

// ContainsLower is [Contains] for callers that have already lowercased both
// arguments — the common case in the per-line hot paths, where hoisting the
// lowercasing out of the loop avoids re-lowercasing a potentially huge line
// once per keyword per match.
//
// Passing text or keyword that is not lowercased will simply fail to match
// uppercase bytes; it is not otherwise unsafe.
func ContainsLower(text, keyword string, m Mode) bool {
	return ContainsFunc(text, keyword, m, nil)
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
func ContainsFunc(text, keyword string, m Mode, accept func(start, end int) bool) bool {
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
		leftOK := i == 0 || !m.isWordByte(text[i-1])
		rightOK := end >= len(text) || !m.isWordByte(text[end])
		if leftOK && rightOK && (accept == nil || accept(i, end)) {
			return true
		}
		from = i + 1
	}
	return false
}

// ContainsAny reports whether text contains any of keywords as a whole word.
// Both text and keywords must already be lowercased.
func ContainsAny(text string, keywords []string, m Mode) bool {
	for _, kw := range keywords {
		if ContainsLower(text, kw, m) {
			return true
		}
	}
	return false
}
