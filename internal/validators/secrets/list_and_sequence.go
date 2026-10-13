// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The assignment matcher added in #395 is single-value, single-line and keyword-adjacent. Each
// of those three properties is a separate false NEGATIVE, and this file closes four shapes that
// follow from them. See #746 for the measurements.
//
//	(d) tokens: <secret>              a suffixed key name -- the stem must sit immediately
//	                                  before the delimiter, so a plural misses entirely
//	(b) "api_keys": ["<secret>"]      a bracket between delimiter and value escapes BOTH the
//	                                  quoted and the unquoted patterns, even though the value
//	                                  is quoted
//	(a) secret: <secret>,<secret2>    only the first element of a list is reachable; nothing
//	                                  re-anchors after the separator
//	(c) api_keys:\n  - <secret>       a value on a different line from its key has no anchor
//
// EVERYTHING HERE IS ADDITIVE, and that is a hard constraint rather than a style choice.
// generateFindingHash folds Match.Text into a finding's identity (internal/suppressions). Widening
// an existing pattern's capture would change Text on findings that already report, which changes
// their hash, which silently stops every suppression rule written against them from matching --
// and the hashVersion compatibility machinery cannot rescue that, because all four formulas
// compute from the CURRENT Text, so every candidate hash moves together. generateFindingHash's own
// comment states the consequence: "a rule that stops matching turns a finding an operator had
// reviewed and accepted back into noise, and in a pre-commit gate back into a block."
//
// So the existing patterns are left byte-for-byte alone and these run alongside them: against a
// scan without this file, the only effect is that findings previously absent appear, and no finding
// the existing patterns report changes.
//
// That protects the patterns that predate this file, NOT this file's own findings, and #754 changed
// some of those. The list-tail walk (findListTailSecrets) and the collection scan
// (findCollectionSecrets) shipped in v2.5.3 reporting bytes no head would take as part of a value --
// a string's closing quote (`<v2>"`), a trailing comment (`<v2> # rotate`), a quoted member's own
// quotes (`"<v2>"`), the rest of the line after a bracket that never closes -- and elements that were
// not members at all (minified fragments, a following `token=<v2>` pair). Since #754 those findings
// have a different Text, and so a different hash, or do not exist. No hashVersion candidate can
// rescue them, for the reason above: a suppression rule written against one with v2.5.3 stops
// matching and must be regenerated. The singular and plural patterns and findSequenceItemSecret are
// unchanged.

// pluralStemSuffix is the key-name suffix these patterns additionally accept.
//
// Deliberately just "s". The stem list is matched with no suffix at all today, so `tokens:`,
// `api_keys:`, `secrets:` and `passwords:` -- the plural a collection of credentials naturally
// takes -- are invisible. Accepting an arbitrary identifier tail (`[a-z0-9_]*`) would also admit
// `token_type: Bearer` and `password_hint: mothers-maiden-name`, which are not credentials, so
// the narrow form is the one that pays for itself. Broader suffixes are deliberately out of scope
// here; add them with their own measurements if a real miss turns up.
const pluralStemSuffix = "s"

// compilePluralUnquotedPatterns mirrors compileUnquotedPatterns for a plural key name.
//
// Separate from the singular set, requiring the "s" rather than making it optional, so the two
// cannot match the same bytes: an existing singular finding keeps its exact span and the plural
// form can only ADD. The value class is copied verbatim from compileUnquotedPatterns -- these
// capture the same thing, from a key that happens to be plural.
func compilePluralUnquotedPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, len(secretAssignmentKeywords))
	for _, keyword := range secretAssignmentKeywords {
		patterns = append(patterns, regexp.MustCompile(
			`(?i)`+keyword+pluralStemSuffix+`\s*[=:]\s*([^\s"\';,#<${(\[][^\s"\';,#]{7,})`,
		))
	}
	return patterns
}

// compilePluralQuotedPatterns mirrors the two assignment patterns in compileKeywordPatterns for a
// plural key name: `tokens = "..."` and the JSON/YAML `"api_keys": "..."`.
//
// No plausibleUnquotedSecret filter, matching how the singular quoted patterns behave: quotes are
// the author's statement that the bytes are a literal value, which is the whole reason the quoted
// and unquoted paths are separate sets.
func compilePluralQuotedPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, 2*len(secretAssignmentKeywords))
	for _, keyword := range secretAssignmentKeywords {
		patterns = append(patterns,
			regexp.MustCompile(`(?i)`+keyword+pluralStemSuffix+`\s*[=:]\s*["']([^"']{8,})["']`),
			regexp.MustCompile(`(?i)["']`+keyword+pluralStemSuffix+`["']\s*:\s*["']([^"']{8,})["']`),
		)
	}
	return patterns
}

// compileListOpenerPatterns finds a secret-stem key -- singular or plural, bare or quoted --
// whose value opens a bracketed collection. The capture group is the opening bracket itself, so
// the caller knows where the collection starts.
//
// `[`, `(` and `{` are all excluded from the unquoted value class's FIRST character, and the
// quoted patterns require a quote IMMEDIATELY after the delimiter, so a collection escapes both.
// That is how `"api_keys": ["<secret>"]` -- an ordinary JSON config shape carrying a QUOTED
// credential -- reaches the scanner completely undetected.
func compileListOpenerPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, len(secretAssignmentKeywords))
	for _, keyword := range secretAssignmentKeywords {
		patterns = append(patterns, regexp.MustCompile(
			`(?i)["']?`+keyword+pluralStemSuffix+`?["']?\s*[=:]\s*([\[{(])`,
		))
	}
	return patterns
}

var (
	// quotedListElement matches one quoted element inside a collection.
	quotedListElement = regexp.MustCompile(`["']([^"']{8,})["']`)

	// sequenceItem matches a YAML block-sequence item, capturing the indent and the value.
	sequenceItem = regexp.MustCompile(`^(\s*)-\s+(.*)$`)

	// bareSecretStemKey matches a line that is a secret-stem key with NO value on it -- the line
	// that opens a YAML block sequence. Built from the same stem list at init.
	bareSecretStemKey *regexp.Regexp

	// shoutySentinel is a value made only of upper-case letters, digits, underscores and hyphens.
	//
	// REDACTED, PLACEHOLDER, CHANGEME, TODO1234, EXAMPLE1 and YOUR_API_KEY_HERE all clear
	// plausibleUnquotedSecret -- they are long enough and carry an upper-case letter, which is all
	// that filter asks -- and isObviousPlaceholder catches only the last of them. Today they are
	// saved from reporting by accident: the unquoted value class excludes `[` as a FIRST character,
	// so `api_key: [REDACTED]` never matches at all, which is exactly what
	// TestImplausibleUnquotedValuesAreRejected pins.
	//
	// Reaching into collections removes that accident, so the veto has to be made explicit or
	// shape (b) would trade a false negative for a false positive. Scoped to the collection and
	// sequence paths ONLY: applying it to the existing unquoted path would stop `password:
	// CHANGEME` reporting, and reducing detection on a path that already reports is not an
	// additive change.
	//
	// There is precedent for the shape. findAWSSecretKeys already skips an all-upper or all-lower
	// candidate, on the reasoning that those "are usually hashes, hex blobs, or shouty
	// placeholders, not AWS secrets (which are base64 of random bytes -- mixed case with
	// overwhelming odds)". A real credential inside a collection is mixed case for the same reason.
	shoutySentinel = regexp.MustCompile(`^[A-Z0-9_-]+$`)
)

func init() {
	stems := make([]string, 0, len(secretAssignmentKeywords))
	for _, keyword := range secretAssignmentKeywords {
		stems = append(stems, keyword+pluralStemSuffix+"?")
	}
	// A key alone on its line: optional indent, the stem, an optional quote, the colon, then
	// nothing but optional trailing space or a comment. A trailing value would mean the ordinary
	// same-line patterns already own this line.
	bareSecretStemKey = regexp.MustCompile(`(?i)^\s*["']?(?:` + strings.Join(stems, "|") + `)["']?\s*:\s*(?:#.*)?$`)
}

// collectionSecretCandidate is a value found inside a collection or sequence, with its span in
// the line so the caller can dedupe it against same-span claims from other patterns.
type collectionSecretCandidate struct {
	text  string
	start int
	end   int
}

// findCollectionSecrets returns every credential-shaped value inside a bracketed collection whose
// key carries a secret stem. Closes shapes (b) and (a).
//
// Both element forms are handled, with different filters and for the same reason the quoted and
// unquoted assignment patterns are separate sets:
//
//   - A QUOTED element is taken as-is. The author wrote quotes around it, which is intent.
//   - An UNQUOTED element must clear plausibleUnquotedSecret AND not be a shouty sentinel, so
//     reaching past the bracket cannot turn `[REDACTED]` into a HIGH-confidence credential.
//
// A collection ends at the first closing bracket, so a value after it is not attributed to the key
// -- or where the NEXT collection's key begins, if that comes first (#754). A bracket that never
// closes otherwise made every collection after it on the line part of its region:
//
//   - The work was O(K x line length) for K openers. One line of K space-joined `token=[<value>`
//     openers cost 1.51s, 6.02s and 25.04s through the CLI at K = 2,000, 4,000 and 8,000 in v2.5.3,
//     and costs 0.23s, 0.41s and 0.81s now (median of three interleaved samples).
//   - The elements were the rest of the line. Joined by spaces, each opener's one element ran to the
//     end of the line, `<v1> token=[<v2> token=[<v3> ...`, and those texts lost 25 points to their
//     length and their spaces, so v2.5.3 reported them only when a file-wide classifier lifted the
//     file: no `dev` substring among the random values, or a "Financial" domain. At K = 4,000 that
//     was 4 findings, the last four openers' rest of the line, on 7 of 12 draws of 16-character
//     values, and all 4,000 rest-of-line texts, up to 95,992 bytes each, on the other 5. Each value
//     is now reported on its own: 3,997 to 4,000 of them across those draws, the value filters and
//     scoring every finding goes through rejecting the rest. Joined by `, `, every later
//     `token=[<v>` was an element of every earlier opener, key and bracket included, and 1,999 of
//     v2.5.3's 3,999 findings at K = 2,000 were `token=[<v>`; now there are 2,000, each a value.
//
// Each bracket is scanned once however many keywords open it (`access_token: [` is opened by the
// access_token and the token patterns alike), so the regions are disjoint and the total work is
// O(line length).
func (v *Validator) findCollectionSecrets(line string) []collectionSecretCandidate {
	var openers []collectionOpener
	for _, pattern := range v.listOpenerPatterns {
		for _, m := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			openers = append(openers, collectionOpener{keyStart: m[0], bracket: m[2]})
		}
	}
	if len(openers) == 0 {
		return nil
	}
	// Bracket order. A keyword holds no bracket, so no opener's key can begin before an earlier
	// opener's bracket, and keyBegins finds the whole key whichever of a bracket's openers it is given.
	sort.Slice(openers, func(i, j int) bool { return openers[i].bracket < openers[j].bracket })

	var out []collectionSecretCandidate
	// closer is the first closing bracket at or after the current region's start, or len(line). The
	// regions only move forward, so each search starts past the last one and the searches together
	// read the line once.
	closer := -1
	for i, op := range openers {
		if i > 0 && op.bracket == openers[i-1].bracket {
			continue // the same collection, opened by an overlapping keyword
		}
		from := op.bracket + 1
		if closer < from {
			closer = len(line)
			if c := strings.IndexAny(line[from:], "]})"); c >= 0 {
				closer = from + c
			}
		}
		end := closer
		for _, next := range openers[i+1:] {
			if next.bracket != op.bracket {
				end = min(end, keyBegins(line, next.keyStart, from))
				break
			}
		}
		out = appendCollectionElements(out, line[from:end], from)
	}
	return out
}

// keyBegins returns where the key whose keyword match starts at line[at] begins, and never anything
// before floor. The keyword can be the tail of a longer key -- `secret` in `client_secret`,
// `session` in `"streaming-session"` -- so it walks back over key bytes and then the key's opening
// quote. Stopping at the keyword instead left `<v1> client_` as the previous collection's element,
// and the JSON key `"streaming-session"` as a quoted element of the object around it.
func keyBegins(line string, at, floor int) int {
	at = max(at, floor)
	for at > floor && isAssignmentKeyByte(line[at-1]) {
		at--
	}
	if at > floor && (line[at-1] == '"' || line[at-1] == '\'') {
		at--
	}
	return at
}

// collectionOpener is one bracket a secret-stem key opens, and where that key begins.
type collectionOpener struct {
	keyStart int // the match start: the key, or the quote before it
	bracket  int // the opening bracket
}

// appendCollectionElements appends the credential-shaped elements of one collection's region, which
// begins at line offset base.
func appendCollectionElements(out []collectionSecretCandidate, region string, base int) []collectionSecretCandidate {
	// Quoted elements first. Their spans are recorded, so the unquoted pass below can skip the bytes
	// they already cover instead of re-reporting a quoted value as a bare token.
	var covered [][2]int
	for _, q := range quotedListElement.FindAllStringSubmatchIndex(region, -1) {
		if len(q) < 4 || q[2] < 0 {
			continue
		}
		out = append(out, collectionSecretCandidate{
			text: region[q[2]:q[3]], start: base + q[2], end: base + q[3],
		})
		covered = append(covered, [2]int{q[0], q[1]})
	}

	// Unquoted elements, separated by a list separator. Only `,` and `;` count: a value after
	// whitespace is as likely to be prose or a trailing comment as a second credential, and guessing
	// wrong there is how the unquoted path earned plausibleUnquotedSecret in the first place.
	//
	// The quoted spans and the elements are both in line order and neither overlaps itself, so one
	// forward cursor answers "does this element overlap a quoted span" for all of them. Testing each
	// element against every quoted span was O(n^2) in a collection of n quoted elements.
	next := 0
	for _, span := range splitListElements(region) {
		for next < len(covered) && covered[next][1] <= span[0] {
			next++
		}
		if next < len(covered) && covered[next][0] < span[1] {
			continue
		}
		text := strings.TrimSpace(region[span[0]:span[1]])
		if len(text) < 8 || !plausibleUnquotedSecret(text) || shoutySentinel.MatchString(text) {
			continue
		}
		// Re-find the trimmed text's offset so the span covers the value, not the padding.
		off := strings.Index(region[span[0]:span[1]], text)
		if off < 0 {
			continue
		}
		out = append(out, collectionSecretCandidate{
			text: text, start: base + span[0] + off, end: base + span[0] + off + len(text),
		})
	}
	return out
}

// findListTailSecrets returns credential-shaped values that sit AFTER the first element of a
// non-bracketed list, e.g. `secret: <first>,<second>`. Closes shape (a) for the unbracketed form.
//
// The capture class excludes `,` and `;`, so an existing pattern stops at the separator, and the
// pattern is anchored on the key, so nothing re-anchors past it. The first element already
// reports; this adds the rest.
//
// Whitespace is NOT treated as a separator here either, for the reason given in
// findCollectionSecrets: `password: <secret> see runbook` would otherwise report "runbook".
//
// WHAT IS A LIST MEMBER (#754). The first version split the whole rest of the line at every `,`
// and `;` and reported each piece that cleared plausibleUnquotedSecret. On a minified line that is
// every statement and property fragment after the first plausible head: measured on 29,130 public
// JS/TS files it produced 136,290 findings from 213 lines, up to 20,066 on one line, and none was a
// credential. A tail element now belongs to the list only while it fits the HEAD'S OWN value
// grammar -- the class compileUnquotedPatterns captures, first byte [^\s"';,#<${(\[] and the rest
// [^\s"';,#] -- and the walk stops at the first element that does not:
//
//   - Whitespace on either side of a separator is skipped: every rune unicode.IsSpace admits, the
//     set v2.5.3's strings.TrimSpace removed from each element. So `password: <v1>, <v2>` and
//     `<v1> ,<v2>` keep their members, and a no-break space, \v or \f next to the separator neither
//     joins the reported text nor hides the element's first byte from the rules below. Measured,
//     refusing whitespace after the separator would have lost the hand-written spaced list to remove
//     52 more JS/TS and 3 more Python fragments that v2.5.3 already reported.
//   - An empty element (`,,`, `, ,`, `;;`) is a hole the walk passes over, as v2.5.3's splitter
//     dropped it, not the end of the list.
//   - An element is the longest run of value-class bytes, so it is truncated at the first byte
//     outside the class. That byte ends the TAIL unless whitespace and then a separator follow it.
//     This is what removes the stray closing quote: in `S = "secret: <v1>,<v2>"` the second element
//     used to report as `<v2>"`, and the head's own capture would never have taken that quote. It is
//     also why an annotated member ends the list: in `<v1>, <v2> (old), <v3>` the space after <v2> is
//     followed by `(`, so <v3> is not reached. That same rule is what cuts minified fragments.
//   - A CLOSED quoted element -- a quote, what an unquoted member could be, the same quote, then
//     whitespace, a separator, the end of the line or a byte that closes what the list sits in
//     (`ARGS=(--token=<v1>,"<v2>")`, `x = 'token=<v1>,"<v2>"'`) -- is a member, reported without its
//     quotes the way the quoted patterns report `API_KEY="<v>"`. v2.5.3 reported
//     `API_KEY=<v1>,"<v2>"` as `"<v2>"`. A quote that does not close that way (`"x":`,
//     `"two words"`, `"<v2>"+x`) ends the list.
//   - A `${NAME}` element is a reference, not a literal: it is passed over unreported and the walk
//     goes on. A bare `$NAME` still ends the list, because `$` begins ordinary identifiers in minified
//     JavaScript (`$e`, `$scope`) and passing over those would walk on through code.
//   - Any other element whose first byte the head could not start with -- `$`, `<`, `{`, `(`, `[`,
//     `#` -- ends the list. `password=$VAR` does not report as a head, so `<secret>,$VAR` does not
//     report `$VAR` as a member either.
//   - An element that opens a new `key=value`, `key: value`, `key:value` or `--flag=value` pair ends
//     the list (see startsListAssignment). That is the NEXT assignment, not a member of this one: in
//     `token=<v1>;token=<v2>` the second head reports through the ordinary pattern, and its
//     `token=<v2>` element used to report a second time, key and all. Padded base64 is not a pair,
//     and neither is a URL (`postgres://app:<v2>@db`), whose scheme only looks like a key.
//
// The grammar is a property of the bytes, not of the value, so the filters for what REPORTS are
// unchanged: an element that fits but is short, prose-shaped or a shouty sentinel is still a member
// -- the walk passes over it to the next one -- and is simply not reported.
//
// LINEAR, which the first version was not. Every head re-split the whole rest of the line, so K
// heads on one line cost O(K^2): 0.81s, 2.53s and 9.96s at K = 2,000, 4,000 and 8,000
// `;`-separated `token=<value>` assignments through the CLI, against 0.23s, 0.39s and 0.82s now
// (median of three interleaved samples). Two things make it O(line length):
//
//   - The walk is LAZY. It reads one element at a time and stops at the first that is not a member,
//     instead of splitting everything after the head before looking at any of it.
//   - No separator is walked twice. A tail depends only on the separator it starts at -- every head
//     shares one element grammar -- so a walk that reaches a separator an earlier walk has already
//     passed stops there: everything after it was emitted by that walk. That holds whichever order
//     the patterns find their heads in, which is pattern order and not line order.
func (v *Validator) findListTailSecrets(line string) []collectionSecretCandidate {
	var out []collectionSecretCandidate
	// walked holds every separator a tail walk has passed on this line. Allocated on the first walk:
	// most lines have no head followed by a separator and should not pay for a map.
	var walked map[int]struct{}

	for _, pattern := range v.unquotedPatterns {
		for _, m := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(m) < 4 || m[2] < 0 || m[3]-m[2] < 8 {
				continue
			}
			// The first element must itself look like a credential. Without this a prose line
			// that merely contains a keyword would open the tail scan.
			if !plausibleUnquotedSecret(line[m[2]:m[3]]) {
				continue
			}
			// A separator must come immediately after the captured value, with nothing between.
			if m[3] >= len(line) || !isListSeparator(line[m[3]]) {
				continue
			}
			if walked == nil {
				walked = make(map[int]struct{})
			}
			out = appendListTail(out, line, m[3], walked)
		}
	}

	return out
}

// appendListTail walks the list that continues at the separator line[sep], appending each member
// that clears the reporting filters, and returns at the first byte that is not part of the list.
// See findListTailSecrets for the grammar and for why walked makes the total work linear. Every
// iteration marks a separator strictly after the one before it, so the walk only moves forward.
func appendListTail(out []collectionSecretCandidate, line string, sep int, walked map[int]struct{}) []collectionSecretCandidate {
	for sep < len(line) && isListSeparator(line[sep]) {
		if _, done := walked[sep]; done {
			return out
		}
		walked[sep] = struct{}{}

		start := skipSpaceRunes(line, sep+1)
		if start >= len(line) {
			return out
		}
		var end int
		switch b := line[start]; {
		case isListSeparator(b):
			// An empty element (`,,`, `, ,`, `;;`): a hole in the list, not its end.
			sep = start
			continue
		case b == '"' || b == '\'':
			closing := closedQuotedMember(line, start)
			if closing < 0 {
				return out
			}
			out = appendTailMember(out, line, start+1, closing)
			end = closing + 1
		case b == '$':
			if end = braceReferenceEnd(line, start); end < 0 {
				return out
			}
		case !isUnquotedValueFirstByte(b) || startsListAssignment(line, start):
			return out
		default:
			end = start + 1
			for end < len(line) && isUnquotedValueByte(line[end]) {
				end++
			}
			// The class admits \v and every non-ASCII space, so a trailing one is trimmed from what
			// is reported, as v2.5.3 trimmed it; the walk itself goes on from the end of the run.
			out = appendTailMember(out, line, start, trimTrailingSpaceRunes(line, start, end))
		}
		// The byte that ended this element continues the list only if it is a separator, after
		// optional whitespace: `<v1> ,<v2>` is as much a list as `<v1>, <v2>`.
		sep = skipSpaceRunes(line, end)
	}
	return out
}

// appendTailMember appends line[start:end] if it clears the tail's reporting filters.
func appendTailMember(out []collectionSecretCandidate, line string, start, end int) []collectionSecretCandidate {
	if text := line[start:end]; len(text) >= 8 && plausibleUnquotedSecret(text) && !shoutySentinel.MatchString(text) {
		out = append(out, collectionSecretCandidate{text: text, start: start, end: end})
	}
	return out
}

// closedQuotedMember returns the index of the closing quote of the quoted list element that opens at
// line[start], or -1 if the element is not a closed quoted member.
//
// Between the quotes must be exactly what an unquoted member could be -- a first byte the head could
// start with, then value-class bytes, and not a new pair -- and after the closing quote must come what
// ends a quoted string (endsAfterClosingQuote): the end of the line, whitespace, a separator, or a
// byte that closes what the list sits in, such as the `)` of `ARGS=(--token=<v1>,"<v2>")` or the
// outer string's quote in `x = 'token=<v1>,"<v2>"'`. So `"<v>"` is a member and `"Content-Type":`
// (a key), `"two words"`, `"<v>"+x` and `"<v>""` are not, and neither is `"it's"`: the value class
// excludes both quote characters, so the content cannot hold the other one.
//
// That content rule is narrower than the quoted patterns, which take any bytes but the quotes: a
// quoted member holding a space, `#` or `;`, or starting with `(`, `[`, `{`, `<` or `$`, is not a
// member, and it ends the list (TestListTailStatedCosts).
func closedQuotedMember(line string, start int) int {
	q, inner := line[start], start+1
	if inner >= len(line) || !isUnquotedValueFirstByte(line[inner]) || startsListAssignment(line, inner) {
		return -1
	}
	i := inner + 1
	for i < len(line) && isUnquotedValueByte(line[i]) {
		i++
	}
	if i >= len(line) || line[i] != q || !endsAfterClosingQuote(line, i+1, q) {
		return -1
	}
	return i
}

// endsAfterClosingQuote reports whether line[after:], straight after a closing quote q, ends the
// quoted string rather than continuing an expression: the end of the line, whitespace (every rune
// unicode.IsSpace admits), a separator, or a byte that closes what the string sits in
// (closesEnclosing).
func endsAfterClosingQuote(line string, after int, q byte) bool {
	return after >= len(line) || isListSeparator(line[after]) || skipSpaceRunes(line, after) != after ||
		closesEnclosing(line, after, q)
}

// closesEnclosing reports whether line[after], straight after a closing quote q, closes what the
// quoted string sits in: a bracket (`)`, `]`, `}`), a tag (`>`, `/>`, `<`), a pipe or query (`|`,
// `&`), an escape (`\`, as in a JSON-escaped `\n`), or an outer string written with the other quote.
// A lone `/`, `+`, `:` or the same quote again continues an expression or a key, and does not.
func closesEnclosing(line string, after int, q byte) bool {
	switch c := line[after]; c {
	case ')', ']', '}', '>', '<', '|', '&', '\\':
		return true
	case '/':
		return after+1 < len(line) && line[after+1] == '>'
	case '"', '\'':
		return c != q
	}
	return false
}

// braceReferenceEnd returns the index just past a `${NAME}` list element at line[start], or -1 if
// the element is not one. NAME is an identifier, so `${NAME:-x}` and `${{ x }}` are not passed over
// and end the list as any other `$` element does. Nor is `${NAME}suffix`: the walk goes on only if
// whitespace and a separator follow the closing brace, as after any other element.
func braceReferenceEnd(line string, start int) int {
	i := start + 2
	if i >= len(line) || line[start] != '$' || line[start+1] != '{' || !isIdentStartByte(line[i]) {
		return -1
	}
	for i < len(line) && (isIdentStartByte(line[i]) || (line[i] >= '0' && line[i] <= '9')) {
		i++
	}
	if i >= len(line) || line[i] != '}' {
		return -1
	}
	return i + 1
}

// isIdentStartByte reports whether b may begin an identifier: [A-Za-z_].
func isIdentStartByte(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// skipSpaceRunes returns the index of the first rune at or after i that unicode.IsSpace rejects:
// the whitespace v2.5.3's strings.TrimSpace removed from each list element. An invalid byte decodes
// as utf8.RuneError, which is not a space, so the skip never splits a rune.
func skipSpaceRunes(line string, i int) int {
	for i < len(line) {
		r, size := utf8.DecodeRuneInString(line[i:])
		if !unicode.IsSpace(r) {
			break
		}
		i += size
	}
	return i
}

// trimTrailingSpaceRunes returns end moved back over every trailing rune of line[start:end] that
// unicode.IsSpace admits.
func trimTrailingSpaceRunes(line string, start, end int) int {
	for end > start {
		r, size := utf8.DecodeLastRuneInString(line[start:end])
		if !unicode.IsSpace(r) {
			break
		}
		end -= size
	}
	return end
}

// isListSeparator reports whether b separates list elements. Only `,` and `;`; see
// findCollectionSecrets for why whitespace is not one.
func isListSeparator(b byte) bool {
	return b == ',' || b == ';'
}

// isUnquotedValueByte reports whether b may appear in an unquoted value: the class
// [^\s"';,#] that compileUnquotedPatterns captures after the first character.
//
// A byte test is exact for that class. Every byte it excludes is ASCII, and a byte at or above
// 0x80 is part of a multi-byte rune (or an invalid one, which the regexp reads as U+FFFD) that the
// negated class admits. \s in Go's regexp is [\t\n\f\r ], which is the whitespace listed here --
// deliberately not unicode.IsSpace, which would also exclude \v and so disagree with the head. The
// wider set is trimmed from the reported text instead; see appendListTail.
func isUnquotedValueByte(b byte) bool {
	switch b {
	case '\t', '\n', '\f', '\r', ' ', '"', '\'', ';', ',', '#':
		return false
	}
	return true
}

// isUnquotedValueFirstByte reports whether b may START an unquoted value: the class
// [^\s"';,#<${(\[] that compileUnquotedPatterns requires of its first character. The extra
// exclusions are a shell or template reference (`$`, `<`, `{`) and a collection or call (`(`, `[`),
// none of which the head pattern will take as a literal.
func isUnquotedValueFirstByte(b byte) bool {
	switch b {
	case '<', '$', '{', '(', '[':
		return false
	}
	return isUnquotedValueByte(b)
}

// startsListAssignment reports whether the list element at line[start] opens a new assignment --
// `key=value`, `key: value`, `key:value`, `--flag=value` -- rather than continuing the list. Such an
// element ends the list; see findListTailSecrets.
//
// A key is an identifier-shaped run ([A-Za-z_] then [A-Za-z0-9_$.-]) after any leading dashes, so a
// command-line flag is a key too: in `ARGS=--token=<v1>,--password=<v2>` the password head reports
// <v2> on its own, and as a member it was reported a second time with `--password=` glued on. Then
// optional spaces, `=` or `:`, and a VALUE: after optional spaces, some byte that is not a
// separator, not `#` and not the end of the line. The delimiter may repeat (`==`, `::`), so a
// comparison or a scope path also counts as code rather than a list member.
//
// Padded base64 is the one identifier-shaped value followed by `=`: a body with no `+` or `/`
// (about a fifth of `openssl rand -base64 32` keys, and most base64url ones) is a valid key run, and
// its padding a valid delimiter. Whether the element is a member must not depend on those random
// bytes, so isBase64Padding reads it by the shape of the padding and by whether the value ends after
// it -- not by whether the body happens to hold a `+` or `/`. Two readings remain without it: at the
// end of the line or before a separator, `#`, `\r` or `\f` there is no value, and before a quote that
// closes rather than opens a string (closesAfterString) there is none either.
//
// A URL is the one identifier-shaped value followed by `:`: its scheme (`postgres://`, `https://`) is
// a member, not a key, because the `//` after a single `:` is what no `key:value` pair has.
//
// The cost of this rule is stated rather than hidden: a `user:pass`-shaped element after a head
// (`password=<v1>,root:<v2>`) is read as the next pair and ends the list. Nothing in the bytes tells
// it from minified `expiresIn:n.expiresIn`, and measured on public JS/TS, letting `key:value` with
// no space through as a member returned 1,413 findings (1,309 HIGH) that this removes.
func startsListAssignment(line string, start int) bool {
	elem := start
	for start < len(line) && line[start] == '-' {
		start++
	}
	if start >= len(line) || !isIdentStartByte(line[start]) {
		return false
	}
	i := start + 1
	for i < len(line) && isAssignmentKeyByte(line[i]) {
		i++
	}
	keyEnd := i
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) || (line[i] != '=' && line[i] != ':') {
		return false
	}
	delim, run := line[i], i
	for i < len(line) && line[i] == delim {
		i++
	}
	if delim == '=' && isBase64Padding(line, elem, keyEnd, run, i) {
		return false
	}
	// A URL's scheme -- `postgres://`, `redis://`, `https://` -- is one `:` written straight after the
	// key and followed by `//`. That is a value the head itself captures (`PASSWORD=postgres://app:<v>@db`
	// reports the whole URL), and the `//` is what tells it from minified `expiresIn:n.expiresIn`, so
	// it is a member, not the next pair.
	if delim == ':' && i-run == 1 && strings.HasPrefix(line[i:], "//") {
		return false
	}
	// A quote straight after `=` is either the OPENING quote of a quoted value (`mode="cors"`) or
	// the CLOSING quote of a string the whole list sits in, after a padded value
	// (`S = "secret: <v1>,QUJD=="`). The byte after the quote tells them apart: quoted content
	// follows an opening quote, and the end of the string -- the end of the line, a separator,
	// whitespace or a closing bracket -- follows a closing one.
	if delim == '=' && i < len(line) && (line[i] == '"' || line[i] == '\'') {
		if j := i + 1; j >= len(line) || closesAfterString(line[j]) {
			return false
		}
		return true
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) {
		return false
	}
	switch line[i] {
	case ',', ';', '#', '\r', '\n', '\f':
		// Nothing follows the delimiter on this line -- including the `\r` a CRLF file leaves at
		// the end of every line -- so it was padding, or an empty assignment, not a key.
		return false
	}
	return true
}

// isBase64Padding reports whether the `=` run line[run:end] is the padding of a base64 value
// line[elem:end], for startsListAssignment. The first three conditions are properties of padding
// itself, and the last asks only that the value end after it:
//
//   - one or two `=`, written straight after the body (run == keyEnd: no space before them);
//   - body and padding together a multiple of four bytes long;
//   - a body of base64 or base64url bytes holding both an upper- and a lower-case letter, as an
//     encoding of random bytes does with overwhelming odds and `credentials` or `state` does not;
//   - and the padding ends the VALUE. A run of sentence or markup punctuation straight after it
//     (isTrailingPunctuation: `<P>.`, `**<P>**`, `_<P>_`, `<P>?`, `<P>: rotate`, `<P>--`) is
//     passed over; then the line ends, or the next byte is one no `key=value` value starts with.
//     That is whitespace (every rune unicode.IsSpace admits, so \v and a no-break space too), a
//     separator, `#`, `)`, `]`, `}`, `<`, `|`, `&` or `\`, or a quote or backtick that does not
//     open quoted content -- one not followed by [A-Za-z0-9_$] -- and does not close at once as an
//     empty string. So a padded member is kept before prose, a tab column, `//`, a closing tag or
//     bracket, the next query parameter, a closing quote, or a sentence's full stop; and
//     `contentType="json"`, `baseUrl=""`, a template literal assigned with no space, `isValid=!0`,
//     `scaleBy=.5` and `offsetY=-1` are still pairs.
//
// What it reads as a pair, so the member ends the list unreported, is padding followed straight away
// by a byte that begins a value, or by punctuation and then one: `<P>>` (`>` is left out of the
// punctuation for `onClick=> run(`), `<P>/path`, `<P>@host`, `<P>+x`, `<P>.x`. In those positions the
// bytes are those of `onClick=>f`, `isValid=!0`, `scaleBy=.5` and `offsetY=-1`, which are pairs.
//
// What it cannot tell apart, and so reads as padding, is a mixed-case key whose length with its `=`
// is a multiple of four, written with no space before the `=` and then a space (`contentType= json`),
// a quote and punctuation (`contentType="/json"`), or punctuation and the end of the value
// (`allowOrigin=*`). Such an element is reported as a member, cut where the value class ends
// (`contentType=`, `allowOrigin=*`). TestListTailStatedCosts pins each; none of these shapes occurs
// after a head and a separator in the public corpora this was measured on.
func isBase64Padding(line string, elem, keyEnd, run, end int) bool {
	if run != keyEnd || end-run > 2 || (end-elem)%4 != 0 || !isMixedCaseBase64Body(line[elem:keyEnd]) {
		return false
	}
	for end < len(line) && isTrailingPunctuation(line[end]) {
		end++
	}
	if end >= len(line) {
		return true
	}
	switch b := line[end]; b {
	case '"', '\'', '`':
		if end+1 < len(line) && line[end+1] == b && endsAfterClosingQuote(line, end+2, b) {
			return false // `baseUrl=""`: an empty string closed at once, so an empty assignment
		}
		return end+1 >= len(line) || !opensQuotedContent(line[end+1])
	case ')', ']', '}', '<', '|', '&', '\\':
		return true
	default:
		if !isUnquotedValueByte(b) {
			return true
		}
		// \v and the non-ASCII spaces are in the value class, as the head's ASCII \s leaves them,
		// but to a reader they end the value as a space does.
		r, _ := utf8.DecodeRuneInString(line[end:])
		return unicode.IsSpace(r)
	}
}

// isTrailingPunctuation reports whether b is sentence or markup punctuation that isBase64Padding
// passes over before it asks whether the value has ended: `.`, `!`, `?`, `:`, `*`, `_`, `~`, `-`,
// `+`, `%`, `@`, `^` or `/`. Some of them also begin code values (`=!0`, `=.5`, `=-1`), and those
// stay pairs because the byte after the run is still asked. Left out are `>`, which would make
// `onClick=> run(` padding, and the opening brackets, which `()`, `[]` and `{}` would close at once.
func isTrailingPunctuation(b byte) bool {
	switch b {
	case '.', '!', '?', ':', '*', '_', '~', '-', '+', '%', '@', '^', '/':
		return true
	}
	return false
}

// opensQuotedContent reports whether b, straight after a quote, reads as the first byte of quoted
// content rather than what follows a closing quote: [A-Za-z0-9_$].
func opensQuotedContent(b byte) bool {
	return isIdentStartByte(b) || b == '$' || (b >= '0' && b <= '9')
}

// isMixedCaseBase64Body reports whether s is made only of base64 or base64url bytes -- less the `+`
// and `/` that isAssignmentKeyByte already refuses -- and holds both an upper- and a lower-case
// letter.
func isMixedCaseBase64Body(s string) bool {
	var upper, lower bool
	for i := 0; i < len(s); i++ {
		switch b := s[i]; {
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= 'a' && b <= 'z':
			lower = true
		case b == '-' || b == '_' || (b >= '0' && b <= '9'):
		default:
			return false
		}
	}
	return upper && lower
}

// closesAfterString reports whether b can follow a closing quote but not begin quoted content, for
// startsListAssignment's padding test.
func closesAfterString(b byte) bool {
	switch b {
	case ',', ';', ' ', '\t', '\r', ')', ']', '}':
		return true
	}
	return false
}

// isAssignmentKeyByte reports whether b may continue an assignment key in startsListAssignment.
func isAssignmentKeyByte(b byte) bool {
	return b == '_' || b == '$' || b == '.' || b == '-' ||
		(b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// findSequenceItemSecret returns the credential-shaped value on a YAML block-sequence item line.
// Closes shape (c). The caller establishes that the sequence belongs to a secret-stem key; this
// function only reads the item.
//
// Quoted and unquoted are filtered exactly as in findCollectionSecrets, and for the same reasons.
func (v *Validator) findSequenceItemSecret(line string) []collectionSecretCandidate {
	m := sequenceItem.FindStringSubmatchIndex(line)
	if m == nil || len(m) < 6 || m[4] < 0 {
		return nil
	}
	value := strings.TrimSpace(line[m[4]:m[5]])
	if value == "" {
		return nil
	}
	start := m[4] + strings.Index(line[m[4]:m[5]], value)

	// A quoted item: strip the quotes and take what is inside, as the quoted patterns would.
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		inner := value[1 : len(value)-1]
		if len(inner) < 8 {
			return nil
		}
		return []collectionSecretCandidate{{text: inner, start: start + 1, end: start + 1 + len(inner)}}
	}

	// An inline comment ends the value.
	if hash := strings.IndexByte(value, '#'); hash >= 0 {
		value = strings.TrimSpace(value[:hash])
	}
	if len(value) < 8 || !plausibleUnquotedSecret(value) || shoutySentinel.MatchString(value) {
		return nil
	}
	return []collectionSecretCandidate{{text: value, start: start, end: start + len(value)}}
}

// lineOpensSecretStemSequence reports whether a line is a bare secret-stem key, i.e. the line a
// YAML block sequence of credentials hangs off. Returns the key's indent so the caller can tell
// when the sequence has ended.
func lineOpensSecretStemSequence(line string) (indent int, ok bool) {
	if !bareSecretStemKey.MatchString(line) {
		return 0, false
	}
	return len(line) - len(strings.TrimLeft(line, " \t")), true
}

// sequenceItemIndent returns the indent of a block-sequence item line, and whether the line is
// one. Used with lineOpensSecretStemSequence to decide whether an item still belongs to the key.
func sequenceItemIndent(line string) (indent int, ok bool) {
	m := sequenceItem.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	return len(m[1]), true
}

// splitListElements returns the spans of every non-empty `,`/`;`-separated element in s. Used by
// findCollectionSecrets, on the region between a collection's opening bracket and the first closing
// one.
//
// No element is skipped. A collection's first element has not been reported by anything — the
// whole point of shape (b) is that the collection was unreachable — so skipping it would leave
// `api_keys: [<secret>]` missed.
//
// findListTailSecrets used this too until #754, splitting the whole rest of the line once per head.
// That was the O(K^2), and it is why the tail now walks element by element in appendListTail
// instead: an unbracketed list has no closing bracket to bound the split, so the walk has to stop
// at the first element that is not a member rather than at the end of the line.
func splitListElements(s string) [][2]int {
	var spans [][2]int
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' || s[i] == ';' {
			if i > start {
				spans = append(spans, [2]int{start, i})
			}
			start = i + 1
		}
	}
	return spans
}

// isPluralBoundary reports whether the byte at end is a plural "s" that itself sits at a word
// boundary, i.e. whether a keyword matched up to end is really the plural of that keyword.
//
// Used by lineHasKeyword's right-boundary test so `tokens:` counts as token context. Requiring the
// "s" to end at a boundary is what keeps `tokensize` and `secretsmanager` out: those are different
// words that merely begin with a keyword, and treating them as context would re-introduce the
// over-matching the boundary rule exists to prevent.
func isPluralBoundary(text string, end int) bool {
	if end >= len(text) {
		return false
	}
	if text[end] != 's' && text[end] != 'S' {
		return false
	}
	after := end + 1
	return after == len(text) || !isKeywordAlnum(text[after])
}
