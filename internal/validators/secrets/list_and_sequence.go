// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"strings"
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
// So the existing patterns are left byte-for-byte alone and these run alongside them. The only
// effect is findings that were previously absent now appear; no reported value changes.

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
// The scan stops at the first closing bracket, so a value after the collection ends is not
// attributed to the key.
func (v *Validator) findCollectionSecrets(line string) []collectionSecretCandidate {
	var out []collectionSecretCandidate

	for _, pattern := range v.listOpenerPatterns {
		for _, m := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			open := m[2]
			region := line[open+1:]
			if end := strings.IndexAny(region, "]})"); end >= 0 {
				region = region[:end]
			}
			base := open + 1

			// Quoted elements first. Their spans are recorded, so the unquoted pass below can
			// skip the bytes they already cover instead of re-reporting a quoted value as a
			// bare token.
			covered := make([][2]int, 0, 4)
			for _, q := range quotedListElement.FindAllStringSubmatchIndex(region, -1) {
				if len(q) < 4 || q[2] < 0 {
					continue
				}
				out = append(out, collectionSecretCandidate{
					text: region[q[2]:q[3]], start: base + q[2], end: base + q[3],
				})
				covered = append(covered, [2]int{q[0], q[1]})
			}

			// Unquoted elements, separated by a list separator. Only `,` and `;` count: a value
			// after whitespace is as likely to be prose or a trailing comment as a second
			// credential, and guessing wrong there is how the unquoted path earned
			// plausibleUnquotedSecret in the first place.
			for _, span := range splitListElements(region) {
				if overlapsAny(span, covered) {
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
		}
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
//   - An element is the longest run of value-class bytes after the separator, so it is truncated
//     at the first byte outside the class. That byte ends the TAIL unless it is itself a separator.
//     This is what removes the stray closing quote: in `S = "secret: <v1>,<v2>"` the second element
//     used to report as `<v2>"`, and the head's own capture would never have taken that quote.
//   - Spaces and tabs straight after the separator are skipped, exactly as the head pattern skips
//     `\s*` after its own delimiter, so `password: <v1>, <v2>` keeps its second member. Measured,
//     refusing them instead would have lost that hand-written list shape to remove 52 more JS/TS
//     and 3 more Python fragments that v2.5.3 already reported.
//   - An element whose first byte the head could not start with -- a quote, `$`, `<`, `{`, `(`,
//     `[` -- ends the list. `password=$VAR` does not report as a head, so `<secret>,$VAR` does
//     not report `$VAR` as a member either.
//   - An element that opens a new `key=value` or `key: value` pair ends the list (see
//     startsListAssignment). That is the NEXT assignment, not a member of this one: in
//     `token=<v1>;token=<v2>` the second head reports through the ordinary pattern, and its
//     `token=<v2>` element used to report a second time, key and all.
//
// The grammar is a property of the bytes, not of the value, so the filters for what REPORTS are
// unchanged: an element that fits but is short, prose-shaped or a shouty sentinel is still a member
// -- the walk passes over it to the next one -- and is simply not reported.
//
// LINEAR, which the first version was not. Every head re-split the whole rest of the line, so K
// heads on one line cost O(K^2): 0.80s, 2.62s and 11.13s at K = 2,000, 4,000 and 8,000
// `;`-separated `token=<value>` assignments through the CLI, against 0.24s, 0.61s and 0.86s now
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
// See findListTailSecrets for the grammar and for why walked makes the total work linear.
func appendListTail(out []collectionSecretCandidate, line string, sep int, walked map[int]struct{}) []collectionSecretCandidate {
	for sep < len(line) && isListSeparator(line[sep]) {
		if _, done := walked[sep]; done {
			return out
		}
		walked[sep] = struct{}{}

		// Spaces or tabs may follow the separator, as `\s*` may follow the head's own delimiter:
		// `password: <v1>, <v2>` is a list as written by hand.
		start := sep + 1
		for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
			start++
		}
		if start >= len(line) || !isUnquotedValueFirstByte(line[start]) || startsListAssignment(line, start) {
			return out
		}
		end := start + 1
		for end < len(line) && isUnquotedValueByte(line[end]) {
			end++
		}

		if text := line[start:end]; len(text) >= 8 && plausibleUnquotedSecret(text) && !shoutySentinel.MatchString(text) {
			out = append(out, collectionSecretCandidate{text: text, start: start, end: end})
		}
		// The byte that ended this element continues the list only if it is a separator.
		sep = end
	}
	return out
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
// deliberately not unicode.IsSpace, which would also exclude \v and so disagree with the head.
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
// `key=value`, `key: value`, `key:value` -- rather than continuing the list. Such an element ends
// the list; see findListTailSecrets.
//
// A key is an identifier-shaped run ([A-Za-z_] then [A-Za-z0-9_$.-]), optional spaces, then `=` or
// `:`, then a VALUE: after optional spaces, some byte that is not a separator, not `#` and not the
// end of the line. The delimiter may repeat (`==`, `::`), so a comparison or a scope path also
// counts as code rather than a list member.
//
// The value requirement is what keeps a padded base64 element in the list. `QUJDREVG==` is an
// identifier-shaped run followed by `=`, but nothing follows the padding, so it is a value and not a
// key -- and the same holds when what follows is the closing quote of the string the list is in.
//
// The cost of this rule is stated rather than hidden: a `user:pass`-shaped element after a head
// (`password=<v1>,root:<v2>`) is read as the next pair and ends the list. Nothing in the bytes tells
// it from minified `expiresIn:n.expiresIn`, and measured on public JS/TS, letting `key:value` with
// no space through as a member returned 1,413 findings (1,309 HIGH) that this removes.
func startsListAssignment(line string, start int) bool {
	b := line[start]
	if !(b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) {
		return false
	}
	i := start + 1
	for i < len(line) && isAssignmentKeyByte(line[i]) {
		i++
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) || (line[i] != '=' && line[i] != ':') {
		return false
	}
	delim := line[i]
	for i < len(line) && line[i] == delim {
		i++
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

// overlapsAny reports whether span intersects any span in covered.
func overlapsAny(span [2]int, covered [][2]int) bool {
	for _, c := range covered {
		if span[0] < c[1] && c[0] < span[1] {
			return true
		}
	}
	return false
}
