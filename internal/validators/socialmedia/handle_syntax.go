// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import "strings"

// A bare "@token" is a Twitter handle in prose and a keyword in half a dozen file formats, and the
// bare-handle pattern cannot tell them apart on its own.
//
// Measured over 1,633 real CSS and JavaScript files on a macOS host, with --limit 0 because the default
// 200-finding display cap silently truncates a measurement like this:
//
//	                          before    after
//	@media                      2772       46      CSS at-rule
//	@keyframes                   587        0      CSS at-rule
//	@supports                     51        3      CSS at-rule
//	@layer @container @page @viewport @import @property   small counts, same cause
//	----------------------------------------------
//	TWITTER findings total     13611    10225      -3386, or -24.9%
//
// #479 was filed against a different shape — 2- and 3-character handles like "@pR" read out of
// compressed bytes — and proposed a length floor. That shape is real but rare on text, and a `{4,15}`
// floor addresses none of the tokens above, which are all at least four characters. Neither the
// vocabulary nor the position discriminates on its own; it takes both.
//
// # A correction to this change's own earlier justification
//
// An earlier version of this comment claimed 1,470 findings dominated by JSON-LD — "@type 1018,
// @context 211". That number does not reproduce, and the label was wrong. Re-measuring showed those
// @type hits are JSDoc `@type` tags in .js files, not JSON-LD object keys: JSON-LD is nearly absent from
// this host, one file in total. So the volume was real but it belongs to the doc-annotation family that
// this change deliberately does NOT touch, and the JSON rule below was credited with work the CSS rule
// was doing. Corrected here rather than quietly dropped, because the mislabelled figure is what made a
// vocabulary extension look attractive.
//
// The large residual is that same family — @returns 4420, @default 595, @linkcode 536, @private 379,
// @internal 262 — and it is untouched on purpose. See the docPatterns note at the bottom.
//
// # Why a veto and not a penalty
//
// The same reason reserved_paths.go gives: validateNotFalsePositive is advisory and the caller turns it
// into a 30-point penalty, but these score 100 and the raw score runs higher still, so the cap absorbs
// the penalty entirely. A categorical decision is the only thing that changes the outcome.
//
// # Both rules require TWO independent signals, because the first version leaked
//
// A wrong veto suppresses a real finding, and a suppressed finding is a cleartext leak — only reported
// findings reach the redactor. The first version of this file used position alone, and a recall hunt
// against it found two confirmed leaks on canonical file shapes:
//
//	@media\n@page\n@layer\n@scope         a one-handle-per-line mentions export. 5 of 6 handles
//	                                      vanished, because opensAStatement is true at column 0 in
//	                                      EVERY file type. Only @schneems survived, purely because
//	                                      its name is not a CSS at-rule.
//	{"@schneems": 42, "@tleish": 17}      a handle-keyed moderator roster / mention-count export.
//	                                      ALL THREE keys vanished — including the two names this
//	                                      change's own commit message cited as proof that real
//	                                      handles survive.
//
// Both reached the sink. On the roster, origin/main masks all three handles; the position-only version
// produced NO redacted file at all, at exit 0, with nothing on stderr — the caller keeps the cleartext
// and is told the file is clean. That is the worst failure this validator has.
//
// The fault was in the test, not just the rule: every case in TestARealHandleIsNeverVetoed placed its
// handle mid-line, which is exactly the region where neither rule can fire, so the safety gate was
// disjoint from the failure region by construction and the whole suite passed green. The must-not-veto
// cases now sit AT the positions the rules act on — column 0, and as a quoted key.
//
// So each rule now needs a second signal that a handle cannot supply:
//
//   - The JSON rule requires a JSON-LD RESERVED keyword as well as the key position. The reserved set is
//     closed by the specification and cannot be used as a term, which is what makes it safe to name here
//     — unlike an open-ended list of tag words, it cannot grow by vocabulary creep. Its benefit is small
//     on this host and is not asserted from volume: JSON-LD appears in exactly one real file here, where
//     it removes 7 findings (@type ×6, @context ×1) while leaving the genuine handle in that same file
//     reported. It is kept because it is correct, cheap and two-signal, and because schema.org JSON-LD is
//     common in the web content this tool is pointed at even when a laptop has none.
//   - The CSS rule requires FOUR signals, and it reached four by leaking twice. See isCSSAtRule for the
//     measurements; in short, the at-rule NAME plus the statement POSITION vetoed a one-handle-per-line
//     mentions export, adding "a `{` later on the line" still vetoed a DELIMITED EXPORT carrying a
//     brace-bearing column (the standard shape of social-listening and webhook exports) and a chat line
//     naming `{general}`, so it now also requires that what FOLLOWS the name can begin a CSS prelude and
//     that the line actually OPENS a block. Both additions are free: real CSS coverage is 9,346 of 9,346
//     occurrences across 1,881 files, and the false-positive count on a 1,633-file corpus is identical
//     with and without them.
//
// The residual are multi-line preludes — `@media only screen` with the brace on the next line — which
// report as false positives. That is the safe direction: positives may widen, suppressors may not.
//
// # Why the doc-annotation family is NOT here, and why its list was not extended either
//
// The validator already filters that family by vocabulary, in the same function that handles
// email-embedded and malformed handles — see docPatterns. A first version of this file added a second,
// position-checked rule for it, which pre-empted the existing one and left its BSC4 log path
// unreachable; TestNoPayloadInDebugLog caught that, because it asserts every filter branch is
// exercised. Two mechanisms for one family is how they drift.
//
// The obvious alternative — extend docPatterns with the tags the measurement found missing — was tried,
// measured, and dropped. On a JSDoc-heavy corpus those 40 words remove a great deal, so the case for
// them looks strong on volume alone; the reason not to ship them is not volume but that docPatterns has
// NO position check, so each word suppresses that handle in every file type and every context. A recall
// hunt confirmed the cost is real and not hypothetical: `@yields` is a GitHub account credited in the
// `debug` package's CHANGELOG in the same credit-line shape as 20 other real handles in that same file,
// origin/main reports it, and the extension silently removed it. If that family is ever revisited, the
// fix is to give docPatterns the same position gate these rules use — not to grow the word list.

// jsonLDKeywords is the set of keywords reserved by JSON-LD, which is what a leading "@" means in a
// JSON object key.
//
// From the JSON-LD 1.1 specification's keyword list. This set is CLOSED by the spec — a reserved keyword
// cannot be used as a term — which is the property that makes naming words here safe when naming tag
// words in docPatterns is not. Anything outside it in key position is somebody's account name and must
// report; that is what makes a handle-keyed map work.
var jsonLDKeywords = map[string]struct{}{
	"base": {}, "container": {}, "context": {}, "direction": {}, "graph": {}, "id": {},
	"import": {}, "included": {}, "index": {}, "json": {}, "language": {}, "list": {},
	"nest": {}, "none": {}, "prefix": {}, "propagate": {}, "protected": {}, "reverse": {},
	"set": {}, "type": {}, "value": {}, "version": {}, "vocab": {},
}

// cssAtRules are the at-rule names defined by CSS, which open a statement rather than name a person.
//
// Names only; the position and a block brace are checked separately. Taken from the CSS specifications
// rather than from what happened to appear in the corpus, so a stylesheet using a rule this host has
// none of is still handled.
//
// Hyphenated names — font-face, counter-style, font-feature-values, font-palette-values,
// starting-style — are deliberately ABSENT. The configured bare-handle pattern is `@[a-zA-Z0-9_]{1,15}`,
// so it stops at the hyphen, and a pre-existing filter then drops the truncated match: `@font-face`
// yields no finding on origin/main or here, while `@font` on its own does. Listing them would be dead
// code that reads like a working guard.
var cssAtRules = map[string]struct{}{
	"charset": {}, "container": {}, "document": {}, "import": {}, "keyframes": {},
	"layer": {}, "media": {}, "namespace": {}, "page": {}, "property": {}, "scope": {},
	"supports": {}, "viewport": {},
}

// isSyntaxNotAHandle reports whether a bare "@token" at [start,end) on line is language syntax.
//
// The "@" prefix is what confines this to bare handles: a match carrying a host name is a URL, is
// already disambiguated by it, and does not begin with "@". A first version also excluded any match
// containing "/", which mutation testing showed to be dead code — no configured pattern produces a
// match that both starts with "@" and contains a slash — so it was removed rather than left as an
// untested guard that reads like a real one.
func isSyntaxNotAHandle(line, match, filename string, start, end int) bool {
	if !strings.HasPrefix(match, "@") {
		return false
	}
	token := strings.ToLower(match[1:])
	if token == "" {
		return false
	}

	if isJSONLDKey(line, token, start, end) {
		return true
	}
	// Both of these are decided by SYNTAX rather than by vocabulary, which is what makes them
	// categorical where the two rules below are probabilistic. See each function for why.
	if isMakeRecipePrefix(line, filename, start) {
		return true
	}
	if isImageDigest(line, end) {
		return true
	}
	if isCSSAtRule(line, token, start, end) {
		return true
	}
	return false
}

// isJSONLDKey reports whether the token is a JSON-LD reserved keyword in object-key position —
// `"@type":`.
//
// Two signals. The position rules out a handle written in prose; the reserved-keyword set rules out a
// handle used as a map key, which is the shape that leaked when this rule was position-only.
//
// Both quote styles, because JSON proper uses double quotes and the YAML and JavaScript that carry the
// same keywords use either.
func isJSONLDKey(line, token string, start, end int) bool {
	if _, ok := jsonLDKeywords[token]; !ok {
		return false
	}
	if start == 0 || end >= len(line) {
		return false
	}
	open, close := line[start-1], line[end]
	if !(open == '"' && close == '"') && !(open == '\'' && close == '\'') {
		return false
	}
	// A colon must follow, possibly after spaces. Without that check this would also veto a quoted
	// handle in prose — `he is "@jack" on twitter` — which is a real finding.
	for i := end + 1; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t':
			continue
		case ':':
			return true
		default:
			return false
		}
	}
	return false
}

// isCSSAtRule reports whether the token is a CSS at-rule opening a block on this line.
//
// FOUR signals, and each of the last three was added because the set before it leaked:
//
//  1. a known at-rule name
//  2. the position an at-rule occupies (opensAStatement)
//  3. what FOLLOWS the name is CSS prelude syntax (cssPreludeFollows)
//  4. the line actually opens a block (opensABlock)
//
// Signals 1 and 2 alone vetoed a one-handle-per-line mentions export, because column 0 is a statement
// opening in every file type. Adding "a `{` somewhere later on the line" fixed that but still vetoed a
// DELIMITED EXPORT carrying a brace-bearing column, which is the standard shape of social-listening and
// webhook exports:
//
//	author,date,payload            -> @media,2026-08-25,"{""rt"":3}"     lost @media and @page
//	date;author;payload            -> 2026-08-25;@media;{"rt":3}         lost them from column 2 as well
//	author<TAB>mentions<TAB>payload -> @media<TAB>42<TAB>{"rt":3}         lost @media and @layer
//	a chat join line               -> @page joined the channel {general}  lost @page
//
// In each case a real handle survived only when its name happened not to collide with an at-rule, and
// the cleartext survived redaction -- with no other finding, no redacted file was produced at all, at
// rc 0. Signals 3 and 4 close all four.
//
// # Both new signals are measured, not reasoned
//
// Over 9,346 at-rule occurrences in 1,881 real CSS files on this host that already pass signals 1-2 and
// carry a brace:
//
//	character immediately after the name    <space> 92.91%   ( 7.02%   { 0.07%   = 100.00%
//	                                        TAB: ZERO occurrences
//	line ends with `{`                      30.57%   (multi-line CSS)
//	line contains two or more `{`           69.43%   (minified CSS)
//	either of those two                     100.00%
//
// So both signals are free: real CSS coverage stays at 9,346 of 9,346. The delimited exports are
// excluded by signal 3 -- their next character is `,`, `;` or a TAB -- and the chat line by signal 4,
// since `{general}` neither ends the line nor is a second brace.
//
// TAB is deliberately NOT accepted as prelude whitespace even though CSS permits it, because it never
// appears there in 9,346 real occurrences while it IS the delimiter of a TSV. Positives may widen,
// suppressors may not.
func isCSSAtRule(line, token string, start, end int) bool {
	if _, ok := cssAtRules[token]; !ok {
		return false
	}
	return opensAStatement(line, start) &&
		cssPreludeFollows(line, end) &&
		opensABlock(line)
}

// cssPreludeFollows reports whether the byte after the at-rule name can begin a CSS prelude.
//
// A space introduces a query or selector (`@media screen`), `(` a minified feature test
// (`@media(min-width:600px)`), `{` a block-only at-rule with no prelude (`@font-face{`), and a QUOTE a
// minified string prelude (`@import"https://..."`, `@charset"utf-8"`). A field delimiter cannot: `,`,
// `;` and TAB mean the token is a value in a row, not a rule opening a block.
//
// The quote is safe despite being a CSV quoting character, and this is structural rather than lucky: for
// a delimited file to put a quote immediately AFTER the token, the token itself would have to be
// unquoted while the next field is quoted -- `@media"12"` -- which no delimited format emits. When a CSV
// does quote the field, the token is PRECEDED by a quote, and opensAStatement already rejects that.
func cssPreludeFollows(line string, end int) bool {
	if end >= len(line) {
		return false // nothing follows, so nothing opens a block either
	}
	switch line[end] {
	case ' ', '(', '{', '"', '\'':
		return true
	default:
		return false
	}
}

// opensABlock reports whether the line looks like one that opens a CSS block.
//
// Two accepted shapes, because CSS is written both ways and a rule covering only one of them would
// suppress in exactly the file type it was not measured on:
//
//   - the line ENDS with `{`, which is how CSS is written for humans
//   - the line holds TWO or more `{`, which is what minification produces when a whole stylesheet
//     lands on one line
//
// Checking "ends with `{`" alone was rejected for that reason: it covers 30.57% of real occurrences.
// A single brace mid-line, closed again on the same line, is the shape of prose or data -- a chat
// message naming `{general}`, or a CSV cell holding `{"rt":3}`.
func opensABlock(line string) bool {
	if strings.HasSuffix(strings.TrimRight(line, " \t\r"), "{") {
		return true
	}
	return strings.Count(line, "{") >= 2
}

// opensAStatement reports whether the token is the first thing on its statement.
//
// CSS at-rules sit at the start of a line or immediately after a `}`, `{` or `;`. This is necessary but
// nowhere near sufficient on its own — see isCSSAtRule.
func opensAStatement(line string, start int) bool {
	for i := start - 1; i >= 0; i-- {
		switch line[i] {
		case ' ', '\t':
			continue
		case '}', '{', ';':
			return true
		default:
			return false
		}
	}
	return true // nothing but whitespace before it
}

// isMakeRecipePrefix reports whether a bare "@token" is Make's recipe-prefix marker.
//
// This is a veto, and vetoes in this file have a bad history — see the leak record above. It is safe
// where the CSS rule was not, and the difference is worth stating precisely: the CSS leaks happened
// because at-rule NAMES collide with plausible account names. "@media" is a credible handle, so a
// name-based rule could only ever be probabilistic.
//
// A Make recipe prefix is not a name, it is a POSITION defined by Make's grammar. A recipe line must
// begin with a TAB, and the first token after it (past any of the `-`, `+`, `@` prefix characters) is
// the command Make executes. A handle cannot occupy that position in a working Makefile, because Make
// would try to run a program by that name.
//
// Measured on this repository's Makefile: 357 of 357 "@token" occurrences sit at that position, zero
// exceptions, and they account for 346 of the 387 TWITTER findings the file produces.
//
// Two signals, per the standard the rest of this file sets:
//
//  1. the token is at the recipe-prefix position — leading TAB, then only `-`, `+` or `@` before it,
//  2. the file is a makefile by name.
//
// A handle LATER on a recipe line is untouched, which is the case that matters:
// "\t@echo \"Follow @awscloud\"" must veto @echo and keep @awscloud.
func isMakeRecipePrefix(line, filename string, start int) bool {
	if !isMakefileName(filename) {
		return false
	}
	if start == 0 || line[0] != '\t' {
		return false
	}
	// Everything between the tab and the token must be Make prefix characters. Anything else — a
	// word, a quote, a brace — means this token is an argument, not the command.
	for i := 1; i < start; i++ {
		switch line[i] {
		case '-', '+', '@', ' ':
		default:
			return false
		}
	}
	return true
}

// isMakefileName reports whether a path names a makefile, by the conventions make itself uses.
func isMakefileName(filename string) bool {
	base := filename
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	lower := strings.ToLower(base)
	switch lower {
	case "makefile", "gnumakefile", "makefile.am", "makefile.in":
		return true
	}
	return strings.HasSuffix(lower, ".mk") || strings.HasSuffix(lower, ".make")
}

// isImageDigest reports whether a bare "@token" is the digest half of a container image reference.
//
// Categorical rather than probabilistic: "@sha256:" is followed by a colon and 64 hex characters, and
// a handle cannot contain a colon — the configured pattern is @[a-zA-Z0-9_]{1,15}, which stops at it.
// So the token captured is "@sha256" and what FOLLOWS it in the line decides. Nothing else in the
// grammar of an image reference can produce that shape.
func isImageDigest(line string, end int) bool {
	rest := line[end:]
	if !strings.HasPrefix(rest, ":") {
		return false
	}
	rest = rest[1:]
	n := 0
	for n < len(rest) && isHexByte(rest[n]) {
		n++
	}
	return n >= 32
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
