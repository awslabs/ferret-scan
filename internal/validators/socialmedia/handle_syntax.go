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
//   - The CSS rule requires a `{` later on the same line as well as the at-rule name and the statement
//     position. Measured over 7,068 at-rule occurrences in 1,881 real CSS files on this host, including
//     minified single-line bundles: 99.17% have a `{` later on the line. A brace was chosen over the
//     alternatives deliberately — `(` covers 94.40% and a quote 70.61%, but a mentions export writes
//     `@media (12 mentions)` and a CSV writes `@media,"12"`, so both of those re-open the leak this rule
//     exists to close. Note the test is "contains a brace later", not "ends in a brace", because
//     minified CSS puts the whole stylesheet on one line.
//
// The residual 0.83% are multi-line preludes — `@media only screen` with the brace on the next line —
// which now report as false positives. That is the safe direction: positives may widen, suppressors may
// not.
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
func isSyntaxNotAHandle(line, match string, start, end int) bool {
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
// Three signals: a known at-rule name, the position an at-rule occupies, and a block brace on the line.
// The brace is what stops this vetoing a one-handle-per-line mentions export, where the first two hold
// for any handle whose name happens to collide with an at-rule.
func isCSSAtRule(line, token string, start, end int) bool {
	if _, ok := cssAtRules[token]; !ok {
		return false
	}
	return opensAStatement(line, start) && strings.Contains(line[end:], "{")
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
