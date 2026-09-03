// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"
)

// A bare "@token" is a handle in prose and a keyword in half a dozen formats.
//
// Measured over 1,633 real CSS and JavaScript files: 13,611 TWITTER findings before, 10,225 after, with
// @media alone accounting for 2,726 of the 3,386 removed.
//
// #479 was filed against a different shape — "@pR" read out of compressed bytes — and proposed a
// {4,15} length floor, which addresses none of these tokens; they are all four characters or more.
// Neither the word nor the position discriminates on its own; it takes both, and the first version of
// these rules used position alone and leaked. See TestTheTwoConfirmedLeaksStayFixed, which is the reason
// the rules look the way they do.

// spanOf locates the token in the line the way the pattern loop does.
func spanOf(t *testing.T, line, token string) (int, int) {
	t.Helper()
	i := strings.Index(line, token)
	if i < 0 {
		t.Fatalf("token %q is not in %q, so the case tests nothing", token, line)
	}
	return i, i + len(token)
}

// TestSyntaxIsVetoed is the reported defect, one case per family.
func TestSyntaxIsVetoed(t *testing.T) {
	for _, tc := range []struct{ name, line, token string }{
		// JSON-LD: 84% of the measured population.
		{"json-ld type", `  "@type": "Article",`, "@type"},
		{"json-ld context", `{"@context": "https://schema.org"}`, "@context"},
		{"single-quoted key", `{'@type': 'Person'}`, "@type"},
		{"spaced colon", `  "@type"  : "Article"`, "@type"},
		{"json-ld id", `  "@id": "urn:x",`, "@id"},
		// CSS at-rules: name AND position AND a block brace on the line.
		{"css media at line start", `@media (min-width: 700px) {`, "@media"},
		{"css media indented", `    @media screen {`, "@media"},
		{"css after closing brace", `}  @media print {`, "@media"},
		{"minified, whole sheet on one line", `a{color:red}@media print{b{color:blue}}`, "@media"},
		{"css keyframes", `@keyframes spin { from { top: 0 } }`, "@keyframes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := spanOf(t, tc.line, tc.token)
			if !isSyntaxNotAHandle(tc.line, tc.token, "probe.txt", s, e) {
				t.Errorf("%q in %q was not recognised as syntax; it reports as TWITTER at confidence 100",
					tc.token, tc.line)
			}
		})
	}
}

// TestARealHandleIsNeverVetoed is the direction that must not break, and the reason every rule requires
// two independent signals rather than acting on the word or the position alone.
//
// A wrong veto suppresses a real finding, and a suppressed finding is a cleartext leak — only reported
// findings reach the redactor.
//
// EVERY CASE HERE SITS AT A POSITION ONE OF THE RULES ACTS ON. The first version of this test placed all
// of its handles mid-line, which is precisely the region where neither rule can fire, so it was disjoint
// from the failure region by construction and passed while two real leaks shipped. Cases marked "leak"
// are the shapes that were actually broken.
func TestARealHandleIsNeverVetoed(t *testing.T) {
	for _, tc := range []struct{ name, line, token string }{
		{"plain prose", `follow @jack for updates`, "@jack"},
		{"quoted in prose, no colon", `he is "@jack" on twitter`, "@jack"},
		{"the word media as a handle", `our account is @media on x`, "@media"},
		{"handle as a json value", `{"owner": "@jack"}`, "@jack"},
		{"handle in a json array", `["@jack", "@jill"]`, "@jack"},
		{"at-rule word mid-statement", `background: url(@media);`, "@media"},

		// leak 1 — a one-handle-per-line mentions export. Column 0 is not evidence of CSS.
		{"leak: at-rule name alone on its line", `@media`, "@media"},
		{"leak: at-rule name, one per line, indented", `  @page`, "@page"},
		{"leak: mention count in parentheses", `@media (12 mentions)`, "@media"},
		{"leak: csv row with a quoted column", `@media,"12 mentions"`, "@media"},
		{"leak: semicolon-delimited csv", `@layer;12;active`, "@layer"},

		// leak 2 — a handle-keyed map: a moderator roster, a mention-count export. The key position is
		// not evidence of JSON-LD; only a reserved keyword in that position is.
		{"leak: handle-keyed map", `  "@schneems": 42,`, "@schneems"},
		{"leak: handle-keyed map, single quotes", `{'@tleish': 17}`, "@tleish"},
		{"leak: handle key in a python dict", `    "@dhh": ["merge"],`, "@dhh"},
		// An at-rule name in key position is not a JSON-LD keyword either, and CSS has no keys.
		{"leak: at-rule name as a map key", `  "@media": 3,`, "@media"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := spanOf(t, tc.line, tc.token)
			if isSyntaxNotAHandle(tc.line, tc.token, "probe.txt", s, e) {
				t.Errorf("%q in %q was vetoed as syntax. A wrong veto suppresses a real finding, and "+
					"only reported findings reach the redactor.", tc.token, tc.line)
			}
		})
	}
}

// TestTheTwoConfirmedLeaksStayFixed drives the real validator end to end on the two shapes a recall hunt
// proved were losing real handles, and pins the sink behaviour rather than the rule.
//
// This is the test that matters. The unit cases above assert the predicate; this asserts that a file of
// real handles still produces findings, which is what decides whether the redactor ever sees them. On the
// roster shape, the position-only version reported nothing, produced no redacted file, and exited 0.
func TestTheTwoConfirmedLeaksStayFixed(t *testing.T) {
	v := newConfiguredValidator()

	for _, tc := range []struct {
		name, content string
		want          []string
	}{
		{
			// Every name here is a plausible account that collides with a CSS at-rule.
			name:    "one handle per line",
			content: "@media\n@page\n@layer\n@scope\n@container\n@schneems\n",
			want:    []string{"@media", "@page", "@layer", "@scope", "@container", "@schneems"},
		},
		{
			name:    "handle-keyed roster",
			content: "{\n  \"@schneems\": 42,\n  \"@tleish\": 17,\n  \"@dhh\": 8\n}\n",
			want:    []string{"@schneems", "@tleish", "@dhh"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.content, "mentions.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			var got strings.Builder
			for _, m := range matches {
				got.WriteString(m.Text)
				got.WriteByte(' ')
			}
			for _, w := range tc.want {
				if !strings.Contains(got.String(), w) {
					t.Errorf("%s was not reported in %q. It is a real handle, nothing reaches the "+
						"redactor unreported, and this exact shape leaked once. reported=[%s]",
						w, tc.content, got.String())
				}
			}
		})
	}
}

// TestVetoIgnoresURLMatches keeps the rules where they belong.
//
// A match carrying a host name is already disambiguated by it, so none of these rules applies. What
// enforces that is the "@" prefix check — a URL match does not start with one. Mutation testing showed
// the extra "no slash" guard this once had was unreachable, so the guard went and this test now pins the
// prefix, which is the thing that actually does the work.
func TestVetoIgnoresURLMatches(t *testing.T) {
	line := `see https://twitter.com/media for the feed`
	for _, token := range []string{"twitter.com/media", "https://twitter.com/media"} {
		s, e := spanOf(t, line, token)
		if isSyntaxNotAHandle(line, token, "probe.txt", s, e) {
			t.Errorf("%q was vetoed; a URL is not a bare handle and these rules must not see it", token)
		}
	}

	// The case that makes the prefix check load-bearing rather than decorative, and the reason a
	// mutation removing it survived until this existed: a profile URL used as a JSON KEY has the
	// quoted-and-colon shape exactly, so without the prefix check a real account in a config file could
	// be silently suppressed.
	keyed := `{"twitter.com/type": "official account"}`
	s, e := spanOf(t, keyed, "twitter.com/type")
	if isSyntaxNotAHandle(keyed, "twitter.com/type", "probe.txt", s, e) {
		t.Error("a profile URL used as a JSON key was vetoed. The JSON rule is about JSON-LD keywords " +
			"beginning with @, not about any quoted string, and a suppressed finding is a cleartext leak.")
	}
}

// TestJSONRuleNeedsBothSignals pins the two conditions separately, so a mutation dropping either one is
// caught by a case that names which signal went missing.
func TestJSONRuleNeedsBothSignals(t *testing.T) {
	// Signal 1: the key position. Without the colon check this would veto a quoted handle in prose.
	withColon := `  "@type": "Article"`
	s, e := spanOf(t, withColon, "@type")
	if !isJSONLDKey(withColon, "type", s, e) {
		t.Error("a reserved keyword in quoted key position was not recognised")
	}
	noColon := `he is "@type" apparently`
	s, e = spanOf(t, noColon, "@type")
	if isJSONLDKey(noColon, "type", s, e) {
		t.Error("a quoted token with no colon after it was treated as an object key; that shape is a " +
			"handle in prose")
	}

	// Signal 2: the reserved-keyword set. This is what makes a handle-keyed map report, and its absence
	// was leak 2.
	roster := `  "@schneems": 42,`
	s, e = spanOf(t, roster, "@schneems")
	if isJSONLDKey(roster, "schneems", s, e) {
		t.Error("a non-keyword in key position was treated as JSON-LD. A handle-keyed roster is a real " +
			"finding and this shape lost every key in the file.")
	}
}

// TestCSSRuleNeedsTheBrace pins the third signal, which is the one that closed leak 1.
//
// Name and position hold for any at-rule-named handle at column 0 in any file type, so the brace is what
// separates a stylesheet from a mentions export.
func TestCSSRuleNeedsTheBrace(t *testing.T) {
	if !isCSSAtRule(`@media print {`, "media", 0, len("@media")) {
		t.Error("a real CSS at-rule opening a block was not recognised")
	}
	if isCSSAtRule(`@media`, "media", 0, len("@media")) {
		t.Error("an at-rule name alone on a line was treated as CSS. That is a one-handle-per-line " +
			"mentions export, and it lost 5 of 6 handles to cleartext.")
	}
	// Deliberate residual false positive, recorded so it is not mistaken for a regression: a multi-line
	// prelude puts the brace on the NEXT line, which this rule cannot see. Measured at 0.83% of 7,068
	// at-rule occurrences in 1,881 real CSS files. Reporting a false positive is the safe direction.
	if isCSSAtRule(`@media only screen`, "media", 0, len("@media")) {
		t.Error("a multi-line prelude was vetoed; the rule is supposed to be line-local")
	}
}

// TestJSONKeyRuleRequiresAMatchedQuotePair closes a smaller gap the same mutation round found.
//
// Accepting a mismatched pair — `"@type'` — would widen the rule to shapes that are not object keys in
// any format, and a suppressor that widens is the direction that costs findings.
func TestJSONKeyRuleRequiresAMatchedQuotePair(t *testing.T) {
	for _, line := range []string{
		`{"@type': "Article"}`,
		`{'@type": "Article"}`,
		`{@type: "Article"}`, // unquoted: not the shape this rule is about
	} {
		s, e := spanOf(t, line, "@type")
		if isJSONLDKey(line, "type", s, e) {
			t.Errorf("%q was treated as a quoted object key", line)
		}
	}
}

// TestVetoIsActuallyWiredIntoTheValidator is the test that was missing, and its absence was the worst
// gap in the first version of this change.
//
// Every unit test here calls the predicate directly, so a mutation DELETING the call from the pattern
// loop survived the entire suite: the rules were perfect and unreachable. This drives the real validator
// instead, so the wiring is part of what is pinned.
//
// Both directions in one test on purpose — the FP must go and the real handle must stay — because a
// veto wired in backwards would pass either assertion alone.
func TestVetoIsActuallyWiredIntoTheValidator(t *testing.T) {
	v := newConfiguredValidator()

	syntax := `{"@context": "https://schema.org", "@type": "Article"}` + "\n" +
		`@media (min-width: 700px) { .a { color: red } }`
	matches, err := v.ValidateContent(syntax, "page.json")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	for _, m := range matches {
		if strings.EqualFold(m.Type, "TWITTER") {
			t.Errorf("JSON-LD keywords and a CSS at-rule produced a TWITTER finding (%q at %.0f). "+
				"The rules are only useful if the pattern loop consults them.", m.Text, m.Confidence)
		}
	}

	// The direction that must not break: a real handle in the same content still reports.
	prose := `follow @jack for updates, he is "@jack" on twitter`
	matches, err = v.ValidateContent(prose, "readme.md")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var handles int
	for _, m := range matches {
		if strings.EqualFold(m.Type, "TWITTER") {
			handles++
		}
	}
	if handles == 0 {
		t.Errorf("a real handle in prose produced no TWITTER finding; the veto is over-reaching. "+
			"matches=%+v", matches)
	}
}

// The CSS rule needed FOUR signals, and it got there by leaking twice.
//
// Name + position vetoed a one-handle-per-line mentions export (covered above). Adding "a `{` later on
// the line" still vetoed a DELIMITED EXPORT carrying a brace-bearing column — the standard shape of a
// social-listening or webhook export — and a chat join line. Measured against the pre-#483 binary:
//
//	author,date,payload              @media,2026-08-25,"{""rt"":3}"      lost @media and @page
//	date;author;payload              2026-08-25;@media;{"rt":3}          lost them from column 2 too
//	author<TAB>mentions<TAB>payload  @media<TAB>42<TAB>{"rt":3}          lost @media and @layer
//	a chat join line                 @page joined the channel {general}  lost @page
//
// In each, a real handle survived only when its name happened not to collide with an at-rule, and the
// cleartext survived redaction — with no other finding, no redacted file was produced at all, at rc 0.
//
// Both new signals are FREE, measured over 9,346 real at-rule occurrences in 1,881 CSS files that
// already pass the earlier signals:
//
//	byte immediately after the name   <space> 92.91%   ( 7.02%   { 0.07%   = 100.00%; TAB never
//	line ends with `{`                30.57%   (CSS written for humans)
//	line has two or more `{`          69.43%   (minified)
//	either                            100.00%
//
// And on the 1,633-file corpus the false-positive count is IDENTICAL with and without them.

// TestDelimitedExportsAreNotCSS is the reported regression, one case per delimiter.
func TestDelimitedExportsAreNotCSS(t *testing.T) {
	for _, tc := range []struct{ name, line, token string }{
		{"comma-delimited, quoted json column", `@media,2026-08-25,"{""rt"":3}"`, "@media"},
		{"semicolon-delimited, handle in column 2", `2026-08-25;@media;{"rt":3}`, "@media"},
		{"tab-separated", "@media\t42\t{\"rt\":3}", "@media"},
		{"tab-separated, second row token", "@layer\t7\t{\"rt\":1}", "@layer"},
		{"chat join line naming a channel", `@page joined the channel {general}`, "@page"},
		{"prose with a brace later", `follow @media for updates, see {docs}`, "@media"},

		// The cases where cssPreludeFollows is the ONLY signal standing between the row and a veto.
		//
		// A first version of this table had none of them: every delimited fixture carried a SINGLE
		// brace, so opensABlock already rejected it, and a mutation deleting the prelude check
		// SURVIVED the whole suite. Two brace-bearing columns, or a row ending in a brace, are what
		// reach the region that check actually governs.
		{"two json columns, comma", `@media,{"rt":3},{"likes":9}`, "@media"},
		{"two json columns, tab", "@media\t{\"a\":1}\t{\"b\":2}", "@media"},
		{"two json columns, semicolon", `@layer;{"a":1};{"b":2}`, "@layer"},
		{"row that ends in a brace", `@media,payload,{`, "@media"},
		{"row ending in a brace, tab", "@page\t42\t{", "@page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := spanOf(t, tc.line, tc.token)
			if isSyntaxNotAHandle(tc.line, tc.token, "probe.txt", s, e) {
				t.Errorf("%q in %q was vetoed as CSS. It is a data row or prose, the handle is real, "+
					"and only reported findings reach the redactor.", tc.token, tc.line)
			}
		})
	}
}

// TestCSSPreludeSignalAcceptsWhatRealCSSWrites is the direction that must not break.
//
// 100% of 9,346 real occurrences are covered by space, `(` or `{`; the quote forms are legal minified
// CSS and were added after a single real file — `@import"https://..."` in a minified Apple stylesheet —
// showed up as the only false positive the first version of this signal caused.
func TestCSSPreludeSignalAcceptsWhatRealCSSWrites(t *testing.T) {
	for _, tc := range []struct{ name, line, token string }{
		{"space then a query", `@media screen and (min-width: 700px) {`, "@media"},
		{"minified paren", `@media(min-width:600px){a{color:red}}`, "@media"},
		{"minified string prelude", `@import"https://example.com/f.css";a{color:red}b{color:blue}`, "@import"},
		{"charset with a quote", `@charset"utf-8";a{color:red}b{color:blue}`, "@charset"},
		{"block-only at-rule, brace flush", `@keyframes spin{from{top:0}}`, "@keyframes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := spanOf(t, tc.line, tc.token)
			if !isSyntaxNotAHandle(tc.line, tc.token, "probe.txt", s, e) {
				t.Errorf("%q in %q was NOT recognised as CSS, so a real at-rule reports as a handle",
					tc.token, tc.line)
			}
		})
	}
}

// TestAQuoteAfterTheNameIsSafeBecauseOfThePositionCheck pins why accepting a quote does not re-open the
// CSV case, structurally rather than by luck.
//
// For a delimited file to put a quote immediately AFTER the token, the token would have to be unquoted
// while the next field is quoted — which no delimited format emits. When a CSV does quote the field, the
// token is PRECEDED by a quote, and opensAStatement rejects that.
func TestAQuoteAfterTheNameIsSafeBecauseOfThePositionCheck(t *testing.T) {
	quoted := `"@media","12"`
	s, e := spanOf(t, quoted, "@media")
	if isSyntaxNotAHandle(quoted, "@media", "probe.txt", s, e) {
		t.Error(`"@media","12" was vetoed. A quoted CSV field puts the quote BEFORE the token, which ` +
			"opensAStatement must reject — that is what makes accepting a trailing quote safe.")
	}
}

// TestOpensABlockNeedsMoreThanOneBraceMidLine pins the fourth signal, both shapes.
func TestOpensABlockNeedsMoreThanOneBraceMidLine(t *testing.T) {
	if !opensABlock(`@media print {`) {
		t.Error("a line ending in `{` opens a block")
	}
	if !opensABlock(`@media print {   `) {
		t.Error("trailing whitespace after `{` must not matter")
	}
	if !opensABlock(`a{color:red}@media print{b{color:blue}}`) {
		t.Error("minified CSS puts many braces on one line and must still count")
	}
	if opensABlock(`@page joined the channel {general}`) {
		t.Error("one brace opened and closed mid-line is prose or data, not a CSS block. Checking only " +
			"\"ends with a brace\" would have covered just 30.57% of real CSS, which is why both shapes " +
			"are accepted and a single mid-line pair is not.")
	}
}

// TestTabIsNotPreludeWhitespace records a deliberate, measured choice.
//
// CSS permits a tab after an at-rule name, but it never appears there in 9,346 real occurrences, while a
// tab IS the delimiter of a TSV. Positives may widen, suppressors may not.
func TestTabIsNotPreludeWhitespace(t *testing.T) {
	if cssPreludeFollows("@media\tscreen {", len("@media")) {
		t.Error("a TAB was accepted as prelude whitespace. It never occurs there in real CSS and it is " +
			"the delimiter of a TSV, so accepting it re-opens the export leak.")
	}
	if !cssPreludeFollows("@media screen {", len("@media")) {
		t.Error("a space must be accepted")
	}
}
