// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// The lexer behind the #753 gate, tested on its own terms: which byte offsets it calls literal, and
// which inputs make it fail open. The gate's end-to-end contract is in source_gate_test.go; these
// pin the grammar each language table entry is read with, so a lexer regression is reported as the
// construct it broke rather than as a finding that moved.

// lexProbe asserts the classification of the FIRST byte of probe inside content.
type lexProbe struct {
	probe   string
	literal bool
}

func checkLex(t *testing.T, lang sourceLanguage, content string, probes []lexProbe) {
	t.Helper()
	lit, reason := lexLiterals(content, lang)
	if reason != "" {
		t.Fatalf("%s lexer failed open (%s) on:\n%s", lang, reason, content)
	}
	for _, p := range probes {
		off := strings.Index(content, p.probe)
		if off < 0 {
			t.Fatalf("probe %q not in content", p.probe)
		}
		if got := lit.has(off); got != p.literal {
			want := "CODE"
			if p.literal {
				want = "LITERAL"
			}
			t.Errorf("%s: %q at offset %d should be %s\n%s", lang, p.probe, off, want, content)
		}
	}
}

func TestLexPythonLiterals(t *testing.T) {
	content := strings.Join([]string{
		`token = get_token()  # comment_token=X`,
		`a = 'single_quote' + "double_quote"`,
		`b = 'it\'s escaped' + after_escape`,
		`c = r"raw\"still_inside" + after_raw`,
		`d = f"fstr {brace_inside} tail" + after_f`,
		`e = rb'raw_bytes' + Br"raw_bytes2" + after_prefix`,
		`f = """triple_open`,
		`body_line = inside_triple`,
		`"""`,
		`g = '''single_triple # not_comment'''`,
		`h = "continued \`,
		`continued_tail" + after_cont`,
		`i = 10 // 3  # floor_div_is_code`,
		"j = `backtick_code`",
	}, "\n") + "\n"
	checkLex(t, langPython, content, []lexProbe{
		{"token = get", false},
		{"# comment_token", true},
		{"'single_quote'", true},
		{"\"double_quote\"", true},
		{"escaped'", true},
		{"after_escape", false},
		{"still_inside", true},
		{"after_raw", false},
		{"brace_inside", true},
		{"after_f", false},
		{"rb'raw_bytes'", true},
		{"Br\"raw_bytes2\"", true},
		{"after_prefix", false},
		{"triple_open", true},
		{"inside_triple", true},
		{"g = '''", false},
		{"not_comment", true},
		{"continued_tail", true},
		{"after_cont", false},
		{"3  # floor", false},
		{"# floor_div", true},
		{"backtick_code", false},
	})
}

func TestLexJSLiterals(t *testing.T) {
	content := strings.Join([]string{
		`#!/usr/bin/env node shebang_comment`,
		`const a = getToken(); // line_comment`,
		`/* block_open`,
		`block_body */ const after_block = 1;`,
		`const s = 'single' + "double" + after_strings;`,
		"const t = `plain_template` + after_template;",
		"const u = `head_text ${inner_code + {obj_brace: 1}.x} tail_text` + after_interp;",
		"const v = `outer ${`nested_text ${deep_code}`} outer_tail`;",
		"const w = `multi_line_open",
		"multi_line_body` + after_multi;",
		`const re = /["']quote_in_regex/g.test(after_regex);`,
		`const div = total / count / per_div;`,
		`const s2 = "continued \`,
		`continued_tail" + after_cont;`,
		`return /return_regex/.source;`,
		`const arrow = list.some((o) => /^--arrow_regex="/.test(o));`,
		// A template that STARTS with ${ is code at its opening backtick; any other keeps it.
		"const x = `${lead_code} lead_tail`;",
		// A '/' that leads its line after an operand is a division: JS inserts no semicolon before
		// it. Read as a regex it would close at the first '/' of the trailing comment and leave the
		// comment in code.
		`const avg = total`,
		`  / count; // leading_div_comment don't use user's`,
		`const avg2 = total`,
		`  / count; /* leading_div_block */ const after_lead_div = 1;`,
		// prevSig skips a comment: the ';' before it, not the comment's last letter, decides.
		`const ratio = "str".length`,
		`  / count; // after_member_div`,
		`const half = 'str'`,
		`  / 2; // after_string_div`,
		`init(); // see a`,
		`/^line_regex/.test(x);`,
		// A ')' that closes an if/for/while/with header ends no operand: the body statement starts
		// there, so a '/' after it is a regex even on the next line. Read as a division, the
		// regex's quote would open a string closed by the comment's quote, leaving the comment
		// text in code without failing open.
		`if (ok)`,
		`  /"/.exec(s) && go(); // the "if_body_comment`,
		`for (const l of lines)`,
		`  /"/.exec(l) && go(); // the "for_body_comment`,
		`while (m)`,
		`  /"/.exec(m) && go(); // the "while_body_comment`,
		`with (o)`,
		`  /"/.exec(m) && go(); // the "with_body_comment`,
		`if (f(a) && (b))`,
		`  /"/.exec(s) && go(); // the "nested_header_comment`,
		`if (a) go(); else if (ok) /"/.exec(s) && go(); // the "same_line_header_comment`,
		// A call's or a group's ')' is still an operand end, and so is a property named like a
		// keyword (o.if, this.#if): the '/' after each is a division.
		`const q = f(a)`,
		`  / count; // after_call_div`,
		`const g = (a + b)`,
		`  / count; // after_group_div`,
		`const p = o.if(a)`,
		`  / count; // after_member_kw_div`,
		`const p2 = this.#if(a)`,
		`  / count; // after_private_kw_div`,
	}, "\n") + "\n"
	checkLex(t, langJS, content, []lexProbe{
		{"#!/usr", true},
		{"getToken", false},
		{"// line_comment", true},
		{"block_open", true},
		{"block_body", true},
		{"const after_block", false},
		{"'single'", true},
		{`"double"`, true},
		{"after_strings", false},
		{"`plain_template`", true}, // no ${ : the backtick itself is literal
		{"after_template", false},
		{"`head_text", true}, // text before the first ${ : the backtick stays literal
		{"head_text", true},
		{"inner_code", false},
		{"obj_brace", false},
		{"tail_text", true},
		{"after_interp", false},
		{"nested_text", true},
		{"deep_code", false},
		{"outer_tail", true},
		{"multi_line_body", true},
		{"after_multi", false},
		{"quote_in_regex", true},
		{"after_regex", false},
		{"count", false},
		{"per_div", false},
		{"continued_tail", true},
		{"after_cont", false},
		{"return_regex", true},
		{"arrow_regex", true},
		{"test(o)", false},
		{"`${lead_code}", false}, // starts with ${ : the backtick counts as code
		{"lead_code", false},
		{"lead_tail", true},
		{"leading_div_comment", true},
		{"leading_div_block", true},
		{"after_lead_div", false},
		{"after_member_div", true},
		{"after_string_div", true},
		{"line_regex", true},
		{"if_body_comment", true},
		{"for_body_comment", true},
		{"while_body_comment", true},
		{"with_body_comment", true},
		{"nested_header_comment", true},
		{"same_line_header_comment", true},
		{"after_call_div", true},
		{"after_group_div", true},
		{"after_member_kw_div", true},
		{"after_private_kw_div", true},
	})
}

func TestLexGoLiterals(t *testing.T) {
	content := strings.Join([]string{
		`package x // pkg_comment`,
		`var a = "interp_string" + after_string`,
		`var r = '"' + after_rune`,
		`var q = '\'' + after_escaped_rune`,
		"var raw = `raw_open \\no_escape",
		"raw_body ${not_interp}` + after_raw",
		`/* block_comment */ var after_block = 1`,
		`var div = a / b / after_div`,
	}, "\n") + "\n"
	checkLex(t, langGo, content, []lexProbe{
		{"// pkg_comment", true},
		{"interp_string", true},
		{"after_string", false},
		{"'\"'", true},
		{"after_rune", false},
		{"after_escaped_rune", false},
		{"`raw_open", true},
		{"raw_body", true},
		{"not_interp", true},
		{"after_raw", false},
		{"block_comment", true},
		{"after_block", false},
		{"after_div", false},
	})
}

func TestLexHCLLiterals(t *testing.T) {
	content := strings.Join([]string{
		`# hash_comment`,
		`// slash_comment`,
		`/* block_comment */`,
		`password = var.code_value`,
		`name = "text_part ${interp_code("nested_string")} tail_part"`,
		`escaped = "$${not_interp} after_escape"`,
		`directive = "%{ if cond_code }yes_text%{ endif }"`,
		`user_data = <<EOT`,
		`heredoc_body password=X`,
		`EOT`,
		`indented = <<-EOF`,
		`    indented_body`,
		`  EOF`,
		`after_heredoc = 1`,
		`single = 'apostrophe_is_code'`,
	}, "\n") + "\n"
	checkLex(t, langHCL, content, []lexProbe{
		{"# hash_comment", true},
		{"// slash_comment", true},
		{"block_comment", true},
		{"var.code_value", false},
		{"text_part", true},
		{"interp_code", false},
		{"nested_string", true},
		{"tail_part", true},
		{"not_interp", true},
		{"after_escape", true},
		{"cond_code", false},
		{"yes_text", true},
		{"heredoc_body", true},
		{"indented_body", true},
		{"after_heredoc", false},
		{"apostrophe_is_code", false},
	})
}

// Every fail-open condition, with the reason the lexer gives. A reason is asserted rather than just
// "failed", so a lexer that fails open for the WRONG reason -- and so would fail open on valid code
// -- cannot pass here by accident.
func TestLexFailOpenConditions(t *testing.T) {
	cases := []struct {
		name    string
		lang    sourceLanguage
		content string
		reason  string
	}{
		{"py unterminated string", langPython, "x = 'abc\ny = 1\n", "unterminated single-line string"},
		{"py unclosed triple", langPython, "x = \"\"\"abc\ny = 1\n", "content ends inside a literal"},
		{"js unterminated string", langJS, "x = \"abc\ny = 1\n", "unterminated single-line string"},
		{"js unclosed block comment", langJS, "/* abc\ny = 1\n", "content ends inside a literal"},
		{"js unclosed template", langJS, "x = `abc\ny = 1\n", "content ends inside a literal"},
		{"js unbalanced interpolation", langJS, "x = `a ${ b `\n", "content ends inside a literal"},
		{"js regex not closed", langJS, "x = (/abc\n", "regex literal not closed on its line"},
		{"go string continued", langGo, "x := \"abc\\\ndef\"\n", "string continued past the end of its line"},
		{"go unterminated rune", langGo, "x := 'a\n", "unterminated single-line string"},
		{"go unclosed raw", langGo, "x := `abc\n", "content ends inside a literal"},
		{"hcl unterminated string", langHCL, "x = \"abc\ny = 1\n", "unterminated single-line string"},
		{"hcl unclosed heredoc", langHCL, "x = <<EOT\nabc\n", "content ends inside a literal"},
		{"hcl unbalanced interpolation", langHCL, "x = \"${ a\n", "unbalanced interpolation"},
		{"js interpolation never closed", langJS, "x = `a ${ b\n", "unbalanced interpolation"},
		{"js nesting too deep", langJS, "x = " + strings.Repeat("`${", maxInterpolationDepth+1) + "\n",
			"interpolation nested deeper than maxInterpolationDepth"},
		// JSX: a closing tag in code position, in .js and in .ts (where it means the file is not
		// TypeScript); an opening tag at an expression start only in .js, .mjs and .cjs.
		{"js JSX closing tag", langJS, "const a = (\n  <p>\n    text\n  </p>\n);\n", "JSX element in a JavaScript file"},
		{"js JSX fragment close", langJS, "const a = (\n  <>\n    text\n  </>\n);\n", "JSX element in a JavaScript file"},
		{"js JSX opener only", langJS, "const a = <p>see http://x</p>;\n", "JSX element in a JavaScript file"},
		{"js JSX after export default", langJS, "export default <p>see http://x</p>;\n", "JSX element in a JavaScript file"},
		// An if/for/while/with header's ')' ends no operand, so a '<' after it starts an element.
		// The `//` in the URL hides the closing tag.
		{"js JSX opener after an if header", langJS, "if (ok)\n  <p>see http://x</p>;\n", "JSX element in a JavaScript file"},
		{"ts markup closing tag", langTS, "<?xml version=\"1.0\"?>\n<TS>\n<source>text</source>\n</TS>\n",
			"JSX element in a JavaScript file"},
		// A typographic quote in code position, in every grammar.
		{"py typographic quote", langPython, "PASSWORD = \u201cabc\u201d\n", "typographic quote in code"},
		{"js typographic quote", langJS, "const p = \u2018abc\u2019;\n", "typographic quote in code"},
		{"ts typographic quote", langTS, "const p = \u201cabc\u201d;\n", "typographic quote in code"},
		{"go typographic quote", langGo, "var p = \u201cabc\u201d\n", "typographic quote in code"},
		{"hcl typographic quote", langHCL, "p = \u201cabc\u201d\n", "typographic quote in code"},
		// Every other non-ASCII quotation mark -- guillemets, CJK corner brackets, full-width and
		// low-9 forms, the Pi/Pf editorial marks -- is just as invalid in code position, and so is
		// a Windows-1252 smart quote, raw (ScanText) or Latin-1-transcoded (a file or --stdin).
		{"py guillemets", langPython, "PASSWORD = \u00ababc\u00bb\n", "typographic quote in code"},
		{"py reversed guillemets", langPython, "PASSWORD = \u00bbabc\u00ab\n", "typographic quote in code"},
		{"js single guillemets", langJS, "const p = \u2039abc\u203a;\n", "typographic quote in code"},
		{"js editorial quote punctuation", langJS, "const p = \u2e02abc\u2e03;\n", "typographic quote in code"},
		{"ts full-width double quote", langTS, "const p = \uff02abc\uff02;\n", "typographic quote in code"},
		{"ts full-width apostrophe", langTS, "const p = \uff07abc\uff07;\n", "typographic quote in code"},
		{"go corner brackets", langGo, "var p = \u300cabc\u300d\n", "typographic quote in code"},
		{"go white corner brackets", langGo, "var p = \u300eabc\u300f\n", "typographic quote in code"},
		{"hcl low-9 and reversed-9", langHCL, "p = \u201eabc\u201f\n", "typographic quote in code"},
		{"hcl single low-9", langHCL, "p = \u201aabc\u201b\n", "typographic quote in code"},
		{"py raw cp1252 smart quotes", langPython, "PASSWORD = \x93abc\x94\n", "typographic quote in code"},
		{"ts raw cp1252 smart quotes", langTS, "const p = \x93abc\x94;\n", "typographic quote in code"},
		{"go raw Latin-1 guillemets", langGo, "var p = \xababc\xbb\n", "typographic quote in code"},
		{"py cp1252 quotes after Latin-1 transcoding", langPython, "PASSWORD = \u0093abc\u0094\n", "typographic quote in code"},
		{"hcl cp1252 single quotes after Latin-1 transcoding", langHCL, "p = \u0091abc\u0092\n", "typographic quote in code"},
		// Redact's spelling of a raw cp1252 quote: every invalid UTF-8 sequence becomes U+FFFD.
		{"py replacement character", langPython, "PASSWORD = \ufffdabc\ufffd\n", "replacement character in code"},
		{"ts replacement character", langTS, "const p = \ufffdabc\ufffd;\n", "replacement character in code"},
		// PEP 701 f-strings: a format spec is text, so the f-string's own quote cannot close there.
		{"py f-string closed in a format spec", langPython, "x = f\"{a:>10\"\n", "f-string closed inside a format spec"},
		{"py newline in a format spec", langPython, "x = f\"{a:>10\n}\"\n", "newline in the format spec of a single-quoted f-string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, reason := lexLiterals(tc.content, tc.lang)
			if reason != tc.reason {
				t.Errorf("fail-open reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

// Non-ASCII that a gated grammar accepts must not fail the file open: letters, combining marks and
// digits in identifiers, the punctuation and symbols that are identifier characters (connector
// punctuation, Other_ID_Start and Other_ID_Continue: · ℘ ℮ ・ ‿), the whitespace JS accepts (NBSP,
// BOM), and any quotation mark inside a string or a comment. The identifiers ë û Г Д 专 且 丫 主 𠂓
// end in the bytes 0xAB 0xBB 0x93 0x94, the Windows-1252 quotes: inside a valid rune those bytes
// are not quotes. 𠂓 (U+20093, F0 A0 82 93) puts a quote byte at the end of a four-byte rune, the
// farthest the look back for its lead byte has to reach.
func TestLexNonASCIICodeDoesNotFailOpen(t *testing.T) {
	ids := "\u00eb, \u00fb, \u0413, \u0414, \u4e13, \u4e14, \u4e2b, \u4e3b, \U00020093"
	cases := []struct {
		name    string
		lang    sourceLanguage
		content string
	}{
		{"py identifiers", langPython, "(" + ids + ") = range(8)  # \u00abok\u00bb\nx = '\u300cok\u300d'\n"},
		{"js identifiers", langJS, "let " + ids + ";\n// \uff02ok\uff02\nconst x = '\u2039ok\u203a';\n"},
		{"ts identifiers", langTS, "let " + ids + ";\nconst x = `\u201eok\u201f`;\n"},
		{"go identifiers", langGo, "var " + ids + " int\nvar x = \"\u00abok\u00bb\" // \u300eok\u300f\n"},
		{"hcl string and comment", langHCL, "x = \"\u00abok\u00bb\" # \u201aok\u201b\n"},
		{"replacement character in a string", langGo, "var x = \"\ufffd\" // \ufffd\n"},
		{"py letters", langPython, "\u00e9t\u00e9 = \u03bb_\u03bc + \u4e16\u754c\n"},
		{"py combining mark", langPython, "e\u0301 = 1\n"},
		{"py middle dot", langPython, "a\u00b7b = 1\n"},
		{"py weierstrass p", langPython, "\u2118 = 1\n"},
		{"js katakana middle dot", langJS, "var a\u30fbb = 1;\n"},
		{"js estimated sign", langJS, "var \u212e = 1;\n"},
		{"js connector punctuation", langJS, "var a\u203fb = 1;\n"},
		{"js NBSP and BOM", langJS, "\ufeffvar\u00a0a = 1;\n"},
		{"ts letters", langTS, "const \u043f\u0430\u0440\u043e\u043b\u044c: string = x;\n"},
		{"go letters", langGo, "var \u4e16\u754c = \u00b5s\n"},
		{"hcl letters", langHCL, "p\u00e4ss = var.\u00e9\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, reason := lexLiterals(tc.content, tc.lang); reason != "" {
				t.Errorf("fail-open reason = %q, want none", reason)
			}
		})
	}
}

// The fail-open set is exactly the Unicode tables it names plus the Windows-1252 quotes, checked
// over every rune: each non-ASCII Quotation_Mark, Pi or Pf rune fails the file open in code
// position of every grammar and is legal inside a string, and no other rune fails it open. A Go
// release that adds a rune to a table is covered without an edit here.
func TestTypographicQuoteIsExactlyTheQuotationMarkTables(t *testing.T) {
	isQuote := func(r rune) bool {
		return r >= utf8.RuneSelf && (unicode.In(r, unicode.Quotation_Mark, unicode.Pi, unicode.Pf) ||
			(r < 0x100 && cp1252Quote(byte(r))))
	}
	langs := []sourceLanguage{langPython, langJS, langTS, langGo, langHCL}
	quotes := 0
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		q := string(r)
		if got := typographicQuoteAt("p = "+q, 4); got != isQuote(r) {
			t.Fatalf("typographicQuoteAt(%U) = %v, want %v", r, got, isQuote(r))
		}
		if !isQuote(r) {
			continue
		}
		quotes++
		for _, lang := range langs {
			if _, reason := lexLiterals("p = "+q+"abc"+q+"\n", lang); reason != "typographic quote in code" {
				t.Errorf("%s: %U in code: fail-open reason %q, want the typographic quote", lang, r, reason)
			}
			if _, reason := lexLiterals("p = \""+q+"abc"+q+"\"\n", lang); reason != "" {
				t.Errorf("%s: %U inside a string failed the file open: %q", lang, r, reason)
			}
		}
	}
	if quotes < 40 {
		t.Fatalf("only %d quotation marks enumerated; the tables did not load", quotes)
	}
}

// Non-ASCII punctuation and symbols are not quotation marks, but no gated grammar accepts them in
// code position either, so a value written between primes or ornaments is not valid source and the
// file fails open like one between typographic quotes. Connector punctuation is legal inside
// identifiers, and in a string or a comment any of them is just text.
func TestLexNonASCIIPunctuationInCodeFailsOpen(t *testing.T) {
	for _, q := range []string{"\u2032", "\u2033", "\u275d", "\u275e", "\u2013", "\u00d7", "\u20ac", "\U0001f511"} {
		for _, lang := range []sourceLanguage{langPython, langJS, langTS, langGo, langHCL} {
			if _, reason := lexLiterals("p = "+q+"abc"+q+"\n", lang); reason != "non-ASCII punctuation or symbol in code" {
				t.Errorf("%s: %+q in code: fail-open reason %q, want the punctuation reason", lang, q, reason)
			}
			if _, reason := lexLiterals("p = \""+q+"abc"+q+"\"\n", lang); reason != "" {
				t.Errorf("%s: %+q inside a string failed the file open (%q)", lang, q, reason)
			}
		}
	}
	for _, lang := range []sourceLanguage{langPython, langJS, langTS} {
		if _, reason := lexLiterals("a\u203fb = 1\n", lang); reason != "" {
			t.Errorf("%s: connector punctuation in an identifier failed the file open (%q)", lang, reason)
		}
	}
}

// The continuation rule is per language: Python and JS continue a single-line string past a
// trailing backslash, Go and HCL have no such form and must fail open on it.
func TestLexCRLFContinuation(t *testing.T) {
	for _, lang := range []sourceLanguage{langPython, langJS} {
		content := "x = \"head \\\r\ncontinued_tail\" + after\r\n"
		checkLex(t, lang, content, []lexProbe{{"continued_tail", true}, {"after", false}})
	}
}

func TestSourceLanguageTable(t *testing.T) {
	want := map[string]sourceLanguage{
		"a.py": langPython, "a.PYI": langPython, "a.pyw": langPython,
		"a.js": langJS, "a.mjs": langJS, "a.cjs": langJS, "a.ts": langTS, "a.mts": langTS,
		"a.cts": langTS, "types.d.ts": langTS, "A.JS": langJS, "A.TS": langTS,
		"a.go":    langGo,
		"main.tf": langHCL, "x.tfvars": langHCL, "x.hcl": langHCL,
		// Not gated: no extension, or an extension the table does not list.
		"<stdin>": langNone, "<text>": langNone, "clipboard": langNone, "<golden:x>": langNone,
		"x.jsx": langNone, "x.tsx": langNone, "x.docx": langNone, ".env.example": langNone,
		"x.ts.txt": langNone, "settings.yaml": langNone, ".env": langNone, "Dockerfile": langNone,
		"x.java": langNone, "x.rb": langNone, "": langNone,
	}
	for path, lang := range want {
		if got := sourceLanguageFor(path); got != lang {
			t.Errorf("sourceLanguageFor(%q) = %s, want %s", path, got, lang)
		}
	}
}

// maxLexBytes is documented as the ceiling on content this validator is handed in one piece. It is
// duplicated rather than imported, so this pins the duplicate.
func TestMaxLexBytesMatchesTheRouterCeiling(t *testing.T) {
	if int64(maxLexBytes) != router.MaxFileSize {
		t.Errorf("maxLexBytes = %d, router.MaxFileSize = %d: the gate's size ceiling no longer "+
			"matches the content the validator is handed in one piece", maxLexBytes, router.MaxFileSize)
	}
}

func TestLiteralSetRange(t *testing.T) {
	s := newLiteralSet(300)
	s.setRange(3, 200)
	for i := 0; i < 300; i++ {
		if got, want := s.has(i), i >= 3 && i < 200; got != want {
			t.Fatalf("has(%d) = %v, want %v", i, got, want)
		}
	}
	s.clear(64)
	if s.has(64) || !s.has(63) || !s.has(65) {
		t.Fatal("clear touched the wrong bit")
	}
	if s.has(-1) || s.has(1<<20) {
		t.Fatal("out-of-range offsets must read as not literal")
	}
}

// PEP 701 (Python 3.12) lets a replacement field hold any expression, including a string in the
// f-string's own quote; PEP 750 (3.14) gives t-strings the same grammar. The f-string is still
// literal as a whole, so every byte up to its real closing quote must be literal and the code after
// it must not be.
func TestLexPythonPEP701FStrings(t *testing.T) {
	content := strings.Join([]string{
		`a = f"{os.environ.get("DSN", "same_quote_inner")}" + after_a`,
		`b = f'{cfg['single_same']}' + after_b`,
		`c = f"{x:{"spec_nested"}}" + after_c`,
		`d = f"{f"{y}" + "nested_f_inner"}" + after_d`,
		`e = t"{d["tstring_inner"]}" + after_e`,
		`g = f"""{x + """`,
		`triple_in_triple`,
		`"""}""" + after_g`,
		`h = rf'(\{{)(raw_brace_text)' + after_h`,
		`i = f"{n:#x} {m:'>10} fmt_tail" + after_i`,
		`j = f"{{literal_brace}} {k!r:{w}} esc_tail" + after_j`,
		`k = f"{ {'a': 1}['a'] } dict_tail" + after_k`,
		`l = f"{x[1:2]} slice_tail" + after_l`,
		`m = f"{{ open_esc" + after_m`,
		`o = f"{d[1:len("slice_same")]} slice_same_tail" + after_o`,
		// The 3.12 "What's New" example: a single-quoted f-string whose field spans lines and holds
		// comments. Ending the f-string at its first inner quote fails this file open on main's lexer.
		`p = f"playlist: {", ".join([`,
		`    'multi_line_field',  # field_comment`,
		`])} multi_tail" + after_p`,
		`q = f"{d['}']}" + f"{d["k"]} brace_in_inner_tail" + after_q`,
	}, "\n") + "\n"
	checkLex(t, langPython, content, []lexProbe{
		{"same_quote_inner", true}, {"after_a", false},
		{"single_same", true}, {"after_b", false},
		{"spec_nested", true}, {"after_c", false},
		{"nested_f_inner", true}, {"after_d", false},
		{`t"{d[`, true}, {"tstring_inner", true}, {"after_e", false},
		{"triple_in_triple", true}, {"after_g", false},
		{"raw_brace_text", true}, {"after_h", false},
		{"fmt_tail", true}, {"after_i", false},
		{"esc_tail", true}, {"after_j", false},
		{"dict_tail", true}, {"after_k", false},
		{"slice_tail", true}, {"after_l", false},
		{"open_esc", true}, {"after_m", false},
		{"slice_same\"", true}, {"slice_same_tail", true}, {"after_o", false},
		{"multi_line_field", true}, {"field_comment", true}, {"multi_tail", true}, {"after_p", false},
		{"brace_in_inner_tail", true}, {"after_q", false},
	})
}

// The JSX opener test is what separates langJS from langTS: in TypeScript `<T` at an expression
// start is a type parameter list or an assertion. Those bytes keep the TS gate active and fail a
// .js file open, and a .js comparison is never an opener.
func TestLexJSXOpenerOnlyInJavaScript(t *testing.T) {
	generics := strings.Join([]string{
		`export const parse = <T extends Schema>(s: T) => s;`,
		`const id = <T,>(x: T) => x;`,
		`const n = <number>value;`,
		`let token: Promise<AuthToken>;`,
	}, "\n") + "\n"
	if _, reason := lexLiterals(generics, langTS); reason != "" {
		t.Errorf("TypeScript generics and assertions failed the gate open: %q", reason)
	}
	if _, reason := lexLiterals(generics, langJS); reason != "JSX element in a JavaScript file" {
		t.Errorf("the same bytes in a .js file: reason %q, want the JSX fail-open", reason)
	}
	comparisons := strings.Join([]string{
		`for (let i = 0; i<n; i++) { if (a <b) {} }`,
		`const ok = total`,
		`  <limit && x.default <max;`,
		`const shifted = a << b, lt = (x) <y;`,
	}, "\n") + "\n"
	if _, reason := lexLiterals(comparisons, langJS); reason != "" {
		t.Errorf("JS comparisons failed the gate open: %q", reason)
	}
}

// In TypeScript a '!' straight after an operand is the postfix non-null assertion, which ends the
// operand, so a '/' after it is a division. Read as a regex opener, the '/' closed at the first '/'
// of a trailing comment and left the comment in code, with a clean end state. A prefix '!' still
// opens a regex, and in JavaScript, which has no postfix '!', nothing changes.
func TestLexTSNonNullAssertionEndsAnOperand(t *testing.T) {
	content := strings.Join([]string{
		`const pct = done! / total; // nonnull_ident_comment`,
		`const w = getX()! / 2; /* nonnull_call_block */ const after_call = 1;`,
		`const h = rows[0]!/2; // nonnull_index_comment`,
		`const ok = !/prefix_regex/.exec(s);`,
		`if (!/paren_regex/.exec(s)) { f(); }`,
		`const both = a&&!/and_regex/.exec(s);`,
		`function g(s: string) { return!/keyword_regex/.exec(s); }`,
		// After the ')' of an if/for/while/with header a '!' starts the body: a prefix '!'.
		`if (ok)!/"/.exec(s) && go(); // the "header_bang_comment`,
		// `default` begins an expression, so its '!' is a prefix too; a property named default
		// is an operand.
		`export default!/"/.exec(s); // the "default_bang_comment`,
		`const q = x.default! / 2; // prop_default_comment`,
	}, "\n") + "\n"
	checkLex(t, langTS, content, []lexProbe{
		{"nonnull_ident_comment", true},
		{"nonnull_call_block", true},
		{"after_call", false},
		{"nonnull_index_comment", true},
		{"prefix_regex", true},
		{"paren_regex", true},
		{"and_regex", true},
		{"keyword_regex", true},
		{"header_bang_comment", true},
		{"default_bang_comment", true},
		{"prop_default_comment", true},
	})
	// `export default` followed directly by a regex, in either language.
	for _, lang := range []sourceLanguage{langJS, langTS} {
		checkLex(t, lang, `export default /"default_regex/; // after "default_regex_comment`+"\n",
			[]lexProbe{{"default_regex", true}, {"default_regex_comment", true}})
	}
	// A '!' that is the file's first byte has no operand before it.
	checkLex(t, langTS, `!/"/.exec(s) && go(); // the "file_start_bang_comment`+"\n",
		[]lexProbe{{"file_start_bang_comment", true}})
	js := "const r = a! / b; // js_comment\n"
	if lit, reason := lexLiterals(js, langJS); reason != "" || !lit.has(strings.Index(js, "/ b")) {
		t.Errorf("JavaScript has no postfix '!': the '/' after it should still open a regex (reason %q)", reason)
	}
}

// The backtick-text subset of the literal set: the TEXT of a JS template (each segment, its
// interpolations excluded) and the body of a Go raw string. Everything else that is literal --
// quoted strings and their delimiters, string prefixes, comments, regex literals, heredocs -- is
// deliberately NOT in it: no unquoted-family capture can run into a quoted string's text, because
// the value class stops at the two ASCII quotes, and the breadth of this set is what decides the
// gate's cost (see sourceGate.tick).
func TestLexBacktickTextSet(t *testing.T) {
	cases := []struct {
		lang    sourceLanguage
		content string
		tick    []string // the first byte of each must be backtick text
		notTick []string // the first byte of each must not be
	}{
		{langJS, "const a = `in_tmpl ${in_code} tail_tmpl` + 'in_sq' + /in_regex/.source; // in_cmt\n",
			[]string{"in_tmpl", "tail_tmpl"},
			[]string{"`in_tmpl", "in_code", "in_sq", "in_regex", "// in_cmt"}},
		{langTS, "const a = `${lead_code} lead_tail` + \"in_dq\";\n",
			[]string{"lead_tail"}, []string{"`${lead_code}", "lead_code", "in_dq"}},
		{langGo, "var a = `in_raw` + \"in_dq\" /* in_block */\n",
			[]string{"in_raw"}, []string{"`in_raw", "in_dq", "in_block"}},
		{langPython, "x = f\"in_f {fld} more\" + b'in_b' # in_cmt\ny = \"\"\"in_triple\"\"\"\nz = `in_tick`\n",
			nil, []string{"in_f", "more", "in_b", "in_triple", "fld", "# in_cmt", "in_tick"}},
		{langHCL, "a = \"in_hcl ${in_interp} tail_hcl\"\nb = <<EOT\nin_heredoc\nEOT\n",
			nil, []string{"in_hcl", "tail_hcl", "in_interp", "in_heredoc"}},
	}
	for _, tc := range cases {
		lit, tick, reason := lexSource(tc.content, tc.lang)
		if reason != "" {
			t.Fatalf("%s failed open (%s) on %q", tc.lang, reason, tc.content)
		}
		for _, probe := range tc.tick {
			off := strings.Index(tc.content, probe)
			if off < 0 || !tick.has(off) || !lit.has(off) {
				t.Errorf("%s: %q should be backtick text (and literal) in %q", tc.lang, probe, tc.content)
			}
		}
		for _, probe := range tc.notTick {
			if off := strings.Index(tc.content, probe); off < 0 || tick.has(off) {
				t.Errorf("%s: %q should not be backtick text in %q", tc.lang, probe, tc.content)
			}
		}
	}
}

func TestLiteralSetHasAny(t *testing.T) {
	s := newLiteralSet(300)
	s.setRange(130, 131)
	for _, r := range []struct {
		from, to int
		want     bool
	}{{0, 130, false}, {0, 131, true}, {130, 131, true}, {131, 300, false}, {64, 200, true}, {-5, 1 << 20, true}, {200, 100, false}} {
		if got := s.hasAny(r.from, r.to); got != r.want {
			t.Errorf("hasAny(%d, %d) = %v, want %v", r.from, r.to, got, r.want)
		}
	}
}
