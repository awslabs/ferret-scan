// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"

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
		{"`head_text", false}, // has ${ : its OPENING backtick counts as code
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
		"a.js": langJS, "a.mjs": langJS, "a.cjs": langJS, "a.ts": langJS, "a.mts": langJS,
		"a.cts": langJS, "types.d.ts": langJS,
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
