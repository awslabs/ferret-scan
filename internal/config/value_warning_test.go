// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestInvalidRegexNamesThePCREConstruct covers every construct #903's acceptance list names, plus the
// other PCRE-only groups RE2 rejects. RE2's own message misleads for the commonest one: a lookbehind
// fails as "invalid named capture".
func TestInvalidRegexNamesThePCREConstruct(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
	}{
		{`(?<=Ticket ref: )ID-\d{6}`, []string{"invalid named capture", `"(?<=" is a PCRE lookbehind`, "no lookaround"}},
		{`(?<!\w)linkedin\.com`, []string{"invalid named capture", `"(?<!" is a PCRE negative lookbehind`}},
		{`ID-(?=\d)\d{6}`, []string{"invalid or unsupported Perl syntax", `"(?=" is a PCRE lookahead`}},
		{`https?://(?!public)git`, []string{`"(?!" is a PCRE negative lookahead`}},
		{`(?>abc)`, []string{`"(?>" is a PCRE atomic group`}},
		{`(?#note)abc`, []string{`"(?#" is a PCRE inline comment`}},
		{`(?|a|b)`, []string{`"(?|" is a PCRE branch reset`}},
		{`(?(1)a|b)`, []string{`"(?(" is a PCRE conditional`}},
		{`\d++`, []string{"invalid nested repetition operator", "possessive quantifier"}},
		{`a*+`, []string{"possessive quantifier"}},
		{`a{2}+`, []string{"possessive quantifier"}},
		{`(a)\1`, []string{"invalid escape sequence", "backreference"}},
		{`abc\Z`, []string{"invalid escape sequence", `"\Z"`, `"\z"`}},
		{`ID-[0-9{6}`, []string{"missing closing ]", `"[" character class is not closed`}},
		{`(abc`, []string{"missing closing )", `"(" group is not closed`}},
		{`abc)`, []string{"unexpected )", `")" has no matching "("`}},
		// (?i) is what the IP and social media validators prepend; the hint must survive it.
		{`(?i)(?<=x)y`, []string{`"(?<=" is a PCRE lookbehind`}},
	}
	for _, c := range cases {
		_, err := regexp.Compile(c.pattern)
		if err == nil {
			t.Fatalf("%q compiled; the case is wrong", c.pattern)
		}
		got := InvalidRegex(err)
		if !strings.HasPrefix(got, "not a valid RE2 regular expression: ") {
			t.Errorf("%q: %q lacks the fixed prefix", c.pattern, got)
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%q: %q lacks %q", c.pattern, got, w)
			}
		}
	}
}

// TestInvalidRegexQuotesNoPattern: RE2's error quotes the pattern from the offending construct to its
// end, and an internal_urls entry is an internal hostname. The warning goes to CI logs, so none of it is
// echoed; the path and index locate the value instead.
func TestInvalidRegexQuotesNoPattern(t *testing.T) {
	for _, p := range []string{
		`https?://(?<=x)wiki\.zz-secret-host\.test`,
		`https?://(?!public)wiki\.zz-secret-host\.test`,
		`https?://wiki\.zz-secret-host\.test[`,
		`(https?://wiki\.zz-secret-host\.test`,
		`https?://wiki\.zz-secret-host\.test\Z`,
		`https?://wiki\.zz-secret-host\.test{2,1}`,
	} {
		_, err := regexp.Compile(p)
		if err == nil {
			t.Fatalf("%q compiled", p)
		}
		if got := InvalidRegex(err); strings.Contains(got, "zz-secret-host") || strings.Contains(got, "wiki") {
			t.Errorf("the warning quotes the pattern: %q", got)
		}
	}
}

// TestRE2AcceptsTheSyntaxThatLooksLikePCRE: named groups in both spellings, inline flags and \b
// compile, so a check that flagged them would warn on a working pattern.
func TestRE2AcceptsTheSyntaxThatLooksLikePCRE(t *testing.T) {
	for _, p := range []string{`(?P<id>x)`, `(?<id>x)`, `(?i)x`, `\bx\b`, `\Ax\z`, `(?:x)`} {
		if _, err := regexp.Compile(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}

func TestNotABoolean(t *testing.T) {
	cases := []struct {
		got  any
		want string
	}{
		{"no", `got the string "no" (YAML 1.2 reads it as text`},
		{"off", `got the string "off"`},
		{"Yes", `got the string "Yes"`},
		{"on", `got the string "on"`},
		{"false", `got the string "false" (quoted`},
		{"TRUE", `got the string "TRUE" (quoted`},
		{"maybe", "expected true or false, got a string"},
		{0, "expected true or false, got a number"},
		{[]any{true}, "expected true or false, got a list"},
	}
	for _, c := range cases {
		if got := NotABoolean(c.got); !strings.Contains(got, c.want) {
			t.Errorf("NotABoolean(%#v) = %q, want it to contain %q", c.got, got, c.want)
		}
	}
	// A string that is not a boolean word is not echoed: it could be anything the user wrote.
	if got := NotABoolean("internal-host.zz"); strings.Contains(got, "internal-host") {
		t.Errorf("echoed an arbitrary string: %q", got)
	}
}

func TestWrongTypeNamesTheKindNotTheValue(t *testing.T) {
	cases := []struct {
		got  any
		want string
	}{
		{"https?://wiki\\.zz-secret-host\\.test", "got a string"},
		{7, "got a number"},
		{7.5, "got a number"},
		{true, "got a boolean"},
		{[]any{"a"}, "got a list"},
		{map[string]any{"a": 1}, "got a map"},
		{map[any]any{1: "a"}, "got a map with non-string keys"},
		{time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), "got a timestamp"},
		{nil, "got an empty value"},
	}
	for _, c := range cases {
		got := WrongType("a list of patterns", c.got)
		if !strings.HasPrefix(got, "expected a list of patterns, ") || !strings.HasSuffix(got, c.want) {
			t.Errorf("WrongType(%#v) = %q, want suffix %q", c.got, got, c.want)
		}
		if strings.Contains(got, "zz-secret-host") {
			t.Errorf("WrongType echoed the value: %q", got)
		}
	}
}

func TestValueWarningLine(t *testing.T) {
	w := NewValueWarning(ElementPath(ValidatorKeyPath("cloud_resources", "custom_patterns"), 1), "the problem", "the effect")
	if got, want := w.String(), "config value validators.cloud_resources.custom_patterns[1]: the problem — the effect"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if w.Path != "validators.cloud_resources.custom_patterns[1]" || w.Message != "the problem — the effect" {
		t.Errorf("fields = %+v", w)
	}
}
