// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package changelogfrag

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The headings are a contract with every fragment already written, so they are pinned byte for
// byte, in order, including the variation selector after ⚠ and its absence after 🛠.
func TestHeadingsAreTheCanonicalList(t *testing.T) {
	want := []string{
		"### \u26a0\ufe0f Breaking Changes",
		"### \U0001f512 Security",
		"### \U0001f680 Features",
		"### \U0001f41b Bug Fixes",
		"### \u26a1 Performance",
		"### \U0001f4da Documentation",
		"### \U0001f6e0 Build System",
		"### \U0001f4e6 Code Refactoring",
		"### \u2705 Tests",
		"### \U0001f528 Internal",
	}
	if !reflect.DeepEqual(Headings, want) {
		t.Fatalf("Headings = %q\nwant      %q", Headings, want)
	}
	for i, h := range want {
		if HeadingIndex(h) != i {
			t.Errorf("HeadingIndex(%q) = %d, want %d", h, HeadingIndex(h), i)
		}
	}
	for _, h := range []string{"### Bug Fixes", "### ✨ New Features", "### Pull Requests", "## 🐛 Bug Fixes",
		"### 🐛 Bug Fixes ", "### \u26a0 Breaking Changes"} {
		if HeadingIndex(h) != -1 {
			t.Errorf("HeadingIndex(%q) accepted a non-canonical heading", h)
		}
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"0800-otp-lowercase-word-not-base32.md": true,
		"0821-changelog-fragments.md":           true,
		"0799-build-go-1-27-3.md":               true,
		"1234-x.md":                             true,
		"README.md":                             false, // the directory's one non-fragment file
		"800-short-number.md":                   false,
		"00800-five-digits.md":                  false,
		"0800-Upper-Case.md":                    false,
		"0800-double--hyphen.md":                false,
		"0800-trailing-.md":                     false,
		"0800_underscore.md":                    false,
		"0800-no-extension":                     false,
		"0800-wrong.markdown":                   false,
		"0800-.md":                              false,
		"0800-x.md.swp":                         false,
		".0800-x.md":                            false,
		"0800-x.MD":                             false,
		"٠٨٠٠-arabic-digits.md":                 false, // \d is ASCII only in RE2
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseFragmentAcceptsTheFormat(t *testing.T) {
	const content = "### 🐛 Bug Fixes\n\n" +
		"- **x (shape):** first line\n  continuation, `code` and 3.97x\n    deeper indentation is kept too\n" +
		"- **y:** second bullet, back to back\n"
	sec, err := ParseFragment([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	want := Section{Heading: "### 🐛 Bug Fixes", Bullets: []Bullet{
		{"- **x (shape):** first line", "  continuation, `code` and 3.97x", "    deeper indentation is kept too"},
		{"- **y:** second bullet, back to back"},
	}}
	if !reflect.DeepEqual(sec, want) {
		t.Fatalf("got %#v\nwant %#v", sec, want)
	}
	// Byte preservation starts here: the bullets hold every content line after the blank one.
	var lines []string
	for _, b := range sec.Bullets {
		lines = append(lines, b...)
	}
	if got := sec.Heading + "\n\n" + strings.Join(lines, "\n") + "\n"; got != content {
		t.Fatalf("parsed lines do not reassemble the file:\n%q\n%q", got, content)
	}
}

func TestParseFragmentRejects(t *testing.T) {
	const h = "### 🐛 Bug Fixes"
	for _, tc := range []struct {
		name    string
		content string
		line    int
		msg     string
	}{
		{"empty file", "", 0, "empty"},
		{"no final newline", h + "\n\n- x", 0, "must end with a newline"},
		{"blank line at the end", h + "\n\n- x\n\n", 4, "single newline"},
		{"non-canonical heading", "### Bug Fixes\n\n- x\n", 1, "not one of the canonical headings"},
		{"a release-section heading", "## [v1.0.0] - 2026-01-01\n\n- x\n", 1, "not one of the canonical headings"},
		{"text before the first heading", "Fixes:\n" + h + "\n\n- x\n", 1, "comes before any heading"},
		{"a blank line before the heading", "\n" + h + "\n\n- x\n", 1, "blank line before the heading"},
		{"no bullet", h + "\n", 1, "has no bullet"},
		{"no bullet after the blank line", h + "\n\n", 1, "has no bullet"},
		{"no blank line after the heading", h + "\n- x\n", 2, "followed by one blank line"},
		{"two blank lines after the heading", h + "\n\n\n- x\n", 3, "not more"},
		{"prose instead of a bullet", h + "\n\nFixed a thing.\n", 3, "must be a bullet"},
		{"an asterisk bullet", h + "\n\n* x\n", 3, "must be a bullet"},
		{"an empty bullet first", h + "\n\n- \n", 3, "empty bullet"},
		{"an empty bullet later", h + "\n\n- x\n-\n", 4, "empty bullet"},
		{"a blank line inside a bullet", h + "\n\n- x\n\n  continuation\n", 4, "blank line inside the bullet list"},
		{"a blank line between bullets", h + "\n\n- x\n\n- y\n", 4, "blank line inside the bullet list"},
		{"a one-space continuation", h + "\n\n- x\n continuation\n", 4, "neither a bullet"},
		{"a tab continuation", h + "\n\n- x\n\tcontinuation\n", 4, "neither a bullet"},
		{"a whitespace-only line", h + "\n\n- x\n  \n", 4, "only whitespace"},
		{"a second heading", h + "\n\n- x\n\n### 🔒 Security\n\n- y\n", 5, "second heading"},
		{"a second heading with no blank line", h + "\n\n- x\n### 🔒 Security\n", 4, "second heading"},
		{"text after the bullets", h + "\n\n- x\n\nThanks!\n", 5, "nothing else goes in a fragment"},
		{"CRLF line endings", h + "\r\n\r\n- x\r\n", 1, "carriage return"},
		{"a byte-order mark", "\ufeff" + h + "\n\n- x\n", 1, "byte-order mark"},
		{"not UTF-8", h + "\n\n- \xff\n", 0, "UTF-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFragment([]byte(tc.content))
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("accepted (err=%v); want a rejection at line %d mentioning %q", err, tc.line, tc.msg)
			}
			if e.Line != tc.line || !strings.Contains(e.Msg, tc.msg) {
				t.Errorf("got %q (line %d); want line %d mentioning %q", e.Msg, e.Line, tc.line, tc.msg)
			}
		})
	}
}

func TestParseSectionsReadsOldStyleEntries(t *testing.T) {
	lines := []string{
		"### 🐛 Bug Fixes", // file line 17
		"",
		"- **a:** one",
		"  two",
		"- **b:** three",
		"",
		"",
		"### 🔒 Security",
		"",
		"- **c:** four",
		"",
	}
	secs, err := ParseSections(lines, 17)
	if err != nil {
		t.Fatal(err)
	}
	want := []Section{
		{Heading: "### 🐛 Bug Fixes", Bullets: []Bullet{{"- **a:** one", "  two"}, {"- **b:** three"}}},
		{Heading: "### 🔒 Security", Bullets: []Bullet{{"- **c:** four"}}},
	}
	if !reflect.DeepEqual(secs, want) {
		t.Fatalf("got %#v\nwant %#v", secs, want)
	}

	// The same grammar inside a section, and errors name the CHANGELOG.md line.
	_, err = ParseSections([]string{"### 🐛 Bug Fixes", "", "- a", "", "- b"}, 17)
	var e *Error
	if !errors.As(err, &e) || e.Line != 20 || !strings.Contains(e.Msg, "blank line inside the bullet list") {
		t.Fatalf("blank line between old-style bullets: got %v, want line 20", err)
	}
	_, err = ParseSections([]string{"### ✨ New Features", "", "- a"}, 17)
	if !errors.As(err, &e) || e.Line != 17 || !strings.Contains(e.Msg, "canonical") {
		t.Fatalf("non-canonical old-style heading: got %v, want line 17", err)
	}
	_, err = ParseSections([]string{"- a stray bullet with no heading"}, 17)
	if !errors.As(err, &e) || e.Line != 17 {
		t.Fatalf("stray bullet: got %v, want a rejection at line 17", err)
	}
	_, err = ParseSections([]string{"### 🐛 Bug Fixes", "", "- a", "", "A closing remark."}, 17)
	if !errors.As(err, &e) || e.Line != 21 || !strings.Contains(e.Msg, "headings and bullets only") {
		t.Fatalf("prose after old-style bullets: got %v, want line 21", err)
	}
}

func TestEntryShaped(t *testing.T) {
	for l, want := range map[string]bool{
		"### 🐛 Bug Fixes":                    true,
		"#### deeper":                        true,
		"- **x:** a bullet":                  true,
		"-":                                  true,
		"* bullet":                           true,
		"+ bullet":                           true,
		"1. numbered":                        true,
		"12) numbered":                       true,
		"  continuation":                     true,
		"\tindented":                         true,
		"":                                   false,
		"   ":                                false, // whitespace only
		"Entries for the next release live":  false, // the pointer paragraph is prose
		"are rendered here. `make x` shows.": false,
		"> a blockquote":                     false,
		"<a name=\"unreleased\"></a>":        false,
		"---":                                false,
		"-x":                                 false,
		"2026 was a year":                    false,
		"1.5x faster":                        false,
	} {
		if got := EntryShaped(l); got != want {
			t.Errorf("EntryShaped(%q) = %v, want %v", l, got, want)
		}
	}
}

func TestFindUnreleased(t *testing.T) {
	pointer := []string{
		"# Changelog", // 0
		"",
		"## [Unreleased]", // 2
		"",
		"Entries live in changelog.d/.", // 4
		"",
		"## [v1.0.0] - 2026-01-01", // 6
		"",
		"- old",
	}
	u, err := FindUnreleased(pointer)
	if err != nil || u != (Unreleased{Heading: 2, LegacyStart: 6, End: 6}) {
		t.Fatalf("pointer only: %+v, %v", u, err)
	}

	legacy := []string{"## [Unreleased]", "", "Prose.", "", "### 🐛 Bug Fixes", "", "- a", "", "## [v1.0.0] - x"}
	u, err = FindUnreleased(legacy)
	if err != nil || u != (Unreleased{Heading: 0, LegacyStart: 4, End: 8}) {
		t.Fatalf("pointer and old-style entries: %+v, %v", u, err)
	}
	if secs, err := Legacy(legacy, u); err != nil || len(secs) != 1 || secs[0].Bullets[0][0] != "- a" {
		t.Fatalf("Legacy: %v, %v", secs, err)
	}

	atEOF := []string{"## [Unreleased]", "", "### 🔨 Internal", "", "- a"}
	if u, err = FindUnreleased(atEOF); err != nil || u != (Unreleased{Heading: 0, LegacyStart: 2, End: 5}) {
		t.Fatalf("block at the end of the file: %+v, %v", u, err)
	}

	if _, err := FindUnreleased([]string{"# Changelog", "", "## [v1.0.0] - x"}); !errors.Is(err, ErrNoAnchor) {
		t.Errorf("missing anchor: %v", err)
	}
	// The anchor matches exactly, as the promotion script's `^## \[Unreleased\]$` does.
	for _, near := range []string{"## [Unreleased] ", "## [unreleased]", "##  [Unreleased]", "## [Unreleased]\r"} {
		if _, err := FindUnreleased([]string{near, "", "## [v1.0.0] - x"}); !errors.Is(err, ErrNoAnchor) {
			t.Errorf("%q accepted as the anchor: %v", near, err)
		}
	}
	if _, err := FindUnreleased([]string{"## [Unreleased]", "", "## [Unreleased]", ""}); err == nil || !strings.Contains(err.Error(), "two") {
		t.Errorf("two anchors: %v", err)
	}
	// The inserted heading must never run into the text above it.
	for name, lines := range map[string][]string{
		"heading directly above the next release": {"## [Unreleased]", "## [v1.0.0] - x"},
		"prose directly above the next release":   {"## [Unreleased]", "", "Prose.", "## [v1.0.0] - x"},
		"prose directly above an old entry":       {"## [Unreleased]", "", "Prose.", "### 🐛 Bug Fixes", "", "- a"},
		"heading at the very end of the file":     {"# C", "## [Unreleased]"},
	} {
		if _, err := FindUnreleased(lines); err == nil || errors.Is(err, ErrNoAnchor) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}
