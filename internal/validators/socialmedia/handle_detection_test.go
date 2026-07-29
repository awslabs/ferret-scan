// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// configuredValidator returns a validator loaded from the SHIPPED config, which is
// the only way SOCIAL_MEDIA does anything: a bare NewValidator leaves
// patternsConfigured false and ValidateContent returns immediately.
//
// Loading the real config on purpose — these tests are about whether the shipped
// patterns work, so a hand-written pattern here would test nothing.
func configuredValidator(t *testing.T) *Validator {
	t.Helper()
	path := filepath.Join("..", "..", "..", "config.yaml")
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}
	v := NewValidator()
	v.Configure(cfg)
	if !v.patternsConfigured || len(v.compiledPatterns) == 0 {
		t.Fatalf("validator not configured from %s: patternsConfigured=%v compiled=%d",
			path, v.patternsConfigured, len(v.compiledPatterns))
	}
	return v
}

// TestBareHandlesAreDetected is the recall gate for the RE2 fix.
//
// The shipped twitter handle pattern used a PCRE lookbehind and lookahead, which
// Go's RE2 engine rejects. A pattern that fails to compile is SKIPPED and logged
// only under FERRET_DEBUG=1, so twitter loaded 2 of its 3 patterns and no bare
// @handle was ever reported — silently, on every document.
func TestBareHandlesAreDetected(t *testing.T) {
	v := configuredValidator(t)

	cases := []struct {
		name string
		line string
		want string
	}{
		{"prose", "Follow our team lead @sarah_devops on twitter for updates", "@sarah_devops"},
		{"labelled", "My handle is @jdoe_2024 and the account is active", "@jdoe_2024"},
		{"parenthetical", "Contact: @company_support (twitter handle)", "@company_support"},
		{"digits", "ping @ops_team_7 about the incident", "@ops_team_7"},
		{"start of line", "@release_bot posted the changelog", "@release_bot"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "notes.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("no findings for %q — the handle pattern is not matching. If the "+
					"config pattern was rewritten, check it compiles under RE2: a failed "+
					"pattern is skipped silently.\n  line: %q", tc.want, tc.line)
			}
			var found bool
			var got []string
			for _, m := range matches {
				got = append(got, m.Text)
				if strings.Contains(m.Text, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("findings %v do not include %q\n  line: %q", got, tc.want, tc.line)
			}
		})
	}
}

// TestHandleFalsePositivesStaySuppressed covers the constraints the PCRE lookahead
// used to express, which now live in isFalsePositiveHandle because RE2 cannot
// express them. Losing these would turn every email address into a "handle".
func TestHandleFalsePositivesStaySuppressed(t *testing.T) {
	v := configuredValidator(t)

	cases := []struct {
		name string
		line string
	}{
		{"email address", "email me at bob@example.com instead"},
		{"email in prose", "send it to alice.smith@corp.internal today"},
		{"federated address", "federated user @alice@mastodon.social posts often"},
		{"hyphenated domain", "contact@my-company.com is the alias"},
		{"code comment", "// @param handle is a code annotation"},
		{"block comment", "/* @author bob */"},
		{"leading underscore", "the @_private flag"},
		{"single char", "wildcard @a matches"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "code.go")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if strings.HasPrefix(m.Text, "@") || strings.Contains(m.Text, "@") {
					t.Errorf("reported %q as a social media handle on a line that carries "+
						"none: %q", m.Text, tc.line)
				}
			}
		})
	}
}

// TestHandleSurvivesURLOnSameLine is the code-comment-veto fix.
//
// The veto asked only whether the line contained "//" ANYWHERE, which is true of
// every line carrying a URL ("https://"). A handle in ordinary prose next to a
// link was therefore discarded. The marker now has to appear BEFORE the handle, and
// a "//" that is part of a URL scheme does not count at all.
func TestHandleSurvivesURLOnSameLine(t *testing.T) {
	v := configuredValidator(t)

	lines := []string{
		"Follow @maria_ops - details at https://example.com/team",
		"see s3://our-bucket/report and ping @data_eng",
		"docs at http://internal.example.com maintained by @docs_team",
	}

	for _, line := range lines {
		matches, err := v.ValidateContent(line, "README.md")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		var handles []string
		for _, m := range matches {
			if strings.HasPrefix(m.Text, "@") {
				handles = append(handles, m.Text)
			}
		}
		if len(handles) == 0 {
			t.Errorf("no handle reported on %q — a URL on the line must not veto an "+
				"unrelated handle (the \"//\" of a scheme is not a comment marker)", line)
		}
	}
}

// TestRealCommentStillVetoes is the other direction: the veto must keep working
// where it is correct, including on a line that ALSO contains a URL.
func TestRealCommentStillVetoes(t *testing.T) {
	v := configuredValidator(t)

	lines := []string{
		"// see https://example.com and ask @someone", // comment precedes both
		"code(); // @reviewer please check",           // trailing comment before handle
		"/* @author @maintainer */",                   // block comment
	}

	for _, line := range lines {
		matches, err := v.ValidateContent(line, "main.go")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range matches {
			if strings.HasPrefix(m.Text, "@") {
				t.Errorf("reported %q on a line where a comment marker precedes the "+
					"handle: %q", m.Text, line)
			}
		}
	}
}

// TestEarliestCommentMarker unit-tests the helper the veto depends on, including
// the URL-scheme exemption that is the entire point of it.
func TestEarliestCommentMarker(t *testing.T) {
	cases := []struct {
		line string
		want int
	}{
		{"// @param handle", 0},
		{"code(); // trailing comment", 8},
		{"follow @maria - see https://example.com/team", -1},
		{"see s3://bucket/key and @handle", -1},
		{"/* @author bob */", 0},
		{"x = 1 /* note */", 6},
		{"plain prose with @handle", -1},
		{"http://a and // real comment", 13},
		{"", -1},
		{"//", 0},
	}

	for _, tc := range cases {
		if got := earliestCommentMarker(tc.line); got != tc.want {
			t.Errorf("earliestCommentMarker(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}
