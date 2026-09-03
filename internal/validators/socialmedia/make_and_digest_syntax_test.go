// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"
)

// #582: `@echo` reported as a TWITTER handle at 100% confidence, HIGH.
//
// Measured on real files, not fixtures. Ten real Makefiles — nine third-party from /Library,
// /Applications and unrelated projects, plus this repository's — carry 797 tab-indented `@` recipe
// lines between them and produced 736 findings, 511 of them HIGH. All are false positives.
//
// These two rules are VETOES, and vetoes in this package have a bad history: handle_syntax.go records
// two cleartext leaks from an over-broad one. The reason these are safe where the CSS rule was not is
// that they key on SYNTAX rather than on a word. A CSS at-rule name can also be somebody's account
// (`@media` is a plausible handle), so a name-based rule is inherently probabilistic. A Make recipe
// prefix is a POSITION in Make's grammar — the token after the tab is the command Make executes, so a
// handle cannot occupy it in a working Makefile. An image digest is followed by a colon, which the
// handle pattern cannot contain at all.

// TestMakeRecipePrefixIsVetoed covers the shapes real Makefiles actually use.
func TestMakeRecipePrefixIsVetoed(t *testing.T) {
	for _, tc := range []struct{ name, line, token, file string }{
		{"plain recipe", "\t@echo hello", "@echo", "Makefile"},
		{"the commonest token by far", "\t@echo \"Building...\"", "@echo", "Makefile"},
		{"silenced conditional", "\t@if [ -f x ]; then true; fi", "@if", "Makefile"},
		{"go invocation", "\t@go build ./...", "@go", "Makefile"},
		{"prefix chars before the at", "\t-@rm -f x", "@rm", "Makefile"},
		{"plus prefix", "\t+@make sub", "@make", "Makefile"},
		{"tab then space", "\t @echo x", "@echo", "Makefile"},
		{"uppercase variable command", "\t@GOOS=linux go build", "@GOOS", "Makefile"},
		{"GNUmakefile", "\t@echo x", "@echo", "GNUmakefile"},
		{"included fragment", "\t@echo x", "@echo", "build/rules.mk"},
		{"full path", "\t@echo x", "@echo", "/home/u/proj/Makefile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.Index(tc.line, tc.token)
			if s < 0 {
				t.Fatalf("fixture error: %q not in %q", tc.token, tc.line)
			}
			if !isSyntaxNotAHandle(tc.line, tc.token, tc.file, s, s+len(tc.token)) {
				t.Errorf("not vetoed: %q at %d in %q (file %q)", tc.token, s, tc.line, tc.file)
			}
		})
	}
}

// TestAHandleOnARecipeLineSurvives is the must-NOT-veto half, and it is the whole safety argument.
//
// Every case places the handle exactly where the rule acts — on a tab-indented line in a file named
// Makefile — because a test that puts it anywhere else is disjoint from the failure region by
// construction. That mistake is on the record in this package: an earlier must-not-veto test placed
// every handle mid-line, where neither rule could fire, and a leaking rule passed it green.
func TestAHandleOnARecipeLineSurvives(t *testing.T) {
	for _, tc := range []struct{ name, line, token, file string }{
		// The case that matters most: the command is vetoed, the handle beside it is not.
		{"handle as a recipe argument", "\t@echo \"Follow @awscloud on Twitter\"", "@awscloud", "Makefile"},
		{"handle in a recipe comment", "\t# ping @awscloud about this", "@awscloud", "Makefile"},
		// Not a recipe line: Make requires a TAB. A space-indented line is not a recipe, and this is
		// the only thing standing between a real handle and a veto — verified by mutation: removing
		// the tab check makes this case report nothing.
		{"space indented, not a recipe", "  @awscloud", "@awscloud", "Makefile"},
		{"four spaces", "    @awscloud", "@awscloud", "Makefile"},
		{"column zero", "@awscloud", "@awscloud", "Makefile"},
		// Same position, but not a makefile. The filename is the second signal.
		{"tab position in a text file", "\t@awscloud", "@awscloud", "notes.txt"},
		{"tab position in a yaml file", "\t@awscloud", "@awscloud", "config.yaml"},
		{"a file merely containing the word", "\t@echo x", "@echo", "MakefileNotes.md"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.Index(tc.line, tc.token)
			if s < 0 {
				t.Fatalf("fixture error: %q not in %q", tc.token, tc.line)
			}
			if isSyntaxNotAHandle(tc.line, tc.token, tc.file, s, s+len(tc.token)) {
				t.Errorf("VETOED a handle that must survive: %q at %d in %q (file %q) — a suppressed "+
					"finding never reaches the redactor, so this is a cleartext leak",
					tc.token, s, tc.line, tc.file)
			}
		})
	}
}

// TestImageDigestIsVetoedOnlyWhenItIsOne pins that the digest rule is categorical rather than a
// vocabulary match on the word "sha256".
//
// The distinction is load-bearing on real files: this repository's Dockerfile carries one genuine
// digest, and its THREAT_MODEL.md and CHANGELOG.md discuss digests in prose using `@sha256:<digest>`
// and `@sha256:...` placeholders. The real one must be vetoed and the prose must not.
func TestImageDigestIsVetoedOnlyWhenItIsOne(t *testing.T) {
	const realDigest = "3f6d04dc61331ee3c2fbbaad62d54412a84680f6a041d269a20a5270a078515b"

	for _, tc := range []struct {
		name, line string
		wantVeto   bool
	}{
		{"real 64-hex digest", "FROM golang:1.27.1-alpine@sha256:" + realDigest + " AS builder", true},
		{"32-hex is still a digest", "image@sha256:" + realDigest[:32], true},
		{"placeholder in prose", "pin FROM lines to `@sha256:<digest>`", false},
		{"ellipsis in prose", "the @sha256:... digest is what determines the image", false},
		{"bare mention with no colon", "we should use @sha256 pinning", false},
		{"colon but too few hex", "@sha256:3f6d04", false},
		{"colon then non-hex", "@sha256:not-a-digest-at-all", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.Index(tc.line, "@sha256")
			if s < 0 {
				t.Fatalf("fixture error: no @sha256 in %q", tc.line)
			}
			got := isSyntaxNotAHandle(tc.line, "@sha256", "probe.txt", s, s+len("@sha256"))
			if got != tc.wantVeto {
				t.Errorf("veto = %v, want %v for %q", got, tc.wantVeto, tc.line)
			}
		})
	}
}

// TestBothVetoSignalsAreRequired removes one signal at a time from a case that fires with both.
//
// Without this, a later edit could collapse either rule to a single signal and every case above
// would still pass: the must-veto cases have both signals and the must-not-veto cases have neither
// or one.
func TestBothVetoSignalsAreRequired(t *testing.T) {
	const line = "\t@echo hello"
	s := strings.Index(line, "@echo")

	if !isSyntaxNotAHandle(line, "@echo", "Makefile", s, s+5) {
		t.Fatal("control failed: the two-signal case does not fire, so the removals below prove nothing")
	}
	// Signal 2 removed: same position, not a makefile.
	if isSyntaxNotAHandle(line, "@echo", "notes.txt", s, s+5) {
		t.Error("position alone vetoed — the filename signal is not being read")
	}
	// Signal 1 removed: makefile, but not at the recipe-prefix position.
	const prose = "see @echo in the docs"
	ps := strings.Index(prose, "@echo")
	if isSyntaxNotAHandle(prose, "@echo", "Makefile", ps, ps+5) {
		t.Error("filename alone vetoed — the position signal is not being read")
	}
}
