// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// #582, the half the two syntax vetoes cannot cover.
//
// Make and image digests are decidable by syntax. JSDoc (`@returns`, `@author`), CSS at-rules quoted
// in prose, JSON-LD, IRC, email and every future `@`-format are not, and a veto per format is a
// vocabulary that rots — an entry that names a table rather than a column, or a term that turns out
// to be ordinary English, reads like a working guard while matching nothing or everything.
//
// So those are DEMOTED, not suppressed, and that choice is the safe direction here:
// dual_path_bridge.clampToCeiling states "a demoted finding is still reported and still redacted".
// Verified end to end rather than trusted: a demoted handle in a roster file is still masked in the
// redacted output even under `--confidence high`.
//
// Measured on 261 real JS/CSS/Dockerfile/Makefile files that actually contain bare `@tokens`:
// HIGH findings fall 1,329 -> 117, a 91% reduction, while the number of DISTINCT values reported
// stays at 75 before and after — nothing is lost, only demoted.

func ceilingOf(m *detector.Match) (float64, bool) {
	if m == nil || m.Metadata == nil {
		return 0, false
	}
	v, ok := m.Metadata[validators.ConfidenceCeilingKey].(float64)
	return v, ok
}

func matchWith(text string) *detector.Match {
	return &detector.Match{Text: text, Metadata: map[string]any{}}
}

// TestABareUncorroboratedHandleIsCapped is the must-demote half.
func TestABareUncorroboratedHandleIsCapped(t *testing.T) {
	for _, token := range []string{"@echo", "@returns", "@media", "@author", "@type", "@awscloud"} {
		m := matchWith(token)
		applyBareHandleCeiling(m, detector.ContextInfo{FullLine: token + " something"}, false)
		got, ok := ceilingOf(m)
		if !ok {
			t.Errorf("%s: no ceiling declared", token)
			continue
		}
		if got >= 60 {
			t.Errorf("%s: ceiling %.0f is not inside the LOW band, so --confidence high,medium "+
				"would still show it", token, got)
		}
	}
}

// TestAProfileURLIsNeverCapped: a URL carries the platform in the value itself, so it needs no
// corroboration. This is the distinction the whole change rests on.
//
// The URLs below are deliberately for platforms whose NAME is not in socialCorroboration. A first
// version of this test used twitter.com URLs and was VACUOUS — proved by mutation: deleting the
// isBareHandle guard entirely left it passing, because "twitter.com" contains "twitter", so the
// corroboration check returned early and the guard under test was never reached. A URL that
// self-corroborates cannot test a rule about URLs.
func TestAProfileURLIsNeverCapped(t *testing.T) {
	for _, v := range []string{
		"https://linkedin.com/in/someone",
		"https://github.com/someone",
		"https://facebook.com/someone",
		"https://youtube.com/channel/abc123",
		"https://tiktok.com/@someone",
	} {
		for _, kw := range socialCorroboration {
			if strings.Contains(strings.ToLower(v), kw) {
				t.Fatalf("fixture error: %q contains the corroboration word %q, so this case would "+
					"pass without exercising the URL rule at all", v, kw)
			}
		}
		m := matchWith(v)
		applyBareHandleCeiling(m, detector.ContextInfo{FullLine: v}, false)
		if got, ok := ceilingOf(m); ok {
			t.Errorf("%s: capped at %.0f, but a profile URL is self-identifying", v, got)
		}
	}
}

// TestCorroborationLiftsTheCap covers both scopes: the token's own line, and anywhere in the document.
func TestCorroborationLiftsTheCap(t *testing.T) {
	t.Run("same line", func(t *testing.T) {
		m := matchWith("@awscloud")
		applyBareHandleCeiling(m, detector.ContextInfo{FullLine: "Follow @awscloud on Twitter"}, false)
		if _, ok := ceilingOf(m); ok {
			t.Error("capped despite social context on the same line")
		}
	})

	t.Run("document scope, heading above", func(t *testing.T) {
		// The shape that motivated document scoping. ContextInfo here carries only the match's own
		// line, so a heading one line up is invisible to the line-scoped check — and this artifact,
		// a one-handle-per-line mentions export, is precisely what handle_syntax.go records two
		// leaks defending.
		m := matchWith("@schneems")
		applyBareHandleCeiling(m, detector.ContextInfo{FullLine: "@schneems"}, true)
		if got, ok := ceilingOf(m); ok {
			t.Errorf("capped at %.0f despite document-level corroboration", got)
		}
	})
}

// TestDocumentCorroborationReadsTheWholeDocument pins the predicate itself, including the case that
// makes the widening safe.
func TestDocumentCorroborationReadsTheWholeDocument(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"heading above the handles", "Twitter mentions export\n@schneems\n@tleish\n", true},
		{"heading below the handles", "@schneems\n@tleish\nTwitter mentions export\n", true},
		{"follow verb anywhere", "changelog\n\nplease follow us\n@jack\n", true},
		{"case insensitive", "TWITTER EXPORT\n@jack\n", true},
		// The case that makes document scope safe rather than reckless: a Makefile says nothing
		// social, so widening the scope leaves every one of its tokens demoted. Verified on the
		// real file — this repository's Makefile contains zero corroboration words.
		{"a makefile says nothing social", "build:\n\t@echo hello\n\t@go build ./...\n", false},
		{"a stylesheet says nothing social", "@media screen {\n  .a { color: red }\n}\n", false},
		{"jsdoc says nothing social", "/**\n * @returns {string}\n * @author someone\n */\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := documentHasSocialCorroboration(tc.content); got != tc.want {
				t.Errorf("documentHasSocialCorroboration = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsBareHandleDistinguishesValueShapes pins the URL/handle split on the VALUE, not on which
// configured pattern happened to match — a config can reorder its patterns.
func TestIsBareHandleDistinguishesValueShapes(t *testing.T) {
	for _, v := range []string{"@jack", "@awscloud", "@echo"} {
		if !isBareHandle(v) {
			t.Errorf("isBareHandle(%q) = false, want true", v)
		}
	}
	for _, v := range []string{
		"https://twitter.com/awscloud", "twitter.com/awscloud",
		"@sha256:abc", "jack", "",
	} {
		if isBareHandle(v) {
			t.Errorf("isBareHandle(%q) = true, want false", v)
		}
	}
}

// TestTheCeilingIsDeclaredNotApplied is the mechanism test, and it is not pedantry.
//
// A validator that clamps its own Confidence has no way to make the bound stick: the +20 context
// adjustment and the cross-path correlation boost are both added downstream. Measured elsewhere in
// this tree, a value a validator scored 55 was reported at 80 once those had run. So the contract is
// that the ceiling arrives as metadata for the bridge to apply, and a change that "simplified" this
// into a direct assignment would silently stop working.
func TestTheCeilingIsDeclaredNotApplied(t *testing.T) {
	m := matchWith("@echo")
	m.Confidence = 100
	applyBareHandleCeiling(m, detector.ContextInfo{FullLine: "\t@echo hello"}, false)

	if m.Confidence != 100 {
		t.Errorf("Confidence was mutated to %.0f; the ceiling must be declared as metadata so the "+
			"bridge can apply it after every boost", m.Confidence)
	}
	if _, ok := ceilingOf(m); !ok {
		t.Error("no ceiling metadata declared")
	}
	if !strings.Contains(validators.ConfidenceCeilingKey, "ceiling") {
		t.Errorf("unexpected key %q", validators.ConfidenceCeilingKey)
	}
}
