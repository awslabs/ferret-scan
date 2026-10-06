// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// #746: the assignment matcher is single-value, single-line and keyword-adjacent, and each of
// those properties hides real credentials. These tests pin the four shapes that follow, at the
// level the misses were measured: ValidateContent, with no confidence filter, because the
// complaint is that the value never reports at all rather than that it scores low.
//
// Every case here returned ZERO findings before list_and_sequence.go.

const (
	secretA = "Sup3rS3cretDbPass!"
	secretB = "AnotherS3cretValue99"
)

// reports returns the texts ValidateContent produces for content.
func reports(t *testing.T, content string) []string {
	t.Helper()
	v := NewValidator()
	matches, err := v.ValidateContent(content, "fixture.yaml")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Text)
	}
	return out
}

// containsAll reports whether got contains every want.
func containsAll(got []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Shape (d): the stem has to sit immediately before the delimiter, so a plural key name matched
// nothing at all. `tokens:` is how a collection of credentials is naturally named.
func TestPluralKeyNamesAreDetected(t *testing.T) {
	cases := []struct{ content, want string }{
		{"api_keys: " + secretA + "\n", secretA},
		{"tokens: " + secretA + "\n", secretA},
		{"secrets: " + secretA + "\n", secretA},
		{"passwords: " + secretA + "\n", secretA},
		{"credentials = " + secretA + "\n", secretA},
		// Quoted, both assignment and JSON/YAML forms.
		{"tokens = \"" + secretA + "\"\n", secretA},
		{"{\n  \"api_keys\": \"" + secretA + "\"\n}\n", secretA},
	}
	for _, tc := range cases {
		t.Run(strings.TrimSpace(tc.content), func(t *testing.T) {
			if got := reports(t, tc.content); !containsAll(got, tc.want) {
				t.Errorf("got %v, want a finding for %q — a plural key name matched no pattern "+
					"because the stem must be adjacent to the delimiter. See #746 shape (d).",
					got, tc.want)
			}
		})
	}
}

// Shape (b): a bracket or brace between the delimiter and the value escapes BOTH pattern sets --
// the unquoted class excludes `[`, `(` and `{` as a first character, and the quoted patterns
// require a quote immediately after the delimiter.
//
// The JSON array cases are the important ones: the value is QUOTED, so the author has marked it
// as a literal, and it was still invisible.
func TestBracketedCollectionsAreDetected(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"json array, one element", "{\n  \"api_keys\": [\"" + secretA + "\"]\n}\n", []string{secretA}},
		{"json array, two elements", "{\n  \"api_keys\": [\"" + secretA + "\", \"" + secretB + "\"]\n}\n", []string{secretA, secretB}},
		{"json array, spaced", "{\n  \"secrets\": [ \"" + secretA + "\" ]\n}\n", []string{secretA}},
		{"json nested object", "{\n  \"tokens\": {\"primary\": \"" + secretA + "\"}\n}\n", []string{secretA}},
		{"yaml inline sequence", "api_keys: [" + secretA + "]\n", []string{secretA}},
		{"parenthesized", "secret: (" + secretA + ")\n", []string{secretA}},
		{"braced", "secret: {" + secretA + "}\n", []string{secretA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reports(t, tc.content); !containsAll(got, tc.want...) {
				t.Errorf("got %v, want %v — a collection is unreachable from both pattern sets. "+
					"See #746 shape (b).", got, tc.want)
			}
		})
	}
}

// Shape (a): the capture class excludes `,` and `;`, and the pattern is anchored on the key, so
// nothing re-anchors past the separator and only the first element of a list reported.
func TestListTailElementsAreDetected(t *testing.T) {
	for _, content := range []string{
		"secret: " + secretA + "," + secretB + "\n",
		"secret: " + secretA + ";" + secretB + "\n",
		"password=" + secretA + "," + secretB + "\n",
	} {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			got := reports(t, content)
			if !containsAll(got, secretA, secretB) {
				t.Errorf("got %v, want both %q and %q — the capture stops at the separator and "+
					"nothing re-anchors, so a credential list reported only its head. "+
					"See #746 shape (a).", got, secretA, secretB)
			}
		})
	}
}

// Shape (c): a YAML block sequence puts the key and the values on different lines, so no line
// carries both and the per-line patterns have nothing to anchor on.
func TestBlockSequenceItemsAreDetected(t *testing.T) {
	t.Run("two unquoted items", func(t *testing.T) {
		got := reports(t, "api_keys:\n  - "+secretA+"\n  - "+secretB+"\n")
		if !containsAll(got, secretA, secretB) {
			t.Errorf("got %v, want both items. See #746 shape (c).", got)
		}
	})

	t.Run("quoted item", func(t *testing.T) {
		if got := reports(t, "api_keys:\n  - \""+secretA+"\"\n"); !containsAll(got, secretA) {
			t.Errorf("got %v, want %q", got, secretA)
		}
	})

	// The second item is the one that regressed while this was being built, and it is worth its
	// own case. A sequence item carries no keyword ON ITS LINE, so it originally scored as though
	// no key existed anywhere: secretA cleared the reporting threshold on its intrinsic character
	// classes alone and secretB did not, so one credential under a key reported and its sibling
	// silently vanished. The key is what makes both of them credentials, which is why
	// processScopedCandidates takes govKeyLine.
	t.Run("both items score off the governing key, not their own line", func(t *testing.T) {
		got := reports(t, "api_keys:\n  - "+secretB+"\n")
		if !containsAll(got, secretB) {
			t.Errorf("got %v, want %q — an item whose value has fewer character classes than its "+
				"sibling must still report, because the key on the earlier line is its context",
				got, secretB)
		}
	})

	// The sequence must END. A value under an unrelated later key is not a credential by
	// inheritance, and treating it as one would be a false positive of our own making.
	t.Run("sequence does not leak into a later key", func(t *testing.T) {
		content := "api_keys:\n  - " + secretA + "\nunrelated_field: plain\nother_list:\n  - " + secretB + "\n"
		got := reports(t, content)
		if !containsAll(got, secretA) {
			t.Errorf("got %v, want the governed item %q", got, secretA)
		}
		for _, g := range got {
			if g == secretB {
				t.Errorf("reported %q, which sits under other_list: — the sequence state must "+
					"reset at the first line that is not a deeper-indented item", secretB)
			}
		}
	})
}

// The false positives reaching into collections could have introduced, pinned so the trade is a
// decision rather than an accident.
//
// REDACTED, PLACEHOLDER and CHANGEME all clear plausibleUnquotedSecret -- long enough, and they
// carry an upper-case letter, which is all that filter asks -- and isObviousPlaceholder catches
// none of them. Before this change they were saved only by the leading-`[` exclusion, i.e. by the
// very gap shape (b) closes, so the veto had to be made explicit.
func TestCollectionsDoNotReportSentinels(t *testing.T) {
	for _, content := range []string{
		"api_key: [REDACTED]\n",
		"api_keys: [PLACEHOLDER]\n",
		"secret: (CHANGEME)\n",
		"tokens: [TODO1234]\n",
		"api_keys:\n  - REDACTED\n",
		"secret: " + secretA + ",PLACEHOLDER\n",
	} {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			for _, g := range reports(t, content) {
				if shoutySentinel.MatchString(g) {
					t.Errorf("reported the sentinel %q as a credential — reaching into a "+
						"collection must not trade a false negative for a false positive", g)
				}
			}
		})
	}
}

// Whitespace is NOT a list separator, deliberately. A value after a space is as likely to be
// prose or a trailing comment as a second credential, and guessing wrong there is how the
// unquoted path earned plausibleUnquotedSecret in the first place.
func TestWhitespaceIsNotAListSeparator(t *testing.T) {
	for _, content := range []string{
		"password: " + secretA + " see runbook\n",
		"password: " + secretA + " # rotate me\n",
	} {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			got := reports(t, content)
			if len(got) != 1 || got[0] != secretA {
				t.Errorf("got %v, want exactly [%q] — only the credential, not the words after it",
					got, secretA)
			}
		})
	}
}

// A key with no secret stem is unaffected in every new path. This establishes that the trigger is
// still the stem and not the collection shape, so a reader can tell which half to look at.
func TestNonSecretKeysAreUnaffected(t *testing.T) {
	for _, content := range []string{
		"items: " + secretA + "\n",
		"items: [" + secretA + "]\n",
		"{\n  \"items\": [\"" + secretA + "\"]\n}\n",
		"items:\n  - " + secretA + "\n",
	} {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			if got := reports(t, content); len(got) != 0 {
				t.Errorf("got %v, want none — no secret stem in the key", got)
			}
		})
	}
}

// splitListElements must return EVERY element, including the first.
//
// It originally skipped the first on the theory that a caller had already reported it. That is
// true for findListTailSecrets, which passes a string starting at the separator, and false for
// findCollectionSecrets, where the whole point is that nothing reported the collection -- so
// `api_keys: [<secret>]`, a single-element list, stayed missed. Pinned because the asymmetry is
// the kind of thing a later edit would re-introduce.
func TestSplitListElementsKeepsTheFirstElement(t *testing.T) {
	if got := splitListElements("onlyone"); len(got) != 1 {
		t.Errorf("splitListElements(%q) returned %d spans, want 1", "onlyone", len(got))
	}
	if got := splitListElements("a,b,c"); len(got) != 3 {
		t.Errorf("splitListElements(%q) returned %d spans, want 3", "a,b,c", len(got))
	}
	// A leading separator yields an empty first element, which is how findListTailSecrets gets
	// the "skip the head" behaviour without a flag.
	if got := splitListElements(",tail"); len(got) != 1 {
		t.Errorf("splitListElements(%q) returned %d spans, want 1 (the empty head drops out)",
			",tail", len(got))
	}
}

// The plural-keyword context fix, pinned separately from the matcher changes because it is a
// SCORING change and the two fail differently.
//
// lineHasKeyword's right-boundary rule rejected a trailing "s", so `tokens:` did not count as
// token context. Finding the candidate was therefore not enough: measured, `tokens =
// "<credential>"` scored 55 against the keyword path's threshold of 60 and was dropped, while
// `token = "<same credential>"` scored 97. `api_keys` escaped only by accident, because it also
// contains the standalone positive keyword "api".
func TestPluralKeywordsCountAsContext(t *testing.T) {
	present := []string{
		"tokens: x", "secrets: x", "passwords: x", "credentials: x", "api_keys: x",
		"TOKENS: x", "Secrets = x",
	}
	for _, line := range present {
		t.Run("present/"+line, func(t *testing.T) {
			if got := (&Validator{positiveKeywords: []string{"token", "secret", "password", "credential", "key"}}).lineHasAnyPositiveKeyword(line); got != lineKeywordPresent {
				t.Errorf("lineHasAnyPositiveKeyword(%q) = %v, want present — a plural names a "+
					"collection of exactly the thing the keyword names", line, got)
			}
		})
	}

	// The plural must END at a boundary. These merely BEGIN with a keyword and are different
	// words; counting them would re-introduce the over-matching the boundary rule prevents.
	absent := []string{"tokensize: x", "secretsmanager: x", "keystone: x"}
	for _, line := range absent {
		t.Run("absent/"+line, func(t *testing.T) {
			if got := (&Validator{positiveKeywords: []string{"token", "secret", "key"}}).lineHasAnyPositiveKeyword(line); got == lineKeywordPresent {
				t.Errorf("lineHasAnyPositiveKeyword(%q) = present, want absent — %q is a "+
					"different word that merely starts with a keyword", line, line)
			}
		})
	}
}

func TestIsPluralBoundary(t *testing.T) {
	cases := []struct {
		text string
		end  int
		want bool
	}{
		{"tokens", 5, true},     // "token" + s at end of string
		{"tokens:", 5, true},    // s followed by ':'
		{"tokens x", 5, true},   // s followed by space
		{"tokensize", 5, false}, // s followed by alnum
		{"token", 5, false},     // nothing at end
		{"tokenX", 5, false},    // not an s
		{"TOKENS:", 5, true},    // upper-case s
	}
	for _, tc := range cases {
		if got := isPluralBoundary(tc.text, tc.end); got != tc.want {
			t.Errorf("isPluralBoundary(%q, %d) = %v, want %v", tc.text, tc.end, got, tc.want)
		}
	}
}
