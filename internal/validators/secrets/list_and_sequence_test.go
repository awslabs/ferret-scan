// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/base64"
	"math/rand"
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

// secretC is assembled at run time, the push-protection-safe way fixtures added since are built.
var secretC = buildTestToken("Third", "S3cret", "Value42x")

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
// It originally skipped the first on the theory that a caller had already reported it. That was
// true for findListTailSecrets, which passed a string starting at the separator, and false for
// findCollectionSecrets, where the whole point is that nothing reported the collection -- so
// `api_keys: [<secret>]`, a single-element list, stayed missed. Pinned because the asymmetry is
// the kind of thing a later edit would re-introduce. (findListTailSecrets no longer uses it: since
// #754 it walks the tail element by element; see appendListTail.)
func TestSplitListElementsKeepsTheFirstElement(t *testing.T) {
	if got := splitListElements("onlyone"); len(got) != 1 {
		t.Errorf("splitListElements(%q) returned %d spans, want 1", "onlyone", len(got))
	}
	if got := splitListElements("a,b,c"); len(got) != 3 {
		t.Errorf("splitListElements(%q) returned %d spans, want 3", "a,b,c", len(got))
	}
	// A leading separator yields an empty first element, which drops out rather than becoming a
	// zero-length span.
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

// #754: a list-tail element is a member only while it fits the head's own value grammar. These
// pin the three boundaries that grammar draws, each of which the first version of the walk got
// wrong, and the members it must keep.

// The element ends at the first byte the head's capture would not take. A closing quote is one:
// the first version split on separators only, so the last element of a list inside a string kept
// the string's closing quote and reported `<v2>"` -- HIGH, as a credential with a quote in it.
func TestListTailElementStopsAtTheHeadsValueClass(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"double-quoted string", "S = \"secret: " + secretA + "," + secretB + "\"\n"},
		{"single-quoted string", "S = 'password=" + secretA + ";" + secretB + "'\n"},
		{"trailing comment", "secret: " + secretA + "," + secretB + "#rotate\n"},
		{"trailing prose", "secret: " + secretA + "," + secretB + " see runbook\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reports(t, tc.content)
			if !containsAll(got, secretA, secretB) {
				t.Errorf("got %v, want both %q and %q exactly — the tail element must be cut at the "+
					"first byte outside the value class, not carry it", got, secretA, secretB)
			}
			for _, g := range got {
				if g != secretA && g != secretB {
					t.Errorf("reported %q — a tail element must not run past the value class "+
						"(a quote, '#' or whitespace ends it, and ends the tail)", g)
				}
			}
		})
	}
}

// A new `key=value` or `key: value` pair is the NEXT assignment, not a member of this list, so it
// ends the list -- and nothing after it belongs to the head either. The first version reported the
// pair itself, key and all, and every element after it.
func TestListTailEndsAtANewAssignment(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"key=value then a bare element", "secret: " + secretA + ",next_key=" + secretB + "," + secretC + "\n", []string{secretA}},
		{"key:value, no space", "password=" + secretA + ";mode:" + secretB + ";" + secretC + "\n", []string{secretA}},
		{"key: value, spaced", "secret: " + secretA + ",description: " + secretB + "\n", []string{secretA}},
		{"comparison", "secret: " + secretA + ",state==" + secretB + "\n", []string{secretA}},
		// A quote after `=` that OPENS a value is a pair, unlike the closing quote after padding.
		{"key=\"quoted value\"", "secret: " + secretA + ",mode_name=\"cors\"," + secretB + "\n", []string{secretA}},
		// The second pair is itself a head and reports through the ordinary pattern. The tail used
		// to report its `token=<v2>` element as well, so every assignment after the first was
		// reported twice, once with its key glued on.
		{"the next pair is another head", "token=" + secretA + ";token=" + secretB + "\n", []string{secretA, secretB}},
		// The stated cost of the rule. `root:<v2>` is shaped exactly like minified `expiresIn:n.x`,
		// and nothing in the bytes tells them apart. Measured, letting `key:value` without a space
		// through as a member returned 1,413 more JS/TS findings (1,309 HIGH), so a user:password
		// element after a head ends the list. Pinned so the trade stays a decision.
		{"user:password element reads as the next pair", "password=admin:" + secretA + ",root:" + secretB + "\n", []string{"admin:" + secretA}},
		// A command-line flag is a key too. As a member, `--password=<v2>` was reported a second time
		// with its key glued on, next to the <v2> the password head reports on its own.
		{"the next pair is a flag", "ARGS=--token=" + secretA + ",--password=" + secretB + "\n", []string{secretA, secretB}},
		{"the next pair is a single-dash flag", "token=" + secretA + ";-token=" + secretB + "\n", []string{secretA, secretB}},
		// Controls for the base64-padding reading (isBase64Padding). Each breaks exactly one of its
		// conditions, so each is still the next pair and ends the list.
		{"key with no upper-case letter", "secret: " + secretA + ",statements1= x\n", []string{secretA}},
		{"quoted pair, key with no upper-case letter", "secret: " + secretA + ",credentials=\"include\"\n", []string{secretA}},
		{"quote opening quoted content", "secret: " + secretA + ",mySecretKey=\"cors\"\n", []string{secretA}},
		{"key not a multiple of four long", "secret: " + secretA + ",Key2Name= cors\n", []string{secretA}},
		{"a value straight after the =", "secret: " + secretA + ",Ke1=" + secretB + "\n", []string{secretA}},
		{"spaced comparison", "secret: " + secretA + ",Abcdef123 == ok\n", []string{secretA}},
		{"strict equality", "secret: " + secretA + ",Abcdefg12=== ok\n", []string{secretA}},
		{"template literal assigned", "secret: " + secretA + ",nextKey=`" + secretB + "`\n", []string{secretA}},
		{"arrow function", "secret: " + secretA + ",onClick=>onClick.run(" + secretB + ")\n", []string{secretA}},
		{"spaced assignment", "secret: " + secretA + ",backupKey2 = " + secretB + "\n", []string{secretA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reports(t, tc.content)
			if !sameStrings(got, tc.want) {
				t.Errorf("got %v, want exactly %v — an element that opens a new key=value or "+
					"key: value pair ends the list, and nothing after it is a member", got, tc.want)
			}
		})
	}
}

// An element whose first byte the head pattern would not start a value with ends the list: the
// head never reports `password=$VAR`, `password=<placeholder>` or `password=[x]`, so a member shaped
// like that is not a literal either. v2.5.3 reported each of these as a credential.
func TestListTailEndsAtAnElementTheHeadCouldNotStart(t *testing.T) {
	for _, content := range []string{
		"secret: " + secretA + ",$OTHER_SECRET_VALUE," + secretB + "\n",
		// A `${NAME}` reference is passed over rather than ending the list (TestListTailKeepsRealMembers
		// pins the member after one), but it is never reported itself.
		"secret: " + secretA + ",${VAULT_SECRET_REF}\n",
		"secret: " + secretA + ",<placeholder-api-key>\n",
		"secret: " + secretA + ",[" + secretB + "]\n",
		"secret: " + secretA + ",(" + secretB + ")\n",
		"secret: " + secretA + ",{" + secretB + "}\n",
		// Only a bare `${NAME}` is passed over; anything more is not a reference this can read.
		"secret: " + secretA + ",${OLD_SECRET:-x}," + secretB + "\n",
		"secret: " + secretA + ",${OLD_SECRET}x," + secretB + "\n",
		"secret: " + secretA + ",${OLD_SECRET ," + secretB + "\n",
		// A quote that does not close as a member: a key, two words, a concatenation.
		"secret: " + secretA + ",\"" + secretB + "\":x\n",
		"secret: " + secretA + ",\"two words\"," + secretB + "\n",
		// Quoted or not, a new pair is the next assignment.
		"secret: " + secretA + ",\"next_key=" + secretB + "\"," + secretC + "\n",
		"secret: " + secretA + ",\"" + secretB + "\"+x," + secretC + "\n",
	} {
		t.Run(strings.TrimSpace(content), func(t *testing.T) {
			if got := reports(t, content); !sameStrings(got, []string{secretA}) {
				t.Errorf("got %v, want exactly [%q] — a member must start the way the head's value "+
					"does, and one that cannot ends the list", got, secretA)
			}
		})
	}
}

// The members the grammar must KEEP, so the stopping rules cannot be satisfied by stopping early.
func TestListTailKeepsRealMembers(t *testing.T) {
	padded := base64.StdEncoding.EncodeToString([]byte("list member, padded")) // ends in '='
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("fixture %q is not padded; it would not exercise the padding rule", padded)
	}
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		// A member that fits the grammar but is not reported -- a sentinel, a short token -- is
		// still a member: the walk passes over it rather than stopping.
		{"past a sentinel", "secret: " + secretA + ",PLACEHOLDER," + secretB + "\n", []string{secretA, secretB}},
		{"past a short element", "secret: " + secretA + ",ab," + secretB + "\n", []string{secretA, secretB}},
		// An empty element is the degenerate short one: a hole in the list, not its end. v2.5.3's
		// splitter dropped it and reported the member after it.
		{"past an empty element", "SECRET=" + secretA + ",," + secretB + "\n", []string{secretA, secretB}},
		{"past a blank element", "SECRET=" + secretA + ", ," + secretB + "\n", []string{secretA, secretB}},
		{"past an empty ;-element", "PASSWORD=" + secretA + ";;" + secretB + "\n", []string{secretA, secretB}},
		// Whitespace before a separator belongs to it, as whitespace after one does.
		{"space before the separator", "password: " + secretA + "," + secretB + " ," + secretC + "\n", []string{secretA, secretB, secretC}},
		{"tab before the separator", "password: " + secretA + "," + secretB + "\t;" + secretC + "\n", []string{secretA, secretB, secretC}},
		// A closed quoted member is a member, reported without its quotes as the quoted patterns
		// report `API_KEY="<v>"`. v2.5.3 reported it with them.
		{"double-quoted member", "API_KEY=" + secretA + ",\"" + secretB + "\"\n", []string{secretA, secretB}},
		{"single-quoted members, spaced", "secret: " + secretA + ", '" + secretB + "', '" + secretC + "'\n", []string{secretA, secretB, secretC}},
		{"quoted member before prose", "secret: " + secretA + ",\"" + secretB + "\" rotate\n", []string{secretA, secretB}},
		// A `${NAME}` reference is passed over, unreported, and the literal after it is reached.
		{"past a ${NAME} reference", "TOKEN=" + secretA + ",${OLD_TOKEN}," + secretB + "\n", []string{secretA, secretB}},
		{"past a spaced ${NAME} reference", "TOKEN=" + secretA + ", ${OLD_TOKEN} , " + secretB + "\n", []string{secretA, secretB}},
		// A leading dash with no assignment after it is still a value byte, not a flag.
		{"a dash-led member", "password=" + secretA + ",-" + secretB + "\n", []string{secretA, "-" + secretB}},
		{"three members", "password=" + secretA + ";" + secretB + ";" + secretC + "\n", []string{secretA, secretB, secretC}},
		// Spaces after the separator are skipped as the head skips them after its delimiter, so a
		// hand-written list keeps its members.
		{"space after the separator", "password: " + secretA + ", " + secretB + ",\t" + secretC + "\n", []string{secretA, secretB, secretC}},
		// base64 padding is an identifier-shaped run followed by '=', but nothing follows the
		// padding, so it is a value and not the next key.
		{"base64 padding is not a key", "secret: " + secretA + "," + padded + "\n", []string{secretA, padded}},
		{"base64 padding mid-list", "secret: " + secretA + "," + padded + "," + secretB + "\n", []string{secretA, padded, secretB}},
		// A CRLF file leaves `\r` at the end of every line, after the padding.
		{"base64 padding at the end of a CRLF line", "secret: " + secretA + "," + padded + "\r\n", []string{secretA, padded}},
		// The list inside a string: the padding is followed by the string's CLOSING quote, which
		// must not read as the opening quote of `key="value"`. v2.5.3 reported this one with the
		// quote attached.
		{"base64 padding before a closing quote", "S = \"secret: " + secretA + "," + padded + "\"\n", []string{secretA, padded}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reports(t, tc.content)
			if !sameStrings(got, tc.want) {
				t.Errorf("got %v, want exactly %v", got, tc.want)
			}
		})
	}
}

// A padded base64 member stays in the list whatever follows its padding on the line, and whether it
// stays must not depend on the value's own bytes. A padded value with no `+` or `/` is an
// identifier-shaped run followed by `=`, so startsListAssignment read `<P>== rotate` as the next
// `key == value` and dropped <P> -- left in cleartext under redaction -- while the same line with
// a `/` in the value kept it. That is about a fifth of `openssl rand -base64 32` keys and most
// base64url ones. Each shape runs both twins.
func TestListTailKeepsAPaddedMemberWhateverFollowsIt(t *testing.T) {
	ident := base64.StdEncoding.EncodeToString([]byte("list member, padded")) // letters and digits, then '='
	if strings.ContainsAny(ident, "+/") || !strings.HasSuffix(ident, "=") {
		t.Fatalf("fixture %q must be identifier-shaped and padded", ident)
	}
	slashed := ident[:6] + "/" + ident[7:]
	urlsafe := base64.URLEncoding.EncodeToString([]byte("url safe~~ member"))
	if !strings.HasSuffix(urlsafe, "=") || !strings.ContainsAny(urlsafe, "-_") {
		t.Fatalf("fixture %q must be padded base64url", urlsafe)
	}
	cases := []struct{ name, before, after string }{
		{"trailing prose", "secret: " + secretA + ",", " rotate quarterly"},
		// Value-class bytes that unicode.IsSpace admits: a space to a reader, and so the end of the
		// padding, though the head's ASCII \s would run on through them.
		{"no-break space, then prose", "secret: " + secretA + ",", "\u00a0rotate"},
		{"vertical tab, then prose", "secret: " + secretA + ",", "\vrotate"},
		{"tab column", "password=" + secretA + ",", "\tprod"},
		{"// comment", "token: " + secretA + ",", " // rotate"},
		{"next shell word", "ENV API_KEY=" + secretA + ",", " REGION=us-east-1"},
		{"shell command", "TOKEN=" + secretA + ",", " node app.js"},
		{"line continuation", "  --set auth.password=" + secretA + ",", " \\"},
		{"markdown table cell", "| prod | API_KEY=" + secretA + ",", " |"},
		{"closing backtick", "Set `API_KEY=" + secretA + ",", "` in the environment."},
		{"closing paren", "ARGS=(--token=" + secretA + ",", ")"},
		{"closing brace", "env: {password: " + secretA + ",", "}"},
		{"closing bracket", "args: [--token=" + secretA + ",", "]"},
		{"JSON-escaped newline", "{\"env\": \"TOKEN=" + secretA + ",", "\\nMODE=prod\"}"},
		{"closing tag", "<value>token=" + secretA + ",", "</value>"},
		{"next query parameter", "curl \"https://api.corp.net/v1?token=" + secretA + ",", "&page=2\""},
		{"shell pipe", "export TOKEN=" + secretA + ",", "|./run.sh"},
		{"attribute, then the tag ends", "<meta content=\"token=" + secretA + ",", "\">"},
		{"attribute, then the tag self-closes", "<add value=\"password=" + secretA + ";", "\"/>"},
		{"string, then concatenation", "x = \"token=" + secretA + ",", "\"+suffix;"},
		{"string, then a method call", "x = \"secret: " + secretA + ",", "\".split(\",\");"},
	}
	for _, tc := range cases {
		for _, v := range []struct{ shape, value string }{{"identifier-shaped", ident}, {"with-slash", slashed}, {"base64url", urlsafe}} {
			t.Run(tc.name+"/"+v.shape, func(t *testing.T) {
				got := reports(t, tc.before+v.value+tc.after+"\n")
				for _, g := range got {
					if strings.HasPrefix(g, v.value) {
						return
					}
				}
				t.Errorf("got %v, want a finding that starts with the padded member — padding "+
					"followed by %q was read as the next key", got, tc.after)
			})
		}
	}
}

// The whitespace v2.5.3 trimmed from each element -- strings.TrimSpace, so every rune
// unicode.IsSpace admits -- is still trimmed, so these members report the same text, and keep the
// same identity hash, as they did there. The walk skipped only spaces and tabs at first: a no-break
// space or \v after the separator joined the reported text (`\u00a0<v2>`), hid the element's
// first byte from the pair and first-byte rules (`\u00a0token=<v2>` and `\u00a0${REF}` reported),
// and \f after a separator ended the list.
func TestListTailTrimsTheWhitespaceV253Trimmed(t *testing.T) {
	for _, ws := range []struct{ name, s string }{
		{"no-break space", "\u00a0"}, {"vertical tab", "\v"}, {"em space", "\u2003"},
		{"ideographic space", "\u3000"}, {"next line", "\u0085"}, {"form feed", "\f"},
	} {
		for _, tc := range []struct {
			name, content string
			want          []string
		}{
			{"before a member", "secret: " + secretA + "," + ws.s + secretB + "\n", []string{secretA, secretB}},
			{"after a member", "secret: " + secretA + "," + secretB + ws.s + "\n", []string{secretA, secretB}},
			{"before a separator", "secret: " + secretA + "," + secretB + ws.s + "," + secretC + "\n", []string{secretA, secretB, secretC}},
			{"before the next pair", "token=" + secretA + ";" + ws.s + "token=" + secretB + "\n", []string{secretA, secretB}},
			{"before a reference", "secret: " + secretA + "," + ws.s + "${VAULT_SECRET_REF}\n", []string{secretA}},
		} {
			t.Run(ws.name+"/"+tc.name, func(t *testing.T) {
				if got := reports(t, tc.content); !sameStrings(got, tc.want) {
					t.Errorf("got %q, want exactly %q", got, tc.want)
				}
			})
		}
	}
}

// What the grammar still costs, pinned so each stays a decision.
func TestListTailStatedCosts(t *testing.T) {
	cases := []struct {
		name, content string
		want          []string
	}{
		// The space inside an annotated member is followed by `(`, not a separator, so it ends the
		// tail. The same rule is what cuts minified fragments at whitespace.
		{"an annotated member ends the list", "TOKEN=" + secretA + ", " + secretB + " (old), " + secretC + "\n", []string{secretA, secretB}},
		// `$` begins ordinary identifiers in minified JavaScript, so a bare `$NAME` is not passed
		// over the way `${NAME}` is.
		{"a bare $NAME ends the list", "TOKEN=" + secretA + ",$OLD_TOKEN," + secretB + "\n", []string{secretA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reports(t, tc.content); !sameStrings(got, tc.want) {
				t.Errorf("got %v, want exactly %v", got, tc.want)
			}
		})
	}
}

// A collection ends where the next collection's key begins, if no closing bracket comes first
// (#754). v2.5.3 gave a bracket that never closes the rest of the line as its region, so every
// later collection was part of it too, and the reported elements were the rest of the line.
func TestCollectionEndsAtTheNextCollectionsKey(t *testing.T) {
	cases := []struct {
		name, content string
		want          []string
	}{
		// v2.5.3: `<v1> token=[<v2>` and <v2>.
		{"unclosed, joined by spaces", "token=[" + secretA + " token=[" + secretB + "\n", []string{secretA, secretB}},
		// v2.5.3: <v1>, <v2> and `token=[<v2>`, key and bracket included.
		{"unclosed, joined by commas", "token=[" + secretA + ", token=[" + secretB + "\n", []string{secretA, secretB}},
		// v2.5.3: <v1>, <v2> and `token: [<v1>`.
		{"nested", "secrets: {token: [" + secretA + ", " + secretB + "]}\n", []string{secretA, secretB}},
		// The keyword is the tail of a longer key: the region stops before all of `client_secret`,
		// not at the `secret` the pattern matched.
		{"keyword inside a longer key", "token=[" + secretA + " client_secret: [" + secretB + "]\n", []string{secretA, secretB}},
		// One bracket opened by two keywords (access_token and token): scanned once, cut before
		// all of `access_token`.
		{"overlapping keywords", "token=[" + secretA + " access_token: [" + secretB + "]\n", []string{secretA, secretB}},
		// The next key is quoted: the region stops before its opening quote too.
		{"quoted next key", "token=[" + secretA + " \"client_secret\": [" + secretB + "]\n", []string{secretA, secretB}},
		// Controls: closed collections are untouched.
		{"closed, then another", "{\"api_keys\": [\"" + secretA + "\"], \"tokens\": [\"" + secretB + "\"]}\n", []string{secretA, secretB}},
		{"closed, one element", "api_keys: [" + secretA + "]\n", []string{secretA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reports(t, tc.content); !sameStrings(got, tc.want) {
				t.Errorf("got %q, want exactly %q", got, tc.want)
			}
		})
	}
}

// appendCollectionElements answers "does this element overlap a quoted span" with one forward
// cursor. Checked against the obvious all-pairs test, which was O(n^2) in a collection of n quoted
// elements, on regions built from the bytes that decide it.
func TestCollectionOverlapCursorMatchesAllPairs(t *testing.T) {
	rng := rand.New(rand.NewSource(754))
	alphabet := []string{"\"", "'", ",", ";", " ", "Qx7aB9", "cD3eF5gH", "z"}
	for n := 0; n < 20000; n++ {
		var sb strings.Builder
		for k := rng.Intn(24); k > 0; k-- {
			sb.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		region := sb.String()
		got := appendCollectionElements(nil, region, 0)
		want := collectionElementsAllPairs(region)
		if len(got) != len(want) {
			t.Fatalf("region %q: cursor gave %v, all-pairs gave %v", region, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("region %q: cursor gave %v, all-pairs gave %v", region, got, want)
			}
		}
	}
}

// collectionElementsAllPairs is appendCollectionElements as v2.5.3 wrote it: every element tested
// against every quoted span. The oracle for TestCollectionOverlapCursorMatchesAllPairs.
func collectionElementsAllPairs(region string) []collectionSecretCandidate {
	var out []collectionSecretCandidate
	var covered [][2]int
	for _, q := range quotedListElement.FindAllStringSubmatchIndex(region, -1) {
		out = append(out, collectionSecretCandidate{text: region[q[2]:q[3]], start: q[2], end: q[3]})
		covered = append(covered, [2]int{q[0], q[1]})
	}
	for _, span := range splitListElements(region) {
		overlaps := false
		for _, c := range covered {
			if span[0] < c[1] && c[0] < span[1] {
				overlaps = true
			}
		}
		if overlaps {
			continue
		}
		text := strings.TrimSpace(region[span[0]:span[1]])
		if len(text) < 8 || !plausibleUnquotedSecret(text) || shoutySentinel.MatchString(text) {
			continue
		}
		off := strings.Index(region[span[0]:span[1]], text)
		out = append(out, collectionSecretCandidate{text: text, start: span[0] + off, end: span[0] + off + len(text)})
	}
	return out
}

// A minified line is the shape that made the first version report 136,290 non-credentials on
// public JS/TS: one plausible head, then every statement and property fragment on the rest of the
// line. The walk now yields the head's real list and stops at the first property.
func TestMinifiedLineYieldsOnlyTheHeadsList(t *testing.T) {
	line := "!function(){var e={token:" + secretA + "," + secretB +
		",expiresIn:3600,scope:o.scope,onDone:function(t){return t.data},retry:n.retryPolicy,mode:\"cors\"};" +
		"e.headerSet=Object.assign({},r.headerSet),e.timeoutMs=a.timeoutMs||3e4,module.exports=e}();\n"
	got := reports(t, line)
	if !sameStrings(got, []string{secretA, secretB}) {
		t.Errorf("got %d findings %v, want exactly the head and its one real member [%q %q] — "+
			"the list ends at the first property, and nothing after it belongs to the head",
			len(got), got, secretA, secretB)
	}
}

// sameStrings reports whether got and want hold the same strings with the same multiplicity.
func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	count := make(map[string]int, len(want))
	for _, w := range want {
		count[w]++
	}
	for _, g := range got {
		count[g]--
		if count[g] < 0 {
			return false
		}
	}
	return true
}
