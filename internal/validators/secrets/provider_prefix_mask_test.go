// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"math/rand"
	"strings"
	"testing"
)

// Tests for #807: a mask that keeps the token's provider prefix. `gho_` followed by 36 `*` is how
// several tools print a token in a log. The already-masked veto in plausibleUnquotedSecret required
// the value to be ENTIRELY `*`, so the kept prefix defeated it, and the issue's line reported as
// API_KEY_OR_SECRET at MEDIUM 75 through the CLI on main (HIGH 100 in a .docx whose tab-separated
// cover block adds the +20 tabular boost). Token bodies are built at run time from a seeded
// generator, so no token-shaped literal sits in this file; none is a real credential.

// issue807Line is the issue's reproducer line around a value.
func issue807Line(value string) string {
	return "Token: " + value + " (masked in the log)"
}

// randomBase62 returns n base62 bytes from rng.
func randomBase62(rng *rand.Rand, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

func maskOf(n int) string { return strings.Repeat("*", n) }

// TestIsMaskedValue pins the helper, including the shapes where getting it wrong would widen the
// veto into values that still carry real bytes.
func TestIsMaskedValue(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
		why  string
	}{
		{maskOf(40), true, "entirely mask characters, as before (#522)"},
		{"gho_" + maskOf(36), true, "the issue's value"},
		{"gho_" + maskOf(providerMaskTailMin), true, "the shortest tail accepted"},
		{"gho_" + maskOf(providerMaskTailMin-1), false, "a tail under the floor is left to ordinary scoring"},
		{"gho_****abcd****", false, "real characters in the tail: the ENTIRELY rule still applies"},
		{"gho_" + maskOf(35) + "Q", false, "one surviving byte, as a partial mask leaves"},
		{"gho_", false, "a bare prefix is not a mask"},
		{maskOf(36) + "gho_", false, "the prefix must lead"},
		{"GHO_" + maskOf(36), false, "prefixes match as the table spells them, as the provider regexes do"},
		{"token_" + maskOf(36), false, "a word is not a provider prefix"},
		{"xoxb-123456789012-123456789012-" + maskOf(24), false, "Slack's head digit groups are not stripped"},
	} {
		if got := isMaskedValue(tc.in); got != tc.want {
			t.Errorf("isMaskedValue(%q) = %v, want %v: %s", tc.in, got, tc.want, tc.why)
		}
	}

	// Every prefix of the grammar table, taken from the table rather than listed here, so a row
	// added to providerRules is covered with nothing to update.
	for _, p := range allProviderPrefixes {
		if !isMaskedValue(p + maskOf(36)) {
			t.Errorf("isMaskedValue(%q + 36 '*') = false: a table prefix followed only by the mask is masked output", p)
		}
		if plausibleUnquotedSecret(p + maskOf(36)) {
			t.Errorf("plausibleUnquotedSecret(%q + 36 '*') = true: the unquoted veto does not see the mask", p)
		}
	}
}

// TestProviderPrefixedMaskReportsNothing drives the public entry point on the issue's line and the
// other places a masked token is written, for every prefix of the table. On main every row here
// reported the mask as API_KEY_OR_SECRET, at 75 on the issue's line; the URI disposition was
// uriScored, and the end-to-end URI row reported through #766's uri_userinfo source. (The URI form
// is driven end to end for the issue's prefix only: with `sk_test_` and `pk_test_` it already
// reported nothing on main, for a reason that has nothing to do with the mask.)
func TestProviderPrefixedMaskReportsNothing(t *testing.T) {
	v := NewValidator()
	for _, p := range allProviderPrefixes {
		value := p + maskOf(36)
		for name, line := range map[string]string{
			"issue line": issue807Line(value),
			"env":        "SERVICE_TOKEN=" + value,
			"colon":      "password: " + value,
			"assignment": "api_key=" + value,
		} {
			if ms := secretsOn(t, v, line, "settings.txt"); len(ms) != 0 {
				t.Errorf("%s/%s: %q reported %d finding(s), want none, the value is a mask that kept its "+
					"provider prefix: %v", p, name, line, len(ms), ms)
			}
		}
		if d := uriValueDisposition(value, "app_user"); d != uriNoCandidate {
			t.Errorf("uriValueDisposition(%q + 36 '*') = %v, want uriNoCandidate, the row an all-'*' password takes", p, d)
		}
	}
	line := "DATABASE_URL=postgres://app_user:gho_" + maskOf(36) + "@db1.orders.invalid:5432/appdb"
	if ms := secretsOn(t, v, line, "settings.txt"); len(ms) != 0 {
		t.Errorf("%q reported %v, want none", line, ms)
	}
}

// TestProviderPrefixedMaskControlsStillReport is the scope proof: the shapes the issue says must keep
// reporting do, at the confidence main gives them. A real-shaped token on the issue's line stays a
// GITHUB_TOKEN; a tail with real characters in it, and a tail under the floor, stay reported as
// generic secrets.
func TestProviderPrefixedMaskControlsStillReport(t *testing.T) {
	v := NewValidator()
	rng := rand.New(rand.NewSource(807))

	tok := "gho_" + randomBase62(rng, 36)
	ms := secretsOn(t, v, issue807Line(tok), "settings.txt")
	if len(ms) != 1 || ms[0].Type != "GITHUB_TOKEN" || ms[0].Text != tok {
		t.Fatalf("a gho_ token with a random body on the issue's line: got %v, want one GITHUB_TOKEN over the token", ms)
	}
	if ms[0].Confidence != 100 {
		t.Errorf("the GITHUB_TOKEN control reported at %.0f, want 100 as on main", ms[0].Confidence)
	}

	for _, value := range []string{"gho_****abcd****", "gho_" + maskOf(providerMaskTailMin-1)} {
		ms := secretsOn(t, v, issue807Line(value), "settings.txt")
		if len(ms) != 1 || ms[0].Text != value || ms[0].Type != "API_KEY_OR_SECRET" {
			t.Errorf("%q: got %v, want one API_KEY_OR_SECRET over the value, as on main", value, ms)
			continue
		}
		if ms[0].Confidence != 75 {
			t.Errorf("%q reported at %.0f, want 75 as on main", value, ms[0].Confidence)
		}
	}
}
