// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"strings"
	"testing"
)

// A shared secret printed in an RFC or in vendor documentation is known to
// everybody, so reporting it as a credential is a false positive by definition.
//
// Measured before this: "TOTP secret JBSWY3DPEHPK3PXP for the authenticator app"
// scored 95 HIGH, the otpauth:// URI carrying the same secret scored 100, and the
// RFC 6238 Appendix B seed scored 100. See #364.
//
// The ceiling is asserted rather than a drop: only reported findings are
// redacted, and these exact values are also what the repo's own fixtures and
// golden corpus use to exercise OTP detection.

// topConfidence returns the highest confidence among findings whose text
// contains want, plus whether any such finding exists. Both halves matter: a
// value that stops being detected is also a value that stops being redacted.
func topConfidence(t *testing.T, content, want string) (float64, bool) {
	t.Helper()

	matches, err := NewValidator().ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}

	best, found := 0.0, false
	for _, m := range matches {
		if strings.Contains(m.Text, want) {
			found = true
			if m.Confidence > best {
				best = m.Confidence
			}
		}
	}
	return best, found
}

func TestPublishedSecretsAreCappedAtLow(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "documentation example secret",
			content: "TOTP secret JBSWY3DPEHPK3PXP for the authenticator app",
			want:    "JBSWY3DPEHPK3PXP",
		},
		{
			// The URI's own Text is the whole URI, so recognizing the bare secret is
			// not enough -- the secret= parameter has to be inspected. Without that,
			// capping the secret still left the enclosing URI at 100.
			name:    "otpauth URI carrying it",
			content: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			want:    "otpauth://",
		},
		{
			name:    "RFC 6238 Appendix B seed",
			content: "totp secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ from the test vector",
			want:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		},
		{
			name:    "RFC 4226 ten-byte seed",
			content: "the totp secret is GEZDGNBVGY3TQOJQ here",
			want:    "GEZDGNBVGY3TQOJQ",
		},
		{
			// Lowercase has its own scanning pass; the ceiling has to apply there too.
			name:    "lowercase form",
			content: "totp secret jbswy3dpehpk3pxp in the config",
			want:    "jbswy3dpehpk3pxp",
		},
		{
			// Padding and readability separators must not evade the ceiling.
			name:    "URI with padded secret",
			content: "otpauth://totp/App:bob?secret=JBSWY3DPEHPK3PXP=&issuer=App",
			want:    "otpauth://",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := topConfidence(t, tc.content, tc.want)
			if !found {
				t.Fatalf("%q was not reported at all in %q -- this asserts a ceiling, "+
					"not a drop, because an unreported value is also an unredacted one",
					tc.want, tc.content)
			}
			if got > publishedSecretCeiling {
				t.Errorf("%q scored %.0f (> ceiling %.0f) in %q -- a secret published in "+
					"a specification is being reported as a real credential",
					tc.want, got, publishedSecretCeiling, tc.content)
			}
		})
	}
}

// The ceiling must not touch secrets that are not published, including ones that
// merely resemble the published values. Over-reach here demotes a real
// credential out of a `--confidence medium,high` scan.
func TestUnpublishedSecretsKeepTheirConfidence(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "ordinary base32 secret",
			content: "TOTP secret HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ for the app",
			want:    "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		},
		{
			name:    "URI with an ordinary secret",
			content: "otpauth://totp/ACME:john@acme.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME",
			want:    "otpauth://",
		},
		{
			// One character longer than the documentation example. An earlier version
			// of normalizeBase32Secret dropped every non-base32 character, which would
			// have folded values like this onto the published key.
			name:    "published secret plus a suffix",
			content: "TOTP secret JBSWY3DPEHPK3PXPQ for the app",
			want:    "JBSWY3DPEHPK3PXPQ",
		},
		{
			name:    "published secret prefix only",
			content: "TOTP secret JBSWY3DPEHPK3PX2 for the app",
			want:    "JBSWY3DPEHPK3PX2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := topConfidence(t, tc.content, tc.want)
			if !found {
				t.Fatalf("%q was not reported in %q", tc.want, tc.content)
			}
			if got <= publishedSecretCeiling {
				t.Errorf("%q scored %.0f (<= ceiling %.0f) in %q -- an ordinary secret is "+
					"being demoted as though it were published, which would hide it from a "+
					"--confidence medium,high scan",
					tc.want, got, publishedSecretCeiling, tc.content)
			}
		})
	}
}

// Piling on OTP context must not lift a published secret above the ceiling.
// Against a build where the ceiling is a fixed penalty, the sparse cases pass and
// the loaded ones do not.
func TestContextCannotLiftThePublishedSecretCeiling(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"

	for i, content := range []string{
		"totp " + secret,
		"totp secret " + secret,
		"the totp mfa secret is " + secret,
		"2fa totp authenticator mfa secret key seed: " + secret + " (base32)",
	} {
		got, found := topConfidence(t, content, secret)
		if !found {
			t.Fatalf("case %d: %q was not reported in %q", i, secret, content)
		}
		if got > publishedSecretCeiling {
			t.Errorf("case %d: with more context %q reached %.0f (> ceiling %.0f) in %q "+
				"-- context is out-voting the ceiling", i, secret, got, publishedSecretCeiling, content)
		}
	}
}

func TestPublishedTestSecretIn(t *testing.T) {
	published := []string{
		"JBSWY3DPEHPK3PXP",
		"jbswy3dpehpk3pxp",
		"JBSWY 3DPE HPK3 PXP",
		"JBSWY3DPEHPK3PXP=",
		"GEZDGNBVGY3TQOJQ",
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A",
		"otpauth://hotp/A:b?counter=0&secret=gezdgnbvgy3tqojq",
	}
	for _, s := range published {
		if _, ok := publishedTestSecretIn(s); !ok {
			t.Errorf("publishedTestSecretIn(%q) = false, want true", s)
		}
	}

	unpublished := []string{
		"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		"JBSWY3DPEHPK3PXPQ",  // one char longer
		"JBSWY3DPEHPK3PX",    // one char shorter
		"JBSWY3DPEHPK3PXP0",  // trailing char outside the base32 alphabet
		"1JBSWY3DPEHPK3PXP",  // leading char outside the base32 alphabet
		"GEZDGNBVGY3TQOJQZZ", // published prefix, different value
		"otpauth://totp/A:b?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		"otpauth://totp/A:b?issuer=A", // no secret param at all
		"",
	}
	for _, s := range unpublished {
		if src, ok := publishedTestSecretIn(s); ok {
			t.Errorf("publishedTestSecretIn(%q) = %q, true; want false -- treating an "+
				"unpublished value as published would demote a real secret", s, src)
		}
	}
}
