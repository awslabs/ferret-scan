// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"testing"
)

// #940: an otpauth:// URI with no secret in it read OTPAUTH_URI 100 HIGH. These tests use only
// ValidateContent, so they run unchanged against the parent commit, where the negatives fail.

func otpauthFindings(t *testing.T, content string) []float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []float64
	for _, m := range matches {
		if m.Type == "OTPAUTH_URI" {
			got = append(got, m.Confidence)
		}
	}
	return got
}

// TestASecretlessURIIsNotAProvisioningURI holds the issue's three repository lines and the shapes
// a documentation placeholder takes.
func TestASecretlessURIIsNotAProvisioningURI(t *testing.T) {
	for _, line := range []string{
		// internal/validators/otp/help.go:26, otp/validator.go:21 and docs/validators-new.md:56 on
		// main, verbatim.
		`			"otpauth://totp/... or otpauth://hotp/... (provisioning URIs)",`,
		`	// Matches otpauth://totp/... or otpauth://hotp/... with parameters.`,
		"| `OTPAUTH_URI` | `otpauth://totp/...` or `otpauth://hotp/...` | URI format; must contain `secret=` parameter |",
		"otpauth://totp/ACME:alice@example.com?issuer=ACME",
		"otpauth://totp/App:user@domain.com?algorithm=SHA1&digits=6", // moved from adversarial_test.go
		"otpauth://totp/ACME:alice@example.com?secret=&issuer=ACME",
		"otpauth://totp/ACME:alice@example.com?secret=...",
		"otpauth://totp/ACME:alice@example.com?secret=\u2026&issuer=ACME",
		"otpauth://hotp/ACME:alice?counter=1&secretkey=K5CUWY3ZNRXW4Z3T", // not the secret parameter
	} {
		if got := otpauthFindings(t, line); len(got) != 0 {
			t.Errorf("OTPAUTH_URI %v on %q; a URI with no secret is not a provisioning URI", got, line)
		}
	}
}

// TestAURIWithASecretKeepsItsScore is the recall half: every URI that carries a secret is reported
// as before, including an upper-case parameter name and a secret that is not the first parameter.
func TestAURIWithASecretKeepsItsScore(t *testing.T) {
	for _, line := range []string{
		"otpauth://totp/ACME:alice@example.com?secret=K5CUWY3ZNRXW4Z3T&issuer=ACME",
		"otpauth://hotp/ACME:alice@example.com?counter=1&secret=K5CUWY3ZNRXW4Z3T",
		"otpauth://totp/ACME:bob?SECRET=K5CUWY3ZNRXW4Z3T",
		"otpauth://totp/My%20Service:user%40example.com?issuer=My%20Service&secret=K5CUWY3ZNRXW4Z3T",
	} {
		got := otpauthFindings(t, line)
		if len(got) != 1 || got[0] < 90 {
			t.Errorf("OTPAUTH_URI %v on %q, want one finding at HIGH", got, line)
		}
	}
	// The published example secret stays demoted, as on main.
	if got := otpauthFindings(t, "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"); len(got) != 1 || got[0] != publishedSecretCeiling {
		t.Errorf("published example URI reported at %v, want one finding at %v", got, publishedSecretCeiling)
	}
}

// TestABase32LabelInsideASecretlessURIIsStillNotASecret: the URI's span still keeps a base32 run
// inside it out of the OTP_SECRET pass, so dropping the URI does not surface its label.
func TestABase32LabelInsideASecretlessURIIsStillNotASecret(t *testing.T) {
	matches, err := NewValidator().ValidateContent("totp setup otpauth://totp/K5CUWY3ZNRXW4Z3T?issuer=ACME", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	for _, m := range matches {
		t.Errorf("%s %v %q reported; want nothing", m.Type, m.Confidence, m.Text)
	}
}
