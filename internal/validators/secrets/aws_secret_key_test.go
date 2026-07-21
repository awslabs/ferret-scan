// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// TestAWSSecretAccessKey covers issue #147 item 4: the secret half of an AWS
// credential pair (40 chars of base64, no prefix) previously had no pattern —
// the golden fixtures proved AWS_SECRET_ACCESS_KEY=... survived redaction in
// cleartext. Detection is context-gated (key-name label or paired AKIA/ASIA
// nearby) because bare 40-char base64 collides with hashes and tokens.
func TestAWSSecretAccessKey(t *testing.T) {
	v := NewValidator()

	find := func(t *testing.T, content string) []float64 {
		t.Helper()
		matches, err := v.ValidateContent(content, "test.env")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		var conf []float64
		for _, m := range matches {
			if m.Type == "AWS_SECRET_ACCESS_KEY" {
				conf = append(conf, m.Confidence)
			}
		}
		return conf
	}

	// A realistic (synthetic, mixed-case, high-entropy) secret value.
	const secret = "kJ8mNpQr2sTuVwXyZ1aBcDeFgHiJkLmNoPqRsT9u"

	t.Run("env assignment form detected", func(t *testing.T) {
		if c := find(t, "AWS_SECRET_ACCESS_KEY="+secret+"\n"); len(c) != 1 {
			t.Fatalf("expected 1 detection, got %d", len(c))
		}
	})

	t.Run("credentials file form detected", func(t *testing.T) {
		if c := find(t, "aws_secret_access_key = "+secret+"\n"); len(c) != 1 {
			t.Fatalf("expected 1 detection, got %d", len(c))
		}
	})

	t.Run("paired AKIA on adjacent line boosts to 95", func(t *testing.T) {
		c := find(t, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY="+secret+"\n")
		if len(c) != 1 {
			t.Fatalf("expected 1 detection, got %d", len(c))
		}
		if c[0] != 95 {
			t.Errorf("paired secret should score 95, got %.1f", c[0])
		}
	})

	t.Run("no context gate no detection", func(t *testing.T) {
		if c := find(t, "some pipeline artifact "+secret+" checksum\n"); len(c) != 0 {
			t.Fatalf("bare 40-char token without AWS context must not match, got %d", len(c))
		}
	})

	t.Run("hex digest near keyword rejected by charset and case", func(t *testing.T) {
		// SHA-1 hex is 40 chars but all-lowercase — the all-one-case guard
		// rejects it even when an AWS keyword is on the line.
		if c := find(t, "secret_access_key digest da39a3ee5e6b4b0d3255bfef95601890afd80709\n"); len(c) != 0 {
			t.Fatalf("hex digest must not match, got %d", len(c))
		}
	})

	t.Run("test context suppresses", func(t *testing.T) {
		if c := find(t, "test secret_access_key example "+secret+"\n"); len(c) != 0 {
			t.Fatalf("test-context line must not match, got %d", len(c))
		}
	})

	t.Run("test keyword requires word boundary", func(t *testing.T) {
		// "latest" contains "test" but is not a test marker.
		if c := find(t, "the latest secret_access_key is "+secret+"\n"); len(c) != 1 {
			t.Fatalf("'latest' must not suppress via substring, got %d detections", len(c))
		}
	})

	t.Run("EXAMPLE embedded demotes below HIGH", func(t *testing.T) {
		c := find(t, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
		if len(c) != 1 {
			t.Fatalf("doc placeholder secret must still be detected (for redaction), got %d", len(c))
		}
		if c[0] >= 90 {
			t.Errorf("EXAMPLE-embedded secret must stay below HIGH, got %.1f", c[0])
		}
	})

	t.Run("AKIA id itself not double-reported as secret", func(t *testing.T) {
		// An AKIA + 16 chars is 20 chars so can't match the 40-char pattern,
		// but a 40-char ASIA-prefixed token could; ensure prefix exclusion.
		if c := find(t, "AWS_SECRET_ACCESS_KEY=ASIA"+strings.Repeat("A1b2C3d4E5f6", 3)+"\n"); len(c) != 0 {
			t.Fatalf("ASIA-prefixed token must not be reported as secret, got %d", len(c))
		}
	})
}
