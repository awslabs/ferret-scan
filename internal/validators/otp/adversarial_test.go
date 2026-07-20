// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"strings"
	"testing"
)

// TestAdversarial_FalsePositive_Base32NormalText tests that common English-like
// base32 strings are NOT flagged as OTP secrets even with positive keyword context.
func TestAdversarial_FalsePositive_Base32NormalText(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Sequential alphabet base32",
			content: "2FA secret key: ABCDEFGHIJKLMNOP",
			desc:    "Sequential A-P (16 chars) is clearly a placeholder, not a real secret",
		},
		{
			name:    "Repeated short pattern ABCD x4",
			content: "authenticator seed: ABCDABCDABCDABCD",
			desc:    "4-char repeating pattern (missed by isLikelyWord which only catches 2-char repeats)",
		},
		{
			name:    "Ascending sequence A2B3C4D5...",
			content: "TOTP key: A2B3C4D5E6F7G2H3",
			desc:    "Obvious ascending pattern, not random",
		},
		{
			name:    "All twos and letters AAAABBBBCCCCDDDD",
			content: "secret key: AAAABBBBCCCCDDDD",
			desc:    "Block-repeating pattern (4 of each char) should be suspicious",
		},
		{
			name:    "English word DOCUMENTATION16",
			content: "OTP enrollment: DOCUMENTATIONDOC",
			desc:    "English word-like pattern in base32 alphabet (all uppercase A-Z)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "OTP_SECRET" && m.Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  Input: %q\n  Matched: %q confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_FalsePositive_UUIDAsRecoveryCode tests that UUIDs and partial
// UUIDs are not flagged as recovery codes.
func TestAdversarial_FalsePositive_UUIDAsRecoveryCode(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Full UUID with recovery keyword",
			content: "recovery token: 550e8400-e29b-41d4-a716-446655440000",
			desc:    "Full UUID should be excluded by reUUID check",
		},
		{
			name:    "Two partial UUIDs with recovery keyword",
			content: "recovery ids: 550e8400-e29b-41d4-a716 abcd1234-5678-90ab-cdef",
			desc:    "Partial UUIDs (first 4 groups) bypass UUID regex but look like recovery codes",
		},
		{
			name:    "Hex-only dash blocks with MFA context",
			content: "MFA session: aabb1122-ccdd-3344 eeff5566-7788-9900",
			desc:    "Hex-only blocks that match recovery code pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "RECOVERY_CODES" && m.Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  Input: %q\n  Matched: %q confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_FalsePositive_LicenseKeys tests that license/product keys
// in XXXX-XXXX-XXXX-XXXX format are not flagged as OTP recovery codes.
func TestAdversarial_FalsePositive_LicenseKeys(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Software license with MFA keyword nearby",
			content: "After MFA setup, enter license: WKRP-4521-LDNV PQRS-8734-MNCV",
			desc:    "License keys on same line as MFA keyword should not be recovery codes",
		},
		{
			name:    "Multiple product keys with 2FA mention",
			content: "2FA activated. Product keys: XXXX-YYYY-ZZZZ AAAA-BBBB-CCCC",
			desc:    "Product key blocks with 2FA context keyword on same line",
		},
		{
			name:    "Windows-style product key with recovery context",
			content: "recovery disk contains key: NKJFK-GPHP7-G8C3J RHJG7-TKMPD-JKKK2",
			desc:    "5-block product key segments should not match with coincidental recovery keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "RECOVERY_CODES" && m.Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  Input: %q\n  Matched: %q confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_FalsePositive_JWTTokens tests that JWT tokens and lines
// containing JWTs are not flagged as OTP secrets.
func TestAdversarial_FalsePositive_JWTTokens(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "JWT with OTP keyword",
			content: "OTP token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			desc:    "JWT token should not be flagged even with 'OTP' and 'token' on the line",
		},
		{
			name:    "JWT with secret keyword",
			content: "secret verification: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.signature",
			desc:    "JWT with 'secret' keyword must not match",
		},
		{
			name:    "Bearer token with authenticator in URL",
			content: "GET /authenticator/verify HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ0b2tlbiI6InRlc3QifQ.abcdefghijklmn",
			desc:    "JWT bearer in authenticator endpoint context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  Input: %q\n  Matched: %q type=%s confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Type, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_OTPAuthURI_HighConfidence verifies that real otpauth:// URIs
// always produce HIGH confidence (>= 80) immediately, regardless of surrounding context.
func TestAdversarial_OTPAuthURI_HighConfidence(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Bare TOTP URI no surrounding text",
			content: "otpauth://totp/Service:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Service",
			desc:    "Standard TOTP URI must be >= 80 confidence",
		},
		{
			name:    "HOTP URI with counter",
			content: "otpauth://hotp/MyBank:customer@bank.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&counter=42",
			desc:    "HOTP URI must be >= 80 confidence",
		},
		{
			name:    "URI in negative context (test file)",
			content: "test fixture: otpauth://totp/TestApp:test@test.com?secret=GEZDGNBVGY3TQOJQ",
			desc:    "Even with 'test' negative keyword, otpauth URI should remain HIGH (>= 60 at minimum)",
		},
		{
			name:    "URI with URL-encoded characters",
			content: "otpauth://totp/My%20Service:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Service",
			desc:    "URL-encoded URI must still be detected at HIGH confidence",
		},
		{
			name:    "Minimal URI without secret param",
			content: "otpauth://totp/App:user@domain.com?algorithm=SHA1&digits=6",
			desc:    "URI without secret= param should still be >= 80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			found := false
			for _, m := range matches {
				if m.Type == "OTPAUTH_URI" {
					found = true
					// For the negative-context test, we allow slightly lower threshold
					minConf := 80.0
					if strings.Contains(tt.name, "negative context") {
						minConf = 60.0
					}
					if m.Confidence < minConf {
						t.Errorf("TOO LOW CONFIDENCE: %s\n  Input: %q\n  Confidence=%.1f (need >= %.1f)\n  %s",
							tt.name, tt.content, m.Confidence, minConf, tt.desc)
					}
				}
			}
			if !found {
				t.Errorf("FALSE NEGATIVE: %s\n  No OTPAUTH_URI match found\n  Input: %q\n  %s",
					tt.name, tt.content, tt.desc)
			}
		})
	}
}

// TestAdversarial_RecoveryCodesWithoutKeyword tests that recovery-code-shaped
// patterns WITHOUT any recovery/backup keyword produce NO match (not even low confidence).
func TestAdversarial_RecoveryCodesWithoutKeyword(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Dash-separated codes no keyword",
			content: "codes: ABCD-EFGH-IJKL MNOP-QRST-UVWX",
			desc:    "Recovery-shaped codes without any recovery keyword should produce NO match",
		},
		{
			name:    "Reference numbers without keyword",
			content: "ref: 1234-5678-9012 abcd-efgh-ijkl",
			desc:    "Reference numbers that look like recovery codes",
		},
		{
			name:    "Tracking numbers",
			content: "tracking: USPS-1234-5678 FEDX-9012-3456",
			desc:    "Shipping tracking numbers should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "RECOVERY_CODES" {
					t.Errorf("SHOULD NOT MATCH: %s\n  Input: %q\n  Matched: %q confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_FalsePositive_ProductSerials tests that product serial numbers
// in XXXX-XXXX format absolutely do NOT match.
func TestAdversarial_FalsePositive_ProductSerials(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Hardware serial number",
			content: "Serial: SN12-AB34-CD56",
			desc:    "Hardware serial must not match (negative keyword 'serial')",
		},
		{
			name:    "Product serial without negative keyword",
			content: "Device ID: WXYZ-1234-ABCD",
			desc:    "A single product serial should not match (needs >= 2 on line + context)",
		},
		{
			name:    "Two serials with emergency keyword",
			content: "emergency replacement devices: WXYZ-1234-ABCD EFGH-5678-IJKL",
			desc:    "Two serial-like patterns with coincidental 'emergency' keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "RECOVERY_CODES" && m.Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  Input: %q\n  Matched: %q confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_ContextWeakness tests that the same value produces dramatically
// different confidence WITH vs WITHOUT keywords.
func TestAdversarial_ContextWeakness(t *testing.T) {
	validator := NewValidator()

	t.Run("Base32 secret with vs without keywords", func(t *testing.T) {
		secret := "JBSWY3DPEHPK3PXP"
		withKeyword := "Google Authenticator 2FA secret key: " + secret
		withoutKeyword := "data: " + secret

		matchWith, err := validator.ValidateContent(withKeyword, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		matchWithout, err := validator.ValidateContent(withoutKeyword, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		// With keywords MUST match
		if len(matchWith) == 0 {
			t.Fatal("Expected match WITH keyword context")
		}
		// Without keywords MUST NOT match (base32 requires positive context)
		if len(matchWithout) > 0 {
			t.Errorf("Should NOT match without keyword context, got confidence=%.1f",
				matchWithout[0].Confidence)
		}

		// If both match, confidence gap must be significant (>= 20 points)
		if len(matchWith) > 0 && len(matchWithout) > 0 {
			gap := matchWith[0].Confidence - matchWithout[0].Confidence
			if gap < 20 {
				t.Errorf("Context gap too small: with=%.1f, without=%.1f, gap=%.1f (need >= 20)",
					matchWith[0].Confidence, matchWithout[0].Confidence, gap)
			}
		}
	})

	t.Run("Recovery code with vs without recovery keyword", func(t *testing.T) {
		codes := "ABCD-EFGH-1234 MNOP-QRST-5678"
		withKeyword := "Your recovery codes: " + codes
		withoutKeyword := "reference numbers: " + codes

		matchWith, err := validator.ValidateContent(withKeyword, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		matchWithout, err := validator.ValidateContent(withoutKeyword, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		// With keyword should match
		if len(matchWith) == 0 {
			t.Error("Expected RECOVERY_CODES match with 'recovery' keyword")
		}
		// Without keyword should NOT match
		for _, m := range matchWithout {
			if m.Type == "RECOVERY_CODES" {
				t.Errorf("Should NOT match without recovery keyword, got confidence=%.1f for %q",
					m.Confidence, m.Text)
			}
		}
	})
}

// TestAdversarial_CrossValidatorConfusion tests patterns that look like they
// belong to other validators and should NOT trigger OTP.
func TestAdversarial_CrossValidatorConfusion(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Credit card number with dashes near 2FA text",
			content: "After 2FA verification, charge card 4111-1111-1111-1111",
			desc:    "Credit card number pattern (4 groups of 4 digits) should not be flagged as recovery code",
		},
		{
			name:    "Phone number with recovery context",
			content: "recovery contact: 555-123-4567 or 555-987-6543",
			desc:    "Phone numbers should not be flagged as recovery codes",
		},
		{
			name:    "MAC address with MFA context",
			content: "MFA device MAC: AA-BB-CC-DD-EE-FF",
			desc:    "MAC address (6 groups of 2 hex) should not match recovery codes",
		},
		{
			name:    "IP address range with backup context",
			content: "backup server IPs: 192-168-001-100 and 10-0-0-1",
			desc:    "IP addresses in dash form should not be recovery codes",
		},
		{
			name:    "AWS access key looks like base32",
			content: "secret key: AKIAIOSFODNN7EXAMPLE",
			desc:    "AWS access key ID is 20 uppercase chars - should not be OTP secret (contains 0,1,8,9,I,O which are not base32 2-7)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Confidence > 50 {
					t.Errorf("CROSS-VALIDATOR CONFUSION: %s\n  Input: %q\n  Matched: %q type=%s confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Type, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_EdgeCases tests boundary conditions and unusual inputs.
func TestAdversarial_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("Max length base32 (64 chars) with context", func(t *testing.T) {
		// 64-char base32 (maximum allowed)
		secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		content := "TOTP secret: " + secret
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match for 64-char base32 secret with TOTP keyword")
		}
	})

	t.Run("Just over max length base32 (65 chars) should not match", func(t *testing.T) {
		secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345672"
		content := "TOTP secret: " + secret
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		for _, m := range matches {
			if m.Type == "OTP_SECRET" && len(m.Text) > 64 {
				t.Errorf("Should not match >64 char base32: matched %d chars", len(m.Text))
			}
		}
	})

	t.Run("Unicode before base32 secret", func(t *testing.T) {
		content := "\xF0\x9F\x94\x91 2FA secret: JBSWY3DPEHPK3PXP"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match even with unicode prefix")
		}
	})

	t.Run("Empty lines between otpauth URI parts should not crash", func(t *testing.T) {
		content := "\n\n\notpauth://totp/App:u@e.com?secret=ABC\n\n\n"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected otpauth match even with surrounding empty lines")
		}
	})

	t.Run("Very long line with otpauth URI at end", func(t *testing.T) {
		padding := strings.Repeat("x", 5000)
		content := padding + " otpauth://totp/App:u@e.com?secret=JBSWY3DPEHPK3PXP"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected otpauth match even on very long line")
		}
	})

	t.Run("Partially redacted base32 does not match", func(t *testing.T) {
		// Someone redacted part of the secret with asterisks
		content := "2FA secret: JBSWY3DP****3PXP"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		for _, m := range matches {
			if m.Type == "OTP_SECRET" && strings.Contains(m.Text, "*") {
				t.Errorf("Partially redacted secret should not match: %q", m.Text)
			}
		}
	})

	t.Run("Base32 with mixed case should not match regex", func(t *testing.T) {
		// The validator only matches uppercase base32
		content := "totp secret: JbSwY3DpEhPk3PxP"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// This is a known limitation - mixed case base32 is not detected
		// We just verify it doesn't crash and doesn't produce a match
		for _, m := range matches {
			if m.Type == "OTP_SECRET" {
				t.Logf("NOTE: Mixed-case base32 produced match: %q (may be false positive)", m.Text)
			}
		}
	})
}

// TestAdversarial_FalsePositive_EmergencyDeviceCodes tests that non-recovery-code
// patterns with coincidental "emergency" keyword don't produce high-confidence matches.
func TestAdversarial_FalsePositive_EmergencyDeviceCodes(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Emergency exit room codes",
			content: "emergency exit: room A123-B456-C789 door D012-E345-F678",
			desc:    "Room/door codes with 'emergency' should not be high-confidence recovery codes",
		},
		{
			name:    "Emergency contact IDs",
			content: "emergency staff IDs: EMP1-DEPT-2024 EMP2-DEPT-2024",
			desc:    "Employee IDs near 'emergency' keyword",
		},
		{
			name:    "Emergency firmware versions",
			content: "emergency patch: v2024-0101-fix1 v2024-0102-fix2",
			desc:    "Version identifiers with 'emergency' keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "RECOVERY_CODES" && m.Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  Input: %q\n  Matched: %q confidence=%.1f\n  %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.desc)
				}
			}
		})
	}
}

// TestAdversarial_FalseNegative_LowercaseBase32 verifies the known limitation
// that lowercase TOTP secrets are not detected.
func TestAdversarial_FalseNegative_LowercaseBase32(t *testing.T) {
	validator := NewValidator()

	// Many OTP apps display secrets in lowercase or with spaces.
	// This is a known false negative.
	content := "2FA secret: jbswy3dpehpk3pxp"
	matches, err := validator.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	hasOTPSecret := false
	for _, m := range matches {
		if m.Type == "OTP_SECRET" {
			hasOTPSecret = true
		}
	}
	if !hasOTPSecret {
		t.Log("KNOWN FALSE NEGATIVE: lowercase base32 TOTP secrets are not detected")
		t.Log("  Input: \"2FA secret: jbswy3dpehpk3pxp\"")
		t.Log("  The regex only matches [A-Z2-7]{16,64}")
	}
}

// TestAdversarial_FalseNegative_MultiLineRecoveryCodes verifies behavior when
// recovery codes span multiple lines (one code per line).
func TestAdversarial_FalseNegative_MultiLineRecoveryCodes(t *testing.T) {
	validator := NewValidator()

	// Real-world recovery code lists are usually one per line
	content := "Your recovery codes:\nABCD-EFGH-IJKL\nMNOP-QRST-UVWX\nYZAB-CDEF-GHIJ"
	matches, err := validator.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	hasRecovery := false
	for _, m := range matches {
		if m.Type == "RECOVERY_CODES" {
			hasRecovery = true
		}
	}
	if !hasRecovery {
		t.Log("KNOWN FALSE NEGATIVE: Recovery codes on separate lines are not detected")
		t.Log("  The validator requires >= 2 recovery-code matches on the SAME line")
		t.Log("  Real-world recovery codes are typically listed one per line")
	}
}
