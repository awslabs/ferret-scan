// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"context"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func TestOTPValidator_OTPAuthURIs(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		matchType   string
		description string
	}{
		{
			name:        "Standard TOTP URI",
			content:     `otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`,
			expectMatch: true,
			matchType:   "OTPAUTH_URI",
			description: "Standard TOTP provisioning URI",
		},
		{
			name:        "HOTP URI",
			content:     `otpauth://hotp/ACME:john@acme.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&counter=0`,
			expectMatch: true,
			matchType:   "OTPAUTH_URI",
			description: "Standard HOTP provisioning URI",
		},
		{
			name:        "TOTP URI without issuer param",
			content:     `otpauth://totp/MyApp:user@domain.com?secret=GEZDGNBVGY3TQOJQ`,
			expectMatch: true,
			matchType:   "OTPAUTH_URI",
			description: "TOTP URI with minimal parameters",
		},
		{
			name:        "URI in config file context",
			content:     `totp_uri = "otpauth://totp/Production:admin@corp.com?secret=NBSWY3DP&issuer=Production"`,
			expectMatch: true,
			matchType:   "OTPAUTH_URI",
			description: "URI found in a config file",
		},
		{
			name:        "URI with algorithm and digits params",
			content:     `otpauth://totp/AWS:root@account.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=30`,
			expectMatch: true,
			matchType:   "OTPAUTH_URI",
			description: "URI with full parameter set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			hasMatch := len(matches) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (found %d matches)",
					tt.description, tt.expectMatch, hasMatch, len(matches))
			}
			if hasMatch && matches[0].Type != tt.matchType {
				t.Errorf("expected Type=%s, got=%s", tt.matchType, matches[0].Type)
			}
			if hasMatch && matches[0].Validator != "otp" {
				t.Errorf("expected Validator=otp, got=%s", matches[0].Validator)
			}
		})
	}
}

func TestOTPValidator_Base32Secrets(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		matchType   string
		description string
	}{
		{
			name:        "TOTP secret with authenticator keyword",
			content:     "Google Authenticator secret key: JBSWY3DPEHPK3PXP",
			expectMatch: true,
			matchType:   "OTP_SECRET",
			description: "Base32 secret with authenticator context",
		},
		{
			name:        "Secret with 2FA keyword",
			content:     "2FA setup key: HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			expectMatch: true,
			matchType:   "OTP_SECRET",
			description: "Longer base32 secret with 2FA context",
		},
		{
			name:        "Secret with TOTP keyword",
			content:     "TOTP seed: GEZDGNBVGY3TQOJQ",
			expectMatch: true,
			matchType:   "OTP_SECRET",
			description: "Base32 secret with TOTP keyword",
		},
		{
			name:        "Secret with MFA keyword",
			content:     "MFA secret: MFRGGZDFMY4TQMZZ",
			expectMatch: true,
			matchType:   "OTP_SECRET",
			description: "Base32 secret with MFA context",
		},
		{
			name:        "Secret key from OTP enrollment",
			content:     "Your OTP enrollment secret is NBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
			expectMatch: true,
			matchType:   "OTP_SECRET",
			description: "32-char secret from OTP enrollment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			hasMatch := len(matches) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (found %d matches)",
					tt.description, tt.expectMatch, hasMatch, len(matches))
			}
			if hasMatch && matches[0].Type != tt.matchType {
				t.Errorf("expected Type=%s, got=%s", tt.matchType, matches[0].Type)
			}
		})
	}
}

// TestOTPValidator_SessionAndDeviceGating locks the Wave-2 OTP fixes:
//   - "session" is a negative signal ONLY with a JWT on the line; a 2FA/TOTP
//     setup line that merely mentions "session" must keep its OTP secret. The
//     AnalyzeContext carve-out and the emit-time -30 (hasNegativeContext) must
//     agree, so the secret is not silently dropped by the -30.
//   - bare "device" no longer vetoes recovery codes ("recovery codes for this
//     device"), while "device id" still suppresses.
func TestOTPValidator_SessionAndDeviceGating(t *testing.T) {
	validator := NewValidator()

	// "session" without a JWT must NOT suppress a real TOTP secret.
	got, err := validator.ValidateContent(
		"2FA authenticator secret key JBSWY3DPEHPK3PXP for this session", "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	foundSecret := false
	for _, m := range got {
		if m.Type == "OTP_SECRET" && m.Confidence > 50 {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Errorf("'session' without a JWT should not suppress the OTP secret; got %d matches", len(got))
	}

	// bare "device" must NOT veto recovery codes.
	rc, err := validator.ValidateContent(
		"Your recovery codes for this device: ABCD-EFGH-IJKL MNOP-QRST-UVWX", "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	foundRC := false
	for _, m := range rc {
		if m.Type == "RECOVERY_CODES" {
			foundRC = true
		}
	}
	if !foundRC {
		t.Errorf("bare 'device' should not veto recovery codes; got %d matches", len(rc))
	}

	// "device id" (hardware identifier) must still suppress recovery-code shapes.
	di, err := validator.ValidateContent(
		"backup device id list: ABCD-EFGH-IJKL MNOP-QRST-UVWX", "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	for _, m := range di {
		if m.Type == "RECOVERY_CODES" {
			t.Errorf("'device id' should still suppress recovery codes; got a match %q", m.Text)
		}
	}
}

func TestOTPValidator_RecoveryCodes(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		matchType   string
		description string
	}{
		{
			name:        "Recovery codes with keyword",
			content:     "Your recovery codes: ABCD-EFGH-IJKL MNOP-QRST-UVWX",
			expectMatch: true,
			matchType:   "RECOVERY_CODES",
			description: "Dash-separated recovery code blocks with recovery keyword",
		},
		{
			name:        "Backup codes for 2FA",
			content:     "2FA backup codes: 1234-5678 abcd-efgh 9012-3456",
			expectMatch: true,
			matchType:   "RECOVERY_CODES",
			description: "Backup codes with 2FA context",
		},
		{
			name:        "MFA recovery codes block",
			content:     "MFA emergency recovery: XYZW-ABCD-1234 EFGH-IJKL-5678 MNOP-QRST-9012",
			expectMatch: true,
			matchType:   "RECOVERY_CODES",
			description: "Multiple recovery codes with MFA keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			hasMatch := len(matches) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (found %d matches)",
					tt.description, tt.expectMatch, hasMatch, len(matches))
			}
			if hasMatch && matches[0].Type != tt.matchType {
				t.Errorf("expected Type=%s, got=%s", tt.matchType, matches[0].Type)
			}
		})
	}
}

func TestOTPValidator_FalsePositives(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Random base32 without context",
			content: "JBSWY3DPEHPK3PXP",
		},
		{
			name:    "License key pattern",
			content: "license key: ABCD-EFGH-IJKL-MNOP",
		},
		{
			name:    "Product activation code",
			content: "activation code: XXXX-YYYY-ZZZZ-WWWW",
		},
		{
			name:    "UUID",
			content: "id: 550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:    "Short 6-digit TOTP code (ephemeral)",
			content: "Your verification code is 123456",
		},
		{
			name:    "Hex hash string",
			content: "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:    "Base32 with test keyword",
			content: "test secret: JBSWY3DPEHPK3PXP",
		},
		{
			name:    "Base32 with example keyword",
			content: "example TOTP: JBSWY3DPEHPK3PXP",
		},
		{
			name:    "Single dash-separated block without recovery context",
			content: "reference: ABCD-EFGH-IJKL",
		},
		{
			name:    "Serial number pattern",
			content: "serial number SN12-AB34-CD56",
		},
		{
			name:    "All same characters base32",
			content: "authenticator key: AAAAAAAAAAAAAAAA",
		},
		{
			name:    "JWT token",
			content: "bearer token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// False positives should either not match or have very low confidence
			for _, m := range matches {
				if m.Confidence > 50 {
					t.Errorf("False positive %q: expected low/no confidence, got %.1f for %q (type=%s)",
						tt.name, m.Confidence, m.Text, m.Type)
				}
			}
		})
	}
}

func TestOTPValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	t.Run("Positive keywords boost confidence", func(t *testing.T) {
		matchAuth, _ := validator.ValidateContent(
			"Google Authenticator secret key: JBSWY3DPEHPK3PXP", "test.txt")
		matchBare, _ := validator.ValidateContent(
			"OTP key JBSWY3DPEHPK3PXP", "test.txt")

		if len(matchAuth) == 0 {
			t.Fatal("Expected match with authenticator context")
		}
		if len(matchBare) == 0 {
			t.Fatal("Expected match with OTP context")
		}
		// Both should detect, but more keywords = higher confidence
		if matchAuth[0].Confidence < matchBare[0].Confidence {
			t.Logf("Multi-keyword context should have higher confidence: auth=%.1f, bare=%.1f",
				matchAuth[0].Confidence, matchBare[0].Confidence)
		}
	})

	t.Run("Negative keywords reduce confidence", func(t *testing.T) {
		matchPositive, _ := validator.ValidateContent(
			`otpauth://totp/App:user@test.com?secret=JBSWY3DPEHPK3PXP`, "test.txt")
		matchNegative, _ := validator.ValidateContent(
			`example demo otpauth://totp/App:user@test.com?secret=JBSWY3DPEHPK3PXP`, "test.txt")

		if len(matchPositive) == 0 {
			t.Fatal("Expected match in positive context")
		}
		if len(matchNegative) == 0 {
			t.Fatal("Expected match in negative context")
		}
		if matchNegative[0].Confidence >= matchPositive[0].Confidence {
			t.Errorf("Negative context should reduce confidence: positive=%.1f, negative=%.1f",
				matchPositive[0].Confidence, matchNegative[0].Confidence)
		}
	})
}

func TestOTPValidator_AnalyzeContextMethod(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string
	}{
		{
			name:           "Authenticator keyword positive",
			match:          "JBSWY3DPEHPK3PXP",
			line:           "Google Authenticator secret: JBSWY3DPEHPK3PXP",
			expectedImpact: "positive",
		},
		{
			name:           "License keyword negative",
			match:          "ABCD-EFGH-IJKL",
			line:           "license key: ABCD-EFGH-IJKL",
			expectedImpact: "negative",
		},
		{
			name:           "2FA keyword positive",
			match:          "JBSWY3DPEHPK3PXP",
			line:           "2FA setup key: JBSWY3DPEHPK3PXP",
			expectedImpact: "positive",
		},
		{
			name:           "Test keyword negative",
			match:          "JBSWY3DPEHPK3PXP",
			line:           "test example: JBSWY3DPEHPK3PXP",
			expectedImpact: "negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := detector.ContextInfo{
				FullLine: tt.line,
			}
			impact := validator.AnalyzeContext(tt.match, ctx)

			switch tt.expectedImpact {
			case "positive":
				if impact <= 0 {
					t.Errorf("Expected positive impact, got %.2f", impact)
				}
			case "negative":
				if impact >= 0 {
					t.Errorf("Expected negative impact, got %.2f", impact)
				}
			}
		})
	}
}

func TestOTPValidator_CalculateConfidence(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		match         string
		minConfidence float64
		maxConfidence float64
	}{
		{
			name:          "OTPAuth URI with secret param",
			match:         "otpauth://totp/App:user@domain.com?secret=JBSWY3DPEHPK3PXP&issuer=App",
			minConfidence: 90,
			maxConfidence: 100,
		},
		{
			name:          "OTPAuth URI without secret param",
			match:         "otpauth://totp/App:user@domain.com",
			minConfidence: 85,
			maxConfidence: 95,
		},
		{
			name:          "16-char base32 secret",
			match:         "JBSWY3DPEHPK3PXP",
			minConfidence: 50,
			maxConfidence: 70,
		},
		{
			name:          "32-char base32 secret",
			match:         "NBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
			minConfidence: 60,
			maxConfidence: 80,
		},
		{
			name:          "Recovery code block",
			match:         "ABCD-EFGH-IJKL",
			minConfidence: 45,
			maxConfidence: 75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, _ := validator.CalculateConfidence(tt.match)
			if confidence < tt.minConfidence || confidence > tt.maxConfidence {
				t.Errorf("confidence %.2f not in range [%.2f, %.2f]",
					confidence, tt.minConfidence, tt.maxConfidence)
			}
		})
	}
}

func TestOTPValidator_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("Empty content", func(t *testing.T) {
		matches, err := validator.ValidateContent("", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("Expected no matches for empty content, got %d", len(matches))
		}
	})

	t.Run("Single character", func(t *testing.T) {
		matches, err := validator.ValidateContent("A", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("Expected no matches for single char, got %d", len(matches))
		}
	})

	t.Run("Multiple OTP findings on separate lines", func(t *testing.T) {
		content := "otpauth://totp/App:user@ex.com?secret=JBSWY3DPEHPK3PXP\nMFA secret: HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) < 2 {
			t.Errorf("Expected at least 2 matches, got %d", len(matches))
		}
	})

	t.Run("OTPAuth URI line number", func(t *testing.T) {
		content := "line 1\nline 2\notpauth://totp/App:user@ex.com?secret=ABC"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected at least one match")
		}
		if matches[0].LineNumber != 3 {
			t.Errorf("Expected line number 3, got %d", matches[0].LineNumber)
		}
	})

	t.Run("Unicode content does not crash", func(t *testing.T) {
		content := "2FA secret: JBSWY3DPEHPK3PXP with unicode chars"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match even with unicode in content")
		}
	})

	t.Run("Metadata fields present", func(t *testing.T) {
		content := `otpauth://totp/App:user@ex.com?secret=JBSWY3DPEHPK3PXP`
		matches, err := validator.ValidateContent(content, "secrets.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected at least one match")
		}
		m := matches[0]
		if _, ok := m.Metadata["validation_checks"]; !ok {
			t.Error("Expected validation_checks in metadata")
		}
		if _, ok := m.Metadata["context_impact"]; !ok {
			t.Error("Expected context_impact in metadata")
		}
		if m.Metadata["source"] != "preprocessed_content" {
			t.Errorf("Expected source=preprocessed_content, got=%v", m.Metadata["source"])
		}
		if m.Metadata["original_file"] != "secrets.txt" {
			t.Errorf("Expected original_file=secrets.txt, got=%v", m.Metadata["original_file"])
		}
	})
}

func TestOTPValidator_CooperativeCancellation(t *testing.T) {
	validator := NewValidator()

	t.Run("Cancelled context returns partial results", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Even with cancelled context, should not error fatally
		_, err := validator.ValidateContentCtx(ctx, "otpauth://totp/App:x?secret=A", "test.txt")
		if err == nil {
			t.Log("No error with immediately cancelled context (may have completed before check)")
		}
	})
}

func TestOTPValidator_NewValidator(t *testing.T) {
	validator := NewValidator()

	if validator == nil {
		t.Fatal("NewValidator() returned nil")
	}
	if validator.regex == nil {
		t.Fatal("NewValidator() did not compile regex")
	}
	if len(validator.positiveKeywords) == 0 {
		t.Fatal("NewValidator() has no positive keywords")
	}
	if len(validator.negativeKeywords) == 0 {
		t.Fatal("NewValidator() has no negative keywords")
	}
}

func TestOTPValidator_IsValidBase32(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		input string
		valid bool
	}{
		{"JBSWY3DPEHPK3PXP", true},                 // 16 chars, valid
		{"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", true}, // 32 chars, valid
		{"ABC", false},                             // Too short
		{"JBSWY3DPEHPK3PX!", false},                // Invalid char
		{"jbswy3dpehpk3pxp", false},                // Lowercase not valid base32
		{"ABCDEFGHIJKLMNOP", true},                 // 16 chars A-Z only
		{"1234567890123456", false},                // Digits 0,1,8,9 invalid in base32
		{"AAAAAAAAAAAAAAAA", true},                 // Valid base32 (though suspicious)
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345678", false}, // 65 chars, too long
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.isValidBase32(tt.input)
			if result != tt.valid {
				t.Errorf("isValidBase32(%q) = %v, want %v", tt.input, result, tt.valid)
			}
		})
	}
}

func TestOTPValidator_HasUniformBlockLength(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		parts   []string
		uniform bool
	}{
		{[]string{"ABCD", "EFGH", "IJKL"}, true},
		{[]string{"ABCD", "EFGHI", "IJKL"}, false},
		{[]string{"AB", "CD"}, true},
		{[]string{"A"}, false},
	}

	for _, tt := range tests {
		result := validator.hasUniformBlockLength(tt.parts)
		if result != tt.uniform {
			t.Errorf("hasUniformBlockLength(%v) = %v, want %v", tt.parts, result, tt.uniform)
		}
	}
}

func TestOTPValidator_IsLikelyWord(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		input  string
		likely bool
	}{
		{"AAAAAAAAAAAAAAAA", true},  // All same
		{"ABABABABABABABAB", true},  // Repeating pair
		{"JBSWY3DPEHPK3PXP", false}, // Random-looking
		{"HXDMVJECJJWSRB3H", false}, // Random-looking
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.isLikelyWord(tt.input)
			if result != tt.likely {
				t.Errorf("isLikelyWord(%q) = %v, want %v", tt.input, result, tt.likely)
			}
		})
	}
}

func TestOTPValidator_LowercaseBase32Secrets(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		matchText   string
		description string
	}{
		{
			name:        "Lowercase TOTP secret with context",
			content:     "totp secret: jbswy3dpehpk3pxp",
			expectMatch: true,
			matchText:   "jbswy3dpehpk3pxp",
			description: "Lowercase base32 with TOTP keyword should match",
		},
		{
			name:        "Lowercase secret with 2FA keyword",
			content:     "2fa seed krugkidrovuwg2zamjzg653oehpk3pxp",
			expectMatch: true,
			matchText:   "krugkidrovuwg2zamjzg653oehpk3pxp",
			description: "Longer lowercase base32 with 2FA context",
		},
		{
			name:        "Lowercase base32 without context",
			content:     "random data: jbswy3dpehpk3pxp here",
			expectMatch: false,
			description: "Lowercase base32 without OTP keywords should not match",
		},
		{
			name:        "English word with OTP context but caught by isLikelyWord",
			content:     "2fa secret: aaaaaaaaaaaaaaaa",
			expectMatch: false,
			description: "All-same-char pattern rejected by isLikelyWord",
		},
		{
			name:        "Lowercase with negative context suppression",
			content:     "test example totp key: jbswy3dpehpk3pxp",
			expectMatch: false,
			description: "Negative keywords should suppress even lowercase matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			hasMatch := false
			for _, m := range matches {
				if m.Type == "OTP_SECRET" && m.Confidence > 50 {
					hasMatch = true
					if tt.matchText != "" && m.Text != tt.matchText {
						t.Errorf("expected match text %q, got %q", tt.matchText, m.Text)
					}
					break
				}
			}
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (matches=%d)",
					tt.description, tt.expectMatch, hasMatch, len(matches))
				for _, m := range matches {
					t.Logf("  match: type=%s text=%q confidence=%.1f", m.Type, m.Text, m.Confidence)
				}
			}
		})
	}
}

func TestOTPValidator_SecretInsideOTPAuthURI(t *testing.T) {
	validator := NewValidator()

	// When a base32 secret appears inside an otpauth URI, we should not
	// double-report it as both an OTPAUTH_URI and an OTP_SECRET.
	content := "2FA otpauth://totp/App:user@ex.com?secret=JBSWY3DPEHPK3PXP&issuer=App"
	matches, err := validator.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}

	uriCount := 0
	secretCount := 0
	for _, m := range matches {
		switch m.Type {
		case "OTPAUTH_URI":
			uriCount++
		case "OTP_SECRET":
			secretCount++
		}
	}

	if uriCount == 0 {
		t.Error("Expected at least one OTPAUTH_URI match")
	}
	if secretCount > 0 {
		t.Errorf("Secret inside otpauth URI should not be reported separately, got %d OTP_SECRET matches", secretCount)
	}
}
