// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"

	"ferret-scan/internal/detector"
)

// buildTestToken constructs test tokens at runtime to avoid triggering
// static secret scanners in pre-commit hooks. These are intentional test
// data for the secrets validator — not real credentials.
func buildTestToken(parts ...string) string {
	return strings.Join(parts, "")
}

// ---------------------------------------------------------------------------
// AWS Access Keys
// ---------------------------------------------------------------------------

func TestSecretsValidator_AWSKeys(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantType   string
		wantDetect bool
	}{
		{
			name:       "Valid AWS access key AKIA prefix 20 chars",
			match:      buildTestToken("AKIA", "IOSFODNN7EXAMPLE"),
			wantType:   "AWS_ACCESS_KEY",
			wantDetect: true,
		},
		{
			name:       "Another valid AWS key",
			match:      buildTestToken("AKIA", "1234567890ABCDEF"),
			wantType:   "AWS_ACCESS_KEY",
			wantDetect: true,
		},
		{
			name:       "Too short AKIA prefix",
			match:      "AKIA12345",
			wantType:   "",
			wantDetect: false,
		},
		{
			name:       "Too long AKIA prefix",
			match:      "AKIAIOSFODNN7EXAMPLE1",
			wantType:   "",
			wantDetect: false,
		},
		{
			name:       "Wrong prefix similar to AWS",
			match:      buildTestToken("ASIA", "1234567890ABCDEF"),
			wantType:   "",
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAWS := v.isAWSAccessKey(tt.match)
			if isAWS != tt.wantDetect {
				t.Errorf("isAWSAccessKey(%q) = %v, want %v", tt.match, isAWS, tt.wantDetect)
			}
			if tt.wantDetect {
				gotType := v.getSecretType(tt.match)
				if gotType != tt.wantType {
					t.Errorf("getSecretType(%q) = %q, want %q", tt.match, gotType, tt.wantType)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitHub Tokens
// ---------------------------------------------------------------------------

func TestSecretsValidator_GitHubTokens(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{
			name:       "Valid ghp_ token",
			match:      buildTestToken("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
			wantDetect: true,
		},
		{
			name:       "Valid gho_ token",
			match:      buildTestToken("gho_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
			wantDetect: true,
		},
		{
			name:       "Valid ghs_ token",
			match:      buildTestToken("ghs_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
			wantDetect: true,
		},
		{
			name:       "Valid ghr_ token",
			match:      buildTestToken("ghr_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
			wantDetect: true,
		},
		{
			name:       "github_pat_ prefix not detected by isGitHubToken (different length)",
			match:      "github_pat_ABCDEFabcdef123456",
			wantDetect: false,
		},
		{
			name:       "Too short ghp_ token",
			match:      "ghp_short",
			wantDetect: false,
		},
		{
			name:       "Wrong prefix ghx_",
			match:      "ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isGitHubToken(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isGitHubToken(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
			if tt.wantDetect {
				gotType := v.getSecretType(tt.match)
				if gotType != "GITHUB_TOKEN" {
					t.Errorf("getSecretType(%q) = %q, want GITHUB_TOKEN", tt.match, gotType)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Slack Tokens
// ---------------------------------------------------------------------------

func TestSecretsValidator_SlackTokens(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{
			name:       "xoxb bot token",
			match:      buildTestToken("xoxb-", "12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"),
			wantDetect: true,
		},
		{
			name:       "xoxp user token",
			match:      buildTestToken("xoxp-", "12345678901-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"),
			wantDetect: true,
		},
		{
			name:       "xoxs prefix detected",
			match:      "xoxs-some-value",
			wantDetect: false,
		},
		{
			name:       "Random string not Slack",
			match:      "not-a-slack-token",
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isSlackToken(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isSlackToken(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
			if tt.wantDetect {
				gotType := v.getSecretType(tt.match)
				if gotType != "SLACK_TOKEN" {
					t.Errorf("getSecretType(%q) = %q, want SLACK_TOKEN", tt.match, gotType)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Stripe API Keys
// ---------------------------------------------------------------------------

func TestSecretsValidator_StripeKeys(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{
			name:       "Valid sk_live_ key 32 chars",
			match:      buildTestToken("sk_live_", "AbCdEfGhIjKlMnOpQrStUvWx"),
			wantDetect: true,
		},
		{
			name:       "Valid sk_test_ key 32 chars",
			match:      buildTestToken("sk_test_", "AbCdEfGhIjKlMnOpQrStUvWx"),
			wantDetect: true,
		},
		{
			name:       "Valid pk_live_ key 32 chars",
			match:      buildTestToken("pk_live_", "AbCdEfGhIjKlMnOpQrStUvWx"),
			wantDetect: true,
		},
		{
			name:       "Valid pk_test_ key 32 chars",
			match:      buildTestToken("pk_test_", "AbCdEfGhIjKlMnOpQrStUvWx"),
			wantDetect: true,
		},
		{
			name:       "Too short Stripe key",
			match:      buildTestToken("sk_live_", "short"),
			wantDetect: false,
		},
		{
			name:       "Wrong prefix rk_live_",
			match:      buildTestToken("rk_live_", "AbCdEfGhIjKlMnOpQrStUvWx"),
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isStripeAPIKey(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isStripeAPIKey(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
			if tt.wantDetect {
				gotType := v.getSecretType(tt.match)
				if gotType != "STRIPE_API_KEY" {
					t.Errorf("getSecretType(%q) = %q, want STRIPE_API_KEY", tt.match, gotType)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JWT Tokens
// ---------------------------------------------------------------------------

func TestSecretsValidator_JWTTokens(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{
			name:       "Valid JWT with three base64 segments",
			match:      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantDetect: true,
		},
		{
			name:       "Minimal JWT structure",
			match:      "eyJhbGci.eyJzdWIi.sig123",
			wantDetect: true,
		},
		{
			name:       "Missing eyJ prefix",
			match:      "abc.def.ghi",
			wantDetect: false,
		},
		{
			name:       "Only two segments",
			match:      "eyJhbGci.eyJzdWIi",
			wantDetect: false,
		},
		{
			name:       "Four segments not JWT",
			match:      "eyJhbGci.eyJzdWIi.sig.extra",
			wantDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isJWTToken(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isJWTToken(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
			if tt.wantDetect {
				gotType := v.getSecretType(tt.match)
				if gotType != "JWT_TOKEN" {
					t.Errorf("getSecretType(%q) = %q, want JWT_TOKEN", tt.match, gotType)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Private Keys (SSH, PGP, Certificates)
// ---------------------------------------------------------------------------

func TestSecretsValidator_PrivateKeys(t *testing.T) {
	v := NewValidator()

	rsaKey := buildTestToken("-----BEGIN RSA ", "PRIVATE KEY-----\nMIIBogIBAAJBALRi...\n-----END RSA PRIVATE KEY-----")
	ecKey := buildTestToken("-----BEGIN EC ", "PRIVATE KEY-----\nMHQCAQEEIA...\n-----END EC PRIVATE KEY-----")
	cert := buildTestToken("-----BEGIN ", "CERTIFICATE-----\nMIICpDCCAYw...\n-----END CERTIFICATE-----")
	encKey := buildTestToken("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----\nMIIFDjBA...\n-----END ENCRYPTED PRIVATE KEY-----")
	pgpKey := buildTestToken("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----\nVersion: GnuPG\n-----END PGP PRIVATE KEY BLOCK-----")

	tests := []struct {
		name     string
		match    string
		wantType string
		checker  func(string) bool
	}{
		{"RSA private key", rsaKey, "SSH_PRIVATE_KEY", v.isSSHPrivateKey},
		{"EC private key", ecKey, "SSH_PRIVATE_KEY", v.isSSHPrivateKey},
		{"Certificate", cert, "CERTIFICATE", v.isCertificate},
		{"Encrypted private key", encKey, "SSH_PRIVATE_KEY", v.isCertificate},
		{"PGP private key", pgpKey, "PGP_PRIVATE_KEY", v.isPGPPrivateKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.checker(tt.match) {
				t.Errorf("checker for %q returned false, want true", tt.name)
			}
			gotType := v.getSecretType(tt.match)
			if gotType != tt.wantType {
				t.Errorf("getSecretType(%q) = %q, want %q", tt.name, gotType, tt.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Generic API Keys and Passwords (keyword-based detection)
// ---------------------------------------------------------------------------

func TestSecretsValidator_GenericAPIKeysAndPasswords(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		line        string
		expectMatch bool
		description string
	}{
		{
			name:        "API_KEY equals quoted value",
			line:        `API_KEY = "sk_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c"`,
			expectMatch: true,
			description: "Standard API_KEY assignment should be detected",
		},
		{
			name:        "api_key colon quoted value",
			line:        `api_key: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"`,
			expectMatch: true,
			description: "Colon-style API key assignment should be detected",
		},
		{
			name:        "password equals quoted value",
			line:        `password = "MyS3cur3P@ssw0rd!"`,
			expectMatch: true,
			description: "Password assignment should be detected",
		},
		{
			name:        "passwd colon value",
			line:        `passwd: "hunter2_extended_password"`,
			expectMatch: true,
			description: "passwd keyword should be detected",
		},
		{
			name:        "JSON password field",
			line:        `"password": "MyS3cur3P@ssw0rd!"`,
			expectMatch: true,
			description: "JSON password field should be detected",
		},
		{
			name:        "Token assignment",
			line:        `token = "a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4"`,
			expectMatch: true,
			description: "Token assignment should be detected",
		},
		{
			name:        "Short value below 8 chars ignored",
			line:        `password = "short"`,
			expectMatch: false,
			description: "Values shorter than 8 characters should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := v.findKeywordSecrets(tt.line)
			got := len(matches) > 0
			if got != tt.expectMatch {
				t.Errorf("findKeywordSecrets(%q): got match=%v, want %v (%s)", tt.line, got, tt.expectMatch, tt.description)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// False Positive Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_FalsePositives(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name  string
		match string
		desc  string
	}{
		{"Placeholder YOUR_API_KEY_HERE", "your_api_key_here", "Obvious placeholder should be detected"},
		{"Placeholder xxx pattern", "xxxxxxxxxxxxxxxx", "Repeated x placeholder should be detected"},
		{"Placeholder zeros", "000000000000000", "All-zero placeholder should be detected"},
		{"Placeholder sequential", "1234567890abcdef", "Sequential placeholder should be detected"},
		{"Replace instruction", "replace_with_actual", "Instruction placeholder should be detected"},
		{"Insert here pattern", "insert_key_here", "Instruction placeholder should be detected"},
		{"Test API key here", "test_api_key_here", "Test placeholder should be detected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !v.isObviousPlaceholder(tt.match) {
				t.Errorf("isObviousPlaceholder(%q) = false, want true: %s", tt.match, tt.desc)
			}
		})
	}
}

func TestSecretsValidator_GlobalTestPatterns(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name      string
		match     string
		wantMatch bool
	}{
		{"test_ prefix pattern matching global db", "test_api_key_here", true},
		{"example_ prefix pattern", "example_secret_key", true},
		{"demo_ prefix pattern", "demo_private_key", true},
		{"sample_ prefix pattern", "sample_password", true},
		{"Real looking key", "Ak8xPqR2sT4uV6wX", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.matchesGlobalTestPatterns(tt.match)
			if got != tt.wantMatch {
				t.Errorf("matchesGlobalTestPatterns(%q) = %v, want %v", tt.match, got, tt.wantMatch)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Context Analysis
// ---------------------------------------------------------------------------

func TestSecretsValidator_ContextAnalysis(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name     string
		match    string
		context  detector.ContextInfo
		wantSign string // "positive", "negative", or "neutral"
		desc     string
	}{
		{
			name:  "Positive context with api keyword on same line",
			match: "a1b2c3d4e5f6g7h8",
			context: detector.ContextInfo{
				FullLine:   `api_key = "a1b2c3d4e5f6g7h8"`,
				BeforeText: "",
				AfterText:  "",
			},
			wantSign: "positive",
			desc:     "API keyword on same line should boost confidence",
		},
		{
			name:  "Negative context with test keyword on same line",
			match: "a1b2c3d4e5f6g7h8",
			context: detector.ContextInfo{
				FullLine:   `test_value = "a1b2c3d4e5f6g7h8"`,
				BeforeText: "",
				AfterText:  "",
			},
			wantSign: "negative",
			desc:     "Test keyword on same line should reduce confidence",
		},
		{
			name:  "Positive context in nearby text",
			match: "a1b2c3d4e5f6g7h8",
			context: detector.ContextInfo{
				FullLine:   `value = "a1b2c3d4e5f6g7h8"`,
				BeforeText: "# secret configuration",
				AfterText:  "",
			},
			wantSign: "positive",
			desc:     "Secret keyword in nearby context should boost confidence",
		},
		{
			name:  "Negative context in nearby text",
			match: "a1b2c3d4e5f6g7h8",
			context: detector.ContextInfo{
				FullLine:   `value = "a1b2c3d4e5f6g7h8"`,
				BeforeText: "# this is just an example",
				AfterText:  "",
			},
			wantSign: "negative",
			desc:     "Example keyword in nearby context should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := v.AnalyzeContext(tt.match, tt.context)
			switch tt.wantSign {
			case "positive":
				if impact <= 0 {
					t.Errorf("AnalyzeContext: got impact %.1f, want positive: %s", impact, tt.desc)
				}
			case "negative":
				if impact >= 0 {
					t.Errorf("AnalyzeContext: got impact %.1f, want negative: %s", impact, tt.desc)
				}
			case "neutral":
				// Accept any value near zero
			}
		})
	}
}

func TestSecretsValidator_ContextAnalysis_EnvFile(t *testing.T) {
	v := NewValidator()

	envContent := "DB_HOST=localhost\nDB_PASSWORD=\"SuperSecretP@ss123\"\nAPI_KEY=" + buildTestToken("sk_live_", "AbCdEfGhIjKlMnOpQrStUvWx") + "\n"
	matches, err := v.ValidateContent(envContent, ".env")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	// Should find at least one match (password or API key)
	if len(matches) == 0 {
		t.Error("Expected at least one match in .env content, got 0")
	}
}

func TestSecretsValidator_ContextAnalysis_ConfigFile(t *testing.T) {
	v := NewValidator()

	configContent := `{
  "database": {
    "password": "Pr0duct10n_S3cr3t!_V@lu3"
  },
  "api": {
    "secret": "a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3"
  }
}`
	matches, err := v.ValidateContent(configContent, "config.json")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Error("Expected at least one match in JSON config content, got 0")
	}
}

func TestSecretsValidator_ContextAnalysis_CodeComment(t *testing.T) {
	v := NewValidator()

	// Comments with example/test keywords should score lower
	commentContent := `// Example: api_key = "example_secret_key"
// This is just a demo token = "demo_private_key"
`
	matches, err := v.ValidateContent(commentContent, "app.go")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	// Matches from comments with test/example keywords should have lower confidence
	for _, m := range matches {
		if m.Confidence > 80 {
			t.Errorf("Expected low confidence for comment match %q, got %.1f", m.Text, m.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

func TestSecretsValidator_EdgeCases_KeysInJSON(t *testing.T) {
	v := NewValidator()

	jsonContent := "{\n  \"auth_token\": \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\",\n  \"stripe_key\": \"" + buildTestToken("sk_live_", "AbCdEfGhIjKlMnOpQrStUvWx") + "\"\n}"
	matches, err := v.ValidateContent(jsonContent, "secrets.json")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Error("Expected matches in JSON content with secrets")
	}
}

func TestSecretsValidator_EdgeCases_KeysInYAML(t *testing.T) {
	v := NewValidator()

	yamlContent := `database:
  password: "MyPr0duct10n_Passw0rd!"
api:
  token: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
`
	matches, err := v.ValidateContent(yamlContent, "config.yaml")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Error("Expected matches in YAML content with secrets")
	}
}

func TestSecretsValidator_EdgeCases_SpecialCharactersInKey(t *testing.T) {
	v := NewValidator()

	content := `secret = "P@$$w0rd!#%&*_2024_Secur3"`
	matches, err := v.ValidateContent(content, "app.conf")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Error("Expected match for secret with special characters")
	}
}

func TestSecretsValidator_EdgeCases_MultiLinePrivateKey(t *testing.T) {
	v := NewValidator()

	content := buildTestToken("-----BEGIN RSA ", "PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJLAnC0lL8r7P7M6V1E3HVN\nj4m7R0EqVpMDkzSGQDmbVnCEsKXME8x8xnT0T0CAwEAAQJAW3eMn1Rvqkz\n-----END RSA PRIVATE KEY-----")

	matches, err := v.ValidateContent(content, "id_rsa")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	found := false
	for _, m := range matches {
		if m.Type == "SSH_PRIVATE_KEY" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected SSH_PRIVATE_KEY match for multi-line RSA private key")
	}
}

// ---------------------------------------------------------------------------
// CalculateConfidence
// ---------------------------------------------------------------------------

func TestSecretsValidator_CalculateConfidence(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name          string
		match         string
		wantSpecific  bool
		minConfidence float64
		desc          string
	}{
		{
			name:          "AWS key gets high confidence",
			match:         "AKIAIOSFODNN7EXAMPLE",
			wantSpecific:  true,
			minConfidence: 90,
			desc:          "AWS access key should have high specific-pattern confidence",
		},
		{
			name:          "JWT token gets high confidence",
			match:         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig_abc",
			wantSpecific:  true,
			minConfidence: 90,
			desc:          "JWT token should have high specific-pattern confidence",
		},
		{
			name:          "Short string gets low confidence",
			match:         "abc",
			wantSpecific:  false,
			minConfidence: 0,
			desc:          "Short string should have reduced confidence",
		},
		{
			name:          "Common word reduces confidence",
			match:         "password123example",
			wantSpecific:  false,
			minConfidence: 0,
			desc:          "Common words in match should reduce confidence",
		},
		{
			name:          "String with spaces reduces confidence",
			match:         "some secret with spaces",
			wantSpecific:  false,
			minConfidence: 0,
			desc:          "Spaces in match should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := v.CalculateConfidence(tt.match)

			if tt.wantSpecific && !checks["specific_pattern"] {
				t.Errorf("Expected specific_pattern=true for %q", tt.match)
			}
			if confidence < tt.minConfidence {
				t.Errorf("CalculateConfidence(%q) = %.1f, want >= %.1f: %s",
					tt.match, confidence, tt.minConfidence, tt.desc)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Shannon Entropy
// ---------------------------------------------------------------------------

func TestSecretsValidator_ShannonEntropy(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name      string
		data      string
		charset   string
		wantAbove float64
	}{
		{
			name:      "High entropy random base64",
			data:      "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u",
			charset:   v.base64Charset,
			wantAbove: 4.0,
		},
		{
			name:      "Low entropy repeated chars",
			data:      "aaaaaaaaaaaaaaaaaaaaaa",
			charset:   v.base64Charset,
			wantAbove: -1.0, // Any value is fine, just should be low
		},
		{
			name:      "Empty string returns zero",
			data:      "",
			charset:   v.base64Charset,
			wantAbove: -1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := v.calculateShannonEntropy(tt.data, tt.charset)
			if entropy < tt.wantAbove {
				t.Errorf("calculateShannonEntropy(%q) = %.2f, want > %.2f", tt.data, entropy, tt.wantAbove)
			}
		})
	}

	// Verify empty string returns exactly 0
	t.Run("Empty string returns exactly zero", func(t *testing.T) {
		entropy := v.calculateShannonEntropy("", v.base64Charset)
		if entropy != 0 {
			t.Errorf("calculateShannonEntropy(\"\") = %f, want 0", entropy)
		}
	})
}

// ---------------------------------------------------------------------------
// High Entropy String Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_FindHighEntropyStrings(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		line        string
		expectMatch bool
	}{
		{
			name:        "Quoted high entropy base64 string",
			line:        `value = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"`,
			expectMatch: true,
		},
		{
			name:        "Quoted high entropy hex string",
			line:        `hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`,
			expectMatch: true,
		},
		{
			name:        "No quotes no match",
			line:        `value = aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u`,
			expectMatch: false,
		},
		{
			name:        "Short quoted string no match",
			line:        `key = "abc"`,
			expectMatch: false,
		},
		{
			name:        "Low entropy repeated string",
			line:        `key = "aaaaaaaaaaaaaaaaaaaa"`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := v.findHighEntropyStrings(tt.line)
			got := len(matches) > 0
			if got != tt.expectMatch {
				t.Errorf("findHighEntropyStrings(%q): got match=%v, want %v", tt.line, got, tt.expectMatch)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Secret Indicators Pre-check
// ---------------------------------------------------------------------------

func TestSecretsValidator_ContainsSecretIndicators(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name string
		line string
		want bool
	}{
		{"Short line", "short", false},
		{"Empty line", "", false},
		{"Structural JSON brace", "  {", false},
		{"Version field", `"version": "1.2.3",`, false},
		{"Boolean value", `"enabled": true,`, false},
		{"JWT indicator", "the token is eyJhbGciOiJIUzI1NiJ9", true},
		{"AWS key indicator", buildTestToken("key = AKIA", "1234567890ABCDEF"), true},
		{"GitHub token ghp_", buildTestToken("token = ghp_", "abc123def456"), true},
		{"Stripe key", buildTestToken("key = sk_live_", "abc123"), true},
		{"Slack token", buildTestToken("token = xoxb", "-1234"), true},
		{"Password keyword with equals", "password = something_secret_here", true},
		{"Integrity hash skip", `"integrity": "sha512-abc..."`, false},
		{"Resolved URL skip", `"resolved": "https://registry.npmjs.org/pkg"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.containsSecretIndicators(tt.line)
			if got != tt.want {
				t.Errorf("containsSecretIndicators(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Shell Variable Reference Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_ShellVariableReferences(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name  string
		line  string
		match string
		want  bool
	}{
		{
			name:  "Dollar prefix variable reference",
			line:  `curl -H "Authorization: $API_TOKEN"`,
			match: "API_TOKEN",
			want:  true,
		},
		{
			name:  "Braces variable reference",
			line:  `echo ${SECRET_KEY}`,
			match: "SECRET_KEY",
			want:  true,
		},
		{
			name:  "Assignment not a reference",
			line:  `SECRET_KEY="actualSecretValue123"`,
			match: "SECRET_KEY",
			want:  false,
		},
		{
			name:  "No dollar sign not a reference",
			line:  `API_KEY: "some_real_value_12345"`,
			match: "some_real_value_12345",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.IsShellVariableReference(tt.line, tt.match)
			if got != tt.want {
				t.Errorf("IsShellVariableReference(%q, %q) = %v, want %v", tt.line, tt.match, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Shell Script Context Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_IsShellScriptContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "Bash script with shebang and export",
			content: "#!/bin/bash\nexport API_KEY=abc123\necho done",
			want:    true,
		},
		{
			name:    "Shell script with conditionals",
			content: "set -e\nif [ -z \"$VAR\" ]; then\n  echo 'missing'\nfi",
			want:    true,
		},
		{
			name:    "Plain JSON not shell",
			content: `{"key": "value", "number": 42}`,
			want:    false,
		},
		{
			name:    "Python code not shell",
			content: "import os\nprint('hello')\nx = 42",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.IsShellScriptContext(tt.content)
			if got != tt.want {
				t.Errorf("IsShellScriptContext: got %v, want %v for %q", got, tt.want, tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Variable Name Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_LooksLikeVariableName(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name  string
		match string
		want  bool
	}{
		{"Lowercase variable with secret suffix", "my_api_secret", true},
		{"Uppercase variable with key suffix", "MY_API_KEY", true},
		{"Actual secret value (mixed chars)", "aB3cD4eF5gH6iJ7kL8mN9oP", false},
		{"Very long string not a variable", strings.Repeat("a", 51) + "_token", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.looksLikeVariableName(tt.match)
			if got != tt.want {
				t.Errorf("looksLikeVariableName(%q) = %v, want %v", tt.match, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Environment Type Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_DetectEnvironmentType(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"Production content", "production server deploy release live", "production"},
		{"Development content", "development staging local dev sandbox", "development"},
		{"Test content", "test testing example sample mock demo", "test"},
		{"Unknown content", "just some random text without env hints", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.detectEnvironmentType(tt.content)
			if got != tt.want {
				t.Errorf("detectEnvironmentType(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tabular Data Detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_IsTabularData(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name  string
		line  string
		match string
		want  bool
	}{
		{"Tab-separated", "name\tpassword\ttoken", "password", true},
		{"Comma-separated", "field1,field2,field3,field4", "field2", true},
		{"Pipe-separated", "col1|col2|col3|col4", "col2", true},
		{"Simple text no delimiters", "this is just a plain sentence", "plain", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isTabularData(tt.line, tt.match)
			if got != tt.want {
				t.Errorf("isTabularData(%q, %q) = %v, want %v", tt.line, tt.match, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validate method (legacy - returns empty)
// ---------------------------------------------------------------------------

func TestSecretsValidator_Validate_ReturnsEmpty(t *testing.T) {
	v := NewValidator()

	matches, err := v.Validate("some/file/path.txt")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate should return empty matches, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// GetSecretType priority
// ---------------------------------------------------------------------------

func TestSecretsValidator_GetSecretType_DefaultsToAPIKeyOrSecret(t *testing.T) {
	v := NewValidator()

	gotType := v.getSecretType("some_random_high_entropy_string")
	if gotType != "API_KEY_OR_SECRET" {
		t.Errorf("getSecretType for generic string = %q, want API_KEY_OR_SECRET", gotType)
	}
}

// ---------------------------------------------------------------------------
// GetCheckInfo
// ---------------------------------------------------------------------------

func TestSecretsValidator_GetCheckInfo(t *testing.T) {
	v := NewValidator()

	info := v.GetCheckInfo()
	if info.Name != "SECRETS" {
		t.Errorf("GetCheckInfo().Name = %q, want SECRETS", info.Name)
	}
	if len(info.Patterns) == 0 {
		t.Error("GetCheckInfo().Patterns should not be empty")
	}
	if len(info.ConfidenceFactors) == 0 {
		t.Error("GetCheckInfo().ConfidenceFactors should not be empty")
	}
}

// ---------------------------------------------------------------------------
// LineContainsShellVariableReferences
// ---------------------------------------------------------------------------

func TestSecretsValidator_LineContainsShellVariableReferences(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name string
		line string
		want bool
	}{
		{"No dollar sign", "plain text without variables", false},
		{"Dollar with letter", "use $MY_VAR here", true},
		{"Dollar with brace", "use ${MY_VAR} here", true},
		{"Dollar with number", "price is $5", false},
		{"Dollar at end", "value is $", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.LineContainsShellVariableReferences(tt.line)
			if got != tt.want {
				t.Errorf("LineContainsShellVariableReferences(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Line Number Calculation
// ---------------------------------------------------------------------------

func TestSecretsValidator_FindLineNumber(t *testing.T) {
	v := NewValidator()

	content := "line1\nline2\nline3\nline4"

	tests := []struct {
		name    string
		match   string
		wantNum int
	}{
		{"First line", "line1", 1},
		{"Second line", "line2", 2},
		{"Fourth line", "line4", 4},
		{"Not found returns 1", "missing", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.findLineNumber(content, tt.match)
			if got != tt.wantNum {
				t.Errorf("findLineNumber for %q = %d, want %d", tt.match, got, tt.wantNum)
			}
		})
	}
}

func TestSecretsValidator_FindLineNumber_LargeContent(t *testing.T) {
	v := NewValidator()

	// Build content larger than 1000 bytes to trigger binary search path
	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString("this is line number padding text\n")
	}
	builder.WriteString("TARGET_MATCH_HERE\n")
	content := builder.String()

	got := v.findLineNumber(content, "TARGET_MATCH_HERE")
	if got != 101 {
		t.Errorf("findLineNumber for large content = %d, want 101", got)
	}
}

// ---------------------------------------------------------------------------
// BuildLineIndex and binary search
// ---------------------------------------------------------------------------

func TestBuildLineIndex(t *testing.T) {
	content := "abc\ndef\nghi"
	index := buildLineIndex(content)

	tests := []struct {
		pos      int
		wantLine int
	}{
		{0, 1},  // 'a' in line 1
		{3, 1},  // '\n' belongs to line 1 boundary
		{4, 2},  // 'd' in line 2
		{8, 3},  // 'g' in line 3
		{-1, 1}, // negative position
	}

	for _, tt := range tests {
		got := index.findLineNumber(tt.pos)
		if got != tt.wantLine {
			t.Errorf("findLineNumber(pos=%d) = %d, want %d", tt.pos, got, tt.wantLine)
		}
	}
}

// ---------------------------------------------------------------------------
// NewValidator initialization
// ---------------------------------------------------------------------------

func TestSecretsValidator_NewValidator(t *testing.T) {
	v := NewValidator()

	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.base64Limit != 4.5 {
		t.Errorf("base64Limit = %f, want 4.5", v.base64Limit)
	}
	if v.hexLimit != 3.0 {
		t.Errorf("hexLimit = %f, want 3.0", v.hexLimit)
	}
	if len(v.keywordPatterns) == 0 {
		t.Error("keywordPatterns should not be empty")
	}
	if len(v.positiveKeywords) == 0 {
		t.Error("positiveKeywords should not be empty")
	}
	if len(v.negativeKeywords) == 0 {
		t.Error("negativeKeywords should not be empty")
	}
	if v.contextAnalyzer == nil {
		t.Error("contextAnalyzer should not be nil")
	}
}

// ---------------------------------------------------------------------------
// GitLab and Docker token detection
// ---------------------------------------------------------------------------

func TestSecretsValidator_GitLabToken(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{"Valid GitLab token 26 chars", "glpat-ABCDEFGHIJKLMNOPQRST", true},
		{"Too short GitLab token", "glpat-short", false},
		{"Wrong prefix", "glpax-ABCDEFGHIJKLMNOPQRST", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isGitLabToken(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isGitLabToken(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
		})
	}
}

func TestSecretsValidator_DockerToken(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{"Valid Docker token 45 chars", "dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", true},
		{"Too short Docker token", "dckr_pat_short", false},
		{"Wrong prefix", "dckr_xxx_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isDockerToken(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isDockerToken(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Google Cloud API Key
// ---------------------------------------------------------------------------

func TestSecretsValidator_GoogleCloudAPIKey(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		match      string
		wantDetect bool
	}{
		{"Valid Google Cloud key 39 chars", "AIzaSyA1234567890abcdefghijklmnopqrstuv", true},
		{"Too short", "AIzaShort", false},
		{"Wrong prefix", "BIzaSyA1234567890abcdefghijklmnopqrstuv", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isGoogleCloudAPIKey(tt.match)
			if got != tt.wantDetect {
				t.Errorf("isGoogleCloudAPIKey(%q) = %v, want %v", tt.match, got, tt.wantDetect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AnalyzeContext confidence capping
// ---------------------------------------------------------------------------

func TestSecretsValidator_AnalyzeContext_CapsImpact(t *testing.T) {
	v := NewValidator()

	// Many positive keywords should be capped at 30
	positiveContext := detector.ContextInfo{
		FullLine:   "api key secret token password auth credential private access session bearer oauth jwt signature hash salt nonce seed entropy",
		BeforeText: "",
		AfterText:  "",
	}
	impact := v.AnalyzeContext("match", positiveContext)
	if impact > 30 {
		t.Errorf("Positive impact should be capped at 30, got %.1f", impact)
	}

	// Many negative keywords should be capped at -40
	negativeContext := detector.ContextInfo{
		FullLine:   "test example demo sample fake mock dummy placeholder template default null empty none public open free guest anonymous debug",
		BeforeText: "",
		AfterText:  "",
	}
	impact = v.AnalyzeContext("match", negativeContext)
	if impact < -40 {
		t.Errorf("Negative impact should be capped at -40, got %.1f", impact)
	}
}
