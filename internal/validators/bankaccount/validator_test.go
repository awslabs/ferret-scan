// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"context"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func TestBankAccountValidator_ABA_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		matchType   string
		description string
	}{
		{
			name:        "ABA with routing keyword",
			content:     "Routing number: 021000089",
			expectMatch: true,
			matchType:   "ABA_ROUTING",
			description: "Valid ABA routing number with keyword",
		},
		{
			name:        "ABA with bank keyword",
			content:     "Bank routing: 011401533",
			expectMatch: true,
			matchType:   "ABA_ROUTING",
			description: "Valid ABA with bank keyword",
		},
		{
			name:        "ABA with ACH keyword",
			content:     "ACH transfer routing 071000013",
			expectMatch: true,
			matchType:   "ABA_ROUTING",
			description: "Valid ABA with ACH keyword",
		},
		{
			name:        "ABA with wire transfer context",
			content:     "Wire transfer routing number: 026009593",
			expectMatch: true,
			matchType:   "ABA_ROUTING",
			description: "Valid ABA with wire transfer context",
		},
		{
			name:        "ABA with direct deposit",
			content:     "Direct deposit routing: 121000248",
			expectMatch: true,
			matchType:   "ABA_ROUTING",
			description: "Valid ABA with direct deposit keyword",
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
			if hasMatch && tt.matchType != "" {
				found := false
				for _, m := range matches {
					if m.Type == tt.matchType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected Type=%s, got types: %v", tt.matchType, matchTypes(matches))
				}
			}
			if hasMatch {
				for _, m := range matches {
					if m.Validator != "bank_account" {
						t.Errorf("expected Validator=bank_account, got=%s", m.Validator)
					}
				}
			}
		})
	}
}

func TestBankAccountValidator_ABA_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Phone number",
			content:     "Phone: 555-123-4567",
			description: "Phone numbers should not match as ABA",
		},
		{
			name:        "ZIP code",
			content:     "ZIP code: 123456789",
			description: "ZIP codes should not match",
		},
		{
			name:        "Test routing 011000015",
			content:     "Routing: 011000015",
			description: "Known test routing number should be suppressed",
		},
		{
			name:        "Test routing 021000021",
			content:     "Routing: 021000021",
			description: "Known test routing number should be suppressed",
		},
		{
			name:        "All same digits",
			content:     "Routing: 111111111",
			description: "Repeating digits are test numbers",
		},
		{
			name:        "Serial number context",
			content:     "Serial number: 071000013",
			description: "Serial context should suppress",
		},
		{
			name:        "Nine digit number without context",
			content:     "The code is 071000013",
			description: "Bare 9-digit number without banking keywords should not match",
		},
		{
			name:        "Invalid prefix 99",
			content:     "Routing: 991000013",
			description: "ABA prefix 99 is invalid",
		},
		{
			name:        "Invalid checksum",
			content:     "Routing: 021000088",
			description: "Valid prefix but invalid checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// Filter for ABA_ROUTING specifically
			abaMatches := filterByType(matches, "ABA_ROUTING")
			if len(abaMatches) > 0 {
				t.Errorf("%s: expected no ABA_ROUTING match, got %d (confidence: %.1f)",
					tt.description, len(abaMatches), abaMatches[0].Confidence)
			}
		})
	}
}

func TestBankAccountValidator_IBAN_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "German IBAN",
			content:     "IBAN: DE89370400440532013000",
			expectMatch: true,
			description: "Valid German IBAN with keyword",
		},
		{
			name:        "UK IBAN",
			content:     "Account IBAN GB29NWBK60161331926819",
			expectMatch: true,
			description: "Valid UK IBAN",
		},
		{
			name:        "French IBAN",
			content:     "Wire to IBAN FR7630006000011234567890189",
			expectMatch: true,
			description: "Valid French IBAN",
		},
		{
			name:        "Dutch IBAN",
			content:     "Transfer to NL91ABNA0417164300",
			expectMatch: true,
			description: "Valid Dutch IBAN (no keyword but valid checksum)",
		},
		{
			name:        "Swiss IBAN",
			content:     "Bank account: CH9300762011623852957",
			expectMatch: true,
			description: "Valid Swiss IBAN with bank account keyword",
		},
		{
			name:        "Spanish IBAN",
			content:     "IBAN ES9121000418450200051332",
			expectMatch: true,
			description: "Valid Spanish IBAN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			ibanMatches := filterByType(matches, "IBAN")
			hasMatch := len(ibanMatches) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v", tt.description, tt.expectMatch, hasMatch)
			}
			if hasMatch {
				if ibanMatches[0].Validator != "bank_account" {
					t.Errorf("expected Validator=bank_account, got=%s", ibanMatches[0].Validator)
				}
			}
		})
	}
}

func TestBankAccountValidator_IBAN_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Invalid checksum",
			content:     "IBAN: DE00370400440532013000",
			description: "IBAN with invalid check digits should not match",
		},
		{
			name:        "Wrong length for country",
			content:     "IBAN: DE8937040044053201300",
			description: "German IBAN must be 22 chars",
		},
		{
			name:        "Invalid country code",
			content:     "IBAN: XX89370400440532013000",
			description: "Invalid country code should not match",
		},
		{
			name:        "Check digits 00",
			content:     "Transfer: GB00NWBK60161331926819",
			description: "Check digits 00 are never valid",
		},
		{
			name:        "Too short",
			content:     "IBAN: DE8937040044",
			description: "Too short to be a valid IBAN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			ibanMatches := filterByType(matches, "IBAN")
			if len(ibanMatches) > 0 {
				t.Errorf("%s: expected no IBAN match, got %d", tt.description, len(ibanMatches))
			}
		})
	}
}

func TestBankAccountValidator_SWIFT_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "SWIFT with keyword",
			content:     "SWIFT code: DEUTDEFF",
			expectMatch: true,
			description: "Valid 8-char SWIFT with keyword",
		},
		{
			name:        "BIC with keyword",
			content:     "BIC: COBADEFFXXX",
			expectMatch: true,
			description: "Valid 11-char SWIFT/BIC with keyword",
		},
		{
			name:        "SWIFT in wire context",
			content:     "Wire transfer SWIFT: BNPAFRPP",
			expectMatch: true,
			description: "SWIFT with wire context",
		},
		{
			name:        "Bank SWIFT code",
			content:     "Bank SWIFT/BIC: CHASUS33",
			expectMatch: true,
			description: "SWIFT with bank keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			swiftMatches := filterByType(matches, "SWIFT_BIC")
			hasMatch := len(swiftMatches) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (all matches: %v)",
					tt.description, tt.expectMatch, hasMatch, matchTypes(matches))
			}
		})
	}
}

func TestBankAccountValidator_SWIFT_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Random 8-letter word",
			content:     "The word BASEBALL is used in sports",
			description: "Common English words should not match",
		},
		{
			name:        "Invalid country code in SWIFT",
			content:     "SWIFT: DEUTXXFF",
			description: "XX is not a valid country code",
		},
		{
			name:        "Too short",
			content:     "SWIFT: DEUT",
			description: "4 chars is too short for SWIFT",
		},
		{
			name:        "Lowercase letters",
			content:     "swift: deutdeff",
			description: "SWIFT codes are uppercase (regex may catch but validation should handle)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			swiftMatches := filterByType(matches, "SWIFT_BIC")
			if len(swiftMatches) > 0 {
				t.Errorf("%s: expected no SWIFT_BIC match, got %d (confidence: %.1f)",
					tt.description, len(swiftMatches), swiftMatches[0].Confidence)
			}
		})
	}
}

func TestBankAccountValidator_USAccount_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Account number with keyword",
			content:     "Bank account number: 12345678901",
			expectMatch: true,
			description: "11-digit account number with bank account keyword",
		},
		{
			name:        "Checking account",
			content:     "Checking account: 9876543210",
			expectMatch: true,
			description: "10-digit number with checking keyword",
		},
		{
			name:        "Savings account",
			content:     "Savings account number: 1234567890123",
			expectMatch: true,
			description: "13-digit number with savings keyword",
		},
		{
			name:        "ACH account",
			content:     "ACH deposit account 87654321",
			expectMatch: true,
			description: "8-digit number with ACH keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
			hasMatch := len(acctMatches) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (all matches: %v)",
					tt.description, tt.expectMatch, hasMatch, matchTypes(matches))
			}
		})
	}
}

func TestBankAccountValidator_USAccount_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Phone number",
			content:     "Call us at 5551234567",
			description: "10-digit phone number without bank context",
		},
		{
			name:        "No banking keywords",
			content:     "Order number: 12345678901",
			description: "Digit sequence without any banking context",
		},
		{
			name:        "Version string",
			content:     "Bank version 12345678",
			description: "Version context should suppress despite bank keyword",
		},
		{
			name:        "Tracking number",
			content:     "Tracking number: 12345678901234",
			description: "Tracking context without banking keywords",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
			if len(acctMatches) > 0 {
				t.Errorf("%s: expected no US_BANK_ACCOUNT match, got %d (confidence: %.1f)",
					tt.description, len(acctMatches), acctMatches[0].Confidence)
			}
		})
	}
}

// TestBankAccountValidator_VersionSubstring locks the looksLikeVersion whole-word
// fix: "version" as a bare substring inside "conversion"/"subversion"/"aversion"
// wrongly suppressed a real account number that happened to follow one of those
// words. Whole-word matching detects the account again, while a genuine "version"
// label and a "v.N" prefix still suppress.
func TestBankAccountValidator_VersionSubstring(t *testing.T) {
	validator := NewValidator()

	// Recovered: "conversion"/"subversion" must NOT suppress a banking-context account.
	for _, content := range []string{
		"checking conversion 12345678901",
		"savings subversion 98765432100",
	} {
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(filterByType(matches, "US_BANK_ACCOUNT")) == 0 {
			t.Errorf("expected US_BANK_ACCOUNT for %q (version-substring must not suppress), got none", content)
		}
	}

	// Still suppressed: a genuine version label / v.N prefix.
	for _, content := range []string{
		"checking version 12345678901",
		"savings v.2 12345678901",
	} {
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(filterByType(matches, "US_BANK_ACCOUNT")) > 0 {
			t.Errorf("expected version context to suppress account for %q, got a match", content)
		}
	}
}

func TestBankAccountValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name            string
		content         string
		expectHighConf  bool // confidence >= 70
		expectDetection bool
		description     string
	}{
		{
			name:            "Positive banking context boosts confidence",
			content:         "Wire transfer routing number for direct deposit: 021000089",
			expectHighConf:  true,
			expectDetection: true,
			description:     "Multiple positive keywords should boost confidence",
		},
		{
			name:            "Negative context suppresses",
			content:         "This is a test example sample routing 021000089",
			expectDetection: false,
			description:     "Multiple negative keywords should suppress the match",
		},
		{
			name:            "Mixed context resolved",
			content:         "Bank test account routing: 021000089",
			expectDetection: true,
			description:     "Bank keyword present but test also present -- bank wins for ABA with valid checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			hasMatch := len(matches) > 0
			if hasMatch != tt.expectDetection {
				t.Errorf("%s: expected detection=%v, got=%v (matches: %d)",
					tt.description, tt.expectDetection, hasMatch, len(matches))
			}
			if hasMatch && tt.expectHighConf {
				if matches[0].Confidence < 70 {
					t.Errorf("%s: expected confidence >= 70, got %.1f",
						tt.description, matches[0].Confidence)
				}
			}
		})
	}
}

func TestBankAccountValidator_EdgeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Empty input",
			content:     "",
			expectMatch: false,
			description: "Empty string should produce no matches",
		},
		{
			name:        "Single character",
			content:     "A",
			expectMatch: false,
			description: "Single character should produce no matches",
		},
		{
			name:        "Only whitespace",
			content:     "   \t\n   ",
			expectMatch: false,
			description: "Whitespace-only should produce no matches",
		},
		{
			name:        "Unicode content",
			content:     "Kontonummer: DE89370400440532013000 Uberweisung",
			expectMatch: true,
			description: "Valid IBAN in unicode context should still be detected",
		},
		{
			name:        "Multiple IBANs on one line",
			content:     "IBAN: DE89370400440532013000 and GB29NWBK60161331926819",
			expectMatch: true,
			description: "Multiple valid IBANs should both be detected",
		},
		{
			name:        "Multiline content",
			content:     "Line 1\nRouting: 021000089\nLine 3",
			expectMatch: true,
			description: "Match on non-first line should work",
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
		})
	}
}

func TestBankAccountValidator_CalculateConfidence(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name       string
		match      string
		minConf    float64
		maxConf    float64
		checkKey   string
		checkValue bool
	}{
		{
			name:       "Valid ABA",
			match:      "021000089",
			minConf:    60.0,
			maxConf:    100.0,
			checkKey:   "checksum",
			checkValue: true,
		},
		{
			name:       "Test ABA",
			match:      "123456789",
			minConf:    0.0,
			maxConf:    30.0,
			checkKey:   "not_test",
			checkValue: false,
		},
		{
			name:       "Valid IBAN",
			match:      "DE89370400440532013000",
			minConf:    80.0,
			maxConf:    100.0,
			checkKey:   "checksum",
			checkValue: true,
		},
		{
			name:       "Invalid IBAN",
			match:      "DE00370400440532013000",
			minConf:    0.0,
			maxConf:    40.0,
			checkKey:   "checksum",
			checkValue: false,
		},
		{
			name:       "Valid SWIFT",
			match:      "DEUTDEFF",
			minConf:    50.0,
			maxConf:    100.0,
			checkKey:   "valid_country",
			checkValue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := validator.CalculateConfidence(tt.match)
			if confidence < tt.minConf || confidence > tt.maxConf {
				t.Errorf("confidence = %.1f, want [%.1f, %.1f]", confidence, tt.minConf, tt.maxConf)
			}
			if tt.checkKey != "" {
				if got, ok := checks[tt.checkKey]; !ok || got != tt.checkValue {
					t.Errorf("checks[%q] = %v, want %v", tt.checkKey, got, tt.checkValue)
				}
			}
		})
	}
}

func TestBankAccountValidator_AnalyzeContext(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		match       string
		context     detector.ContextInfo
		wantSign    int // 1 for positive, -1 for negative, 0 for neutral
		description string
	}{
		{
			name:  "Positive banking context",
			match: "021000089",
			context: detector.ContextInfo{
				FullLine:   "Wire transfer routing number: 021000089",
				BeforeText: "Wire transfer routing number: ",
				AfterText:  "",
			},
			wantSign:    1,
			description: "Banking keywords should increase confidence",
		},
		{
			name:  "Negative context",
			match: "021000089",
			context: detector.ContextInfo{
				FullLine:   "Phone serial model version: 021000089",
				BeforeText: "Phone serial model version: ",
				AfterText:  "",
			},
			wantSign:    -1,
			description: "Negative keywords should decrease confidence",
		},
		{
			name:  "Neutral context",
			match: "021000089",
			context: detector.ContextInfo{
				FullLine:   "The number is 021000089 here",
				BeforeText: "The number is ",
				AfterText:  " here",
			},
			wantSign:    0,
			description: "No keywords should have zero impact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := validator.AnalyzeContext(tt.match, tt.context)
			switch tt.wantSign {
			case 1:
				if impact <= 0 {
					t.Errorf("%s: expected positive impact, got %.1f", tt.description, impact)
				}
			case -1:
				if impact >= 0 {
					t.Errorf("%s: expected negative impact, got %.1f", tt.description, impact)
				}
			case 0:
				if impact != 0 {
					t.Errorf("%s: expected zero impact, got %.1f", tt.description, impact)
				}
			}
		})
	}
}

func TestBankAccountValidator_CooperativeCancellation(t *testing.T) {
	validator := NewValidator()

	// Create a pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	content := "Routing: 021000089\nIBAN: DE89370400440532013000\nSWIFT: DEUTDEFF"
	matches, err := validator.ValidateContentCtx(ctx, content, "test.txt")
	if err == nil {
		t.Error("expected context cancellation error, got nil")
	}
	// Should return partial or no matches (cancelled immediately)
	_ = matches
}

func TestBankAccountValidator_IBANChecksum(t *testing.T) {
	validator := NewValidator()

	// Test mod-97 validation specifically
	tests := []struct {
		iban  string
		valid bool
	}{
		{"DE89370400440532013000", true},
		{"GB29NWBK60161331926819", true},
		{"FR7630006000011234567890189", true},
		{"NL91ABNA0417164300", true},
		{"DE00370400440532013000", false}, // check digits 00
		{"DE01370400440532013000", false}, // check digits 01
		{"GB82WEST12345698765432", true},
		{"SA0380000000608010167519", true},
	}

	for _, tt := range tests {
		t.Run(tt.iban, func(t *testing.T) {
			got := validator.isValidIBAN(tt.iban)
			if got != tt.valid {
				t.Errorf("isValidIBAN(%q) = %v, want %v", tt.iban, got, tt.valid)
			}
		})
	}
}

func TestBankAccountValidator_ABAChecksum(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		routing string
		valid   bool
	}{
		{"021000089", true},
		{"011401533", true},
		{"071000013", true},
		{"026009593", true},
		{"121000248", true},
		{"021000088", false}, // bad checksum
		{"991000013", false}, // invalid prefix
		{"001000013", false}, // prefix 00 invalid
		{"000000000", false}, // all zeros
	}

	for _, tt := range tests {
		t.Run(tt.routing, func(t *testing.T) {
			got := validator.isValidABA(tt.routing)
			if got != tt.valid {
				t.Errorf("isValidABA(%q) = %v, want %v", tt.routing, got, tt.valid)
			}
		})
	}
}

func TestBankAccountValidator_SWIFTValidation(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		swift string
		valid bool
	}{
		{"DEUTDEFF", true},
		{"COBADEFFXXX", true},
		{"BNPAFRPP", true},
		{"CHASUS33", true},
		{"DEUT", false},       // too short
		{"DEUTXXFF", false},   // invalid country
		{"1234DEFF", false},   // digits in bank code
		{"DEUTDE", false},     // too short (6 chars)
		{"DEUTDEFF12", false}, // wrong length (10 chars)
	}

	for _, tt := range tests {
		t.Run(tt.swift, func(t *testing.T) {
			got := validator.isValidSWIFT(tt.swift)
			if got != tt.valid {
				t.Errorf("isValidSWIFT(%q) = %v, want %v", tt.swift, got, tt.valid)
			}
		})
	}
}

// --- Test helpers ---

func filterByType(matches []detector.Match, matchType string) []detector.Match {
	var filtered []detector.Match
	for _, m := range matches {
		if m.Type == matchType {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func matchTypes(matches []detector.Match) []string {
	var types []string
	for _, m := range matches {
		types = append(types, m.Type)
	}
	return types
}
