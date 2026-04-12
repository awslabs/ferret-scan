// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"testing"

	"ferret-scan/internal/detector"
)

func TestCreditCardValidator_ValidCardsByType(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name         string
		content      string
		expectMatch  bool
		expectedType string
		description  string
	}{
		{
			name:         "Visa card with dashes",
			content:      "credit card: 4532-0151-1283-0366",
			expectMatch:  true,
			expectedType: "VISA",
			description:  "Visa card starting with 4",
		},
		{
			name:         "Visa card with spaces",
			content:      "card: 4532 0151 1283 0366",
			expectMatch:  true,
			expectedType: "VISA",
			description:  "Visa card with space separators",
		},
		{
			name:         "Mastercard 51xx with dashes",
			content:      "credit card: 5425-2334-3010-9903",
			expectMatch:  true,
			expectedType: "MASTERCARD",
			description:  "Mastercard starting with 51-55 range",
		},
		{
			name:         "Mastercard 2221-2720 range",
			content:      "payment card: 2223-0000-4841-0010",
			expectMatch:  true,
			expectedType: "MASTERCARD",
			description:  "Mastercard in 2221-2720 range",
		},
		{
			name:         "Amex card with dashes",
			content:      "credit card: 3714-496353-98431",
			expectMatch:  true,
			expectedType: "AMERICAN_EXPRESS",
			description:  "American Express starting with 37",
		},
		{
			name:         "Amex card 34xx",
			content:      "credit card: 3437-277263-38688",
			expectMatch:  true,
			expectedType: "AMERICAN_EXPRESS",
			description:  "American Express starting with 34",
		},
		{
			name:         "Discover 6011",
			content:      "credit card: 6011-1111-1111-1117",
			expectMatch:  true,
			expectedType: "DISCOVER",
			description:  "Discover card starting with 6011",
		},
		{
			name:         "Discover 65xx",
			content:      "payment: 6500-0000-0000-0002",
			expectMatch:  true,
			expectedType: "DISCOVER",
			description:  "Discover card starting with 65",
		},
		{
			name:         "JCB card",
			content:      "card: 3566-0020-2036-0505",
			expectMatch:  true,
			expectedType: "JCB",
			description:  "JCB card starting with 35",
		},
		{
			name:         "Diners Club 36xx",
			content:      "credit card: 3600-0000-0000-08",
			expectMatch:  true,
			expectedType: "DINERS_CLUB",
			description:  "Diners Club starting with 36",
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
			if hasMatch && tt.expectedType != "" {
				if matches[0].Type != tt.expectedType {
					t.Errorf("expected Type=%s, got=%s", tt.expectedType, matches[0].Type)
				}
				if matches[0].Validator != "creditcard" {
					t.Errorf("expected Validator=creditcard, got=%s", matches[0].Validator)
				}
			}
		})
	}
}

func TestCreditCardValidator_LuhnValidation(t *testing.T) {
	validator := NewValidator()

	t.Run("Cards that pass Luhn", func(t *testing.T) {
		validNumbers := []string{
			"4532015112830366", // Visa
			"5425233430109903", // Mastercard
			"6011111111111117", // Discover
			"3566002020360505", // JCB
		}

		for _, num := range validNumbers {
			if !validator.luhnCheck(num) {
				t.Errorf("luhnCheck(%s) should return true", num)
			}
		}
	})

	t.Run("Cards that fail Luhn", func(t *testing.T) {
		invalidNumbers := []string{
			"4532015112830367", // Off by one from valid
			"4532015112830361", // Wrong check digit
			"4532015112830360", // Wrong check digit
		}

		for _, num := range invalidNumbers {
			if validator.luhnCheck(num) {
				t.Errorf("luhnCheck(%s) should return false", num)
			}
		}
	})
}

func TestCreditCardValidator_KnownTestCards(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Visa test card 4111-1111-1111-1111",
			content: "credit card: 4111-1111-1111-1111",
		},
		{
			name:    "Mastercard test card 5555-5555-5555-4444",
			content: "credit card: 5555-5555-5555-4444",
		},
		{
			name:    "Visa test card 4000-0000-0000-0002",
			content: "credit card: 4000-0000-0000-0002",
		},
		{
			name:    "Mastercard test card 5100-0000-0000-0008",
			content: "credit card: 5100-0000-0000-0008",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// Test cards should be detected but with low confidence (capped at 15)
			if len(matches) == 0 {
				t.Error("Test card should still be detected")
				return
			}
			if matches[0].Confidence > 15 {
				t.Errorf("Test card should have low confidence (<=15), got %.1f", matches[0].Confidence)
			}
		})
	}
}

func TestCreditCardValidator_FormatVariants(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Dash-separated",
			content:     "credit card: 4532-0151-1283-0366",
			expectMatch: true,
			description: "Card with dashes",
		},
		{
			name:        "Space-separated",
			content:     "credit card: 4532 0151 1283 0366",
			expectMatch: true,
			description: "Card with spaces",
		},
		{
			name:        "No separator",
			content:     "credit card: 4532015112830366",
			expectMatch: true,
			description: "Card without separators",
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
				t.Errorf("%s: expected match=%v, got=%v", tt.description, tt.expectMatch, hasMatch)
			}
		})
	}
}

func TestCreditCardValidator_FalsePositives(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "16 zeros",
			content:     "0000000000000000",
			description: "All zeros should not match (fails Luhn or repeating)",
		},
		{
			name:        "Random 16 digits failing Luhn",
			content:     "4532015112830361",
			description: "Random digits failing Luhn should not match",
		},
		{
			name:        "Hex context",
			content:     "hash: 0x4532015112830366 checksum",
			description: "Number in hex context should be rejected",
		},
		{
			name:        "UUID-like number",
			content:     "uuid: 4532015112830366 guid",
			description: "Number in UUID context should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// Should either not match or have 0 confidence
			for _, m := range matches {
				if m.Confidence > 15 {
					t.Errorf("%s: expected no/low confidence match, got %.1f for %s",
						tt.description, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestCreditCardValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string // "positive", "negative"
	}{
		{
			name:           "Payment context",
			match:          "4532015112830366",
			line:           "payment credit card: 4532015112830366",
			expectedImpact: "positive",
		},
		{
			name:           "Billing context",
			match:          "4532015112830366",
			line:           "billing visa card 4532015112830366",
			expectedImpact: "positive",
		},
		{
			name:           "Test context",
			match:          "4532015112830366",
			line:           "test example fake 4532015112830366",
			expectedImpact: "negative",
		},
		{
			name:           "Hash context",
			match:          "4532015112830366",
			line:           "md5 hash checksum 4532015112830366",
			expectedImpact: "negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := detector.ContextInfo{
				FullLine: tt.line,
			}
			impact := validator.AnalyzeContext(tt.match, context)

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

func TestCreditCardValidator_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("Card in CSV format", func(t *testing.T) {
		content := `"John Smith","4532-0151-1283-0366","2025-12","123"`
		matches, err := validator.ValidateContent(content, "test.csv")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected credit card match in CSV format")
		}
	})

	t.Run("Card in log file format", func(t *testing.T) {
		content := "2024-01-15 INFO payment processed card 4532-0151-1283-0366 amount 99.99"
		matches, err := validator.ValidateContent(content, "app.log")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected credit card match in log format")
		}
	})

	t.Run("Card with surrounding punctuation", func(t *testing.T) {
		content := "(4532-0151-1283-0366)"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected credit card match with surrounding parentheses")
		}
	})

	t.Run("Empty content", func(t *testing.T) {
		matches, err := validator.ValidateContent("", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("Expected no matches for empty content, got %d", len(matches))
		}
	})

	t.Run("Tabular data with card", func(t *testing.T) {
		content := "John Smith\t4532-0151-1283-0366\t2025-12\t$99.99"
		matches, err := validator.ValidateContent(content, "test.tsv")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected credit card match in tabular data")
		}
	})
}

func TestCreditCardValidator_CardTypeDetection(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		number       string
		expectedType string
	}{
		{"4532015112830366", "VISA"},
		{"5425233430109903", "MASTERCARD"},
		{"2223000048410010", "MASTERCARD"},
		{"371449635398431", "AMERICAN_EXPRESS"},
		{"343727726338688", "AMERICAN_EXPRESS"},
		{"6011111111111117", "DISCOVER"},
		{"3566002020360505", "JCB"},
		{"36000000000008", "DINERS_CLUB"},
		{"6200000000000000", "UNIONPAY"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedType+"_"+tt.number[:4], func(t *testing.T) {
			result := validator.getCreditCardType(tt.number)
			if result != tt.expectedType {
				t.Errorf("getCreditCardType(%s) = %s, want %s", tt.number, result, tt.expectedType)
			}
		})
	}
}

func TestCreditCardValidator_VendorDetection(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		number   string
		expected string
	}{
		{"4532015112830366", "Visa"},
		{"5425233430109903", "MasterCard"},
		{"371449635398431", "American Express"},
		{"6011111111111117", "Discover"},
		{"3566002020360505", "JCB"},
		{"36000000000008", "Diners Club"},
		{"6200000000000000", "UnionPay"},
		{"9999999999999999", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected+"_"+tt.number[:4], func(t *testing.T) {
			result := validator.DetectCardVendor(tt.number)
			if result != tt.expected {
				t.Errorf("DetectCardVendor(%s) = %s, want %s", tt.number, result, tt.expected)
			}
		})
	}
}

func TestCreditCardValidator_CalculateConfidence(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		match         string
		minConfidence float64
		maxConfidence float64
		description   string
	}{
		{
			name:          "Valid Visa card",
			match:         "4532015112830366",
			minConfidence: 50,
			maxConfidence: 100,
			description:   "Valid Visa with good entropy should have high confidence",
		},
		{
			name:          "Test card 4111111111111111",
			match:         "4111111111111111",
			minConfidence: 1,
			maxConfidence: 15,
			description:   "Known test card should have very low confidence",
		},
		{
			name:          "Unknown vendor card",
			match:         "9876543210987654",
			minConfidence: 0,
			maxConfidence: 70,
			description:   "Unknown vendor should have penalty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, _ := validator.CalculateConfidence(tt.match)
			if confidence < tt.minConfidence || confidence > tt.maxConfidence {
				t.Errorf("%s: confidence %.2f not in range [%.2f, %.2f]",
					tt.description, confidence, tt.minConfidence, tt.maxConfidence)
			}
		})
	}
}

func TestCreditCardValidator_CalculateConfidenceChecks(t *testing.T) {
	validator := NewValidator()

	t.Run("Valid card passes key checks", func(t *testing.T) {
		_, checks := validator.CalculateConfidence("4532015112830366")
		if !checks["length"] {
			t.Error("Valid card should pass length check")
		}
		if !checks["luhn"] {
			t.Error("Valid card should pass luhn check")
		}
		if !checks["vendor"] {
			t.Error("Known vendor card should pass vendor check")
		}
		if !checks["not_test"] {
			t.Error("Non-test card should pass not_test check")
		}
		if !checks["not_repeating"] {
			t.Error("Non-repeating card should pass not_repeating check")
		}
	})

	t.Run("Test card fails not_test check", func(t *testing.T) {
		_, checks := validator.CalculateConfidence("4111111111111111")
		if checks["not_test"] {
			t.Error("Test card should fail not_test check")
		}
	})
}

func TestCreditCardValidator_HasRepeatingPatterns(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		number    string
		repeating bool
	}{
		{"1111111111111111", true},  // All same digit
		{"1212121212121212", true},  // Alternating
		{"1234567890123456", true},  // Sequential
		{"4532015112830366", false}, // Normal card
		{"5425233430109903", false}, // Normal card
	}

	for _, tt := range tests {
		t.Run(tt.number[:8], func(t *testing.T) {
			result := validator.hasRepeatingPatterns(tt.number)
			if result != tt.repeating {
				t.Errorf("hasRepeatingPatterns(%s) = %v, want %v", tt.number, result, tt.repeating)
			}
		})
	}
}

func TestCreditCardValidator_Entropy(t *testing.T) {
	validator := NewValidator()

	t.Run("Low entropy number", func(t *testing.T) {
		// All same digit has 1 unique digit -> entropy = 0.5
		entropy := validator.calculateEntropy("1111111111111111")
		if entropy >= 2.5 {
			t.Errorf("All same digits should have low entropy, got %.2f", entropy)
		}
	})

	t.Run("High entropy number", func(t *testing.T) {
		// Many unique digits -> higher entropy
		entropy := validator.calculateEntropy("4532015112830366")
		if entropy < 2.5 {
			t.Errorf("Diverse digits should have higher entropy, got %.2f", entropy)
		}
	})
}

func TestCreditCardValidator_IsTabularData(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		line     string
		match    string
		expected bool
	}{
		{"Name\t4532015112830366\t2025-12", "4532015112830366", true},
		{"Name,4532015112830366,2025-12,123", "4532015112830366", true},
		{"Name|4532015112830366|2025-12", "4532015112830366", true},
		{"John Smith   4532015112830366   2025-12", "4532015112830366", true},
		{"card 4532015112830366", "4532015112830366", false},
	}

	for _, tt := range tests {
		t.Run(tt.line[:20], func(t *testing.T) {
			result := validator.isTabularData(tt.line, tt.match)
			if result != tt.expected {
				t.Errorf("isTabularData(%q, %q) = %v, want %v", tt.line, tt.match, result, tt.expected)
			}
		})
	}
}

func TestCreditCardValidator_LegacyValidate(t *testing.T) {
	validator := NewValidator()
	matches, err := validator.Validate("nonexistent.txt")
	if err != nil {
		t.Fatalf("Validate() should not error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate() should return empty matches, got %d", len(matches))
	}
}

func TestCreditCardValidator_ValidateContentMetadata(t *testing.T) {
	validator := NewValidator()

	content := "credit card: 4532-0151-1283-0366"
	matches, err := validator.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("Expected at least one match")
	}

	m := matches[0]
	if _, ok := m.Metadata["card_type"]; !ok {
		t.Error("Expected card_type in metadata")
	}
	if _, ok := m.Metadata["vendor"]; !ok {
		t.Error("Expected vendor in metadata")
	}
	if _, ok := m.Metadata["validation_checks"]; !ok {
		t.Error("Expected validation_checks in metadata")
	}
	if _, ok := m.Metadata["context_impact"]; !ok {
		t.Error("Expected context_impact in metadata")
	}
	if m.Metadata["source"] != "preprocessed_content" {
		t.Errorf("Expected source=preprocessed_content, got=%v", m.Metadata["source"])
	}
	if m.Metadata["original_file"] != "test.txt" {
		t.Errorf("Expected original_file=test.txt, got=%v", m.Metadata["original_file"])
	}
	if m.LineNumber != 1 {
		t.Errorf("Expected LineNumber=1, got=%d", m.LineNumber)
	}
}

func TestCreditCardValidator_CleanCreditCardNumber(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		input    string
		expected string
	}{
		{"4532-0151-1283-0366", "4532015112830366"},
		{"4532 0151 1283 0366", "4532015112830366"},
		{"4532015112830366", "4532015112830366"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := validator.cleanCreditCardNumber(tt.input)
			if result != tt.expected {
				t.Errorf("cleanCreditCardNumber(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCreditCardValidator_IsValidLength(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		number string
		valid  bool
	}{
		{"12345678901234", true},     // 14 digits (Diners)
		{"123456789012345", true},    // 15 digits (Amex)
		{"1234567890123456", true},   // 16 digits (standard)
		{"1234567890123", false},     // 13 digits
		{"12345678901234567", false}, // 17 digits
	}

	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			result := validator.isValidLength(tt.number)
			if result != tt.valid {
				t.Errorf("isValidLength(%s) = %v, want %v", tt.number, result, tt.valid)
			}
		})
	}
}

func TestCreditCardValidator_NewValidator(t *testing.T) {
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
	if len(validator.binRanges) == 0 {
		t.Fatal("NewValidator() has no BIN ranges")
	}
	if len(validator.testPatterns) == 0 {
		t.Fatal("NewValidator() has no test patterns")
	}
}

func TestCreditCardValidator_KnownTestPattern(t *testing.T) {
	validator := NewValidator()

	testPatterns := []string{
		"4111111111111111",
		"5555555555554444",
		"4444444444444448",
		"4000000000000002",
		"5100000000000008",
		"340000000000009",
	}

	for _, pattern := range testPatterns {
		t.Run(pattern, func(t *testing.T) {
			if !validator.isKnownTestPattern(pattern) {
				t.Errorf("isKnownTestPattern(%s) should return true", pattern)
			}
		})
	}

	nonTestPatterns := []string{
		"4532015112830366",
		"5425233430109903",
	}

	for _, pattern := range nonTestPatterns {
		t.Run(pattern+"_not_test", func(t *testing.T) {
			if validator.isKnownTestPattern(pattern) {
				t.Errorf("isKnownTestPattern(%s) should return false", pattern)
			}
		})
	}
}
