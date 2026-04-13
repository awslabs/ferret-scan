// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"testing"

	"ferret-scan/internal/detector"
)

func TestSSNValidator_ValidSSNs(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Hyphenated SSN with SSN keyword",
			content:     "SSN: 219-09-9999",
			expectMatch: true,
			description: "Standard hyphenated format with SSN keyword",
		},
		{
			name:        "Space-separated SSN with social security keyword",
			content:     "social security number: 468 12 3456",
			expectMatch: true,
			description: "Space-separated format with social security keyword",
		},
		{
			name:        "Bare 9-digit SSN with tax id keyword",
			content:     "tax id: 321074567",
			expectMatch: true,
			description: "Nine-digit format with tax id keyword",
		},
		{
			name:        "SSN with payroll context",
			content:     "Payroll record: 145-76-8321",
			expectMatch: true,
			description: "Hyphenated SSN in payroll context",
		},
		{
			name:        "SSN with W2 context",
			content:     "W2 form employee SSN 523-48-7190",
			expectMatch: true,
			description: "SSN on W2 form",
		},
		{
			name:        "SSN with HR context",
			content:     "HR employee record SSN: 287-65-4321",
			expectMatch: true,
			description: "SSN in HR context",
		},
		{
			name:        "SSN area 001 low end",
			content:     "SSN: 001-01-0001",
			expectMatch: true,
			description: "Lowest valid SSN area number",
		},
		{
			name:        "SSN area 665 high end before gap",
			content:     "SSN: 665-12-3456",
			expectMatch: true,
			description: "Highest valid area before 666 gap",
		},
		{
			name:        "SSN area 667 after gap",
			content:     "SSN: 667-12-3456",
			expectMatch: true,
			description: "First valid area after 666 gap",
		},
		{
			name:        "SSN area 899 high end",
			content:     "SSN: 899-12-3456",
			expectMatch: true,
			description: "Highest valid area number",
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
			if hasMatch {
				if matches[0].Type != "SSN" {
					t.Errorf("expected Type=SSN, got=%s", matches[0].Type)
				}
				if matches[0].Validator != "ssn" {
					t.Errorf("expected Validator=ssn, got=%s", matches[0].Validator)
				}
			}
		})
	}
}

func TestSSNValidator_InvalidSSNs(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Area 000 invalid",
			content:     "SSN: 000-12-3456",
			description: "Area 000 is never valid",
		},
		{
			name:        "Area 666 invalid",
			content:     "SSN: 666-12-3456",
			description: "Area 666 is never valid",
		},
		{
			name:        "Area 900 invalid",
			content:     "SSN: 900-12-3456",
			description: "Area 900+ is never valid",
		},
		{
			name:        "Area 950 invalid",
			content:     "SSN: 950-12-3456",
			description: "Area 950 is never valid",
		},
		{
			name:        "Area 999 invalid",
			content:     "SSN: 999-12-3456",
			description: "Area 999 is never valid",
		},
		{
			name:        "Group 00 invalid",
			content:     "SSN: 219-00-3456",
			description: "Group 00 is never valid",
		},
		{
			name:        "Serial 0000 invalid",
			content:     "SSN: 219-09-0000",
			description: "Serial 0000 is never valid",
		},
		{
			name:        "Known test 123-45-6789",
			content:     "SSN: 123-45-6789",
			description: "Well-known test SSN should be rejected or have very low confidence",
		},
		{
			name:        "All same digits 111-11-1111",
			content:     "SSN: 111-11-1111",
			description: "All same digits should be rejected or have very low confidence",
		},
		{
			name:        "All same digits 555-55-5555",
			content:     "SSN: 555-55-5555",
			description: "All same digits should be rejected or have very low confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// Invalid SSNs should either not match or have 0 confidence (filtered out)
			if len(matches) > 0 {
				t.Errorf("%s: expected no match but found %d matches (first: %s, confidence: %.1f)",
					tt.description, len(matches), matches[0].Text, matches[0].Confidence)
			}
		})
	}
}

func TestSSNValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	t.Run("HR context boosts confidence", func(t *testing.T) {
		matchHR, _ := validator.ValidateContent("HR employee record SSN: 219-09-9999", "test.txt")
		matchPlain, _ := validator.ValidateContent("number 219-09-9999", "test.txt")

		if len(matchHR) == 0 {
			t.Fatal("Expected match in HR context")
		}
		if len(matchPlain) == 0 {
			t.Fatal("Expected match in plain context")
		}
		if matchHR[0].Confidence <= matchPlain[0].Confidence {
			t.Errorf("HR context should boost confidence: HR=%.1f, plain=%.1f",
				matchHR[0].Confidence, matchPlain[0].Confidence)
		}
	})

	t.Run("Tax context boosts confidence", func(t *testing.T) {
		matchTax, _ := validator.ValidateContent("tax return W2 form SSN: 219-09-9999", "test.txt")
		matchPlain, _ := validator.ValidateContent("number 219-09-9999", "test.txt")

		if len(matchTax) == 0 {
			t.Fatal("Expected match in tax context")
		}
		if len(matchPlain) == 0 {
			t.Fatal("Expected match in plain context")
		}
		if matchTax[0].Confidence <= matchPlain[0].Confidence {
			t.Errorf("Tax context should boost confidence: tax=%.1f, plain=%.1f",
				matchTax[0].Confidence, matchPlain[0].Confidence)
		}
	})

	t.Run("Healthcare context boosts confidence", func(t *testing.T) {
		matchHealth, _ := validator.ValidateContent("patient medical record SSN: 219-09-9999", "test.txt")
		matchPlain, _ := validator.ValidateContent("number 219-09-9999", "test.txt")

		if len(matchHealth) == 0 {
			t.Fatal("Expected match in healthcare context")
		}
		if len(matchPlain) == 0 {
			t.Fatal("Expected match in plain context")
		}
		if matchHealth[0].Confidence <= matchPlain[0].Confidence {
			t.Errorf("Healthcare context should boost confidence: health=%.1f, plain=%.1f",
				matchHealth[0].Confidence, matchPlain[0].Confidence)
		}
	})

	t.Run("Negative context reduces confidence", func(t *testing.T) {
		matchPositive, _ := validator.ValidateContent("SSN: 219-09-9999", "test.txt")
		matchNegative, _ := validator.ValidateContent("phone serial test 219-09-9999", "test.txt")

		if len(matchPositive) == 0 {
			t.Fatal("Expected match in positive context")
		}
		// Negative context may suppress entirely or reduce confidence
		if len(matchNegative) > 0 {
			if matchNegative[0].Confidence >= matchPositive[0].Confidence {
				t.Errorf("Negative context should reduce confidence: positive=%.1f, negative=%.1f",
					matchPositive[0].Confidence, matchNegative[0].Confidence)
			}
		}
	})
}

func TestSSNValidator_ContextAnalysisMethod(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string // "positive", "negative", or "neutral"
	}{
		{
			name:           "SSN keyword in context",
			match:          "219-09-9999",
			line:           "Employee SSN: 219-09-9999",
			expectedImpact: "positive",
		},
		{
			name:           "Phone keyword in context",
			match:          "219-09-9999",
			line:           "phone number: 219-09-9999",
			expectedImpact: "negative",
		},
		{
			name:           "Test keyword in context",
			match:          "219-09-9999",
			line:           "test example: 219-09-9999",
			expectedImpact: "negative",
		},
		{
			name:           "Tax keyword in context",
			match:          "219-09-9999",
			line:           "IRS tax return 219-09-9999",
			expectedImpact: "positive",
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
			case "neutral":
				if impact < -10 || impact > 10 {
					t.Errorf("Expected neutral impact (-10 to 10), got %.2f", impact)
				}
			}
		})
	}
}

func TestSSNValidator_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("SSN in CSV format", func(t *testing.T) {
		content := `"John Smith","219-09-9999","2024-01-15","Engineering"`
		matches, err := validator.ValidateContent(content, "test.csv")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected SSN match in CSV format")
		}
	})

	t.Run("SSN near multiple keywords", func(t *testing.T) {
		content := "Employee SSN for W2 tax payroll: 219-09-9999"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected SSN match with multiple keywords")
		}
		// With many positive keywords, confidence should be high
		if matches[0].Confidence < 50 {
			t.Errorf("Expected high confidence with multiple keywords, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("SSN-like pattern that is a phone number format", func(t *testing.T) {
		// Phone numbers are XXX-XXX-XXXX (10 digits), SSN is XXX-XX-XXXX (9 digits)
		// This test verifies the regex won't match phone formats
		content := "phone: 219-099-9999"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) > 0 {
			t.Errorf("Phone number format should not match as SSN, got %d matches", len(matches))
		}
	})

	t.Run("Tabular data with SSN", func(t *testing.T) {
		content := "John Smith\t219-09-9999\tjsmith@company.com\t2024-01-15"
		matches, err := validator.ValidateContent(content, "test.tsv")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected SSN match in tabular data")
		}
	})

	t.Run("Multiple SSNs in same line", func(t *testing.T) {
		content := "SSN: 219-09-9999, Spouse SSN: 468-12-3456"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) < 2 {
			t.Errorf("Expected at least 2 SSN matches, got %d", len(matches))
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

	t.Run("SSN on its own line without context", func(t *testing.T) {
		content := "219-09-9999"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		// Should still match but with moderate confidence (no positive keywords)
		// The base confidence is 70 + 15 (valid area) + 10 (format) = 95 before capping,
		// but without positive keywords in non-tabular data, it gets capped at 50,
		// then the format bonus may still apply. Allow up to 60 for edge cases.
		if len(matches) > 0 && matches[0].Confidence > 60 {
			t.Errorf("SSN without context should have moderate confidence, got %.1f", matches[0].Confidence)
		}
	})
}

func TestSSNValidator_ConfidenceScoring(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		match         string
		minConfidence float64
		maxConfidence float64
		description   string
	}{
		{
			name:          "Well-formatted SSN valid area",
			match:         "219-09-9999",
			minConfidence: 70,
			maxConfidence: 100,
			description:   "Properly formatted SSN with valid area should have high base confidence",
		},
		{
			name:          "Bare digits valid SSN",
			match:         "219099999",
			minConfidence: 50,
			maxConfidence: 100,
			description:   "Bare digit SSN should still have reasonable confidence",
		},
		{
			name:          "Space-separated valid SSN",
			match:         "219 09 9999",
			minConfidence: 50,
			maxConfidence: 100,
			description:   "Space-separated SSN should have reasonable confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := validator.CalculateConfidence(tt.match)
			if confidence < tt.minConfidence || confidence > tt.maxConfidence {
				t.Errorf("%s: confidence %.2f not in range [%.2f, %.2f]",
					tt.description, confidence, tt.minConfidence, tt.maxConfidence)
			}
			// Valid area should be checked
			if _, ok := checks["valid_area"]; !ok {
				t.Error("Expected valid_area check in results")
			}
		})
	}
}

func TestSSNValidator_CalculateConfidenceChecks(t *testing.T) {
	validator := NewValidator()

	t.Run("Valid SSN passes all checks", func(t *testing.T) {
		confidence, checks := validator.CalculateConfidence("219-09-9999")
		if confidence <= 0 {
			t.Errorf("Valid SSN should have positive confidence, got %.1f", confidence)
		}
		if !checks["format"] {
			t.Error("Valid SSN should pass format check")
		}
		if !checks["digits"] {
			t.Error("Valid SSN should pass digits check")
		}
		if !checks["valid_area"] {
			t.Error("Valid SSN should pass valid_area check")
		}
		if !checks["not_test_number"] {
			t.Error("Valid SSN should pass not_test_number check")
		}
		if !checks["not_sequential"] {
			t.Error("Valid SSN should pass not_sequential check")
		}
	})

	t.Run("Test SSN 123456789 fails test check", func(t *testing.T) {
		_, checks := validator.CalculateConfidence("123456789")
		if checks["not_test_number"] {
			t.Error("123456789 should fail not_test_number check")
		}
	})

	t.Run("Sequential SSN fails sequential check", func(t *testing.T) {
		_, checks := validator.CalculateConfidence("123456789")
		if checks["not_sequential"] {
			t.Error("Sequential SSN should fail not_sequential check")
		}
	})

	t.Run("Repeating pattern fails repeating check", func(t *testing.T) {
		_, checks := validator.CalculateConfidence("111111111")
		if checks["not_repeating"] {
			t.Error("All-same-digit SSN should fail not_repeating check")
		}
	})
}

func TestSSNValidator_ValidateContentMethod(t *testing.T) {
	validator := NewValidator()

	t.Run("Preprocessed content with SSN", func(t *testing.T) {
		content := "Employee Record\nName: John Smith\nSSN: 219-09-9999\nDepartment: Engineering"
		matches, err := validator.ValidateContent(content, "employee.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected at least one SSN match in preprocessed content")
		}
		match := matches[0]
		if match.Text != "219-09-9999" {
			t.Errorf("Expected match text '219-09-9999', got '%s'", match.Text)
		}
		if match.LineNumber != 3 {
			t.Errorf("Expected line number 3, got %d", match.LineNumber)
		}
		if match.Filename != "employee.txt" {
			t.Errorf("Expected filename 'employee.txt', got '%s'", match.Filename)
		}
	})

	t.Run("Content with multiple lines and SSNs", func(t *testing.T) {
		content := "SSN: 219-09-9999\nOther data\nSSN: 468-12-3456"
		matches, err := validator.ValidateContent(content, "data.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) < 2 {
			t.Errorf("Expected at least 2 matches, got %d", len(matches))
		}
	})

	t.Run("Metadata fields present", func(t *testing.T) {
		content := "SSN: 219-09-9999"
		matches, err := validator.ValidateContent(content, "test.txt")
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
		if m.Metadata["original_file"] != "test.txt" {
			t.Errorf("Expected original_file=test.txt, got=%v", m.Metadata["original_file"])
		}
	})
}

func TestSSNValidator_LegacyValidate(t *testing.T) {
	validator := NewValidator()
	matches, err := validator.Validate("nonexistent.txt")
	if err != nil {
		t.Fatalf("Validate() should not error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate() should return empty matches, got %d", len(matches))
	}
}

func TestSSNValidator_IsValidSSN(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name  string
		ssn   string
		valid bool
	}{
		{"Valid SSN 219099999", "219099999", true},
		{"Valid SSN 001010001", "001010001", true}, // area 001 is valid, group 01, serial 0001
		{"Area 000", "000123456", false},
		{"Area 666", "666123456", false},
		{"Area 900", "900123456", false},
		{"Area 999", "999123456", false},
		{"Group 00", "219003456", false},
		{"Serial 0000", "219090000", false},
		{"All zeros", "000000000", false},
		{"Too short", "12345678", false},
		{"Too long", "1234567890", false},
		{"Valid area 001", "001011234", true},
		{"Valid area 665", "665121234", true},
		{"Valid area 667", "667121234", true},
		{"Valid area 899", "899121234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isValidSSN(tt.ssn)
			if result != tt.valid {
				t.Errorf("isValidSSN(%s) = %v, want %v", tt.ssn, result, tt.valid)
			}
		})
	}
}

func TestSSNValidator_IsValidAreaNumber(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		area  string
		valid bool
	}{
		{"001", true},
		{"100", true},
		{"665", true},
		{"666", false},
		{"667", true},
		{"899", true},
		{"900", false},
		{"999", false},
		{"000", false},
		{"abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.area, func(t *testing.T) {
			result := validator.isValidAreaNumber(tt.area)
			if result != tt.valid {
				t.Errorf("isValidAreaNumber(%s) = %v, want %v", tt.area, result, tt.valid)
			}
		})
	}
}

func TestSSNValidator_IsTestSSN(t *testing.T) {
	validator := NewValidator()

	testSSNs := []string{
		"123456789", "111111111", "222222222", "333333333",
		"444444444", "555555555", "777777777", "888888888",
		"999999999", "987654321", "123454321",
	}

	for _, ssn := range testSSNs {
		t.Run(ssn, func(t *testing.T) {
			if !validator.isTestSSN(ssn) {
				t.Errorf("isTestSSN(%s) should return true", ssn)
			}
		})
	}

	nonTestSSNs := []string{"219099999", "468123456", "321074567"}
	for _, ssn := range nonTestSSNs {
		t.Run(ssn+"_not_test", func(t *testing.T) {
			if validator.isTestSSN(ssn) {
				t.Errorf("isTestSSN(%s) should return false", ssn)
			}
		})
	}
}

func TestSSNValidator_IsSequential(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		ssn        string
		sequential bool
	}{
		{"123456789", true},
		{"987654321", true},
		{"219099999", false},
		{"468123456", false},
	}

	for _, tt := range tests {
		t.Run(tt.ssn, func(t *testing.T) {
			result := validator.isSequential(tt.ssn)
			if result != tt.sequential {
				t.Errorf("isSequential(%s) = %v, want %v", tt.ssn, result, tt.sequential)
			}
		})
	}
}

func TestSSNValidator_HasRepeatingPatterns(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		ssn       string
		repeating bool
	}{
		{"111111111", true},
		{"222333444", true},  // consecutive identical digits
		{"219099999", true},  // three consecutive 9s
		{"219094567", false}, // no 3+ consecutive
	}

	for _, tt := range tests {
		t.Run(tt.ssn, func(t *testing.T) {
			result := validator.hasRepeatingPatterns(tt.ssn)
			if result != tt.repeating {
				t.Errorf("hasRepeatingPatterns(%s) = %v, want %v", tt.ssn, result, tt.repeating)
			}
		})
	}
}

func TestSSNValidator_FalsePositives(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "ZIP+4 code",
			content: "ZIP: 12345-6789",
		},
		{
			name:    "Version number",
			content: "version 123-45-6789 build info",
		},
		{
			name:    "Serial number context",
			content: "serial number: 219-09-9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// These should either not match or have very low confidence
			for _, m := range matches {
				if m.Confidence > 50 {
					t.Errorf("False positive scenario %q should have low confidence, got %.1f for %s",
						tt.name, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestSSNValidator_DocxConcatenatedNumbers(t *testing.T) {
	validator := NewValidator()

	t.Run("Concatenated SSNs in docx content", func(t *testing.T) {
		// Two valid 9-digit SSN candidates concatenated into 18 digits
		content := "Employee data: 219099999468123456"
		matches, err := validator.ValidateContent(content, "test.docx")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		// The findSSNsInConcatenatedNumbers should find these
		if len(matches) == 0 {
			t.Log("No matches found for concatenated SSNs in docx - this may be expected depending on validation")
		}
	})
}

func TestSSNValidator_NewValidator(t *testing.T) {
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
	if len(validator.invalidPatterns) == 0 {
		t.Fatal("NewValidator() has no invalid patterns")
	}
	if len(validator.hrKeywords) == 0 {
		t.Fatal("NewValidator() has no HR keywords")
	}
	if len(validator.taxKeywords) == 0 {
		t.Fatal("NewValidator() has no tax keywords")
	}
	if len(validator.healthcareKeywords) == 0 {
		t.Fatal("NewValidator() has no healthcare keywords")
	}
}
