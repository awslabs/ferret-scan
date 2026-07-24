// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"context"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func TestDriversLicenseValidator_PositiveCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		content       string
		expectMatch   bool
		minConfidence float64
		description   string
	}{
		{
			name:          "California DL with keyword",
			content:       "Driver's License: D1234567",
			expectMatch:   true,
			minConfidence: 60,
			description:   "California format (1 letter + 7 digits) with DL keyword",
		},
		{
			name:          "California DL with DL prefix",
			content:       "DL: D1234567",
			expectMatch:   true,
			minConfidence: 80,
			description:   "California format with explicit DL: prefix",
		},
		{
			name:          "Texas DL with DMV keyword",
			content:       "DMV license number: 12345678",
			expectMatch:   true,
			minConfidence: 60,
			description:   "Texas format (8 digits) with DMV keyword",
		},
		{
			name:          "Florida DL with keyword",
			content:       "Florida driver license: D123456789012",
			expectMatch:   true,
			minConfidence: 80,
			description:   "Florida format (1 letter + 12 digits) with state + keyword",
		},
		{
			name:          "New York DL with keyword",
			content:       "NY driver's license: 123456789",
			expectMatch:   true,
			minConfidence: 60,
			description:   "New York format (9 digits) with keyword",
		},
		{
			name:          "Illinois DL with keyword",
			content:       "Illinois DL# B12345678901",
			expectMatch:   true,
			minConfidence: 80,
			description:   "Illinois format (1 letter + 11 digits) with state + prefix",
		},
		{
			name:          "Ohio DL with keyword",
			content:       "Ohio driver license: AB123456",
			expectMatch:   true,
			minConfidence: 80,
			description:   "Ohio format (2 letters + 6 digits) with state + keyword",
		},
		{
			name:          "Michigan DL with keyword",
			content:       "Michigan driving permit: M123456789012",
			expectMatch:   true,
			minConfidence: 80,
			description:   "Michigan format (1 letter + 12 digits) with state + keyword",
		},
		{
			name:          "Pennsylvania DL with keyword",
			content:       "PA driver's license number: 87654321",
			expectMatch:   true,
			minConfidence: 60,
			description:   "Pennsylvania format (8 digits) with state + keyword",
		},
		{
			name:          "Generic DL with operator keyword",
			content:       "operator license D9876543",
			expectMatch:   true,
			minConfidence: 60,
			description:   "California format with operator keyword",
		},
		{
			name:          "State ID keyword",
			content:       "state id: A1234567",
			expectMatch:   true,
			minConfidence: 60,
			description:   "California format with state id keyword",
		},
		{
			name:          "DMV permit",
			content:       "DMV permit number A1234567 issued 2024",
			expectMatch:   true,
			minConfidence: 60,
			description:   "California format with dmv + permit keywords",
		},
		{
			name:          "License number prefix colon",
			content:       "License Number: 12345678",
			expectMatch:   true,
			minConfidence: 60,
			description:   "Texas format with license number prefix",
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
				if matches[0].Type != "DRIVERS_LICENSE" {
					t.Errorf("expected Type=DRIVERS_LICENSE, got=%s", matches[0].Type)
				}
				if matches[0].Validator != "driverslicense" {
					t.Errorf("expected Validator=driverslicense, got=%s", matches[0].Validator)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("%s: expected confidence >= %.0f, got %.1f",
						tt.description, tt.minConfidence, matches[0].Confidence)
				}
			}
		})
	}
}

// TestDriversLicenseValidator_AddressDoesNotSuppress locks the removal of the
// "address" negative keyword: a driver's-license record almost always lists the
// holder's physical address on the same line, so "address" hard-suppressed real
// DLs. The DL must still surface with address context, while "IP address" (via
// the "ip" keyword) still suppresses.
func TestDriversLicenseValidator_AddressDoesNotSuppress(t *testing.T) {
	validator := NewValidator()

	// Recovered: a real DL line that also mentions the holder's address.
	for _, content := range []string{
		"Driver's License: D1234567, address 123 Main St",
		"California DL D1234567 mailing address on file",
	} {
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		found := false
		for _, m := range matches {
			if m.Type == "DRIVERS_LICENSE" && m.Confidence >= 60 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("real DL with address context should surface for %q, got %d matches", content, len(matches))
		}
	}

	// Still suppressed: an IP address / port context (via "ip"/"port").
	for _, content := range []string{
		"IP address port for device D1234567",
	} {
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		for _, m := range matches {
			if m.Type == "DRIVERS_LICENSE" && m.Confidence >= 60 {
				t.Errorf("IP/port context should suppress DL for %q, got %.1f", content, m.Confidence)
			}
		}
	}
}

func TestDriversLicenseValidator_NegativeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "8 digits without DL keyword",
			content:     "Account number: 12345678",
			description: "8 digits with account keyword should not match",
		},
		{
			name:        "9 digits without DL keyword",
			content:     "Order reference 123456789 shipped",
			description: "9 digits in order context should not match",
		},
		{
			name:        "Phone number",
			content:     "Phone: 2125551234",
			description: "Phone number should not match",
		},
		{
			name:        "SSN context",
			content:     "SSN: 123456789",
			description: "Number in SSN context should not match",
		},
		{
			name:        "Serial number",
			content:     "Serial number A1234567 for product",
			description: "Serial number context should suppress",
		},
		{
			name:        "Invoice reference",
			content:     "Invoice #12345678 due date",
			description: "Invoice number should not match",
		},
		{
			name:        "Tracking number",
			content:     "Tracking: AB123456 delivered",
			description: "Tracking number should not match",
		},
		{
			name:        "Version string",
			content:     "Version 12345678 build 100",
			description: "Version number should not match",
		},
		{
			name:        "IP address context",
			content:     "IP address port 12345678",
			description: "IP/port context should suppress",
		},
		{
			name:        "Hash value",
			content:     "Hash: AB123456 checksum verified",
			description: "Hash context should suppress",
		},
		{
			name:        "Test/example context",
			content:     "Example driver license: D1234567",
			description: "Test/example context should suppress",
		},
		{
			name:        "Fake/mock context",
			content:     "Fake DL number for demo: A9876543",
			description: "Fake/mock/demo context should suppress",
		},
		{
			name:        "No keywords at all",
			content:     "The value is D1234567 in the record",
			description: "No DL keywords means no detection",
		},
		{
			name:        "Model number",
			content:     "Model AB123456 specifications",
			description: "Model number context should not match",
		},
		{
			name:        "ISBN-like",
			content:     "ISBN 123456789 published 2024",
			description: "ISBN context should not match",
		},
		{
			name:        "UUID fragment",
			content:     "UUID AB123456 generated",
			description: "UUID context should not match",
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
					t.Errorf("%s: expected no high-confidence match but got %q at confidence %.1f",
						tt.description, m.Text, m.Confidence)
				}
			}
		})
	}
}

func TestDriversLicenseValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	t.Run("DL prefix gives highest confidence", func(t *testing.T) {
		matchPrefix, _ := validator.ValidateContent("DL: D1234567", "test.txt")
		matchKeyword, _ := validator.ValidateContent("driver license D1234567", "test.txt")

		if len(matchPrefix) == 0 || len(matchKeyword) == 0 {
			t.Fatal("Expected matches in both cases")
		}
		if matchPrefix[0].Confidence <= matchKeyword[0].Confidence {
			t.Errorf("DL: prefix should give higher confidence than generic keyword: prefix=%.1f, keyword=%.1f",
				matchPrefix[0].Confidence, matchKeyword[0].Confidence)
		}
	})

	t.Run("State name boosts confidence", func(t *testing.T) {
		matchState, _ := validator.ValidateContent("California driver license D1234567", "test.txt")
		matchNoState, _ := validator.ValidateContent("driver license D1234567", "test.txt")

		if len(matchState) == 0 || len(matchNoState) == 0 {
			t.Fatal("Expected matches in both cases")
		}
		if matchState[0].Confidence <= matchNoState[0].Confidence {
			t.Errorf("State name should boost confidence: state=%.1f, no_state=%.1f",
				matchState[0].Confidence, matchNoState[0].Confidence)
		}
	})

	t.Run("Negative keyword suppresses", func(t *testing.T) {
		matchPositive, _ := validator.ValidateContent("driver license D1234567", "test.txt")
		matchNegative, _ := validator.ValidateContent("driver license serial D1234567", "test.txt")

		if len(matchPositive) == 0 {
			t.Fatal("Expected match in positive context")
		}
		if len(matchNegative) > 0 && matchNegative[0].Confidence >= matchPositive[0].Confidence {
			t.Errorf("Negative keyword should reduce confidence: positive=%.1f, negative=%.1f",
				matchPositive[0].Confidence, matchNegative[0].Confidence)
		}
	})
}

func TestDriversLicenseValidator_ContextAnalysisMethod(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string // "positive", "negative"
	}{
		{
			name:           "DL prefix in context",
			match:          "D1234567",
			line:           "DL: D1234567",
			expectedImpact: "positive",
		},
		{
			name:           "Driver keyword in context",
			match:          "D1234567",
			line:           "driver license D1234567",
			expectedImpact: "positive",
		},
		{
			name:           "Serial keyword in context",
			match:          "D1234567",
			line:           "serial number D1234567",
			expectedImpact: "negative",
		},
		{
			name:           "State name adds boost",
			match:          "D1234567",
			line:           "California DL D1234567",
			expectedImpact: "positive",
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

func TestDriversLicenseValidator_EdgeCases(t *testing.T) {
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

	t.Run("All zeros suppressed", func(t *testing.T) {
		matches, err := validator.ValidateContent("DL: A0000000", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		// Should match but with reduced confidence due to all-zero digits
		if len(matches) > 0 && matches[0].Confidence > 80 {
			t.Errorf("All-zero DL should have reduced confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Sequential digits suppressed", func(t *testing.T) {
		matches, err := validator.ValidateContent("DL: 12345678", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) > 0 && matches[0].Confidence > 80 {
			t.Errorf("Sequential DL should have reduced confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Multiple DLs on same line", func(t *testing.T) {
		content := "DL: D1234567, Spouse DL: D7654321"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) < 2 {
			t.Errorf("Expected at least 2 DL matches, got %d", len(matches))
		}
	})

	t.Run("Multiline content", func(t *testing.T) {
		content := "Name: John Smith\nDriver's License: D1234567\nState: California"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected DL match in multiline content")
		}
		if matches[0].LineNumber != 2 {
			t.Errorf("Expected line number 2, got %d", matches[0].LineNumber)
		}
	})

	t.Run("Unicode content does not crash", func(t *testing.T) {
		content := "Driver's license: D1234567 for user"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match with unicode content")
		}
	})

	t.Run("Lowercase letter in DL", func(t *testing.T) {
		matches, err := validator.ValidateContent("Driver's License: d1234567", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match with lowercase letter prefix")
		}
	})
}

func TestDriversLicenseValidator_ConfidenceStrategy(t *testing.T) {
	validator := NewValidator()

	t.Run("Pattern alone without keyword stays at base 20", func(t *testing.T) {
		// No keyword context -> lineHasPositiveKeyword returns false -> no match
		matches, _ := validator.ValidateContent("The code is D1234567 here", "test.txt")
		if len(matches) > 0 {
			t.Errorf("Pattern without any DL keyword should not produce a match, got %d", len(matches))
		}
	})

	t.Run("One DL keyword reaches ~65", func(t *testing.T) {
		matches, _ := validator.ValidateContent("license D1234567", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected match with one keyword")
		}
		if matches[0].Confidence < 55 || matches[0].Confidence > 75 {
			t.Errorf("Expected confidence ~65 with one keyword, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("State name + keyword reaches ~85", func(t *testing.T) {
		matches, _ := validator.ValidateContent("California driver license D1234567", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected match with state + keyword")
		}
		if matches[0].Confidence < 75 {
			t.Errorf("Expected confidence >= 75 with state + keyword, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("DL: prefix reaches ~95", func(t *testing.T) {
		matches, _ := validator.ValidateContent("DL: D1234567", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected match with DL: prefix")
		}
		if matches[0].Confidence < 90 {
			t.Errorf("Expected confidence >= 90 with DL: prefix, got %.1f", matches[0].Confidence)
		}
	})
}

func TestDriversLicenseValidator_CooperativeCancellation(t *testing.T) {
	validator := NewValidator()

	t.Run("Cancelled context returns early", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		// Large content that would take time to scan
		var lines []string
		for i := 0; i < 1000; i++ {
			lines = append(lines, "Driver's License: D1234567")
		}
		content := ""
		for _, l := range lines {
			content += l + "\n"
		}

		matches, err := validator.ValidateContentCtx(ctx, content, "test.txt")
		if err == nil {
			t.Error("Expected error from cancelled context")
		}
		// Should return partial results (possibly none since cancelled at start)
		_ = matches
	})
}

func TestDriversLicenseValidator_ClassifyMatch(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		match    string
		expected string
	}{
		{"D1234567", "CA_1L7D"},
		{"A12345678901", "IL_1L11D"},
		{"B123456789012", "FL_MI_1L12D"},
		{"AB123456", "OH_2L6D"},
		{"123456789", "NY_GA_9D"},
		{"12345678", "TX_PA_8D"},
	}

	for _, tt := range tests {
		t.Run(tt.match, func(t *testing.T) {
			result := validator.classifyMatch(tt.match)
			if result != tt.expected {
				t.Errorf("classifyMatch(%s) = %s, want %s", tt.match, result, tt.expected)
			}
		})
	}
}

func TestDriversLicenseValidator_NewValidator(t *testing.T) {
	validator := NewValidator()

	if validator == nil {
		t.Fatal("NewValidator() returned nil")
	}
	if validator.regex == nil {
		t.Fatal("NewValidator() did not set regex")
	}
	if len(validator.positiveKeywords) == 0 {
		t.Fatal("NewValidator() has no positive keywords")
	}
	if len(validator.negativeKeywords) == 0 {
		t.Fatal("NewValidator() has no negative keywords")
	}
	if len(validator.stateKeywords) == 0 {
		t.Fatal("NewValidator() has no state keywords")
	}
}

func TestDriversLicenseValidator_MetadataFields(t *testing.T) {
	validator := NewValidator()

	content := "DL: D1234567"
	matches, err := validator.ValidateContent(content, "record.txt")
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
	if _, ok := m.Metadata["format"]; !ok {
		t.Error("Expected format in metadata")
	}
	if m.Metadata["source"] != "preprocessed_content" {
		t.Errorf("Expected source=preprocessed_content, got=%v", m.Metadata["source"])
	}
	if m.Metadata["original_file"] != "record.txt" {
		t.Errorf("Expected original_file=record.txt, got=%v", m.Metadata["original_file"])
	}
}
