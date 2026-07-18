// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import (
	"context"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func TestAddressValidator_PositiveCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		matchType   string
		description string
	}{
		{
			name:        "Simple street address",
			content:     "Our office is at 123 Main St in the city",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Basic street number + name + type",
		},
		{
			name:        "Full address with Avenue",
			content:     "Shipping address: 456 Oak Avenue, Springfield, IL 62701",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Full address with city/state/ZIP",
		},
		{
			name:        "Boulevard address",
			content:     "Located at 7890 Sunset Blvd, Los Angeles, CA 90028",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Boulevard with city/state/ZIP",
		},
		{
			name:        "Drive address",
			content:     "Home address: 42 Willow Creek Dr",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Drive suffix",
		},
		{
			name:        "Lane address",
			content:     "Billing: 8 Maple Ln, Portland, OR 97201",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Lane suffix with city/state/ZIP",
		},
		{
			name:        "Court address",
			content:     "Residence: 15 Birch Ct",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Court suffix",
		},
		{
			name:        "Road address",
			content:     "Located at 2001 Country Club Rd",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Road suffix with multi-word name",
		},
		{
			name:        "Parkway address",
			content:     "Office at 500 Corporate Pkwy, Suite 200",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Parkway suffix with suite",
		},
		{
			name:        "Circle address",
			content:     "Send to 33 Rose Cir",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Circle suffix",
		},
		{
			name:        "Place address",
			content:     "Mailing address: 1 Park Pl",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Place suffix with address keyword",
		},
		{
			name:        "Highway address",
			content:     "Located at 12345 State Hwy",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Highway suffix",
		},
		{
			name:        "PO Box simple",
			content:     "P.O. Box 12345",
			expectMatch: true,
			matchType:   "PO_BOX",
			description: "Standard PO Box format",
		},
		{
			name:        "PO Box no periods",
			content:     "PO Box 999",
			expectMatch: true,
			matchType:   "PO_BOX",
			description: "PO Box without periods",
		},
		{
			name:        "Post Office Box",
			content:     "Send mail to Post Office Box 54321",
			expectMatch: true,
			matchType:   "PO_BOX",
			description: "Full Post Office Box format",
		},
		{
			name:        "Multi-word street name",
			content:     "Located at 100 Martin Luther King Blvd",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Multi-word street name with suffix",
		},
		{
			name:        "Terrace address",
			content:     "Home: 22 Valley View Ter",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Terrace suffix",
		},
		{
			name:        "Trail address",
			content:     "Address: 789 Deer Trl",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Trail suffix with address keyword",
		},
		{
			name:        "Street with trailing dot",
			content:     "Office: 44 Elm St.",
			expectMatch: true,
			matchType:   "US_STREET_ADDRESS",
			description: "Street with period after abbreviation",
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
					if m.Validator != "physical_address" {
						t.Errorf("expected Validator=physical_address, got=%s", m.Validator)
					}
				}
			}
		})
	}
}

func TestAddressValidator_NegativeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Just a number and word",
			content:     "There are 123 reasons to go",
			description: "Number + word without street type should not match",
		},
		{
			name:        "IP address",
			content:     "Server at 192.168.1.1",
			description: "IP address should not match",
		},
		{
			name:        "Version string",
			content:     "Updated to version 2.3.4",
			description: "Version number should not match",
		},
		{
			name:        "Code line reference",
			content:     "Error at 42 main.go line 5",
			description: "Code file reference should not match",
		},
		{
			name:        "Numbered list",
			content:     "1. First item\n2. Second item",
			description: "Numbered list items should not match",
		},
		{
			name:        "Math expression",
			content:     "Calculate 5 + 3 = 8",
			description: "Math expressions should not match",
		},
		{
			name:        "Number without street type",
			content:     "There are 100 Main things to do",
			description: "Without a valid street suffix, should not match",
		},
		{
			name:        "Just a number",
			content:     "42",
			description: "Standalone number should not match",
		},
		{
			name:        "Empty content",
			content:     "",
			description: "Empty string should not match",
		},
		{
			name:        "Single character",
			content:     "x",
			description: "Single character should not match",
		},
		{
			name:        "Test/mock address with negative context",
			content:     "This is a test address: 123 Fake St",
			description: "Test keyword should suppress or significantly reduce confidence",
		},
		{
			name:        "Example address",
			content:     "For example, 456 Sample Ave is a placeholder address",
			description: "Example/placeholder keywords should suppress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// Negative cases should either not match or have very low confidence
			for _, m := range matches {
				if m.Confidence > 50 {
					t.Errorf("%s: expected no high-confidence match, got %q with confidence %.1f",
						tt.description, m.Text, m.Confidence)
				}
			}
		})
	}
}

func TestAddressValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	t.Run("Address keyword boosts confidence", func(t *testing.T) {
		matchWithKeyword, _ := validator.ValidateContent("Shipping address: 123 Oak Ave", "test.txt")
		matchWithout, _ := validator.ValidateContent("See 123 Oak Ave for more", "test.txt")

		if len(matchWithKeyword) == 0 {
			t.Fatal("Expected match with address keyword")
		}
		if len(matchWithout) == 0 {
			t.Fatal("Expected match without keyword")
		}
		if matchWithKeyword[0].Confidence <= matchWithout[0].Confidence {
			t.Errorf("Address keyword should boost confidence: with=%.1f, without=%.1f",
				matchWithKeyword[0].Confidence, matchWithout[0].Confidence)
		}
	})

	t.Run("City/state/ZIP boosts confidence significantly", func(t *testing.T) {
		matchWithCSZ, _ := validator.ValidateContent("456 Elm St, Austin, TX 78701", "test.txt")
		matchWithoutCSZ, _ := validator.ValidateContent("456 Elm St somewhere", "test.txt")

		if len(matchWithCSZ) == 0 {
			t.Fatal("Expected match with city/state/ZIP")
		}
		if len(matchWithoutCSZ) == 0 {
			t.Fatal("Expected match without city/state/ZIP")
		}
		if matchWithCSZ[0].Confidence <= matchWithoutCSZ[0].Confidence {
			t.Errorf("City/state/ZIP should boost confidence: with=%.1f, without=%.1f",
				matchWithCSZ[0].Confidence, matchWithoutCSZ[0].Confidence)
		}
	})

	t.Run("Adjacent line city/state/ZIP boosts confidence", func(t *testing.T) {
		multiLine := "123 Main St\nSpringfield, IL 62701"
		matches, _ := validator.ValidateContent(multiLine, "test.txt")

		if len(matches) == 0 {
			t.Fatal("Expected match with city/state/ZIP on adjacent line")
		}
		// Should have higher confidence than bare street
		if matches[0].Confidence <= 50 {
			t.Errorf("Adjacent city/state/ZIP should boost above 50, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Negative keywords reduce confidence", func(t *testing.T) {
		matchPositive, _ := validator.ValidateContent("Billing address: 123 Oak Ave", "test.txt")
		matchNegative, _ := validator.ValidateContent("This is a test 123 Oak Ave example", "test.txt")

		if len(matchPositive) == 0 {
			t.Fatal("Expected match with positive context")
		}
		// Negative context may reduce confidence significantly
		if len(matchNegative) > 0 {
			if matchNegative[0].Confidence >= matchPositive[0].Confidence {
				t.Errorf("Negative context should reduce confidence: positive=%.1f, negative=%.1f",
					matchPositive[0].Confidence, matchNegative[0].Confidence)
			}
		}
	})
}

func TestAddressValidator_ContextAnalysisMethod(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string // "positive", "negative", or "neutral"
	}{
		{
			name:           "Address keyword in context",
			match:          "123 Main St",
			line:           "Shipping address: 123 Main St",
			expectedImpact: "positive",
		},
		{
			name:           "IP keyword in context",
			match:          "123 Main St",
			line:           "ip version 123 Main St",
			expectedImpact: "negative",
		},
		{
			name:           "Test keyword in context",
			match:          "123 Main St",
			line:           "test example 123 Main St",
			expectedImpact: "negative",
		},
		{
			name:           "Neutral context",
			match:          "123 Main St",
			line:           "data: 123 Main St noted",
			expectedImpact: "neutral",
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
			case "neutral":
				if impact < -5 || impact > 5 {
					t.Errorf("Expected neutral impact (-5 to 5), got %.2f", impact)
				}
			}
		})
	}
}

func TestAddressValidator_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("Multiple addresses on same line", func(t *testing.T) {
		content := "From: 123 Main St, To: 456 Oak Ave"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) < 2 {
			t.Errorf("Expected at least 2 matches, got %d", len(matches))
		}
	})

	t.Run("Address with apartment number", func(t *testing.T) {
		content := "Address: 100 Broadway Ave, Apt 4B"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match for address with apartment")
		}
	})

	t.Run("Full multi-line address", func(t *testing.T) {
		content := "Ship to:\n789 Elm Boulevard\nSuite 300\nDenver, CO 80202"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected match for multi-line address")
		}
		if matches[0].Confidence < 60 {
			t.Errorf("Multi-line full address should have high confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("PO Box with city/state/ZIP", func(t *testing.T) {
		content := "P.O. Box 1234\nAnytown, NY 10001"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected PO Box match")
		}
		if matches[0].Confidence < 70 {
			t.Errorf("PO Box with city/state/ZIP should have high confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Empty content returns no matches", func(t *testing.T) {
		matches, err := validator.ValidateContent("", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("Expected no matches for empty content, got %d", len(matches))
		}
	})

	t.Run("Unicode content does not crash", func(t *testing.T) {
		content := "Direccion: 123 Main St in the distrito federal"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		// Should still detect the English address pattern
		if len(matches) == 0 {
			t.Error("Expected match for address with unicode context")
		}
	})

	t.Run("Very long line does not hang", func(t *testing.T) {
		// Build a long line with an address buried in it
		long := strings.Repeat("word ", 500) + "123 Main St" + strings.Repeat(" word", 500)
		matches, err := validator.ValidateContent(long, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match in long line")
		}
	})

	t.Run("Max length street number", func(t *testing.T) {
		content := "Located at 999999 Industrial Pkwy"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected match for 6-digit street number")
		}
	})
}

func TestAddressValidator_ConfidenceScoring(t *testing.T) {
	validator := NewValidator()

	t.Run("Bare street address has base 50 confidence", func(t *testing.T) {
		// No keywords, no city/state/ZIP
		matches, _ := validator.ValidateContent("near 100 Oak Rd in the area", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected match")
		}
		if matches[0].Confidence != 50 {
			t.Errorf("Bare street should have 50 base confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Street + city/state/ZIP reaches 80+", func(t *testing.T) {
		matches, _ := validator.ValidateContent("456 Pine Ave, Seattle, WA 98101", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected match")
		}
		if matches[0].Confidence < 80 {
			t.Errorf("Street + city/state/ZIP should reach 80+, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Street + keyword + city/state/ZIP reaches 90+", func(t *testing.T) {
		matches, _ := validator.ValidateContent("Billing address: 789 Elm Blvd, Chicago, IL 60601", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected match")
		}
		if matches[0].Confidence < 90 {
			t.Errorf("Street + keyword + city/state/ZIP should reach 90+, got %.1f", matches[0].Confidence)
		}
	})
}

func TestAddressValidator_CalculateConfidence(t *testing.T) {
	validator := NewValidator()

	t.Run("Street address match", func(t *testing.T) {
		confidence, checks := validator.CalculateConfidence("123 Main St")
		if confidence < 50 {
			t.Errorf("Street address should have >= 50 confidence, got %.1f", confidence)
		}
		if !checks["has_street_number"] {
			t.Error("Expected has_street_number to be true")
		}
		if !checks["has_street_name"] {
			t.Error("Expected has_street_name to be true")
		}
		if !checks["has_street_type"] {
			t.Error("Expected has_street_type to be true")
		}
	})

	t.Run("Full address with city/state/ZIP", func(t *testing.T) {
		confidence, checks := validator.CalculateConfidence("123 Main St, Denver, CO 80202")
		if confidence < 80 {
			t.Errorf("Full address should have >= 80 confidence, got %.1f", confidence)
		}
		if !checks["has_city_state"] {
			t.Error("Expected has_city_state to be true")
		}
		if !checks["has_zip"] {
			t.Error("Expected has_zip to be true")
		}
	})

	t.Run("PO Box", func(t *testing.T) {
		confidence, checks := validator.CalculateConfidence("P.O. Box 12345")
		if confidence < 60 {
			t.Errorf("PO Box should have >= 60 confidence, got %.1f", confidence)
		}
		if !checks["has_street_number"] {
			t.Error("Expected has_street_number to be true for PO Box")
		}
	})
}

func TestAddressValidator_CooperativeCancellation(t *testing.T) {
	validator := NewValidator()

	t.Run("Cancelled context returns early", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		content := "123 Main St\n456 Oak Ave\n789 Elm Blvd"
		matches, err := validator.ValidateContentCtx(ctx, content, "test.txt")
		if err == nil {
			t.Error("Expected error from cancelled context")
		}
		// Should return partial or no results
		_ = matches
	})
}

func TestAddressValidator_NewValidator(t *testing.T) {
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

func TestAddressValidator_FalsePositiveScenarios(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "IP address context",
			content: "Connect to 192.168.1.100 Main St port 8080",
		},
		{
			name:    "Version in line",
			content: "Release 3.2.1 of the package is out",
		},
		{
			name:    "Code reference",
			content: "Error on line 42 main.go",
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
					t.Errorf("False positive scenario %q should have low confidence, got %.1f for %q",
						tt.name, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestAddressValidator_Metadata(t *testing.T) {
	validator := NewValidator()

	content := "Ship to: 123 Oak Ave"
	matches, err := validator.ValidateContent(content, "order.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("Expected at least one match")
	}
	m := matches[0]
	if m.Metadata["source"] != "preprocessed_content" {
		t.Errorf("Expected source=preprocessed_content, got=%v", m.Metadata["source"])
	}
	if m.Metadata["original_file"] != "order.txt" {
		t.Errorf("Expected original_file=order.txt, got=%v", m.Metadata["original_file"])
	}
	if m.LineNumber != 1 {
		t.Errorf("Expected line number 1, got %d", m.LineNumber)
	}
}

// helper to extract match types
func matchTypes(matches []detector.Match) []string {
	var types []string
	for _, m := range matches {
		types = append(types, m.Type)
	}
	return types
}

// Ensure strings is used (needed for strings.Repeat in edge case test).
var _ = strings.Repeat
