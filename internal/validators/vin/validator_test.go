// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import (
	"testing"
)

func TestVINValidator_ValidVINs(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Valid Honda VIN",
			content:     "VIN: 1HGBH41JXMN109186",
			expectMatch: true,
			description: "Standard Honda VIN with valid check digit",
		},
		{
			name:        "Valid Ford VIN with context",
			content:     "The vehicle identification number is 1FAHP3F26CL363274",
			expectMatch: true,
			description: "Ford VIN in sentence context",
		},
		{
			name:        "Valid BMW VIN",
			content:     "VIN# WBA3A5C58FK198058",
			expectMatch: true,
			description: "BMW VIN with VIN# prefix",
		},
		{
			name:        "Valid Toyota VIN",
			content:     "chassis: JTDKN3DU3A0001234",
			expectMatch: true,
			description: "Toyota VIN with chassis label",
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
				if matches[0].Type != "VIN" {
					t.Errorf("expected Type=VIN, got=%s", matches[0].Type)
				}
				if matches[0].Validator != "vin" {
					t.Errorf("expected Validator=vin, got=%s", matches[0].Validator)
				}
			}
		})
	}
}

func TestVINValidator_InvalidVINs(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Wrong check digit",
			content:     "VIN: 1HGBH41JAMN109186",
			description: "VIN with invalid check digit should be rejected",
		},
		{
			name:        "All repeating characters",
			content:     "11111111111111111",
			description: "All same characters should be rejected",
		},
		{
			name:        "Too short",
			content:     "1HGBH41JXMN1091",
			description: "16-character string should not match regex",
		},
		{
			name:        "Contains I",
			content:     "1HGBI41JXMN109186",
			description: "VIN containing I should not match regex",
		},
		{
			name:        "Contains O",
			content:     "1HGBO41JXMN109186",
			description: "VIN containing O should not match regex",
		},
		{
			name:        "Contains Q",
			content:     "1HGBQ41JXMN109186",
			description: "VIN containing Q should not match regex",
		},
		{
			name:        "Embedded in longer string",
			content:     "ABC1HGBH41JXMN109186DEF",
			description: "VIN embedded in longer alphanumeric should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("%s: expected no match but found %d matches", tt.description, len(matches))
			}
		})
	}
}

func TestVINValidator_CheckDigitAlgorithm(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		vin   string
		valid bool
	}{
		{"1HGBH41JXMN109186", true},
		{"1FAHP3F26CL363274", true},
		{"WBA3A5C58FK198058", true},
		{"1HGBH41JAMN109186", false}, // wrong check digit
		{"1HGBH41J0MN109186", false}, // wrong check digit
	}

	for _, tt := range tests {
		t.Run(tt.vin, func(t *testing.T) {
			result := validator.checkDigitValid(tt.vin)
			if result != tt.valid {
				t.Errorf("checkDigitValid(%s) = %v, want %v", tt.vin, result, tt.valid)
			}
		})
	}
}

func TestVINValidator_ManufacturerDetection(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		vin          string
		manufacturer string
	}{
		{"1HGBH41JXMN109186", "Honda"},
		{"WBA3A5C58FK198058", "BMW"},
		{"1FAHP3F26CL363274", "Ford"},
		{"ZZZ0000000000000A", ""},
	}

	for _, tt := range tests {
		t.Run(tt.vin[:3], func(t *testing.T) {
			result := validator.detectManufacturer(tt.vin)
			if result != tt.manufacturer {
				t.Errorf("detectManufacturer(%s) = %q, want %q", tt.vin, result, tt.manufacturer)
			}
		})
	}
}

func TestVINValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	// VIN with negative context should have lower confidence than neutral
	matchesNeutral, _ := validator.ValidateContent("1HGBH41JXMN109186", "data.txt")
	matchesNegative, _ := validator.ValidateContent("serial number hash token 1HGBH41JXMN109186", "code.go")

	if len(matchesNeutral) == 0 {
		t.Fatal("Expected match in neutral context")
	}

	if len(matchesNegative) == 0 {
		// Negative context may suppress entirely, which is acceptable
		return
	}

	if matchesNegative[0].Confidence >= matchesNeutral[0].Confidence {
		t.Errorf("Negative context should reduce confidence: neutral=%.1f, negative=%.1f",
			matchesNeutral[0].Confidence, matchesNegative[0].Confidence)
	}
}

func TestVINValidator_FalsePositives(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Hex dump line",
			content: "0x1A2B 1HGBH41JXMN109186 0xFF3C 0xAB12 0xCD34 0xEF56 0x7890 0xABCD 0x1234 0x5678 0x9ABC",
		},
		{
			name:    "Part of longer token",
			content: "token=ABC1HGBH41JXMN109186XYZ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("Expected no matches for false positive scenario %q, got %d", tt.name, len(matches))
			}
		})
	}
}

func TestVINValidator_MetadataFields(t *testing.T) {
	validator := NewValidator()

	matches, err := validator.ValidateContent("VIN: 1HGBH41JXMN109186", "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("Expected at least one match")
	}

	m := matches[0]
	if m.Metadata["manufacturer"] != "Honda" {
		t.Errorf("expected manufacturer=Honda, got=%v", m.Metadata["manufacturer"])
	}
	if _, ok := m.Metadata["validation_checks"]; !ok {
		t.Error("expected validation_checks in metadata")
	}
	if _, ok := m.Metadata["context_impact"]; !ok {
		t.Error("expected context_impact in metadata")
	}
}

func TestVINValidator_LegacyValidate(t *testing.T) {
	validator := NewValidator()
	matches, err := validator.Validate("nonexistent.txt")
	if err != nil {
		t.Fatalf("Validate() should not error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate() should return empty matches, got %d", len(matches))
	}
}
