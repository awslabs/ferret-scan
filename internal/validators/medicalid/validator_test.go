// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"context"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func TestMedicalIDValidator_NPI_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "NPI with provider keyword",
			content: "Provider NPI: 1104332188",
		},
		{
			name:    "NPI with physician keyword",
			content: "Physician NPI number: 1497759005",
		},
		{
			name:    "NPI with healthcare keyword",
			content: "Healthcare provider NPI 1679576003",
		},
		{
			name:    "NPI with hospital context",
			content: "Hospital registry NPI: 1124028006",
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
				if m.Type == "NPI" {
					found = true
					if m.Confidence < 50 {
						t.Errorf("NPI match confidence too low: %.1f", m.Confidence)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected NPI match in: %s", tt.content)
			}
		})
	}
}

func TestMedicalIDValidator_NPI_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "NPI-like number without context",
			content: "Order number: 1104332188",
		},
		{
			name:    "10 digits failing NPI Luhn",
			content: "Provider NPI: 1234567890",
		},
		{
			name:    "Phone number starting with 1",
			content: "Phone: 1234567890",
		},
		{
			name:    "NPI-like with test keyword",
			content: "Test NPI example: 1104332188",
		},
		{
			name:    "10 digits starting with 3 (invalid NPI prefix)",
			content: "Provider NPI: 3234567891",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "NPI" && m.Confidence >= 60 {
					t.Errorf("Expected no high-confidence NPI match in: %s (got confidence %.1f)",
						tt.content, m.Confidence)
				}
			}
		})
	}
}

func TestMedicalIDValidator_DEA_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		dea     string
	}{
		{
			name:    "DEA with prescriber keyword",
			content: "Prescriber DEA: AB1234563",
			dea:     "AB1234563",
		},
		{
			name:    "DEA with pharmacy keyword",
			content: "Pharmacy DEA number: FC2014354",
			dea:     "FC2014354",
		},
		{
			name:    "DEA with controlled substance context",
			content: "DEA for controlled substance dispensing: BJ3109560",
			dea:     "BJ3109560",
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
				if m.Type == "DEA_NUMBER" {
					found = true
					if m.Confidence < 60 {
						t.Errorf("DEA match confidence too low: %.1f for %s", m.Confidence, m.Text)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected DEA_NUMBER match in: %s", tt.content)
			}
		})
	}
}

func TestMedicalIDValidator_DEA_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "DEA-like with invalid checksum",
			content: "DEA: AB1234567",
		},
		{
			name:    "DEA-like with invalid first char",
			content: "DEA number: XY1234563",
		},
		{
			name:    "DEA-like with test and example keywords",
			content: "This is a test example DEA: AB1234563",
		},
		{
			name:    "Random 2 letter + 7 digit pattern",
			content: "Serial number: HQ9876543",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "DEA_NUMBER" && m.Confidence >= 60 {
					t.Errorf("Expected no high-confidence DEA match in: %s (got confidence %.1f for %s)",
						tt.content, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestMedicalIDValidator_MBI_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "MBI with medicare keyword",
			content: "Medicare MBI: 1EG4TE5MK72",
		},
		{
			name:    "MBI with beneficiary keyword",
			content: "Beneficiary ID: 2AW3HA4NK91",
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
				if m.Type == "MEDICARE_MBI" {
					found = true
					if m.Confidence < 50 {
						t.Errorf("MBI match confidence too low: %.1f", m.Confidence)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected MEDICARE_MBI match in: %s", tt.content)
			}
		})
	}
}

func TestMedicalIDValidator_MBI_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "MBI-like without context",
			content: "Reference code: 1EG4TE5MK72",
		},
		{
			name:    "MBI with excluded letters (S, L, O, I, B, Z)",
			content: "Medicare MBI: 1SG4TE5MK72",
		},
		{
			name:    "MBI starting with 0 (invalid)",
			content: "Medicare beneficiary: 0EG4TE5MK72",
		},
		{
			name:    "MBI starting with 0 (invalid)",
			content: "Medicare beneficiary: 0EG4TE5MK72",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "MEDICARE_MBI" && m.Confidence >= 60 {
					t.Errorf("Expected no high-confidence MBI match in: %s (got confidence %.1f for %s)",
						tt.content, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestMedicalIDValidator_MRN_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "MRN with explicit keyword",
			content: "MRN: 12345678",
		},
		{
			name:    "Medical record number",
			content: "Medical record number: 987654",
		},
		{
			name:    "Patient ID with hospital context",
			content: "Hospital patient id: 7654321",
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
				if m.Type == "MRN" {
					found = true
					if m.Confidence < 40 {
						t.Errorf("MRN match confidence too low: %.1f", m.Confidence)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected MRN match in: %s", tt.content)
			}
		})
	}
}

// TestMedicalIDValidator_PatientAccountMRN locks the soft-suppressor fix: a real
// MRN labelled with "patient account number" must surface even though "account"
// is a suppressor keyword, because "patient account" is a strong MRN keyword. A
// bare "Account: <digits>" line (no MRN keyword) must still be suppressed.
func TestMedicalIDValidator_PatientAccountMRN(t *testing.T) {
	validator := NewValidator()

	// Recovered: "patient account (number)" is a hospital MRN label.
	for _, content := range []string{
		"Patient account number: 1234567",
		"patient account: 7654321 on file",
	} {
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		found := false
		for _, m := range matches {
			if m.Type == "MRN" && m.Confidence >= 60 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected high-confidence MRN for %q, got %d matches", content, len(matches))
		}
	}

	// Still suppressed: soft label without a strong MRN keyword, and hard
	// suppressors regardless of MRN keyword.
	for _, content := range []string{
		"Account: 1104332188",               // soft label, no MRN keyword
		"Order for patient: 12345678",       // soft label + generic "patient" only
		"patient account phone: 5551234567", // MRN keyword but a hard phone veto
	} {
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		for _, m := range matches {
			if m.Type == "MRN" && m.Confidence >= 60 {
				t.Errorf("expected no high-confidence MRN for %q, got %.1f for %s", content, m.Confidence, m.Text)
			}
		}
	}
}

func TestMedicalIDValidator_MRN_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Random digits without medical context",
			content: "Value: 12345678",
		},
		{
			name:    "Phone number digits",
			content: "Phone patient: 5551234567",
		},
		{
			name:    "SSN-length digits in medical context",
			content: "Patient SSN: 123456789",
		},
		{
			name:    "Zip code in medical context",
			content: "Hospital zip: 902101234",
		},
		{
			name:    "Order number with medical keyword",
			content: "Order for patient: 12345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "MRN" && m.Confidence >= 60 {
					t.Errorf("Expected no high-confidence MRN match in: %s (got confidence %.1f for %s)",
						tt.content, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestMedicalIDValidator_InsuranceID_Positive(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Member ID with insurance keyword",
			content: "Insurance member id: XYZ123456789",
		},
		{
			name:    "Subscriber ID",
			content: "Subscriber id: H12345678A",
		},
		{
			name:    "Policy number with health plan",
			content: "Health plan policy number: POL987654AB",
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
				if m.Type == "INSURANCE_MEMBER_ID" {
					found = true
					if m.Confidence < 50 {
						t.Errorf("Insurance ID confidence too low: %.1f for %s", m.Confidence, m.Text)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected INSURANCE_MEMBER_ID match in: %s", tt.content)
			}
		})
	}
}

func TestMedicalIDValidator_InsuranceID_Negative(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Hex hash with insurance keyword",
			content: "Insurance account: abcdef1234567890",
		},
		{
			name:    "All-digit string (no letters)",
			content: "Member id: 1234567890",
		},
		{
			name:    "All-alpha string (no digits)",
			content: "Member id: ABCDEFGHIJ",
		},
		{
			name:    "Serial number with insurance context",
			content: "Insurance serial number: SN12345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "INSURANCE_MEMBER_ID" && m.Confidence >= 60 {
					t.Errorf("Expected no high-confidence insurance ID match in: %s (got confidence %.1f for %s)",
						tt.content, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestMedicalIDValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	t.Run("Positive keywords boost confidence", func(t *testing.T) {
		context := detector.ContextInfo{
			FullLine: "Provider NPI number for the hospital physician: 1104332188",
		}
		impact := validator.AnalyzeContext("1104332188", context)
		if impact <= 0 {
			t.Errorf("Expected positive context impact, got %.2f", impact)
		}
	})

	t.Run("Negative keywords reduce confidence", func(t *testing.T) {
		context := detector.ContextInfo{
			FullLine: "Test phone serial number mock: 1104332188",
		}
		impact := validator.AnalyzeContext("1104332188", context)
		if impact >= 0 {
			t.Errorf("Expected negative context impact, got %.2f", impact)
		}
	})

	t.Run("Strong negative dominates positive keywords", func(t *testing.T) {
		context := detector.ContextInfo{
			FullLine: "Test provider NPI: 1104332188",
		}
		// "test" is a strong negative (-25), "provider" and "npi" are positive (+10 each)
		// Net should be negative because "test" as a strong indicator suppresses
		impact := validator.AnalyzeContext("1104332188", context)
		if impact >= 0 {
			t.Errorf("Expected negative impact when strong negative 'test' present, got %.2f", impact)
		}
	})
}

func TestMedicalIDValidator_EdgeCases(t *testing.T) {
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
		matches, err := validator.ValidateContent("x", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("Expected no matches for single char, got %d", len(matches))
		}
	})

	t.Run("Multiline content", func(t *testing.T) {
		content := "Patient record\nProvider NPI: 1104332188\nDEA: AB1234563\nEnd of record"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		npiFound := false
		deaFound := false
		for _, m := range matches {
			if m.Type == "NPI" {
				npiFound = true
				if m.LineNumber != 2 {
					t.Errorf("Expected NPI on line 2, got %d", m.LineNumber)
				}
			}
			if m.Type == "DEA_NUMBER" {
				deaFound = true
				if m.LineNumber != 3 {
					t.Errorf("Expected DEA on line 3, got %d", m.LineNumber)
				}
			}
		}
		if !npiFound {
			t.Error("Expected NPI match in multiline content")
		}
		if !deaFound {
			t.Error("Expected DEA_NUMBER match in multiline content")
		}
	})

	t.Run("Context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		matches, err := validator.ValidateContentCtx(ctx, "Provider NPI: 1104332188", "test.txt")
		if err == nil {
			t.Error("Expected context cancellation error")
		}
		// Partial matches are OK (might be empty since we cancelled before first line)
		_ = matches
	})
}

func TestMedicalIDValidator_NPILuhnValidation(t *testing.T) {
	tests := []struct {
		npi   string
		valid bool
	}{
		{"1104332188", true},  // Valid NPI (80840 prefix Luhn)
		{"1196001337", true},  // Valid NPI
		{"1890838638", true},  // Valid NPI
		{"1794026546", true},  // Valid NPI
		{"1234567893", true},  // Valid NPI
		{"1234567890", false}, // Invalid NPI Luhn
		{"1111111111", false}, // Invalid NPI Luhn
	}

	for _, tt := range tests {
		t.Run(tt.npi, func(t *testing.T) {
			result := npiLuhnValid(tt.npi)
			if result != tt.valid {
				t.Errorf("npiLuhnValid(%s) = %v, want %v", tt.npi, result, tt.valid)
			}
		})
	}
}

func TestMedicalIDValidator_DEAChecksum(t *testing.T) {
	tests := []struct {
		dea   string
		valid bool
	}{
		{"AB1234563", true},  // Valid DEA checksum: (1+3+5) + 2*(2+4+6) = 9+24=33, 33%10=3=d7
		{"FC2014354", true},  // Valid: (2+1+3) + 2*(0+4+5) = 6+18=24, no wait let me recalc
		{"XY1234563", false}, // Invalid first char (X not in ABCDFGM)
		{"AB1234560", false}, // Invalid checksum
		{"AB123456", false},  // Too short
	}

	for _, tt := range tests {
		t.Run(tt.dea, func(t *testing.T) {
			result := deaChecksumValid(tt.dea)
			if result != tt.valid {
				t.Errorf("deaChecksumValid(%s) = %v, want %v", tt.dea, result, tt.valid)
			}
		})
	}
}

func TestMedicalIDValidator_NewValidator(t *testing.T) {
	validator := NewValidator()

	if validator == nil {
		t.Fatal("NewValidator() returned nil")
	}
	if len(validator.positiveKeywords) == 0 {
		t.Fatal("NewValidator() has no positive keywords")
	}
	if len(validator.negativeKeywords) == 0 {
		t.Fatal("NewValidator() has no negative keywords")
	}
}

func TestMedicalIDValidator_CalculateConfidence(t *testing.T) {
	validator := NewValidator()

	t.Run("Valid NPI returns 80", func(t *testing.T) {
		confidence, checks := validator.CalculateConfidence("1104332188")
		if confidence != 80.0 {
			t.Errorf("Expected 80.0 for valid NPI, got %.1f", confidence)
		}
		if !checks["has_checksum"] {
			t.Error("Expected has_checksum=true for valid NPI")
		}
	})

	t.Run("Valid DEA returns 85", func(t *testing.T) {
		confidence, checks := validator.CalculateConfidence("AB1234563")
		if confidence != 85.0 {
			t.Errorf("Expected 85.0 for valid DEA, got %.1f", confidence)
		}
		if !checks["has_checksum"] {
			t.Error("Expected has_checksum=true for valid DEA")
		}
	})

	t.Run("Generic match returns 50", func(t *testing.T) {
		confidence, _ := validator.CalculateConfidence("XYZ123456789")
		if confidence != 50.0 {
			t.Errorf("Expected 50.0 for generic match, got %.1f", confidence)
		}
	})
}

func TestMedicalIDValidator_ValidatorField(t *testing.T) {
	validator := NewValidator()

	content := "Provider NPI: 1104332188"
	matches, err := validator.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	for _, m := range matches {
		if m.Validator != "medicalid" {
			t.Errorf("Expected Validator='medicalid', got '%s'", m.Validator)
		}
	}
}

func TestMedicalIDValidator_FalsePositiveSuppression(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Random 10-digit number without context",
			content: "Reference: 1104332188",
		},
		{
			name:    "Phone number",
			content: "Phone: 1234567890",
		},
		{
			name:    "Account number",
			content: "Account: 1104332188",
		},
		{
			name:    "Invoice number",
			content: "Invoice: 1104332188",
		},
		{
			name:    "Tracking number",
			content: "Tracking: 1104332188",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Confidence >= 60 {
					t.Errorf("False positive: %s should not have high confidence (got %.1f for type %s, text %s)",
						tt.name, m.Confidence, m.Type, m.Text)
				}
			}
		})
	}
}
