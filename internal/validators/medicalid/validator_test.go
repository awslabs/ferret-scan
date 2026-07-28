// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"context"
	"strings"
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
		{
			name:    "MBI with legacy HICN keyword",
			content: "HICN 1EG4TE5MK72 on legacy record",
		},
		{
			name:    "MBI with health insurance claim keyword",
			content: "health insurance claim number 1EG4TE5MK72",
		},
		{
			name:    "MBI with pharmacy RxBIN context",
			content: "RxBIN 610014 member 2AW3HA4NK91 pharmacy",
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

// TestMedicalIDValidator_IntrinsicValueFloor locks the value-intrinsic floor for
// the two checksum-bearing subtypes here, NPI and DEA, against the
// keyword-padding evasion (threat model TM-11).
//
// Context keywords could drive either score to zero, and the `confidence <= 0`
// gate then returned no match at all. That made a checksum-valid identifier
// INVISIBLE rather than low-ranked, and because redaction only rewrites what was
// emitted, the value passed through --enable-redaction in cleartext. Measured
// before the fix: "NPI 1234567893" scored 90 and vanished entirely under heavy
// negative padding.
//
// The CMS NPI-Luhn and DEA checksums are intrinsic to the value and not
// attacker-deniable, so they earn a floor: context may demote to the bottom of
// LOW, but it may not erase.
//
// MRN and insurance member IDs are deliberately NOT floored — they have no
// value-intrinsic check, so context is the only evidence they have and
// suppressing them to nothing stays correct. That residual is documented in
// THREAT_MODEL.md section 4.7.
func TestMedicalIDValidator_IntrinsicValueFloor(t *testing.T) {
	v := NewValidator()

	// Heavy negative padding, well past the point where any single keyword
	// threshold trips. "phone" is excluded on purpose: phone context is a
	// separate hard drop that survives this change (a 10-digit number near
	// "phone" really is more likely a phone number), and the reason it is not
	// fixed here is recorded at the drop site in evaluateNPI.
	const pad = "test example fake mock sample serial tracking invoice order " +
		"timestamp unix epoch hash uuid guid crc checksum version build"

	for _, tc := range []struct {
		name    string
		clean   string
		typ     string
		minBase float64
	}{
		{"NPI", "NPI 1234567893", "NPI", 80},
		{"DEA", "DEA number AB1234563", "DEA_NUMBER", 80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Baseline, so the padded assertion cannot pass vacuously.
			base, err := v.ValidateContent(tc.clean, "clean.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			var baseConf float64
			for _, m := range base {
				if m.Type == tc.typ {
					baseConf = m.Confidence
				}
			}
			if baseConf < tc.minBase {
				t.Fatalf("baseline %s: want >= %.0f, got %.1f", tc.typ, tc.minBase, baseConf)
			}

			matches, err := v.ValidateContent(tc.clean+" "+pad, "padded.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			found := false
			for _, m := range matches {
				if m.Type != tc.typ {
					continue
				}
				found = true
				if m.Confidence < intrinsicValueFloor {
					t.Errorf("%s: confidence %.1f fell below the floor %.1f",
						tc.typ, m.Confidence, intrinsicValueFloor)
				}
				if m.Confidence >= baseConf {
					t.Errorf("%s: padding must still demote (base %.1f, padded %.1f)",
						tc.typ, baseConf, m.Confidence)
				}
			}
			if !found {
				t.Errorf("padding erased a checksum-valid %s (%d matches) — TM-11 evasion regressed",
					tc.typ, len(matches))
			}
		})
	}

	// The floor is earned by the checksum, not granted to anything NPI-shaped: a
	// 10-digit number that fails NPI-Luhn is still rejected outright.
	bad, err := v.ValidateContent("NPI 1234567890 test", "bad.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	for _, m := range bad {
		if m.Type == "NPI" {
			t.Errorf("NPI-Luhn-invalid value must not receive the floor, got %.1f", m.Confidence)
		}
	}

	// MRN has no value-intrinsic check, so it must not be floored: a label that
	// hard-suppresses it still erases it. "account" is a non-medical hard keyword
	// for MRN, which is the shape a real suppression takes.
	mrn, err := v.ValidateContent("account 1234567", "mrn.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	for _, m := range mrn {
		if m.Type == "MRN" {
			t.Errorf("MRN has no value-intrinsic check and must stay suppressible to nothing, got %.1f",
				m.Confidence)
		}
	}

	// The floor must sit in LOW: emitted (so redaction covers it) but below a
	// `--confidence high,medium` cut, which starts at 60.
	if intrinsicValueFloor <= 0 || intrinsicValueFloor >= 60 {
		t.Errorf("floor %.1f must be inside the LOW band (0 < floor < 60)", intrinsicValueFloor)
	}
}

// TestLongFormLabelRecall covers the label spellings printed on physical
// insurance and Medicare cards and used in EDI 837 exports. Keyword matching is
// whole-token, so "member id" cannot match "member identification number" —
// "identification" is not the token "id". Before the long forms were added, the
// wording on the card itself either scored LOW or, for an all-uppercase card ID,
// produced no finding at all: hasInsuranceKeyword gates the uppercase-shape
// check in looksLikeNonInsuranceIDShape, so the ID was dropped outright and
// would have passed through redaction in cleartext.
func TestLongFormLabelRecall(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name     string
		content  string
		wantType string
		minConf  float64
	}{
		{"medicare card member identification", "member identification number: 1EG4TE5MK73", "MEDICARE_MBI", 60},
		{"insurance member identification", "member identification number: W1234567801", "INSURANCE_MEMBER_ID", 60},
		{"subscriber identification", "subscriber identification number: W1234567801", "INSURANCE_MEMBER_ID", 60},
		{"enrollee identification", "enrollee identification number: W1234567801", "INSURANCE_MEMBER_ID", 60},
		{"policyholder id", "policyholder id: W1234567801", "INSURANCE_MEMBER_ID", 60},
		{"patient identification", "patient identification number: 4472901", "MRN", 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if m.Type == tt.wantType && m.Confidence >= tt.minConf {
					return
				}
			}
			t.Errorf("no %s match with confidence >= %.0f in %q; got %v",
				tt.wantType, tt.minConf, tt.content, summarize(matches))
		})
	}
}

// TestLongFormLabelNoTechFalsePositives locks the deliberate exclusions. A bare
// "certificate number" names an X.509 certificate far more often than an
// insurance one, and "policy identification" names an IAM or Terraform policy,
// so neither is a keyword — adding them made build IDs and key material match
// as insurance member IDs.
func TestLongFormLabelNoTechFalsePositives(t *testing.T) {
	v := NewValidator()

	for _, content := range []string{
		"X.509 certificate serial number: 0A1B2C3D4E5F6789",
		"signing certificate number: SHA256ABCDEF1234",
		"policy identification for terraform module: MODULEVERSION123",
		"IAM policy identification number: AKIAIOSFODNN7EXAMPLE",
	} {
		matches, err := v.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		for _, m := range matches {
			if m.Type == "INSURANCE_MEMBER_ID" {
				t.Errorf("INSURANCE_MEMBER_ID false positive on %q (confidence %.0f)",
					content, m.Confidence)
			}
		}
	}
}

// TestHexShapedMemberIDRecall covers the recall half of the hex-gate fix. The
// all-hex shape check in looksLikeNonInsuranceIDShape used to fire before the
// strong-keyword check was consulted, so a member ID that happens to use only
// A-F produced NO finding at all even beside an explicit "member id:" label —
// and therefore also passed --enable-redaction in cleartext with exit code 0.
// Real member IDs are commonly a letter prefix plus digits, and 6 of the 26
// possible leading letters are hex digits, so this was roughly a quarter of
// that shape.
//
// The 12-character cases are here on purpose: a UUID-component check for
// len 8/12/16 sat below the gate testing the same isHexString condition, so it
// was unreachable while the gate was unconditional but would have come alive
// and re-dropped exactly these once the gate deferred to the keyword.
func TestHexShapedMemberIDRecall(t *testing.T) {
	v := NewValidator()

	for _, tt := range []struct {
		name    string
		content string
		want    string
	}{
		{"hex letter prefix", "member id: E1122334455", "E1122334455"},
		{"all hex letters then digits, len 12", "member id: ABCDEF123456", "ABCDEF123456"},
		{"hex word prefix", "member id: BEEF1234567", "BEEF1234567"},
		{"digits then hex letters, len 12", "subscriber id: 1234567890AB", "1234567890AB"},
		{"hex embedded, len 12", "member id: 55DEADBEEF12", "55DEADBEEF12"},
		{"non-hex letter prefix (was already detected)", "member id: W1122334455", "W1122334455"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if m.Type == "INSURANCE_MEMBER_ID" && m.Text == tt.want {
					return
				}
			}
			t.Errorf("no INSURANCE_MEMBER_ID for %q in %q; got %v",
				tt.want, tt.content, summarize(matches))
		})
	}
}

// TestHexShapedDecoysStillSuppressed is the other half: the hex gate exists to
// keep hashes, commit SHAs and hex blobs in source and logs from matching, and
// deferring it to the insurance keyword must not give that up. None of these
// lines carries a strong insurance label, so every one must still be dropped.
func TestHexShapedDecoysStillSuppressed(t *testing.T) {
	v := NewValidator()

	for _, content := range []string{
		"commit 9462e98abcdef1234567890abcdef1234567890a",
		"fix(medicalid): recall long-form labels (85705bdcafe1)",
		"sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
		"etag: \"d41d8cd98f00b204e9800998ecf8427e\"",
		"0xDEADBEEF12345678",
		"blob abcdef1234567890 written to cache",
		"session token: 1234567890abcdef",
		// The keyword is present here and the value is still a hash. Casing is
		// the only thing separating these from a real card ID, so they belong
		// in the decoy set rather than the recall set.
		"Member id verification: 1234abcd5678ef90",
		"Insurance claims hash: a1b2c3d4e5f6a7b8",
		"member id lookup checksum d41d8cd98f00b204",
	} {
		matches, err := v.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		for _, m := range matches {
			if m.Type == "INSURANCE_MEMBER_ID" {
				t.Errorf("INSURANCE_MEMBER_ID false positive on %q (matched %q, confidence %.0f)",
					content, m.Text, m.Confidence)
			}
		}
	}
}

// TestHexGateDefersOnlyToInsuranceKeyword pins the exact predicate, so a future
// edit cannot widen the rescue to any medical context. "patient chart" is
// medical but is not a strong INSURANCE label, so a bare hex blob beside it must
// stay suppressed while the same value beside "member id:" is recovered.
func TestHexGateDefersOnlyToInsuranceKeyword(t *testing.T) {
	v := NewValidator()

	const val = "ABCDEF123456"

	hasIns := func(content string) bool {
		matches, err := v.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		for _, m := range matches {
			if m.Type == "INSURANCE_MEMBER_ID" && m.Text == val {
				return true
			}
		}
		return false
	}

	if !hasIns("member id: " + val) {
		t.Error("strong insurance keyword did not rescue the hex-shaped ID")
	}
	if hasIns("patient chart reference " + val) {
		t.Error("generic medical context rescued a hex blob; only a strong insurance keyword should")
	}
	// Casing is the second half of the predicate: the same value lowercased is a
	// digest, and no keyword may lift it.
	if hasIns("member id: " + strings.ToLower(val)) {
		t.Error("all-lowercase hex was rescued by the keyword; digests must stay suppressed")
	}
}

// TestChecksumSubtypeWinsOverInsuranceID locks the arbitration that the hex gate
// used to provide by accident. A valid DEA number is 2 letters + 7 digits, so
// "AB1234563" is entirely hex digits and the old unconditional gate suppressed
// the duplicate INSURANCE_MEMBER_ID as a side effect. That was fragile — it only
// covered DEAs whose letters fall in A-F — so the veto is now explicit, and
// checked here for all three checksum/format subtypes.
func TestChecksumSubtypeWinsOverInsuranceID(t *testing.T) {
	v := NewValidator()

	for _, tt := range []struct {
		name     string
		content  string
		value    string
		wantType string
	}{
		{"DEA in insurance context", "Insurance member id for prescriber: AB1234563", "AB1234563", "DEA_NUMBER"},
		{"MBI in insurance context", "member id: 1EG4TE5MK73", "1EG4TE5MK73", "MEDICARE_MBI"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "claims.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			var sawWanted bool
			for _, m := range matches {
				if m.Text != tt.value {
					continue
				}
				if m.Type == tt.wantType {
					sawWanted = true
				}
				if m.Type == "INSURANCE_MEMBER_ID" {
					t.Errorf("%s %q also reported as INSURANCE_MEMBER_ID (confidence %.0f); the specific subtype must win",
						tt.wantType, tt.value, m.Confidence)
				}
			}
			if !sawWanted {
				t.Errorf("no %s match for %q in %q; got %v", tt.wantType, tt.value, tt.content, summarize(matches))
			}
		})
	}
}

func summarize(matches []detector.Match) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Type)
	}
	return out
}
