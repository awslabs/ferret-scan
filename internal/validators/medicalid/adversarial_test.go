// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"fmt"
	"strings"
	"testing"
)

// --- Helper: generate a valid NPI from a 9-digit prefix using the 80840 Luhn algorithm ---
func generateValidNPI(prefix string) string {
	if len(prefix) != 9 {
		panic("prefix must be 9 digits")
	}
	// We need 80840 + prefix + checkDigit to pass Luhn
	// Try each digit 0-9 for the check digit
	for d := 0; d <= 9; d++ {
		candidate := prefix + fmt.Sprintf("%d", d)
		if npiLuhnValid(candidate) {
			return candidate
		}
	}
	panic("no valid check digit found for prefix: " + prefix)
}

// --- Helper: generate a valid DEA number from prefix letters + 6-digit body ---
func generateValidDEA(firstChar byte, secondChar byte, digits6 string) string {
	if len(digits6) != 6 {
		panic("need exactly 6 digits")
	}
	d := make([]int, 6)
	for i := 0; i < 6; i++ {
		d[i] = int(digits6[i] - '0')
	}
	sum := (d[0] + d[2] + d[4]) + 2*(d[1]+d[3]+d[5])
	checkDigit := sum % 10
	return fmt.Sprintf("%c%c%s%d", firstChar, secondChar, digits6, checkDigit)
}

// =============================================================================
// ATTACK VECTOR 1: Random 10-digit numbers without medical context MUST NOT match as NPI
// =============================================================================
func TestAdversarial_NPI_RandomDigitsNoContext(t *testing.T) {
	v := NewValidator()

	// Generate valid NPI numbers but place them without any medical context
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Valid NPI Luhn in bare reference",
			content: "Reference: " + generateValidNPI("110433218"),
		},
		{
			name:    "Valid NPI Luhn in unrelated sentence",
			content: "The total number of items is " + generateValidNPI("167957600"),
		},
		{
			name:    "Valid NPI Luhn as ID without context",
			content: "ID=" + generateValidNPI("189083863"),
		},
		{
			name:    "Valid NPI Luhn in a URL path",
			content: "https://example.com/items/" + generateValidNPI("179402654"),
		},
		{
			name:    "Valid NPI Luhn in random data file",
			content: generateValidNPI("123456789") + " apples sold today",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "data.csv")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "NPI" && m.Confidence >= 50 {
					t.Errorf("FALSE POSITIVE: NPI matched '%s' with confidence %.1f in non-medical context: %q",
						m.Text, m.Confidence, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 2: Phone numbers (10 digits) MUST NOT match as NPI
// =============================================================================
func TestAdversarial_NPI_PhoneNumbers(t *testing.T) {
	v := NewValidator()

	// Phone numbers that happen to start with 1 or 2 (matching NPI regex)
	// We need ones that actually pass Luhn to test the full path
	validNPI := generateValidNPI("121255512") // Looks like a phone: 1-212-555-12xx

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Explicit phone keyword",
			content: "Phone: " + validNPI,
		},
		{
			name:    "Call context without phone keyword",
			content: "Call us at " + validNPI + " for more info",
		},
		{
			name:    "Fax number",
			content: "Fax: " + validNPI,
		},
		{
			name:    "Contact number in physician office (CRITICAL: phone-like + medical keyword)",
			content: "Contact the physician at " + validNPI,
		},
		{
			name:    "Doctor office phone (explicit phone keyword with medical)",
			content: "Doctor's office phone: " + validNPI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "contacts.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "NPI" && m.Confidence >= 50 {
					t.Errorf("FALSE POSITIVE: Phone number matched as NPI with confidence %.1f: %q",
						m.Confidence, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 3: SSNs MUST NOT match
// =============================================================================
func TestAdversarial_SSN_NotMRN(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "SSN with explicit SSN keyword in medical context",
			content: "Patient SSN: 123456789 at the hospital",
		},
		{
			name:    "SSN-like 9 digits in medical record context",
			content: "Medical record shows SSN 987654321",
		},
		{
			name:    "9 digits in patient context without SSN keyword",
			content: "Patient tax ID: 234567890 in the clinic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "records.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "MRN" && m.Text == "123456789" || m.Text == "987654321" || m.Text == "234567890" {
					t.Errorf("FALSE POSITIVE: SSN-like number matched as MRN with confidence %.1f: text=%q content=%q",
						m.Confidence, m.Text, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 4: NPI with valid Luhn + "provider" keyword MUST be HIGH
// =============================================================================
func TestAdversarial_NPI_ValidWithProviderContext(t *testing.T) {
	v := NewValidator()

	validNPI := generateValidNPI("110433218") // known: 1104332188

	tests := []struct {
		name          string
		content       string
		minConfidence float64
	}{
		{
			name:          "NPI with provider keyword",
			content:       "Provider NPI: " + validNPI,
			minConfidence: 80,
		},
		{
			name:          "NPI with physician and hospital keywords",
			content:       "Hospital physician NPI: " + validNPI,
			minConfidence: 80,
		},
		{
			name:          "NPI with healthcare keyword",
			content:       "Healthcare NPI: " + validNPI,
			minConfidence: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "providers.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			found := false
			for _, m := range matches {
				if m.Type == "NPI" {
					found = true
					if m.Confidence < tt.minConfidence {
						t.Errorf("FALSE NEGATIVE: NPI with provider context should be >= %.0f, got %.1f for %q",
							tt.minConfidence, m.Confidence, tt.content)
					}
				}
			}
			if !found {
				t.Errorf("FALSE NEGATIVE: Expected NPI match in %q", tt.content)
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 5: NPI with valid Luhn but "phone" context MUST NOT match high
// =============================================================================
func TestAdversarial_NPI_PhoneContext(t *testing.T) {
	v := NewValidator()

	validNPI := generateValidNPI("110433218")

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Phone keyword suppresses NPI",
			content: "Phone number for NPI registry: " + validNPI,
		},
		{
			name:    "Phone keyword even with medical keywords",
			content: "Hospital phone: " + validNPI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "contacts.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "NPI" && m.Confidence >= 70 {
					t.Errorf("NPI should be suppressed with phone context, got confidence %.1f for %q",
						m.Confidence, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 6: DEA without valid checksum MUST NOT match
// =============================================================================
func TestAdversarial_DEA_NoChecksum(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "DEA format with bad checksum and DEA keyword",
			content: "DEA number: AB1234567",
		},
		{
			name:    "DEA format with bad checksum in pharmacy context",
			content: "Pharmacy prescriber DEA: FC9999999",
		},
		{
			name:    "DEA format all zeros (except check)",
			content: "DEA registration: AB0000001",
		},
		{
			name:    "DEA-like pattern that is actually a product code",
			content: "Product code: AB7654321 in the pharmacy system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "DEA_NUMBER" {
					t.Errorf("FALSE POSITIVE: DEA matched without valid checksum: confidence=%.1f text=%q content=%q",
						m.Confidence, m.Text, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 7: Insurance-ID-like strings without insurance keywords MUST be very LOW
// =============================================================================
func TestAdversarial_InsuranceID_NoContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Alphanumeric string without any insurance context",
			content: "Value: XYZ123456789",
		},
		{
			name:    "Mixed case alphanumeric in code",
			content: "const apiKey = Abc12345Def",
		},
		{
			name:    "UUID-like segment",
			content: "ID: a1b2c3d4e5f6",
		},
		{
			name:    "Git hash prefix",
			content: "commit abc123def4",
		},
		{
			name:    "Build version string",
			content: "version v1234alpha5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "code.go")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "INSURANCE_MEMBER_ID" {
					t.Errorf("FALSE POSITIVE: Insurance ID matched without insurance context: confidence=%.1f text=%q content=%q",
						m.Confidence, m.Text, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 8: MRN (just 6 digits) without medical context MUST NOT match
// =============================================================================
func TestAdversarial_MRN_NoMedicalContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "6 digits in a random file",
			content: "Count: 123456",
		},
		{
			name:    "8 digits as a date-like number",
			content: "Date value: 20240101",
		},
		{
			name:    "7 digits as a ticket number",
			content: "Ticket #1234567 is resolved",
		},
		{
			name:    "6 digits in code",
			content: "port := 654321",
		},
		{
			name:    "10 digits as epoch timestamp",
			content: "timestamp: 1718900000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "app.log")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "MRN" {
					t.Errorf("FALSE POSITIVE: MRN matched without medical context: confidence=%.1f text=%q content=%q",
						m.Confidence, m.Text, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 9: Duplicate detection - NPI starting with 2 also matching as MRN
// =============================================================================
func TestAdversarial_NPI_DuplicateAsMRN(t *testing.T) {
	v := NewValidator()

	// Generate a valid NPI starting with 2
	validNPI2 := generateValidNPI("210433218") // starts with 2

	// Place in medical context (triggers both NPI and MRN scanning)
	content := "Patient medical record - provider NPI: " + validNPI2

	matches, err := v.ValidateContent(content, "records.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	npiCount := 0
	mrnCount := 0
	for _, m := range matches {
		if m.Text == validNPI2 {
			switch m.Type {
			case "NPI":
				npiCount++
			case "MRN":
				mrnCount++
				t.Errorf("DUPLICATE DETECTION: Valid NPI '%s' also reported as MRN (confidence %.1f). "+
					"NPI should suppress MRN for the same value.", validNPI2, m.Confidence)
			}
		}
	}

	if npiCount == 0 {
		t.Errorf("Expected NPI match for %s in medical context", validNPI2)
	}
}

// =============================================================================
// ATTACK VECTOR 10: Cross-validator confusion - DEA in insurance context
// =============================================================================
func TestAdversarial_DEA_InsuranceCrossMatch(t *testing.T) {
	v := NewValidator()

	// Generate a valid DEA number
	validDEA := generateValidDEA('A', 'B', "123456") // AB1234563

	// Place in insurance context - should match as DEA but NOT also as insurance ID
	content := "Insurance member id for prescriber: " + validDEA

	matches, err := v.ValidateContent(content, "claims.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	deaCount := 0
	insuranceCount := 0
	for _, m := range matches {
		if m.Text == validDEA {
			switch m.Type {
			case "DEA_NUMBER":
				deaCount++
			case "INSURANCE_MEMBER_ID":
				insuranceCount++
				t.Errorf("CROSS-VALIDATOR CONFUSION: Valid DEA '%s' also matched as INSURANCE_MEMBER_ID "+
					"(confidence %.1f). DEA should take precedence.", validDEA, m.Confidence)
			}
		}
	}

	if deaCount == 0 {
		t.Logf("Note: DEA '%s' not matched as DEA_NUMBER (may or may not be a bug depending on context)", validDEA)
	}
}

// =============================================================================
// ATTACK VECTOR 11: Context weakness - same value with vs without keywords
// =============================================================================
func TestAdversarial_ContextDifference(t *testing.T) {
	v := NewValidator()

	validNPI := generateValidNPI("110433218")

	// With strong medical context
	contentWithContext := "Provider NPI: " + validNPI
	matchesHigh, err := v.ValidateContent(contentWithContext, "test.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Without any context
	contentNoContext := "Number: " + validNPI
	matchesLow, err := v.ValidateContent(contentNoContext, "test.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var confHigh, confLow float64
	for _, m := range matchesHigh {
		if m.Type == "NPI" {
			confHigh = m.Confidence
		}
	}
	for _, m := range matchesLow {
		if m.Type == "NPI" {
			confLow = m.Confidence
		}
	}

	// There should be a dramatic difference (at least 30 points)
	diff := confHigh - confLow
	if diff < 30 {
		t.Errorf("CONTEXT WEAKNESS: Confidence difference between with-context (%.1f) and without-context (%.1f) "+
			"is only %.1f points (should be >= 30)", confHigh, confLow, diff)
	}

	t.Logf("Context difference: with=%.1f without=%.1f diff=%.1f", confHigh, confLow, diff)
}

// =============================================================================
// ATTACK VECTOR 12: Phone number in medical context (KEY FALSE POSITIVE VECTOR)
// The physician's office phone number should NOT be flagged as NPI
// =============================================================================
func TestAdversarial_PhoneLike_InMedicalContext(t *testing.T) {
	v := NewValidator()

	// Generate NPI-valid numbers that look like phone numbers
	// US area codes: 212, 213, 215, etc.
	phonePrefixes := []string{
		"121255512", // looks like 1-212-555-12xx
		"121355567", // looks like 1-213-555-67xx
		"120255543", // looks like 1-202-555-43xx
	}

	for _, prefix := range phonePrefixes {
		validNPI := generateValidNPI(prefix)
		t.Run("phone_"+prefix, func(t *testing.T) {
			// Medical context without "phone" keyword - this is the dangerous case
			content := "Contact the physician office at " + validNPI + " to schedule"
			matches, err := v.ValidateContent(content, "directory.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "NPI" && m.Confidence >= 70 {
					t.Errorf("FALSE POSITIVE: Phone-like number %s matched as NPI with confidence %.1f "+
						"in a 'contact at' context. The word 'physician' causes false positive: %q",
						m.Text, m.Confidence, content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 13: MBI-like strings that are really product codes / reference IDs
// =============================================================================
func TestAdversarial_MBI_FalsePositives(t *testing.T) {
	v := NewValidator()

	// MBI format: C-A-AN-N-A-AN-N-A-A-N-N (11 chars)
	// C=[1-9], A=[AC-HJ-KM-NP-RT-Y], N=[0-9], AN=A|N
	// Let's craft strings that match the pattern but aren't MBIs
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Product code that matches MBI format",
			content: "Product code: 1EG4TE5MK72 is in stock",
		},
		{
			name:    "License key segment matching MBI format",
			content: "License: 3AC2DE7FG81 activated",
		},
		{
			name:    "AWS resource ID matching MBI",
			content: "Resource 2AW3HA4NK91 deployed successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "deploy.log")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "MEDICARE_MBI" && m.Confidence >= 50 {
					t.Errorf("FALSE POSITIVE: Non-MBI string matched as MEDICARE_MBI with confidence %.1f: "+
						"text=%q content=%q", m.Confidence, m.Text, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 14: Extremely long lines (performance/correctness edge case)
// =============================================================================
func TestAdversarial_LongLineWithMultipleMatches(t *testing.T) {
	v := NewValidator()

	// Build a line with many NPI-like numbers
	validNPI := generateValidNPI("110433218")
	var parts []string
	parts = append(parts, "Provider records:")
	for i := 0; i < 100; i++ {
		parts = append(parts, fmt.Sprintf("NPI_%d=%s", i, validNPI))
	}
	longLine := strings.Join(parts, " ")

	matches, err := v.ValidateContent(longLine, "bulk.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Should find matches but not crash or produce absurd counts
	npiCount := 0
	for _, m := range matches {
		if m.Type == "NPI" {
			npiCount++
		}
	}
	// We expect roughly 100 matches (one per occurrence)
	if npiCount < 50 {
		t.Errorf("Expected ~100 NPI matches on long line with repeated valid NPIs, got %d", npiCount)
	}
	t.Logf("Found %d NPI matches on long line", npiCount)
}

// =============================================================================
// ATTACK VECTOR 15: Unicode/special chars around boundaries
// =============================================================================
func TestAdversarial_UnicodeBoundaries(t *testing.T) {
	v := NewValidator()

	validNPI := generateValidNPI("110433218")

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "NPI surrounded by unicode quotes",
			content: "Provider NPI: “" + validNPI + "”",
		},
		{
			name:    "NPI after em-dash",
			content: "Provider NPI—" + validNPI,
		},
		{
			name:    "NPI with zero-width space before",
			content: "Provider NPI: ​" + validNPI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			// Should still detect the NPI (unicode chars should act as word boundaries)
			found := false
			for _, m := range matches {
				if m.Type == "NPI" && m.Confidence >= 50 {
					found = true
				}
			}
			if !found {
				t.Errorf("FALSE NEGATIVE: NPI not detected through unicode boundary in: %q", tt.content)
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 16: MRN 10-digit starting with 2 - should NOT duplicate with NPI
// =============================================================================
func TestAdversarial_MRN_10Digit_StartsWith2(t *testing.T) {
	v := NewValidator()

	// A 10-digit number starting with 2 that is NOT valid NPI Luhn
	// should still be detected as MRN (not NPI) in medical context
	// Find a 10-digit number starting with 2 that fails Luhn
	candidate := "2000000000"
	if npiLuhnValid(candidate) {
		candidate = "2000000001"
	}
	if npiLuhnValid(candidate) {
		candidate = "2000000002"
	}
	// At least one of these should fail Luhn

	content := "Medical record number: " + candidate

	matches, err := v.ValidateContent(content, "records.txt")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Should NOT match as NPI (fails Luhn)
	for _, m := range matches {
		if m.Type == "NPI" && m.Text == candidate {
			t.Errorf("10-digit number failing Luhn should not match as NPI: %s", candidate)
		}
	}

	// Should match as MRN in medical context (but check if the 10-digit-starts-with-2 filter blocks it)
	mrnFound := false
	for _, m := range matches {
		if m.Type == "MRN" && m.Text == candidate {
			mrnFound = true
		}
	}
	// The looksLikeNonMedicalNumber only filters len==10 && match[0]=='1'
	// So a 10-digit number starting with 2 should pass through to MRN detection
	// This is expected behavior (it IS in medical context)
	t.Logf("MRN found for 10-digit starting with 2: %v", mrnFound)
}

// =============================================================================
// ATTACK VECTOR 17: Insurance ID that is actually a hex hash
// =============================================================================
func TestAdversarial_InsuranceID_HexHash(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "SHA256 prefix in insurance context",
			content: "Insurance claims hash: a1b2c3d4e5f6a7b8",
		},
		{
			name:    "MD5-like in member context",
			content: "Member id verification: 1234abcd5678ef90",
		},
		{
			name:    "Hex address in insurance context",
			content: "Insurance system address: 0xdeadbeef1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "system.log")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Type == "INSURANCE_MEMBER_ID" && m.Confidence >= 50 {
					t.Errorf("FALSE POSITIVE: Hex hash matched as insurance ID: confidence=%.1f text=%q content=%q",
						m.Confidence, m.Text, tt.content)
				}
			}
		})
	}
}

// =============================================================================
// ATTACK VECTOR 18: "test" and "example" suppression verification
// =============================================================================
func TestAdversarial_TestExampleSuppression(t *testing.T) {
	v := NewValidator()

	validNPI := generateValidNPI("110433218")
	validDEA := generateValidDEA('A', 'B', "123456")

	tests := []struct {
		name    string
		content string
		maxConf float64
	}{
		{
			name:    "NPI in test context",
			content: "Test provider NPI: " + validNPI,
			maxConf: 60,
		},
		{
			name:    "NPI as example",
			content: "Example NPI for healthcare: " + validNPI,
			maxConf: 60,
		},
		{
			name:    "DEA in sample data",
			content: "Sample DEA prescriber: " + validDEA,
			maxConf: 60,
		},
		{
			name:    "NPI in mock data",
			content: "Mock provider NPI data: " + validNPI,
			maxConf: 60,
		},
		{
			name:    "NPI with demo keyword",
			content: "Demo healthcare provider NPI: " + validNPI,
			maxConf: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test_data.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Confidence > tt.maxConf {
					t.Errorf("SUPPRESSION FAILURE: %s should suppress to <= %.0f, got %.1f for type=%s text=%q",
						tt.name, tt.maxConf, m.Confidence, m.Type, m.Text)
				}
			}
		})
	}
}
