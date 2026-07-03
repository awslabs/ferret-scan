// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
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

// TestVINValidator_NonNorthAmericanCheckDigit is a regression test for the
// mandatory-check-digit gate that silently dropped most non-North-American
// VINs. The ISO 3779 check digit is required only for WMI region 1-5 (North
// America); EU/Asian manufacturers commonly do not encode it, so genuine VINs
// from WVW/WAU/ZFF (all in knownWMIs) were being hard-rejected. We assert those
// are now detected, while VINs that fail the check digit WITHOUT a corroborating
// signal (NA region, or unknown WMI) remain rejected so we add no false positives.
func TestVINValidator_NonNorthAmericanCheckDigit(t *testing.T) {
	validator := NewValidator()

	// True positives recovered: non-NA VINs with a known WMI that fail the
	// (optional) NA check digit.
	detect := []struct {
		name    string
		content string
	}{
		{"VW Europe", "VIN: WVWZZZ1JZ3W386752"},
		{"Audi Europe", "vehicle identification number WAUZZZ8K9BA123456"},
		{"Ferrari Italy", "chassis ZFF67NFA8E0193082 on file"},
	}
	for _, tt := range detect {
		t.Run("detect/"+tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("%s: expected non-NA VIN to be detected, got none", tt.name)
			}
		})
	}

	// False-positive guards: failing the check digit with no corroboration must
	// still be rejected.
	reject := []struct {
		name    string
		content string
	}{
		// Non-NA shape, unknown WMI, bad check digit -> not enough signal.
		{"Unknown WMI random token", "ref ABCDEFGH1JKLMNPRS in log"},
		// North American region (starts with 1) with a wrong check digit is a
		// genuinely invalid VIN and must stay rejected (unchanged behavior).
		{"NA VIN bad check digit", "VIN: 1HGBH41JAMN109186"},
	}
	for _, tt := range reject {
		t.Run("reject/"+tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("%s: expected no match, got %d", tt.name, len(matches))
			}
		})
	}

	// A verified (valid check digit) VIN should still outscore a non-NA VIN that
	// relies only on its WMI, so ranking still favors fully-validated VINs. We
	// check the base score directly: in the full pipeline a positive context
	// keyword ("VIN:") saturates both to 100, masking the (real) base-score gap.
	verifiedConf, vChecks := validator.CalculateConfidence("1HGBH41JXMN109186")
	wmiOnlyConf, wChecks := validator.CalculateConfidence("WVWZZZ1JZ3W386752")
	if !vChecks["check_digit"] {
		t.Error("expected valid check digit for 1HGBH41JXMN109186")
	}
	if wChecks["check_digit"] {
		t.Error("expected invalid check digit for WVWZZZ1JZ3W386752")
	}
	if wmiOnlyConf >= verifiedConf {
		t.Errorf("check-digit-valid VIN (%.1f) should outscore WMI-only VIN (%.1f)",
			verifiedConf, wmiOnlyConf)
	}
}

// TestVINValidator_LowercaseAndMixedCase is a regression test for M19: the
// uppercase-only regex never matched lowercase/mixed-case VINs (common in
// logs/JSON/CSV), and the downstream ToUpper was a detection no-op.
func TestVINValidator_LowercaseAndMixedCase(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"vin: 1hgbh41jxmn109186",
		"vin 1HgBh41JxMn109186",
		"chassis WVWZZZ1JZ3W386752 logged",
	} {
		matches, err := v.ValidateContent(line, "test.txt")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(matches) == 0 {
			t.Errorf("lowercase/mixed-case VIN should be detected for %q, got none", line)
		}
	}
}

// TestVINValidator_KeywordWordBoundary is a regression test for M18: context
// keywords matched as substrings ("car" in "carbon", negative "sha" in "shall")
// fabricated or suppressed confidence. Matching is now whole-word.
func TestVINValidator_KeywordWordBoundary(t *testing.T) {
	v := NewValidator()
	// Phantom positives must contribute nothing.
	if imp := v.AnalyzeContext("X", detector.ContextInfo{FullLine: "carbon moving study"}); imp != 0 {
		t.Errorf("'carbon'/'moving' should not register as VIN keywords, impact=%.1f", imp)
	}
	// Phantom negative must contribute nothing.
	if imp := v.AnalyzeContext("X", detector.ContextInfo{FullLine: "we shall proceed"}); imp != 0 {
		t.Errorf("'shall' should not register as negative keyword 'sha', impact=%.1f", imp)
	}
	// Real keywords still boost.
	if imp := v.AnalyzeContext("X", detector.ContextInfo{FullLine: "vehicle vin chassis"}); imp <= 0 {
		t.Errorf("real VIN keywords should boost, impact=%.1f", imp)
	}
}

// TestVINValidator_HexDumpHeuristic is a regression test for L47: the 0x>=3
// count dropped a valid VIN whenever its line mentioned three hex literals
// (e.g. color values). A real hex dump must still be rejected.
func TestVINValidator_HexDumpHeuristic(t *testing.T) {
	v := NewValidator()
	// Valid VIN with incidental hex color literals must still be detected.
	m, _ := v.ValidateContent("VIN 1HGBH41JXMN109186 colors 0xFF0000 0x00FF00 0x0000FF", "test.txt")
	if len(m) == 0 {
		t.Error("L47: valid VIN with incidental hex literals should be detected")
	}
	// A genuine hex dump (majority 0x tokens) is still recognized as encoded.
	if !looksLikeHexDump("0x1A 0x2B 0x3C 0x4D 0x5E 0x6F") {
		t.Error("L47: a real hex dump should be recognized")
	}
	if looksLikeHexDump("VIN 1HGBH41JXMN109186 colors 0xFF0000 0x00FF00 0x0000FF") {
		t.Error("L47: a VIN line with a few hex literals is not a hex dump")
	}
}

// TestVINValidator_SingleLineDoSGuard is a performance regression test for the
// O(n^2) blowup that occurred on a SINGLE very long line packed with candidate
// VINs. The original ValidateContent recomputed per-line-global work (the
// match offset via strings.Index, the hex-dump heuristics, and a ~60-keyword
// case-insensitive scan of the WHOLE line — twice, for AnalyzeContext and
// findKeywords) once PER MATCH, making one line O(M*L) and a ~1MB line take
// many minutes (it would not complete within the package test timeout). After
// hoisting per-line work and using regex offsets the cost is linear. We assert
// a ~1MB single line of valid VINs validates well within a generous ceiling so
// any reintroduced quadratic behavior is caught (the fixed implementation runs
// in well under a second; the 5s ceiling tolerates slow/loaded CI hosts).
func TestVINValidator_SingleLineDoSGuard(t *testing.T) {
	const vin = "1HGBH41JXMN109186" // valid check digit, known WMI (Honda)
	const n = 60000                 // ~1MB on a single line, no newlines

	parts := make([]string, n)
	for i := range parts {
		parts[i] = vin
	}
	line := strings.Join(parts, " ") // single line: contains no '\n'

	v := NewValidator()
	start := time.Now()
	matches, err := v.ValidateContent(line, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if len(matches) != n {
		t.Errorf("expected %d matches on packed single line, got %d", n, len(matches))
	}
	if raceEnabled {
		// -race inflates wall-clock 5-20x; the scan ran above (so -race checks
		// the per-line cached state for data races), but the timing ceiling is
		// meaningless and skipped.
		t.Logf("packed single line: %d bytes, %d matches (timing assertion skipped under -race)", len(line), len(matches))
		return
	}
	const ceiling = 5 * time.Second
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a ~1MB single line took %s, exceeding %s "+
			"ceiling: the per-line O(n^2) DoS may have regressed", elapsed, ceiling)
	}
	t.Logf("packed single line: %d bytes, %d matches, validated in %s", len(line), len(matches), elapsed)
}
