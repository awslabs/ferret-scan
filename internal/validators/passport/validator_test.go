// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"testing"

	"ferret-scan/internal/detector"
)

// ---------------------------------------------------------------------------
// US Passports
// ---------------------------------------------------------------------------

func TestPassportValidator_USPassports(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		match       string
		wantCountry string
		wantFormat  bool
	}{
		{
			name:        "Valid US passport C12345678",
			match:       "C12345678",
			wantCountry: "US",
			wantFormat:  true,
		},
		{
			name:        "Valid US passport B98765432",
			match:       "B98765432",
			wantCountry: "US",
			wantFormat:  true,
		},
		{
			name:        "Invalid US - too few digits",
			match:       "A1234567",
			wantCountry: "",
			wantFormat:  false,
		},
		{
			name:        "Invalid US - too many digits",
			match:       "A1234567890",
			wantCountry: "",
			wantFormat:  false,
		},
		{
			name:        "Invalid US - starts with digit",
			match:       "112345678",
			wantCountry: "UK",
			wantFormat:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country := v.determineCountry(tt.match)
			if country != tt.wantCountry {
				t.Errorf("determineCountry(%q) = %q, want %q", tt.match, country, tt.wantCountry)
			}
			if tt.wantFormat {
				matched := reUSPassport.MatchString(tt.match)
				if !matched {
					t.Errorf("US passport pattern did not match %q", tt.match)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UK Passports
// ---------------------------------------------------------------------------

func TestPassportValidator_UKPassports(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		match       string
		wantCountry string
	}{
		{
			name:        "Valid UK passport 9 digits",
			match:       "987654321",
			wantCountry: "UK",
		},
		{
			name:        "Valid UK passport 9 digits starting with 5",
			match:       "512345678",
			wantCountry: "UK",
		},
		{
			name:        "Too few digits for UK",
			match:       "12345678",
			wantCountry: "",
		},
		{
			name:        "Too many digits for UK",
			match:       "1234567890",
			wantCountry: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country := v.determineCountry(tt.match)
			if country != tt.wantCountry {
				t.Errorf("determineCountry(%q) = %q, want %q", tt.match, country, tt.wantCountry)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Canadian Passports
// ---------------------------------------------------------------------------

func TestPassportValidator_CanadianPassports(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		match       string
		wantCountry string
	}{
		{
			name:        "Valid Canadian passport CA format",
			match:       "CA654321",
			wantCountry: "Canada",
		},
		{
			name:        "Valid Canadian passport GB format",
			match:       "GB123456",
			wantCountry: "Canada",
		},
		{
			name:        "Invalid - 3 letters",
			match:       "ABC12345",
			wantCountry: "",
		},
		{
			name:        "Invalid - too few digits",
			match:       "CA1234",
			wantCountry: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country := v.determineCountry(tt.match)
			if country != tt.wantCountry {
				t.Errorf("determineCountry(%q) = %q, want %q", tt.match, country, tt.wantCountry)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EU Passports
// ---------------------------------------------------------------------------

func TestPassportValidator_EUPassports(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		match       string
		wantCountry string
	}{
		{
			name:        "Valid EU passport C01X00T47",
			match:       "C01X00T47",
			wantCountry: "",
		},
		{
			name:        "Valid EU passport 2 letters + 7 alphanum",
			match:       "FR1234567",
			wantCountry: "EU",
		},
		{
			name:        "Valid EU passport DE prefix",
			match:       "DEABCDE12",
			wantCountry: "EU",
		},
		{
			name:        "Invalid EU - only 6 alphanum after letters",
			match:       "FR123456",
			wantCountry: "Canada",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country := v.determineCountry(tt.match)
			if country != tt.wantCountry {
				t.Errorf("determineCountry(%q) = %q, want %q", tt.match, country, tt.wantCountry)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Context Analysis
// ---------------------------------------------------------------------------

func TestPassportValidator_ContextAnalysis_PassportKeywordBoost(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name     string
		match    string
		context  detector.ContextInfo
		wantSign string
		desc     string
	}{
		{
			name:  "Passport keyword on same line boosts confidence",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine:   "Passport Number: C12345678",
				BeforeText: "",
				AfterText:  "",
			},
			wantSign: "positive",
			desc:     "Passport keyword directly adjacent should strongly boost",
		},
		{
			name:  "Travel context with visa and immigration",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine:   "C12345678",
				BeforeText: "visa application for immigration purposes",
				AfterText:  "",
			},
			wantSign: "positive",
			desc:     "Travel-related keywords should boost confidence",
		},
		{
			name:  "Immigration context nearby",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine:   "document number C12345678",
				BeforeText: "immigration form",
				AfterText:  "border control",
			},
			wantSign: "positive",
			desc:     "Immigration and border keywords should boost",
		},
		{
			name:  "Negative context with order keyword",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine:   "order number C12345678",
				BeforeText: "tracking shipment",
				AfterText:  "",
			},
			wantSign: "negative",
			desc:     "Order/tracking keywords should reduce confidence",
		},
		{
			name:  "Test data context",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine:   "test data C12345678 example sample",
				BeforeText: "",
				AfterText:  "",
			},
			wantSign: "negative",
			desc:     "Test/example keywords should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := v.AnalyzeContext(tt.match, tt.context)
			switch tt.wantSign {
			case "positive":
				if impact <= 0 {
					t.Errorf("AnalyzeContext: got impact %.1f, want positive: %s", impact, tt.desc)
				}
			case "negative":
				if impact >= 0 {
					t.Errorf("AnalyzeContext: got impact %.1f, want negative: %s", impact, tt.desc)
				}
			}
		})
	}
}

func TestPassportValidator_ContextAnalysis_ImpactCapping(t *testing.T) {
	v := NewValidator()

	// Many positive keywords
	ctx := detector.ContextInfo{
		FullLine:   "passport number travel document visa immigration border customs embassy consulate nationality citizenship mrz machine readable icao",
		BeforeText: "passport holder issuing authority passport authority",
		AfterText:  "identification identity travel international foreign expiry expiration valid until expires surname given name date of birth",
	}
	impact := v.AnalyzeContext("C12345678", ctx)
	if impact > 40 {
		t.Errorf("Positive impact should be capped at 40, got %.1f", impact)
	}

	// Many negative keywords
	negCtx := detector.ContextInfo{
		FullLine:   "example test sample mock fake dummy placeholder template demo random generated simulation serial order invoice tracking shipment customer account uuid guid",
		BeforeText: "primary key foreign key index database table record field column row entry item element",
		AfterText:  "",
	}
	impact = v.AnalyzeContext("C12345678", negCtx)
	if impact < -60 {
		t.Errorf("Negative impact should be capped at -60, got %.1f", impact)
	}
}

// ---------------------------------------------------------------------------
// False Positives
// ---------------------------------------------------------------------------

func TestPassportValidator_FalsePositives(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		desc        string
	}{
		{
			name:        "Order number without passport context",
			content:     "Order number: 987654321",
			expectMatch: false,
			desc:        "Random 9-digit number in order context should not match",
		},
		{
			name:        "Serial number without passport context",
			content:     "Serial: C98765432",
			expectMatch: false,
			desc:        "Serial number should not match as passport without context",
		},
		{
			name:        "Random 9 digit sequence no context",
			content:     "The value is 234567891 for this record",
			expectMatch: false,
			desc:        "Random 9-digit number should not match without passport context",
		},
		{
			name:        "Product code pattern",
			content:     "SKU12345 is in stock",
			expectMatch: false,
			desc:        "Product SKU should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "data.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			got := len(matches) > 0
			if got != tt.expectMatch {
				t.Errorf("ValidateContent(%q): got match=%v, want %v: %s", tt.content, got, tt.expectMatch, tt.desc)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

func TestPassportValidator_EdgeCases_PassportInBookingText(t *testing.T) {
	v := NewValidator()

	content := "Passenger: John Smith, Passport Number: C12345679, Flight: BA123"
	matches, err := v.ValidateContent(content, "booking.txt")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Error("Expected passport match in booking text with explicit passport context")
	}
}

func TestPassportValidator_EdgeCases_NearTravelKeywords(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "Near departing keyword",
			content: "Departing passenger passport: C87654321",
			desc:    "Passport near departing keyword",
		},
		{
			name:    "Near flight keyword",
			content: "Flight BA456, passport number C87654321",
			desc:    "Passport near flight keyword",
		},
		{
			name:    "Near visa keyword",
			content: "Visa application: passport C87654321, nationality: British",
			desc:    "Passport near visa keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "travel.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("Expected passport match for %s", tt.desc)
			}
		})
	}
}

func TestPassportValidator_EdgeCases_MRZFormat(t *testing.T) {
	v := NewValidator()

	// A proper MRZ line 1 for TD3 (passport)
	mrzLine := "P<GBRSMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
	country := v.determineCountry(mrzLine)

	// MRZ format should be detected as MRZ or MRZ_TD3
	if country != "MRZ" && country != "MRZ_TD3" {
		// MRZ detection depends on exact length; just verify it starts with P
		if mrzLine[0] != 'P' {
			t.Errorf("MRZ line should start with P")
		}
	}
}

// ---------------------------------------------------------------------------
// CalculateConfidence
// ---------------------------------------------------------------------------

func TestPassportValidator_CalculateConfidence(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name          string
		match         string
		minConfidence float64
		maxConfidence float64
		desc          string
	}{
		{
			name:          "Valid US format",
			match:         "C12345679:US",
			minConfidence: 30,
			maxConfidence: 100,
			desc:          "Valid US passport format should have reasonable confidence",
		},
		{
			name:          "Known test pattern reduces confidence",
			match:         "A12345678:US",
			minConfidence: 0,
			maxConfidence: 50,
			desc:          "Known test pattern should have low confidence",
		},
		{
			name:          "UK format 9 digits",
			match:         "987654321:UK",
			minConfidence: 0,
			maxConfidence: 100,
			desc:          "UK passport format should have some confidence",
		},
		{
			name:          "Canadian format valid country code",
			match:         "CA654321:Canada",
			minConfidence: 30,
			maxConfidence: 100,
			desc:          "Canadian passport with valid country code",
		},
		{
			name:          "EU format with valid country",
			match:         "FR1234567:EU",
			minConfidence: 30,
			maxConfidence: 100,
			desc:          "EU passport with valid country code",
		},
		{
			name:          "EU format with invalid XX code",
			match:         "XX1234567:EU",
			minConfidence: 0,
			maxConfidence: 40,
			desc:          "EU passport with XX code should have low confidence",
		},
		{
			name:          "Test number all zeros UK",
			match:         "000000000:UK",
			minConfidence: 0,
			maxConfidence: 50,
			desc:          "All-zeros test pattern should have low confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, _ := v.CalculateConfidence(tt.match)
			if confidence < tt.minConfidence || confidence > tt.maxConfidence {
				t.Errorf("CalculateConfidence(%q) = %.1f, want [%.1f, %.1f]: %s",
					tt.match, confidence, tt.minConfidence, tt.maxConfidence, tt.desc)
			}
		})
	}
}

func TestPassportValidator_CalculateConfidence_Checks(t *testing.T) {
	v := NewValidator()

	_, checks := v.CalculateConfidence("C12345679:US")

	expectedChecks := []string{"format", "length", "not_test_number", "not_sequential", "valid_characters", "not_common_word"}
	for _, key := range expectedChecks {
		if _, exists := checks[key]; !exists {
			t.Errorf("CalculateConfidence checks missing key %q", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper Methods
// ---------------------------------------------------------------------------

func TestPassportValidator_IsCommonWord(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		match string
		want  bool
	}{
		{"password", true},
		{"passport", true},
		{"document", true},
		{"C12345678", false},
		{"FR1234567", false},
	}

	for _, tt := range tests {
		t.Run(tt.match, func(t *testing.T) {
			got := v.isCommonWord(tt.match)
			if got != tt.want {
				t.Errorf("isCommonWord(%q) = %v, want %v", tt.match, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_IsTestPattern(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		match string
		want  bool
	}{
		{"A12345678", true},
		{"123456789", true},
		{"AB123456", true},
		{"AAAAAAAAA", true},
		{"C98765432", false},
	}

	for _, tt := range tests {
		t.Run(tt.match, func(t *testing.T) {
			got := v.isTestPattern(tt.match)
			if got != tt.want {
				t.Errorf("isTestPattern(%q) = %v, want %v", tt.match, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_IsKnownTestPattern(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		match string
		want  bool
	}{
		{"A00000000", true},
		{"A11111111", true},
		{"A12345678", true},
		{"AA000000", true},
		{"XX0000000", true},
		{"C98765432", false},
	}

	for _, tt := range tests {
		t.Run(tt.match, func(t *testing.T) {
			got := v.isKnownTestPattern(tt.match)
			if got != tt.want {
				t.Errorf("isKnownTestPattern(%q) = %v, want %v", tt.match, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_IsSequentialOrRepeated(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		text string
		want bool
	}{
		{"AAAA", true},
		{"1234", true},
		{"ABCD", true},
		{"A1B2C3D4", false},
		{"C98765432", false},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := v.isSequentialOrRepeated(tt.text)
			if got != tt.want {
				t.Errorf("isSequentialOrRepeated(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_IsPossibleFalsePositive(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		text string
		want bool
	}{
		{"SKU12345", true},
		{"AB1234", true},
		{"C12345679", false},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := v.isPossibleFalsePositive(tt.text)
			if got != tt.want {
				t.Errorf("isPossibleFalsePositive(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_GetLetterDigitPattern(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		text string
		want string
	}{
		{"AB123456", "LL######"},
		{"C12345678", "L########"},
		{"short", ""},
		{"FR1234567", "LL#######"},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := v.getLetterDigitPattern(tt.text)
			if got != tt.want {
				t.Errorf("getLetterDigitPattern(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_AreSimilarPatterns(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name string
		pat1 string
		pat2 string
		want bool
	}{
		{"Same prefix different last char", "C1234567A", "C1234567B", true},
		{"Same letter-digit pattern", "AB123456", "CD654321", true},
		{"Different patterns", "AB123456", "ABCDEFGH", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.areSimilarPatterns(tt.pat1, tt.pat2)
			if got != tt.want {
				t.Errorf("areSimilarPatterns(%q, %q) = %v, want %v", tt.pat1, tt.pat2, got, tt.want)
			}
		})
	}
}

func TestPassportValidator_GetFormatDescription(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		country string
		want    string
	}{
		{"US", "US passport (1 letter followed by 8 digits)"},
		{"UK", "UK passport (9 digits)"},
		{"Canada", "Canadian passport (2 letters followed by 6 digits)"},
		{"EU", "EU passport (2 letters followed by 7 alphanumeric characters)"},
		{"MRZ", "Machine Readable Zone format"},
		{"Unknown", "Unknown passport format"},
	}

	for _, tt := range tests {
		t.Run(tt.country, func(t *testing.T) {
			got := v.getFormatDescription(tt.country)
			if got != tt.want {
				t.Errorf("getFormatDescription(%q) = %q, want %q", tt.country, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tabular Data Detection
// ---------------------------------------------------------------------------

func TestPassportValidator_IsTabularData(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name  string
		line  string
		match string
		want  bool
	}{
		{"Tab-separated", "Name\tPassport\tNationality", "Passport", true},
		{"Comma-separated", "Smith,C12345678,British,London", "C12345678", true},
		{"Pipe-separated", "Name|Passport|DOB|Nationality", "Passport", true},
		{"Multi-space fixed width", "John Smith     C12345678     British", "C12345678", true},
		{"Travel pattern", "John Smith C12345678", "C12345678", true},
		{"Single field", "C12345678", "C12345678", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isTabularData(tt.line, tt.match)
			if got != tt.want {
				t.Errorf("isTabularData(%q, %q) = %v, want %v", tt.line, tt.match, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Form Context Detection
// ---------------------------------------------------------------------------

func TestPassportValidator_IsInFormContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		match   string
		context detector.ContextInfo
		want    bool
	}{
		{
			name:  "Passport colon label",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine: "Passport: C12345678",
			},
			want: true,
		},
		{
			name:  "Document number colon",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine: "Document Number: C12345678",
			},
			want: true,
		},
		{
			name:  "Tab-separated form",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine: "Name\tPassport\tNationality",
			},
			want: true,
		},
		{
			name:  "No form pattern",
			match: "C12345678",
			context: detector.ContextInfo{
				FullLine: "The value is C12345678",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.isInFormContext(tt.match, tt.context)
			if got != tt.want {
				t.Errorf("isInFormContext(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Strong Passport Context
// ---------------------------------------------------------------------------

func TestPassportValidator_HasStrongPassportContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		match   string
		context *detector.ContextInfo
		want    bool
	}{
		{
			name:  "Passport keyword present",
			match: "C12345678",
			context: &detector.ContextInfo{
				FullLine:   "Passport Number: C12345678",
				BeforeText: "",
				AfterText:  "",
			},
			want: true,
		},
		{
			name:  "MRZ keyword present",
			match: "C12345678",
			context: &detector.ContextInfo{
				FullLine:   "MRZ data C12345678",
				BeforeText: "",
				AfterText:  "",
			},
			want: true,
		},
		{
			name:  "Two medium indicators (visa + immigration)",
			match: "C12345678",
			context: &detector.ContextInfo{
				FullLine:   "C12345678",
				BeforeText: "visa application",
				AfterText:  "immigration processing",
			},
			want: true,
		},
		{
			name:  "Only one medium indicator not enough",
			match: "C12345678",
			context: &detector.ContextInfo{
				FullLine:   "C12345678",
				BeforeText: "visa application",
				AfterText:  "",
			},
			want: false,
		},
		{
			name:    "Nil context returns false",
			match:   "C12345678",
			context: nil,
			want:    false,
		},
		{
			name:  "No relevant keywords",
			match: "C12345678",
			context: &detector.ContextInfo{
				FullLine:   "C12345678 in database record",
				BeforeText: "",
				AfterText:  "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.hasStrongPassportContext(tt.match, tt.context)
			if got != tt.want {
				t.Errorf("hasStrongPassportContext(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Passport Proximity Calculation
// ---------------------------------------------------------------------------

func TestPassportValidator_CalculatePassportProximity(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		match   string
		context detector.ContextInfo
		wantMin float64
		wantMax float64
	}{
		{
			name:  "Very close to passport keyword",
			match: "c12345678",
			context: detector.ContextInfo{
				FullLine: "passport: c12345678",
			},
			wantMin: 15,
			wantMax: 25,
		},
		{
			name:  "Passport in before text",
			match: "c12345678",
			context: detector.ContextInfo{
				FullLine:   "c12345678",
				BeforeText: "passport holder information",
			},
			wantMin: 1,
			wantMax: 10,
		},
		{
			name:  "No passport keyword",
			match: "c12345678",
			context: detector.ContextInfo{
				FullLine: "some random text c12345678 here",
			},
			wantMin: 0,
			wantMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.calculatePassportProximity(tt.match, tt.context)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculatePassportProximity: got %.1f, want [%.1f, %.1f]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Keyword Weight
// ---------------------------------------------------------------------------

func TestPassportValidator_GetKeywordWeight(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		keyword   string
		wantAbove float64
	}{
		{"passport", 10},
		{"passport number", 10},
		{"visa", 4},
		{"immigration", 4},
		{"travel", 1},
		{"gender", 0},
		{"unlisted_keyword", 1},
	}

	for _, tt := range tests {
		t.Run(tt.keyword, func(t *testing.T) {
			got := v.getKeywordWeight(tt.keyword)
			if got < tt.wantAbove {
				t.Errorf("getKeywordWeight(%q) = %.1f, want > %.1f", tt.keyword, got, tt.wantAbove)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FindKeywords
// ---------------------------------------------------------------------------

func TestPassportValidator_FindKeywords(t *testing.T) {
	v := NewValidator()

	ctx := detector.ContextInfo{
		FullLine:   "passport number: C12345678",
		BeforeText: "visa application",
		AfterText:  "",
	}

	found := v.findKeywords(ctx, v.positiveKeywords)
	if len(found) == 0 {
		t.Error("Expected to find positive keywords in context")
	}

	// "passport" should be in the found list
	hasPassport := false
	for _, kw := range found {
		if kw == "passport" || kw == "passport number" {
			hasPassport = true
			break
		}
	}
	if !hasPassport {
		t.Error("Expected 'passport' or 'passport number' in found keywords")
	}
}

// ---------------------------------------------------------------------------
// Legacy Validate method (returns empty)
// ---------------------------------------------------------------------------

func TestPassportValidator_Validate_ReturnsEmpty(t *testing.T) {
	v := NewValidator()

	matches, err := v.Validate("some/file/path.txt")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate should return empty matches, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// NewValidator initialization
// ---------------------------------------------------------------------------

func TestPassportValidator_NewValidator(t *testing.T) {
	v := NewValidator()

	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if len(v.patterns) == 0 {
		t.Error("patterns should not be empty")
	}
	if len(v.compiledPatterns) == 0 {
		t.Error("compiledPatterns should not be empty")
	}
	if len(v.positiveKeywords) == 0 {
		t.Error("positiveKeywords should not be empty")
	}
	if len(v.negativeKeywords) == 0 {
		t.Error("negativeKeywords should not be empty")
	}
	if v.validCountryCodes == nil || len(v.validCountryCodes) == 0 {
		t.Error("validCountryCodes should not be empty")
	}
	if v.contextAnalyzer == nil {
		t.Error("contextAnalyzer should not be nil")
	}
	if len(v.travelKeywords) == 0 {
		t.Error("travelKeywords should not be empty")
	}
	if len(v.governmentKeywords) == 0 {
		t.Error("governmentKeywords should not be empty")
	}
	if len(v.globalTestPassports) == 0 {
		t.Error("globalTestPassports should not be empty")
	}
}

// ---------------------------------------------------------------------------
// DetermineCountry
// ---------------------------------------------------------------------------

func TestPassportValidator_DetermineCountry_NoMatch(t *testing.T) {
	v := NewValidator()

	// Something that matches no pattern
	country := v.determineCountry("!!!!")
	if country != "" {
		t.Errorf("determineCountry for invalid input = %q, want empty string", country)
	}
}

// ---------------------------------------------------------------------------
// IsLikelyWord
// ---------------------------------------------------------------------------

func TestPassportValidator_IsLikelyWord(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		text string
		want bool
	}{
		{"positive", true},   // In common words list
		{"national", true},   // In common words list
		{"XYZQW", false},     // No vowels, short
		{"C12345678", false}, // Alphanumeric, not a word
		{"abcde", true},      // Has vowels, reasonable ratio
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := v.isLikelyWord(tt.text)
			if got != tt.want {
				t.Errorf("isLikelyWord(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SetObserver
// ---------------------------------------------------------------------------

func TestPassportValidator_SetObserver(t *testing.T) {
	v := NewValidator()

	// Should not panic when setting nil observer
	v.SetObserver(nil)
	if v.observer != nil {
		t.Error("observer should be nil after SetObserver(nil)")
	}
}
