// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/context"
	"github.com/awslabs/ferret-scan/internal/detector"
)

// TestPersonNameValidator_ValidNames tests detection of valid person names
func TestPersonNameValidator_ValidNames(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Simple first last",
			content:     "Contact John Smith for details",
			expectMatch: true,
			description: "Standard First Last name should be detected",
		},
		{
			name:        "Name with title Dr.",
			content:     "Dr. Sarah Johnson will attend",
			expectMatch: true,
			description: "Name with Dr. title should be detected",
		},
		{
			name:        "Name with Mr. prefix",
			content:     "Mr. Robert Williams submitted the form",
			expectMatch: true,
			description: "Name with Mr. prefix should be detected",
		},
		{
			name:        "Name with Mrs. prefix",
			content:     "Mrs. Emily Davis is the contact",
			expectMatch: true,
			description: "Name with Mrs. prefix should be detected",
		},
		{
			name:        "Name with Ms. prefix",
			content:     "Ms. Jennifer Wilson was present",
			expectMatch: true,
			description: "Name with Ms. prefix should be detected",
		},
		{
			name:        "Name with middle initial",
			content:     "Michael J. Thompson signed the document",
			expectMatch: true,
			description: "Name with middle initial should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

// TestPersonNameValidator_AccentedNames is a regression test for the ASCII
// word-boundary bug. The old patterns used [A-ZÀ-ÿ] with a leading/trailing
// ASCII \b, so:
//   - names starting with an accented capital (Ángel, Óscar) never matched, and
//   - names ending in an accent (José, André) were truncated ("Jos", "Andr"),
//     corrupting the reported Text and the name-DB lookup.
//
// The patterns now use Unicode-aware boundaries (wrapNamePattern) and capture
// the name in group 1.
func TestPersonNameValidator_AccentedNames(t *testing.T) {
	pm := NewPatternManager()

	// Each name must be found AND reported in full (no truncation).
	wantFound := []string{
		"Ángel Ruiz",
		"Óscar Núñez",
		"José André",
		"María González",
		"François Dubois",
	}
	for _, name := range wantFound {
		line := "contact " + name + " today"
		matches := pm.FindMatches(line)
		found := false
		for _, m := range matches {
			if m.Text == name {
				found = true
				break
			}
		}
		if !found {
			got := make([]string, 0, len(matches))
			for _, m := range matches {
				got = append(got, m.Text)
			}
			t.Errorf("expected to find %q in full, got matches %v", name, got)
		}
	}

	// The math symbols × (U+00D7) and ÷ (U+00F7) fall inside the old À-ÿ range
	// but are NOT letters; they must not be treated as name characters.
	for _, line := range []string{"5 × 3 equals 15", "A ÷ B ratio"} {
		for _, m := range pm.FindMatches(line) {
			if strings.ContainsAny(m.Text, "×÷") {
				t.Errorf("name match %q in %q wrongly includes a math symbol", m.Text, line)
			}
		}
	}
}

// TestPersonNameValidator_CommonWordBigram is a regression test for H6: a
// Title-Cased bigram whose two tokens are both ordinary English words that also
// appear in the name databases ("Will Read", "Grace Hill") jumped straight to 90
// (HIGH). Such bigrams must now stay BELOW the HIGH bucket, while real names
// (with at least one distinctive token) and formal patterns stay HIGH.
func TestPersonNameValidator_CommonWordBigram(t *testing.T) {
	v := NewValidator()
	const highBucket = 90.0

	best := func(line string) float64 {
		matches, err := v.ValidateContent(line, "test.txt")
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", line, err)
		}
		var b float64
		for _, m := range matches {
			if m.Confidence > b {
				b = m.Confidence
			}
		}
		return b
	}

	// Common-word bigrams: must not reach HIGH on a bare two-word match.
	for _, line := range []string{"Will Read", "Mark Brown", "Grace Hill", "Bill Young", "Rose Stone"} {
		if c := best(line); c >= highBucket {
			t.Errorf("common-word bigram %q should stay below HIGH (%.0f), got %.1f", line, highBucket, c)
		}
	}

	// Real names (at least one distinctive token) must still reach HIGH.
	for _, line := range []string{"John Smith", "Sarah Johnson", "Michael Williams", "David Brown"} {
		if c := best(line); c < highBucket {
			t.Errorf("real name %q should reach HIGH (>=%.0f), got %.1f", line, highBucket, c)
		}
	}

	// A formal pattern (title / comma form) overrides the gate: a titled or
	// directory-style entry could be a genuine person, so it stays HIGH.
	for _, line := range []string{"Dr. Will Read", "Read, Will"} {
		if c := best(line); c < highBucket {
			t.Errorf("formal pattern %q should stay HIGH (>=%.0f), got %.1f", line, highBucket, c)
		}
	}
}

// TestPersonNameValidator_ContextAnalysis tests context-based confidence adjustments
func TestPersonNameValidator_ContextAnalysis(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name           string
		match          string
		contextLine    string
		expectPositive bool
		description    string
	}{
		{
			name:           "Employee context boosts confidence",
			match:          "John Smith",
			contextLine:    "employee John Smith started today",
			expectPositive: true,
			description:    "Employee keyword should boost confidence",
		},
		{
			name:           "Patient context boosts confidence",
			match:          "Sarah Johnson",
			contextLine:    "patient Sarah Johnson admitted",
			expectPositive: true,
			description:    "Patient keyword should boost confidence",
		},
		{
			name:           "Author context boosts confidence",
			match:          "Michael Brown",
			contextLine:    "author Michael Brown published",
			expectPositive: true,
			description:    "Author keyword should boost confidence",
		},
		{
			name:           "Contact context boosts confidence",
			match:          "Emily Davis",
			contextLine:    "contact Emily Davis for inquiries",
			expectPositive: true,
			description:    "Contact keyword should boost confidence",
		},
		{
			name:           "Company context can reduce confidence",
			match:          "Tech Solutions",
			contextLine:    "company Tech Solutions corporation announced",
			expectPositive: false,
			description:    "Company/corporation context should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextInfo := detector.ContextInfo{
				FullLine: tt.contextLine,
			}
			impact := v.AnalyzeContext(tt.match, contextInfo)
			if tt.expectPositive && impact <= 0 {
				t.Errorf("Expected positive context impact, got %f: %s", impact, tt.description)
			}
			if !tt.expectPositive && impact > 0 {
				t.Errorf("Expected non-positive context impact, got %f: %s", impact, tt.description)
			}
		})
	}
}

// TestPersonNameValidator_FalsePositives tests that common false positives are filtered
func TestPersonNameValidator_FalsePositives(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Technical term - Main Street",
			input:       "Main Street",
			description: "Geographic locations should be filtered",
		},
		{
			name:        "Technical term - New York",
			input:       "New York",
			description: "City names should be filtered as technical terms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isTechnicalTerm(tt.input)
			if !result {
				// If not caught by isTechnicalTerm, check that CalculateConfidence returns low confidence
				confidence, _ := v.CalculateConfidence(tt.input)
				if confidence >= 50.0 {
					t.Logf("Note: %q not caught as technical term, confidence=%f: %s",
						tt.input, confidence, tt.description)
				}
			}
		})
	}
}

// TestPersonNameValidator_CalculateConfidence tests confidence scoring
func TestPersonNameValidator_CalculateConfidence(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name            string
		input           string
		expectHighConf  bool
		expectZeroConf  bool
		expectBothKnown bool
		description     string
	}{
		{
			name:            "Both names in database",
			input:           "John Smith",
			expectHighConf:  true,
			expectZeroConf:  false,
			expectBothKnown: true,
			description:     "Both first and last name in database should get high confidence",
		},
		{
			name:            "Test data - John Doe",
			input:           "John Doe",
			expectHighConf:  false,
			expectZeroConf:  false,
			expectBothKnown: true,
			description:     "Known test names should get reduced confidence",
		},
		{
			name:            "Unknown names",
			input:           "Xyzabc Qwerty",
			expectHighConf:  false,
			expectZeroConf:  true,
			expectBothKnown: false,
			description:     "Names not in database should get zero confidence",
		},
		{
			name:            "Single word",
			input:           "Smith",
			expectHighConf:  false,
			expectZeroConf:  true,
			expectBothKnown: false,
			description:     "Single word should get zero or very low confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := v.CalculateConfidence(tt.input)

			if tt.expectZeroConf && confidence > 0 {
				t.Errorf("Expected zero confidence for %q, got %f: %s", tt.input, confidence, tt.description)
			}
			if tt.expectHighConf && confidence < 70 {
				t.Errorf("Expected high confidence for %q, got %f: %s", tt.input, confidence, tt.description)
			}
			if tt.expectBothKnown {
				if !checks["known_first_name"] || !checks["known_last_name"] {
					t.Logf("Both names expected known for %q: first=%v, last=%v",
						tt.input, checks["known_first_name"], checks["known_last_name"])
				}
			}
		})
	}
}

// TestPersonNameValidator_EdgeCases tests edge cases in name detection
func TestPersonNameValidator_EdgeCases(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Name with suffix Jr",
			content:     "Robert Williams Jr attended the meeting",
			expectMatch: true,
			description: "Name with Jr suffix should be detected",
		},
		{
			name:        "Name in email header context",
			content:     "From: John Smith sent a message",
			expectMatch: true,
			description: "Name near email header patterns should be detected",
		},
		{
			name:        "Empty content",
			content:     "",
			expectMatch: false,
			description: "Empty content should produce no matches",
		},
		{
			name:        "Content with no names",
			content:     "The quick brown fox jumps over the lazy dog.",
			expectMatch: false,
			description: "Content without person names should produce no matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

// TestPersonNameValidator_IsTechnicalTerm tests the technical term filter
func TestPersonNameValidator_IsTechnicalTerm(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		input       string
		isTechnical bool
		description string
	}{
		{
			name:        "Business suffix - Inc",
			input:       "Acme Inc",
			isTechnical: true,
			description: "Names ending with Inc should be flagged as business names",
		},
		{
			name:        "Business suffix - LLC",
			input:       "Smith LLC",
			isTechnical: true,
			description: "Names ending with LLC should be flagged as business names",
		},
		{
			name:        "Technical phrase - First Name",
			input:       "First Name",
			isTechnical: true,
			description: "Form field labels should be flagged as technical terms",
		},
		{
			name:        "Technical phrase - Last Name",
			input:       "Last Name",
			isTechnical: true,
			description: "Form field labels should be flagged as technical terms",
		},
		{
			name:        "Real person name",
			input:       "John Smith",
			isTechnical: false,
			description: "Real person names should not be flagged as technical terms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isTechnicalTerm(tt.input)
			if result != tt.isTechnical {
				t.Errorf("isTechnicalTerm(%q) = %v, want %v: %s",
					tt.input, result, tt.isTechnical, tt.description)
			}
		})
	}
}

// TestPersonNameValidator_IsTechnicalContext tests the technical context detector
func TestPersonNameValidator_IsTechnicalContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		match       string
		components  NameComponents
		isTechnical bool
		description string
	}{
		{
			name:  "Technical first name - test",
			match: "Test User",
			components: NameComponents{
				FirstName: "Test",
				LastName:  "User",
			},
			isTechnical: true,
			description: "Technical first names like 'Test' should be flagged",
		},
		{
			name:  "Technical first name - admin",
			match: "Admin Service",
			components: NameComponents{
				FirstName: "Admin",
				LastName:  "Service",
			},
			isTechnical: true,
			description: "Technical first names like 'Admin' should be flagged",
		},
		{
			name:  "Technical last name - handler",
			match: "John Handler",
			components: NameComponents{
				FirstName: "John",
				LastName:  "Handler",
			},
			isTechnical: true,
			description: "Technical last names like 'Handler' should be flagged",
		},
		{
			name:  "Real person name",
			match: "John Smith",
			components: NameComponents{
				FirstName: "John",
				LastName:  "Smith",
			},
			isTechnical: false,
			description: "Real person names should not be flagged as technical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isTechnicalContext(tt.match, tt.components)
			if result != tt.isTechnical {
				t.Errorf("isTechnicalContext(%q) = %v, want %v: %s",
					tt.match, result, tt.isTechnical, tt.description)
			}
		})
	}
}

// TestPersonNameValidator_IsProperlyCapitalized tests capitalization checking
func TestPersonNameValidator_IsProperlyCapitalized(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name           string
		input          string
		isProperlyCapd bool
	}{
		{name: "Proper case", input: "John Smith", isProperlyCapd: true},
		{name: "All lowercase", input: "john smith", isProperlyCapd: false},
		{name: "Title with proper case", input: "Dr. Sarah Johnson", isProperlyCapd: true},
		{name: "Mixed case first word", input: "jOHN Smith", isProperlyCapd: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isProperlyCapitalized(tt.input)
			if result != tt.isProperlyCapd {
				t.Errorf("isProperlyCapitalized(%q) = %v, want %v",
					tt.input, result, tt.isProperlyCapd)
			}
		})
	}
}

// TestPersonNameValidator_HasSuspiciousPatterns tests suspicious pattern detection
func TestPersonNameValidator_HasSuspiciousPatterns(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name         string
		input        string
		isSuspicious bool
	}{
		{name: "Normal name", input: "John Smith", isSuspicious: false},
		{name: "Contains 123", input: "John123 Smith", isSuspicious: true},
		{name: "Contains abc", input: "Abc Smith", isSuspicious: true},
		{name: "Contains qwerty", input: "Qwerty User", isSuspicious: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.hasSuspiciousPatterns(tt.input)
			if result != tt.isSuspicious {
				t.Errorf("hasSuspiciousPatterns(%q) = %v, want %v",
					tt.input, result, tt.isSuspicious)
			}
		})
	}
}

// TestPersonNameValidator_HasRepeatedCharacters tests repeated character detection
func TestPersonNameValidator_HasRepeatedCharacters(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		input       string
		hasRepeated bool
	}{
		{name: "Normal name", input: "John Smith", hasRepeated: false},
		{name: "Repeated chars", input: "Joohn Smiiith", hasRepeated: true},
		{name: "Three same chars", input: "Aaaa Smith", hasRepeated: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.hasRepeatedCharacters(tt.input)
			if result != tt.hasRepeated {
				t.Errorf("hasRepeatedCharacters(%q) = %v, want %v",
					tt.input, result, tt.hasRepeated)
			}
		})
	}
}

// TestPersonNameValidator_Validate_ReturnsEmpty tests that direct Validate returns empty
func TestPersonNameValidator_Validate_ReturnsEmpty(t *testing.T) {
	v := NewValidator()

	matches, err := v.Validate("somefile.txt")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate should return empty (direct file processing not supported), got %d", len(matches))
	}
}

// TestPersonNameValidator_ParseNameParts tests the legacy name parsing
func TestPersonNameValidator_ParseNameParts(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name              string
		input             string
		expectedFirstName string
		expectedLastName  string
		expectedTitle     string
		expectedSuffix    string
	}{
		{
			name:              "Simple name",
			input:             "John Smith",
			expectedFirstName: "John",
			expectedLastName:  "Smith",
		},
		{
			name:              "Name with title",
			input:             "Dr. Sarah Johnson",
			expectedFirstName: "Sarah",
			expectedLastName:  "Johnson",
			expectedTitle:     "Dr.",
		},
		{
			name:              "Name with suffix",
			input:             "Robert Williams Jr.",
			expectedFirstName: "Robert",
			expectedLastName:  "Williams",
			expectedSuffix:    "Jr.",
		},
		{
			name:              "Name with middle",
			input:             "Michael James Thompson",
			expectedFirstName: "Michael",
			expectedLastName:  "Thompson",
		},
		{
			name:              "Single word",
			input:             "Smith",
			expectedFirstName: "Smith",
			expectedLastName:  "",
		},
		{
			name:              "Empty string",
			input:             "",
			expectedFirstName: "",
			expectedLastName:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := v.parseNameParts(tt.input)
			if parts.FirstName != tt.expectedFirstName {
				t.Errorf("parseNameParts(%q).FirstName = %q, want %q",
					tt.input, parts.FirstName, tt.expectedFirstName)
			}
			if parts.LastName != tt.expectedLastName {
				t.Errorf("parseNameParts(%q).LastName = %q, want %q",
					tt.input, parts.LastName, tt.expectedLastName)
			}
			if tt.expectedTitle != "" && parts.Title != tt.expectedTitle {
				t.Errorf("parseNameParts(%q).Title = %q, want %q",
					tt.input, parts.Title, tt.expectedTitle)
			}
			if tt.expectedSuffix != "" && parts.Suffix != tt.expectedSuffix {
				t.Errorf("parseNameParts(%q).Suffix = %q, want %q",
					tt.input, parts.Suffix, tt.expectedSuffix)
			}
		})
	}
}

// TestPersonNameValidator_IsTitle tests title detection
func TestPersonNameValidator_IsTitle(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		token   string
		isTitle bool
	}{
		{"Mr.", true},
		{"Mrs.", true},
		{"Ms.", true},
		{"Dr.", true},
		{"Prof.", true},
		{"Sir", false},
		{"Mr", false},
		{"Doctor", false},
	}

	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			result := v.isTitle(tt.token)
			if result != tt.isTitle {
				t.Errorf("isTitle(%q) = %v, want %v", tt.token, result, tt.isTitle)
			}
		})
	}
}

// TestPersonNameValidator_IsSuffix tests suffix detection
func TestPersonNameValidator_IsSuffix(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		token    string
		isSuffix bool
	}{
		{"Jr.", true},
		{"Sr.", true},
		{"Jr", true},
		{"Sr", true},
		{"III", true},
		{"IV", true},
		{"Ph.D.", false},
		{"Esq", false},
	}

	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			result := v.isSuffix(tt.token)
			if result != tt.isSuffix {
				t.Errorf("isSuffix(%q) = %v, want %v", tt.token, result, tt.isSuffix)
			}
		})
	}
}

// TestPersonNameValidator_NormalizeAccents tests accent normalization
func TestPersonNameValidator_NormalizeAccents(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		input    string
		expected string
	}{
		{input: "josé", expected: "jose"},
		{input: "müller", expected: "muller"},
		{input: "résumé", expected: "resume"},
		{input: "naïve", expected: "naive"},
		{input: "john", expected: "john"},
		{input: "María", expected: "Maria"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := v.normalizeAccents(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeAccents(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestPersonNameValidator_DeduplicateMatches tests match deduplication
func TestPersonNameValidator_DeduplicateMatches(t *testing.T) {
	v := NewValidator()

	t.Run("removes exact duplicates keeping higher confidence", func(t *testing.T) {
		matches := []detector.Match{
			{Text: "John Smith", LineNumber: 1, Confidence: 80},
			{Text: "John Smith", LineNumber: 1, Confidence: 90},
		}
		result := v.deduplicateMatches(matches)
		if len(result) != 1 {
			t.Errorf("Expected 1 deduplicated match, got %d", len(result))
		}
		if len(result) > 0 && result[0].Confidence != 90 {
			t.Errorf("Expected higher confidence (90), got %f", result[0].Confidence)
		}
	})

	t.Run("keeps different matches on different lines", func(t *testing.T) {
		matches := []detector.Match{
			{Text: "John Smith", LineNumber: 1, Confidence: 80},
			{Text: "Jane Doe", LineNumber: 2, Confidence: 70},
		}
		result := v.deduplicateMatches(matches)
		if len(result) != 2 {
			t.Errorf("Expected 2 matches on different lines, got %d", len(result))
		}
	})

	t.Run("prefers longer matches containing shorter ones", func(t *testing.T) {
		matches := []detector.Match{
			{Text: "John", LineNumber: 1, Confidence: 60},
			{Text: "John Smith", LineNumber: 1, Confidence: 80},
		}
		result := v.deduplicateMatches(matches)
		if len(result) != 1 {
			t.Errorf("Expected 1 deduplicated match, got %d", len(result))
		}
		if len(result) > 0 && result[0].Text != "John Smith" {
			t.Errorf("Expected longer match 'John Smith', got %q", result[0].Text)
		}
	})

	t.Run("single match returns unchanged", func(t *testing.T) {
		matches := []detector.Match{
			{Text: "John Smith", LineNumber: 1, Confidence: 80},
		}
		result := v.deduplicateMatches(matches)
		if len(result) != 1 {
			t.Errorf("Expected 1 match, got %d", len(result))
		}
	})

	t.Run("empty list returns empty", func(t *testing.T) {
		var matches []detector.Match
		result := v.deduplicateMatches(matches)
		if len(result) != 0 {
			t.Errorf("Expected 0 matches, got %d", len(result))
		}
	})
}

// TestPersonNameValidator_ValidateWithContext tests context-aware validation
func TestPersonNameValidator_ValidateWithContext(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		insights    context.ContextInsights
		description string
	}{
		{
			name:    "Employee directory context",
			content: "John Smith works in accounting",
			insights: context.ContextInsights{
				DocumentType:          "employee_directory",
				Domain:                "hr",
				SemanticContext:       map[string]float64{"person": 0.9},
				ConfidenceAdjustments: map[string]float64{},
			},
			description: "Employee directory context should boost detection",
		},
		{
			name:    "Technical documentation context",
			content: "John Smith works in accounting",
			insights: context.ContextInsights{
				DocumentType:          "technical_documentation",
				Domain:                "technology",
				SemanticContext:       map[string]float64{"business": 0.5},
				ConfidenceAdjustments: map[string]float64{},
			},
			description: "Technical documentation context should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateWithContext(tt.content, "test.txt", tt.insights)
			if err != nil {
				t.Fatalf("ValidateWithContext returned error: %v", err)
			}
			// Just verify no error and matches are returned as expected
			t.Logf("Got %d matches for %q context", len(matches), tt.insights.DocumentType)
		})
	}
}

// TestPersonNameValidator_ApplyContextInsights tests context insight adjustments
func TestPersonNameValidator_ApplyContextInsights(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name           string
		match          string
		insights       context.ContextInsights
		expectPositive bool
		description    string
	}{
		{
			name:  "Employee directory boosts",
			match: "John Smith",
			insights: context.ContextInsights{
				DocumentType:          "employee_directory",
				Domain:                "hr",
				SemanticContext:       map[string]float64{},
				ConfidenceAdjustments: map[string]float64{},
			},
			expectPositive: true,
			description:    "Employee directory + HR domain should boost",
		},
		{
			name:  "Product catalog reduces",
			match: "John Smith",
			insights: context.ContextInsights{
				DocumentType:          "product_catalog",
				Domain:                "technology",
				SemanticContext:       map[string]float64{},
				ConfidenceAdjustments: map[string]float64{},
			},
			expectPositive: false,
			description:    "Product catalog + technology should reduce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := v.applyContextInsights(tt.match, tt.insights)
			if tt.expectPositive && impact <= 0 {
				t.Errorf("Expected positive impact, got %f: %s", impact, tt.description)
			}
			if !tt.expectPositive && impact >= 0 {
				t.Errorf("Expected negative impact, got %f: %s", impact, tt.description)
			}
		})
	}
}

// TestPersonNameValidator_ApplyCrossValidatorSignals tests cross-validator signal handling
func TestPersonNameValidator_ApplyCrossValidatorSignals(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name           string
		match          string
		signals        []context.CrossValidatorSignal
		expectPositive bool
		description    string
	}{
		{
			name:  "Email signal boosts",
			match: "John Smith",
			signals: []context.CrossValidatorSignal{
				{ValidatorType: "EMAIL", SignalType: "person_context", Confidence: 0.9},
			},
			expectPositive: true,
			description:    "Email person_context signal should boost confidence",
		},
		{
			name:  "Phone signal boosts",
			match: "John Smith",
			signals: []context.CrossValidatorSignal{
				{ValidatorType: "PHONE", SignalType: "contact_context", Confidence: 0.8},
			},
			expectPositive: true,
			description:    "Phone contact_context signal should boost confidence",
		},
		{
			name:           "No signals",
			match:          "John Smith",
			signals:        []context.CrossValidatorSignal{},
			expectPositive: false,
			description:    "No signals should produce zero adjustment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := v.applyCrossValidatorSignals(tt.match, tt.signals)
			if tt.expectPositive && impact <= 0 {
				t.Errorf("Expected positive impact, got %f: %s", impact, tt.description)
			}
			if !tt.expectPositive && impact != 0 {
				t.Errorf("Expected zero impact, got %f: %s", impact, tt.description)
			}
		})
	}
}

// TestPersonNameValidator_GetSupportedLanguages tests language listing
func TestPersonNameValidator_GetSupportedLanguages(t *testing.T) {
	v := NewValidator()

	languages := v.GetSupportedLanguages()
	if len(languages) == 0 {
		t.Error("Expected at least one supported language")
	}

	// Should contain "en"
	found := false
	for _, lang := range languages {
		if lang == "en" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'en' in supported languages")
	}
}

// TestPersonNameValidator_SetLanguage tests language setting
func TestPersonNameValidator_SetLanguage(t *testing.T) {
	v := NewValidator()

	err := v.SetLanguage("en")
	if err != nil {
		t.Errorf("SetLanguage('en') returned error: %v", err)
	}
}

// TestPersonNameValidator_IsFormalNamePattern tests formal pattern detection
func TestPersonNameValidator_IsFormalNamePattern(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		pattern  string
		isFormal bool
	}{
		{"name_with_title", true},
		{"name_with_suffix", true},
		{"last_comma_first", true},
		{"first_last", false},
		{"unknown_pattern", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			result := v.isFormalNamePattern(tt.pattern)
			if result != tt.isFormal {
				t.Errorf("isFormalNamePattern(%q) = %v, want %v", tt.pattern, result, tt.isFormal)
			}
		})
	}
}

// TestPersonNameValidator_IsProperlyCapitalizedUnicode is a regression test for
// M20: (1) the title/suffix exemption used a reversed strings.Contains so
// substrings like "M"/"V"/"Pro" skipped the check; (2) word[0] byte-indexing
// rejected accented capitals like 'Á'.
func TestPersonNameValidator_IsProperlyCapitalizedUnicode(t *testing.T) {
	v := NewValidator()
	proper := []string{"John Smith", "Ángel Ramos", "Óscar Núñez", "Dr. Smith", "Mr. John Doe"}
	for _, n := range proper {
		if !v.isProperlyCapitalized(n) {
			t.Errorf("%q should be considered properly capitalized", n)
		}
	}
	improper := []string{"john smith", "john Smith", "ángel ramos"}
	for _, n := range improper {
		if v.isProperlyCapitalized(n) {
			t.Errorf("%q should NOT be considered properly capitalized", n)
		}
	}
}

// TestPersonNameValidator_SuffixNotInWord is a regression test for M21: the
// name_with_suffix pattern matched ordinary word triples ("Grace Park Verified")
// by treating a leading "V"/"IV"/"III" of the third word as a suffix.
func TestPersonNameValidator_SuffixNotInWord(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"Grace Park Verified today",
		"Michael Davis IVory tower",
		"Thomas Anderson IIIumination",
	} {
		matches, _ := v.ValidateContent(line, "test.txt")
		for _, m := range matches {
			if p, ok := m.Metadata["pattern"]; ok && p == "name_with_suffix" {
				t.Errorf("%q should not match as name_with_suffix (matched %q)", line, m.Text)
			}
		}
	}
	// A genuine suffixed name still matches.
	matches, _ := v.ValidateContent("Grace Park Jr.", "test.txt")
	if len(matches) == 0 {
		t.Error("genuine 'Grace Park Jr.' should still be detected")
	}
}

// TestPersonNameValidator_AllCapsNames is a regression test for M22: all-caps
// names (common in forms/spreadsheets) never matched. They now surface when
// DB-backed, while non-name all-caps prose is rejected (no new false positives).
func TestPersonNameValidator_AllCapsNames(t *testing.T) {
	v := NewValidator()
	best := func(line string) float64 {
		matches, _ := v.ValidateContent(line, "test.txt")
		var b float64
		for _, m := range matches {
			if m.Confidence > b {
				b = m.Confidence
			}
		}
		return b
	}
	// Real all-caps names must surface.
	for _, n := range []string{"JOHN SMITH", "SARAH JOHNSON", "MICHAEL WILLIAMS"} {
		if best(n) < 50 {
			t.Errorf("all-caps name %q should surface, got %.1f", n, best(n))
		}
	}
	// All-caps prose must NOT surface (not in the name DB).
	for _, n := range []string{"ERROR CODE", "TODO FIXME", "THE END", "NOT FOUND"} {
		if best(n) >= 60 {
			t.Errorf("all-caps prose %q must not reach MEDIUM, got %.1f", n, best(n))
		}
	}
}

// TestPersonNameValidator_ContextKeywordWordBoundary is a regression test for
// L25: context keywords were matched as substrings, so "park" fired inside
// "parking" (-35) and "inc" inside "incident" (-20), nudging confidence. They
// now match on whole words; a real keyword still applies its penalty.
func TestPersonNameValidator_ContextKeywordWordBoundary(t *testing.T) {
	v := NewValidator()
	// Substrings inside unrelated words must not trip the penalty.
	for _, line := range []string{"Grace Hill parking lot", "Mark Brown incident report"} {
		if imp := v.AnalyzeContext(strings.Join(strings.Fields(line)[:2], " "),
			detector.ContextInfo{FullLine: line}); imp < 0 {
			t.Errorf("L25: %q should not incur a negative keyword penalty, got %.1f", line, imp)
		}
	}
	// A real geographic keyword still penalizes.
	if imp := v.AnalyzeContext("John Smith", detector.ContextInfo{FullLine: "John Smith visited park today"}); imp >= 0 {
		t.Errorf("L25: a real 'park' keyword should still penalize, got %.1f", imp)
	}
}

// TestPersonNameValidator_PerformanceWorstCase is a regression guard against the
// O(n^2) DoS that previously lived in ValidateContent: deduplicateMatches compared
// every match against every other match across the whole file, and AnalyzeContext /
// analyzeContext recomputed all per-line work (lowercasing, keyword scans, regexes)
// once per match. On the two worst-case shapes below this took tens of seconds to
// minutes for ~1MB of input (a single 200KB line took ~6 minutes; 1MB timed out).
//
// After hoisting the per-line work out of the per-match loop and making dedup
// per-line, both shapes are linear and finish in ~1s. We assert a generous 5s
// ceiling so the test is not flaky on slow/loaded CI while still catching any
// reintroduction of quadratic behavior (which would blow far past 5s).
func TestPersonNameValidator_PerformanceWorstCase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance regression test in -short mode")
	}

	const ceiling = 5 * time.Second
	const targetBytes = 1_000_000

	build := func(unit string) string {
		var b strings.Builder
		for b.Len() < targetBytes {
			b.WriteString(unit)
		}
		return b.String()
	}

	cases := []struct {
		name    string
		content string
	}{
		// One very long line packed with (mostly duplicate) name matches: this is
		// what made deduplicateMatches and the per-match line scans quadratic.
		{name: "single_long_line", content: build("John Smith ")},
		// Many lines with one match each (tens of thousands of lines): this is what
		// made the cross-line dedup comparison quadratic.
		{name: "many_lines", content: build("John Smith\n")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewValidator()
			start := time.Now()
			if _, err := v.ValidateContent(tc.content, "perf.txt"); err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			elapsed := time.Since(start)
			t.Logf("%s: %d bytes processed in %s", tc.name, len(tc.content), elapsed)
			if raceEnabled {
				// The race detector adds large, variable wall-clock overhead, so the
				// ceiling would be meaningless. We still run the scan above (so -race
				// can detect any data race in the cached/shared per-line state) but
				// skip the timing assertion.
				return
			}
			if elapsed > ceiling {
				t.Errorf("%s: ValidateContent took %s, exceeding %s ceiling (possible O(n^2) regression)",
					tc.name, elapsed, ceiling)
			}
		})
	}
}

// TestAnalyzeContextCached_OffsetEquivalence guards the single-long-line DoS
// fix in analyzeLineContextForMatch: the hot path passes the match's known byte
// offset (instead of re-running strings.Index over the whole line per match).
// The result MUST be identical to the fallback (-1) path that locates the match
// itself — otherwise the optimization would change confidence/behavior. This is
// the behavior-equivalence the fix relies on; the perf guard is
// TestPersonNameValidator_PerformanceWorstCase.
func TestAnalyzeContextCached_OffsetEquivalence(t *testing.T) {
	v := NewValidator()
	lines := []string{
		"employee John Smith started today",
		"company Tech Solutions corporation announced", // negative keyword present
		"contact Emily Davis (emily.davis@example.com) for details",
		"Raw Data Detected At Location Details Secret Keyword account id reference",
		"Robert Johnson account manager, invoice prepared by Maria Garcia",
	}
	for _, line := range lines {
		cache := v.newLineContextCache(line)
		for _, pm := range v.patternManager.FindMatches(line) {
			withOffset := v.analyzeContextCached(pm.Text, pm.StartIndex, cache)
			withFallback := v.analyzeContextCached(pm.Text, -1, cache)
			if withOffset != withFallback {
				t.Errorf("offset vs fallback mismatch for %q in %q: %.2f != %.2f",
					pm.Text, line, withOffset, withFallback)
			}
		}
	}
}
