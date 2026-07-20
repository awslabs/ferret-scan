// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"fmt"
	"strings"
	"testing"
)

// TestAdversarial_FalsePositives exercises inputs that MUST NOT produce
// high-confidence matches (>50) because they are clearly not driver's license
// numbers despite matching DL regex patterns.
func TestAdversarial_FalsePositives(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		content       string
		maxConfidence float64 // must not exceed this
		description   string
	}{
		// --- Generic "license" usage (not driver's license) ---
		{
			name:          "fishing license number",
			content:       "Fishing license 12345678 valid in Montana",
			maxConfidence: 50,
			description:   "Fishing license is NOT a driver's license",
		},
		{
			name:          "software license key",
			content:       "Software license key: A1234567 for activation",
			maxConfidence: 50,
			description:   "Software license key is NOT a driver's license",
		},
		{
			name:          "business license",
			content:       "Business license number 12345678 issued by city",
			maxConfidence: 50,
			description:   "Business license is NOT a driver's license",
		},
		{
			name:          "gun license",
			content:       "Gun license: 12345678 concealed carry permit",
			maxConfidence: 50,
			description:   "Gun license is NOT a driver's license",
		},
		{
			name:          "hunting license",
			content:       "Hunting license 87654321 season 2024",
			maxConfidence: 50,
			description:   "Hunting license is NOT a driver's license",
		},

		// --- Generic "permit" usage (not driver's permit) ---
		{
			name:          "parking permit",
			content:       "Parking permit 12345678 valid until March",
			maxConfidence: 50,
			description:   "Parking permit is NOT a driver's license",
		},
		{
			name:          "work permit",
			content:       "Work permit A1234567 issued by immigration",
			maxConfidence: 50,
			description:   "Work permit is NOT a driver's license",
		},
		{
			name:          "building permit",
			content:       "Building permit 12345678 for construction",
			maxConfidence: 50,
			description:   "Building permit is NOT a driver's license",
		},

		// --- Phone numbers near DL keywords ---
		{
			name:          "DMV phone number",
			content:       "Call DMV at 12345678 for appointments",
			maxConfidence: 50,
			description:   "Phone number near DMV keyword should not be high confidence DL",
		},

		// --- Random 8-digit numbers near DL keywords ---
		{
			name:          "license plate reference",
			content:       "License plate: AB123456 registered",
			maxConfidence: 50,
			description:   "License plate (2 letter + 6 digit) is not a DL",
		},

		// --- Account numbers that happen to have DL format ---
		{
			name:          "account number D-format",
			content:       "Account: D1234567",
			maxConfidence: 30,
			description:   "Account keyword should suppress (and no positive keyword gate)",
		},

		// --- Cross-validator confusion: SSN-like ---
		{
			name:          "SSN with license context",
			content:       "Social security number 123456789 on license application",
			maxConfidence: 50,
			description:   "SSN should not match as DL even with 'license' nearby",
		},

		// --- "dl" substring in words should not trigger ---
		{
			name:          "handle keyword contains dl substring",
			content:       "handle D1234567 to the process",
			maxConfidence: 0,
			description:   "'handle' contains 'dl' substring but should not trigger DL keyword gate",
		},
		{
			name:          "idle contains dl-like",
			content:       "idle worker D1234567 timed out",
			maxConfidence: 0,
			description:   "'idle' should not trigger DL keyword gate",
		},

		// --- "id" substring false gate pass ---
		{
			name:          "video keyword passes gate via id substring",
			content:       "Florida video ID 12345678 uploaded",
			maxConfidence: 50,
			description:   "Video + state should not create high-confidence DL",
		},

		// --- Numbers that look like dates/timestamps ---
		{
			name:          "date-like 8 digits with license context",
			content:       "License expires 20240315 renew now",
			maxConfidence: 50,
			description:   "Date-format number near license should not be DL",
		},

		// --- ZIP+4 or other common 9-digit patterns ---
		{
			name:          "zip plus routing with license nearby",
			content:       "License mailed to 100234567 Main St",
			maxConfidence: 50,
			description:   "Address numbers should not be DL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Confidence > tt.maxConfidence {
					t.Errorf("FALSE POSITIVE: %s\n  input: %q\n  matched: %q confidence=%.1f (max allowed=%.1f)\n  detail: %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.maxConfidence, tt.description)
				}
			}
		})
	}
}

// TestAdversarial_FalseNegatives exercises inputs that MUST match at HIGH
// confidence because they clearly ARE driver's license numbers with proper context.
func TestAdversarial_FalseNegatives(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		content       string
		minConfidence float64
		wantMatch     string // expected matched text (optional)
		description   string
	}{
		// --- Specified attack vector: "DL: D1234567" must match HIGH ---
		{
			name:          "DL prefix with CA format",
			content:       "DL: D1234567",
			minConfidence: 90,
			wantMatch:     "D1234567",
			description:   "Explicit DL: prefix with California format must be HIGH",
		},

		// --- State name + "driver" + number ---
		{
			name:          "California driver with number",
			content:       "California driver D1234567",
			minConfidence: 75,
			wantMatch:     "D1234567",
			description:   "State name + driver keyword + CA format should be HIGH",
		},
		{
			name:          "Texas driver license 8 digits",
			content:       "Texas driver license 87654321",
			minConfidence: 75,
			wantMatch:     "87654321",
			description:   "State name + driver + license + TX format should be HIGH",
		},
		{
			name:          "Florida DL 13 char format",
			content:       "Florida DL# B839201746582",
			minConfidence: 85,
			wantMatch:     "B839201746582",
			description:   "Florida state + DL prefix + FL format must be very high",
		},
		{
			name:          "New York driver license 9 digits",
			content:       "New York driver's license: 847293016",
			minConfidence: 85,
			wantMatch:     "847293016",
			description:   "NY state + driver's license: prefix must be very high",
		},
		{
			name:          "Ohio DL 2-letter format",
			content:       "Ohio DMV driver license: XY654321",
			minConfidence: 80,
			wantMatch:     "XY654321",
			description:   "Ohio state + DMV + driver license + OH format must be high",
		},

		// --- Various explicit DL prefix patterns ---
		{
			name:          "DL hash prefix",
			content:       "DL# A9876543",
			minConfidence: 90,
			wantMatch:     "A9876543",
			description:   "DL# prefix must match at high confidence",
		},
		{
			name:          "drivers license colon prefix",
			content:       "Drivers license: 84729301",
			minConfidence: 85,
			wantMatch:     "84729301",
			description:   "Drivers license: prefix must match high",
		},
		{
			name:          "licence number colon prefix",
			content:       "Licence number: D7654321",
			minConfidence: 85,
			wantMatch:     "D7654321",
			description:   "Licence number: prefix must match high",
		},

		// --- DMV context ---
		{
			name:          "DMV driving permit",
			content:       "DMV driving permit D5678901",
			minConfidence: 70,
			wantMatch:     "D5678901",
			description:   "DMV + driving + permit = strong DL context",
		},

		// --- Illinois format ---
		{
			name:          "Illinois DL 12 char format",
			content:       "Illinois driver license: C12345678901",
			minConfidence: 80,
			wantMatch:     "C12345678901",
			description:   "Illinois state + driver license: + IL format must be high",
		},

		// --- Multi-keyword stacking ---
		{
			name:          "driver license number with state",
			content:       "PA driver's license number: 56781234",
			minConfidence: 80,
			description:   "Multiple keywords + state should produce high confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("FALSE NEGATIVE: %s\n  input: %q\n  expected match with confidence >= %.0f but got NO matches\n  detail: %s",
					tt.name, tt.content, tt.minConfidence, tt.description)
				return
			}

			// Find the best match
			best := matches[0]
			for _, m := range matches[1:] {
				if m.Confidence > best.Confidence {
					best = m
				}
			}

			if tt.wantMatch != "" && best.Text != tt.wantMatch {
				t.Errorf("FALSE NEGATIVE: %s\n  expected match text %q, got %q",
					tt.name, tt.wantMatch, best.Text)
			}
			if best.Confidence < tt.minConfidence {
				t.Errorf("FALSE NEGATIVE: %s\n  input: %q\n  matched %q at confidence=%.1f (need >= %.0f)\n  detail: %s",
					tt.name, tt.content, best.Text, best.Confidence, tt.minConfidence, tt.description)
			}
		})
	}
}

// TestAdversarial_ContextWeakness verifies that the SAME value produces
// dramatically different confidence levels depending on surrounding context.
func TestAdversarial_ContextWeakness(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		highCtx     string // should produce HIGH confidence
		lowCtx      string // should produce LOW or no match
		minDelta    float64
		description string
	}{
		{
			name:        "DL keyword vs no keyword for CA format",
			highCtx:     "DL: D1234567",
			lowCtx:      "Reference: D1234567",
			minDelta:    50,
			description: "DL: prefix must score 50+ higher than generic context",
		},
		{
			name:        "driver keyword vs serial keyword for same number",
			highCtx:     "driver license D1234567",
			lowCtx:      "serial number D1234567",
			minDelta:    30,
			description: "Driver keyword must score significantly higher than serial context",
		},
		{
			name:        "state+keyword vs generic for 8 digits",
			highCtx:     "Texas driver license 12345678",
			lowCtx:      "order number 12345678 placed",
			minDelta:    50,
			description: "State+keyword must dramatically outperform generic usage",
		},
		{
			name:        "DL prefix vs account context for same format",
			highCtx:     "DL# AB123456",
			lowCtx:      "Account AB123456 balance",
			minDelta:    50,
			description: "Explicit DL prefix vs account context",
		},
		{
			name:        "multiple DL keywords vs single generic keyword",
			highCtx:     "California DMV driver's license D9876543",
			lowCtx:      "license D9876543",
			minDelta:    20,
			description: "Multiple DL keywords + state must score higher than lone keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			highMatches, err := validator.ValidateContent(tt.highCtx, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(high) error = %v", err)
			}
			lowMatches, err := validator.ValidateContent(tt.lowCtx, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(low) error = %v", err)
			}

			var highConf, lowConf float64
			if len(highMatches) > 0 {
				highConf = highMatches[0].Confidence
			}
			if len(lowMatches) > 0 {
				lowConf = lowMatches[0].Confidence
			}

			delta := highConf - lowConf
			if delta < tt.minDelta {
				t.Errorf("CONTEXT WEAKNESS: %s\n  high=%q → confidence=%.1f\n  low=%q → confidence=%.1f\n  delta=%.1f (need >= %.0f)\n  detail: %s",
					tt.name, tt.highCtx, highConf, tt.lowCtx, lowConf, delta, tt.minDelta, tt.description)
			}
		})
	}
}

// TestAdversarial_CrossValidatorConfusion verifies that values belonging to
// other validators (SSN, phone, credit card prefixes, etc.) are NOT matched
// as driver's licenses even when DL-adjacent keywords are present.
func TestAdversarial_CrossValidatorConfusion(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		content       string
		maxConfidence float64
		description   string
	}{
		{
			name:          "SSN 9 digits with driver keyword",
			content:       "driver SSN 123456789 on file",
			maxConfidence: 30,
			description:   "SSN keyword must suppress DL detection even with driver present",
		},
		{
			name:          "phone with DMV keyword",
			content:       "DMV phone 12345678 call now",
			maxConfidence: 50,
			description:   "Phone keyword should suppress DL even near DMV",
		},
		{
			name:          "social security with license application",
			content:       "Social security 123456789 for license application",
			maxConfidence: 50,
			description:   "Social security context must suppress 9-digit DL match",
		},
		{
			name:          "IP address near driver context",
			content:       "Driver service IP address 12345678 port",
			maxConfidence: 30,
			description:   "IP address context should strongly suppress",
		},
		{
			name:          "bank account with DL keyword nearby",
			content:       "DL holder account 12345678 balance",
			maxConfidence: 50,
			description:   "Account keyword should suppress even with DL keyword",
		},
		{
			name:          "UUID-like with license keyword",
			content:       "License UUID AB123456 generated",
			maxConfidence: 30,
			description:   "UUID context should suppress DL detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Confidence > tt.maxConfidence {
					t.Errorf("CROSS-VALIDATOR CONFUSION: %s\n  input: %q\n  matched: %q confidence=%.1f (max=%.1f)\n  detail: %s",
						tt.name, tt.content, m.Text, m.Confidence, tt.maxConfidence, tt.description)
				}
			}
		})
	}
}

// TestAdversarial_EdgeCases exercises boundary conditions, malformed inputs,
// and unusual character patterns.
func TestAdversarial_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("empty string", func(t *testing.T) {
		matches, err := validator.ValidateContent("", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) > 0 {
			t.Error("Empty string should produce no matches")
		}
	})

	t.Run("only whitespace with keywords", func(t *testing.T) {
		matches, err := validator.ValidateContent("   driver license   ", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) > 0 {
			t.Error("Keywords without number patterns should produce no matches")
		}
	})

	t.Run("number too long for any format", func(t *testing.T) {
		// 14 digits should not match any format
		matches, err := validator.ValidateContent("DL: 12345678901234", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// The 14-digit number shouldn't match, but substrings might
		for _, m := range matches {
			if m.Text == "12345678901234" {
				t.Error("14-digit number should not match any DL format")
			}
		}
	})

	t.Run("number embedded in longer token no word boundary", func(t *testing.T) {
		// D1234567 embedded in longer string without word boundaries
		matches, err := validator.ValidateContent("DL: XD1234567Y", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// Word boundaries should prevent matching the embedded pattern
		for _, m := range matches {
			if m.Text == "D1234567" {
				t.Error("Should not match D1234567 when embedded in XD1234567Y")
			}
		}
	})

	t.Run("unicode smart quotes around DL number", func(t *testing.T) {
		content := "Driver’s license: D1234567"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// "driver" keyword should still be detected (it's in the content)
		// The smart apostrophe should not prevent detection
		if len(matches) == 0 {
			t.Error("Smart quote apostrophe should not prevent DL detection when 'driver' keyword matches")
		}
	})

	t.Run("DL number at start of line", func(t *testing.T) {
		matches, err := validator.ValidateContent("D1234567 driver license", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("DL number at start of line should still match when keywords present")
		}
	})

	t.Run("DL number at end of line", func(t *testing.T) {
		matches, err := validator.ValidateContent("driver license D1234567", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("DL number at end of line should still match")
		}
	})

	t.Run("very long line with DL in middle", func(t *testing.T) {
		padding := strings.Repeat("x", 500)
		content := padding + " DL: D1234567 " + padding
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("DL in middle of very long line should still be detected")
		}
	})

	t.Run("multiple lines only one has DL context", func(t *testing.T) {
		content := "Line 1: nothing here\nLine 2: D1234567 some random code\nLine 3: DL: D7654321\nLine 4: more random"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// Should only match line 3 (has DL: prefix)
		if len(matches) != 1 {
			t.Errorf("Expected exactly 1 match (line 3), got %d", len(matches))
			for _, m := range matches {
				t.Logf("  match: %q line=%d confidence=%.1f", m.Text, m.LineNumber, m.Confidence)
			}
		}
		if len(matches) == 1 && matches[0].LineNumber != 3 {
			t.Errorf("Expected match on line 3, got line %d", matches[0].LineNumber)
		}
	})

	t.Run("all zeros in DL format with prefix", func(t *testing.T) {
		matches, err := validator.ValidateContent("DL: D0000000", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) > 0 && matches[0].Confidence > 80 {
			t.Errorf("All-zero DL should have reduced confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("sequential digits 12345678 with DL keyword", func(t *testing.T) {
		matches, err := validator.ValidateContent("DL: 12345678", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) > 0 && matches[0].Confidence > 85 {
			t.Errorf("Sequential digit DL should have reduced confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("repeated digit 99999999 with DL keyword", func(t *testing.T) {
		matches, err := validator.ValidateContent("DL: 99999999", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) > 0 && matches[0].Confidence > 75 {
			t.Errorf("Repeated digit DL should have further reduced confidence, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("DL on line with keyword on different line", func(t *testing.T) {
		// Keywords only matter on the SAME line
		content := "driver's license information:\n12345678"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// Line 2 has no keyword, so should not match
		for _, m := range matches {
			if m.LineNumber == 2 {
				t.Errorf("Number on line without keywords should not match, got %q confidence=%.1f", m.Text, m.Confidence)
			}
		}
	})

	t.Run("partial DL number should not match", func(t *testing.T) {
		// Only 6 digits with a letter (too short for any format)
		matches, err := validator.ValidateContent("DL: D123456", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) > 0 {
			t.Errorf("6-digit letter-prefix should not match any format, got %q", matches[0].Text)
		}
	})

	t.Run("number with leading zeros California format", func(t *testing.T) {
		matches, err := validator.ValidateContent("DL: A0123456", "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("California DL with leading zeros should still match")
		}
	})

	t.Run("massive content does not panic", func(t *testing.T) {
		// 10000 lines of generic content with one DL in the middle
		var b strings.Builder
		for i := 0; i < 5000; i++ {
			fmt.Fprintf(&b, "Line %d: generic content here\n", i)
		}
		b.WriteString("DL: D1234567\n")
		for i := 5001; i < 10000; i++ {
			fmt.Fprintf(&b, "Line %d: more generic content\n", i)
		}
		matches, err := validator.ValidateContent(b.String(), "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(matches) == 0 {
			t.Error("Should find DL in large content")
		}
	})
}

// TestAdversarial_ContainsKeywordBoundary verifies the word-boundary logic
// in containsKeyword does not produce false triggers from substrings.
func TestAdversarial_ContainsKeywordBoundary(t *testing.T) {
	tests := []struct {
		text     string
		keyword  string
		expected bool
	}{
		// "dl" should NOT match inside other words
		{"handle this", "dl", false},
		{"idle worker", "dl", false},
		{"badly done", "dl", false},
		{"middle ground", "dl", false},
		{"download file", "dl", false},

		// "dl" SHOULD match as standalone or with punctuation
		{"DL: D1234567", "dl", true},
		{"my dl number", "dl", true},
		{"check dl# here", "dl", true},
		{"(dl) value", "dl", true},

		// "license" should NOT match inside longer words
		{"unlicensed driver", "license", false},

		// "license" SHOULD match standalone
		{"my license is", "license", true},
		{"license: ABC", "license", true},

		// "id" boundary checks
		{"video game", "id", false},
		{"provide data", "id", false},
		{"avoid this", "id", false},
		{"state id card", "id", true},
		{"id: 12345", "id", true},

		// "permit" boundary checks
		{"permitted entry", "permit", false},
		{"parking permit", "permit", true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("containsKeyword(%q,%q)", tt.text, tt.keyword)
		t.Run(name, func(t *testing.T) {
			got := containsKeyword(tt.text, tt.keyword)
			if got != tt.expected {
				t.Errorf("containsKeyword(%q, %q) = %v, want %v", tt.text, tt.keyword, got, tt.expected)
			}
		})
	}
}

// TestAdversarial_LineGateSubstringID specifically tests that the
// lineHasPositiveKeyword "id" check does not produce false gate passes
// from words merely containing "id" as a substring.
func TestAdversarial_LineGateSubstringID(t *testing.T) {
	validator := NewValidator()

	// These lines have state names + words containing "id" substring but
	// should NOT pass the gate (no actual "id" keyword as standalone word).
	noMatchCases := []struct {
		name    string
		content string
	}{
		{
			name:    "Florida + video (id substring)",
			content: "Florida video 12345678 uploaded",
		},
		{
			name:    "California + provide (id substring)",
			content: "California provide 87654321 services",
		},
		{
			name:    "Texas + avoid (id substring)",
			content: "Texas avoid 12345678 delays",
		},
		{
			name:    "Ohio + consider (id substring)",
			content: "Ohio considered 12345678 invalid",
		},
	}

	for _, tt := range noMatchCases {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Confidence > 50 {
					t.Errorf("GATE SUBSTRING BUG: %s\n  input: %q\n  matched %q at confidence=%.1f\n  'id' substring in word should not pass gate",
						tt.name, tt.content, m.Text, m.Confidence)
				}
			}
		})
	}
}
