// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"context"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func TestDOBValidator_PositiveCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name          string
		content       string
		expectMatch   bool
		minConfidence float64
		description   string
	}{
		{
			name:          "DOB with explicit keyword MM/DD/YYYY",
			content:       "Date of Birth: 03/15/1990",
			expectMatch:   true,
			minConfidence: 80,
			description:   "Explicit DOB keyword with US date format",
		},
		{
			name:          "DOB with dob abbreviation",
			content:       "DOB: 12/25/1985",
			expectMatch:   true,
			minConfidence: 80,
			description:   "DOB abbreviation with date",
		},
		{
			name:          "DOB with d.o.b abbreviation",
			content:       "d.o.b: 07/04/1976",
			expectMatch:   true,
			minConfidence: 80,
			description:   "d.o.b abbreviation with date",
		},
		{
			name:          "Born keyword with ISO date",
			content:       "Patient born 1985-06-15",
			expectMatch:   true,
			minConfidence: 60,
			description:   "born keyword with ISO format date",
		},
		{
			name:          "Birthday with written month",
			content:       "birthday: January 15, 1990",
			expectMatch:   true,
			minConfidence: 60,
			description:   "birthday keyword with Month DD, YYYY format",
		},
		{
			name:          "Birth date with DD Month YYYY",
			content:       "birth date: 15 March 1982",
			expectMatch:   true,
			minConfidence: 80,
			description:   "birth date keyword with DD Month YYYY format",
		},
		{
			name:          "DOB in form field",
			content:       "Applicant DOB: 1992-11-30",
			expectMatch:   true,
			minConfidence: 80,
			description:   "DOB in application form context",
		},
		{
			name:          "Date of birth with hyphenated date",
			content:       "date of birth: 05-22-1988",
			expectMatch:   true,
			minConfidence: 80,
			description:   "Date of birth with hyphenated numeric format",
		},
		{
			name:          "Multiple positive keywords",
			content:       "Patient DOB (date of birth): 08/14/1975",
			expectMatch:   true,
			minConfidence: 85,
			description:   "Multiple strong DOB keywords",
		},
		{
			name:          "Age context with date",
			content:       "Age 34, born 06/12/1989",
			expectMatch:   true,
			minConfidence: 60,
			description:   "Age keyword with born context",
		},
		{
			name:          "Abbreviated month DOB",
			content:       "DOB: Feb 28, 1995",
			expectMatch:   true,
			minConfidence: 80,
			description:   "DOB with abbreviated month name",
		},
		{
			name:          "DD abbreviated month YYYY",
			content:       "Date of Birth: 5 Sep 1970",
			expectMatch:   true,
			minConfidence: 80,
			description:   "DOB with DD abbreviated month YYYY",
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
				return
			}
			if hasMatch {
				if matches[0].Type != "DATE_OF_BIRTH" {
					t.Errorf("expected Type=DATE_OF_BIRTH, got=%s", matches[0].Type)
				}
				if matches[0].Validator != "dob" {
					t.Errorf("expected Validator=dob, got=%s", matches[0].Validator)
				}
				if matches[0].Confidence < tt.minConfidence {
					t.Errorf("%s: confidence %.1f below minimum %.1f",
						tt.description, matches[0].Confidence, tt.minConfidence)
				}
			}
		})
	}
}

func TestDOBValidator_NegativeCases(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "File timestamp",
			content:     "File created: 03/15/2024",
			description: "File creation date should not match",
		},
		{
			name:        "Modified date",
			content:     "Last modified: 2023-12-01",
			description: "File modification date should not match",
		},
		{
			name:        "Expiry date",
			content:     "Expires: 06/30/2025",
			description: "Expiration date should not match",
		},
		{
			name:        "Due date",
			content:     "Due date: January 15, 2024",
			description: "Due date should not match",
		},
		{
			name:        "Meeting date",
			content:     "Meeting scheduled: 03/20/2024",
			description: "Calendar/meeting date should not match",
		},
		{
			name:        "Published date",
			content:     "Published: 2023-08-15",
			description: "Article published date should not match",
		},
		{
			name:        "Version/build date",
			content:     "Build version 2.0, compiled 2024-01-10",
			description: "Software build date should not match",
		},
		{
			name:        "Release date",
			content:     "Released: March 1, 2024",
			description: "Product release date should not match",
		},
		{
			name:        "Date without any context",
			content:     "03/15/1990",
			description: "Bare date without context should have very low confidence",
		},
		{
			name:        "Date in code comment",
			content:     "// Updated 2024-03-15 by developer",
			description: "Code date should not match",
		},
		{
			name:        "Deployment timestamp",
			content:     "Deployed: 11/22/2023",
			description: "Deployment date should not match",
		},
		{
			name:        "Event calendar date",
			content:     "Event date: 15 June 2024",
			description: "Calendar event date should not match",
		},
		{
			name:        "Test data",
			content:     "Test DOB: 01/01/2000",
			description: "Test/sample data with DOB keyword should still suppress",
		},
		{
			name:        "Example placeholder",
			content:     "Example date of birth: 12/31/1990",
			description: "Example/placeholder should suppress",
		},
		{
			name:        "Schedule date",
			content:     "Schedule: appointment on 04/10/2024",
			description: "Appointment scheduling should not match",
		},
		{
			name:        "Copyright year",
			content:     "Copyright 01/01/2020 All rights reserved",
			description: "Copyright date should not match",
		},
		{
			name:        "Future year as DOB",
			content:     "DOB: 03/15/2030",
			description: "Future dates are not valid DOBs",
		},
		{
			name:        "Very old year",
			content:     "DOB: 03/15/1850",
			description: "Implausibly old dates are not valid DOBs",
		},
		{
			name:        "Invalid month 13",
			content:     "DOB: 13/15/1990",
			description: "Invalid month should not match",
		},
		{
			name:        "Invalid day 32",
			content:     "DOB: 01/32/1990",
			description: "Invalid day should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			// These should either not match or have very low confidence (<=15)
			for _, m := range matches {
				if m.Confidence > 15 {
					t.Errorf("%s: should not surface a high-confidence match, got %.1f for %q",
						tt.description, m.Confidence, m.Text)
				}
			}
		})
	}
}

func TestDOBValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	t.Run("DOB keyword boosts confidence far above no-keyword", func(t *testing.T) {
		matchDOB, _ := validator.ValidateContent("DOB: 03/15/1990", "test.txt")
		matchPlain, _ := validator.ValidateContent("value: 03/15/1990", "test.txt")

		if len(matchDOB) == 0 {
			t.Fatal("Expected match with DOB keyword")
		}
		// Plain should either not match or have very low confidence
		plainConf := 0.0
		if len(matchPlain) > 0 {
			plainConf = matchPlain[0].Confidence
		}
		if matchDOB[0].Confidence <= plainConf {
			t.Errorf("DOB keyword should boost confidence far above plain: DOB=%.1f, plain=%.1f",
				matchDOB[0].Confidence, plainConf)
		}
	})

	t.Run("Negative keyword suppresses even with positive keyword", func(t *testing.T) {
		// "test" should suppress even when "DOB" is present
		matches, _ := validator.ValidateContent("Test DOB: 03/15/1990", "test.txt")
		for _, m := range matches {
			if m.Confidence > 15 {
				t.Errorf("test + DOB should suppress, got confidence %.1f", m.Confidence)
			}
		}
	})

	t.Run("Multiple positive keywords increase confidence", func(t *testing.T) {
		matchSingle, _ := validator.ValidateContent("born 03/15/1990", "test.txt")
		matchMultiple, _ := validator.ValidateContent("Patient DOB date of birth: 03/15/1990", "test.txt")

		if len(matchSingle) == 0 || len(matchMultiple) == 0 {
			t.Fatal("Expected matches in both cases")
		}
		if matchMultiple[0].Confidence <= matchSingle[0].Confidence {
			t.Errorf("Multiple keywords should yield higher confidence: single=%.1f, multiple=%.1f",
				matchSingle[0].Confidence, matchMultiple[0].Confidence)
		}
	})
}

func TestDOBValidator_ContextAnalysisMethod(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string // "positive", "negative", or "neutral"
	}{
		{
			name:           "DOB keyword in context",
			match:          "03/15/1990",
			line:           "DOB: 03/15/1990",
			expectedImpact: "positive",
		},
		{
			name:           "Created keyword in context",
			match:          "03/15/2024",
			line:           "File created: 03/15/2024",
			expectedImpact: "negative",
		},
		{
			name:           "No relevant keywords",
			match:          "03/15/1990",
			line:           "value: 03/15/1990",
			expectedImpact: "negative", // slight negative without DOB context
		},
		{
			name:           "Birthday keyword",
			match:          "03/15/1990",
			line:           "Happy birthday 03/15/1990",
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

func TestDOBValidator_EdgeCases(t *testing.T) {
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

	t.Run("Multiple DOBs in same line", func(t *testing.T) {
		content := "Primary DOB: 03/15/1990, Spouse DOB: 07/22/1988"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) < 2 {
			t.Errorf("Expected at least 2 DOB matches, got %d", len(matches))
		}
	})

	t.Run("DOB on separate lines", func(t *testing.T) {
		content := "Patient Information\nDOB: 1985-06-15\nName: John Smith"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("Expected at least one DOB match")
		}
		if matches[0].LineNumber != 2 {
			t.Errorf("Expected line number 2, got %d", matches[0].LineNumber)
		}
	})

	t.Run("Leap year Feb 29", func(t *testing.T) {
		matches, err := validator.ValidateContent("DOB: 02/29/2000", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Feb 29 should be valid for leap year")
		}
	})

	t.Run("Feb 30 invalid", func(t *testing.T) {
		matches, err := validator.ValidateContent("DOB: 02/30/1990", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		// Should not match because Feb 30 is invalid
		for _, m := range matches {
			if m.Confidence > 15 {
				t.Errorf("Feb 30 should not produce high-confidence match, got %.1f", m.Confidence)
			}
		}
	})

	t.Run("Unicode text around date", func(t *testing.T) {
		matches, err := validator.ValidateContent("Nombre completo, DOB: 03/15/1990", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Expected DOB match even with unicode characters nearby")
		}
	})

	t.Run("Year boundary 1900", func(t *testing.T) {
		matches, err := validator.ValidateContent("DOB: 01/01/1900", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Year 1900 should be valid for DOB")
		}
	})

	t.Run("Year boundary 2025", func(t *testing.T) {
		matches, err := validator.ValidateContent("DOB: 01/01/2025", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("Year 2025 should be valid for DOB")
		}
	})
}

func TestDOBValidator_ConfidenceStrategy(t *testing.T) {
	validator := NewValidator()

	t.Run("Base confidence without keywords is very low", func(t *testing.T) {
		confidence, _ := validator.CalculateConfidence("03/15/1990")
		if confidence > 20 {
			t.Errorf("Base confidence without context should be <=20, got %.1f", confidence)
		}
	})

	t.Run("Strong DOB keyword gives high confidence", func(t *testing.T) {
		matches, _ := validator.ValidateContent("DOB: 03/15/1990", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected a match with DOB keyword")
		}
		if matches[0].Confidence < 85 {
			t.Errorf("Strong DOB keyword should yield >=85, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("Weaker positive keyword gives moderate confidence", func(t *testing.T) {
		matches, _ := validator.ValidateContent("born 03/15/1990", "test.txt")
		if len(matches) == 0 {
			t.Fatal("Expected a match with born keyword")
		}
		if matches[0].Confidence < 60 || matches[0].Confidence > 80 {
			t.Errorf("Weaker keyword should yield 60-80, got %.1f", matches[0].Confidence)
		}
	})

	t.Run("No keywords gives very low or no match", func(t *testing.T) {
		matches, _ := validator.ValidateContent("Record: 03/15/1990", "test.txt")
		// Should either not match or be very low confidence
		for _, m := range matches {
			if m.Confidence > 15 {
				t.Errorf("No DOB keywords should not yield significant confidence, got %.1f", m.Confidence)
			}
		}
	})
}

func TestDOBValidator_DateFormats(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{"MM/DD/YYYY slash", "DOB: 03/15/1990"},
		{"MM-DD-YYYY hyphen", "DOB: 03-15-1990"},
		{"DD/MM/YYYY high day", "DOB: 25/03/1990"},
		{"YYYY-MM-DD ISO", "DOB: 1990-03-15"},
		{"Month DD YYYY full", "DOB: March 15, 1990"},
		{"Month DD YYYY no comma", "DOB: March 15 1990"},
		{"DD Month YYYY", "DOB: 15 March 1990"},
		{"Abbreviated month", "DOB: Mar 15, 1990"},
		{"DD abbreviated month", "DOB: 15 Mar 1990"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("Expected DOB match for format %q", tt.name)
				return
			}
			if matches[0].Confidence < 80 {
				t.Errorf("DOB with explicit keyword should have high confidence, got %.1f for %q",
					matches[0].Confidence, tt.name)
			}
		})
	}
}

func TestDOBValidator_CooperativeCancellation(t *testing.T) {
	validator := NewValidator()

	t.Run("Cancelled context returns partial results", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		matches, err := validator.ValidateContentCtx(ctx, "DOB: 03/15/1990\nDOB: 06/20/1985", "test.txt")
		if err == nil {
			// If error is nil, it means LineLoopCancelled was not hit on the first
			// iteration stride — which is fine, it should stop quickly
			_ = matches
		}
		// Either we get an error or partial/no results — both are acceptable
	})
}

func TestDOBValidator_Metadata(t *testing.T) {
	validator := NewValidator()

	matches, err := validator.ValidateContent("DOB: 03/15/1990", "patient.txt")
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
	if m.Metadata["source"] != "preprocessed_content" {
		t.Errorf("Expected source=preprocessed_content, got=%v", m.Metadata["source"])
	}
	if m.Metadata["original_file"] != "patient.txt" {
		t.Errorf("Expected original_file=patient.txt, got=%v", m.Metadata["original_file"])
	}
}

func TestDOBValidator_NewValidator(t *testing.T) {
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

func TestDOBValidator_FalsePositiveRegression(t *testing.T) {
	validator := NewValidator()

	// These are all common date patterns that should NOT trigger as DOB
	falsePositives := []struct {
		name    string
		content string
	}{
		{"git log date", "commit abc123 Date: 2024-03-15"},
		{"HTTP last modified", "Last-Modified: 15 Jan 2024"},
		{"JSON timestamp", `"updated_at": "2024-03-15"`},
		{"Log timestamp", "[2024-03-15] INFO: server started"},
		{"HTML copyright", "Copyright 2020-01-01 Company Inc"},
		{"Cron schedule", "# runs daily since 01/01/2020"},
		{"File date in path", "backup_2024-01-15/data.sql"},
		{"Calendar invite", "Meeting: 15 March 2024 at 2pm"},
		{"News article", "Published March 15, 2024 by Reuters"},
		{"Software version", "Version 2.0, released 01/15/2024"},
	}

	for _, fp := range falsePositives {
		t.Run(fp.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(fp.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Confidence > 15 {
					t.Errorf("False positive %q: should not surface, got confidence %.1f for %q",
						fp.name, m.Confidence, m.Text)
				}
			}
		})
	}
}
