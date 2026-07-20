// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"testing"
)

// TestDOB_ExtendedFormats covers the format coverage added after the
// recall-gap audit: two-digit years (3/14/87), dot separators (03.14.1987),
// and ordinal day names (March 14th, 1987) — plus the guards that keep the
// new patterns from matching semver strings and mixed-separator tokens.
func TestDOB_ExtendedFormats(t *testing.T) {
	validator := NewValidator()

	positive := []struct {
		name, content, wantText string
	}{
		{"two-digit year slash", "patient dob 3/14/87 on file", "3/14/87"},
		{"two-digit year dash", "DOB: 3-14-87 recorded", "3-14-87"},
		{"two-digit year dotted", "birthdate: 3.14.87 form", "3.14.87"},
		{"dotted four-digit year", "date of birth 03.14.1987 admission", "03.14.1987"},
		{"ordinal month-day", "her birthday is March 14th, 1987", "March 14th, 1987"},
		{"ordinal day-month", "born 14th March 1987 in Ohio", "14th March 1987"},
		{"first ordinal", "born June 1st, 1990", "June 1st, 1990"},
	}
	for _, tt := range positive {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			var found bool
			for _, m := range matches {
				if m.Type == "DATE_OF_BIRTH" && m.Text == tt.wantText {
					found = true
					if m.Confidence < 60 {
						t.Errorf("keyword-context DOB confidence too low: %.1f", m.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("expected DATE_OF_BIRTH match %q in: %s", tt.wantText, tt.content)
			}
		})
	}

	negative := []struct {
		name, content, decoy string
	}{
		// Version-context guard: dotted 2-digit-year shapes are semver shapes.
		// "dob" here is a service name — a strong keyword the guard must beat.
		{"semver with version keyword", "upgrade dob service to version 2.14.87 build", "2.14.87"},
		{"pip pin", "pip install dob==1.4.87 today", "1.4.87"},
		{"release tag", "dob v2.3.87 release notes", "2.3.87"},
		// Mixed separators are not dates.
		{"mixed separators", "dob 3/14-87 malformed", "3/14-87"},
	}
	for _, tt := range negative {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "DATE_OF_BIRTH" && m.Text == tt.decoy {
					t.Errorf("guard failed: %q reported as DOB (conf=%.1f)", m.Text, m.Confidence)
				}
			}
		})
	}

	t.Run("two-digit year century resolution", func(t *testing.T) {
		// 87 → 1987 (past), not 2087: a future year would be rejected by
		// isPlausibleDOB, so a match at all proves 19xx resolution.
		matches, err := validator.ValidateContent("dob 3/14/87 applicant", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			t.Error("expected match: two-digit year 87 must resolve to 1987, not 2087")
		}
	})
}
