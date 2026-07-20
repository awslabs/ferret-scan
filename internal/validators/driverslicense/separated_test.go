// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"testing"
)

// TestDriversLicense_SeparatedFormats covers the separator-formatted DL pass
// (printed licenses use dashes/spaces, e.g. "D123-4567-8901"): candidates are
// normalized, must classify into a known state format, and the original span
// is reported. The shape guards must keep SSNs, dates, and ZIP+4 codes out
// even on lines with DL keywords.
func TestDriversLicense_SeparatedFormats(t *testing.T) {
	validator := NewValidator()

	positive := []struct {
		name, content, wantText string
	}{
		{"dashed 1L12D", "driver's license D123-4567-8901 verified", "D123-4567-8901"},
		{"spaced 9 digits", "license number 123 456 789 on file", "123 456 789"},
		{"dashed 8 digits", "texas dl 1234-5678 record", "1234-5678"},
	}
	for _, tt := range positive {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			var found bool
			for _, m := range matches {
				if m.Type == "DRIVERS_LICENSE" && m.Text == tt.wantText {
					found = true
					if m.Metadata["normalized"] == nil {
						t.Error("separated match must carry normalized metadata")
					}
				}
			}
			if !found {
				t.Errorf("expected DRIVERS_LICENSE match %q in: %s", tt.wantText, tt.content)
			}
		})
	}

	// Shape guards: these tokens classify into DL formats once separators are
	// stripped, but their groupings are canonically other identifiers. They
	// appear WITH DL keywords (the keyword gate is open) and must still not match.
	negative := []struct {
		name, content, decoy string
	}{
		{"SSN 3-2-4 grouping", "license check ssn 123-45-6789 cross-reference", "123-45-6789"},
		{"date M-D-Y grouping", "license issued 12-31-1987 expires", "12-31-1987"},
		{"date Y-M-D grouping", "license dated 1987-12-31 renewal", "1987-12-31"},
		{"ZIP+4 grouping", "zip on license record 12345-6789", "12345-6789"},
	}
	for _, tt := range negative {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "DRIVERS_LICENSE" && m.Text == tt.decoy {
					t.Errorf("shape guard failed: %q reported as DL (conf=%.1f)", m.Text, m.Confidence)
				}
			}
		})
	}

	t.Run("contiguous match not duplicated by separated pass", func(t *testing.T) {
		matches, err := validator.ValidateContent("driver license D1234567 on file", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		var count int
		for _, m := range matches {
			if m.Type == "DRIVERS_LICENSE" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly one DL match for contiguous token, got %d", count)
		}
	})
}
