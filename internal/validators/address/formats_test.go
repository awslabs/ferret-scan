// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import (
	"testing"
)

// TestAddress_ExtendedFormats covers the coverage added after the recall-gap
// audit: ordinal street names (123 42nd Street), residential-development
// suffixes (Ridge, Point, Cove, ...), highway route-number spans, and the
// keyword/ZIP-gated case-insensitive fallback for lowercased text.
func TestAddress_ExtendedFormats(t *testing.T) {
	validator := NewValidator()

	positive := []struct {
		name, content, wantText string
	}{
		{"ordinal street", "ship to 123 42nd Street, New York, NY 10036", "123 42nd Street"},
		{"ordinal avenue", "office at 350 5th Ave, New York, NY 10118", "350 5th Ave"},
		{"ridge suffix", "mailing 500 Oak Ridge address", "500 Oak Ridge"},
		{"landing suffix", "residence at 900 Harbor Landing", "900 Harbor Landing"},
		{"highway with route number", "mailing address 1234 US Highway 61", "1234 US Highway 61"},
		{"lowercase with zip", "deliver to 742 evergreen terrace, springfield, il 62704", "742 evergreen terrace"},
		{"lowercase with keyword", "mailing address: 100 main st", "100 main st"},
	}
	for _, tt := range positive {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			var found bool
			for _, m := range matches {
				if m.Type == "US_STREET_ADDRESS" && m.Text == tt.wantText {
					found = true
				}
			}
			if !found {
				t.Errorf("expected US_STREET_ADDRESS match %q in: %s", tt.wantText, tt.content)
			}
		})
	}

	negative := []struct {
		name, content string
	}{
		// The case-relaxed gate must stay closed without address context:
		// lowercase suffix words are ordinary prose.
		{"prose way no context", "5 people way too many for the room"},
		{"prose way with items", "3 items in way of progress"},
		{"bare lowercase no context", "grabbed 2 point wins in the game"},
		// Suffix + trailing time must not swallow the time digit.
		{"street then time", "meet at 100 Main St 3 pm sharp"},
	}
	for _, tt := range negative {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Type == "US_STREET_ADDRESS" && len(m.Text) > len("100 Main St") {
					t.Errorf("span too wide or prose matched: %q (conf=%.1f)", m.Text, m.Confidence)
				}
				if tt.name != "street then time" && m.Type == "US_STREET_ADDRESS" {
					t.Errorf("unexpected address match in prose: %q (conf=%.1f)", m.Text, m.Confidence)
				}
			}
		})
	}
}
