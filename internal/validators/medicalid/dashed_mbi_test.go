// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestMedicalIDValidator_MBI_Dashed covers the card-printed dashed MBI format
// (4-3-4 grouping, e.g. 1EG4-TE5-MK73) added after the recall-gap audit: the
// dashes are stripped, the contiguous rules re-applied, and the ORIGINAL
// dashed span reported so redaction masks the token as printed on the card.
func TestMedicalIDValidator_MBI_Dashed(t *testing.T) {
	validator := NewValidator()

	t.Run("dashed MBI with medicare context", func(t *testing.T) {
		matches, err := validator.ValidateContent("Medicare beneficiary 1EG4-TE5-MK73 on card", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		var found bool
		for _, m := range matches {
			if m.Type != "MEDICARE_MBI" {
				continue
			}
			found = true
			if m.Text != "1EG4-TE5-MK73" {
				t.Errorf("reported span must be the dashed original for redaction, got %q", m.Text)
			}
			if m.Metadata["normalized"] != "1EG4TE5MK73" {
				t.Errorf("normalized metadata = %v, want 1EG4TE5MK73", m.Metadata["normalized"])
			}
			if m.Confidence < 50 {
				t.Errorf("dashed MBI with context: confidence too low: %.1f", m.Confidence)
			}
		}
		if !found {
			t.Error("expected MEDICARE_MBI match for dashed card format")
		}
	})

	t.Run("dashed and contiguous score identically", func(t *testing.T) {
		dashed, err := validator.ValidateContent("Medicare MBI 1EG4-TE5-MK73 patient", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		contiguous, err := validator.ValidateContent("Medicare MBI 1EG4TE5MK73 patient", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		dc, cc := mbiConfidence(t, dashed), mbiConfidence(t, contiguous)
		if dc != cc {
			t.Errorf("dashed (%.1f) and contiguous (%.1f) MBI must score identically", dc, cc)
		}
	})

	t.Run("wrong grouping does not match", func(t *testing.T) {
		// MBI dash grouping on cards is exactly 4-3-4; 3-4-4 must not match.
		matches, err := validator.ValidateContent("Medicare MBI 1EG-4TE5-MK73 odd grouping", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		for _, m := range matches {
			if m.Type == "MEDICARE_MBI" && strings.Contains(m.Text, "-") {
				t.Errorf("unexpected dashed MBI match for wrong grouping: %q", m.Text)
			}
		}
	})

	t.Run("invalid positional chars rejected after normalization", func(t *testing.T) {
		// S/L/O/I/B/Z are excluded from MBI letter positions; 1SG4-TE5-MK73
		// normalizes to an invalid MBI and must be rejected.
		matches, err := validator.ValidateContent("Medicare MBI 1SG4-TE5-MK73 invalid char", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		for _, m := range matches {
			if m.Type == "MEDICARE_MBI" {
				t.Errorf("unexpected MBI match for invalid positional char: %q", m.Text)
			}
		}
	})
}

// mbiConfidence returns the confidence of the single MEDICARE_MBI match in
// matches, failing the test if there is not exactly one.
func mbiConfidence(t *testing.T, matches []detector.Match) float64 {
	t.Helper()
	var conf []float64
	for _, m := range matches {
		if m.Type == "MEDICARE_MBI" {
			conf = append(conf, m.Confidence)
		}
	}
	if len(conf) != 1 {
		t.Fatalf("expected exactly one MEDICARE_MBI match, got %d", len(conf))
	}
	return conf[0]
}
