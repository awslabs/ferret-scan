// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestBankAccountValidator_IBAN_Spaced covers the display-format IBAN pass
// (space-grouped fours, e.g. "DE89 3704 0044 0532 0130 00" as printed on
// invoices): candidates are normalized and must pass the same isValidIBAN
// gate as contiguous IBANs; the reported span is the original spaced text.
func TestBankAccountValidator_IBAN_Spaced(t *testing.T) {
	validator := NewValidator()

	t.Run("spaced IBAN detected with original span", func(t *testing.T) {
		matches, err := validator.ValidateContent("pay to IBAN DE89 3704 0044 0532 0130 00 per invoice", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		var found bool
		for _, m := range matches {
			if m.Type != "IBAN" {
				continue
			}
			found = true
			if !strings.Contains(m.Text, " ") {
				t.Errorf("reported span must keep the printed spacing for redaction, got %q", m.Text)
			}
			if m.Metadata["normalized"] != "DE89370400440532013000" {
				t.Errorf("normalized metadata = %v, want DE89370400440532013000", m.Metadata["normalized"])
			}
			if m.Metadata["country"] != "DE" {
				t.Errorf("country metadata = %v, want DE", m.Metadata["country"])
			}
		}
		if !found {
			t.Error("expected IBAN match for spaced display format")
		}
	})

	t.Run("spaced IBAN with bad mod-97 checksum rejected", func(t *testing.T) {
		matches, err := validator.ValidateContent("IBAN DE89 3704 0044 0532 0130 01 transfer", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		for _, m := range matches {
			if m.Type == "IBAN" {
				t.Errorf("unexpected IBAN match for invalid checksum: %q", m.Text)
			}
		}
	})

	t.Run("spaced groups that are not an IBAN rejected", func(t *testing.T) {
		// Coordinates / measurement groups: no country code, wrong length.
		matches, err := validator.ValidateContent("bank grid 40 7128 74 0060 sector", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		for _, m := range matches {
			if m.Type == "IBAN" {
				t.Errorf("unexpected IBAN match for non-IBAN groups: %q", m.Text)
			}
		}
	})

	t.Run("test-context spaced IBAN scores below contiguous baseline", func(t *testing.T) {
		clean, err := validator.ValidateContent("wire to IBAN DE89 3704 0044 0532 0130 00 now", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		test, err := validator.ValidateContent("test iban DE89 3704 0044 0532 0130 00 example fixture", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		cc, tc := singleIBANConfidence(t, clean), singleIBANConfidence(t, test)
		if tc >= cc {
			t.Errorf("test-context IBAN (%.1f) must score below clean-context (%.1f)", tc, cc)
		}
	})
}

// singleIBANConfidence returns the confidence of the single IBAN match,
// failing the test if there is not exactly one.
func singleIBANConfidence(t *testing.T, matches []detector.Match) float64 {
	t.Helper()
	var conf []float64
	for _, m := range matches {
		if m.Type == "IBAN" {
			conf = append(conf, m.Confidence)
		}
	}
	if len(conf) != 1 {
		t.Fatalf("expected exactly one IBAN match, got %d", len(conf))
	}
	return conf[0]
}
