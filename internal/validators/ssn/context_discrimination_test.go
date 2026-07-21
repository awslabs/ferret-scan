// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"testing"
)

// TestSSNValidator_ContextDiscrimination is the regression net for the
// self-counting tabular bug: the date pattern matched the tail of every
// XXX-XX-XXXX SSN (e.g. 87-4100 parses as \d{1,2}-\d{2}-\d{4}), so a line
// holding ONE bare SSN counted two "structured elements", every line got the
// +15 tabular boost, and real-context vs decoy-context lines both re-clamped
// to 100 HIGH — zero context discrimination (locked as a wart by the
// context_decoys_original golden case before this fix).
func TestSSNValidator_ContextDiscrimination(t *testing.T) {
	v := NewValidator()

	conf := func(t *testing.T, content string) float64 {
		t.Helper()
		matches, err := v.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}
		if len(matches) == 0 {
			return -1
		}
		return matches[0].Confidence
	}

	t.Run("decoy contexts stay below HIGH", func(t *testing.T) {
		for _, line := range []string{
			"part number 449-87-4100 from the catalog",
			"requisition 526-33-8210 approved for shipment",
			"lot 449-87-4100 shipped yesterday",
		} {
			if c := conf(t, line); c >= 90 {
				t.Errorf("decoy context %q should stay below HIGH, got %.1f", line, c)
			}
		}
	})

	t.Run("real contexts still reach HIGH", func(t *testing.T) {
		for _, line := range []string{
			"employee ssn 449-87-4100 on file",
			"SSN: 449-87-4100",
			"payroll record 449-87-4100 for W2",
		} {
			if c := conf(t, line); c < 90 {
				t.Errorf("real context %q should reach HIGH, got %.1f", line, c)
			}
		}
	})

	t.Run("real vs decoy context separates", func(t *testing.T) {
		real := conf(t, "employee ssn 449-87-4100 on file")
		decoy := conf(t, "part number 449-87-4100 from the catalog")
		if real <= decoy {
			t.Errorf("real context (%.1f) must outscore decoy context (%.1f)", real, decoy)
		}
	})

	t.Run("single bare SSN is not tabular", func(t *testing.T) {
		if v.isTabularData("449-87-4100", "449-87-4100") {
			t.Error("a line holding one bare SSN must not self-count as tabular data")
		}
	})

	t.Run("genuine tabular lines still boost", func(t *testing.T) {
		for _, line := range []string{
			"Alice,449-87-4100,alice@example.com",      // CSV: SSN + email
			"449-87-4100\t2024-01-15\tEngineering",     // TSV: SSN + date + tabs
			"John Smith  449-87-4100  555-123-4567 x2", // fixed-width, SSN + phone
		} {
			if !v.isTabularData(line, "449-87-4100") {
				t.Errorf("genuine tabular line %q should still be detected as tabular", line)
			}
		}
	})
}
