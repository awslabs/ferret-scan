// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"testing"
)

// #939: nine bare digits followed by a byte unit read PASSPORT 90 HIGH. Behaviour tests use only
// ValidateContent, so they run unchanged against the parent commit.

func passportFindings(t *testing.T, content string) []float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []float64
	for _, m := range matches {
		if m.Type == "PASSPORT" {
			got = append(got, m.Confidence)
		}
	}
	return got
}

func TestAByteCountIsNotAPassport(t *testing.T) {
	for _, line := range []string{
		// docs/COVERAGE_DISCLOSURE.md:172 on main, verbatim.
		"| the 200 MB **per-container** byte budget | `embedded part \"big.bin\" was not examined: would " +
			"exceed the 209715200-byte total embedded extraction budget for this document` |",
		"Travel document scan: 209715200 bytes uploaded for the international application form",
		"passport photo upload limit 104857600 B",
	} {
		if got := passportFindings(t, line); len(got) != 0 {
			t.Errorf("PASSPORT %v on %q; a byte count is not a passport number", got, line)
		}
	}
}

func TestALabelledPassportNumberKeepsItsScore(t *testing.T) {
	for _, line := range []string{
		"Passport Number: 987654321",
		"Passport Number: 512345678 issued 2019",
		"UK passport: 512345678 (bytes on the next line)",
	} {
		got := passportFindings(t, line)
		if len(got) != 1 || got[0] < 90 {
			t.Errorf("PASSPORT %v on %q, want one HIGH finding", got, line)
		}
	}
}
