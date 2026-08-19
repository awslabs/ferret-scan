// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"testing"
)

// 078-05-1120 was printed on the specimen card in Woolworth wallets sold from
// 1938. Around 40,000 people subsequently filed it as their own number and the
// SSA voided it: it was never validly issued and can never be reissued, so it
// identifies nobody. It remains the most widely copied example SSN.
//
// Measured before this: "Employee SSN 078-05-1120 on file" scored 100 HIGH.
// isValidSSN accepts it (area 078, group 05 and serial 1120 are all in range) and
// the SSN keyword pushed it to the top, so nothing in the validator recognized it.
// See #364.
//
// The treatment here is the DROP the surrounding testSSNs entries already get,
// not the confidence ceiling phone and otp use. That is deliberate: the argument
// for a ceiling is that a reported finding still reaches the redactor, and a
// value that identifies nobody has nothing to redact. Matching this validator's
// eleven existing entries also beats introducing a second mechanism inside it.

func TestVoidedSSNIsNotReported(t *testing.T) {
	v := NewValidator()

	// Every form the patterns accept, each with the strongest SSN context
	// available -- which is what took the original to 100.
	for _, content := range []string{
		"Employee SSN 078-05-1120 on file",
		"social security number: 078-05-1120",
		"ssn 078 05 1120 verified",
		"taxpayer identification 078051120 on record",
		"SSN,Name\n078-05-1120,Marcus Whitfield\n",
	} {
		matches, err := v.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", content, err)
		}
		for _, m := range matches {
			if v.cleanSSN(m.Text) == "078051120" {
				t.Errorf("%q reported the voided SSN 078-05-1120 at %.0f -- it was never "+
					"issued and identifies nobody, so it is a false positive at any "+
					"confidence", content, m.Confidence)
			}
		}
	}
}

// The drop must not spread to numbers that merely resemble it. Each of these
// differs from 078-05-1120 in one position and is an ordinary, valid SSN; a
// validator that suppressed them would be hiding real values.
func TestSSNsAdjacentToTheVoidedOneStillReport(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct{ ssn, content string }{
		{"078051121", "Employee SSN 078-05-1121 on file"},
		{"078051119", "Employee SSN 078-05-1119 on file"},
		{"078061120", "Employee SSN 078-06-1120 on file"},
		{"079051120", "Employee SSN 079-05-1120 on file"},
	} {
		matches, err := v.ValidateContent(tc.content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", tc.content, err)
		}
		found := false
		for _, m := range matches {
			if v.cleanSSN(m.Text) == tc.ssn {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not report %s -- suppression has spread beyond the single "+
				"voided number, which would hide real SSNs", tc.content, tc.ssn)
		}
	}
}

func TestIsTestSSNCoversTheVoidedNumber(t *testing.T) {
	v := NewValidator()

	if !v.isTestSSN("078051120") {
		t.Error(`isTestSSN("078051120") = false, want true -- the SSA voided this number`)
	}

	// 219-09-9999 is also described as voided, but it is this suite's canonical
	// real-SSN fixture and TestSSNValidator_IsTestSSN asserts false for it.
	// Pinned here so the two expectations cannot silently diverge; changing it is
	// a separate call tracked in #364.
	if v.isTestSSN("219099999") {
		t.Error(`isTestSSN("219099999") = true -- this suite uses 219-09-9999 as its ` +
			`real-SSN fixture, so adding it here breaks a dozen unrelated tests; see #364`)
	}

	// The SSA's advertising block needs no entry: area 987 is outside the valid
	// 001-665/667-899 range, so isValidSSN rejects it first. Asserted so a future
	// change to the area rules does not silently open it up.
	if v.isValidSSN("987654325") {
		t.Error(`isValidSSN("987654325") = true -- area 987 is out of range, and the ` +
			`SSA advertising block 987-65-4320..4329 relies on that rejection`)
	}
}
