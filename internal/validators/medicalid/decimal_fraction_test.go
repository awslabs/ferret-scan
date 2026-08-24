// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "testing"

// The digits after a decimal point are not a medical identifier.
//
// Measured at main @ 0610b7e: "0.1234567893" reported MEDICAL_ID NPI at LOW 40. This is the THIRD
// instance of one predicate — PHONE (#443) and SSN (#446) were the first two, fixed separately by
// hand — and it was found by testing the class rather than by waiting for a report. The shared
// predicate now lives in kwmatch so the fourth validator does not need to rediscover it.
//
// Applied at the scanMatches chokepoint, so NPI, DEA, MBI and anything added later are covered by one
// line rather than by each evaluator remembering.
func TestDecimalFractionIsNotAMedicalID(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"0.1234567893",
		"ratio 0.1234567893",
		"value: 0.1234567893 computed",
		"coords 0.1234567893,0.9876543217",
	} {
		t.Run(line, func(t *testing.T) {
			got, err := v.ValidateContent(line, "metrics.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(got) != 0 {
				texts := make([]string, 0, len(got))
				for _, m := range got {
					texts = append(texts, m.Text+"@"+m.Type)
				}
				t.Errorf("a decimal fraction was reported as a medical identifier: %s -> %v", line, texts)
			}
		})
	}
}

// The other direction, across every identifier kind this validator reports.
//
// The guard sits at the chokepoint every regex passes through, so a mistake there would silence all of
// them at once — which for a medical identifier means a cleartext leak, since only reported findings
// reach the redactor. DEA and MBI are alphanumeric and a decimal fraction cannot produce them, so they
// are here to prove the guard does not overreach rather than because they were ever at risk.
func TestRealMedicalIDsStillReport(t *testing.T) {
	v := NewValidator()

	cases := []struct{ name, line string }{
		{"npi labelled", "NPI: 1234567893"},
		{"mrn labelled", "MRN 1234567893"},
		{"dea", "DEA AB1234563"},
		{"npi in prose ending in a period", "The provider NPI is 1234567893."},
		{"npi after an equals", "npi=1234567893"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := v.ValidateContent(c.line, "records.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(got) == 0 {
				t.Errorf("a real medical identifier stopped being reported: %s\n  only reported "+
					"findings reach the redactor, so suppressing this leaves the value in cleartext", c.line)
			}
		})
	}
}
