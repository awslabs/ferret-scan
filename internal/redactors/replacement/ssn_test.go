// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/validators/ssn"
)

// A synthetic SSN must be neither an SSN nor an ITIN (#884).
//
// The generator drew its area from {000, 666, 900, 999} with any group. The SSN validator now reports
// an ITIN, a 9xx area with a group in 50-65, 70-88, 90-92 or 94-99, so a 900 or 999 area with such a
// group re-detected: the issue measured 52-77 of 300 synthetic replacements re-detected once the area
// veto was lifted (#669 is the class: a "redacted" document that still reports the value it redacted).

// issuedAsSSN and issuedAsITIN restate the two issuers' rules here, independent of the validator, so
// this test cannot share a wrong belief with the code it checks.
func issuedAsSSN(d string) bool {
	area := d[:3]
	return area != "000" && area != "666" && area < "900" && d[3:5] != "00" && d[5:] != "0000"
}

func issuedAsITIN(d string) bool {
	if d[0] != '9' {
		return false
	}
	g := int(d[3]-'0')*10 + int(d[4]-'0')
	return (g >= 50 && g <= 65) || (g >= 70 && g <= 88) || (g >= 90 && g <= 92) || (g >= 94 && g <= 99)
}

func TestSyntheticSSNIsNeitherAnSSNNorAnITIN(t *testing.T) {
	v := ssn.NewValidator()
	areas := map[string]int{}
	nineGroups := map[string]bool{}

	for i := 0; i < 10000; i++ {
		out, err := Synthetic("130-07-5728", "SSN")
		if err != nil {
			t.Fatalf("Synthetic: %v", err)
		}
		digits := strings.ReplaceAll(out, "-", "")
		if len(out) != 11 || len(digits) != 9 || out[3] != '-' || out[6] != '-' {
			t.Fatalf("Synthetic(130-07-5728) = %q, want the XXX-XX-XXXX shape kept", out)
		}
		if issuedAsSSN(digits) {
			t.Fatalf("Synthetic produced %q, which is an issuable SSN", out)
		}
		if issuedAsITIN(digits) {
			t.Fatalf("Synthetic produced %q, which is an ITIN: a 9xx area with an ITIN group", out)
		}
		area := digits[:3]
		switch {
		case area == "000" || area == "666":
			areas[area]++
		case area[0] == '9':
			areas["9xx"]++
			nineGroups[digits[3:5]] = true
		default:
			t.Fatalf("Synthetic produced %q, whose area is outside {000, 666, 9xx}", out)
		}

		// What a user does with a redacted document: scan it again. Under the strongest labels
		// either type reads, the validator reports nothing.
		if i < 2000 {
			for _, line := range []string{"SSN: " + out, "ITIN: " + out, "ITIN: " + digits} {
				ms, err := v.ValidateContent(line, "redacted.txt")
				if err != nil {
					t.Fatalf("ValidateContent: %v", err)
				}
				if len(ms) != 0 {
					t.Fatalf("re-scanning %q reported %s %.0f", line, ms[0].Type, ms[0].Confidence)
				}
			}
		}
	}

	// Non-vacuity: every branch of the generator was drawn, so each was checked.
	for _, k := range []string{"000", "666", "9xx"} {
		if areas[k] < 1000 {
			t.Errorf("area %s drawn %d times in 10,000; the generator no longer covers it", k, areas[k])
		}
	}
	if len(nineGroups) != 49 {
		t.Errorf("a 9xx area was drawn with %d distinct groups, want all 49 of 01-49", len(nineGroups))
	}
}

// TestTheTestsIssuerRulesAgreeWithTheValidator keeps the two restatements above honest: the issued
// values they accept must be reported, or the gate above would pass vacuously.
func TestTheTestsIssuerRulesAgreeWithTheValidator(t *testing.T) {
	v := ssn.NewValidator()
	for _, tc := range []struct {
		value, typ string
		ssn, itin  bool
	}{
		{"212-70-3456", "SSN", true, false},
		{"912-70-3456", "ITIN", false, true},
		{"912-40-3456", "", false, false},
		{"666-70-3456", "", false, false},
	} {
		d := strings.ReplaceAll(tc.value, "-", "")
		if issuedAsSSN(d) != tc.ssn || issuedAsITIN(d) != tc.itin {
			t.Errorf("%s: issuedAsSSN=%v issuedAsITIN=%v, want %v %v", tc.value, issuedAsSSN(d),
				issuedAsITIN(d), tc.ssn, tc.itin)
		}
		ms, err := v.ValidateContent("SSN: "+tc.value, "x.txt")
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(ms) == 1 {
			got = ms[0].Type
		}
		if got != tc.typ {
			t.Errorf("SSN: %s reported %q, want %q", tc.value, got, tc.typ)
		}
	}
}
