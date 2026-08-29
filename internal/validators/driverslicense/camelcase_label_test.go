// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"strings"
	"testing"
)

// #438: a licence label written the way JSON, REST payloads and ORM exports write it —
// `driversLicenseNumber` — matched NO keyword, so the DL gate never opened and the value was never
// reported. A licence that is not reported is never handed to the redactor either.
//
// The mechanism is kwmatch's whole-word rule, and it is not a bug in that rule. A keyword's words may
// concatenate ("drivers license" finds `driversLicense`), but the concatenation must equal the WHOLE
// word. Appending "Number" makes the word `driverslicensenumber`, and no keyword in the vocabulary
// reached that far: the longest DL keywords were two words. Measured at HEAD, one line per row,
// same-line and cross-line window both:
//
//	driversLicenseNumber: D1234567       0 findings
//	driverslicensenumber: D1234567       0 findings
//	drivers_license_number: D1234567     1 @ 85
//	Drivers License Number: D1234567     1 @ 95
//	driver's license number: D1234567    1 @ 95
//	driversLicense: D1234567             1 @ 65
//
// Note the fourth and fifth rows. The issue was filed against the APOSTROPHE in "driver's license",
// and that premise is wrong: the apostrophe spellings already worked, and the two forms that failed
// contain no apostrophe at all. The fix is therefore a vocabulary one — three-word keywords whose
// words concatenate to the field names the exports actually write.

// validDL is a California-format licence number. Deliberately paired with labels that carry NO state
// name: reStateName plus "number" opens the gate on its own (lineHasPositiveKeyword), which would
// make every row below pass regardless of the vocabulary.
const validDL = "D1234567"

// TestCamelCaseLicenceLabelIsFound is the regression test for the reported gap.
func TestCamelCaseLicenceLabelIsFound(t *testing.T) {
	for _, label := range []string{
		"driversLicenseNumber",
		"driverslicensenumber",
		"driverLicenseNumber",
		"drivingLicenseNumber",
		"driversLicenceNumber",
		"driverLicenceNumber",
		"driversLicenseNo", // not expected to match; see the sub-test's own guard
	} {
		t.Run(label, func(t *testing.T) {
			content := label + ": " + validDL + "\n"
			matches, err := NewValidator().ValidateContent(content, "export.json")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			// "No" is a separate abbreviation the vocabulary does not carry; it is listed here so a
			// future reader can see the boundary of what was added rather than guess at it.
			if label == "driversLicenseNo" {
				if len(matches) > 0 {
					t.Logf("%q now matches too (%d findings) — the vocabulary grew; fold this into "+
						"the table above", label, len(matches))
				}
				return
			}
			if len(matches) == 0 {
				t.Errorf("%q reported nothing. The label names the value beside it, so the licence "+
					"is neither reported nor redacted — the sink rule makes this a cleartext leak, "+
					"not a missing nice-to-have.\ncontent: %q", label, content)
			}
		})
	}
}

// TestTheSpellingsThatAlreadyWorkedStillDo.
//
// The fix ADDS keywords, and an added positive keyword can only add findings — but it can also change
// which keyword wins and therefore the confidence. These rows are the ones a regression would show up
// in first, because they are the spellings users already rely on.
func TestTheSpellingsThatAlreadyWorkedStillDo(t *testing.T) {
	for _, tc := range []struct {
		label       string
		wantAtLeast float64
	}{
		{"drivers_license_number", 85},
		{"Drivers License Number", 95},
		{"driver's license number", 95},
		{"driversLicense", 65},
		{"Driver license number", 95},
		{"dlNumber", 65},
	} {
		t.Run(tc.label, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(tc.label+": "+validDL+"\n", "f.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("%q reported nothing — this spelling worked before the fix", tc.label)
			}
			if got := matches[0].Confidence; got < tc.wantAtLeast {
				t.Errorf("%q now scores %.0f, was at least %.0f before the fix. Adding a positive "+
					"keyword must not DEMOTE a spelling that already worked.",
					tc.label, got, tc.wantAtLeast)
			}
		})
	}
}

// TestTheAddedKeywordsDoNotMatchALongerWord.
//
// The whole-word rule is the entire false-positive defence for the concatenated spelling: without it
// the widening becomes a substring search, and "drivers license number" would fire inside any longer
// token containing it. These are the shapes that would break first.
func TestTheAddedKeywordsDoNotMatchALongerWord(t *testing.T) {
	for _, label := range []string{
		"driverslicensenumbers", // trailing plural
		"xdriverslicensenumber", // leading noise
		"mydriverslicensenumberx",
		"nondriverslicensenumber",
	} {
		t.Run(label, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(label+": "+validDL+"\n", "f.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("%q reported %d findings: a longer word that merely CONTAINS the label is "+
					"not the label, and admitting it turns the concatenation match into a substring "+
					"search", label, len(matches))
			}
		})
	}
}

// TestTheCrossLineWindowGainsTheSameSpellings.
//
// driverslicense reads a label from the PREVIOUS line via kwmatch.LooksLikeFieldLabel, which is a
// second, independent sink — it had the identical gap (measured 0 findings with the camelCase label
// alone on the line above). A fix to the same-line gate does not automatically fix this one, because
// the two use different matchers (containsLabel vs keywordWord).
func TestTheCrossLineWindowGainsTheSameSpellings(t *testing.T) {
	for _, label := range []string{"driversLicenseNumber", "driverLicenseNumber", "driversLicenceNumber"} {
		t.Run(label, func(t *testing.T) {
			content := label + ":\n" + validDL + "\n"
			matches, err := NewValidator().ValidateContent(content, "export.json")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("label %q on the line ABOVE the value reported nothing, so the cross-line "+
					"window still cannot see a camelCase label.\ncontent: %q", label, content)
			}
			// Non-vacuity for the fixture itself: the value must be on its own line, or this would
			// be testing the same-line path again.
			if strings.Contains(strings.SplitN(content, "\n", 2)[0], validDL) {
				t.Fatal("fixture bug: the value is on the label line, so this is not the cross-line path")
			}
		})
	}
}

// TestAStateNameDoesNotSecretlyOpenTheGate.
//
// This is the control that makes every table above meaningful. lineHasPositiveKeyword accepts a state
// name plus "number" WITHOUT any licence keyword, so a fixture reading "California ... number" passes
// on the unfixed code and proves nothing about the vocabulary.
func TestAStateNameDoesNotSecretlyOpenTheGate(t *testing.T) {
	// A label with no licence vocabulary and no state name must stay unreported: this shows the DL
	// gate is genuinely closed without one, which is what the other tests rely on.
	matches, err := NewValidator().ValidateContent("recordNumber: "+validDL+"\n", "f.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("a bare %q label reported %d findings, so the DL gate opens without licence "+
			"vocabulary and none of the camelCase rows above prove anything", "recordNumber", len(matches))
	}
	// And with a state name plus "number" it DOES open — documenting the alternate path so a future
	// fixture author does not add a state name and read a false pass.
	withState, err := NewValidator().ValidateContent("California record number: "+validDL+"\n", "f.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(withState) == 0 {
		t.Log("the state-name + \"number\" path no longer opens the gate; if that was deliberate, " +
			"the warning in this test and in lineHasPositiveKeyword can be relaxed")
	}
}
