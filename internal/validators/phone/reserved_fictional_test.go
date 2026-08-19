// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"fmt"
	"strings"
	"testing"
)

// A number in the NANP reserved fictional range 555-0100..555-0199 cannot be
// assigned to a subscriber, so it reaches nobody and is not a contact detail.
//
// It used to be reported at 100 HIGH. isTestPhoneNumber already recognized the
// range and applied confidence -= 20, but a fixed penalty is out-voted by enough
// positive context, so "Call the support desk on 415-555-0100 for help." scored
// 100 with `Not Test Number: false` and --explain called it "likely_real". The
// fix is a ceiling context cannot lift. See #364.
//
// These tests assert the CEILING, not merely a lower number: the reserved cases
// are checked with deliberately phone-heavy context, which is exactly what
// defeated the penalty.

// highestConfidence returns the top confidence among findings whose text
// contains want, and whether any such finding exists.
//
// Both return values matter. A test that only checked the confidence would pass
// against a validator that had stopped detecting the number at all — and a
// number that is not reported is also not redacted, which is the failure this
// whole area exists to avoid.
func highestConfidence(t *testing.T, content, want string) (float64, bool) {
	t.Helper()

	matches, err := NewValidator().ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}

	best, found := 0.0, false
	for _, m := range matches {
		if strings.Contains(strings.ReplaceAll(m.Text, " ", ""), strings.ReplaceAll(want, " ", "")) {
			found = true
			if m.Confidence > best {
				best = m.Confidence
			}
		}
	}
	return best, found
}

func TestReservedFictionalRangeIsCappedAtLow(t *testing.T) {
	// Every form the patterns can produce for a number in the reserved range,
	// each wrapped in the strongest phone context available — a label, the word
	// "phone", and a name — because that context is what out-voted the old
	// penalty.
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"dashed with label", "Phone: 415-555-0100 (main office contact number)", "415-555-0100"},
		{"parenthesized area code", "Contact phone (212) 555-0187 for support", "(212) 555-0187"},
		{"country code", "Call +1 415-555-0142 -- customer service phone", "555-0142"},
		{"compact ten digits", "Primary contact phone number 4155550100 on file", "4155550100"},
		{"dotted", "Phone. 415.555.0199 is the contact number", "415.555.0199"},
		{"bottom of range", "Phone: 415-555-0100 contact", "415-555-0100"},
		{"top of range", "Phone: 415-555-0199 contact", "415-555-0199"},
		// The extension forms have their own pattern (US_Extension), and
		// cleanPhoneNumber folds the extension digits into the number, which moves
		// the end of the string. reFictional555 is end-anchored, so before
		// isReservedFictionalNumber stripped the extension these were missed:
		// "(212) 555-0187 ext 4" cleans to 21255501874, ending in "74".
		{"ext marker", "Contact phone (212) 555-0187 ext 4 for the desk", "555-0187"},
		{"extension word", "Desk phone (212) 555-0187 extension 221 today", "555-0187"},
		{"x marker", "Phone contact 4155550142x99 for the office", "4155550142"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := highestConfidence(t, tc.content, tc.want)
			if !found {
				t.Fatalf("%q was not reported at all in %q -- a value that is not "+
					"reported is also not redacted; this test asserts a ceiling, not a drop",
					tc.want, tc.content)
			}
			if got > reservedFictionalCeiling {
				t.Errorf("%q scored %.0f (> ceiling %.0f) in %q -- the reserved-range "+
					"ceiling is being applied as a penalty that context can out-vote, or "+
					"not at all",
					tc.want, got, reservedFictionalCeiling, tc.content)
			}
		})
	}
}

// The ceiling must not touch assignable numbers. This is the over-veto side, and
// it is the dangerous direction: a real number pushed to LOW is a real number
// that a `--confidence medium,high` pipeline never sees.
func TestAssignableNumbersKeepTheirConfidence(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"ordinary number", "Phone: 415-267-3141 for the main office", "415-267-3141"},
		// Boundaries of the reserved block, both sides. 555-0099 and 555-0200 are
		// outside 0100..0199 and are ordinary assignable numbers.
		{"just below the block", "Phone: 415-555-0099 contact", "415-555-0099"},
		{"just above the block", "Phone: 415-555-0200 contact", "415-555-0200"},
		// A real number carrying an extension: the extension strip must not turn a
		// non-reserved number into a reserved one.
		{"real number with extension", "Desk phone (212) 867-5310 ext 4 today", "867-5310"},
		// A number whose digits merely CONTAIN 55501 away from the subscriber
		// position. reFictional555 is anchored for exactly this reason.
		{"55501 run inside other digits", "Phone: +81 3 5550 1005 contact", "555010"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := highestConfidence(t, tc.content, tc.want)
			if !found {
				t.Skipf("%q is not detected by any pattern, so the ceiling cannot "+
					"affect it either way", tc.want)
			}
			if got <= reservedFictionalCeiling {
				t.Errorf("%q scored %.0f (<= ceiling %.0f) in %q -- an assignable "+
					"number is being demoted to the reserved-range ceiling, which would "+
					"hide it from a --confidence medium,high scan",
					tc.want, got, reservedFictionalCeiling, tc.content)
			}
		})
	}
}

// Adding positive context must not raise a reserved number above the ceiling, no
// matter how much of it there is.
//
// This is the assertion the pre-existing -20 penalty fails. Run it against a
// build where the ceiling is replaced by `confidence -= 20` and the 0-keyword
// case still passes while the loaded cases do not.
func TestContextCannotLiftTheReservedCeiling(t *testing.T) {
	const number = "415-555-0100"

	// Each step adds another positive signal a real document would carry.
	escalation := []string{
		number,
		"Phone: " + number,
		"Contact phone: " + number,
		"Customer contact phone number: " + number,
		"Customer service contact phone number: " + number + " (mobile, direct line, tel)",
	}

	for i, content := range escalation {
		t.Run(fmt.Sprintf("signals_%d", i), func(t *testing.T) {
			got, found := highestConfidence(t, content, number)
			if !found {
				t.Fatalf("%q was not reported in %q", number, content)
			}
			if got > reservedFictionalCeiling {
				t.Errorf("with %d context signals %q reached %.0f (> ceiling %.0f) in %q "+
					"-- context is out-voting the ceiling, which is the defect: a constant "+
					"penalty always loses to a large enough context budget",
					i, number, got, reservedFictionalCeiling, content)
			}
		})
	}
}

// isReservedFictionalNumber is exercised directly as well, because the table
// above can only reach forms that some pattern happens to match.
func TestIsReservedFictionalNumber(t *testing.T) {
	v := NewValidator()

	reserved := []string{
		"415-555-0100", "415-555-0199", "(212) 555-0187", "+1 415 555 0142",
		"4155550100", "555-0100", "5550199", "415.555.0150",
		"(212) 555-0187 ext 4", "(212) 555-0187 extension 221", "4155550142x99",
		"415-555-0187 EXT. 12",
	}
	for _, s := range reserved {
		if !v.isReservedFictionalNumber(s) {
			t.Errorf("isReservedFictionalNumber(%q) = false, want true -- 555-0100..0199 "+
				"is the NANP reserved fictional block", s)
		}
	}

	assignable := []string{
		"415-267-3141", "415-555-0099", "415-555-0200", "415-555-1212",
		"(212) 867-5310", "+44 20 7946 0958", "2125550287", "555-0299",
		// One digit past the block in the last position.
		"415-555-0299", "415-556-0100",
	}
	for _, s := range assignable {
		if v.isReservedFictionalNumber(s) {
			t.Errorf("isReservedFictionalNumber(%q) = true, want false -- vetoing an "+
				"assignable number would hide a real contact detail", s)
		}
	}
}
