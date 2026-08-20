// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

import "testing"

// The discriminator that makes a previous-line label window safe. Both directions are
// asserted in one table, because the whole difficulty is that the two shapes are
// indistinguishable on length, keyword presence and digit absence.
func TestLooksLikeFieldLabel(t *testing.T) {
	dl := []string{"driver", "license", "licence", "dl", "dmv", "driver's license"}
	pp := []string{"passport"}
	ins := []string{"member", "insurance", "policy", "subscriber"}

	cases := []struct {
		line string
		kws  []string
		want bool
		why  string
	}{
		// Real form layouts.
		{"Driver's License Number", dl, true, "bare label, all label vocabulary"},
		{"Field: Passport Number", pp, true, "the shape from the issue"},
		{"Passport Number:", pp, true, "trailing colon"},
		{"Member ID", ins, true, "two-word label"},
		{"MEMBER ID", ins, true, "upper case"},
		{"  Member ID  ", ins, true, "surrounding whitespace"},
		{"Insurance Member Identification", ins, true, "long-form label"},
		{"Member ID (primary)", ins, true, "parenthesised qualifier"},
		{"ID Number (2 of 3)", ins, false, "no keyword of this validator's own"},

		// Prose that mentions the keyword. These are the false positives a naive
		// previous-line keyword check admits.
		{"Please renew your driver's license soon.", dl, false, "terminal period, and non-label words"},
		{"Please renew your driver's license soon", dl, false, "non-label words even without the period"},
		{"Your passport will expire next year.", pp, false, "prose"},
		{"Did you bring your passport?", pp, false, "question mark"},
		{"Send the member the insurance packet today", ins, false, "prose with two keywords"},

		// Not labels at all.
		{"", dl, false, "empty"},
		{"   ", dl, false, "whitespace only"},
		{"D12345678901234", dl, false, "a value, no keyword"},
		{"Marcus Whitfield,W9998887776,ok", ins, false, "a data row"},
		{"This line is far too long to be a bare form field label for anything", dl, false, "over the length bound"},
	}

	for _, tc := range cases {
		if got := LooksLikeFieldLabel(tc.line, tc.kws); got != tc.want {
			t.Errorf("LooksLikeFieldLabel(%q) = %v, want %v (%s)", tc.line, got, tc.want, tc.why)
		}
	}
}

// A data row must never qualify, or a label window would let one row vouch for the next.
func TestFieldLabelRejectsDataRows(t *testing.T) {
	ins := []string{"member", "insurance"}
	for _, row := range []string{
		"member_id,policy_id,group_id",       // a CSV HEADER is handled by tabular, not here
		"W9998887776,P1234567890,G987654321", // a data row
		"member 449871234567",                // label plus a value on the same line
	} {
		if LooksLikeFieldLabel(row, ins) && hasDigit(row) {
			t.Errorf("LooksLikeFieldLabel(%q) = true; a line carrying values must not open a "+
				"label window for the NEXT line", row)
		}
	}
}
