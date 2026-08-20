// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import "testing"

// DRIVERS_LICENSE is label-gated — a driver's licence has no checksum, so context is the only evidence — and the keyword search stops at the newline. In a
// CSV export the label IS the header row, so a drivers_license column produced NO finding while
// the identical value written inline is reported. An unreported value is never handed to
// the redactor, so the redacted copy of such an export still held the value in cleartext.
//
// PASSPORT and SSN already consume tabular.HeaderAt; this is the same mechanism for the
// remaining label-gated types. Checksum-bearing types do not need it: CREDIT_CARD reports
// VISA 100 from a CSV column with no inline label, because Luhn stands on the value.

func hdrDetect(t *testing.T, content string) map[string]float64 {
	t.Helper()
	v := NewValidator()
	ms, err := v.ValidateContent(content, "t.csv")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	out := make(map[string]float64, len(ms))
	for _, m := range ms {
		if c, seen := out[m.Text]; !seen || m.Confidence > c {
			out[m.Text] = m.Confidence
		}
	}
	return out
}

func TestColumnHeaderAdmitsValues(t *testing.T) {
	got := hdrDetect(t, "name,drivers_license,notes\nMarcus Whitfield,D12345678901234,ok\nElena Papadopoulos,S98765432109876,ok\n")
	for _, want := range []string{"D12345678901234", "S98765432109876"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q in a drivers_license column was not reported; the label is the header row, "+
				"and an unreported value is never redacted (got %v)", want, got)
		}
	}
}

// The header must vouch for its OWN column only. Row-level admission is deliberately
// permissive so candidates can be found at all, so without a per-column check an
// unlabelled column's values ride in on a sibling's header. Measured: the two routing_number values were reported as licences at 40 purely because the row had been admitted for the licence column.
func TestColumnHeaderDoesNotVouchAcrossColumns(t *testing.T) {
	got := hdrDetect(t, "name,drivers_license,routing_number\nMarcus Whitfield,D12345678901234,121000248\n")
	if _, ok := got["D12345678901234"]; !ok {
		t.Fatal("the labelled column value was not reported, so this test cannot detect bleed")
	}
	for _, leak := range []string{"121000248"} {
		if c, ok := got[leak]; ok {
			t.Errorf("%q from an unlabelled column was reported at %.0f — a header must not "+
				"lend its standing to another column", leak, c)
		}
	}
}

// Non-tabular documents must be untouched.
func TestNonTabularBehaviourIsUnchanged(t *testing.T) {
	if got := hdrDetect(t, "Driver's License Number: D12345678901234\n"); len(got) == 0 {
		t.Error("an inline-labelled value stopped being reported")
	}
	if got := hdrDetect(t, "D12345678901234"+"\n"); len(got) != 0 {
		t.Errorf("a bare unlabelled value was reported %v; context is the only evidence here, "+
			"so this must stay silent", got)
	}
	if got := hdrDetect(t, "col_a\n"+"D12345678901234"+"\n"); len(got) != 0 {
		t.Errorf("a two-line file with a NON-label first line was admitted: %v. neither mechanism should fire: tabular.Analyze needs >=3 fields, and "+
			"the label window needs a bare field LABEL, which \"col_a\" is not", got)
	}
}
