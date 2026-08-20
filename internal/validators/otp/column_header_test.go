// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import "testing"

// OTP is label-gated — a bare base32 run is far too ambiguous to report without context — and the keyword search stops at the newline. In a
// CSV export the label IS the header row, so a totp_secret column produced NO finding while
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
	got := hdrDetect(t, "name,totp_secret,notes\nMarcus Whitfield,K5CUWY3ZNRXW4Z3T,ok\nElena Papadopoulos,MFYGC4TLLBQXA5DP,ok\n")
	for _, want := range []string{"K5CUWY3ZNRXW4Z3T", "MFYGC4TLLBQXA5DP"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q in a totp_secret column was not reported; the label is the header row, "+
				"and an unreported value is never redacted (got %v)", want, got)
		}
	}
}

// The header must vouch for its OWN column only. Row-level admission is deliberately
// permissive so candidates can be found at all, so without a per-column check an
// unlabelled column's values ride in on a sibling's header. Measured: the equivalent leak was measured in driverslicense, where two routing_number values were reported as licences at 40.
func TestColumnHeaderDoesNotVouchAcrossColumns(t *testing.T) {
	got := hdrDetect(t, "user,totp_secret,internal_notes\nmarcus,K5CUWY3ZNRXW4Z3T,MFYGC4TLLBQXA5DP\n")
	if _, ok := got["K5CUWY3ZNRXW4Z3T"]; !ok {
		t.Fatal("the labelled column value was not reported, so this test cannot detect bleed")
	}
	for _, leak := range []string{"MFYGC4TLLBQXA5DP"} {
		if c, ok := got[leak]; ok {
			t.Errorf("%q from an unlabelled column was reported at %.0f — a header must not "+
				"lend its standing to another column", leak, c)
		}
	}
}

// Non-tabular documents must be untouched.
func TestNonTabularBehaviourIsUnchanged(t *testing.T) {
	if got := hdrDetect(t, "totp secret K5CUWY3ZNRXW4Z3T here\n"); len(got) == 0 {
		t.Error("an inline-labelled value stopped being reported")
	}
	if got := hdrDetect(t, "K5CUWY3ZNRXW4Z3T"+"\n"); len(got) != 0 {
		t.Errorf("a bare unlabelled value was reported %v; context is the only evidence here, "+
			"so this must stay silent", got)
	}
	if got := hdrDetect(t, "totp_secret\n"+"K5CUWY3ZNRXW4Z3T"+"\n"); len(got) != 0 {
		t.Errorf("a two-line non-table was treated as tabular: %v. tabular.Analyze requires "+
			">=3 fields and a consistent delimiter precisely so prose is not reinterpreted", got)
	}
}
