// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"strings"
	"testing"
)

// MEDICAL_ID is label-gated: a member ID has no checksum, so context is the only
// evidence it is one. The keyword search stops at the newline, and in a CSV export the
// label IS the header row — so a member_id column produced NO finding while the
// identical value written inline as "Member ID: W9998887776" is reported.
//
// An unreported value is never handed to the redactor. Measured on a
// name,member_id,drivers_license,routing_number export before this: the redacted copy
// still held every member ID and licence in cleartext, at exit 0, in a file the tool
// reported as successfully redacted.
//
// PASSPORT and SSN already consume tabular.HeaderAt; this is the same mechanism for the
// remaining label-gated types. Checksum-bearing types do not need it — CREDIT_CARD
// reports VISA 100 from a CSV column with no inline label at all, because Luhn stands on
// the value.

func detect(t *testing.T, content string) map[string]float64 {
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

func TestColumnHeaderAdmitsMemberIDs(t *testing.T) {
	got := detect(t, "name,member_id,notes\nMarcus Whitfield,W9998887776,ok\nElena Papadopoulos,W1112223334,ok\n")
	for _, want := range []string{"W9998887776", "W1112223334"} {
		if _, ok := got[want]; !ok {
			t.Errorf("member ID %q in a member_id column was not reported; the label is the "+
				"header row, and an unreported value is never redacted (got %v)", want, got)
		}
	}
}

// The header must vouch for its OWN column only. Row-level admission is deliberately
// permissive so candidates can be found at all, so without a per-column check an
// unlabelled column's values ride in on a sibling's header.
func TestColumnHeaderDoesNotVouchAcrossColumns(t *testing.T) {
	got := detect(t, "name,member_id,internal_notes,order_ref\n"+
		"Marcus Whitfield,W9998887776,ABCD12345678,XY9876543210\n")

	if _, ok := got["W9998887776"]; !ok {
		t.Fatal("the member_id column value was not reported, so this test cannot detect bleed")
	}
	for _, leak := range []string{"ABCD12345678", "XY9876543210"} {
		if c, ok := got[leak]; ok {
			t.Errorf("%q from an unlabelled column was reported at %.0f — the member_id header "+
				"must not lend insurance context to another column", leak, c)
		}
	}
}

// Non-tabular documents must be untouched: tabular.Analyze is conservative, and an
// inline label is still the ordinary path.
func TestNonTabularBehaviourIsUnchanged(t *testing.T) {
	if got := detect(t, "Member ID: W9998887776 on file\n"); len(got) == 0 {
		t.Error("an inline-labelled member ID stopped being reported")
	}
	if got := detect(t, "W9998887776\n"); len(got) != 0 {
		t.Errorf("a bare unlabelled value was reported %v; context is the only evidence a "+
			"member ID is one, so this must stay silent", got)
	}
	// A header-shaped first line that is NOT a table (too few fields) must not admit.
	if got := detect(t, "member_id\nW9998887776\n"); len(got) != 0 {
		t.Errorf("a two-line non-table was treated as tabular: %v. tabular.Analyze requires "+
			">=3 fields and a consistent delimiter precisely so prose is not reinterpreted", got)
	}
}

// The header row itself is not a value-bearing line.
func TestHeaderRowIsNotScannedAsData(t *testing.T) {
	got := detect(t, "member_id,policy_id,group_id\nW9998887776,P1234567890,G9876543210\n")
	for text := range got {
		if strings.Contains(text, "_id") {
			t.Errorf("a header cell %q was reported as a value", text)
		}
	}
}
