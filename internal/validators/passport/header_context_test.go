// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	stdctx "context"
	"strings"
	"testing"
)

func scanContent(t *testing.T, content string) int {
	t.Helper()
	v := NewValidator()
	m, err := v.ValidateContentCtx(stdctx.Background(), content, "/test/export.csv")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	return len(m)
}

// TestCSVHeaderValidatesItsColumn is the leak gate.
//
// PASSPORT is label-GATED — it reports nothing without a nearby label — and the
// label search stops at the newline. In a CSV export the only label IS the header
// row, so before this change the whole file scanned as unlabelled values and
// produced NOTHING, while the identical text written inline scored HIGH.
//
// An unreported value is never handed to the redactor, so the redacted output of
// such a CSV still contained every passport number in cleartext. Measured on the
// pre-change binary: 2 cleartext passport numbers survived --enable-redaction (and
// one column was mislabelled SSN-REDACTED); after, 0 survive.
//
// The row count matters: the fix must scale with the file, not just fix row one.
func TestCSVHeaderValidatesItsColumn(t *testing.T) {
	content := strings.Join([]string{
		"name,email,passport_number,country",
		"Jane,jane.smith@acmecorp.io,987654321,US",
		"Bob,bob.jones@acmecorp.io,512345678,GB",
		"Amy,amy.lee@acmecorp.io,512345671,CA",
		"Sam,sam.roe@acmecorp.io,987654322,AU",
	}, "\n") + "\n"

	if got := scanContent(t, content); got != 4 {
		t.Errorf("got %d findings, want 4 (one per data row) — the header names the "+
			"column, so every value in it is labelled. A fix that only reaches the first "+
			"data row leaves the rest of the export leaking.", got)
	}
}

// TestHeaderContextIsSuppressionSafe is the property that makes this shippable.
//
// The header can only ADD context, never withhold it, so no edit to the header can
// reduce a finding below what the pre-change code reported. That matters because
// the header is attacker-influenceable in a submitted document: if renaming a
// column could delete a finding, this fix would convert a recall bug into a
// suppression oracle, which is strictly worse than the bug.
//
// The parent behavior for every header below is 0 findings (no label on the value's
// line), so the assertion is: never fewer than 0, and never fewer for a
// "suspicious" header than for a plain one.
func TestHeaderContextIsSuppressionSafe(t *testing.T) {
	// Headers that DO name a passport column: must validate, including when they
	// also carry words a naive negative-keyword check would veto on.
	validating := []string{
		"passport_number",
		"passport_test",
		"example_passport",
		"fake_passport",
		"sample_passport_no",
	}
	for _, hdr := range validating {
		content := "name," + hdr + ",country\nJane,987654321,US\nBob,512345678,GB\n"
		if got := scanContent(t, content); got != 2 {
			t.Errorf("header %q: got %d findings, want 2 — a header that names a passport "+
				"column must validate its values. Vetoing on 'test'/'example'/'fake' in the "+
				"HEADER would let a one-word column rename hide real passport numbers.",
				hdr, got)
		}
	}

	// Headers that do NOT name a passport column: back to baseline, never below.
	nonValidating := []string{"sample", "order", "document_number_internal", "xyz", "value"}
	for _, hdr := range nonValidating {
		content := "name," + hdr + ",country\nJane,987654321,US\nBob,512345678,GB\n"
		if got := scanContent(t, content); got != 0 {
			t.Errorf("header %q: got %d findings, want 0 (unchanged from the pre-change "+
				"baseline) — an unrelated header must neither validate nor suppress", hdr, got)
		}
	}
}

// TestNonTabularContentIsUnchanged pins the blast radius. Anything the table
// detector rejects must behave exactly as before, because this change is only
// allowed to affect delimited data.
func TestNonTabularContentIsUnchanged(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"inline label still works", "Passport Number: 987654321\n", 1},
		{"unlabelled bare number still ignored", "987654321\n", 0},
		{"prose with commas is not a table", "The passport, issued in 2019, was 987654321.\n" +
			"It expired, eventually, in 2024.\nNo action, please, is needed.\n", 1},
		{"two-field lines are not a table", "Smith, 987654321\nDoe, 512345678\nRoe, 512345671\n", 0},
		{"ragged rows are not a table", "a,b,passport\n987654321\n1,2\n3,4,5,6,7\n", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanContent(t, tc.content); got != tc.want {
				t.Errorf("got %d findings, want %d\n  content: %q", got, tc.want, tc.content)
			}
		})
	}
}

// TestHeaderRowIsNotScannedAsData guards an obvious own-goal: the header row holds
// labels, not values, so a number appearing in a header cell must not be reported
// as a value in its own column.
func TestHeaderRowIsNotScannedAsData(t *testing.T) {
	// A header whose cell text happens to contain a passport-shaped number.
	content := "name,passport_987654321,country\nJane,512345678,US\nBob,512345671,GB\n"
	got := scanContent(t, content)
	// The two data-row values are legitimate findings; the header's number is not.
	if got != 2 {
		t.Errorf("got %d findings, want 2 (the two data rows only; the header cell is a "+
			"label, not a value)", got)
	}
}

// TestQuotedDelimiterKeepsColumnAlignment is the failure mode most likely to
// mis-map a real export: a quoted field CONTAINING the delimiter. Real airport and
// geo exports carry "lat, long" in one column, and splitting on that comma would
// shift every later column by one — attaching the wrong header to the passport
// value, or attaching "passport" to something else.
func TestQuotedDelimiterKeepsColumnAlignment(t *testing.T) {
	content := strings.Join([]string{
		"ident,coordinates,passport_number",
		"KSEA,\"47.449, -122.309\",987654321",
		"KPDX,\"45.588, -122.597\",512345678",
	}, "\n") + "\n"

	if got := scanContent(t, content); got != 2 {
		t.Errorf("got %d findings, want 2 — the comma inside the quoted coordinate must "+
			"not split the row, or the passport column is misidentified", got)
	}
}

// TestManyColumnsStaysLinear guards the performance contract. The column lookup is
// a binary search over per-line bounds computed once per line, so a wide row with
// many matches must not reintroduce the O(matches x lineLen) rescan this repo has
// already had to fix elsewhere.
//
// Carries a non-vacuity floor: a timing assertion means nothing if the scan
// stopped finding anything.
func TestManyColumnsStaysLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guard skipped in -short mode")
	}

	build := func(cols int) string {
		hdr := make([]string, cols)
		row := make([]string, cols)
		for i := range hdr {
			hdr[i] = "passport_number"
			row[i] = "98765432" + string(rune('0'+i%10))
		}
		return strings.Join(hdr, ",") + "\n" + strings.Join(row, ",") + "\n"
	}

	small := scanContent(t, build(200))
	large := scanContent(t, build(800))
	if small == 0 || large == 0 {
		t.Fatalf("non-vacuity: got %d and %d findings — a wide row of labelled passport "+
			"columns must produce findings, or the shape below measures nothing", small, large)
	}
	if large <= small {
		t.Errorf("4x the columns produced %d findings vs %d — the count must grow with "+
			"the row, otherwise per-match cost is not being exercised", large, small)
	}
}
