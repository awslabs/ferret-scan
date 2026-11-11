// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"testing"
)

// #939: a nine-digit value whose own context says what else it is read SSN at HIGH. These tests
// use only ValidateContent and symbols the parent commit has, so they run unchanged against it,
// where the byte-count and passport-label rows fail and the controls pass.

// wantOtherMeaningCeiling is otherMeaningCeiling, spelled through the constant it is defined as so
// this file compiles against the parent commit. TestOtherMeaningCeilingIsTheHeaderCap pins it.
const wantOtherMeaningCeiling = contradictingHeaderCap

// ssnFindings returns the SSN findings for value on content.
func ssnFindings(t *testing.T, content, value string) []float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []float64
	for _, m := range matches {
		if m.Type == "SSN" && m.Text == value {
			got = append(got, m.Confidence)
		}
	}
	return got
}

// ssnCeiling returns the confidence ceiling the single SSN finding on content publishes, or -1.
func ssnCeiling(t *testing.T, content string) float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches on %q, want 1", len(matches), content)
	}
	if c, ok := matches[0].Metadata[confidenceCeilingKey].(float64); ok {
		return c
	}
	return -1
}

// TestAByteCountIsAQuantityNotAnSSN holds a bare nine-digit run followed by a byte unit at the
// ceiling. It is reported, never dropped, so the redactor still covers it.
func TestAByteCountIsAQuantityNotAnSSN(t *testing.T) {
	cases := []struct {
		name, line, value string
	}{
		// docs/reference/quotas-and-limits.md:262 on main, verbatim: a pipe table, so the line
		// was tabular, boosted and never capped.
		{"pipe-table row, bytes", "| `file too large: <n> bytes (max: 104857600 bytes)` | Plain-text " +
			"preprocessor (`internal/preprocessors/plaintext_preprocessor.go`) | As above |", "104857600"},
		// docs/COVERAGE_DISCLOSURE.md:172 on main, verbatim.
		{"pipe-table row, -byte", "| the 200 MB **per-container** byte budget | `embedded part \"big.bin\" " +
			"was not examined: would exceed the 209715200-byte total embedded extraction budget for this " +
			"document` |", "209715200"},
		{"comma row, B", "limit,104857600 B,per file,total", "104857600"},
		{"comma row, KiB", "cache,104857600 KiB,per host,total", "104857600"},
		{"tab row, Bytes", "max\t104857600 Bytes\tper upload", "104857600"},
		{"a keyword does not lift a quantity", "| SSN | 452119384 bytes | payroll |", "452119384"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ssnFindings(t, tc.line, tc.value)
			if len(got) != 1 {
				t.Fatalf("%s reported %d times (%v), want once: a quantity is demoted, never dropped",
					tc.value, len(got), got)
			}
			if got[0] > wantOtherMeaningCeiling {
				t.Errorf("%s reported at %v, want at most the ceiling %v", tc.value, got[0], wantOtherMeaningCeiling)
			}
		})
	}
}

// TestTheQuantityCeilingIsPublished: the bridge raises confidence after this validator returns
// (tabular_boost is +20 for a CSV), so the cap holds only if it is published, and a byte count is
// marked whether or not it was above the ceiling here.
func TestTheQuantityCeilingIsPublished(t *testing.T) {
	for _, line := range []string{
		"limit,104857600 B,per file,total", // 95 before the cap
		"max 104857600 bytes allowed",      // 50, already below it
	} {
		if got := ssnCeiling(t, line); got != wantOtherMeaningCeiling {
			t.Errorf("%q published %s = %v, want %v", line, confidenceCeilingKey, got, wantOtherMeaningCeiling)
		}
	}
}

// TestAQuantityRuleLeavesOtherValuesAlone: the unit must follow the value, end at a word
// boundary, and every occurrence of the value on the line must be one.
func TestAQuantityRuleLeavesOtherValuesAlone(t *testing.T) {
	cases := []struct {
		name, line, value string
	}{
		{"a labelled SSN in a pipe table", "| SSN | 452119384 | payroll |", "452119384"},
		{"a word starting with B is not a unit", "| SSN | 452119384 Baker Street | payroll |", "452119384"},
		{"bytecode is not a unit", "| SSN | 452119384 bytecode | payroll |", "452119384"},
		{"the same value once bare", "| SSN | 452119384 | 452119384 bytes |", "452119384"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ssnFindings(t, tc.line, tc.value)
			if len(got) == 0 {
				t.Fatalf("%s not reported", tc.value)
			}
			for _, c := range got {
				if c < 90 {
					t.Errorf("%s reported at %v, want HIGH: the quantity rule must not reach it", tc.value, c)
				}
			}
		})
	}
}

// TestAPassportLabelHoldsTheSSNReadingInLow: a value labelled as a passport number, on its line or
// by a field label above it, is not also an SSN at HIGH or MEDIUM. It is still reported.
func TestAPassportLabelHoldsTheSSNReadingInLow(t *testing.T) {
	cases := []struct {
		name, content, value string
	}{
		// internal/validators/passport/help.go:21 on main, verbatim (two commas: tabular).
		{"help text", `"UK passport: 9 digits (e.g., 512345678)",`, "512345678"},
		{"tab-separated", "Passport Number:\t512345678\tissued", "512345678"},
		{"travel document", "Travel document,512345678,issued,2019", "512345678"},
		// internal/validators/passport/validator.go:1213-1214 on main: the two-line form.
		{"label above", "\t// labelAbove ...\n\t//\tField: Passport Number\n\t//\tValue: 512345678\n", "512345678"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ssnFindings(t, tc.content, tc.value)
			if len(got) != 1 {
				t.Fatalf("got %v, want one SSN finding: the rule demotes, it never drops", got)
			}
			if got[0] > wantOtherMeaningCeiling {
				t.Errorf("SSN at %v under a passport label, want at most %v", got[0], wantOtherMeaningCeiling)
			}
		})
	}
}

// TestAPassportLabelChangesNothingBelowTheCeiling: the golden case overlap_groups_render_once's
// line 3 reads SSN 50 on main, already below the ceiling, and must read the same with no ceiling
// published (see namesAPassport).
func TestAPassportLabelChangesNothingBelowTheCeiling(t *testing.T) {
	const line = "Passport number: 512010001"
	if got := ssnFindings(t, line, "512010001"); len(got) != 1 || got[0] != 50 {
		t.Errorf("SSN %v on %q, want one finding at 50", got, line)
	}
	if c := ssnCeiling(t, line); c != -1 {
		t.Errorf("%q published %s = %v, want none", line, confidenceCeilingKey, c)
	}
}

// TestALabelThatIsNotOnlyAPassportLabelChangesNothing: an SSN keyword on the line outranks the
// passport label, and a label above that is prose, names an SSN, or names two things is not read.
func TestALabelThatIsNotOnlyAPassportLabelChangesNothing(t *testing.T) {
	if got := ssnFindings(t, "Employee SSN 452119384, passport 512345678", "452119384"); len(got) != 1 || got[0] < 90 {
		t.Errorf("SSN beside a passport mention reported at %v, want HIGH", got)
	}
	const valueLine = "\tValue: 452119384\tpayroll"
	want := ssnFindings(t, valueLine, "452119384")
	if len(want) != 1 {
		t.Fatalf("control line alone: %v", want)
	}
	for _, above := range []string{"Field: SSN", "Please renew your passport soon.", "Field: Passport or SSN"} {
		got := ssnFindings(t, above+"\n"+valueLine, "452119384")
		if len(got) != 1 || got[0] != want[0] {
			t.Errorf("under %q: %v, want %v (the line alone)", above, got, want)
		}
	}
}

// TestTheIssueControlsKeepTheirScores: the issue's own controls.
func TestTheIssueControlsKeepTheirScores(t *testing.T) {
	if got := ssnFindings(t, "SSN: 452-11-9384", "452-11-9384"); len(got) != 1 || got[0] < 90 {
		t.Errorf("SSN: 452-11-9384 reported at %v, want HIGH", got)
	}
	if got := ssnFindings(t, "SSN 452119384 on file", "452119384"); len(got) != 1 || got[0] < 90 {
		t.Errorf("SSN 452119384 reported at %v, want HIGH", got)
	}
}
