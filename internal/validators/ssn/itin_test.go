// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #884, Part A: the SSN validator reports an IRS ITIN under its own type.
//
// Measured on main @ 769be4e, --config /dev/null --confidence all, one line per file: every line in
// TestITINDisplayFormsReportOneITIN reported nothing (the long-form label gave PASSPORT 78 only), and
// 60 seeded ITINs gave 0/60 in each of the three display forms.

// itinGroupsFromIRS is the IRS's own statement of the 4th and 5th digits, written out here as a list
// rather than imported from isITINGroup, so the test cannot share a wrong belief with the code.
// IRS Publication 4757: 50 to 65, 70 to 88, 90 to 92, and 94 to 99.
var itinGroupsFromIRS = func() map[int]bool {
	m := map[int]bool{}
	for _, r := range [][2]int{{50, 65}, {70, 88}, {90, 92}, {94, 99}} {
		for g := r[0]; g <= r[1]; g++ {
			m[g] = true
		}
	}
	return m
}()

func scanAll(t *testing.T, v *Validator, content, path string) []detector.Match {
	t.Helper()
	matches, err := v.ValidateContent(content, path)
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	return matches
}

func describeMatches(ms []detector.Match) string {
	if len(ms) == 0 {
		return "nothing"
	}
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, fmt.Sprintf("%s %.0f %q", m.Type, m.Confidence, m.Text))
	}
	return strings.Join(parts, ", ")
}

func band(c float64) string {
	switch {
	case c >= 90:
		return "HIGH"
	case c >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// TestITINDisplayFormsReportOneITIN is the issue's first acceptance criterion: each line gives exactly
// one ITIN, HIGH when labelled and MEDIUM bare, and no SSN.
func TestITINDisplayFormsReportOneITIN(t *testing.T) {
	v := NewValidator()
	for _, tc := range []struct {
		line, value, band string
	}{
		{"ITIN: 912-70-3456", "912-70-3456", "HIGH"},
		{"ITIN: 912 70 3456", "912 70 3456", "HIGH"},
		{"Taxpayer ID: 912-70-3456", "912-70-3456", "HIGH"},
		{"SSN: 912-70-3456", "912-70-3456", "HIGH"},
		{"912-70-3456", "912-70-3456", "MEDIUM"},
		{"ITIN: 912703456", "912703456", "HIGH"},
		{"Individual Taxpayer Identification Number: 912703456", "912703456", "HIGH"},
		{"Form W-7 approved, number 912-70-3456", "912-70-3456", "HIGH"},
		{"customer_itin=912703456", "912703456", "HIGH"},
	} {
		got := scanAll(t, v, tc.line, "record.txt")
		if len(got) != 1 || got[0].Type != "ITIN" || got[0].Text != tc.value {
			t.Errorf("%q gave %s, want exactly one ITIN %q", tc.line, describeMatches(got), tc.value)
			continue
		}
		if b := band(got[0].Confidence); b != tc.band {
			t.Errorf("%q: ITIN at %.0f (%s), want %s", tc.line, got[0].Confidence, b, tc.band)
		}
		if got[0].Validator != "ssn" {
			t.Errorf("%q: validator %q, want ssn (an ITIN rides under --checks SSN)", tc.line, got[0].Validator)
		}
	}
}

// TestITINDecoysReportNothing is the second criterion, plus the form gate's two decoys: a bare
// nine-digit 9xx value with no ITIN label, and a Chilean mobile, +56 9XXXXXXXX.
func TestITINDecoysReportNothing(t *testing.T) {
	v := NewValidator()
	lines := []string{
		"912703456",                   // bare, unlabelled
		"Contacto: +56 912703456",     // a Chilean mobile; phone claims it, not this validator
		"const requestID = 912703456", // a bare 9xx run in code
		"912-40-3456",                 // group 40: not issued as an ITIN
		"912-93-3456",                 // group 93: an ATIN, out of scope
		"912-89-3456",                 // group 89: not issued
		"912-70-0000",                 // serial 0000
		"999-99-9999",                 // the 9xx repdigit
		"SSN: 912-40-3456",
		"ITIN: 912-93-3456",
		"ITIN: 912-70-0000",
		"ITIN: 999-99-9999",
		"SSN: 999-99-9999",
		"912\t70\t3456", // a tab-separated row is three numbers, not a separated ITIN
		"https://hr.invalid/people/912703456",
		"ratio 0.912703456 ITIN", // a decimal fraction's tail, whatever the line says
	}
	for i := 0; i < 10; i++ {
		v := fmt.Sprintf("987-65-432%d", i) // the SSA advertising block
		lines = append(lines, v, "SSN: "+v, "ITIN: "+v)
	}
	for _, line := range lines {
		if got := scanAll(t, v, line, "record.txt"); len(got) != 0 {
			t.Errorf("%q gave %s, want nothing", line, describeMatches(got))
		}
	}
}

// TestChileanMobilesAreNotITINs pins the form gate on the population the issue measured: accepting any
// 9xx form with an ITIN group reported 75 and 92 false findings per 200 of these. The gate reports 0.
func TestChileanMobilesAreNotITINs(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(56))
	itinShaped := 0
	for i := 0; i < 200; i++ {
		num := fmt.Sprintf("9%08d", r.Intn(100000000))
		if isITIN(num) {
			itinShaped++
		}
		line := "Contacto: +56 " + num
		if got := scanAll(t, v, line, "contacts.txt"); len(got) != 0 {
			t.Errorf("%q gave %s, want nothing: a mobile's digits are an ITIN only under an ITIN label",
				line, describeMatches(got))
		}
	}
	// Non-vacuity: the population must hold values the predicate alone accepts, or the gate is not
	// what this measures.
	if itinShaped < 50 {
		t.Fatalf("only %d of 200 mobiles pass isITIN; the sample no longer exercises the form gate", itinShaped)
	}
}

// TestIsValidSSNRejectsEveryArea900To999: an ITIN is not an SSN, so the SSN predicate still rejects
// the whole 9xx range for every group.
func TestIsValidSSNRejectsEveryArea900To999(t *testing.T) {
	v := NewValidator()
	for area := 900; area <= 999; area++ {
		for group := 1; group <= 99; group++ {
			s := fmt.Sprintf("%03d%02d3456", area, group)
			if v.isValidSSN(s) {
				t.Fatalf("isValidSSN(%s) = true; the 900-999 areas are never an SSN", s)
			}
		}
	}
}

// TestOnePredicateServesBothPaths sweeps every group through the regex path and the glued-run path,
// which used to carry two copies of the area rule.
func TestOnePredicateServesBothPaths(t *testing.T) {
	v := NewValidator()
	accepted := 0
	for g := 0; g <= 99; g++ {
		want := itinGroupsFromIRS[g]
		digits := fmt.Sprintf("912%02d3456", g)
		if got := isITIN(digits); got != want {
			t.Errorf("isITIN(%s) = %v, want %v", digits, got, want)
		}

		// The regex path, separated and labelled-bare.
		for _, line := range []string{
			fmt.Sprintf("ITIN: 912-%02d-3456", g),
			fmt.Sprintf("ITIN: %s", digits),
		} {
			got := scanAll(t, v, line, "record.txt")
			hasITIN := len(got) == 1 && got[0].Type == "ITIN"
			if hasITIN != want || (!want && len(got) != 0) {
				t.Errorf("regex path, group %02d: %q gave %s, want ITIN=%v", g, line, describeMatches(got), want)
			}
		}

		// The glued path: two adjacent Word runs extracted as one 18-digit run. Both halves must
		// pass, so the SSN half is reported only when the ITIN half is.
		line := "ITIN and SSN " + digits + "130075728"
		got := scanAll(t, v, line, "record.docx")
		var types []string
		for _, m := range got {
			types = append(types, m.Type+":"+m.Text)
		}
		wantGlued := ""
		if want {
			wantGlued = "ITIN:" + digits + ",SSN:130075728"
		}
		if strings.Join(types, ",") != wantGlued {
			t.Errorf("glued path, group %02d: %q gave %s, want %q", g, line, describeMatches(got), wantGlued)
		}
		if want {
			accepted++
		}
	}
	if accepted != 44 {
		t.Errorf("%d groups accepted; the IRS ranges hold 44", accepted)
	}
}

// TestAGluedITINHalfNeedsTheLabel: a glued half is bare digits, so it is an ITIN only under an ITIN
// label, as on the regex path. Without one the run reports what main reports.
func TestAGluedITINHalfNeedsTheLabel(t *testing.T) {
	v := NewValidator()
	if got := scanAll(t, v, "employee ids 912703456130075728 end", "record.docx"); len(got) != 0 {
		t.Errorf("unlabelled glued run gave %s, want nothing (main reports nothing: its first half is 9xx)",
			describeMatches(got))
	}
	// The SSN-only glued run is unchanged.
	got := scanAll(t, v, "employee ids 449874100130075728 end", "record.docx")
	if describeMatches(got) != `SSN 50 "449874100", SSN 50 "130075728"` {
		t.Errorf("SSN glued run gave %s, want both halves as SSN at 50", describeMatches(got))
	}
	// The advertising block is withheld on this path too.
	if got := scanAll(t, v, "ITIN 987654325130075728", "record.docx"); len(got) != 0 {
		t.Errorf("glued advertising-block half gave %s, want nothing", describeMatches(got))
	}
	// And the gate is the TYPE gate the regex path never had: a .txt never takes the glued path.
	if got := scanAll(t, v, "ITIN 912703456130075728", "record.txt"); len(got) != 0 {
		t.Errorf(".txt glued run gave %s, want nothing", describeMatches(got))
	}
}

// TestITINScoresOnTheSSNCurve: with the same context an ITIN and an SSN of the same shape score the
// same. The one difference in the curve is the area term, and that is what makes them equal.
func TestITINScoresOnTheSSNCurve(t *testing.T) {
	v := NewValidator()
	for _, ctx := range []string{
		"", "SSN: ", "Taxpayer ID: ", "Employee SSN ", "IRS form 1099 ", "payroll record ",
		"test value ", "invoice ", "Phone: ", "tracking number ",
	} {
		for _, pair := range [][2]string{
			{"912-70-3456", "212-70-3456"},
			{"912 70 3456", "212 70 3456"},
			{"912-70-1000", "212-70-1000"}, // a repeated-digit serial: penalised, never dropped
		} {
			itinLine, ssnLine := ctx+pair[0], ctx+pair[1]
			ig := scanAll(t, v, itinLine, "record.txt")
			sg := scanAll(t, v, ssnLine, "record.txt")
			if len(sg) != 1 || sg[0].Type != "SSN" {
				t.Fatalf("control %q gave %s, want one SSN", ssnLine, describeMatches(sg))
			}
			if len(ig) != 1 || ig[0].Type != "ITIN" {
				t.Errorf("%q gave %s, want one ITIN", itinLine, describeMatches(ig))
				continue
			}
			if ig[0].Confidence != sg[0].Confidence {
				t.Errorf("%q scored %.0f but the SSN %q scored %.0f; an ITIN is scored on the SSN's curve",
					itinLine, ig[0].Confidence, ssnLine, sg[0].Confidence)
			}
		}
	}
}

// TestITINKeywordsDoNotMoveAnSSN: the ITIN's labels are read only for an ITIN candidate. An SSN on a
// line that mentions an ITIN or a W-7 scores what it scores with neutral words in their place, which
// is what main does (main has no such keywords).
//
// Each line carries an SSN keyword and a negative one, so the control scores between the caps (80 or
// 65) and a stray +25 would show. A line at 100, or one capped for having no SSN keyword, would pass
// this test even if the SSN read the ITIN's keywords; measured, the first version of this test did.
func TestITINKeywordsDoNotMoveAnSSN(t *testing.T) {
	v := NewValidator()
	for _, tc := range [][2]string{
		{"ITIN SSN case 130075728", "ABCD SSN case 130075728"},
		{"W-7 SSN case 130075728", "Q-7 SSN case 130075728"},
		// "Corporate" keeps the SSN's own keywords on the line (taxpayer, identification number)
		// and removes only the ITIN's long-form label.
		{"Individual Taxpayer Identification Number test 130075728",
			"Corporate Taxpayer Identification Number test 130075728"},
	} {
		a := scanAll(t, v, tc[0], "record.txt")
		b := scanAll(t, v, tc[1], "record.txt")
		if len(b) != 1 || b[0].Confidence >= 100 || b[0].Confidence <= 60 {
			t.Fatalf("control %q gave %s; it must score strictly between the caps to test anything",
				tc[1], describeMatches(b))
		}
		if describeMatches(a) != describeMatches(b) {
			t.Errorf("%q gave %s but %q gave %s; an ITIN keyword moved an SSN", tc[0], describeMatches(a),
				tc[1], describeMatches(b))
		}
	}
}

// TestITINUnderAColumnHeader: a column headed itin labels its bare values, as a header naming an SSN
// labels its column for the SSN keywords.
func TestITINUnderAColumnHeader(t *testing.T) {
	v := NewValidator()
	csv := "name,itin,city\nAna Lopez,912703456,Boston\nBo Chen,913751234,Denver\nCy Diaz,914802468,Austin\n"
	got := scanAll(t, v, csv, "people.csv")
	if len(got) != 3 {
		t.Fatalf("itin column gave %s, want three ITINs", describeMatches(got))
	}
	for _, m := range got {
		if m.Type != "ITIN" {
			t.Errorf("itin column reported %s %q, want ITIN", m.Type, m.Text)
		}
	}
	// A column that names something else gives no label, so its bare 9xx values are not ITINs.
	other := strings.Replace(csv, "itin", "account", 1)
	if got := scanAll(t, v, other, "people.csv"); len(got) != 0 {
		t.Errorf("account column gave %s, want nothing", describeMatches(got))
	}
}

// TestALabelledITINInAURLPathIsKept: the URL veto reads only the bare form, and a bare ITIN is
// reported only under an ITIN label, which names the identifier as an SSN label does.
func TestALabelledITINInAURLPathIsKept(t *testing.T) {
	v := NewValidator()
	got := scanAll(t, v, "ITIN: https://hr.invalid/people/912703456", "record.txt")
	if len(got) != 1 || got[0].Type != "ITIN" {
		t.Errorf("labelled ITIN in a URL path gave %s, want one ITIN", describeMatches(got))
	}
	// An SSN in the same position is still vetoed: the ITIN label does not lift the SSN's veto.
	if got := scanAll(t, v, "ITIN: https://hr.invalid/people/212703456", "record.txt"); len(got) != 0 {
		t.Errorf("SSN-range value in a URL path under an ITIN label gave %s, want nothing (as main)",
			describeMatches(got))
	}
}

// TestAHyphenatedITINKeepsTheEncodedLineFloor: the canonical hyphenated ITIN is the strong shape, so
// on a line of encoded-looking numbers it keeps the MEDIUM floor a hyphenated SSN keeps.
func TestAHyphenatedITINKeepsTheEncodedLineFloor(t *testing.T) {
	v := NewValidator()
	tail := " 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16"
	ig := scanAll(t, v, "912-70-3456"+tail, "record.txt")
	sg := scanAll(t, v, "212-70-3456"+tail, "record.txt")
	if len(ig) != 1 || len(sg) != 1 || ig[0].Confidence != sg[0].Confidence || ig[0].Confidence != encodedDataStrongFloor {
		t.Errorf("encoded line: ITIN %s, SSN %s; want both at the %.0f floor", describeMatches(ig),
			describeMatches(sg), encodedDataStrongFloor)
	}
}

// TestCalculateConfidenceStillScoresAnSSN: the exported scorer keeps its SSN meaning. A 9xx value is
// an invalid SSN area there, exactly as on main (70 - 15 + 10).
func TestCalculateConfidenceStillScoresAnSSN(t *testing.T) {
	v := NewValidator()
	conf, checks := v.CalculateConfidence("912-70-3456")
	if conf != 65 || checks["valid_area"] {
		t.Errorf("CalculateConfidence(912-70-3456) = %.0f, valid_area=%v; want 65, false", conf, checks["valid_area"])
	}
	conf, checks = v.calculateConfidence("912-70-3456", true)
	if conf != 95 || !checks["valid_area"] {
		t.Errorf("calculateConfidence(912-70-3456, itin) = %.0f, valid_area=%v; want 95, true", conf, checks["valid_area"])
	}
}

func TestIsSeparatedITINForm(t *testing.T) {
	for in, want := range map[string]bool{
		"912-70-3456":  true,
		"912 70 3456":  true,
		"912703456":    false,
		"912\t70 3456": false,
		"912 70-3456":  false,
		"912-703-456":  false,
		"9a2-70-3456":  false,
		"912-70-34567": false,
	} {
		if got := isSeparatedITINForm(in); got != want {
			t.Errorf("isSeparatedITINForm(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestHelpNamesTheITIN keeps --list-checks honest: the 900-999 rule is no longer "filtered out".
func TestHelpNamesTheITIN(t *testing.T) {
	info := NewValidator().GetCheckInfo()
	if !strings.Contains(info.DetailedDescription, "ITIN") {
		t.Errorf("the SSN check's help does not mention the ITIN it now reports:\n%s", info.DetailedDescription)
	}
}
