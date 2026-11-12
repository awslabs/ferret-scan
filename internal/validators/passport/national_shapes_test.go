// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strconv"
	"strings"
	"testing"
)

// #888 Part 3: the German digit-second and current-Canadian shapes, the German
// MRZ issuing-state code "D<<", and the guards every bucket must pass.

// TestNationalShapesReportedBehindALabel: each national shape is reported, in
// its own bucket, wherever a passport label vouches for it.
func TestNationalShapesReportedBehindALabel(t *testing.T) {
	cases := []struct {
		name, content, text, bucket string
	}{
		{"DE form label", "Passport Number: C1234567K\n", "C1234567K", "Germany"},
		{"DE prose", "my passport no is C1234567K thanks\n", "C1234567K", "Germany"},
		{"DE specimen with a 0", "Passport Number: C01X00T47\n", "C01X00T47", "Germany"},
		{"DE label above", "Passport Number\nC1234567K\n", "C1234567K", "Germany"},
		{"DE lowercase", "Passport Number: c1234567k\n", "c1234567k", "Germany"},
		{"CA current form label", "Passport Number: R123456KX\n", "R123456KX", "CanadaCurrent"},
		{"CA current CSV column", "name,passport_number,country\nB. Roe,A100001BC,CA\n", "A100001BC", "CanadaCurrent"},
		{"DE CSV column", "name,passport_number,country\nA. Roe,C1234567K,DE\n", "C1234567K", "Germany"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := findText(scanPassport(t, tc.content), tc.text)
			if !ok {
				t.Fatalf("%q not reported in %q", tc.text, tc.content)
			}
			if got := m.Metadata["country"]; got != tc.bucket {
				t.Errorf("%q bucket = %v, want %s", tc.text, got, tc.bucket)
			}
			if m.Confidence < 85 {
				t.Errorf("%q confidence %.1f, want >= 85", tc.text, m.Confidence)
			}
		})
	}
	// Control: a German number with a letter second is the EU shape, as on main.
	if m, ok := findText(scanPassport(t, "Passport Number: CF1234567\n"), "CF1234567"); !ok || m.Metadata["country"] != "EU" {
		t.Errorf("CF1234567 should stay the EU bucket, got %v %v", ok, m.Metadata["country"])
	}
}

// TestNationalShapeDecoysStayUnreported: the #888 national decoys, each a
// national-shaped ID next to the word "passport" but not behind a label. With
// only the existing context rules 12 of 12 reported at 77.5-100.
func TestNationalShapeDecoysStayUnreported(t *testing.T) {
	decoys := []string{
		"Passport renewal invoice 24FR00317 paid in full.",
		"passport office purchase 25AB12345 shipped",
		"Passport photo batch 23PH48207 printed today.",
		"Passport application ref 26CA90412 received.",
		"Travel and visa desk: case 22VS40981 for the passport team",
		"passport kiosk S482071US back online",
		"passport-svc ticket R482071CS escalated to tier 2",
		"Passport week 2026: room K482071TZ booked for the international team",
		"passport scanner model L1024N160 firmware update",
		"passport printer part M2T48K9Z1 replaced",
		"passport lounge wifi code H4KT29XN7",
		"passport API build C7JK2M9X4 promoted",
		// A label after the value is not covered, as for mixed case.
		"C1234567K (passport number)",
		// France is deferred: no primary source for the layout.
		"Passport Number: 12CF34567",
	}
	for _, d := range decoys {
		if got := scanPassport(t, d+"\n"); len(got) != 0 {
			t.Errorf("%q reported %q (%v, %.1f)", d, got[0].Text, got[0].Metadata["country"], got[0].Confidence)
		}
	}
}

// TestGermanCanadaOverlapRule pins the one documented overlap between buckets:
// a letter + 6 digits + 2 letters whose letters are all German ones fits both
// the current-Canadian and the German shape. The current-Canadian bucket owns it,
// and the score is the same whichever pattern is applied first.
func TestGermanCanadaOverlapRule(t *testing.T) {
	const both = "R123456KX"
	if !reCanadaCurrentPassport.MatchString(both) || !isGermanPassport(both) {
		t.Fatalf("precondition: %s no longer fits both shapes, so this test pins nothing", both)
	}
	v := NewValidator()
	if got := v.determineCountry(both); got != "CanadaCurrent" {
		t.Errorf("determineCountry(%s) = %q, want CanadaCurrent", both, got)
	}
	cGermany, _ := v.CalculateConfidence(both + ":Germany")
	cCanada, _ := v.CalculateConfidence(both + ":CanadaCurrent")
	if cGermany != cCanada {
		t.Errorf("score depends on the claiming bucket: Germany %.1f, CanadaCurrent %.1f", cGermany, cCanada)
	}

	content := "Passport Number: " + both + "\n"
	want := scanPassport(t, content)
	if len(want) != 1 || want[0].Metadata["country"] != "CanadaCurrent" {
		t.Fatalf("want one CanadaCurrent finding, got %v", want)
	}
	// Reverse the two national buckets: same single finding, same score.
	v2 := NewValidator()
	order := append([]string{}, v2.patternOrder...)
	for i, name := range order {
		switch name {
		case "CanadaCurrent":
			order[i] = "Germany"
		case "Germany":
			order[i] = "CanadaCurrent"
		}
	}
	v2.patternOrder = order
	got, err := v2.ValidateContent(content, "t.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Metadata["country"] != want[0].Metadata["country"] || got[0].Confidence != want[0].Confidence {
		t.Errorf("reversed order: got %v, want %v", got, want)
	}
}

// TestEveryBucketHasItsOwnScoringCase is the scoring-case guard: every bucket's
// exemplar must be scored by an arm of CalculateConfidence that checks its
// format, and a value of another shape must fail that check. A bucket that fell
// through the switch scored a flat 60 whatever the value.
func TestEveryBucketHasItsOwnScoringCase(t *testing.T) {
	v := NewValidator()
	const offShape = "Q<<<<<<<<"
	for _, name := range v.patternOrder {
		for _, s := range caseExemplars[name].upper {
			if _, checks := v.CalculateConfidence(s + ":" + name); !checks["format"] {
				t.Errorf("%s: exemplar %q fails its own format check", name, s)
			}
		}
		if name == "MRZ_TD3_L2" {
			continue // its gate is mrzLine2ChecksValid, applied before scoring
		}
		if _, checks := v.CalculateConfidence(offShape + ":" + name); checks["format"] {
			t.Errorf("%s: %q passes the format check, so the bucket has no scoring case of its own", name, offShape)
		}
	}
}

// buildMRZLine2 builds a synthetic TD3 line 2 whose five check digits verify.
func buildMRZLine2(doc, state, dob, sex, exp string) string {
	doc = (doc + strings.Repeat("<", 9))[:9]
	personal := strings.Repeat("<", 14)
	d := func(s string) string { return strconv.Itoa(mrzCheckDigit(s)) }
	body := doc + d(doc) + state + dob + d(dob) + sex + exp + d(exp) + personal + d(personal)
	return body + d(doc+d(doc)+dob+d(dob)+exp+d(exp)+personal+d(personal))
}

// TestGermanMRZIsReportedWhole: a German TD3 MRZ ("D<<" as issuing state) is
// reported on both lines, each as one whole-line span, which is what the
// redactor masks. On main line 1 (the holder's name) matched nothing and stayed
// in clear while line 2 was masked, and line 2 scored 75 where FRA's scored 85.
func TestGermanMRZIsReportedWhole(t *testing.T) {
	line1 := "P<D<<ROE<<JANE<ALICE" + strings.Repeat("<", 24)
	if len(line1) != 44 {
		t.Fatalf("line 1 is %d chars", len(line1))
	}
	de := buildMRZLine2("C1234567K", "D<<", "900101", "F", "300101")
	fr := buildMRZLine2("C1234567K", "FRA", "900101", "F", "300101")
	if !mrzLine2ChecksValid(de) || !mrzLine2ChecksValid(fr) {
		t.Fatal("fixture line 2 does not verify")
	}

	got := scanPassport(t, line1+"\n"+de+"\n")
	m1, ok1 := findText(got, line1)
	m2, ok2 := findText(got, de)
	if !ok1 || !ok2 || len(got) != 2 {
		t.Fatalf("want both whole lines reported, got %d findings: %v", len(got), got)
	}
	if m1.Metadata["country"] != "MRZ_TD3" || m2.Metadata["country"] != "MRZ_TD3_L2" {
		t.Errorf("buckets %v / %v", m1.Metadata["country"], m2.Metadata["country"])
	}

	frLine2, ok := findText(scanPassport(t, fr+"\n"), fr)
	if !ok || frLine2.Confidence != m2.Confidence {
		t.Errorf("German line 2 scores %.1f, FRA's %.1f: D<< should earn the valid-code credit", m2.Confidence, frLine2.Confidence)
	}
	frLine1 := strings.Replace(line1, "D<<", "FRA", 1)
	if m, ok := findText(scanPassport(t, frLine1+"\n"), frLine1); !ok || m.Confidence != m1.Confidence {
		t.Errorf("German line 1 scores %.1f, FRA's %v", m1.Confidence, m)
	}

	// The German national number inside line 2 is not a second finding.
	if _, dup := findText(got, "C1234567K"); dup {
		t.Error("C1234567K reported apart from its line 2")
	}
}

// TestTD1AndTD2AreNotPassports: an identity-card MRZ (TD1 3 x 30, TD2 2 x 36,
// codes I, A, C) is not a passport; the "D<<" code must not widen PASSPORT onto
// it. Its owner is the national-ID work (#888 names it).
func TestTD1AndTD2AreNotPassports(t *testing.T) {
	for _, s := range []string{
		"IDD<<C1234567K0<<<<<<<<<<<<<<<\n9001011F3001019D<<<<<<<<<<<<6\nROE<<JANE<ALICE<<<<<<<<<<<<<<<",
		"IDD<<ROE<<JANE<ALICE<<<<<<<<<<<<<<<<\nC1234567K0D<<9001011F3001019<<<<<<<<",
	} {
		if got := scanPassport(t, s+"\n"); len(got) != 0 {
			t.Errorf("identity-card MRZ reported as PASSPORT: %q", got[0].Text)
		}
	}
}
