// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"strings"
	"testing"
)

// #861 (bug half): British and "driving" spellings of a licence label were missed or band-demoted,
// because the three label lists were written out by hand and had drifted apart (see vocabulary.go).
// Measured on main @ b0a9163, one label per line, `D1234567` as the value:
//
//	drivingLicence: / DrivingLicenceNo: / driversLicence: / JSON / YAML    no finding
//	Driving licence: / Driving license: / driving_licence:                  75
//	Licence No. D1234567                                                     65
//
// while every US twin scored 95.

// bestDL returns the highest-confidence DRIVERS_LICENSE finding for value in content, or -1.
func bestDL(t *testing.T, content, value string) float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "record.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	best := -1.0
	for _, m := range matches {
		if m.Type == "DRIVERS_LICENSE" && m.Text == value && m.Confidence > best {
			best = m.Confidence
		}
	}
	return best
}

// TestBritishAndDrivingKeysAreReported is the "none -> 95" row of the issue's matrix: 10 of 10
// gave no finding on main, so the value was never redacted.
func TestBritishAndDrivingKeysAreReported(t *testing.T) {
	for _, content := range []string{
		"drivingLicence: D1234567",
		"DrivingLicence: D1234567",
		"drivingLicenceNumber: D1234567",
		"DrivingLicenceNo: D1234567",
		"drivingLicense: D1234567",
		"DrivingLicenseNo: D1234567",
		"driversLicence: D1234567",
		"driverLicence: D1234567",
		`{"drivingLicenceNumber": "D1234567"}`,
		"holder:\n  drivingLicence: D1234567",
	} {
		t.Run(content, func(t *testing.T) {
			if got := bestDL(t, content+"\n", validDL); got < 90 {
				t.Errorf("%q: best DRIVERS_LICENSE confidence %.0f, want >= 90 like its US twin "+
					"(-1 = not reported, so not redacted)", content, got)
			}
		})
	}
}

// TestBritishLabelsAreNotBandDemoted is the "75 -> 95" and "65 -> 95" rows: the label was found but
// missed the label boost, so a consumer gated on HIGH did not see the value.
func TestBritishLabelsAreNotBandDemoted(t *testing.T) {
	for _, tc := range []struct{ british, usTwin string }{
		{"Driving licence: D1234567", "Driver's license: D1234567"},
		{"Driving license: D1234567", "Driver license: D1234567"},
		{"Driving licence #: D1234567", "Drivers license #: D1234567"},
		{"driving_licence: D1234567", "drivers_license: D1234567"},
		{"Driving Licence No. D1234567", "Driving License No. D1234567"},
		{"Licence No. D1234567", "License No. D1234567"},
		{"Name: A. Wombat, Driving licence: D1234567", "Name: A. Wombat, Driver license: D1234567"},
	} {
		t.Run(tc.british, func(t *testing.T) {
			british := bestDL(t, tc.british+"\n", validDL)
			us := bestDL(t, tc.usTwin+"\n", validDL)
			if us != 95 {
				t.Fatalf("control %q scores %.0f, want 95; the comparison below is meaningless", tc.usTwin, us)
			}
			if british != us {
				t.Errorf("%q scores %.0f where its US twin %q scores %.0f", tc.british, british, tc.usTwin, us)
			}
		})
	}
}

// TestLabelSpellingRegressionTable pins the issue's matrix as written, so the generator is checked
// against an independent table and not only against itself. The value is the line's last field;
// want -1 means no finding.
func TestLabelSpellingRegressionTable(t *testing.T) {
	for _, tc := range []struct {
		content string
		want    float64
	}{
		// Already 95 on main; must not move.
		{"drivingLicenseNumber: D1234567", 95},
		{"driversLicenceNumber: D1234567", 95},
		{"driverLicenceNumber: D1234567", 95},
		{"driversLicense: D1234567", 95},
		{"driverLicense: D1234567", 95},
		{"licenceNumber: D1234567", 95},
		{"Driver's licence: D1234567", 95},
		{"Drivers licence: D1234567", 95},
		{"Driving licence number: D1234567", 95},
		{"Licence no: D1234567", 95},
		{"License No. D1234567", 95},
		{"Driving License No. D1234567", 95},
		{"Driver License Number: D1234567", 95},
		// Deliberately unchanged: "driver number" names device, racing and delivery IDs too.
		{"Driver number: D1234567", 65},
		// Deliberately unchanged: bare "licence" is not a label (software, fishing, gun licence).
		{"License: D1234567", 65},
		{"Licence #: D1234567", 65},
		// Out of scope: a non-English label needs a jurisdiction-paired gate (#392's reasoning).
		{"F\u00fchrerscheinnummer: D1234567", -1},
		{"Num\u00e9ro de permis de conduire : D1234567", -1},
		{"Rijbewijsnummer: D1234567", -1},
		// The whole-word rule still holds for the new spellings.
		{"drivinglicencenumbers: D1234567", -1},
		{"xdrivinglicence: D1234567", -1},
		{"nondrivinglicence: D1234567", -1},
		// Non-licence licences keep their main scores ("key", "fishing", "business" are negatives).
		{"Licence key: D1234567", 45},
		{"Fishing licence: D1234567", 45},
		{"Business licence: 12345678", 30},
	} {
		t.Run(tc.content, func(t *testing.T) {
			fields := strings.Fields(tc.content)
			if got := bestDL(t, tc.content+"\n", fields[len(fields)-1]); got != tc.want {
				t.Errorf("%q scores %.0f, want %.0f", tc.content, got, tc.want)
			}
		})
	}
}

// conventions renders a spaced label in the writing conventions exports use.
func conventions(label string) map[string]string {
	upperFirst := func(w string) string { return strings.ToUpper(w[:1]) + w[1:] }
	words := strings.Fields(label)
	title := make([]string, len(words))
	camel, pascal := words[0], upperFirst(words[0])
	for i, w := range words {
		title[i] = upperFirst(w)
		if i > 0 {
			camel += upperFirst(w)
			pascal += upperFirst(w)
		}
	}
	return map[string]string{
		"spaced": label,
		"title":  strings.Join(title, " "),
		"snake":  strings.Join(words, "_"),
		"kebab":  strings.Join(words, "-"),
		"camel":  camel,
		"pascal": pascal,
	}
}

// TestEveryLabelFormScoresTheSameInEveryConvention is the vocabulary invariant: each of the 24
// generated spellings, in every convention and with every field separator, gives D1234567 the same
// confidence as the canonical "Driver's License Number:".
func TestEveryLabelFormScoresTheSameInEveryConvention(t *testing.T) {
	want := bestDL(t, "Driver's License Number: "+validDL+"\n", validDL)
	if want != 95 {
		t.Fatalf("canonical control scores %.0f, want 95", want)
	}
	forms := licenceLabelForms()
	if len(forms) != 24 {
		t.Fatalf("licenceLabelForms() has %d spellings, want 24 (4 holders x 2 nouns x 3 suffixes)", len(forms))
	}
	for _, form := range forms {
		for conv, label := range conventions(form) {
			for _, sep := range []string{": ", " #: ", "=", " = "} {
				line := label + sep + validDL
				if got := bestDL(t, line+"\n", validDL); got != want {
					t.Errorf("%s %q: %q scores %.0f, want %.0f", conv, form, line, got, want)
				}
			}
		}
		// The printed-form abbreviation ends the label with its own full stop and no separator.
		if !strings.HasSuffix(form, " number") && !strings.HasSuffix(form, " no") {
			for _, label := range []string{form, conventions(form)["title"]} {
				line := label + " No. " + validDL
				if got := bestDL(t, line+"\n", validDL); got != want {
					t.Errorf("%q scores %.0f, want %.0f", line, got, want)
				}
			}
		}
	}
}

// TestOneVocabularyFeedsAllThreeLists: a spelling that admits a line must also earn the label boost,
// in the label position and anywhere on the line. Drift between these lists is the defect (#861).
func TestOneVocabularyFeedsAllThreeLists(t *testing.T) {
	v := NewValidator()
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, form := range licenceLabelForms() {
		if !in(v.positiveKeywords, form) {
			t.Errorf("%q is not a positive keyword, so a line labelled with it is never scanned", form)
		}
		if !in(prefixLabels, form) {
			t.Errorf("%q is not a prefix label, so it is admitted but band-demoted", form)
		}
		if !hasLabelLiteral(form + ":") {
			t.Errorf("no label literal matches %q, so the label after another field is band-demoted", form+":")
		}
	}
	for _, form := range []string{"license number", "licence number", "license no", "licence no"} {
		if !in(prefixLabels, form) || !hasLabelLiteral(form+":") {
			t.Errorf("holder-less field label %q is missing from prefixLabels or labelLiterals", form)
		}
	}
	for _, s := range []string{"license no.", "licence no."} {
		if !hasLabelLiteral(s) {
			t.Errorf("%q is not a label literal, so the separator-less printed form is band-demoted", s)
		}
	}
}

// TestVocabularyIsLowercase guards the lowercase-once hoisting: ContainsLabelLower on a lowered line
// equals containsLabel only when the keyword is lowercase too.
func TestVocabularyIsLowercase(t *testing.T) {
	v := NewValidator()
	for _, list := range [][]string{v.positiveKeywords, prefixLabels, labelLiterals} {
		for _, kw := range list {
			if strings.ToLower(kw) != kw {
				t.Errorf("%q is not lowercase", kw)
			}
		}
	}
}

// TestGateMatchesTheNaiveDefinition: the hoisted, driv-skipping gate must give exactly the answer of
// testing every keyword with containsLabel on the line as written, on lines with and without "driv"
// and in any case.
func TestGateMatchesTheNaiveDefinition(t *testing.T) {
	v := NewValidator()
	naive := func(line string) bool {
		for _, kw := range v.positiveKeywords {
			if containsLabel(line, kw) {
				return true
			}
		}
		lower := strings.ToLower(line)
		return reStateName.MatchString(line) && (containsKeyword(line, "id") ||
			strings.Contains(lower, "number") || strings.Contains(lower, "no.") || strings.Contains(lower, "no:"))
	}
	for _, line := range []string{
		"drivingLicence: D1234567", "DRIVING LICENCE: D1234567", "DrivingLicenceNo: D1234567",
		"Driver's licence D1234567", "licenceNumber: D1234567", "DL# A9876543", "motor_vehicle record",
		"deriving the drive", "redrive licensee", "the driveway permit", "func main() {", "", "DRIV",
		"driv", "Driv er", "no keyword at all 12345678", "Operator: X", "state-id 12345678",
		"identificationCard 1", "Texas record no. 12345678", "OHIO ID 12345678",
	} {
		if got, want := v.lineHasPositiveKeyword(line), naive(line); got != want {
			t.Errorf("%q: lineHasPositiveKeyword = %v, testing every keyword = %v", line, got, want)
		}
	}
}

// TestPreExistingKeywordsKeepTheirRelativeOrder pins the claim in buildPositiveKeywords: SARIF
// reports Context.PositiveKeywords in list order, so a line matching only keywords that existed
// before #861 must report them in the same order as before.
func TestPreExistingKeywordsKeepTheirRelativeOrder(t *testing.T) {
	legacy := []string{
		"driver", "license", "licence", "dl", "dmv", "motor vehicle", "driving", "permit", "state id",
		"identification card", "operator", "driver's license", "drivers license", "driver license",
		"dl number", "license number", "licence number", "drivers license number",
		"drivers licence number", "driver license number", "driver licence number",
		"driving license number", "driver's license number",
	}
	pos := map[string]int{}
	for i, kw := range NewValidator().positiveKeywords {
		pos[kw] = i
	}
	last := -1
	for _, kw := range legacy {
		i, ok := pos[kw]
		if !ok {
			t.Fatalf("pre-#861 keyword %q was dropped", kw)
		}
		// driver's license number is the one legacy entry the holder-major generation moves ahead of
		// the other three-word forms; no single label contains two of them, so no line reports both.
		if kw == "driver's license number" {
			continue
		}
		if i < last {
			t.Errorf("%q moved ahead of a keyword that preceded it before #861", kw)
		}
		last = i
	}
}
