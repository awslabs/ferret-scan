// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// #861 (enhancement half): GB DVLA driver numbers and Ontario/Quebec licences as printed gave no
// finding of any type on main @ b0a9163, under any label. All values here are synthetic.

// dvla builds a GB driver number from its parts, following the DVLA layout documented on
// validGBDriverNumber. It mirrors the generator in the issue, so the fixtures are derived from the
// layout rather than typed by hand.
func dvla(surname string, year, month, day int, female bool, initials, arb, check string) string {
	s := (strings.ToUpper(surname) + "99999")[:5]
	if female {
		month += 50
	}
	ini := (strings.ToUpper(initials) + "99")[:2]
	return fmt.Sprintf("%s%d%02d%02d%d%s%s%s", s, (year/10)%10, month, day, year%10, ini, arb, check)
}

// dlFindings returns the DRIVERS_LICENSE findings for content.
func dlFindings(t *testing.T, content string) []struct {
	text, format string
	line         int
	confidence   float64
} {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "record.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	var out []struct {
		text, format string
		line         int
		confidence   float64
	}
	for _, m := range matches {
		if m.Type != "DRIVERS_LICENSE" {
			continue
		}
		format, _ := m.Metadata["format"].(string)
		out = append(out, struct {
			text, format string
			line         int
			confidence   float64
		}{m.Text, format, m.LineNumber, m.Confidence})
	}
	return out
}

func TestDVLAFixtureGenerator(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{dvla("Wombat", 1990, 1, 1, false, "ZZ", "9", "AA"), "WOMBA901010ZZ9AA"},
		{dvla("Emu", 1990, 1, 1, true, "Z", "9", "AA"), "EMU99951010Z99AA"},
		{dvla("Quokka", 1980, 1, 1, false, "ZZ", "9", "1A"), "QUOKK801010ZZ91A"},
	} {
		if tc.got != tc.want {
			t.Errorf("dvla() = %q, want %q (the issue's values)", tc.got, tc.want)
		}
	}
}

// TestGBDriverNumberDisplayVariants is the issue's "GB 0/12": every display variant reports the
// number as GB_DVLA at 90 or more, except the label-on-the-line-above form, which scores 85 as any
// label above does.
func TestGBDriverNumberDisplayVariants(t *testing.T) {
	const gb = "WOMBA901010ZZ9AA"
	for _, tc := range []struct {
		content, wantText string
		wantMin           float64
	}{
		{"Driving licence number: " + gb, gb, 90},
		{"Driving licence number: EMU99951010Z99AA", "EMU99951010Z99AA", 90},
		{"Driving licence number: " + gb + " 01", gb, 90}, // the issue number stays outside the span
		{"Driving licence number: " + gb + "01", gb + "01", 90},
		{"Driver's License Number: " + gb, gb, 90},
		// A column header. Three columns so tabular.Analyze sees a table; the issue's two-column
		// .csv scores 100 through the CLI, and 85 here through the label-above path alone, exactly
		// as its US twin `name,drivers_license_number` does on main.
		{"name,driving_licence_number,country\nA. Wombat," + gb + ",GB", gb, 90},
		{"name,driving_licence_number\nA. Wombat," + gb, gb, 85},
		{"Driving licence number: womba901010zz9aa", "womba901010zz9aa", 90},
		{"Driving licence number: QUOKK801010ZZ91A", "QUOKK801010ZZ91A", 90},
		{"Driving licence number: WOMBA 901010 ZZ9AA", "WOMBA 901010 ZZ9AA", 90},
		{"DL No: " + gb, gb, 90},
		{"Driving licence number\n" + gb, gb, 85},
		{`{"drivingLicenceNumber": "` + gb + `"}`, gb, 90},
	} {
		t.Run(tc.content, func(t *testing.T) {
			found := dlFindings(t, tc.content+"\n")
			if len(found) != 1 {
				t.Fatalf("%d DRIVERS_LICENSE findings, want 1: %+v", len(found), found)
			}
			f := found[0]
			if f.text != tc.wantText || f.format != formatGBDVLA || f.confidence < tc.wantMin {
				t.Errorf("got %q %s %.0f, want %q %s >= %.0f", f.text, f.format, f.confidence,
					tc.wantText, formatGBDVLA, tc.wantMin)
			}
		})
	}
}

func TestGBDriverNumberGate(t *testing.T) {
	accept := map[string]string{
		"male":                    dvla("Wombat", 1990, 1, 1, false, "ZZ", "9", "AA"),
		"female, month + 50":      dvla("Wombat", 1990, 12, 31, true, "ZZ", "9", "AA"),
		"short surname, 9-padded": dvla("Emu", 1985, 6, 15, false, "AB", "9", "AA"),
		"one-letter surname":      dvla("O", 1985, 6, 15, false, "AB", "9", "AA"),
		"no middle initial (Z9)":  dvla("Wombat", 1990, 1, 1, false, "Z", "9", "AA"),
		"no split name (99)":      dvla("Wombat", 1990, 1, 1, false, "", "9", "AA"),
		"digit check character":   dvla("Quokka", 1980, 1, 1, false, "ZZ", "9", "1A"),
		"digit check characters":  dvla("Quokka", 1980, 1, 1, false, "ZZ", "8", "12"),
		"lowercase":               strings.ToLower(dvla("Wombat", 1990, 1, 1, false, "ZZ", "9", "AA")),
	}
	for name, s := range accept {
		if !validGBDriverNumber(s) {
			t.Errorf("%s: validGBDriverNumber(%q) = false, want true", name, s)
		}
		if found := dlFindings(t, "Driving licence number: "+s+"\n"); len(found) != 1 || found[0].format != formatGBDVLA {
			t.Errorf("%s: %q reported %+v, want one GB_DVLA finding", name, s, found)
		}
	}

	base := dvla("Wombat", 1990, 1, 1, false, "ZZ", "9", "AA") // WOMBA901010ZZ9AA
	withMonth := func(mm string) string { return base[:6] + mm + base[8:] }
	withDay := func(dd string) string { return base[:8] + dd + base[10:] }
	reject := map[string]string{
		"month 00":                    withMonth("00"),
		"month 13":                    withMonth("13"),
		"month 50":                    withMonth("50"),
		"month 63":                    withMonth("63"),
		"day 00":                      withDay("00"),
		"day 32":                      withDay("32"),
		"digit before a letter (1-5)": "WOM9A" + base[5:],
		"surname starts with 9":       "9OMBA" + base[5:],
		"surname all 9s":              "99999" + base[5:],
		"initials 9Q":                 base[:11] + "9Q" + base[13:],
	}
	for name, s := range reject {
		if validGBDriverNumber(s) {
			t.Errorf("%s: validGBDriverNumber(%q) = true, want false", name, s)
		}
		if found := dlFindings(t, "Driving licence number: "+s+"\n"); len(found) != 0 {
			t.Errorf("%s: %q reported %+v under a licence label, want nothing", name, s, found)
		}
	}
	if validGBDriverNumber(base[:15]) || validGBDriverNumber(base+"0") {
		t.Error("validGBDriverNumber accepted a length other than 16")
	}
}

// TestInvalidDateGBShapesStayUnreported is the issue's 500-decoy family: GB-shaped values whose month
// or day is impossible, each on a licence-labelled line. The layout gate is the only thing between
// them and a HIGH finding, so all 500 must stay unreported.
func TestInvalidDateGBShapesStayUnreported(t *testing.T) {
	r := rand.New(rand.NewSource(861))
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alnum := letters + "0123456789"
	var b strings.Builder
	for i := 0; i < 500; i++ {
		n := 1 + r.Intn(5)
		surname := ""
		for j := 0; j < n; j++ {
			surname += string(letters[r.Intn(26)])
		}
		surname = (surname + "99999")[:5]
		month, day := 1+r.Intn(12), 1+r.Intn(31)
		if i%2 == 0 { // impossible month: 00, 13-50 or 63-99
			for month = r.Intn(100); month >= 1 && month <= 12 || month >= 51 && month <= 62; month = r.Intn(100) {
			}
		} else { // impossible day: 00 or 32-99
			for day = r.Intn(100); day >= 1 && day <= 31; day = r.Intn(100) {
			}
		}
		v := fmt.Sprintf("%s%d%02d%02d%d%c%c%d%c%c", surname, r.Intn(10), month, day, r.Intn(10),
			letters[r.Intn(26)], letters[r.Intn(26)], r.Intn(10), alnum[r.Intn(36)], alnum[r.Intn(36)])
		fmt.Fprintf(&b, "Driving licence number: %s\n", v)
	}
	if found := dlFindings(t, b.String()); len(found) != 0 {
		t.Errorf("%d of 500 invalid-date GB shapes reported, want 0; first: %+v", len(found), found[0])
	}
}

func TestPrintedOntarioAndQuebec(t *testing.T) {
	for _, tc := range []struct {
		content, wantText, wantFormat, wantNormalized string
	}{
		{"Driving licence number: W1234-12345-12345", "W1234-12345-12345", formatOntario, "W12341234512345"},
		{"Ontario Driver's Licence No. W1234-12345-12345", "W1234-12345-12345", formatOntario, "W12341234512345"},
		{"Driving licence number: W1234-123456-12", "W1234-123456-12", formatQuebec, "W123412345612"},
		{"Driving licence number: (W1234-12345-12345)", "W1234-12345-12345", formatOntario, "W12341234512345"},
	} {
		t.Run(tc.content, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(tc.content+"\n", "record.txt")
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 1 {
				t.Fatalf("%d findings, want 1", len(matches))
			}
			m := matches[0]
			if m.Text != tc.wantText || m.Metadata["format"] != tc.wantFormat || m.Confidence < 90 ||
				m.Metadata["normalized"] != tc.wantNormalized {
				t.Errorf("got %q %v %.0f normalized=%v, want %q %s >= 90 normalized=%s", m.Text,
					m.Metadata["format"], m.Confidence, m.Metadata["normalized"], tc.wantText,
					tc.wantFormat, tc.wantNormalized)
			}
		})
	}

	// Contiguous, the same numbers are already US shapes on main; they keep main's Text, confidence
	// and format exactly.
	for _, tc := range []struct{ value, format string }{
		{"W12341234512345", "NJ_1L14D"},
		{"W123412345612", "FL_MI_1L12D"},
	} {
		found := dlFindings(t, "Driving licence number: "+tc.value+"\n")
		if len(found) != 1 || found[0].text != tc.value || found[0].format != tc.format || found[0].confidence != 95 {
			t.Errorf("contiguous %q: got %+v, want one %s finding at 95", tc.value, found, tc.format)
		}
	}

	// A segment of a longer hyphenated token is some other identifier.
	for _, content := range []string{
		"Driving licence number: W1234-12345-12345-0001",
		"Driving licence number: X1-W1234-12345-12345",
		"Driving licence number: W1234-123456-12-34",
	} {
		if found := dlFindings(t, content+"\n"); len(found) != 0 {
			t.Errorf("%q reported %+v, want nothing", content, found)
		}
	}

	// Under a non-driving licence label the negative keyword still holds the value at LOW.
	found := dlFindings(t, "License key: W1234-12345-12345\n")
	if len(found) != 1 || found[0].confidence > 45 {
		t.Errorf("License key + Ontario layout: got %+v, want one finding at <= 45", found)
	}
}

// TestNonUSShapesLeaveUSMatchesAlone pins the claim on reAnyDL: adding the non-US alternatives
// changes no US-shape span. On random lines mixing US, non-US and near-miss tokens, the US spans of
// the composite are exactly the spans of the US-only composite main shipped.
func TestNonUSShapesLeaveUSMatchesAlone(t *testing.T) {
	usOnly := regexp.MustCompile(`\b(?:[A-Za-z]{2}\d{6}|[A-Za-z]\d{14}|[A-Za-z]\d{13}|[A-Za-z]\d{12}` +
		`|[A-Za-z]\d{11}|[A-Za-z]\d{7}|\d{9}|\d{8})\b`)
	tokens := []string{
		"D1234567", "12345678", "123456789", "XY654321", "W12341234512345", "W123412345612",
		"J1234567890123", "C12345678901", "WOMBA901010ZZ9AA", "WOMBA901010ZZ9AA01", "WOMBA 901010 ZZ9AA",
		"W1234-12345-12345", "W1234-123456-12", "W1234-12345-12345-0001", "99999901010999AA",
		"AB999901010ZZ9AA", "A9999901010ZZ9AA", "WOMBA913010ZZ9AA", "1234-5678", "D123-4567-8901",
	}
	r := rand.New(rand.NewSource(8610))
	seps := []string{" ", "-", ",", ": ", "  ", "_", "(", ")", ""}
	v := NewValidator()
	for i := 0; i < 3000; i++ {
		var b strings.Builder
		for j := 0; j < 1+r.Intn(6); j++ {
			b.WriteString(tokens[r.Intn(len(tokens))])
			b.WriteString(seps[r.Intn(len(seps))])
		}
		line := b.String()
		want := usOnly.FindAllStringIndex(line, -1)
		var got [][]int
		for _, loc := range reAnyDL.FindAllStringIndex(line, -1) {
			if f, _ := v.classifyContiguous(line, loc[0], loc[1]); f != formatGBDVLA && f != formatOntario && f != formatQuebec && f != "" {
				got = append(got, loc)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("line %q: US spans %v with the non-US shapes, %v without", line, got, want)
		}
	}
}

// TestOnboardingRecordIsReported is the issue's redaction sink at the validator: each licence number
// in scope is reported with a span covering it, so the redactor masks it. India is out of scope for
// this change (docs/validators-new.md lists it), so its value is asserted unreported as documented.
func TestOnboardingRecordIsReported(t *testing.T) {
	record := "Driver onboarding record\n" +
		"Applicant: A. Wombat\n" +
		"Driving licence number: WOMBA901010ZZ9AA\n" +
		"Ontario Driver's Licence No. W1234-12345-12345\n" +
		"India DL No: KA01 20191234567\n" +
		"drivingLicence: D1234567\n" +
		"US Driver License Number: K7654321\n"
	got := map[string]bool{}
	for _, f := range dlFindings(t, record) {
		got[f.text] = true
	}
	for _, want := range []string{"WOMBA901010ZZ9AA", "W1234-12345-12345", "D1234567", "K7654321"} {
		if !got[want] {
			t.Errorf("%q not reported, so the redacted copy keeps it in cleartext; got %v", want, got)
		}
	}
	if got["KA01 20191234567"] {
		t.Error("the India value is now reported; update the docs that list India as unsupported")
	}
}
