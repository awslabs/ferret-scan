// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The tests in this file pin #859: UK NHS numbers and Scottish CHI numbers had no owning type. A
// labelled NHS number reported only as a US/CA PHONE (redacted with its last four digits kept), and
// a spaced CHI, a JSON NHS number with a run of zeros and a JSON CHI number reported nothing at all.
// All values are synthetic: NHS numbers from NHS England's never-issued 999 range or generated with
// a computed check digit, CHIs with a zero serial.

func ukScan(t *testing.T, content string) []detector.Match {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, "uk.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	return ms
}

// ukFindings returns the NHS_NUMBER and CHI_NUMBER findings only.
func ukFindings(t *testing.T, content string) []detector.Match {
	t.Helper()
	var out []detector.Match
	for _, m := range ukScan(t, content) {
		if m.Type == "NHS_NUMBER" || m.Type == "CHI_NUMBER" {
			out = append(out, m)
		}
	}
	return out
}

func ukDescribe(matches []detector.Match) []string {
	var out []string
	for _, m := range matches {
		out = append(out, fmt.Sprintf("%s %.0f %q", m.Type, m.Confidence, m.Text))
	}
	return out
}

func ukChecks(t *testing.T, m detector.Match) map[string]bool {
	t.Helper()
	c, ok := m.Metadata["validation_checks"].(map[string]bool)
	if !ok {
		t.Fatalf("%s %q: validation_checks is %T", m.Type, m.Text, m.Metadata["validation_checks"])
	}
	return c
}

// withCheckDigit appends the mod-11 check digit to nine digits, or returns "" when the check digit
// would be 10 (such a number is never issued).
func withCheckDigit(d9 string) string {
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d9[i]-'0') * (10 - i)
	}
	c := 11 - sum%11
	if c == 11 {
		c = 0
	}
	if c == 10 {
		return ""
	}
	return d9 + string(rune('0'+c))
}

// TestUKHealthIssueCases is the issue's 17-case table. Every case now reports its type; the
// 999-range NHS numbers are capped at 15 with the ceiling published, and the zero-serial CHIs are
// HIGH.
func TestUKHealthIssueCases(t *testing.T) {
	for _, tc := range []struct {
		name, content, typ, text string
		want                     float64
	}{
		{"01 spaced NHS", "NHS number: 999 111 2227", "NHS_NUMBER", "999 111 2227", 15},
		{"02 plain NHS", "NHS number: 9991112227", "NHS_NUMBER", "9991112227", 15},
		{"03 dashed NHS", "NHS No: 999-111-2227", "NHS_NUMBER", "999-111-2227", 15},
		{"04 patient NHS", "Patient NHS number: 9991112227", "NHS_NUMBER", "9991112227", 15},
		{"05 spaced CHI", "CHI number: 150100 0004", "CHI_NUMBER", "150100 0004", 90},
		{"06 dashed CHI", "CHI number: 150100-0004", "CHI_NUMBER", "150100-0004", 90},
		{"07 CHI day 0x", "CHI number: 070300 0004", "CHI_NUMBER", "070300 0004", 90},
		{"08 plain CHI", "CHI number: 1501000004", "CHI_NUMBER", "1501000004", 90},
		{"09 patient CHI", "Patient CHI number: 150100 0004", "CHI_NUMBER", "150100 0004", 100},
		{"10 CHI that passes NPI-Luhn", "CHI number: 1301000000", "CHI_NUMBER", "1301000000", 90},
		{"11 JSON NHS", `{"nhsNumber": "9991112227"}`, "NHS_NUMBER", "9991112227", 15},
		{"12 JSON NHS with a zero run", `{"nhsNumber": "9990000018"}`, "NHS_NUMBER", "9990000018", 15},
		{"13 JSON CHI", `{"chiNumber": "1501000004"}`, "CHI_NUMBER", "1501000004", 90},
		{"14 FHIR", `{"identifier": [{"system": "https://fhir.nhs.uk/Id/nhs-number", "value": "9991112227"}]}`, "NHS_NUMBER", "9991112227", 15},
		{"15 XML", "<nhsNumber>9991112227</nhsNumber>", "NHS_NUMBER", "9991112227", 15},
		{"16 HL7 PID-3", "PID|1||9991112227^^^NHS^NH||ALPHA^BRAVO", "NHS_NUMBER", "9991112227", 15},
		{"17 two-column CSV", "surname,nhs_number\nAlpha,9991112227", "NHS_NUMBER", "9991112227", 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ukFindings(t, tc.content)
			if len(got) != 1 || got[0].Type != tc.typ || got[0].Text != tc.text {
				t.Fatalf("got %v, want one %s %q", ukDescribe(got), tc.typ, tc.text)
			}
			m := got[0]
			if m.Confidence != tc.want {
				t.Errorf("confidence %.0f, want %.0f", m.Confidence, tc.want)
			}
			if m.Metadata["checksum_valid"] != true {
				t.Errorf("checksum_valid = %v", m.Metadata["checksum_valid"])
			}
			if tc.want == 15 {
				if m.Metadata["confidence_ceiling"] != 15.0 {
					t.Errorf("a capped value must publish its ceiling, got %v", m.Metadata["confidence_ceiling"])
				}
				if ukChecks(t, m)["not_reserved_test_range"] {
					t.Error("not_reserved_test_range = true on a 999-range value")
				}
			} else if _, ok := m.Metadata["confidence_ceiling"]; ok {
				t.Errorf("an uncapped value published a ceiling: %v", m.Metadata["confidence_ceiling"])
			}
		})
	}
}

// TestUKHealthIsAdditive: no NHS or CHI label lowers or removes another finding. On the 17 cases the
// only other MEDICAL_ID findings are the three main already reported, at main's scores.
func TestUKHealthIsAdditive(t *testing.T) {
	want := map[string]string{
		"Patient NHS number: 9991112227":  `MRN 55 "9991112227"`,
		"Patient CHI number: 150100 0004": `MRN 55 "150100"`,
		"CHI number: 1301000000":          `NPI 40 "1301000000"`,
	}
	for _, content := range []string{
		"NHS number: 999 111 2227", "NHS number: 9991112227", "NHS No: 999-111-2227",
		"Patient NHS number: 9991112227", "CHI number: 150100 0004", "CHI number: 150100-0004",
		"CHI number: 070300 0004", "CHI number: 1501000004", "Patient CHI number: 150100 0004",
		"CHI number: 1301000000", `{"nhsNumber": "9991112227"}`, `{"nhsNumber": "9990000018"}`,
		`{"chiNumber": "1501000004"}`, "<nhsNumber>9991112227</nhsNumber>",
		"PID|1||9991112227^^^NHS^NH||ALPHA^BRAVO", "surname,nhs_number\nAlpha,9991112227",
	} {
		var other []string
		for _, m := range ukScan(t, content) {
			if m.Type != "NHS_NUMBER" && m.Type != "CHI_NUMBER" {
				other = append(other, fmt.Sprintf("%s %.0f %q", m.Type, m.Confidence, m.Text))
			}
		}
		if got := strings.Join(other, "; "); got != want[content] {
			t.Errorf("%q: other findings %q, want %q", content, got, want[content])
		}
	}
}

// TestUKHealthRecallPerRange: 1,000 valid values per population, generated here and never
// committed, are HIGH under every binding. The populations are England/Wales/Isle of Man 4xx and
// 6xx-7xx, Northern Ireland 320-399, and CHI with random real dates of birth.
func TestUKHealthRecallPerRange(t *testing.T) {
	rng := rand.New(rand.NewSource(43))
	nhs := func(lo, hi int) string {
		for {
			if v := withCheckDigit(fmt.Sprintf("%09d", lo+rng.Intn(hi-lo))); v != "" {
				return v
			}
		}
	}
	chi := func() string {
		for {
			d := time.Date(1930+rng.Intn(95), time.January, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, rng.Intn(365))
			if v := withCheckDigit(d.Format("020106") + fmt.Sprintf("%03d", rng.Intn(1000))); v != "" {
				return v
			}
		}
	}
	type population struct {
		name string
		kind ukHealthKind
		gen  func() string
	}
	pops := []population{
		{"eng4", ukHealthNHS, func() string { return nhs(400000000, 500000000) }},
		{"eng67", ukHealthNHS, func() string { return nhs(600000000, 800000000) }},
		{"ni3", ukHealthNHS, func() string { return nhs(320000000, 400000000) }},
		{"chi", ukHealthCHI, chi},
	}
	for _, p := range pops {
		values := make([]string, 1000)
		for i := range values {
			values[i] = p.gen()
		}
		label, key, col, spaced := "NHS number", "nhsNumber", "nhs_number", func(v string) string { return v[:3] + " " + v[3:6] + " " + v[6:] }
		if p.kind == ukHealthCHI {
			label, key, col, spaced = "CHI number", "chiNumber", "chi_number", func(v string) string { return v[:6] + " " + v[6:] }
		}
		layouts := map[string]func(i int, v string) string{
			"spaced":      func(_ int, v string) string { return label + ": " + spaced(v) },
			"plain":       func(_ int, v string) string { return label + ": " + v },
			"json":        func(_ int, v string) string { return fmt.Sprintf(`  {"%s": "%s"},`, key, v) },
			"patient":     func(_ int, v string) string { return "Patient " + label + ": " + v },
			"label_above": func(_ int, v string) string { return label + "\n" + v },
		}
		if p.kind == ukHealthNHS {
			layouts["hl7"] = func(_ int, v string) string { return "PID|1||" + v + "^^^NHS^NH||ALPHA^BRAVO" }
			layouts["fhir"] = func(_ int, v string) string {
				return `{"system": "https://fhir.nhs.uk/Id/nhs-number", "value": "` + v + `"}`
			}
		}
		for name, layout := range layouts {
			t.Run(p.name+"/"+name, func(t *testing.T) {
				var b strings.Builder
				for i, v := range values {
					b.WriteString(layout(i, v) + "\n")
				}
				assertAllHigh(t, b.String(), values, p.kind)
			})
		}
		t.Run(p.name+"/table", func(t *testing.T) {
			var b strings.Builder
			b.WriteString("row," + col + ",ward\n")
			for i, v := range values {
				fmt.Fprintf(&b, "%d,%s,W%d\n", i, v, i%7)
			}
			assertAllHigh(t, b.String(), values, p.kind)
		})
	}
}

func assertAllHigh(t *testing.T, doc string, values []string, kind ukHealthKind) {
	t.Helper()
	high := map[string]bool{}
	for _, m := range ukFindings(t, doc) {
		if m.Type == kind.typeName() && m.Confidence >= 90 {
			high[strings.NewReplacer(" ", "", "-", "").Replace(m.Text)] = true
		}
	}
	missed := 0
	for _, v := range values {
		if !high[v] {
			missed++
		}
	}
	if missed > 0 {
		t.Errorf("%d of %d values not reported HIGH as %s", missed, len(values), kind.typeName())
	}
}

// TestUKHealthCeilings: the never-issued 999 range and every repdigit (all ten pass the check digit)
// are capped at the T2 ceiling, 15, and the ceiling is published.
func TestUKHealthCeilings(t *testing.T) {
	for _, tc := range []struct{ content, typ string }{
		{"NHS number: 9990000018", "NHS_NUMBER"},
		{"NHS number: 999 999 9999", "NHS_NUMBER"},
		{"NHS number: 0000000000", "NHS_NUMBER"},
		{"NHS number: 4444444444", "NHS_NUMBER"},
		{"CHI number: 1111111111", "CHI_NUMBER"},
		{"Patient NHS number: 999 000 0026 hospital medical record", "NHS_NUMBER"},
	} {
		t.Run(tc.content, func(t *testing.T) {
			got := ukFindings(t, tc.content)
			if len(got) != 1 || got[0].Type != tc.typ {
				t.Fatalf("got %v, want one %s", ukDescribe(got), tc.typ)
			}
			if got[0].Confidence > 15 || got[0].Metadata["confidence_ceiling"] != 15.0 {
				t.Errorf("confidence %.0f ceiling %v, want <= 15 and 15", got[0].Confidence, got[0].Metadata["confidence_ceiling"])
			}
		})
	}
}

// TestUKHealthFailedChecksAreLowNotDropped: a bound label whose value fails the check digit, or a
// CHI whose date is not a real date, is still reported, at LOW, with the failed check recorded.
func TestUKHealthFailedChecksAreLowNotDropped(t *testing.T) {
	for _, tc := range []struct {
		content, typ, check string
	}{
		{"NHS number: 4505577105", "NHS_NUMBER", "nhs_checksum"},
		{`{"nhsNumber": "1234567890"}`, "NHS_NUMBER", "nhs_checksum"},
		{"CHI number: 1501000005", "CHI_NUMBER", "chi_checksum"},
		{"CHI number: 3201000000", "CHI_NUMBER", "chi_date"}, // 32 January
		{"CHI number: 2902010001", "CHI_NUMBER", "chi_date"}, // 29 February 1901 and 2001: neither is a leap year
	} {
		t.Run(tc.content, func(t *testing.T) {
			got := ukFindings(t, tc.content)
			if len(got) != 1 || got[0].Type != tc.typ {
				t.Fatalf("got %v, want one %s", ukDescribe(got), tc.typ)
			}
			m := got[0]
			if m.Confidence >= 60 || m.Confidence < 15 {
				t.Errorf("confidence %.0f, want LOW and at least the 15 floor", m.Confidence)
			}
			if ukChecks(t, m)[tc.check] {
				t.Errorf("%s = true for a value that fails it", tc.check)
			}
		})
	}
	// The control: the same CHI date rule accepts a real 29 February.
	if got := ukFindings(t, "CHI number: 2902000006"); len(got) != 1 || got[0].Confidence != 90 {
		t.Errorf("29 February 2000 is a real date, got %v", ukDescribe(got))
	}
}

// TestUKHealthDecoys: the check digit alone is no evidence, so nothing here reports an NHS or CHI
// number. A bare "NHS" or "CHI" token never binds, nor does a label that does not sit right before
// the value.
func TestUKHealthDecoys(t *testing.T) {
	for _, content := range []string{
		"NHS library ISBN 0306406152",                            // a numeric ISBN-10: passes the same mod-11 check
		"Call NHS 111 or +44 7700900123 for advice",              // a UK phone number after +44
		"NHS 212-555-0142 switchboard",                           // NANP beside a bare NHS
		"chi := tls.ClientHelloInfo{ServerName: \"1501000004\"}", // Go code
		"CHI 1501000004 rejected",                                // bare CHI
		"nhs_sync ts=1751328000 status=ok",                       // an epoch, beside nhs but no label
		"4505577104",                                             // an unlabelled mod-11-valid run
		"Reference 4505577104 for the NHS number form",           // a label AFTER the value
		"NHS number\n+44 7700900123",                             // a label line above a phone number
		"NHS number: 150100 0004",                                // the CHI grouping under an NHS label
		"CHI number: 999 111 2227",                               // the NHS grouping under a CHI label
		"NHS number: 999 111-2227",                               // mixed separators
		"NHS number: 4505 577 104 1234",                          // not a 10-digit grouping
		"NHS number: 999 111 2227 4444",                          // one group of a longer grouped number
		"NHS number: 0.9991112227",                               // a decimal fraction
		`{"system": "https://fhir.nhs.uk/Id/ods-organization-code", "value": "4505577104"}`, // a different FHIR system
		"Please quote your NHS number when you call\n4505577104",                            // prose above, not a label
	} {
		t.Run(content, func(t *testing.T) {
			if got := ukFindings(t, content); len(got) != 0 {
				t.Errorf("decoy reported %v", ukDescribe(got))
			}
		})
	}

	// A precision population: 20,000 random 10-digit values (about 9% pass the check digit) on
	// lines that carry a bare NHS or CHI token but no label bound to the value.
	rng := rand.New(rand.NewSource(859))
	var b strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&b, "NHS 111 log %010d\n", rng.Int63n(1e10))
		fmt.Fprintf(&b, "chi handshake %010d ok\n", rng.Int63n(1e10))
	}
	if got := ukFindings(t, b.String()); len(got) != 0 {
		t.Errorf("%d of 20,000 unbound values reported, e.g. %v", len(got), ukDescribe(got[:1]))
	}
}

// TestUKHealthRecordsOnlyTheChecksItMade (#537): each type records its own checks, and none of the
// other scheme's.
func TestUKHealthRecordsOnlyTheChecksItMade(t *testing.T) {
	nhs := ukFindings(t, "NHS number: 4505577104")
	if len(nhs) != 1 {
		t.Fatalf("got %v", ukDescribe(nhs))
	}
	if got := ukChecks(t, nhs[0]); len(got) != 5 || !got["nhs_checksum"] || !got["nhs_label"] ||
		!got["not_reserved_test_range"] || !got["not_repdigit"] || !got["not_test_data"] {
		t.Errorf("NHS checks %v", got)
	}
	if nhs[0].Confidence != 90 || nhs[0].Metadata["label_binding"] != "label" {
		t.Errorf("NHS confidence %.0f binding %v, want 90 and label", nhs[0].Confidence, nhs[0].Metadata["label_binding"])
	}

	chi := ukFindings(t, "CHI number: 150100 0004")
	if len(chi) != 1 {
		t.Fatalf("got %v", ukDescribe(chi))
	}
	if got := ukChecks(t, chi[0]); len(got) != 5 || !got["chi_checksum"] || !got["chi_date"] ||
		!got["chi_label"] || !got["not_repdigit"] || !got["not_test_data"] {
		t.Errorf("CHI checks %v", got)
	}
	if chi[0].Metadata["normalized"] != "1501000004" {
		t.Errorf("normalized = %v", chi[0].Metadata["normalized"])
	}
}

// TestUKHealthBindings names each binding the value can carry.
func TestUKHealthBindings(t *testing.T) {
	for _, tc := range []struct{ content, binding string }{
		{"NHS number: 4505577104", "label"},
		{"H&C number: 3201234567", "label"},
		{"Health and Care Number: 3201234567", "label"},
		{"Community Health Index: 1501000004", "label"},
		{"nhs_number=4505577104", "label"},
		{"<nhsNumber>4505577104</nhsNumber>", "label"},
		{"PID|1||4505577104^^^NHS^NH||ALPHA^BRAVO", "hl7_assigning_authority"},
		{`  "system": "https://fhir.nhs.uk/Id/nhs-number",` + "\n" + `  "value": "4505577104"`, "fhir_system"},
		{"name,nhs_number,ward\nAlpha,4505577104,W1\nBravo,4505577104,W2\n", "column_header"},
		{"Patient NHS Number:\n4505577104", "label_above"},
	} {
		t.Run(tc.content, func(t *testing.T) {
			got := ukFindings(t, tc.content)
			if len(got) == 0 {
				t.Fatal("no finding")
			}
			for _, m := range got {
				if m.Metadata["label_binding"] != tc.binding {
					t.Errorf("binding %v, want %s", m.Metadata["label_binding"], tc.binding)
				}
			}
		})
	}
}

// TestUKHealthLongLineStaysLinear mirrors TestSingleLongLine_NotQuadratic for this scanner: every
// candidate's label is looked for in a bounded window, so a dense labelled line stays linear.
func TestUKHealthLongLineStaysLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}
	var b strings.Builder
	for b.Len() < 32*1024 {
		b.WriteString("NHS number: 4505577104 CHI number: 150100 0004 ")
	}
	start := time.Now()
	got := ukFindings(t, b.String())
	elapsed := time.Since(start)
	if len(got) < 1000 {
		t.Fatalf("only %d findings on the dense line; the timing below would measure nothing", len(got))
	}
	if !raceEnabled && elapsed > 2*time.Second {
		t.Fatalf("%d-byte line took %s (ceiling 2s)", b.Len(), elapsed)
	}
}

// TestUKHealthCheckDigit pins the published algorithm against hand-computed values.
func TestUKHealthCheckDigit(t *testing.T) {
	for d, want := range map[string]bool{
		"9991112227": true, // 279 mod 11 = 4, 11 - 4 = 7
		"9990000018": true, // 245 mod 11 = 3, 11 - 3 = 8
		"4505577104": true, // 216 mod 11 = 7, 11 - 7 = 4
		"1501000004": true, // 62 mod 11 = 7, 11 - 7 = 4
		"0306406152": true, // a numeric ISBN-10: 130 mod 11 = 9, 11 - 9 = 2
		"0000000000": true, // 0 mod 11 = 0, 11 - 0 = 11, which means 0
		"4505577105": false,
	} {
		if got := ukHealthCheckDigitValid(d); got != want {
			t.Errorf("ukHealthCheckDigitValid(%s) = %v, want %v", d, got, want)
		}
	}
	// 123456789 weighs 210, 210 mod 11 = 1, so its check digit would be 10: such a number is never
	// issued, and no tenth digit passes.
	for c := 0; c <= 9; c++ {
		if ukHealthCheckDigitValid("123456789" + string(rune('0'+c))) {
			t.Errorf("123456789%d passed, but 123456789 needs check digit 10", c)
		}
	}
}
