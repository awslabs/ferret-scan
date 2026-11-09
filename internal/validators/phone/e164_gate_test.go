// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"
)

// TestE164CodesCount: the table holds exactly what the generator wrote, so a hand edit that adds or
// drops a code instead of regenerating fails, and the table is not a sample: ITU assigns over 200.
func TestE164CodesCount(t *testing.T) {
	if len(e164Codes) != e164CodeCount {
		t.Fatalf("e164Codes holds %d codes, the generator wrote %d: regenerate e164_codes.go instead of editing it",
			len(e164Codes), e164CodeCount)
	}
	if e164CodeCount < 200 {
		t.Fatalf("only %d calling codes; the table is not the complete assignment list", e164CodeCount)
	}
	for _, code := range []string{"1", "7", "33", "39", "44", "49", "55", "81", "353", "421", "800", "882", "971"} {
		if _, ok := e164Codes[code]; !ok {
			t.Errorf("assigned code %s is missing", code)
		}
	}
	for _, code := range []string{"0", "00", "16", "28", "42", "553", "999", "6", "8"} {
		if _, ok := e164Codes[code]; ok {
			t.Errorf("unassigned code %s is in the table", code)
		}
	}
}

// TestE164CodesArePrefixFree: longestAssignedPrefix reads at most one of a run's first three
// prefixes as a code, which is only sound while no code begins another.
func TestE164CodesArePrefixFree(t *testing.T) {
	for a, ea := range e164Codes {
		if len(a) < 1 || len(a) > 3 || a[0] == '0' || strings.Trim(a, "0123456789") != "" {
			t.Errorf("code %q is not 1-3 digits without a leading 0", a)
		}
		if ea.lengths == 0 {
			t.Errorf("code %s has no national length", a)
		}
		for b := range e164Codes {
			if a != b && strings.HasPrefix(b, a) {
				t.Errorf("code %s is a prefix of code %s", a, b)
			}
		}
	}
}

func TestJudge(t *testing.T) {
	for _, c := range []struct {
		code     string
		national int
		trunk    bool
		want     gateVerdict
	}{
		{"44", 10, false, gatePass},
		{"44", 10, true, gatePass},
		{"33", 9, true, gatePass},
		{"1", 10, false, gatePass},
		{"1", 9, false, gateLength}, // "+1 449-87-4100"
		{"421", 3, false, gateLength},
		{"41", 4, false, gateLength},
		{"1", 10, true, gateCode},  // NANP writes no "(0)": "+1(0)8 953 370"
		{"39", 10, true, gateCode}, // nor does Italy, whose 0 is part of the number
		{"553", 9, false, gateCode},
		{"16", 9, false, gateCode},
		{"", 9, false, gateCode},
		{"49", 14, false, gateCode}, // 16 digits: over the E.164 maximum
		{"49", 13, false, gatePass}, // 15
	} {
		if got := judge(c.code, c.national, c.trunk); got != c.want {
			t.Errorf("judge(%q, %d, %t) = %d, want %d", c.code, c.national, c.trunk, got, c.want)
		}
	}
}

func TestScanIntl(t *testing.T) {
	for _, c := range []struct {
		line    string
		want    string // the reading, "" for none
		code    string
		verdict gateVerdict
	}{
		{"+44 20 7946 0958", "+44 20 7946 0958", "44", gatePass},
		{"+442079460958", "+442079460958", "44", gatePass},
		{"+12972010095", "+12972010095", "1", gatePass},
		{"(+44) 20 7946 0948", "(+44) 20 7946 0948", "44", gatePass},
		{"+44 (0)20 7946 0372", "+44 (0)20 7946 0372", "44", gatePass},
		{"0044 (0)20 7946 0372", "0044 (0)20 7946 0372", "44", gatePass},
		{"+7 (495) 101-10-24", "+7 (495) 101-10-24", "7", gatePass},
		{"+49 30/23125417", "+49 30/23125417", "49", gatePass},
		{"+1-555-123-4567 x456", "+1-555-123-4567 x456", "1", gatePass},
		// A trailing group the number cannot hold is left out, at a space only.
		{"+44 20 7946 0958 2 lines", "+44 20 7946 0958", "44", gatePass},
		{"+33 1 99 00 47 18 19 20", "+33 1 99 00 47 18", "33", gatePass},
		// Never cut before "-", "." or "/": the greedy reading is returned with its verdict.
		{"+44 20 7946 0958-12", "+44 20 7946 0958-12", "44", gateLength},
		{"+553 274 123 784", "+553 274 123 784", "", gateCode},
		{"+16 338 705 681", "+16 338 705 681", "", gateCode},
		{"00421337", "00421337", "421", gateLength},
		{"000104.66", "000104.66", "", gateCode},
		{"+1(0)8 953 370", "+1(0)8 953 370", "1", gateCode},
		// Seven digits after +1 is a length the table lists (Canada's 310-NNNN), so the gate passes
		// "+1130 2010"; it is refused as a new reading for its glued code (TestGluedCodeIsNotANewReading).
		{"+1130 2010", "+1130 2010", "1", gatePass},
		{"(+44 20 7946 0958)", "", "", gatePass}, // "(+" not closed after the code: read from the '+'
		{"+", "", "", gatePass},
	} {
		end, num, ok := scanIntl(c.line, 0)
		got := ""
		if ok {
			got = c.line[:end]
		}
		if got != c.want || (ok && (num.code != c.code || num.verdict != c.verdict)) {
			t.Errorf("scanIntl(%q) = %q code %q verdict %d, want %q code %q verdict %d",
				c.line, got, num.code, num.verdict, c.want, c.code, c.verdict)
		}
	}
}

func TestJudgeIntlTextAgreesWithTheScanner(t *testing.T) {
	for _, text := range []string{
		"+44 20 7946 0958", "+442079460958", "(+44) 20 7946 0948", "+44 (0)20 7946 0372",
		"0044 (0)20 7946 0372", "+7 (495) 101-10-24", "+1-555-123-4567 x456", "+553 274 123 784",
		"00421337", "000104.66", "+1 449-87-4100", "00493682185944899873",
	} {
		end, scanned, ok := scanIntl(text, 0)
		if !ok || end != len(text) {
			t.Fatalf("scanIntl(%q) did not read the whole text", text)
		}
		if judged := judgeIntlText(text); judged.code != scanned.code || judged.verdict != scanned.verdict {
			t.Errorf("%q: judgeIntlText %+v, scanIntl %+v", text, judged, scanned)
		}
	}
}

func TestClassifyBoundary(t *testing.T) {
	for _, c := range []struct {
		line string
		want boundary
	}{
		{"+44", boundaryLegacy},
		{"x +44", boundaryLegacy},
		{"a,+44", boundaryLegacy},
		{"(+44", boundaryOpen},
		{"[+44", boundaryOpen},
		{"a/+44", boundaryOpen},
		{"Tel:+44", boundaryPhone},
		{`<a href="tel:+44`, boundaryPhone},
		{"TEL;TYPE=work,voice:+44", boundaryPhone},
		{"item1.TEL:+44", boundaryPhone},
		{`TEL;TYPE="voice,cell":tel:+44`, boundaryPhone},
		{"phone=+44", boundaryPhone},
		{"Telefon:+44", boundaryPhone},
		{"Téléphone:+44", boundaryPhone},
		{"work-mobile:+44", boundaryPhone},
		{"id:+44", boundaryRefuse},
		{"trace_id=+44", boundaryRefuse},
		{"token=+44", boundaryRefuse},
		{"bytes_delta:+44", boundaryUnlabelled},
		{"m=+44", boundaryUnlabelled},
		{":+44", boundaryUnlabelled},
		{"x+44", boundaryRefuse},
		{"5+44", boundaryRefuse},
		{"-+44", boundaryRefuse},
	} {
		s := strings.LastIndexByte(c.line, '+')
		if got := classifyBoundary(c.line, s); got != c.want {
			t.Errorf("classifyBoundary(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}

func TestDecimalShaped(t *testing.T) {
	for text, want := range map[string]bool{
		"+9252.619193895":     true,
		"+92.619193895":       true,
		"+49.78461-159.03771": true,
		"+44.20.7946.0958":    false,
		"+1 415.555.0123":     false,
		"+44 20 7946 0958":    false,
		"+49.87.02.966":       false,
		"+44-20-7946-0958":    false,
	} {
		if got := decimalShaped(text); got != want {
			t.Errorf("decimalShaped(%q) = %t, want %t", text, got, want)
		}
	}
}

// TestGluedCodeIsNotANewReading: a grouped number whose code is not a group of its own is how a time
// zone offset beside a year reads ("Sep 2010 +1130 2010" in time/format_test.go was MEDIUM on a
// draft of this change), never how E.123 writes an international number. An unseparated number
// still reads its code off the front.
func TestGluedCodeIsNotANewReading(t *testing.T) {
	_, num, ok := scanIntl("+1130 2010", 0)
	if !ok || !num.glued {
		t.Fatalf("scanIntl(+1130 2010) glued=%t ok=%t, want a glued reading", num.glued, ok)
	}
	if _, num, _ := scanIntl("+442079460627", 0); num.glued {
		t.Errorf("an unseparated number is not glued")
	}
	if _, num, _ := scanIntl("+44 20 7946 0958", 0); num.glued {
		t.Errorf("a separated code is not glued")
	}
	for _, line := range []string{"Sep 2010 +1130 2010", "offset +0530 2024 applied"} {
		if ms := phoneFindings(t, line); len(ms) > 0 {
			t.Errorf("%q: want no finding, got %s", line, describe(ms))
		}
	}
}

// TestCountryFormatHandlesEveryPattern: countryFormat has a case for the country of every pattern
// the validator reports with, so no pattern falls through to "not checked".
func TestCountryFormatHandlesEveryPattern(t *testing.T) {
	v := NewValidator()
	handled := map[string]bool{"US/CA": true, "UK": true, "International": true, "Europe": true, "Mobile": true}
	patterns := append(append([]phonePattern{}, v.patterns...), intlGrammarPattern)
	for _, p := range patterns {
		if !handled[p.country] {
			t.Errorf("pattern %s has country %q, which countryFormat does not handle", p.name, p.country)
		}
	}
}

// TestPatternIndexes pins the indexes international.go uses to the patterns they name.
func TestPatternIndexes(t *testing.T) {
	v := NewValidator()
	for idx, name := range map[int]string{
		patternUSStandard:            "US_Standard",
		patternUKStandard:            "UK_Standard",
		patternUSWithExtension:       "US_With_Extension",
		patternUSTollFreeParentheses: "US_TollFree_Parentheses",
	} {
		if v.patterns[idx].name != name {
			t.Errorf("patterns[%d] is %s, want %s", idx, v.patterns[idx].name, name)
		}
	}
}

// TestFormattedTollFreeNeedsCodeOne: a NANP toll-free area code is evidence only in a NANP number.
// "+86 6688 4965" is ten digits starting 866 and was credited as toll-free.
func TestFormattedTollFreeNeedsCodeOne(t *testing.T) {
	for text, want := range map[string]bool{
		"1-800-201-0001":   true,
		"+1 800 201 0001":  true,
		"(888) 201-0001":   true,
		"+86 6688 4965":    false,
		"(+86) 6688 4965":  false,
		"+44 800 201 0001": false,
	} {
		if got := formattedTollFree(text); got != want {
			t.Errorf("formattedTollFree(%q) = %t, want %t", text, got, want)
		}
	}
}

// TestCountryLabels: NANP and the UK keep the labels the national patterns give them; every other
// code reports its main region; a non-geographic code reads International.
func TestCountryLabels(t *testing.T) {
	for code, want := range map[string]string{"1": "US/CA", "44": "UK", "39": "IT", "7": "RU", "800": "International", "553": "Unknown"} {
		if got := countryLabelForCode(code); got != want {
			t.Errorf("countryLabelForCode(%q) = %q, want %q", code, got, want)
		}
	}
}

// TestGateCapsMainsFindingsNeverRemovesThem: the gate's demotion of a value main reports is a
// ceiling, published so the document bridge cannot lift it, with the country check recorded false.
func TestGateCapsMainsFindingsNeverRemovesThem(t *testing.T) {
	ms := phoneFindings(t, "+553 274 123 784")
	if len(ms) != 1 {
		t.Fatalf("want one finding, got %s", describe(ms))
	}
	m := ms[0]
	if m.Confidence != e164GateCeiling || m.Metadata[confidenceCeilingKey] != e164GateCeiling {
		t.Errorf("confidence %.0f ceiling %v, want %.0f published", m.Confidence, m.Metadata[confidenceCeilingKey], e164GateCeiling)
	}
	if checks, _ := m.Metadata["validation_checks"].(map[string]bool); checks["valid_country"] {
		t.Errorf("valid_country is true for an unassigned code: %v", checks)
	}
	// The unlabelled ':' cap records why it applied.
	ms = phoneFindings(t, "bytes_delta:+299192121")
	if len(ms) != 1 {
		t.Fatalf("want one finding, got %s", describe(ms))
	}
	if checks, _ := ms[0].Metadata["validation_checks"].(map[string]bool); checks["phone_label_recognized"] || len(checks) == 0 {
		t.Errorf("want phone_label_recognized=false, got %v", checks)
	}
}
