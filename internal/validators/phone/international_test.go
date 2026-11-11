// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The tests of #889 that drive only ValidateContent and GetCheckInfo, so the same file compiles
// against the parent commit and shows what it reported there. The values are those of the issue:
// regulator drama ranges (UK 020 7946 0xxx, 0161 496 0xxx; AU 02 5550 4xxx; FR 01 99 00 xx xx; DE 030
// 23125xxx), NANP area 297, and otherwise patterned 1010... digits ending in the case number.

// phoneFindings returns the findings ValidateContent reports for content.
func phoneFindings(t *testing.T, content string) []detector.Match {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, "intl.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	return ms
}

func describe(ms []detector.Match) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, fmt.Sprintf("%q %.0f %v %v", m.Text, m.Confidence, m.Metadata["pattern_name"], m.Metadata["country"]))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// wantOneWhole asserts that content reports exactly one finding and that it is want.
func wantOneWhole(t *testing.T, content, want string) detector.Match {
	t.Helper()
	ms := phoneFindings(t, content)
	if len(ms) != 1 || ms[0].Text != want {
		t.Fatalf("%q: want one finding %q, got %d: %s", content, want, len(ms), describe(ms))
	}
	return ms[0]
}

// tableA are the issue's contexts: a number glued to a label, a tel: URI, a vCard TEL value, a
// bracket or an "=". Main reported nothing for every one of them but the last, whose "+1" it left
// outside the finding.
var tableA = [][2]string{
	{"Tel:+44 20 7946 0519", "+44 20 7946 0519"},
	{"Phone:+44 20 7946 0815", "+44 20 7946 0815"},
	{"Telefon:+49 30 23125417", "+49 30 23125417"},
	{`<a href="tel:+442079460627">call</a>`, "+442079460627"},
	{"TEL;TYPE=work,voice:+44 20 7946 0731", "+44 20 7946 0731"},
	{"TEL;TYPE=home:(297) 201-0010", "(297) 201-0010"},
	{"Tel:(297) 201-0011", "(297) 201-0011"},
	{"(+44) 20 7946 0948", "(+44) 20 7946 0948"},
	{"Ana Lima (+44 20 7946 0164)", "+44 20 7946 0164"},
	{"[+44 20 7946 0283]", "+44 20 7946 0283"},
	{"phone=+442079460391", "+442079460391"},
	{"Tel:+1 297 201 0016", "+1 297 201 0016"},
}

// tableB are the issue's international display forms, the truncations among them included: a "(0)"
// trunk slot, a bracketed area code, one-digit areas, digit pairs, five-digit groups, "/". Each is a
// whole number; main reported nothing for all but one, and that one ("+44 (0)161 496 0815") as its
// tail, labelled a NANP number.
var tableB = []string{
	"+44 (0)20 7946 0372", "+44(0)20 7946 0372", "+49 (0)30 23125417", "+33 (0)1 99 00 47 18",
	"+41 (0)44 101 10 21", "0044 (0)20 7946 0372", "+44 (0)161 496 0815", "+7 (495) 101-10-24",
	"+55 (11) 91010-1025", "+52 (55) 1010 1026", "+44 (20) 7946 0372", "(020) 7946 0372",
	"+33 1 99 00 47 18", "+33 6 39 98 52 07", "+34 91 101 10 31", "+41 44 101 10 32",
	"+41 79 101 10 33", "+32 2 101 10 34", "+353 1 101 1035", "+61 2 5550 4713", "+81 3-1010-1037",
	"+82 2 101 1038", "+46 8 101 101 39", "+47 22 10 10 40", "+48 22 101 10 41", "+7 495 101 10 42",
	"+90 212 101 10 43", "+971 4 101 1044", "+49 30/23125417", "0033 1 99 00 47 18",
	"0034 91 101 10 47", "+55 11 91010 1048", "+55 11 91010-1049", "+55 11 91010-1050",
	"+49 30 23125-417",
}

// tableD are numbers main covered but cut: their "+1"/"1-" prefix or extension outside the finding,
// or (the last) split in two.
var tableD = []string{
	"+1 297 201 0052", "+1-297-201-0053", "+1 (297) 201-0054", "1-888-201-0055",
	"297-201-0056 ext 27", "+39 310 101 1057", "+44 207 946 0372",
}

func TestInternationalContextsAreOneWholeFinding(t *testing.T) {
	for _, c := range tableA {
		t.Run(c[0], func(t *testing.T) { wantOneWhole(t, c[0], c[1]) })
	}
}

func TestInternationalDisplayFormsAreOneWholeFinding(t *testing.T) {
	for _, shape := range append(append([]string{}, tableB...), tableD...) {
		for _, carrier := range []string{"%s", "Phone: %s", "Please call me at %s tomorrow."} {
			content := fmt.Sprintf(carrier, shape)
			t.Run(content, func(t *testing.T) { wantOneWhole(t, content, shape) })
		}
	}
}

// TestCountryComesFromTheCodeTable: main labelled both of these US/CA (or Unknown) because the
// pattern that claimed them was US_Dashed, on their tails.
func TestCountryComesFromTheCodeTable(t *testing.T) {
	for _, c := range []struct{ line, text, country string }{
		{"+39 310 101 1057", "+39 310 101 1057", "IT"},
		{"+44 (0)161 496 0815", "+44 (0)161 496 0815", "UK"},
		{"+33 1 99 00 47 18", "+33 1 99 00 47 18", "FR"},
		{"Tel:+1 297 201 0016", "+1 297 201 0016", "US/CA"},
	} {
		m := wantOneWhole(t, c.line, c.text)
		if got := m.Metadata["country"]; got != c.country {
			t.Errorf("%q: country %v, want %q from the E.164 table", c.line, got, c.country)
		}
	}
}

// TestControlsAreUnchanged: the issue's controls, and the international finding main reports on its
// "00" control line. Text, confidence, pattern and country are what main reported.
func TestControlsAreUnchanged(t *testing.T) {
	for _, c := range []struct {
		line, text, pattern, country string
		conf                         float64
	}{
		{"Phone: +44 20 7946 0372", "+44 20 7946 0372", "International_Plus", "International", 100},
		{"+49 30 23125417", "+49 30 23125417", "International_Plus", "International", 95},
		{"(297) 201-0003", "(297) 201-0003", "US_Standard", "US/CA", 85},
		{"Tel:297-201-0004", "297-201-0004", "US_Dashed", "US/CA", 100},
		{"Call 0044 20 7946 0958 after 6pm", "0044 20 7946 0958", "International_00", "International", 100},
		// The golden corpus's "call +1 449-87-4100" (overlap_groups_render_once): nine digits after
		// +1 is a length NANP does not have, and "call" outweighs the length table for a value main
		// already reports, so it keeps everything main gave it.
		{"call +1 449-87-4100", "+1 449-87-4100", "International_Plus", "International", 100},
	} {
		m := wantOneWhole(t, c.line, c.text)
		if m.Confidence != c.conf || m.Metadata["pattern_name"] != c.pattern || m.Metadata["country"] != c.country {
			t.Errorf("%q: got %.0f %v %v, want %.0f %s %s", c.line, m.Confidence, m.Metadata["pattern_name"],
				m.Metadata["country"], c.conf, c.pattern, c.country)
		}
	}
}

// coveredDigits reports, for each byte of line, whether some finding covers it. Findings are located
// left to right, which is unambiguous here: every line carries one number.
func coveredDigits(line string, ms []detector.Match) []bool {
	cov := make([]bool, len(line))
	from := 0
	for _, m := range ms {
		i := strings.Index(line[from:], m.Text)
		if i < 0 {
			i = strings.Index(line, m.Text)
			if i < 0 {
				continue
			}
		} else {
			i += from
		}
		for k := i; k < i+len(m.Text); k++ {
			cov[k] = true
		}
		from = i + len(m.Text)
	}
	return cov
}

// TestNoDigitOfAPhoneValueIsLeftUncovered is the redaction run of the issue in validator terms:
// redaction rewrites exactly the reported spans, so a digit outside every span is a digit left in
// cleartext. On main six of these lines had no finding at all and five a truncated one.
func TestNoDigitOfAPhoneValueIsLeftUncovered(t *testing.T) {
	for _, line := range []string{
		"Phone: 0033 1 99 00 47 18",
		"Phone: 0034 91 101 10 47",
		"Phone: +55 11 91010 1048",
		"Phone: +55 11 91010-1050",
		"Phone: +49 30 23125-417",
		"Phone: +1 297 201 0059",
		"Phone: +44 (0)161 496 0815",
		"Phone: +44 (0)20 7946 0372",
		"Phone: +33 1 99 00 47 18",
		"Tel:+44 20 7946 0519",
		"TEL;TYPE=work,voice:+44 20 7946 0111",
		"TEL;TYPE=cell:+1-297-201-0091",
		"TEL;TYPE=home:(297) 201-0092",
		"TEL:+33 1 99 00 47 19",
		"TEL;VALUE=uri;TYPE=home:tel:+44-20-7946-0222",
		`TEL;VALUE=uri;TYPE="voice,cell":tel:+1-297-201-0093`,
		`<p>Office: <a href="tel:+442079460333">+44 20 7946 0333</a></p>`,
		`<p>Sales: <a href="tel:+12972010094">call sales</a></p>`,
	} {
		ms := phoneFindings(t, line)
		cov := coveredDigits(line, ms)
		var left []string
		for i := 0; i < len(line); i++ {
			if line[i] >= '0' && line[i] <= '9' && !cov[i] {
				left = append(left, fmt.Sprintf("%c@%d", line[i], i))
			}
		}
		if len(left) > 0 {
			t.Errorf("%q: digits %v outside every finding %s -- redaction would leave them in cleartext", line, left, describe(ms))
		}
	}
}

// TestZeroZeroFormIsBounded: main reported "00" followed by 5 to 21 digits, "00" then "0" included.
// No calling code starts with 0, E.164 allows 15 digits after the prefix, and "421 337" leaves a
// Slovak number three digits long. Each is still reported, at LOW, so it is still redacted. A "00"
// decimal ("total 000104.66 EUR") was here too; since #938 it is not reported at all
// (TestCoordinateAndDecimalAreNotPhoneNumbers).
func TestZeroZeroFormIsBounded(t *testing.T) {
	for _, c := range [][2]string{
		{"row,00421337,active", "00421337"},
		{"Mon Jan _2 15:04:05,000 2006", "000 2006"},
		{"Order 00493682185944899873 shipped", "00493682185944899873"},
		{"Order 0001234 shipped", "0001234"},
		{"Order 00512345678901234567 shipped", "00512345678901234567"},
		{"Order 0091234567890123456 shipped", "0091234567890123456"},
	} {
		m := wantOneWhole(t, c[0], c[1])
		if m.Confidence > reservedFictionalCeiling {
			t.Errorf("%q: %q scored %.0f, want at most %.0f", c[0], m.Text, m.Confidence, reservedFictionalCeiling)
		}
	}
}

// TestGateDecoys are the issue's fourteen decoys: what a naive widening of the boundaries and groups
// reports. Only the bracketed Danish shape may exceed LOW (it is one); the three main reports are
// still reported, at LOW; the rest are not reported at all.
func TestGateDecoys(t *testing.T) {
	for _, c := range []struct {
		line   string
		report string // "" when nothing may be reported
		low    bool
	}{
		{"2026-11-07 08:10:00.123 +0000 UTC m=+9252.619193895", "", true},
		{"+553 274 123 784", "+553 274 123 784", true},
		{"+8 60 06 33 99 50", "", true},
		{"net change +16 338 705 681 SEK", "+16 338 705 681", true},
		{"pos=+57.42636-074.32963/", "", true},
		{"tag=+49.87.02.966", "+49.87.02.966", true},
		{"delta=+51490173", "", true},
		{"bytes_delta:+299192121", "+299192121", true},
		{"Order:+449766143", "+449766143", true},
		{"(+45) 3318 7742 total", "(+45) 3318 7742", false},
		{"score +6 (0) 686 477", "", true},
		{"f(x) = +1(0)8 953 370", "", true},
		{"git tag +2024.1.1 released", "", true},
		{"v6.9.15+00410257", "00410257", true},
	} {
		ms := phoneFindings(t, c.line)
		if c.report == "" {
			if len(ms) > 0 {
				t.Errorf("%q: want no finding, got %s", c.line, describe(ms))
			}
			continue
		}
		if len(ms) != 1 || ms[0].Text != c.report {
			t.Errorf("%q: want one finding %q, got %s", c.line, c.report, describe(ms))
			continue
		}
		if c.low && ms[0].Confidence > reservedFictionalCeiling {
			t.Errorf("%q: %q scored %.0f, want at most %.0f", c.line, c.report, ms[0].Confidence, reservedFictionalCeiling)
		}
	}
}

// TestBoundaryMatrix: an international number reads the same behind every character a phone is
// written after, and its span is the number, never the context.
func TestBoundaryMatrix(t *testing.T) {
	shapes := []string{
		"+44 20 7946 0958", "+33 1 99 00 47 18", "+49 30 23125417", "+1 297 201 0016",
		"+55 11 91010-1050", "+44 (0)20 7946 0372", "+442079460627",
	}
	carriers := []string{
		"%s", "(%s)", "[%s]", "a/%s", "Tel:%s", "tel:%s", `<a href="tel:%s">x</a>`,
		"TEL;TYPE=cell:%s", "item1.TEL;TYPE=work:%s", "phone=%s", "Telefon: %s", `"phone": "%s"`,
	}
	for _, shape := range shapes {
		for _, carrier := range carriers {
			content := fmt.Sprintf(carrier, shape)
			t.Run(content, func(t *testing.T) {
				m := wantOneWhole(t, content, shape)
				if m.Confidence <= reservedFictionalCeiling {
					t.Errorf("%q: %q scored %.0f; a phone context must not cost it its band", content, shape, m.Confidence)
				}
			})
		}
	}
}

// TestDelimiterLabels: after ':' or '=', a phone label reads like its spaced twin, an identifier
// label refuses the number, and a word that is neither costs confidence, never the finding.
func TestDelimiterLabels(t *testing.T) {
	spaced := wantOneWhole(t, "Phone: +44 20 7946 0815", "+44 20 7946 0815")
	glued := wantOneWhole(t, "Phone:+44 20 7946 0815", "+44 20 7946 0815")
	if glued.Confidence != spaced.Confidence {
		t.Errorf("Phone:+44 ... scored %.0f, its spaced twin %.0f", glued.Confidence, spaced.Confidence)
	}
	for _, line := range []string{"id:+44 20 7946 0958", "token=+44 20 7946 0958", "session:+33 1 99 00 47 18"} {
		if ms := phoneFindings(t, line); len(ms) > 0 {
			t.Errorf("%q: an identifier label must refuse the value, got %s", line, describe(ms))
		}
	}
	for _, c := range [][2]string{{"ref:+44 20 7946 0958", "+44 20 7946 0958"}, {"x=+33 1 99 00 47 18", "+33 1 99 00 47 18"}} {
		m := wantOneWhole(t, c[0], c[1])
		if m.Confidence > reservedFictionalCeiling {
			t.Errorf("%q: an unrecognised label scored %.0f, want at most %.0f", c[0], m.Confidence, reservedFictionalCeiling)
		}
	}
}

// TestLetterGluedNumberIsWholeOrNothing: a number with a letter straight after it is an identifier's
// digits or a typo. A reading may not stop short of the letter and report the head: main reported
// "+44 20 7946" for the first line, which left "0958" in cleartext. Where main reported a piece, the
// whole number is reported in its place; where it reported nothing, nothing is.
func TestLetterGluedNumberIsWholeOrNothing(t *testing.T) {
	for _, c := range [][2]string{
		{"Phone: +44 20 7946 0958stored", "+44 20 7946 0958"},
		{"Tel:+33 1 99 00 47 18x", ""},
		{"m=+0.123456789", ""},
	} {
		ms := phoneFindings(t, c[0])
		if c[1] == "" {
			if len(ms) > 0 {
				t.Errorf("%q: want no finding, got %s", c[0], describe(ms))
			}
			continue
		}
		if len(ms) != 1 || ms[0].Text != c[1] {
			t.Errorf("%q: want the whole number %q or nothing, got %s", c[0], c[1], describe(ms))
		}
	}
}

// TestDocumentedExamplesAreWholeFindings: every phone number --help phone shows is one finding whose
// text is the whole example. This tests the binary's behaviour against its documentation, so a
// changed example that the validator does not read whole fails here. Main read none of
// "+33 1 42 34 56 78" and cut five others (the "+1 ", "1-" or "+1-" prefix, " ext 123", " x456") and
// split "+44 207 123 4567" in two.
func TestDocumentedExamplesAreWholeFindings(t *testing.T) {
	examples := 0
	for _, entry := range NewValidator().GetCheckInfo().Patterns {
		_, list, ok := strings.Cut(entry, ": ")
		if !ok || !strings.ContainsAny(list, "0123456789") {
			continue
		}
		for _, ex := range strings.Split(list, ", ") {
			examples++
			t.Run(ex, func(t *testing.T) { wantOneWhole(t, ex, ex) })
		}
	}
	if examples < 10 {
		t.Fatalf("only %d documented examples found in GetCheckInfo().Patterns; the help text changed shape", examples)
	}
}

// TestPhoneValidator_InternationalSingleLineDoSRegression is TestPhoneValidator_SingleLineDoSRegression
// for the readings #889 adds: one ~1 MiB line on which every number is a new reading after a label
// ("Tel:+44 ..."), a bracketed code, or a wider reading replacing main's truncated "00" one, all
// distinct, so neither main's dedup nor the repeat check shortcuts the resolver. On this fixture at
// 1, 2 and 4 MiB the validator's CPU grew 1.89x and 2.02x per doubling, main's 1.98x and 1.98x.
func TestPhoneValidator_InternationalSingleLineDoSRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}
	const targetBytes = 1 << 20
	var b strings.Builder
	b.Grow(targetBytes + 64)
	for i := 0; b.Len() < targetBytes; i++ {
		fmt.Fprintf(&b, "Tel:+44 20 7%03d %04d (+45) %04d %04d 0033 1 %02d %02d %02d %02d ",
			(i/10000)%1000, i%10000, (i/10000)%10000, i%10000,
			(i/1000000)%100, (i/10000)%100, (i/100)%100, i%100)
	}
	content := b.String()

	const ceiling = 5 * time.Second
	start := time.Now()
	matches, err := NewValidator().ValidateContent(content, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if len(matches) < 10000 {
		t.Fatalf("only %d findings on the dense line: the fixture no longer exercises the new readings", len(matches))
	}
	if raceEnabled {
		t.Logf("processed %d-byte single line, %d findings (timing assertion skipped under -race)", len(content), len(matches))
		return
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a %d-byte single line took %s, exceeding the %s ceiling (likely an O(n^2) regression in the widest-span pass)",
			len(content), elapsed, ceiling)
	}
	t.Logf("processed %d-byte single line in %s, %d findings", len(content), elapsed, len(matches))
}

// TestSpanInvariant over every recall line above: on a line no two findings overlap, and none ends
// right before a digit or before '-', '.' or '/' and a digit.
func TestSpanInvariant(t *testing.T) {
	var lines []string
	for _, c := range tableA {
		lines = append(lines, c[0])
	}
	for _, shape := range append(append([]string{}, tableB...), tableD...) {
		lines = append(lines, shape, "Phone: "+shape, "Please call me at "+shape+" tomorrow.", "call "+shape+" or "+shape)
	}
	for _, line := range lines {
		ms := phoneFindings(t, line)
		type span struct{ s, e int }
		var spans []span
		claimed := map[int]bool{}
		for _, m := range ms {
			// The first occurrence of the text no earlier finding claimed: findings come in the
			// validator's order, which is not the line's.
			s := -1
			for from := 0; ; {
				i := strings.Index(line[from:], m.Text)
				if i < 0 {
					break
				}
				if !claimed[from+i] {
					s = from + i
					break
				}
				from += i + 1
			}
			if s < 0 {
				t.Fatalf("%q: finding %q not located", line, m.Text)
			}
			claimed[s] = true
			e := s + len(m.Text)
			spans = append(spans, span{s, e})
			if e < len(line) {
				c := line[e]
				if c >= '0' && c <= '9' || (c == '-' || c == '.' || c == '/') && e+1 < len(line) && line[e+1] >= '0' && line[e+1] <= '9' {
					t.Errorf("%q: %q ends right before %q -- a truncated span", line, m.Text, line[e:])
				}
			}
		}
		for i := range spans {
			for j := range spans {
				if i != j && spans[i].s < spans[j].e && spans[j].s < spans[i].e {
					t.Errorf("%q: findings overlap: %s", line, describe(ms))
				}
			}
		}
	}
}

// TestARepeatOfAReplacedTextStaysCovered: main reports one finding per number on a line and relies
// on redaction's completeness sweep, which masks every occurrence of a reported text, for the
// repeats. When a wider reading replaces "297 201 0052", that text is no longer reported, so a bare
// repeat of it would be masked by nothing. The narrow finding is then kept beside the wide one.
func TestARepeatOfAReplacedTextStaysCovered(t *testing.T) {
	for _, line := range []string{
		"call +1 297 201 0052 or 297 201 0052",
		"0033 1 99 00 47 18 then 0033 1 99 00",
	} {
		ms := phoneFindings(t, line)
		cov := coveredDigits(line, ms)
		texts := map[string]bool{}
		for _, m := range ms {
			texts[m.Text] = true
		}
		for i := 0; i < len(line); i++ {
			if line[i] < '0' || line[i] > '9' || cov[i] {
				continue
			}
			swept := false
			for text := range texts {
				for from := 0; ; {
					j := strings.Index(line[from:], text)
					if j < 0 {
						break
					}
					if from+j <= i && i < from+j+len(text) {
						swept = true
					}
					from += j + 1
				}
			}
			if !swept {
				t.Errorf("%q: digit at %d is in no reported span and no occurrence of a reported text %s", line, i, describe(ms))
			}
		}
	}
}
