// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Part 1 of #888: the two passport-keyword boosts compared text in two different
// letter cases, so they only ever fired for a lower-case match beside a lower-case
// label.
//
//   - The proximity boost (+25/+15/+8) searched for the ORIGINAL-CASE match in the
//     LOWERED line. "GK123456" is never a substring of a lowered line, so every
//     letter-bearing passport number got 0 while a 9-digit number in the same
//     sentence got 25.
//   - The same-line 1.5x keyword boost searched for the LOWERED keyword in the
//     ORIGINAL-CASE line, so "Passport" and "PASSPORT" earned 1x where "passport"
//     earned 1.5x.
//
// Measured on main before the fix: of the 15 sentence pairs below, the
// letter-bearing number's context_impact was 10-20 below its 9-digit twin's in 10
// and the number was not reported at all in 4.

// contextFor builds the ContextInfo the hot path builds: the whole line plus the
// +/-50 bytes either side of the match's first occurrence.
func contextFor(line, match string) detector.ContextInfo {
	i := strings.Index(line, match)
	start, end := i-50, i+len(match)+50
	if start < 0 {
		start = 0
	}
	if end > len(line) {
		end = len(line)
	}
	return detector.ContextInfo{
		FullLine:   line,
		BeforeText: line[start:i],
		AfterText:  line[i+len(match) : end],
	}
}

// TestProximityBoostIsCaseBlind pins the first mechanism directly: the boost for a
// value right after a passport label must not depend on the letter case of either
// the value or the label. On main the uppercase values score 0 here and the
// lowercase one 25, which is the whole of the defect.
func TestProximityBoostIsCaseBlind(t *testing.T) {
	v := NewValidator()
	for _, m := range []string{"C12345678", "c12345678", "GK123456", "gk123456", "Gk123456", "100000001"} {
		for _, label := range []string{"passport", "Passport", "PASSPORT"} {
			got := v.calculatePassportProximity(m, detector.ContextInfo{FullLine: label + ": " + m})
			if got != 25 {
				t.Errorf("calculatePassportProximity(%q) on %q = %v, want 25: the value sits two "+
					"bytes after the label, whatever the case of either", m, label+": "+m, got)
			}
		}
	}
}

// TestAnalyzeContextIsCaseBlind is the property behind both mechanisms: across every
// combination of value case and label case the whole context score is the same. The
// sentences carry no negative keyword, whose same-line check stays case-sensitive on
// purpose (it is a suppressor, see analyzeContext).
func TestAnalyzeContextIsCaseBlind(t *testing.T) {
	v := NewValidator()
	templates := []string{
		"%L %M",
		"%L Number: %M",
		"She showed %L %M at the border.",
		"The holder's %L %M was checked at the gate.",
		"He renewed his %L %M last spring.",
		"Please send a scan of %L %M before Friday.",
	}
	values := []string{"C12345678", "GK123456", "YA1234567", "DE1234567"}
	for _, tpl := range templates {
		for _, val := range values {
			render := func(label, m string) (string, string) {
				line := strings.ReplaceAll(strings.ReplaceAll(tpl, "%L", label), "%M", m)
				return line, m
			}
			refLine, refM := render("passport", strings.ToLower(val))
			want := v.AnalyzeContext(refM, contextFor(refLine, refM))
			for _, label := range []string{"passport", "Passport", "PASSPORT"} {
				for _, m := range []string{val, strings.ToLower(val), val[:1] + strings.ToLower(val[1:])} {
					line, mm := render(label, m)
					if got := v.AnalyzeContext(mm, contextFor(line, mm)); got != want {
						t.Errorf("AnalyzeContext(%q) on %q = %v, want %v (the score of %q): the "+
							"letter case of the value or the label moved the context score",
							mm, line, got, want, refLine)
					}
				}
			}
		}
	}
}

// TestLetterBearingNumberScoresLikeItsTwin runs the 15 pairs from #888 through the
// real scan. Each line is scanned alone, then again with its value replaced by the
// 9-digit 100000001. The letter-bearing value must be reported, and its context
// impact must equal its twin's: the only remaining gap is the format score (a
// non-ISO prefix such as GK or YA costs 15), which is not about context.
func TestLetterBearingNumberScoresLikeItsTwin(t *testing.T) {
	pairs := []struct{ line, value string }{
		{"passport GK123456", "GK123456"},
		{"Passport GK123456", "GK123456"},
		{"The holder's passport GK123456 was checked at the gate.", "GK123456"},
		{"Please send a scan of passport K12345678 before Friday.", "K12345678"},
		{"He renewed his passport YA1234567 last spring.", "YA1234567"},
		{"Traveller passport DE1234567, flight BA117 to Toronto.", "DE1234567"},
		{"Passport Number: GK123456", "GK123456"},
		// The four main did not report at all.
		{"She showed passport GK123456 at the border.", "GK123456"},
		{"Customer passport GK123456 on booking", "GK123456"},
		{"Please confirm passport GK123456 for the reservation.", "GK123456"},
		{"passport GK123456 entry", "GK123456"},
		{"Booking 7QX2LM: passport K12345678 verified at check-in.", "K12345678"},
		{"Account holder passport YA1234567 updated today.", "YA1234567"},
		{"Updated the passport number on the account to GK123456.", "GK123456"},
		{"Guest passport DE1234567 recorded at reception.", "DE1234567"},
	}
	v := NewValidator()
	impact := func(line, value string) (float64, bool) {
		t.Helper()
		got, err := v.ValidateContent(line+"\n", "/test/pair.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range got {
			if m.Text == value {
				ci, _ := m.Metadata["context_impact"].(float64)
				return ci, true
			}
		}
		return 0, false
	}
	for _, p := range pairs {
		twinLine := strings.Replace(p.line, p.value, "100000001", 1)
		twin, ok := impact(twinLine, "100000001")
		if !ok {
			t.Fatalf("control %q is not reported: the twin is what the letter-bearing value is "+
				"measured against, so the comparison below means nothing", twinLine)
		}
		got, ok := impact(p.line, p.value)
		if !ok {
			t.Errorf("%q: %s is not reported, while its 9-digit twin is (context_impact %v)",
				p.line, p.value, twin)
			continue
		}
		if got != twin {
			t.Errorf("%q: context_impact %v, its 9-digit twin's is %v: the context score "+
				"depends on whether the number contains a letter", p.line, got, twin)
		}
	}
}
