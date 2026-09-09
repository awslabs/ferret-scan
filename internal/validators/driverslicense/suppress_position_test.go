// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// realRecordLines are labelled licence numbers on lines that also contain a
// test/placeholder keyword in ordinary DMV, HR or lab vocabulary. Every one of
// these reported NOTHING before the suppression rule was made positional.
//
// The consequence is a leak, not a scoring nit: only reported findings reach the
// redactor, and a file with no findings has no redacted output written at all,
// so the licence number survived in cleartext.
var realRecordLines = []string{
	"Driver License Number: D1234567, road test scheduled 2026-08-01",
	"Driver License Number: D1234567 -- vision test passed",
	"Driver License Number: D1234567 for the sample collection unit",
	"DL: D1234567 issued CA, demo vehicle assigned",
	"Applicant DL: D1234567 -- retest required in 30 days",
	"Driver License Number: D1234567; hearing test waived",
	"DL D1234567 passed the practical test on 2026-06-02",
	"license number: D1234567, urine sample chain of custody",
	"Driver License Number: D1234567, drug test negative",
	"Driver License Number: D1234567 -- DOT physical and drug test on file",
	"DL: D1234567, CDL skills test appointment 08/14",
	"license number: D1234567 (CA) breath sample refused",
	"Driver License Number: D1234567 issued 2019, road test waiver granted",
	"Driver License Number: D1234567 for demo day shuttle driver",
	"driver license D1234567 assigned to the testing fleet",
}

// testDataLines are genuine test/placeholder values. The keyword modifies the
// licence itself — it sits before the label, or opens an aside on the value — and
// these must stay unreported.
var testDataLines = []string{
	"test DL: D1234567",
	"example driver license D1234567",
	"sample license number: D1234567",
	"DL: D1234567 placeholder value",
	"mock DL D1234567 for demo",
	"DL: D1234567 -- test record do not use",
	"fake dl number D1234567",
	"driver license D1234567 (example only)",
	"DL: D1234567 // sample data",
	"demo account driver license D1234567",
	"DL: D1234567 <- example value",
	"driver license D1234567 [test data]",
	"# sample: driver license D1234567",
	"DL: D1234567 fake",
	"placeholder driver license D1234567",
	"DL: D1234567 -- mock up only",
	"uuid driver license D1234567",
}

// TestRealLicenceNearTestVocabularyIsReported is the leak this file exists for.
func TestRealLicenceNearTestVocabularyIsReported(t *testing.T) {
	v := NewValidator()

	for _, line := range realRecordLines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "records.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("a labelled licence was deleted by a test-vocabulary keyword "+
					"elsewhere on the line; an unreported value is never redacted.\nline: %s", line)
			}
		})
	}
}

// TestGenuineTestDataStaysUnreported is the other direction, and the constraint
// that makes the fix acceptable: widening recall must not start reporting sample
// data. An example value should stay undetected because it is not real.
func TestGenuineTestDataStaysUnreported(t *testing.T) {
	v := NewValidator()

	for _, line := range testDataLines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "fixtures.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("genuine test data was reported as a real licence: %s\ngot %d match(es)",
					line, len(matches))
			}
		})
	}
}

// TestSuppressionIsPositionalNotLineGlobal pins the specific defect: the old
// rule used containsKeyword over the whole line, so a keyword arbitrarily far
// from the value killed the finding just as effectively as an adjacent one.
func TestSuppressionIsPositionalNotLineGlobal(t *testing.T) {
	v := NewValidator()

	// 400 characters of filler between the licence and the keyword.
	line := "Driver License Number: D1234567 issued CA " + strings.Repeat("x ", 200) + "(test)"

	matches, err := v.ValidateContent(line, "records.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("a keyword 400 characters away still deleted the finding; the " +
			"suppression is line-global rather than positional")
	}
}

// TestMarkerBeforeLabel covers the per-line half of the rule directly, including
// the no-label fallback that must stay conservative.
func TestMarkerBeforeLabel(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		// Marker attached to the label.
		{"test DL: D1234567", true},
		{"example driver license D1234567", true},
		{"sample license number: D1234567", true},
		{"placeholder driver license D1234567", true},
		// "uuid" is deliberately NOT here. It is an identifierTypeMarker, not a provenance marker: it
		// says the VALUE is a different kind of identifier, so it suppresses wherever it sits and is
		// handled by markerModifiesLabel rather than by this positional half. The suppression it
		// provides is asserted in TestIdentifierTypeMarkerSuppressesRegardlessOfPosition below, and
		// end to end at 0 findings — moved, not dropped.

		// Marker after the label: not this half's business.
		{"Driver License Number: D1234567, road test scheduled", false},
		{"DL: D1234567 -- vision test passed", false},
		{"DL: D1234567 (placeholder)", false},

		// Clean labelled lines.
		{"Driver License Number: D1234567", false},
		{"DL: D1234567 issued CA", false},

		// No label ON THIS LINE: fall back to the old conservative rule so an unlabelled line with a
		// marker is still suppressed. Reachable only when the line carries no DL label at all, since
		// the label search now covers the same vocabulary that admits a line (#614).
		{"serial D1234567 test value", true},
		{"serial D1234567 issued", false},

		// #614: a label spelling outside the OLD 11-entry dlLabelForms list must be recognised, so a
		// marker AFTER it no longer suppresses. Every row here returned true before the fix — meaning
		// the licence was dropped and returned in cleartext — and the same words with a listed
		// spelling returned false, which is how the list drift was identified.
		{"license D1234567, road test scheduled", false},
		{"DMV D1234567, road test scheduled", false},
		{"driving license D1234567 vision test passed", false},
		{"operator license D1234567 breath sample collected", false},
		{"permit D1234567 drug test negative", false},
		{"driversLicense: D1234567 alice@example.com", false},
		{"drivers_license: D1234567 example.com", false},
	}

	for _, c := range cases {
		if got := markerBeforeLabel(c.line, NewValidator().positiveKeywords); got != c.want {
			t.Errorf("markerBeforeLabel(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestMarkerOpensAsideAfter covers the per-match half. The offset is the end of
// the value's span, which is what the caller passes.
func TestMarkerOpensAsideAfter(t *testing.T) {
	cases := []struct {
		line string
		val  string
		want bool
	}{
		// Marker opens an aside on the value.
		{"DL: D1234567 (placeholder)", "D1234567", true},
		{"DL: D1234567 // sample data", "D1234567", true},
		{"DL: D1234567 <- example value", "D1234567", true},
		{"driver license D1234567 [test data]", "D1234567", true},
		{"DL: D1234567 -- mock up only", "D1234567", true},
		{"DL: D1234567 fake", "D1234567", true},
		{"DL: D1234567 -- test record do not use", "D1234567", true},

		// A clause with its own subject follows: not an apposition.
		{"Driver License Number: D1234567, drug test negative", "D1234567", false},
		{"DL: D1234567 -- vision test passed", "D1234567", false},
		{"DL: D1234567 issued CA, demo vehicle assigned", "D1234567", false},

		// Nothing after the value at all.
		{"DL: D1234567", "D1234567", false},

		// #614: a marker word that is part of a DOTTED or @-JOINED token is a hostname or address
		// component, not an apposition. Every row here returned true before the fix, dropping the
		// licence and returning it in cleartext. RFC 2606 is incidental — `demo.com` and
		// `status.mock.acme.io` are not reserved names and behaved identically, which is why the fix
		// keys on the token shape rather than on a list of reserved domains.
		{"license D1234567 example.com", "D1234567", false},
		{"license D1234567 example.org", "D1234567", false},
		{"license D1234567 demo.com", "D1234567", false},
		{"license D1234567 status.mock.acme.io", "D1234567", false},
		{"license D1234567 alice@example.com", "D1234567", false},
		{"license D1234567 test.internal.corp", "D1234567", false},

		// NON-VACUITY for that guard: a marker followed by a dot that ENDS A SENTENCE is still an
		// apposition, so the guard must key on a dot followed by a WORD byte, not on any dot. Without
		// this pair the guard could be widened to "any following dot" and nothing would notice.
		{"DL: D1234567 (sample).", "D1234567", true},
		{"DL: D1234567 fake.", "D1234567", true},
	}

	for _, c := range cases {
		idx := strings.Index(c.line, c.val)
		if idx < 0 {
			t.Fatalf("test setup: %q not in %q", c.val, c.line)
		}
		if got := markerOpensAsideAfter(c.line, idx+len(c.val)); got != c.want {
			t.Errorf("markerOpensAsideAfter(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestMarkerOpensAsideAfterBoundsAreSafe feeds out-of-range offsets, since the
// caller computes them from span arithmetic.
func TestMarkerOpensAsideAfterBoundsAreSafe(t *testing.T) {
	line := "DL: D1234567 (test)"
	for _, off := range []int{-5, -1, len(line), len(line) + 1, len(line) + 100} {
		if markerOpensAsideAfter(line, off) {
			t.Errorf("offset %d returned true; out-of-range offsets must be inert", off)
		}
	}
}

// TestPositionalSuppressionStaysLinear guards the hoist. The line-global half
// stays a per-line invariant; only the O(1) aside check runs per match. If the
// positional rule were evaluated per match over the whole line, scanning would
// become O(matches x line length) — the single-long-line CPU-exhaustion shape
// dos_test.go already guards for the rest of this validator.
//
// Asserts on match-count growth with a non-vacuity floor rather than wall-clock.
func TestPositionalSuppressionStaysLinear(t *testing.T) {
	v := NewValidator()

	build := func(n int) string {
		var sb strings.Builder
		sb.WriteString("driver license")
		for i := 0; i < n; i++ {
			sb.WriteString(" D")
			sb.WriteString(pad7(i))
		}
		return sb.String()
	}

	var prev int
	for _, n := range []int{100, 200, 400} {
		matches, err := v.ValidateContent(build(n), "big.txt")
		if err != nil {
			t.Fatalf("ValidateContent at n=%d: %v", n, err)
		}
		if len(matches) == 0 {
			t.Fatalf("non-vacuity floor: zero findings at n=%d, so this test would "+
				"pass regardless of the suppression's cost", n)
		}
		if len(matches) <= prev {
			t.Errorf("findings did not grow with input at n=%d: got %d, previous %d",
				n, len(matches), prev)
		}
		prev = len(matches)
	}
}

// TestAnalyzeContextRejectsMarkerModifiedLabel keeps the scoring contract
// visible: when the rule fires the impact must still cancel the base score, so
// the emit gate (confidence <= 0) drops the finding.
func TestAnalyzeContextRejectsMarkerModifiedLabel(t *testing.T) {
	v := NewValidator()

	suppressed := v.AnalyzeContext("D1234567", detector.ContextInfo{
		FullLine: "test DL: D1234567",
	})
	if suppressed > -20 {
		t.Errorf("marker-modified label scored %v, want <= -20 so base 20 lands at 0", suppressed)
	}

	kept := v.AnalyzeContext("D1234567", detector.ContextInfo{
		FullLine: "Driver License Number: D1234567, road test scheduled",
	})
	if kept <= 0 {
		t.Errorf("real labelled licence scored %v, want a positive impact", kept)
	}
}

func pad7(i int) string {
	s := "0000000" + itoa7(i)
	return s[len(s)-7:]
}

func itoa7(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestIdentifierTypeMarkerSuppressesRegardlessOfPosition guards the class split #614 introduced.
//
// strongSuppressKeywords used to mix two kinds of marker, and its own comment described both:
// "test/placeholder data OR definitive non-DL identifiers". Position matters for the first kind — that
// is the whole point of the positional rule — and is irrelevant to the second, because "License UUID
// AB123456 generated" is a UUID whatever the word order.
//
// Conflating them is what made the #614 fix LOOK like a precision regression: once "license" was
// recognised as a label at offset 0, a trailing "uuid" was no longer "before the label" and stopped
// suppressing, failing TestAdversarial_CrossValidatorConfusion. Splitting the classes fixed that
// without narrowing the leak fix, so this test exists to stop the two being merged again.
func TestIdentifierTypeMarkerSuppressesRegardlessOfPosition(t *testing.T) {
	kws := NewValidator().positiveKeywords

	// Before, after, and with no label at all — every position must suppress.
	for _, line := range []string{
		"uuid driver license D1234567",
		"License UUID AB123456 generated",
		"driver license D1234567 uuid",
		"guid driver license D1234567",
		"driver license D1234567 (guid)",
	} {
		if !markerModifiesLabel(line, "D1234567", kws) && !markerModifiesLabel(line, "AB123456", kws) {
			t.Errorf("markerModifiesLabel(%q) = false; an identifier-type marker must suppress wherever "+
				"it appears, because it is a claim about what the VALUE is, not about whether the data "+
				"is real", line)
		}
	}

	// NON-VACUITY: the same shape with a PROVENANCE marker after the label must NOT suppress, or this
	// test would pass with the class distinction removed and every marker suppressing everywhere —
	// which is the leak #614 is about.
	for _, line := range []string{
		"driver license D1234567, road test scheduled",
		"license D1234567 vision test passed",
	} {
		if markerModifiesLabel(line, "D1234567", kws) {
			t.Errorf("markerModifiesLabel(%q) = true; a provenance marker AFTER the label must not "+
				"suppress — that is the #614 leak", line)
		}
	}
}
