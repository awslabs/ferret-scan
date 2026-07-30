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
		{"uuid driver license D1234567", true},

		// Marker after the label: not this half's business.
		{"Driver License Number: D1234567, road test scheduled", false},
		{"DL: D1234567 -- vision test passed", false},
		{"DL: D1234567 (placeholder)", false},

		// Clean labelled lines.
		{"Driver License Number: D1234567", false},
		{"DL: D1234567 issued CA", false},

		// No recognizable label form: fall back to the old conservative rule so
		// an unlabelled line with a marker is still suppressed.
		{"serial D1234567 test value", true},
		{"serial D1234567 issued", false},
	}

	for _, c := range cases {
		if got := markerBeforeLabel(c.line); got != c.want {
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
