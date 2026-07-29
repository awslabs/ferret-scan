// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestClinicalSampleVocabularyKeepsTheDOB is the leak this file exists for.
//
// The disqualifier check fired on "sample" appearing anywhere in the context,
// with no positional bound, so ordinary clinical vocabulary deleted a labelled
// date of birth. Only reported findings are handed to the redactor, and a file
// with no findings has no redacted output written at all, so the DOB stayed in
// cleartext.
func TestClinicalSampleVocabularyKeepsTheDOB(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Patient DOB: 03/14/1987, blood sample collected at intake",
		"date of birth 03/14/1987, urine sample chain of custody",
		"Patient DOB: 03/14/1987, blood collected at intake",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "chart.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("clinical vocabulary elsewhere on the line deleted a labelled "+
					"date of birth: %s", line)
			}
		})
	}
}

// TestSyntheticDOBStaysSuppressed is the other direction. Widening recall must
// not start reporting fixture data: a marker that modifies the LABEL still
// suppresses.
func TestSyntheticDOBStaysSuppressed(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Test DOB: 01/01/2000",
		"sample patient dob 3/14/87",
		"example date of birth 03/14/1987",
		"DOB: 03/14/1987 (test)",
		"dob 3/14/87 -- sample data",
		"mock DOB: 01/01/2000",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "fixtures.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("synthetic data was reported as a real DOB: %s (got %d)",
					line, len(matches))
			}
		})
	}
}

// TestDisqualifierWithoutAStrongLabelStillSuppresses pins the fallback. With no
// strong DOB label on the line the disqualifier is the best signal available, so
// the old unconditional behavior is kept there.
func TestDisqualifierWithoutAStrongLabelStillSuppresses(t *testing.T) {
	v := NewValidator()

	// "born" is a weak positive, not a strong label, so the sample keyword should
	// still suppress regardless of position.
	for _, line := range []string{
		"born 03/14/1987, sample collected",
		"birthday 03/14/1987 in the test batch",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "notes.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("weak-positive line with a disqualifier was reported: %s (got %d)",
					line, len(matches))
			}
		})
	}
}

// TestDisqualifierModifiesLabel covers the positional helper directly.
func TestDisqualifierModifiesLabel(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		after string
		want  bool
	}{
		// Marker before the label.
		{"before/test", "test dob: 01/01/2000", "", true},
		{"before/sample", "sample patient dob 3/14/87", "", true},
		{"before/example", "example date of birth 03/14/1987", "", true},
		{"before/mock", "mock dob: 01/01/2000", "", true},

		// Marker opening an aside on the value.
		{"aside/paren", "dob: 03/14/1987 (test)", " (test)", true},
		{"aside/dash", "dob 3/14/87 -- sample data", " -- sample data", true},
		{"aside/comment", "dob 3/14/87 // fake", " // fake", true},

		// A clause with its own subject: NOT an apposition on the value.
		{"clause/blood", "patient dob: 03/14/1987, blood sample collected at intake", ", blood sample collected at intake", false},
		{"clause/urine", "date of birth 03/14/1987, urine sample chain of custody", ", urine sample chain of custody", false},

		// Clean labelled line.
		{"clean", "patient dob: 03/14/1987", "", false},

		// No recognizable label: stay conservative.
		{"nolabel", "03/14/1987 sample collected", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := disqualifierModifiesLabel(c.line, detector.ContextInfo{
				FullLine:  c.line,
				AfterText: c.after,
			})
			if got != c.want {
				t.Errorf("disqualifierModifiesLabel(%q, after=%q) = %v, want %v",
					c.line, c.after, got, c.want)
			}
		})
	}
}

// TestDisqualifierModifiesLabelBoundsAreSafe feeds degenerate input, since
// AfterText is derived from match arithmetic and can be empty.
func TestDisqualifierModifiesLabelBoundsAreSafe(t *testing.T) {
	for _, after := range []string{"", " ", "   ", "-", "((", ","} {
		// Should not panic, and with a clean label none of these is an aside.
		if disqualifierModifiesLabel("patient dob: 03/14/1987", detector.ContextInfo{AfterText: after}) {
			t.Errorf("AfterText %q was read as a disqualifier aside", after)
		}
	}
}
