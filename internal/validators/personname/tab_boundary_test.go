// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/context"
)

// A tab is a column boundary in extracted table and spreadsheet content, not a
// word space. Every name pattern used to join its tokens with `\s+`, and Go's \s
// includes \t, so two adjacent cells were glued into one "name" whenever the
// right-hand cell happened to hold a real surname.
//
// Measured over 714 real Office/PDF documents before the fix: 95 of 1931
// PERSON_NAME findings spanned a tab and 32 of those presented as HIGH — a
// two-column status table produced "Preventative<TAB>Strong" at 100.
//
// The fix is not "a tab never joins a name": a genuine "First Name | Last Name"
// roster row does exist. It is that a tab is WEAKER evidence than a space, so the
// one pattern allowed to span it must clear a stricter bar (both tokens confirmed
// by the name database) instead of the surname-only bar used elsewhere.

// tabbedTableCells are real values reported before the fix, taken from the
// 714-document corpus. In each one the left token is not a given name, so the
// adjacency is a table layout and nothing more.
var tabbedTableCells = []string{
	"Preventative\tStrong",
	"Closed\tCook",
	"Project\tSun",
	"Healthcare\tJohnson",
	"Launched\tJohnson",
	"Circle\tRyan",
	"Closed\tHolland",
	"Project\tWashington",
	"Change Log\tMajor",
	"Financial Services\tWashington",
	"Data Handling Standard\tLink",
}

func TestTabbedTableCellsAreNotOneName(t *testing.T) {
	v := NewValidator()

	for _, line := range tabbedTableCells {
		t.Run(strings.ReplaceAll(line, "\t", "<TAB>"), func(t *testing.T) {
			matches, err := v.ValidateContent(line, "table.tsv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if strings.Contains(m.Text, "\t") {
					t.Errorf("reported a name spanning a column boundary: %q at %.0f", m.Text, m.Confidence)
				}
			}
		})
	}
}

// TestTabbedCellsWouldMatchWithASpace is the non-vacuity gate for the test above.
//
// Replacing each tab with a space must still produce a finding. Without this, the
// suite above would keep passing if the patterns stopped matching for some
// unrelated reason (a broken character class, an empty name database) and would
// no longer be testing the column boundary at all.
func TestTabbedCellsWouldMatchWithASpace(t *testing.T) {
	v := NewValidator()

	for _, line := range tabbedTableCells {
		spaced := strings.ReplaceAll(line, "\t", " ")
		t.Run(spaced, func(t *testing.T) {
			matches, err := v.ValidateContent(spaced, "prose.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("%q produced no finding, so the tab variant proves nothing "+
					"about column boundaries", spaced)
			}
		})
	}
}

// TestTwoColumnRosterNameIsStillReported pins the recall side. These are the rows
// that make a blanket "a tab never joins a name" rule wrong: both tokens are
// database-confirmed name parts, so the row is a person split across two columns
// and dropping it would leave the name unredactable.
func TestTwoColumnRosterNameIsStillReported(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"Marcus\tHolloway",
		"Sarah\tChen",
		"Michael\tJohnson",
		"Marcus \t Holloway", // padded cell boundary
	} {
		t.Run(strings.ReplaceAll(line, "\t", "<TAB>"), func(t *testing.T) {
			matches, err := v.ValidateContent(line, "roster.tsv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("%q lost the name entirely: a First/Last column pair must "+
					"stay reportable, or it is never redacted", line)
			}
		})
	}
}

// TestTabbedRowReportsTheNameNotTheLabelCell covers the case that improves in both
// directions. "Nomination<TAB>Christian Kelley" used to be reported verbatim, so
// the value handed downstream carried a foreign label cell inside it. The name is
// still found — with the correct span.
func TestTabbedRowReportsTheNameNotTheLabelCell(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct{ line, want string }{
		{"Nomination\tChristian Kelley", "Christian Kelley"},
		{"Barclays\tRob Jackson", "Rob Jackson"},
		{"Lost\tAlex Goff", "Alex Goff"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "table.tsv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			found := false
			for _, m := range matches {
				if m.Text == tc.want {
					found = true
				}
				if strings.Contains(m.Text, "\t") {
					t.Errorf("value still carries the label cell: %q", m.Text)
				}
			}
			if !found {
				var got []string
				for _, m := range matches {
					got = append(got, m.Text)
				}
				t.Errorf("want %q reported from %q, got %v", tc.want, tc.line, got)
			}
		})
	}
}

// TestTabGateAppliesOnBothScoringPaths guards against the dual-path trap: this
// validator scores through findNamesInLine OR findNamesInLineWithContext
// depending on the caller, and a gate added to only one of them is dead code for
// every caller that takes the other.
func TestTabGateAppliesOnBothScoringPaths(t *testing.T) {
	v := NewValidator()
	const line = "Preventative\tStrong"

	insights := context.ContextInsights{
		DocumentType:          "employee_directory",
		Domain:                "hr",
		SemanticContext:       map[string]float64{"person": 0.9},
		ConfidenceAdjustments: map[string]float64{},
	}

	plain, err := v.ValidateContent(line, "table.tsv")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	withCtx, err := v.ValidateWithContext(line, "table.tsv", insights)
	if err != nil {
		t.Fatalf("ValidateWithContext: %v", err)
	}

	for _, m := range plain {
		if strings.Contains(m.Text, "\t") {
			t.Errorf("ValidateContent reported %q across a column boundary", m.Text)
		}
	}
	for _, m := range withCtx {
		if strings.Contains(m.Text, "\t") {
			t.Errorf("ValidateWithContext reported %q across a column boundary — the "+
				"gate is missing from the context path", m.Text)
		}
	}
}

// TestBothNamesKnownBarIsAnExplicitInventory keeps the stricter bar from spreading.
// CalculateConfidenceWithComponents documents why the general rule is surname-only
// (both-known costs 30 recall points), so every pattern that opts in has to be listed
// here with a reason in requiresBothNamesKnown — adding one silently fails this test.
func TestBothNamesKnownBarIsAnExplicitInventory(t *testing.T) {
	want := map[string]bool{
		tabSeparatedNamePattern: true, // tokens are in different table columns
		"name_with_particle":    true, // "Applied de Morgan" is prose, not a data subject
	}

	got := map[string]bool{}
	for _, p := range NewPatternManager().GetPatterns() {
		if requiresBothNamesKnown(p.Name) {
			got[p.Name] = true
		}
	}

	for name := range want {
		if !got[name] {
			t.Errorf("%q should require both names known", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("%q newly requires both names known: add it to this inventory with "+
				"a reason, or it silently costs recall", name)
		}
	}
}
