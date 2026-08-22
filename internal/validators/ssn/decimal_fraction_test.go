// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"strings"
	"testing"
)

// The digits after a decimal point are not an SSN.
//
// Measured at main @ 0610b7e. Path data reached HIGH 100 through two conjoined mechanisms: the
// fraction was admitted as a candidate at all, and comma-bearing coordinates were classified as
// CSV, which granted the tabular context boost (+25 on an original 95):
//
//	M0.5,1 C0.304262935,18 0.125262935,18.115   ->  2 x SSN HIGH 100   in .txt AND .svg
//	0.304262935 alone                            ->  SSN LOW 50
//	449874100  (a REAL unpunctuated SSN)         ->  SSN LOW 50
//
// The false positive outranked the true positive by 50 points. SSN-only scan of 1,842 real .svg
// files: 678 findings, 616 of them HIGH, now 0.
//
// NOTE the corpora could not have caught this: zero golden INPUT fixtures contain a
// decimal-adjacent nine-digit run, in either direction. That is the same blindness that made
// "the suite passes" worthless evidence for an earlier attempt at this fix.
func TestDecimalFractionIsNotAnSSN(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		file string
	}{
		{"svg path data, two fractions", "M0.5,1 C0.304262935,18 0.125262935,18.115", "icon.txt"},
		{"svg path attribute", `<path d="M0.5,1 C0.304262935,18 0.125262935,18"/>`, "icon.svg"},
		{"bare ratio", "ratio 0.304262935", "notes.txt"},
		{"labelled value", "value: 0.130075728", "notes.txt"},
		{"geojson coordinates", `{"coordinates":[0.304262935,51.4875]}`, "geo.json"},
		{"csv cell", "a,0.304262935", "data.csv"},
		{"dotted version component", "version 1.2.449874100", "notes.txt"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := v.ValidateContent(c.line, c.file)
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(got) != 0 {
				texts := make([]string, 0, len(got))
				for _, m := range got {
					texts = append(texts, m.Text)
				}
				t.Errorf("a decimal fraction was reported as an SSN: %s\n  matched %v\n"+
					"  reporting these at HIGH drives redaction, which overwrites ordinary "+
					"numeric data", c.line, texts)
			}
		})
	}
}

// The rows that an earlier version of this fix DELETED. All must survive.
//
// That attempt looked AHEAD of the match, so a sentence-terminal period read as a decimal point and
// a labelled SSN at the end of a sentence produced no finding at all — a cleartext leak, because
// only reported findings reach the redactor. It was refuted for exactly these four rows.
//
// This guard looks BEHIND the match instead. A sentence-terminal period is AFTER the value; a
// decimal point is BEFORE it, so the two cases are not variants of one idea — one of them cannot
// reach a real finding. These rows are kept as the standing proof of that.
func TestLabelledSSNsTheRejectedGuardDeletedStillReport(t *testing.T) {
	v := NewValidator()

	// Verbatim from the refutation.
	cases := []string{
		"Employee record: the SSN is 130075728.",
		"Employee SSN: 130-07-5728.",
		"Social Security Number: 130 07 5728.",
		"ssn=130075728.",
	}

	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			got, err := v.ValidateContent(line, "employees.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(got) == 0 {
				t.Errorf("a labelled SSN stopped being reported: %s\n  only reported findings reach "+
					"the redactor, so suppressing this leaves the number in cleartext — the exact "+
					"failure an earlier version of this guard was refuted for", line)
			}
		})
	}
}

// A value that appears BOTH as a fraction and as a real SSN on one line must still be reported.
//
// This is the aliasing hazard, and it is why the decision is made per OCCURRENCE rather than from
// matchSpan.start. That field holds the FIRST occurrence's offset, shared by every duplicate of the
// same text, so a guard keyed on it would let the earlier fraction suppress the later SSN — losing a
// real value to a false one. An earlier attempt at this fix was flagged for precisely that.
//
// Both orderings are tested, because a guard that only checked the first occurrence would pass one
// of them by luck.
func TestAFractionDoesNotSuppressARealSSNOnTheSameLine(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"ratio 0.130075728 and SSN: 130075728",
		"SSN: 130075728 and ratio 0.130075728",
	} {
		t.Run(line, func(t *testing.T) {
			got, err := v.ValidateContent(line, "mixed.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(got) == 0 {
				t.Fatalf("the real SSN was suppressed by the fraction sharing its digits: %s\n"+
					"  a value is only a false positive when EVERY occurrence is a fraction tail", line)
			}
			// The labelled occurrence must be the one carrying real confidence.
			var best float64
			for _, m := range got {
				if m.Confidence > best {
					best = m.Confidence
				}
			}
			if best < 60 {
				t.Errorf("highest confidence is %.0f%%, expected the labelled occurrence to keep a "+
					"reportable score", best)
			}
		})
	}
}

// isDecimalFractionTail is unit-tested directly on its boundaries, which are awkward to reach
// through a whole validator run and are where a guard like this goes wrong.
func TestIsDecimalFractionTail(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		match string
		want  bool
	}{
		{"fraction after a digit and a dot", "0.304262935", "304262935", true},
		{"fraction mid-line", "C0.304262935,18", "304262935", true},
		{"version component", "1.2.449874100", "449874100", true},

		// Not a decimal point.
		{"preceded by a space", "SSN is 130075728.", "130075728", false},
		{"preceded by an equals", "ssn=130075728.", "130075728", false},
		{"preceded by a dot with no digit", "v.449874100", "449874100", false},
		{"at line start", "449874100", "449874100", false},
		{"dot at line start", ".449874100", "449874100", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := strings.Index(c.line, c.match)
			if idx < 0 {
				t.Fatalf("test setup: %q does not contain %q", c.line, c.match)
			}
			if got := isDecimalFractionTail(c.line, idx); got != c.want {
				t.Errorf("isDecimalFractionTail(%q, %d) = %v, want %v", c.line, idx, got, c.want)
			}
		})
	}
}

// The false positive must not outrank the true positive.
//
// Pinned as an ORDERING rather than on either absolute number, so it survives a future rebalance of
// the confidence table. Before this change a coordinate scored HIGH 100 while a real unpunctuated
// SSN scored LOW 50.
func TestARealSSNOutranksWhatIsNoLongerReported(t *testing.T) {
	v := NewValidator()

	real, err := v.ValidateContent("SSN: 449-87-4100", "hr.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(real) == 0 {
		t.Fatal("the labelled SSN is not reported at all, so there is no ordering to check")
	}

	coord, err := v.ValidateContent("M0.5,1 C0.449874100,18", "icon.svg")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(coord) != 0 {
		t.Errorf("the coordinate still reports at %.0f%% while the real SSN is at %.0f%% — a false "+
			"positive must never outrank a true one", coord[0].Confidence, real[0].Confidence)
	}
}
