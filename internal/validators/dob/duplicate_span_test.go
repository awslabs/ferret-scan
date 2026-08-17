// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"strings"
	"testing"
)

// The same date twice on one line is two findings, not one.
//
// extractDates shares a `seen` map across every pattern loop so that two patterns
// matching the same bytes collapse to one candidate — which is correct. But the key
// was the matched TEXT, so a date appearing twice on one line at different offsets
// also collapsed, and only the first was emitted.
//
// Redaction rewrites what was reported, so the second occurrence survived. Measured
// on the shipped binary:
//
//	input:    Date of Birth: 1985-03-14 (DOB 1985-03-14)
//	findings: 1
//	redacted: Date of Birth: ********** (DOB 1985-03-14)
//
// rc=0, with a date of birth in cleartext in a file the caller believes is redacted.
// Keying on the byte span fixes it while still collapsing genuine cross-pattern
// duplicates.
func TestSameDateTwiceOnOneLineYieldsTwoCandidates(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		date string
		want int
	}{
		{"iso twice", "Date of Birth: 1985-03-14 (DOB 1985-03-14)", "1985-03-14", 2},
		{"iso three times", "DOB 1985-03-14 / 1985-03-14 / 1985-03-14", "1985-03-14", 3},
		{"numeric twice", "Date of Birth: 03/14/1985 confirmed 03/14/1985", "03/14/1985", 2},
		{"month name twice", "Born March 14, 1985 (DOB March 14, 1985)", "March 14, 1985", 2},
		// A single occurrence must still be a single finding — the fix must not
		// start double-emitting.
		{"single occurrence unchanged", "Date of Birth: 1985-03-14", "1985-03-14", 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches, err := v.ValidateContent(c.line, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			n := 0
			for _, m := range matches {
				if strings.EqualFold(m.Text, c.date) {
					n++
				}
			}
			if n != c.want {
				t.Errorf("got %d findings for %q, want %d.\n"+
					"Redaction only rewrites what was reported, so a dropped occurrence stays "+
					"in cleartext in the redacted file.", n, c.date, c.want)
			}
		})
	}
}

// Deduplication must still collapse two PATTERNS matching the same bytes. That is
// what the shared `seen` map is for, and losing it would emit the same span twice
// and redact the same bytes twice.
func TestSameSpanFromDifferentPatternsCollapses(t *testing.T) {
	// Every candidate returned for a line must have a distinct start offset.
	for _, line := range []string{
		"Date of Birth: 1985-03-14",
		"DOB 03/14/1985",
		"DOB 3/14/85",
		"Born March 14, 1985",
		"Born 14 March 1985",
		"Mixed 1985-03-14 and 03/14/1985 and March 14, 1985",
	} {
		v := NewValidator()
		got := v.extractDates(line)
		seenStart := make(map[int]int)
		for _, c := range got {
			seenStart[c.start]++
		}
		for start, n := range seenStart {
			if n > 1 {
				t.Errorf("line %q: %d candidates share start offset %d — the same bytes would be "+
					"redacted more than once", line, n, start)
			}
		}
	}
}

// The span key must distinguish occurrences by offset, and collapse identical
// spans. Asserted on extractDates directly so the guarantee does not depend on
// downstream scoring choosing to emit.
func TestExtractDatesKeysOnSpanNotText(t *testing.T) {
	v := NewValidator()
	line := "DOB 1985-03-14 and again 1985-03-14"

	got := v.extractDates(line)
	var starts []int
	for _, c := range got {
		if c.text == "1985-03-14" {
			starts = append(starts, c.start)
		}
	}
	if len(starts) != 2 {
		t.Fatalf("got %d candidates for the repeated date (starts %v), want 2", len(starts), starts)
	}
	if starts[0] == starts[1] {
		t.Errorf("both candidates report start %d; they are different occurrences", starts[0])
	}
	// Each start must actually be where that text occurs.
	for _, s := range starts {
		if s < 0 || s+len("1985-03-14") > len(line) || line[s:s+len("1985-03-14")] != "1985-03-14" {
			t.Errorf("start %d does not address the date in %q", s, line)
		}
	}
}
