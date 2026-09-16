// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"
)

// Every confidence value is either understood or REFUSED — never silently ignored.
//
// # What silence cost
//
// An unrecognised token was dropped by a switch with no default, so the filter it produced had every
// level false and matched nothing. Measured on a file holding three findings, each of these returned an
// empty report at exit 0 while the SAME document's stats block said total_findings 3:
//
//	--confidence nonsense    results 0
//	--confidence hi          results 0
//	--confidence ALL         results 0   <- the DOCUMENTED value, wrong case
//	--confidence All         results 0
//	--confidence " all "     results 0   <- the documented value, with spaces
//	--confidence all,high    results 1   <- "all" ignored inside a list
//
// Three of the six are the documented value `all` in a spelling the code did not accept, because the
// wildcard was compared with == against the raw string while the token loop lowercased and trimmed.
// That is the part a reviewer would not predict, and it is why this table lists spellings rather than
// values.
func TestParseConfidenceLevelsAcceptsEverySpellingOfAll(t *testing.T) {
	for _, input := range []string{
		"all", "ALL", "All", "aLL", " all ", "\tall\t", "all,high", "high,all", "all,all",
		"", "   ", ",", "high,,low",
	} {
		t.Run(strings.ReplaceAll(input, " ", "_"), func(t *testing.T) {
			got, err := ParseConfidenceLevels(input)
			if err != nil {
				t.Fatalf("ParseConfidenceLevels(%q) = error %v; every one of these is a documented "+
					"spelling of a valid value", input, err)
			}
			// The comma-only and whitespace-only inputs mean "nothing specified", which is all.
			// "high,,low" is high+low, not all — handled below.
			if input == "high,,low" {
				if !got["high"] || !got["low"] || got["medium"] {
					t.Errorf("ParseConfidenceLevels(%q) = %v; a doubled comma must be ignored, not "+
						"change which levels are selected", input, got)
				}
				return
			}
			for _, level := range ConfidenceLevelNames() {
				if !got[level] {
					t.Errorf("ParseConfidenceLevels(%q) left %q disabled; this spelling means ALL",
						input, level)
				}
			}
		})
	}
}

func TestParseConfidenceLevelsRefusesWhatItDoesNotUnderstand(t *testing.T) {
	for _, input := range []string{
		"nonsense", "hi", "high,med", "medum", "HIGHEST", "none", "high;low", "low medium",
	} {
		t.Run(strings.ReplaceAll(input, " ", "_"), func(t *testing.T) {
			got, err := ParseConfidenceLevels(input)
			if err == nil {
				t.Fatalf("ParseConfidenceLevels(%q) was ACCEPTED and returned %v. An unrecognised "+
					"token used to be dropped, producing a filter that matches nothing and a report "+
					"that contradicts its own stats block.", input, got)
			}
			// The message must name the offending token AND the valid values, or a user cannot act
			// on it. "invalid confidence level" alone sends them to the docs.
			if !strings.Contains(err.Error(), "high") {
				t.Errorf("error for %q does not list the valid values: %v", input, err)
			}
		})
	}
}

// TestParseConfidenceLevelsSelectsExactlyWhatWasAsked pins the ordinary path, so the strictness above
// cannot be satisfied by rejecting everything.
func TestParseConfidenceLevelsSelectsExactlyWhatWasAsked(t *testing.T) {
	cases := []struct {
		input string
		want  map[string]bool
	}{
		{"high", map[string]bool{"high": true, "medium": false, "low": false}},
		{"HIGH", map[string]bool{"high": true, "medium": false, "low": false}},
		{"high,medium", map[string]bool{"high": true, "medium": true, "low": false}},
		{" high , low ", map[string]bool{"high": true, "medium": false, "low": true}},
		{"Medium", map[string]bool{"high": false, "medium": true, "low": false}},
	}
	for _, c := range cases {
		t.Run(strings.ReplaceAll(c.input, " ", "_"), func(t *testing.T) {
			got, err := ParseConfidenceLevels(c.input)
			if err != nil {
				t.Fatalf("ParseConfidenceLevels(%q): %v", c.input, err)
			}
			for level, want := range c.want {
				if got[level] != want {
					t.Errorf("ParseConfidenceLevels(%q)[%q] = %v, want %v", c.input, level, got[level], want)
				}
			}
		})
	}
}

// TestConfidenceLevelNamesIsNotEmpty is the non-vacuity floor: the tables above iterate this list, so
// an empty one would make them assert nothing.
func TestConfidenceLevelNamesIsNotEmpty(t *testing.T) {
	names := ConfidenceLevelNames()
	if len(names) != 3 {
		t.Fatalf("ConfidenceLevelNames() = %v, want the three bands; the tables above iterate this "+
			"and would pass vacuously if it were empty", names)
	}
	// Sorted, because the error text renders it and an unstable order makes a message unreviewable.
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Errorf("ConfidenceLevelNames() is not sorted: %v", names)
		}
	}
}
