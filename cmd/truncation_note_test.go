// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// noteMatches builds n findings at the given confidence on distinct lines.
func noteMatches(n int, confidence float64) []detector.Match {
	out := make([]detector.Match, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, detector.Match{
			Text:       fmt.Sprintf("user%02d@example.com", i),
			LineNumber: i + 1,
			Type:       "EMAIL",
			Confidence: confidence,
			Filename:   "many.txt",
			Validator:  "email",
		})
	}
	return out
}

func noteOptions(levels ...string) formatters.FormatterOptions {
	filter := map[string]bool{}
	for _, l := range levels {
		filter[l] = true
	}
	return formatters.FormatterOptions{ConfidenceLevel: filter, NoColor: true}
}

// The disclosure must fire when, and only when, the report is actually short.
//
// All cases below use "csv" as the format: it is the one format with no in-band
// disclosure, so it is the only one that should ever produce this note. Per-format
// scoping has its own test below.
func TestTruncationNote(t *testing.T) {
	const low, high = 40.0, 95.0

	tests := []struct {
		name    string
		matches []detector.Match
		options formatters.FormatterOptions
		limit   int
		want    string // "" means no note
	}{
		{
			name:    "truncated reports disclose the real total",
			matches: noteMatches(36, low),
			options: noteOptions("high", "medium", "low"),
			limit:   3,
			want:    "3 of 36 findings shown",
		},
		{
			// The regression this helper exists for. Formatters filter by confidence
			// and only then apply the limit, so counting every unsuppressed match
			// announced truncation on a report that carried every finding it had.
			// 36 LOW findings are filtered out entirely, leaving 1 HIGH: a complete
			// report, which previously printed "limited to 3 of 37".
			name:    "confidence filter removes more than the limit would",
			matches: append(noteMatches(36, low), noteMatches(1, high)...),
			options: noteOptions("high"),
			limit:   3,
			want:    "",
		},
		{
			name:    "exactly at the limit is complete",
			matches: noteMatches(3, low),
			options: noteOptions("high", "medium", "low"),
			limit:   3,
			want:    "",
		},
		{
			name:    "one over the limit truncates",
			matches: noteMatches(4, low),
			options: noteOptions("high", "medium", "low"),
			limit:   3,
			want:    "3 of 4 findings shown",
		},
		{
			name:    "limit 0 means unlimited",
			matches: noteMatches(36, low),
			options: noteOptions("high", "medium", "low"),
			limit:   0,
			want:    "",
		},
		{
			name:    "no findings",
			matches: nil,
			options: noteOptions("high", "medium", "low"),
			limit:   3,
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncationNote(tc.matches, tc.options, tc.limit, "csv")

			if tc.want == "" {
				if got != "" {
					t.Errorf("a complete report announced truncation: %q\n"+
						"Claiming findings were dropped when none were is the same class "+
						"of bug as hiding a truncation that happened.", got)
				}
				return
			}

			if !strings.Contains(got, tc.want) {
				t.Errorf("note = %q, want it to contain %q", got, tc.want)
			}
			if !strings.Contains(got, "--limit 0") {
				t.Errorf("note = %q, want it to tell the user how to see everything", got)
			}
		})
	}
}

// TestTruncationNoteOnlyForFormatsThatCannotSayItThemselves — no duplicate lines.
//
// The note used to be printed for every format "since it costs nothing to be
// consistent", which meant six of seven formats repeated a disclosure the report
// already contained, immediately after it. Measured on a 3-finding scan at
// --limit 1: text prints "... and 2 more findings", json/yaml carry
// truncated:true, junit uses <system-out>, sarif uses run properties, gitlab-sast
// uses the scan block. Only csv has nowhere to put it.
func TestTruncationNoteOnlyForFormatsThatCannotSayItThemselves(t *testing.T) {
	matches := noteMatches(36, 40)
	opts := noteOptions("high", "medium", "low")

	for _, format := range []string{"text", "json", "yaml", "junit", "sarif", "gitlab-sast"} {
		if got := truncationNote(matches, opts, 3, format); got != "" {
			t.Errorf("%s already discloses truncation in the report itself, so the "+
				"out-of-band note is a duplicate line immediately after it; got %q",
				format, got)
		}
	}

	if got := truncationNote(matches, opts, 3, "csv"); got == "" {
		t.Error("csv has nowhere in the report to record truncation — a comment line is " +
			"not CSV syntax and an extra row inflates the count consumers read — so it " +
			"MUST still get the out-of-band note, or a truncated CSV is indistinguishable " +
			"from a complete one")
	}
}
