// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

import (
	"strings"
	"testing"
)

// IsDecimalFractionTail is the shared predicate three validators now depend on, so its boundaries are
// tested here once rather than in each of them.
func TestIsDecimalFractionTail(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		match string
		want  bool
	}{
		{"fraction after digit and dot", "0.304262935", "304262935", true},
		{"fraction mid line", "C0.304262935,18", "304262935", true},
		{"version component", "1.2.449874100", "449874100", true},
		{"two digit integer part", "35.008 31.354", "008 31.354", true},

		// Not a decimal point — these are the rows an earlier look-AHEAD guard deleted.
		{"preceded by a space", "SSN is 130075728.", "130075728", false},
		{"preceded by an equals", "ssn=130075728.", "130075728", false},
		{"preceded by a colon and space", "NPI: 1234567893", "1234567893", false},
		{"dot with no digit before it", "v.449874100", "449874100", false},
		{"at line start", "449874100", "449874100", false},
		{"dot at line start", ".449874100", "449874100", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := strings.Index(c.line, c.match)
			if idx < 0 {
				t.Fatalf("test setup: %q does not contain %q", c.line, c.match)
			}
			if got := IsDecimalFractionTail(c.line, idx); got != c.want {
				t.Errorf("IsDecimalFractionTail(%q, %d) = %v, want %v", c.line, idx, got, c.want)
			}
		})
	}
}

// Out-of-range and degenerate indices must not panic. Callers pass an offset from
// FindAllStringIndex, but a future caller may not.
func TestIsDecimalFractionTailBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		line  string
		index int
	}{
		{"negative index", "0.123", -1},
		{"zero index", "0.123", 0},
		{"index one", "0.123", 1},
		{"index past the end", "0.123", 99},
		{"index exactly at the end", "0.123", 5},
		{"empty line", "", 0},
		{"empty line, positive index", "", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The assertion is that this returns rather than panics.
			_ = IsDecimalFractionTail(tc.line, tc.index)
		})
	}
}
