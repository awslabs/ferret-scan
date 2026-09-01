// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// The --output half of #562 was pinned by nothing: reverting both call sites to the substring gate
// left the whole cmd suite green. These two sites are a DIFFERENT trust question from the input
// sites — refusing where the tool WRITES loses no scan coverage and is loud (exit 1), whereas the
// input refusals printed nothing at exit 0. So the refusal is kept and only the test is narrowed:
// an --output filename that merely contains ".." is accepted, a path that climbs is still refused.
//
// Identifiers are prefixed t562out so this file coexists with the other cmd test files added by
// concurrent PRs; duplicate top-level names merge cleanly and then fail to compile.
func TestT562OutputPathAcceptsATwoDotNameAndRefusesAClimb(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		refuse bool
	}{
		// Accepted: an ordinary artifact name that happens to contain two dots.
		{"report..final.json", "report..final.json", false},
		{"date range", "scan.2024..2025.json", false},
		{"nested ordinary", "out/report..final.json", false},
		{"absolute ordinary", "/tmp/out/report..final.json", false},

		// Refused: the path climbs out of the working directory.
		{"leading climb", "../escape.json", true},
		{"double climb", "../../escape.json", true},
		{"climb in the middle", "out/../../escape.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathEscapesBase(tc.path); got != tc.refuse {
				t.Errorf("pathEscapesBase(%q) = %v, want %v.\n"+
					"This is the gate both --output sites use (cmd/main.go and cmd/stdin.go). "+
					"Accepting a climb would let the tool write outside the working directory; "+
					"refusing an ordinary two-dot name makes it exit 1 and write nothing for a "+
					"filename a user may legitimately choose.", tc.path, got, tc.refuse)
			}
		})
	}
}
