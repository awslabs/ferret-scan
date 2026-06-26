// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"
	"time"
)

// TestSocialMediaValidator_NoQuadraticBlowup is a performance regression guard.
//
// The validator previously scanned each match's full line with
// strings.Index(line, match), re-lowercased and re-substring-scanned the entire
// line for every keyword of every match, re-opened the source file per match,
// and ran O(M^2) clustering over every match in the document. On a single ~1MB
// line packed with matches this was quadratic: ~31s for a 100 KB line, i.e. tens
// of minutes for 1 MB.
//
// Both worst-case shapes (one giant line with many matches, and a file with one
// match per line across tens of thousands of lines) must now complete well
// within a generous ceiling. After the fix this runs in ~1-4s on a dev machine;
// the prior quadratic was tens of seconds at 100 KB and minutes at 1 MB. The 10s
// bound is intentionally loose so it decisively flags a reintroduced O(n^2)
// regression without flaking on slow or loaded CI machines.
func TestSocialMediaValidator_NoQuadraticBlowup(t *testing.T) {
	const (
		targetBytes = 1 << 20 // ~1 MB
		ceiling     = 10 * time.Second
	)

	cases := []struct {
		name  string
		build func() string
	}{
		{
			// One pathologically long line densely packed with matches.
			name: "single_long_line",
			build: func() string {
				var sb strings.Builder
				for sb.Len() < targetBytes {
					sb.WriteString("https://twitter.com/johndoe ")
				}
				return sb.String()
			},
		},
		{
			// Tens of thousands of lines, one match per line.
			name: "many_lines_one_match_each",
			build: func() string {
				var sb strings.Builder
				for sb.Len() < targetBytes {
					sb.WriteString("Connect: https://twitter.com/johndoe\n")
				}
				return sb.String()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newConfiguredValidator()
			content := tc.build()

			start := time.Now()
			matches, err := v.ValidateContent(content, "timing_test_input.txt")
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			// Sanity: the input is full of valid matches, so we must still detect
			// something — the perf fix must not silently drop all detections.
			if len(matches) == 0 {
				t.Fatalf("expected matches for %q input, got none (perf fix must not disable detection)", tc.name)
			}
			if raceEnabled {
				// -race inflates wall-clock 5-20x; the scan ran above (so -race
				// checks for data races), but the timing ceiling is skipped.
				t.Logf("%s: %d bytes, %d matches (timing assertion skipped under -race)", tc.name, len(content), len(matches))
				return
			}
			if elapsed > ceiling {
				t.Fatalf("ValidateContent took %s on %d-byte %q input, exceeds %s ceiling — likely an O(n^2) regression",
					elapsed, len(content), tc.name, ceiling)
			}
			t.Logf("%s: %d bytes, %d matches, %s", tc.name, len(content), len(matches), elapsed)
		})
	}
}
