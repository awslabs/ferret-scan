// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"testing"
)

// gpsMatchText returns the single GPS finding's text, or "" if none was emitted.
func gpsMatchText(t *testing.T, content string) string {
	t.Helper()
	v := NewValidator()
	matches, err := v.ValidateContent(content, "/test/photo.jpg")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	text := ""
	for _, m := range matches {
		if m.Type != "GPS" {
			continue
		}
		if text != "" {
			t.Fatalf("expected at most one GPS finding, got another: %q after %q", m.Text, text)
		}
		text = m.Text
	}
	return text
}

// bothSourcesContent carries an authoritative EXIF pair (San Francisco) AND a
// looser plain pair (London). Before the fix, combineGPSCoordinates ranged the
// field map and assigned to shared latitude/longitude variables, so the winner
// was whichever field the map happened to yield last — independently for
// latitude and for longitude. That produced FOUR outcomes across runs of the
// same binary, two of which mixed the two pairs into a location present nowhere
// in the file (37.7749/-0.1278 and 51.5074/-122.4194).
const bothSourcesContent = "--- image_metadata ---\n" +
	"GPSLatitude: 37.7749\n" +
	"GPSLongitude: -122.4194\n" +
	"Latitude: 51.5074\n" +
	"Longitude: -0.1278\n"

// TestGPSPairIsNeverMixedAcrossSources is the data-integrity assertion: the
// emitted coordinate must be a pair that actually exists in the input, and
// specifically the authoritative gps* one.
func TestGPSPairIsNeverMixedAcrossSources(t *testing.T) {
	got := gpsMatchText(t, bothSourcesContent)
	const want = "37.7749, -122.4194"
	if got != want {
		t.Fatalf("GPS finding = %q, want %q (the gps*-prefixed pair wins, and latitude/longitude must come from the same source)", got, want)
	}
}

// TestGPSPairStableAcrossRuns is the anti-flake guard. A single call could pick
// the right pair by luck, so pin it over 200 runs; the pre-fix code produced 4
// distinct values here.
func TestGPSPairStableAcrossRuns(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < 200; i++ {
		seen[gpsMatchText(t, bothSourcesContent)]++
	}
	if len(seen) != 1 {
		t.Fatalf("GPS coordinate varied across 200 runs: %d distinct values %v", len(seen), seen)
	}
	if _, ok := seen["37.7749, -122.4194"]; !ok {
		t.Fatalf("stable but wrong pair: %v", seen)
	}
}

// TestGPSFallsBackToPlainPair covers the second precedence tier: no gps* fields
// at all, so the plain pair is the only pair and must still be emitted.
func TestGPSFallsBackToPlainPair(t *testing.T) {
	content := "--- image_metadata ---\n" +
		"Latitude: 51.5074\n" +
		"Longitude: -0.1278\n"
	if got, want := gpsMatchText(t, content), "51.5074, -0.1278"; got != want {
		t.Fatalf("GPS finding = %q, want %q", got, want)
	}
}

// TestGPSCombinesAcrossSourcesOnlyWhenIncomplete covers the third tier and is
// the behavior-preservation test: a file with GPSLatitude but only a plain
// Longitude has no complete pair from either source, so cross-source combining
// is the only way to report the location at all. Detection must not be lost.
func TestGPSCombinesAcrossSourcesOnlyWhenIncomplete(t *testing.T) {
	content := "--- image_metadata ---\n" +
		"GPSLatitude: 37.7749\n" +
		"Longitude: -122.4194\n"
	if got, want := gpsMatchText(t, content), "37.7749, -122.4194"; got != want {
		t.Fatalf("GPS finding = %q, want %q (incomplete sources must still be combined)", got, want)
	}
}

// TestSortedGPSFieldsIsLongestFirst pins the helper's contract. Length-first
// matters because the caller dispatches with strings.Contains over names that
// are substrings of each other: if "latitude" were visited before
// "gpslatituderef", the shorter name's case would claim the longer field.
func TestSortedGPSFieldsIsLongestFirst(t *testing.T) {
	in := map[string]string{
		"latitude":        "1",
		"gpslatitude":     "2",
		"gpslatituderef":  "3",
		"gpslongituderef": "4",
		"longitude":       "5",
		"gpslongitude":    "6",
	}
	got := sortedGPSFields(in)
	// Strictly by descending length (15, 14, 12, 11, 9, 8), with alphabetical
	// order only breaking ties between equal-length names.
	want := []string{"gpslongituderef", "gpslatituderef", "gpslongitude", "gpslatitude", "longitude", "latitude"}
	if len(got) != len(want) {
		t.Fatalf("sortedGPSFields returned %d fields, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedGPSFields = %v, want %v", got, want)
		}
	}
	// The helper must also be total: every key present, none invented.
	for _, f := range got {
		if _, ok := in[f]; !ok {
			t.Fatalf("sortedGPSFields returned %q, which is not a key of the input", f)
		}
	}
}

// TestSortedGPSFieldsIsDeterministic runs the helper repeatedly on the same map
// to prove the sort, not the map, decides the order.
func TestSortedGPSFieldsIsDeterministic(t *testing.T) {
	in := map[string]string{"aa": "", "bb": "", "cc": "", "dddd": "", "e": "", "ff": "", "gg": ""}
	first := sortedGPSFields(in)
	for i := 0; i < 200; i++ {
		got := sortedGPSFields(in)
		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("run %d differed: %v vs %v", i, got, first)
			}
		}
	}
}
