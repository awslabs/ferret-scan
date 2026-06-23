// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"strings"
	"testing"
)

// TestContainsEnhancedGPSData_NoLetterFalsePositive is a regression test for the
// enhanced-GPS detector. The old coordinate fallback matched any decimal number
// AND OR-ed the single letters n/s/e/w across the whole line, so benign metadata
// carrying a version number (e.g. "Software: Adobe Photoshop 21.0") was flagged
// as GPS and pushed toward HIGH confidence. The fix requires a real
// decimal-degree coordinate with an adjacent N/S/E/W hemisphere reference.
func TestContainsEnhancedGPSData_NoLetterFalsePositive(t *testing.T) {
	v := NewValidator()

	// Real GPS coordinates / explicit GPS fields must still be detected.
	gps := []string{
		"GPSLatitude: 40.7128 N",
		"40.7128° N, 74.0060° W",
		"location 51.5074 N",
		"GPSLongitude: 0.1278 W",
		"coordinates: 48.8566, 2.3522", // matched by the explicit "coordinates" keyword
	}
	for _, s := range gps {
		if !v.containsEnhancedGPSData(s) {
			t.Errorf("expected GPS detection for %q", s)
		}
	}

	// Benign metadata with decimals (and incidental n/s/e/w inside words) must
	// NOT be classified as GPS.
	notGPS := []string{
		"Software: Adobe Photoshop 21.0",
		"Application: Microsoft Excel 16.0",
		"Creator: GIMP 2.10",
		"Aperture: f/2.8",
		"ISO: 100.0",
		"FocalLength: 35.0 mm",
		"Resolution: 72.0 dpi west", // 'west' present but not adjacent to a number
		"Version: 1.2.3",
	}
	for _, s := range notGPS {
		if v.containsEnhancedGPSData(s) {
			t.Errorf("expected NO GPS detection for %q, but got one", s)
		}
	}
}

// TestMetadata_NoDuplicateFieldEmission is a regression test for M31: a single
// Author/Manager/Comments line was emitted twice (once by the priority helper,
// once by a legacy inline block).
func TestMetadata_NoDuplicateFieldEmission(t *testing.T) {
	v := NewValidator()
	for _, tc := range []struct {
		line    string
		typeStr string
	}{
		{"Manager: Jane Doe", "MANAGER_INFO"},
		{"Author: John Smith", "AUTHOR_INFO"},
	} {
		matches, err := v.ValidateContent(tc.line, "f.docx")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		count := 0
		for _, m := range matches {
			if m.Type == tc.typeStr {
				count++
			}
		}
		if count > 1 {
			t.Errorf("%q emitted %s %d times; expected at most 1", tc.line, tc.typeStr, count)
		}
	}
}

// TestMetadata_PhoneBasicRequiresSeparator is a regression test for M32: the
// phoneBasic pattern matched any bare 10-digit run (timestamps, IDs), producing
// phantom phone confidence. A separator is now required.
func TestMetadata_PhoneBasicRequiresSeparator(t *testing.T) {
	for _, s := range []string{"1234567890", "2021012345"} {
		if phoneBasic.MatchString(s) {
			t.Errorf("bare 10-digit %q should not match phoneBasic", s)
		}
	}
	for _, s := range []string{"123-456-7890", "123.456.7890"} {
		if !phoneBasic.MatchString(s) {
			t.Errorf("separated phone %q should match phoneBasic", s)
		}
	}
}

// TestMetadata_CombineGPSNoEarlyReturn is a regression test for M33: a stray
// "Coordinates:" placeholder field used to short-circuit the lat/long pairing
// and be emitted itself. The placeholder is now skipped and the real pair is
// still combined.
func TestMetadata_CombineGPSNoEarlyReturn(t *testing.T) {
	v := NewValidator()
	gps := map[string]string{"coordinates": "N/A", "gpslatitude": "40.7128", "gpslongitude": "-74.0060"}
	lines := map[string]int{"coordinates": 1, "gpslatitude": 2, "gpslongitude": 3}
	res := v.combineGPSCoordinates(gps, lines, "f.jpg", "")

	pairFound := false
	for _, r := range res {
		if strings.Contains(strings.ToLower(r.Text), "n/a") {
			t.Errorf("placeholder 'N/A' should not be emitted as GPS, got %q", r.Text)
		}
		if strings.Contains(r.Text, "40.7128") && strings.Contains(r.Text, "-74.0060") {
			pairFound = true
		}
	}
	if !pairFound {
		t.Error("real lat/long pair should still be combined despite the stray Coordinates field")
	}
}
