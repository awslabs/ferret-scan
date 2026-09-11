// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"strings"
	"testing"
)

// TestSyntheticMarkerSuppressionDoesNotDependOnFoldedByteLength pins the fix at the
// package that owns it.
//
// The defect: disqualifierOpensAsideAfter(lowerLineCached, cand.start+len(cand.text))
// is handed an offset produced by the date regexes run on the UNFOLDED line, and
// indexes the folded copy with it. strings.ToLower is not byte-length-preserving.
//
// The failure was a FALSE POSITIVE rather than a panic, and that is the interesting
// part: the function's own guard (matchEnd >= len(lowerLine)) absorbs the overshoot
// and returns false, so it fails OPEN. The synthetic-marker rule simply stops
// firing, and a date the tool correctly refuses to report becomes a HIGH-confidence
// finding. A bounds check was already present and was what made the bug quiet.
func TestSyntheticMarkerSuppressionDoesNotDependOnFoldedByteLength(t *testing.T) {
	v := NewValidator()

	const kelvin = "K" // 3 bytes, folds to 1
	const suppressed = "Patient date of birth: 03/14/1985 (test) per the intake form."

	// Precondition: with no hostile rune the marker rule must suppress this line
	// completely. If it ever stops doing so, every assertion below is vacuous.
	base, err := v.ValidateContent(suppressed+"\n", "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(baseline): %v", err)
	}
	if len(base) != 0 {
		t.Fatalf("premise stale: the \"(test)\" marker no longer suppresses this date "+
			"(got %d findings), so this test cannot detect the suppression being defeated", len(base))
	}

	for _, n := range []int{1, 2, 4, 8, 20, 40} {
		hostile := strings.Repeat(kelvin, n) + " " + suppressed
		control := strings.Repeat("q", 3*n) + " " + suppressed
		if len(hostile) != len(control) {
			t.Fatalf("fixture bug: %d vs %d bytes", len(hostile), len(control))
		}

		hm, err := v.ValidateContent(hostile+"\n", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(hostile, n=%d): %v", n, err)
		}
		cm, err := v.ValidateContent(control+"\n", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(control, n=%d): %v", n, err)
		}

		if len(cm) != 0 {
			t.Errorf("n=%d: the CONTROL reported %d findings; a byte-length-identical run of "+
				"ASCII must not defeat the marker either, so the fixture no longer isolates folding",
				n, len(cm))
		}
		if len(hm) != 0 {
			t.Errorf("n=%d (%d bytes, identical to the control): reported %d finding(s) at "+
				"confidence %.1f for a date the marker rule suppresses. A run of "+
				"byte-length-changing runes must not defeat a suppression rule — that publishes "+
				"a synthetic value at HIGH and spends a reviewer's attention on a decoy.",
				n, len(hostile), len(hm), hm[0].Confidence)
		}
	}
}

// TestARealDOBStillReportsAlongsideHostileRunes is the other half: the fix must not
// have bought suppression correctness by dropping genuine detections.
func TestARealDOBStillReportsAlongsideHostileRunes(t *testing.T) {
	v := NewValidator()
	const real = "Patient date of birth: 03/14/1985 per the intake form."
	for _, n := range []int{2, 8, 40} {
		hostile := strings.Repeat("K", n) + " " + real
		got, err := v.ValidateContent(hostile+"\n", "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(n=%d): %v", n, err)
		}
		if len(got) == 0 {
			t.Errorf("n=%d: a real labelled date of birth was not reported at all", n)
		}
	}
}
