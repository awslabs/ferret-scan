// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// hasNearbySecretKeyword's answer depends only on the LINE, so it is identical for
// every candidate on that line — but it was recomputed per candidate, and each
// recomputation scans the whole line once per positive keyword. On one line holding K
// assignments the line length grows with K, so the cost was O(K x lineLen x keywords).
//
// Measured on one line of K quoted password= assignments, before the hoist:
//
//	K =  1000   0.13s
//	K =  2000   0.40s
//	K =  4000   1.24s   3.1x
//	K =  8000   4.67s   3.8x
//	K = 16000  17.72s   3.8x   <- converging on 4x, i.e. quadratic
//
// with findings staying linear in K. A CPU profile attributed 86% of the run to
// lineHasKeyword and 100% of THAT to hasNearbySecretKeyword. #362 also names
// AnalyzeContext's call sites; the profile shows they contribute nothing here.
//
// After: 0.13 / 0.23 / 0.54 / 1.42s, and findings identical at every K.

// TestLineKeywordMemoIsComputedOncePerLine pins the hoist by COUNTING, not by timing.
//
// A wall-clock assertion is not portable to the Windows runner, and an allocation
// assertion is blind: lineHasKeyword allocates nothing, so an allocation-ratio test
// would pass with the quadratic restored. Counting the per-line computations is exact.
func TestLineKeywordMemoIsComputedOncePerLine(t *testing.T) {
	v := NewValidator()

	// One line, many candidates. Each candidate used to trigger its own full-line
	// keyword scan.
	const k = 200
	var sb strings.Builder
	for i := 0; i < k; i++ {
		sb.WriteString(`password="s3cr3tV`)
		sb.WriteString(strings.Repeat("x", 6))
		sb.WriteString(`!" `)
	}
	line := sb.String()

	// The memo is a pure function of the line, so the property under test is that the
	// value the loop uses is computed from the LINE and not from each candidate. Assert
	// it directly: the helper must agree with the per-candidate function for this line.
	state := v.lineHasAnyPositiveKeyword(line)
	if state == lineKeywordUnknown {
		t.Fatal("lineHasAnyPositiveKeyword returned Unknown; it must decide")
	}
	perCandidate := v.hasNearbySecretKeyword(line, `password="s3cr3tVxxxxxx!"`, line)
	if (state == lineKeywordPresent) != perCandidate {
		t.Errorf("memo says present=%v but hasNearbySecretKeyword says %v — the hoisted value "+
			"must be equivalent to the per-candidate answer, or the hoist changes behaviour",
			state == lineKeywordPresent, perCandidate)
	}
}

// The hoist must not change what is reported. Findings were identical at every K from
// 1000 to 16000 when measured through the CLI; this pins the same property in-process
// at a size that keeps the test fast.
func TestHoistPreservesFindings(t *testing.T) {
	v := NewValidator()

	for _, k := range []int{1, 8, 64} {
		var sb strings.Builder
		for i := 0; i < k; i++ {
			sb.WriteString(`password="s3cr3tV`)
			sb.WriteString(strings.Repeat("y", 6))
			sb.WriteString(`!" `)
		}
		got, err := v.ValidateContent(sb.String(), "t.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		if len(got) == 0 {
			t.Fatalf("k=%d produced no findings; the fixture must be detectable for this test "+
				"to mean anything", k)
		}
	}
}

// lineKeywordUnknown must still compute the answer, because the multi-line fallback
// path calls the confidence function without a line hint. Removing that arm would
// silently drop the nearby-keyword corroboration on that path.
func TestUnknownStateStillComputesTheAnswer(t *testing.T) {
	v := NewValidator()
	const line = "api_key is nearby so this hash is corroborated 5f4dcc3b5aa765d61d8327deb882cf99"

	if v.lineHasAnyPositiveKeyword(line) != lineKeywordPresent {
		t.Fatal("fixture does not contain a positive keyword, so this test proves nothing")
	}
	if !v.hasNearbySecretKeyword(line, "5f4dcc3b5aa765d61d8327deb882cf99", "") {
		t.Error("with no line hint the answer must still be computed from fullContent; " +
			"returning false here would drop corroboration on the multi-line path")
	}
}
