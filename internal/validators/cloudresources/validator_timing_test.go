// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestCloudResources_SingleLineDoSGuard is a regression guard for the residual
// O(n^2) blowup fixed alongside this test: scoreMatch re-ran hasKeywordToken
// (a full-line, per-negative-keyword scan) for EVERY match, so a single line
// packed with thousands of distinct ARNs cost O(matches x lineLen). On a ~1MB
// single line the pre-fix cost was ~4.7s; after hoisting the negative-keyword
// scan into the per-line cache it is well under 200ms.
//
// The trigger SHAPE matters: the input must be a single line of many DISTINCT,
// matchable cloud-resource identifiers (minified-JSON/one-line-log shape). A
// synthetic input that does not match cloud-resource patterns exercises none of
// the per-match loop and would not reproduce the quadratic (the lesson from the
// personname residual that earlier synthetic worst cases missed).
func TestCloudResources_SingleLineDoSGuard(t *testing.T) {
	const targetBytes = 1 << 20 // ~1MB single line, no newlines

	var b strings.Builder
	for i := 0; b.Len() < targetBytes; i++ {
		// Distinct account id + role name each iteration so the containment
		// dedup and match cap behave as they would on real dense input.
		fmt.Fprintf(&b, "arn:aws:iam::%012d:role/Role%d ", i, i)
	}
	line := b.String()

	// -race inflates wall-clock 5-20x, so relax the ceiling under the race
	// detector. The scan still runs (so -race exercises the per-line cached
	// state); only the timing bound is relaxed.
	ceiling := 3 * time.Second
	if raceEnabled {
		ceiling = 30 * time.Second
	}

	v := NewValidator()
	start := time.Now()
	matches, err := v.ValidateContent(line, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("expected matches on the worst-case line, got 0 (perf guard must not disable detection)")
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a %d-byte single line took %v (> %v ceiling); "+
			"the O(n^2) per-match negative-keyword rescan may have regressed", len(line), elapsed, ceiling)
	}
	t.Logf("1MB single line: %d matches in %v (ceiling %v)", len(matches), elapsed, ceiling)
}
