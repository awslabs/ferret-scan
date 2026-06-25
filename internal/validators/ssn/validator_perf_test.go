// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"strings"
	"testing"
	"time"
)

// TestSSNValidator_SingleLineDoSRegression guards against the O(n^2) blowup that
// previously made ValidateContent quadratic in the length of a single line.
//
// The worst case is ONE very long line (no newlines) densely packed with valid
// SSN tokens. The original code recomputed per-line-global work (whole-line
// strings.ToLower, keyword scans, tabular/encoded detectors) and re-ran
// strings.Index(line, match) once PER MATCH, so M matches on a length-N line cost
// O(M*N). With M growing linearly in N, that is O(N^2): at ~16KB this line took
// ~14s, and a 1MB line did not finish within 10 minutes.
//
// After hoisting the line-global work out of the per-match loop and caching the
// first-occurrence offset of each token, the same 1MB line completes in a few
// seconds. We assert a generous 30s ceiling so this catches a regression to
// quadratic behavior without being flaky on slow/CI machines.
func TestSSNValidator_SingleLineDoSRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression test in -short mode")
	}

	const targetBytes = 1 << 20 // ~1MB single line

	var sb strings.Builder
	sb.Grow(targetBytes + 32)
	// "219-09-9999 " — 219 is a valid area number, group 09, serial 9999, so each
	// token is a valid SSN that survives all structural checks (worst case for the
	// per-match analysis path).
	for sb.Len() < targetBytes {
		sb.WriteString("219-09-9999 ")
	}
	content := sb.String()

	v := NewValidator()

	done := make(chan int, 1)
	start := time.Now()
	go func() {
		matches, err := v.ValidateContent(content, "dos_regression.txt")
		if err != nil {
			t.Errorf("ValidateContent returned error: %v", err)
		}
		done <- len(matches)
	}()

	// -race inflates wall-clock 5-20x, so relax both the assertion and the
	// watchdog timeout under the race detector. The scan still runs (so -race
	// exercises the per-line cached state); only the timing bound is relaxed.
	ceiling := 30 * time.Second
	if raceEnabled {
		ceiling = 180 * time.Second
	}
	select {
	case n := <-done:
		elapsed := time.Since(start)
		if n == 0 {
			t.Fatalf("expected matches on the worst-case line, got 0")
		}
		if elapsed > ceiling {
			t.Fatalf("ValidateContent on a 1MB single line took %v (> %v ceiling); "+
				"the O(n^2) per-match line rescan may have regressed", elapsed, ceiling)
		}
		t.Logf("1MB single line: %d matches in %v (ceiling %v)", n, elapsed, ceiling)
	case <-time.After(ceiling):
		t.Fatalf("ValidateContent on a 1MB single line did not finish within %v; "+
			"the O(n^2) per-match line rescan may have regressed", ceiling)
	}
}
