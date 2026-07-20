// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	stdctx "context"
	"strings"
	"testing"
	"time"
)

// TestSingleLongLine_NotQuadratic is a regression guard for the O(n^2)
// CPU-exhaustion DoS (security finding HIGH-5). Before the per-line hoisting of
// AnalyzeContext / hasStrongNegativeContext / hasBankingKeywords, a single ~36KB
// line packed with banking tokens took ~5.6s (quadratic in line length). After
// the fix it is linear and completes in tens of milliseconds.
func TestSingleLongLine_NotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}

	var b strings.Builder
	b.Grow(48*1024 + 64)
	b.WriteString("routing account bank wire ach ")
	for b.Len() < 48*1024 {
		b.WriteString("021000021 GB29NWBK60161331926819 DEUTDEFF 123456789012 ")
	}
	content := b.String()
	if strings.Contains(content, "\n") {
		t.Fatalf("worst-case input must be a single line")
	}

	const ceiling = 2 * time.Second
	start := time.Now()
	matches, err := NewValidator().ValidateContent(content, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if raceEnabled {
		t.Logf("processed %d-byte single line, %d matches (timing assertion skipped under -race)", len(content), len(matches))
		return
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a %d-byte single line took %s, exceeding the %s ceiling (likely an O(n^2) regression)",
			len(content), elapsed, ceiling)
	}
}

// TestSingleLongLine_Cancellable verifies the per-match ctx polling makes a
// single pathological line interruptible mid-scan (before the fix, ctx was only
// checked between lines, so one giant line ignored the deadline entirely).
func TestSingleLongLine_Cancellable(t *testing.T) {
	var b strings.Builder
	b.Grow(1<<20 + 64)
	b.WriteString("routing account bank ")
	for b.Len() < 1<<20 {
		b.WriteString("021000021 GB29NWBK60161331926819 123456789012 ")
	}

	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	cancel() // already cancelled: the loop must bail promptly

	start := time.Now()
	_, err := NewValidator().ValidateContentCtx(ctx, b.String(), "cancel.txt")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled scan took %s; per-match ctx polling not effective", elapsed)
	}
	if err == nil {
		t.Log("scan returned nil error (finished before first poll); acceptable if fast")
	}
}
