// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import (
	stdctx "context"
	"strings"
	"testing"
	"time"
)

// TestSingleLongLine_NotQuadratic guards against the O(n^2) DoS (HIGH-5, the
// worst of the four: a ~48KB single line of address tokens took ~63s). The fix
// hoists calculateStreetConfidence / hasNegativeKeywords / the buildContextInfo
// keyword scan / the FP locus regexes out of the per-match loop and replaces the
// directional loop's O(matches^2) "already matched" scan with a binary search.
func TestSingleLongLine_NotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}

	var b strings.Builder
	b.Grow(48*1024 + 64)
	b.WriteString("mailing address residence ")
	for b.Len() < 48*1024 {
		b.WriteString("123 Main St 456 Oak Ave 789 Elm Blvd PO Box 12 ")
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

// TestSingleLongLine_Cancellable verifies per-match ctx polling interrupts a
// single pathological line promptly.
func TestSingleLongLine_Cancellable(t *testing.T) {
	var b strings.Builder
	b.Grow(1<<20 + 64)
	b.WriteString("mailing address ")
	for b.Len() < 1<<20 {
		b.WriteString("123 Main St 456 Oak Ave 789 Elm Blvd ")
	}

	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	cancel()

	start := time.Now()
	_, _ = NewValidator().ValidateContentCtx(ctx, b.String(), "cancel.txt")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled scan took %s; per-match ctx polling not effective", elapsed)
	}
}
