// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	stdctx "context"
	"strings"
	"testing"
	"time"
)

// TestSingleLongLine_NotQuadratic guards against the O(n^2) DoS the other
// validators were hardened against (a 48KB single line of dense base32
// tokens with OTP keywords took ~6.7s before the per-line context hoist).
// The fix computes AnalyzeContext / keyword sets / positive-negative context
// once per line and builds ContextInfo from FindAllStringIndex offsets
// instead of re-scanning the line per match.
func TestSingleLongLine_NotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}

	var b strings.Builder
	b.Grow(48*1024 + 64)
	b.WriteString("2fa secret totp ")
	for b.Len() < 48*1024 {
		b.WriteString("jbswy3dpehpk3pxp krugkidrovuwg2zamjzg653o JBSWY3DPEHPK3PXP ")
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
	b.WriteString("2fa secret totp ")
	for b.Len() < 1<<20 {
		b.WriteString("jbswy3dpehpk3pxp krugkidrovuwg2zamjzg653o JBSWY3DPEHPK3PXP ")
	}

	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	cancel()

	start := time.Now()
	_, _ = NewValidator().ValidateContentCtx(ctx, b.String(), "cancel.txt")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled scan took %s; per-match ctx polling not effective", elapsed)
	}
}
