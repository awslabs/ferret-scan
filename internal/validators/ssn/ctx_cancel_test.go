// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/execguard"
)

// TestValidateContentCtx_ReclaimsRunawayMultiLineScan is the v2 Phase 3
// regression test: a large multi-line input that would otherwise run to
// completion is reclaimed promptly when the context is already cancelled — the
// validator polls ctx per line and returns ctx.Err() instead of scanning every
// line.
func TestValidateContentCtx_ReclaimsRunawayMultiLineScan(t *testing.T) {
	v := NewValidator()

	// Many lines of dense near-SSN tokens — enough that a full scan is clearly
	// measurable, so an early return is unambiguous.
	line := "ssn 449-87-4100 and 555-12-3456 and 111-22-3333"
	content := strings.Repeat(line+"\n", 500000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the loop must bail on (or before) the first check

	start := time.Now()
	matches, err := v.ValidateContentCtx(ctx, content, "<stdin>")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected a context error from a cancelled scan, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// Reclaimed promptly: must not scan all 500k lines. Generous ceiling guards
	// against a regression where the poll is missing (which would take seconds).
	if elapsed > 500*time.Millisecond {
		t.Errorf("cancelled scan took %v; expected prompt return (per-line ctx poll missing?)", elapsed)
	}
	// Partial matches are acceptable (<= the first ctxCheckStride lines' worth);
	// the point is we did NOT scan the whole input.
	_ = matches
}

// TestValidateContentCtx_DeadlineWhileScanning verifies a deadline that fires
// mid-scan also reclaims the loop (not just an already-cancelled context).
func TestValidateContentCtx_DeadlineWhileScanning(t *testing.T) {
	v := NewValidator()
	content := strings.Repeat("ssn 449-87-4100 more text here\n", 2000000)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := v.ValidateContentCtx(ctx, content, "<stdin>")
	elapsed := time.Since(start)

	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
	// Should stop within a small multiple of the 50ms budget, not scan 2M lines.
	if elapsed > 5*time.Second {
		t.Errorf("scan ran %v past a 50ms deadline; ctx polling not effective", elapsed)
	}
}

// TestValidateContent_BackgroundShimUnaffected confirms the non-ctx shim behaves
// exactly as before: a normal scan completes and finds the SSN.
func TestValidateContent_BackgroundShimUnaffected(t *testing.T) {
	v := NewValidator()
	matches, err := v.ValidateContent("employee ssn: 449-87-4100 on record", "<stdin>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Error("expected the SSN to be detected via the background shim")
	}
}

// TestLineLoopCancelled_StrideBehavior locks the helper's cheap-check contract:
// it reads ctx only on stride boundaries, and an already-done ctx is caught at
// i==0.
func TestLineLoopCancelled_StrideBehavior(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if !execguard.LineLoopCancelled(done, 0) {
		t.Error("expected cancellation to be detected at i=0")
	}
	// A live context never reports cancelled regardless of index.
	live := context.Background()
	for _, i := range []int{0, 1, 255, 256, 512} {
		if execguard.LineLoopCancelled(live, i) {
			t.Errorf("live context reported cancelled at i=%d", i)
		}
	}
	// nil context never cancels.
	if execguard.LineLoopCancelled(nil, 0) {
		t.Error("nil context must not report cancelled")
	}
}
