// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestValidateContentCtx_ReclaimsRunawayMultiLineScan: a cancelled context stops a
// large multi-line scan promptly (v2 Phase 3 per-line ctx polling). SECRETS' DoS
// shape is many dense lines (per-line shell/entropy work), so the input is
// many-lines rather than one long line.
func TestValidateContentCtx_ReclaimsRunawayMultiLineScan(t *testing.T) {
	v := NewValidator()
	content := strings.Repeat("export API_KEY=\"AKIAIOSFODNN7EXAMPLE\" password=hunter2 token=abcd1234\n", 500000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// An already-cancelled scan bails at the entry check before the whole-content
	// context-analysis / multi-line passes, so this is near-instant. -race inflates
	// wall-clock 5-20x, so relax the ceiling under the race detector.
	ceiling := 500 * time.Millisecond
	if raceEnabled {
		ceiling = 5 * time.Second
	}

	start := time.Now()
	_, err := v.ValidateContentCtx(ctx, content, "<stdin>")
	if elapsed := time.Since(start); elapsed > ceiling {
		t.Errorf("cancelled scan took %v; expected prompt return", elapsed)
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestValidateContent_BackgroundShimEqualsCtx: the non-ctx shim must produce the
// same result as ValidateContentCtx with a never-cancelling context.
func TestValidateContent_BackgroundShimEqualsCtx(t *testing.T) {
	const content = "export API_KEY=\"AKIAIOSFODNN7EXAMPLE\"\npassword=hunter2\n"
	shim, err1 := NewValidator().ValidateContent(content, "<stdin>")
	ctxRes, err2 := NewValidator().ValidateContentCtx(context.Background(), content, "<stdin>")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: shim=%v ctx=%v", err1, err2)
	}
	if len(shim) != len(ctxRes) {
		t.Errorf("shim vs ctx match count differ: %d != %d", len(shim), len(ctxRes))
	}
}
