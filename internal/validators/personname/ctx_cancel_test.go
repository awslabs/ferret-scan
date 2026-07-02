// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestValidateContentCtx_ReclaimsRunawayMultiLineScan: a cancelled context stops a
// large multi-line scan promptly (v2 Phase 3 per-line ctx polling). personname
// returns the pre-dedup partial matches plus ctx.Err() on cancel.
func TestValidateContentCtx_ReclaimsRunawayMultiLineScan(t *testing.T) {
	v := NewValidator()
	content := strings.Repeat("John Smith and Jane Doe met Robert Brown today\n", 500000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := v.ValidateContentCtx(ctx, content, "<stdin>")
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("cancelled scan took %v; expected prompt return", elapsed)
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestValidateContent_BackgroundShimEqualsCtx: the non-ctx shim must produce the
// same result as ValidateContentCtx with a never-cancelling context.
func TestValidateContent_BackgroundShimEqualsCtx(t *testing.T) {
	const content = "John Smith and Jane Doe met Robert Brown today\nAlice Johnson called\n"
	shim, err1 := NewValidator().ValidateContent(content, "<stdin>")
	ctxRes, err2 := NewValidator().ValidateContentCtx(context.Background(), content, "<stdin>")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: shim=%v ctx=%v", err1, err2)
	}
	if len(shim) != len(ctxRes) {
		t.Errorf("shim vs ctx match count differ: %d != %d", len(shim), len(ctxRes))
	}
}
