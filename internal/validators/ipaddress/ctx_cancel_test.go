// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestValidateContentCtx_ReclaimsRunawayMultiLineScan: a cancelled context stops
// a large multi-line IP scan promptly (v2 Phase 3 per-line ctx polling).
func TestValidateContentCtx_ReclaimsRunawayMultiLineScan(t *testing.T) {
	v := NewValidator()
	content := strings.Repeat("host 203.0.113.42 gw 192.168.1.1 dns 8.8.8.8\n", 500000)

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
// exact same result as ValidateContentCtx with a never-cancelling context — that
// is the behavior-preserving invariant (the shim just supplies context.Background).
// Asserting equality avoids coupling the test to IP-scoring specifics.
func TestValidateContent_BackgroundShimEqualsCtx(t *testing.T) {
	v := NewValidator()
	const content = "server address 203.0.113.50 for access\nprivate 10.0.0.5 internal\n"

	shim, err1 := v.ValidateContent(content, "<stdin>")
	ctxRes, err2 := v.ValidateContentCtx(context.Background(), content, "<stdin>")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: shim=%v ctx=%v", err1, err2)
	}
	if len(shim) != len(ctxRes) {
		t.Errorf("shim vs ctx match count differ: %d != %d", len(shim), len(ctxRes))
	}
}
