// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// buildManyARNs returns n lines each carrying a distinct AWS IAM-role ARN, so the
// scoring loop over deduped spans has n iterations to poll.
func buildManyARNs(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "arn:aws:iam::%012d:role/Role%d\n", i, i)
	}
	return b.String()
}

// TestValidateContentCtx_ReclaimsRunawayScan: a cancelled context stops a large
// scan promptly (v2 Phase 3 per-span ctx polling in the scoring loop).
func TestValidateContentCtx_ReclaimsRunawayScan(t *testing.T) {
	v := NewValidator()
	// Keep the input under maxContentBytes (5MB); ~100k ARNs (~3.9MB) still gives
	// the scoring loop plenty of iterations for the pre-cancelled poll to catch.
	content := buildManyARNs(100000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// An already-cancelled scan bails at the entry check before the whole-content
	// regex pass, so this is near-instant. -race inflates wall-clock 5-20x, so
	// relax the ceiling under the race detector (the scan still runs; only the
	// timing bound is relaxed). The ctx.Err() assertion below is the real guard.
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
	const content = "prod arn:aws:iam::123456789012:role/PaymentsAdmin\nexample arn:aws:iam::123456789012:role/PaymentsAdmin\n"
	shim, err1 := NewValidator().ValidateContent(content, "<stdin>")
	ctxRes, err2 := NewValidator().ValidateContentCtx(context.Background(), content, "<stdin>")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: shim=%v ctx=%v", err1, err2)
	}
	if len(shim) != len(ctxRes) {
		t.Errorf("shim vs ctx match count differ: %d != %d", len(shim), len(ctxRes))
	}
}
