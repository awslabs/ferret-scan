// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestValidateContentCtx_ReclaimsRunawayMultiLineScan: a cancelled context stops
// a large multi-line phone scan promptly (v2 Phase 3 per-line ctx polling).
func TestValidateContentCtx_ReclaimsRunawayMultiLineScan(t *testing.T) {
	v := NewValidator()
	content := strings.Repeat("call 212-555-0142 or 415-555-0199 or 312-555-0123\n", 500000)

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

// TestValidateContent_BackgroundShimUnaffected: the non-ctx shim still detects.
func TestValidateContent_BackgroundShimUnaffected(t *testing.T) {
	v := NewValidator()
	matches, err := v.ValidateContent("call me at 212-555-0142 tomorrow", "<stdin>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Error("expected the phone number to be detected via the background shim")
	}
}
