// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"runtime"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/observability"
)

// TestAdaptiveProcessor_StopExitsScalingLoop ensures the adaptive scaling
// goroutine exits when Stop is called. Before the fix, Stop only stopped the
// ticker and the goroutine kept blocking on the closed-but-never-signaled
// channel — leaking one goroutine per NewAdaptiveProcessor.
func TestAdaptiveProcessor_StopExitsScalingLoop(t *testing.T) {
	cfg := DefaultAdaptiveConfig()
	cfg.ScalingCheckInterval = 5 * time.Millisecond

	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		ap := NewAdaptiveProcessor(cfg, observability.NewStandardObserver(observability.ObservabilityMetrics, nil))
		// Give the loop a tick or two to start.
		time.Sleep(10 * time.Millisecond)
		ap.Stop()
	}

	// Yield so any exiting goroutines complete.
	time.Sleep(50 * time.Millisecond)
	runtime.GC()

	after := runtime.NumGoroutine()
	// Allow a small tolerance for runtime fluctuation; the leak would
	// produce ~20 extra goroutines.
	if after-before > 5 {
		t.Fatalf("scaling loop leaked goroutines: before=%d after=%d", before, after)
	}
}

// Note: a Stop()-twice idempotence test would currently fail because
// WorkerPool.Stop closes its results channel unconditionally — a separate
// pre-existing bug. AdaptiveProcessor.Stop itself is now safe to call twice
// (sync.Once-guarded), but the underlying WorkerPool.Stop isn't. Leaving
// that to a follow-up so this commit stays focused on the goroutine leak.
