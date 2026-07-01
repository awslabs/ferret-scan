// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLimiter_BoundsConcurrency verifies the semaphore never lets more than n
// holders run at once, under heavy contention. Run with -race for full value.
func TestLimiter_BoundsConcurrency(t *testing.T) {
	const n = 4
	const goroutines = 50
	lim := NewLimiter(n)

	var inFlight int64
	var maxSeen int64
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := lim.Acquire(context.Background()); err != nil {
				t.Errorf("Acquire failed: %v", err)
				return
			}
			cur := atomic.AddInt64(&inFlight, 1)
			// Track the high-water mark of concurrent holders.
			for {
				old := atomic.LoadInt64(&maxSeen)
				if cur <= old || atomic.CompareAndSwapInt64(&maxSeen, old, cur) {
					break
				}
			}
			time.Sleep(time.Millisecond) // hold the slot briefly to force contention
			atomic.AddInt64(&inFlight, -1)
			lim.Release()
		}()
	}
	wg.Wait()

	if maxSeen > n {
		t.Errorf("limiter allowed %d concurrent holders; cap is %d", maxSeen, n)
	}
	if maxSeen == 0 {
		t.Error("no holders observed — test did not exercise the limiter")
	}
}

// TestLimiter_AcquireRespectsCancelledContext verifies Acquire returns the
// context error (and grants no token) when the limiter is full and ctx is
// cancelled — so a cancelled scan never blocks forever waiting for a slot.
func TestLimiter_AcquireRespectsCancelledContext(t *testing.T) {
	lim := NewLimiter(1)
	// Fill the single slot.
	if err := lim.Acquire(context.Background()); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer lim.Release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	err := lim.Acquire(ctx)
	if err == nil {
		t.Fatal("expected Acquire to fail on a cancelled context while full")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("Acquire on a cancelled context should return promptly, took %v", time.Since(start))
	}
}

// TestLimiter_AcquireUnblocksOnRelease verifies a waiter proceeds once a slot is
// freed (the happy path under contention).
func TestLimiter_AcquireUnblocksOnRelease(t *testing.T) {
	lim := NewLimiter(1)
	if err := lim.Acquire(context.Background()); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		_ = lim.Acquire(context.Background()) // blocks until Release below
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second Acquire returned before the slot was released")
	case <-time.After(50 * time.Millisecond):
		// expected: still blocked
	}

	lim.Release()
	select {
	case <-acquired:
		// expected: unblocked
	case <-time.After(time.Second):
		t.Fatal("second Acquire did not proceed after Release")
	}
	lim.Release()
}

// TestLimiter_ZeroOrNegativeBecomesOne guards the floor: a non-positive size
// must not produce a deadlocking zero-capacity limiter.
func TestLimiter_ZeroOrNegativeBecomesOne(t *testing.T) {
	for _, n := range []int{0, -5} {
		lim := NewLimiter(n)
		if err := lim.Acquire(context.Background()); err != nil {
			t.Errorf("NewLimiter(%d): Acquire blocked/failed: %v", n, err)
		}
		lim.Release()
	}
}

// TestLimiter_StrayReleaseIsSafe verifies Release without a matching Acquire
// does not block or panic (a stray Release must never wedge a scan).
func TestLimiter_StrayReleaseIsSafe(t *testing.T) {
	lim := NewLimiter(2)
	lim.Release() // no token held
	// The limiter must still grant its full capacity afterward.
	if err := lim.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire after stray Release: %v", err)
	}
	if err := lim.Acquire(context.Background()); err != nil {
		t.Fatalf("second Acquire after stray Release: %v", err)
	}
	lim.Release()
	lim.Release()
}
