// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// TestBytesLimiter_DisabledIsNoOp verifies that a non-positive budget disables
// the gate: AcquireBytes never blocks and ReleaseBytes is harmless. This is the
// behavior-preserving default for callers that don't set MaxLiveBytes.
func TestBytesLimiter_DisabledIsNoOp(t *testing.T) {
	for _, budget := range []int64{0, -1} {
		bl := NewBytesLimiter(budget)
		// Acquiring more than "budget" must not block.
		if err := bl.AcquireBytes(context.Background(), 1<<30); err != nil {
			t.Fatalf("budget=%d: disabled limiter should not error, got %v", budget, err)
		}
		bl.ReleaseBytes(1 << 30) // no-op, must not panic
	}
	// A nil limiter is also a safe no-op.
	var nilBL *BytesLimiter
	if err := nilBL.AcquireBytes(context.Background(), 100); err != nil {
		t.Fatalf("nil limiter acquire should be a no-op, got %v", err)
	}
	nilBL.ReleaseBytes(100)
}

// TestBytesLimiter_ZeroBytesNeverBlocks confirms empty content is admitted
// immediately even against a tiny budget.
func TestBytesLimiter_ZeroBytesNeverBlocks(t *testing.T) {
	bl := NewBytesLimiter(10)
	if err := bl.AcquireBytes(context.Background(), 0); err != nil {
		t.Fatalf("zero-byte acquire should not block or error, got %v", err)
	}
	bl.ReleaseBytes(0)
}

// TestBytesLimiter_BlocksUntilRelease verifies the core budget semantics: a
// second acquire that would exceed the budget blocks until the first releases.
func TestBytesLimiter_BlocksUntilRelease(t *testing.T) {
	bl := NewBytesLimiter(100)

	// Reserve 80 of 100.
	if err := bl.AcquireBytes(context.Background(), 80); err != nil {
		t.Fatal(err)
	}

	// A 40-byte acquire cannot fit (80+40 > 100); it must block until release.
	admitted := make(chan struct{})
	go func() {
		_ = bl.AcquireBytes(context.Background(), 40)
		close(admitted)
	}()

	select {
	case <-admitted:
		t.Fatal("second acquire admitted before budget was freed")
	default:
		// Expected: still blocked.
	}

	bl.ReleaseBytes(80) // frees budget; the waiter should now proceed
	<-admitted
}

// TestBytesLimiter_OversizedItemRunsAlone verifies the deadlock guard: an item
// larger than the whole budget is still admitted when the pool is empty, so it
// runs alone rather than blocking forever.
func TestBytesLimiter_OversizedItemRunsAlone(t *testing.T) {
	bl := NewBytesLimiter(100)
	if err := bl.AcquireBytes(context.Background(), 250); err != nil {
		t.Fatalf("oversized item should be admitted alone, got %v", err)
	}
	// While the oversized item holds the (over-)budget, another item must wait.
	blocked := make(chan struct{})
	go func() {
		_ = bl.AcquireBytes(context.Background(), 10)
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("a second item was admitted while the oversized item held the pool")
	default:
	}
	bl.ReleaseBytes(250)
	<-blocked
}

// TestBytesLimiter_ContextCancelUnblocks verifies a blocked waiter observes
// context cancellation and returns ctx.Err() without needing a release.
func TestBytesLimiter_ContextCancelUnblocks(t *testing.T) {
	bl := NewBytesLimiter(100)
	if err := bl.AcquireBytes(context.Background(), 100); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- bl.AcquireBytes(ctx, 50) }()

	cancel() // no release; the only way the waiter unblocks is via ctx
	if err := <-errCh; err == nil {
		t.Fatal("expected ctx error from a cancelled blocked acquire, got nil")
	}
}

// TestBytesLimiter_AlreadyCancelledCtx verifies an already-cancelled context is
// honored promptly even when budget is available.
func TestBytesLimiter_AlreadyCancelledCtx(t *testing.T) {
	bl := NewBytesLimiter(100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bl.AcquireBytes(ctx, 10); err == nil {
		t.Fatal("expected error for already-cancelled ctx")
	}
}

// TestBytesLimiter_ConcurrentNeverExceedsBudget is the -race stress test: many
// goroutines acquire/release; the concurrently-held total must never exceed the
// budget.
func TestBytesLimiter_ConcurrentNeverExceedsBudget(t *testing.T) {
	const budget int64 = 1000
	bl := NewBytesLimiter(budget)

	var inFlight int64
	var maxSeen int64
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int64) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := bl.AcquireBytes(context.Background(), n); err != nil {
					continue
				}
				cur := atomic.AddInt64(&inFlight, n)
				for {
					m := atomic.LoadInt64(&maxSeen)
					if cur <= m || atomic.CompareAndSwapInt64(&maxSeen, m, cur) {
						break
					}
				}
				atomic.AddInt64(&inFlight, -n)
				bl.ReleaseBytes(n)
			}
		}(int64(100 + i*5)) // sizes 100..345, all <= budget
	}
	wg.Wait()

	if maxSeen > budget {
		t.Fatalf("concurrently-held bytes %d exceeded budget %d", maxSeen, budget)
	}
}
