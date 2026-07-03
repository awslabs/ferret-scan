// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"sync"
)

// BytesLimiter is a byte-weighted admission gate that bounds how many bytes of
// content are held in memory across concurrently processing files. It closes
// the "admission" slice of v2 gap 2.3: the per-file 100MB size check is not a
// memory budget, so N concurrent large files multiply memory independently
// (workers × up-to-100MB × the combine copy). On a memory-constrained embedder
// (e.g. Lambda) that envelope can OOM even though each individual file is within
// the size gate.
//
// It complements Limiter, which bounds concurrency by COUNT: Limiter keeps the
// number of in-flight validator goroutines proportional to CPU, while
// BytesLimiter keeps the number of in-flight content BYTES under a ceiling. A
// file worker acquires its content size before validating and releases it after,
// so total live validator content never exceeds the budget regardless of how
// many workers run.
//
// It is a thin, dependency-free weighted semaphore (mutex + cond), not
// golang.org/x/sync/semaphore — the project avoids that dependency for a
// primitive this small, mirroring Limiter.
//
// A zero-value or non-positive budget disables the gate entirely: Acquire/Release
// become no-ops, so callers that do not opt in behave exactly as before.
type BytesLimiter struct {
	mu        sync.Mutex
	cond      *sync.Cond
	budget    int64 // total bytes allowed in flight; <= 0 means unbounded (disabled)
	available int64 // bytes currently free
}

// NewBytesLimiter returns a BytesLimiter permitting up to budget bytes in flight.
// A budget <= 0 disables the gate (Acquire/Release are no-ops), which is the
// behavior-preserving default for callers that do not set a live-bytes budget.
func NewBytesLimiter(budget int64) *BytesLimiter {
	bl := &BytesLimiter{budget: budget, available: budget}
	bl.cond = sync.NewCond(&bl.mu)
	return bl
}

// AcquireBytes blocks until n bytes of budget are free, then reserves them and
// returns nil. The caller MUST call ReleaseBytes(n) exactly once on success.
//
// Behavior notes:
//   - When the gate is disabled (budget <= 0), this returns nil immediately and
//     ReleaseBytes is a no-op — a true passthrough.
//   - n <= 0 reserves nothing and returns nil immediately (empty content never
//     blocks and never needs releasing, though ReleaseBytes(0) is safe).
//   - Oversized single item: if n exceeds the whole budget, the item is still
//     admitted once the pool is otherwise empty (available == budget), so a file
//     larger than the budget can never deadlock — it runs alone. This mirrors the
//     "must permit at least one holder" rule in Limiter.
//   - If ctx is cancelled/expired before admission, it returns ctx.Err() and the
//     caller MUST NOT call ReleaseBytes.
func (bl *BytesLimiter) AcquireBytes(ctx context.Context, n int64) error {
	if bl == nil || bl.budget <= 0 || n <= 0 {
		return ctx.Err() // nil unless the caller passed an already-done ctx
	}

	// Wake the cond wait when ctx is cancelled. Without this, a blocked waiter
	// would not observe cancellation until some other holder released bytes.
	stop := context.AfterFunc(ctx, func() {
		bl.mu.Lock()
		bl.cond.Broadcast()
		bl.mu.Unlock()
	})
	defer stop()

	bl.mu.Lock()
	defer bl.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Admit when enough budget is free, OR when this item alone exceeds the
		// whole budget and the pool is empty (oversized-item deadlock guard).
		if bl.available >= n || (n > bl.budget && bl.available == bl.budget) {
			bl.available -= n
			return nil
		}
		bl.cond.Wait()
	}
}

// ReleaseBytes returns n bytes to the budget and wakes any waiters. Call exactly
// once per successful AcquireBytes with the same n. It is a no-op when the gate
// is disabled or n <= 0. available is capped at budget so a stray or mismatched
// release can never inflate the pool beyond its ceiling.
func (bl *BytesLimiter) ReleaseBytes(n int64) {
	if bl == nil || bl.budget <= 0 || n <= 0 {
		return
	}
	bl.mu.Lock()
	bl.available += n
	if bl.available > bl.budget {
		bl.available = bl.budget
	}
	bl.cond.Broadcast()
	bl.mu.Unlock()
}
