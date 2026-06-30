// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"runtime"
)

// Limiter is a counting semaphore that bounds how many validator invocations run
// concurrently across the WHOLE process. It exists to close v2 gap 2.1: file
// workers (capped at min(NumCPU, 8)) each fan out one goroutine per document
// validator (~12), so without a shared cap the live goroutine count is
// workers × validators ≈ 100 CPU-bound goroutines on an 8-core box — oversubscription
// that hurts throughput and memory under directory scans. A single shared Limiter
// keeps total in-flight validator work proportional to CPU count regardless of how
// the file/validator layers multiply.
//
// It is a thin, dependency-free counting semaphore (buffered channel), not
// golang.org/x/sync/semaphore — the project avoids adding that dependency for a
// primitive this small.
type Limiter struct {
	tokens chan struct{}
}

// NewLimiter returns a Limiter allowing n concurrent holders. n <= 0 is treated
// as 1 (a Limiter must permit at least one holder or it would deadlock).
func NewLimiter(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	return &Limiter{tokens: make(chan struct{}, n)}
}

// Acquire blocks until a token is available or ctx is done. It returns ctx.Err()
// if the context is cancelled/expired before a token is obtained, in which case
// the caller MUST NOT call Release. On success it returns nil and the caller must
// Release exactly once.
func (l *Limiter) Acquire(ctx context.Context) error {
	// Honor an already-cancelled context promptly (don't race the select).
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l.tokens <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a token. Call exactly once per successful Acquire.
func (l *Limiter) Release() {
	select {
	case <-l.tokens:
	default:
		// No token held — calling Release without a matching Acquire is a bug;
		// the default branch keeps it non-blocking rather than panicking, since a
		// stray Release must never wedge a scan.
	}
}

// DefaultLimiter is the process-wide validator-concurrency limiter. It is sized
// to GOMAXPROCS so total concurrent validator work tracks available CPU rather
// than the (file workers × validators) product. Validator dispatch acquires from
// it; see the document fan-out in internal/validators.
//
// Sizing rationale: validator work is CPU-bound regex scanning, so GOMAXPROCS is
// the natural ceiling. It is deliberately NOT min(NumCPU,8)-capped like the file
// worker pool — the file pool already bounds I/O-bound preprocessing breadth;
// this bounds CPU-bound validation depth.
var DefaultLimiter = NewLimiter(runtime.GOMAXPROCS(0))
