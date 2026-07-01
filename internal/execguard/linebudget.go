// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import "context"

// ctxCheckStride is how often (in loop iterations) a validator's line loop
// consults the context. Checking ctx.Err() on every iteration would add a
// (cheap but non-zero) atomic load to the hot path for no benefit; a stride of
// 256 bounds the worst-case over-run to at most 255 extra lines after a deadline
// fires — negligible against a multi-million-line runaway — while keeping the
// per-line cost effectively free.
const ctxCheckStride = 256

// LineLoopCancelled reports whether a validator's per-line loop should stop
// because its context is done (deadline exceeded or cancelled). It is the
// v2 Phase 3 cooperative-cancellation primitive: validators that implement
// execguard.ContextAwareValidator call this once per line so a runaway scan of a
// large multi-line input is reclaimed promptly instead of running to completion.
//
// It only actually reads ctx.Err() every ctxCheckStride iterations (and always
// on the first, i==0, so an already-expired budget skips the work entirely), so
// the common case is a single integer-modulo test. A nil ctx never cancels.
//
// Usage in a validator's ValidateContentCtx:
//
//	for i, line := range lines {
//	    if execguard.LineLoopCancelled(ctx, i) {
//	        return matches, ctx.Err() // return partial matches + why we stopped
//	    }
//	    // ... scan line ...
//	}
//
// Returning the partial matches gathered so far (rather than discarding them) is
// deliberate: a timed-out DLP scan should surface what it found, and the caller
// records ctx.Err() as an incomplete-coverage signal (see ScanResult.Incomplete).
func LineLoopCancelled(ctx context.Context, i int) bool {
	if ctx == nil {
		return false
	}
	if i%ctxCheckStride != 0 {
		return false
	}
	return ctx.Err() != nil
}
