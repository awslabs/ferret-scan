// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package execguard provides the single dispatch chokepoint through which every
// validator invocation should pass. It exists to close two structural gaps
// identified in the v2 architecture audit (see docs/proposals/V2_ARCHITECTURE.md):
//
//   - Gap 1.3 — a panic inside a validator goroutine crashes the entire process,
//     because Go panics do not cross goroutine boundaries and the only recover()
//     lives on a different (worker) goroutine. SafeRun recovers at the boundary
//     where untrusted/complex validator code is actually invoked and converts the
//     panic into a NON-retryable error, so the surrounding resilience retry
//     wrapper does not re-run a deterministically-panicking validator.
//
//   - Gap 1.1 — the detector.Validator interface takes no context.Context, so a
//     running validator cannot observe cancellation or a deadline. execguard
//     introduces the OPTIONAL ContextAwareValidator extension interface: a
//     validator that implements ValidateContentCtx is handed the context and can
//     poll it; validators that do not are invoked exactly as before. This is the
//     additive, behavior-preserving seam that Phase 3 builds on to make residual
//     O(n^2) hot paths interruptible.
//
// Phase 1 deliberately does NOT change the detector.Validator interface itself
// (that would be a source-breaking change for the ~13 validators and any external
// implementers). The optional interface + helper is a zero-breakage shim that can
// be adopted incrementally.
package execguard

import (
	"context"
	"errors"
	"fmt"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/resilience"
)

// ErrMatchBudgetExceeded is returned (alongside the truncated, capped matches) by
// ValidateContent when a validator emits more matches than its ValidatorBudget
// MatchLimit allows. Callers can errors.Is-check it to record incomplete coverage
// (see internal/core/scanner.go). It is distinct from context errors: a match-cap
// hit is not a deadline/cancellation.
var ErrMatchBudgetExceeded = errors.New("validator match budget exceeded")

// ContextAwareValidator is an OPTIONAL extension of detector.Validator. A
// validator that implements it receives the active context and is expected to
// poll ctx.Err() at loop/match boundaries so it can abort promptly on deadline
// or cancellation. Validators that do not implement it keep their current
// behavior and are invoked through the legacy ValidateContent method.
type ContextAwareValidator interface {
	ValidateContentCtx(ctx context.Context, content, originalPath string) ([]detector.Match, error)
}

// SafeRun executes fn under panic recovery and best-effort boundary
// cancellation. It is the primitive both fan-out sites use.
//
// Semantics:
//   - If ctx is already cancelled/expired when SafeRun is entered, fn is NOT
//     invoked and ctx.Err() is returned. (A validator already in flight cannot
//     be interrupted in Phase 1 — see package doc — but new work is not started.)
//   - If fn panics, the panic is recovered and returned as a NON-retryable
//     resilience error. matches is reset to nil so a partial slice produced
//     before the panic is never surfaced as if it were complete.
//
// Note on no-payload-bytes: the recovered value is interpolated into the error
// message. Runtime panics (nil map, index out of range, etc.) carry no payload
// content; a validator that explicitly panic()s with matched bytes would be the
// only way payload could reach this message, which no current validator does.
// Callers already gate validator-error logging behind --debug.
func SafeRun(ctx context.Context, name string, fn func() ([]detector.Match, error)) (matches []detector.Match, err error) {
	defer func() {
		if r := recover(); r != nil {
			matches = nil
			// Non-retryable: a deterministic panic will panic again on retry,
			// so re-running it only amplifies the failure. NewPermanentError
			// produces a *resilience.ClassifiedError that ClassifyError returns
			// verbatim (Retryable=false), bypassing string-based reclassification.
			err = resilience.NewPermanentError(fmt.Sprintf("validator %q panicked: %v", name, r), nil)
		}
	}()

	if ctx != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
	}

	return fn()
}

// ValidateContent dispatches a single validator's content validation through the
// chokepoint: it prefers the context-aware method when the validator implements
// ContextAwareValidator, otherwise it calls the legacy ValidateContent. Either
// way the call is wrapped by SafeRun (panic recovery + boundary cancellation).
func ValidateContent(ctx context.Context, name string, v detector.Validator, content, originalPath string) ([]detector.Match, error) {
	b := budgetFor(ctx, name)

	// Per-validator TIME budget: derive a child deadline tighter than the parent
	// (per-file/job) deadline. context.WithTimeout never extends a parent deadline,
	// so the tighter of {parent, TimeLimit} always wins. The derived ctx is the one
	// handed to a ContextAwareValidator, which polls it via LineLoopCancelled — so
	// a runaway validator self-terminates at its own budget. Disabled (<=0) leaves
	// ctx untouched: byte-identical to the no-budget path.
	if b.TimeLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.TimeLimit)
		defer cancel()
	}

	matches, err := SafeRun(ctx, name, func() ([]detector.Match, error) {
		if cav, ok := v.(ContextAwareValidator); ok {
			return cav.ValidateContentCtx(ctx, content, originalPath)
		}
		return v.ValidateContent(content, originalPath)
	})

	// Per-validator MATCH budget: cap only a SUCCESSFUL result. Never truncate a
	// partial slice returned alongside an error (e.g. ctx.Err() from a timed-out
	// scan) — that path already carries its own incompleteness meaning, and
	// dropping matches a timed-out scan did find would double-signal. When the
	// count is at/under the cap (or the cap is disabled), matches is returned
	// completely unmutated: byte-identical to the no-budget path.
	if err == nil && b.MatchLimit > 0 && len(matches) > b.MatchLimit {
		matches = matches[:b.MatchLimit]
		err = fmt.Errorf("%w: validator %q emitted more than %d matches", ErrMatchBudgetExceeded, name, b.MatchLimit)
	}
	return matches, err
}
