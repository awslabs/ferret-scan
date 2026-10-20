// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"fmt"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// ValidatorBudget bounds a single validator's work on one scan. Both fields are
// opt-in: the zero value (TimeLimit<=0, MatchLimit<=0) is DISABLED and preserves
// historical behavior exactly. Budgets are carried on the context (see
// WithBudgets) so no fan-out signature changes are needed — the single dispatch
// chokepoint (ValidateContent) reads the budget for the validator it is about to
// run.
type ValidatorBudget struct {
	// TimeLimit is a per-validator wall-clock ceiling. When > 0, ValidateContent
	// derives a child context.WithTimeout(ctx, TimeLimit) so the validator gets
	// its own deadline, tighter than the per-file/job deadline. It only has teeth
	// on validators that poll the context (execguard.ContextAwareValidator); a
	// legacy validator still gets the tighter deadline for the SafeRun entry check
	// but cannot be interrupted mid-run.
	TimeLimit time.Duration

	// MatchLimit caps how many matches a validator may emit on one scan. When > 0
	// and the validator returns more, the slice is truncated (keeping emission
	// order) and ErrMatchBudgetExceeded is returned alongside the capped matches.
	MatchLimit int
}

// budgetKey is the unexported context key type for the per-validator budget map,
// collision-proof against any other context value.
type budgetKey struct{}

// WithBudgets attaches per-validator budgets (keyed by the same validator name
// passed to ValidateContent) to ctx. An empty/nil map is a no-op: the parent ctx
// is returned unchanged, so the context-value chain is identical to today when no
// budgets are configured (preserving byte-identical behavior).
func WithBudgets(ctx context.Context, budgets map[string]ValidatorBudget) context.Context {
	if len(budgets) == 0 {
		return ctx
	}
	return context.WithValue(ctx, budgetKey{}, budgets)
}

// budgetFor returns the budget configured for validator name, or the zero
// (disabled) ValidatorBudget when none is set. A nil ctx or a ctx without budgets
// yields the disabled zero value.
func budgetFor(ctx context.Context, name string) ValidatorBudget {
	if ctx == nil {
		return ValidatorBudget{}
	}
	if m, ok := ctx.Value(budgetKey{}).(map[string]ValidatorBudget); ok {
		return m[name] // absent key => zero value => disabled
	}
	return ValidatorBudget{}
}

// LoopBudget starts the budget for a validator that is dispatched once per ITEM
// through SafeRun rather than once per file through ValidateContent. The dual-path
// bridge's metadata loop is that site: it runs the metadata validator once per
// metadata section of a file.
//
// The budget is read under name exactly as ValidateContent reads it, so one
// --validator-budget entry reaches both kinds of dispatch. Before #771 the metadata
// loop never read a budget at all: budgetFor ran only inside ValidateContent, and
// the loop dispatched under the Go type name besides. So METADATA=<d> was accepted,
// checked against the list of check names, and did nothing.
//
// The TIME budget becomes ONE deadline for the whole loop, returned as the context
// the caller checks before each item. That check is the granularity: an item
// already running is not interrupted, because the metadata validator does not poll
// its context (#110 exempted it: it is not driven by a token loop). A budget that
// fires mid-item therefore stops the loop when that item returns. Disabled (<= 0)
// returns ctx itself and a no-op cancel, so the no-budget path is unchanged.
//
// The returned ValidatorBudget is for CapMatches, applied to the union of the items.
func LoopBudget(ctx context.Context, name string) (context.Context, context.CancelFunc, ValidatorBudget) {
	b := budgetFor(ctx, name)
	if b.TimeLimit <= 0 {
		return ctx, func() {}, b
	}
	loopCtx, cancel := context.WithTimeout(ctx, b.TimeLimit)
	return loopCtx, cancel, b
}

// CapMatches applies b's MATCH budget to matches that validator name produced
// without error. Over the cap it keeps the first MatchLimit matches, in emission
// order, and returns ErrMatchBudgetExceeded alongside them. At or under the cap, or
// with the cap disabled, matches is returned unmutated with a nil error.
//
// Callers pass only successfully produced matches: a partial slice that came back
// with an error already carries its own incompleteness (see ValidateContent).
func CapMatches(name string, b ValidatorBudget, matches []detector.Match) ([]detector.Match, error) {
	if b.MatchLimit <= 0 || len(matches) <= b.MatchLimit {
		return matches, nil
	}
	return matches[:b.MatchLimit], fmt.Errorf("%w: validator %q emitted more than %d matches",
		ErrMatchBudgetExceeded, name, b.MatchLimit)
}
