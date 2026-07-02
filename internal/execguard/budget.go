// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"time"
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
