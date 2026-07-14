// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// blockingCtxValidator implements ContextAwareValidator by blocking on ctx.Done()
// and then returning a partial match + ctx.Err(). It waits for the deadline
// rather than racing a sleep against it — the anti-flake pattern the codebase
// relies on (see execguard_test.go / validator_runner_cancel_test.go).
type blockingCtxValidator struct{ started chan struct{} }

func (b *blockingCtxValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (b *blockingCtxValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (b *blockingCtxValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (b *blockingCtxValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, errors.New("legacy path must not be used")
}
func (b *blockingCtxValidator) ValidateContentCtx(ctx context.Context, _, _ string) ([]detector.Match, error) {
	if b.started != nil {
		close(b.started)
	}
	<-ctx.Done()
	return []detector.Match{{Type: "PARTIAL", Text: "x"}}, ctx.Err()
}

// manyMatchValidator returns n matches, no error, ignoring ctx.
type manyMatchValidator struct{ n int }

func (m manyMatchValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (m manyMatchValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (m manyMatchValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (m manyMatchValidator) ValidateContent(string, string) ([]detector.Match, error) {
	out := make([]detector.Match, m.n)
	for i := range out {
		out[i] = detector.Match{Type: "T", Text: string(rune('a' + i%26))}
	}
	return out, nil
}

// --- TIME budget ---

func TestTimeBudget_FiresAndReturnsCtxErr(t *testing.T) {
	v := &blockingCtxValidator{started: make(chan struct{})}
	ctx := WithBudgets(context.Background(), map[string]ValidatorBudget{
		"STUB": {TimeLimit: 20 * time.Millisecond},
	})

	matches, err := ValidateContent(ctx, "STUB", v, "content", "p")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded from per-validator budget, got %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("want partial matches preserved, got %d", len(matches))
	}
}

func TestTimeBudget_AlreadyExpiredParentSkipsLaunch(t *testing.T) {
	// A pre-cancelled parent must skip launching the validator entirely — no
	// wall-clock involved (deterministic; the Windows-safe pattern).
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	v := &blockingCtxValidator{started: make(chan struct{})}
	ctx := WithBudgets(parent, map[string]ValidatorBudget{"STUB": {TimeLimit: time.Hour}})

	_, err := ValidateContent(ctx, "STUB", v, "content", "p")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v", err)
	}
	select {
	case <-v.started:
		t.Fatal("validator was launched despite an already-cancelled context")
	default:
	}
}

func TestTimeBudget_DisabledDoesNotDeriveDeadline(t *testing.T) {
	// With no budget, a background context has no deadline: the validator must see
	// exactly the parent ctx (no child WithTimeout). We assert by having the stub
	// report whether its ctx had a deadline.
	var sawDeadline bool
	v := deadlineProbe{report: func(has bool) { sawDeadline = has }}
	_, err := ValidateContent(context.Background(), "PROBE", v, "c", "p")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawDeadline {
		t.Error("disabled budget must not derive a deadline; validator saw one")
	}
}

// deadlineProbe reports whether the ctx it received carries a deadline.
type deadlineProbe struct{ report func(bool) }

func (deadlineProbe) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (deadlineProbe) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (deadlineProbe) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (deadlineProbe) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, errors.New("legacy path must not be used")
}
func (d deadlineProbe) ValidateContentCtx(ctx context.Context, _, _ string) ([]detector.Match, error) {
	_, has := ctx.Deadline()
	d.report(has)
	return nil, nil
}

// --- MATCH budget ---

func TestMatchBudget_TruncatesAndSignals(t *testing.T) {
	ctx := WithBudgets(context.Background(), map[string]ValidatorBudget{
		"MANY": {MatchLimit: 3},
	})
	matches, err := ValidateContent(ctx, "MANY", manyMatchValidator{n: 10}, "c", "p")
	if !errors.Is(err, ErrMatchBudgetExceeded) {
		t.Fatalf("want ErrMatchBudgetExceeded, got %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("want matches truncated to 3, got %d", len(matches))
	}
}

func TestMatchBudget_UnderCapIsUnmutated(t *testing.T) {
	ctx := WithBudgets(context.Background(), map[string]ValidatorBudget{
		"MANY": {MatchLimit: 100},
	})
	matches, err := ValidateContent(ctx, "MANY", manyMatchValidator{n: 10}, "c", "p")
	if err != nil {
		t.Fatalf("under-cap must not error, got %v", err)
	}
	if len(matches) != 10 {
		t.Fatalf("under-cap must return all matches, got %d", len(matches))
	}
}

func TestMatchBudget_DisabledReturnsAll(t *testing.T) {
	matches, err := ValidateContent(context.Background(), "MANY", manyMatchValidator{n: 10}, "c", "p")
	if err != nil {
		t.Fatalf("disabled must not error, got %v", err)
	}
	if len(matches) != 10 {
		t.Fatalf("disabled must return all matches, got %d", len(matches))
	}
}

// --- WithBudgets / budgetFor semantics ---

func TestWithBudgets_EmptyMapIsNoOp(t *testing.T) {
	parent := context.Background()
	if got := WithBudgets(parent, nil); got != parent {
		t.Error("WithBudgets(nil) must return the parent ctx unchanged")
	}
	if got := WithBudgets(parent, map[string]ValidatorBudget{}); got != parent {
		t.Error("WithBudgets(empty) must return the parent ctx unchanged")
	}
}

func TestBudgetFor_AbsentAndNilAreDisabled(t *testing.T) {
	if b := budgetFor(nil, "X"); b.TimeLimit != 0 || b.MatchLimit != 0 {
		t.Errorf("nil ctx must yield disabled budget, got %+v", b)
	}
	ctx := WithBudgets(context.Background(), map[string]ValidatorBudget{"A": {TimeLimit: time.Second}})
	if b := budgetFor(ctx, "B"); b.TimeLimit != 0 || b.MatchLimit != 0 {
		t.Errorf("absent key must yield disabled budget, got %+v", b)
	}
}
