// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
)

// stallingValidator blocks in ValidateContent until released, simulating a
// runaway/quadratic validator that ignores deadlines (the pre-v2 reality: the
// detector.Validator interface has no ctx for it to observe). The point of the
// Phase 1 change is that the SCAN no longer hangs waiting for it.
type stallingValidator struct {
	release chan struct{}
}

func (s *stallingValidator) Validate(string) ([]detector.Match, error) { return nil, nil }
func (s *stallingValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 0, nil
}
func (s *stallingValidator) AnalyzeContext(string, detector.ContextInfo) float64 { return 0 }
func (s *stallingValidator) ValidateContent(string, string) ([]detector.Match, error) {
	<-s.release // block until the test releases us
	return nil, nil
}

// TestRunValidators_ReturnsWhenContextExpiresDespiteStalledValidator is the
// keystone Phase 1 regression test: previously RunValidators did an
// unconditional wg.Wait(), so a single stalled validator blocked the whole scan
// forever with no way to terminate it short of killing the process. Now the
// join honors ctx, so the scan returns shortly after the deadline.
func TestRunValidators_ReturnsWhenContextExpiresDespiteStalledValidator(t *testing.T) {
	stall := &stallingValidator{release: make(chan struct{})}
	// Release the goroutine when the test ends so it doesn't leak past the test.
	defer close(stall.release)

	processed := newProcessed("some content", "/virtual/path")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	done := make(chan struct{})
	var runErr error
	go func() {
		_, runErr = RunValidators(ctx, []detector.Validator{stall}, processed, nil)
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		// Should return shortly after the 100ms deadline, NOT hang.
		if elapsed > 2*time.Second {
			t.Fatalf("RunValidators took %v; expected it to return shortly after the 100ms deadline", elapsed)
		}
		if runErr == nil || !errors.Is(runErr, context.DeadlineExceeded) {
			t.Errorf("expected context.DeadlineExceeded surfaced as the error, got %v", runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunValidators did not return within 3s — the stalled validator blocked the whole scan (Phase 1 regression)")
	}
}

// TestRunValidators_NormalCompletionUnaffected confirms the cancellable join did
// not change behavior on the happy path: a fast validator completes and its
// matches are returned with no context error.
func TestRunValidators_NormalCompletionUnaffected(t *testing.T) {
	v := &stubContentValidator{
		name:    "fast",
		matches: []detector.Match{{Type: "TEST", Text: "x"}},
	}
	processed := newProcessed("content", "/virtual/path")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	matches, err := RunValidators(ctx, []detector.Validator{v}, processed, nil)
	if err != nil {
		t.Fatalf("unexpected error on happy path: %v", err)
	}
	if len(matches) != 1 || matches[0].Type != "TEST" {
		t.Fatalf("expected 1 TEST match, got %v", matches)
	}
}
