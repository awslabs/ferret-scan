// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/resilience"
)

// panicValidator panics inside ValidateContent — the exact failure mode that,
// without execguard, crashes the whole process because the panic occurs on a
// fan-out goroutine where the worker-level recover() cannot catch it.
type panicValidator struct{}

func (panicValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (panicValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (panicValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (panicValidator) ValidateContent(string, string) ([]detector.Match, error) {
	panic("boom")
}

// okValidator returns one match and no error.
type okValidator struct{}

func (okValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (okValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (okValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (okValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return []detector.Match{{Type: "TEST", Text: "x"}}, nil
}

// ctxAwareValidator implements ContextAwareValidator and records whether the
// context-aware path was taken and what content it received.
type ctxAwareValidator struct {
	calledCtx     bool
	gotContent    string
	returnMatches []detector.Match
}

func (c *ctxAwareValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (c *ctxAwareValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (c *ctxAwareValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (c *ctxAwareValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, errors.New("legacy path must not be used when ctx-aware exists")
}
func (c *ctxAwareValidator) ValidateContentCtx(_ context.Context, content, _ string) ([]detector.Match, error) {
	c.calledCtx = true
	c.gotContent = content
	return c.returnMatches, nil
}

func TestSafeRun_RecoversPanicAsNonRetryableError(t *testing.T) {
	matches, err := SafeRun(context.Background(), "panicValidator", func() ([]detector.Match, error) {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected an error from a panicking function, got nil")
	}
	if matches != nil {
		t.Errorf("expected nil matches after panic, got %v", matches)
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("expected error to mention panic, got %q", err.Error())
	}
	// Must be classified non-retryable so the retry wrapper does not re-run a
	// deterministically-panicking validator.
	if resilience.IsRetryable(err) {
		t.Errorf("panic-derived error must be non-retryable, but IsRetryable=true: %v", err)
	}
}

func TestSafeRun_NoPanicPassesThrough(t *testing.T) {
	want := []detector.Match{{Type: "TEST"}}
	got, err := SafeRun(context.Background(), "ok", func() ([]detector.Match, error) {
		return want, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != "TEST" {
		t.Errorf("matches not passed through unchanged: %v", got)
	}
}

func TestSafeRun_AlreadyCancelledSkipsExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before running

	ran := false
	matches, err := SafeRun(ctx, "ok", func() ([]detector.Match, error) {
		ran = true
		return []detector.Match{{Type: "TEST"}}, nil
	})
	if ran {
		t.Error("fn should NOT run when ctx is already cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if matches != nil {
		t.Errorf("expected nil matches when skipped, got %v", matches)
	}
}

func TestValidateContent_RecoversPanic(t *testing.T) {
	// The dispatch helper must also recover panics (it wraps SafeRun).
	matches, err := ValidateContent(context.Background(), "panicValidator", panicValidator{}, "content", "/path")
	if err == nil {
		t.Fatal("expected recovered panic error, got nil")
	}
	if matches != nil {
		t.Errorf("expected nil matches, got %v", matches)
	}
	if resilience.IsRetryable(err) {
		t.Errorf("panic error must be non-retryable: %v", err)
	}
}

func TestValidateContent_LegacyPathUnchanged(t *testing.T) {
	matches, err := ValidateContent(context.Background(), "ok", okValidator{}, "content", "/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match from legacy validator, got %d", len(matches))
	}
}

func TestValidateContent_PrefersContextAwarePath(t *testing.T) {
	v := &ctxAwareValidator{returnMatches: []detector.Match{{Type: "CTX"}}}
	matches, err := ValidateContent(context.Background(), "ctxAware", v, "the-content", "/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.calledCtx {
		t.Error("expected ValidateContentCtx to be called for a ContextAwareValidator")
	}
	if v.gotContent != "the-content" {
		t.Errorf("ctx-aware validator got wrong content: %q", v.gotContent)
	}
	if len(matches) != 1 || matches[0].Type != "CTX" {
		t.Errorf("expected ctx-aware matches, got %v", matches)
	}
}

// Guards the timing claim: SafeRun returns immediately on an already-expired
// deadline rather than invoking work.
func TestSafeRun_ExpiredDeadlineReturnsFast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has passed

	start := time.Now()
	_, err := SafeRun(ctx, "ok", func() ([]detector.Match, error) {
		time.Sleep(2 * time.Second) // would dominate if it ran
		return nil, nil
	})
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("SafeRun should skip work on an expired deadline, took %v", time.Since(start))
	}
	if err == nil {
		t.Error("expected a context deadline error")
	}
}
