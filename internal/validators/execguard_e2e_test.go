// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	stdctx "context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/observability"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
)

// These tests exercise the REAL nested validation stack the way core.ScanContent
// builds it (EnhancedManagerWrapper -> EnhancedValidatorManager -> dual-path
// helper -> EnhancedValidatorBridge -> DocumentValidatorBridge -> validator),
// rather than handing a stub straight to parallel.RunValidators. That is the
// only path that proves the end-to-end Phase 1 claims: a stalled or panicking
// document validator does not take down the scan.

// stallingDocValidator blocks in ValidateContent until released — a runaway
// validator that ignores deadlines (the interface gives it no ctx to observe).
type stallingDocValidator struct {
	release chan struct{}
	started chan struct{}
}

func (s *stallingDocValidator) Validate(string) ([]detector.Match, error) { return nil, nil }
func (s *stallingDocValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 0, nil
}
func (s *stallingDocValidator) AnalyzeContext(string, detector.ContextInfo) float64 { return 0 }
func (s *stallingDocValidator) ValidateContent(string, string) ([]detector.Match, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	return nil, nil
}

// panicDocValidator panics inside ValidateContent.
type panicDocValidator struct{}

func (panicDocValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (panicDocValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (panicDocValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (panicDocValidator) ValidateContent(string, string) ([]detector.Match, error) {
	panic("boom in document validator")
}

// buildWrapper assembles the Detector facade the same way core.ScanContent does,
// for the supplied non-metadata validators.
func buildWrapper(t *testing.T, validators map[string]detector.Validator) *Detector {
	t.Helper()
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)

	d := NewDetector(observer)
	if err := d.SetupValidators(validators); err != nil {
		t.Fatalf("SetupValidators: %v", err)
	}
	return d
}

func processed(text string) *preprocessors.ProcessedContent {
	return &preprocessors.ProcessedContent{
		Text:          text,
		OriginalPath:  "<stdin>",
		Filename:      "<stdin>",
		ProcessorType: "plaintext",
		Success:       true,
	}
}

// TestE2E_StalledDocumentValidatorDoesNotHangScan is the end-to-end keystone:
// a stalled document validator must not block the whole nested stack. The
// ctx-aware ValidateProcessedContentCtx path must return shortly after the
// deadline rather than blocking on the inner leaf join.
func TestE2E_StalledDocumentValidatorDoesNotHangScan(t *testing.T) {
	stall := &stallingDocValidator{
		release: make(chan struct{}),
		started: make(chan struct{}, 1),
	}
	defer close(stall.release) // let the leaked goroutine exit at test end

	wrapper := buildWrapper(t, map[string]detector.Validator{"STALL": stall})

	ctx, cancel := stdctx.WithTimeout(stdctx.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := wrapper.ValidateProcessedContentCtx(ctx, processed("some sensitive-looking content"))
		done <- err
	}()

	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("scan took %v; expected return shortly after the 150ms deadline", elapsed)
		}
		if err == nil || !errors.Is(err, stdctx.DeadlineExceeded) {
			t.Errorf("expected DeadlineExceeded surfaced, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not return within 5s — stalled validator blocked the nested stack (regression)")
	}
}

// TestE2E_PanicInDocumentValidatorIsRecovered proves a document-validator panic
// is converted to a recovered error instead of crashing the process. If the
// panic were not recovered, the test binary would abort.
func TestE2E_PanicInDocumentValidatorIsRecovered(t *testing.T) {
	wrapper := buildWrapper(t, map[string]detector.Validator{"PANIC": panicDocValidator{}})

	// Should return normally (no panic propagates out of the stack). The
	// dual-path bridge swallows per-validator errors into an empty result, so
	// we assert only that we get here without crashing.
	matches, err := wrapper.ValidateProcessedContentCtx(stdctx.Background(), processed("content"))
	if err != nil {
		t.Fatalf("unexpected top-level error (panic should be isolated per-validator): %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches from a panicking validator, got %d", len(matches))
	}
}

// TestE2E_HappyPathUnaffected confirms a normal validator still produces its
// matches through the full stack with no context error.
func TestE2E_HappyPathUnaffected(t *testing.T) {
	ok := &okDocValidator{}
	wrapper := buildWrapper(t, map[string]detector.Validator{"OK": ok})

	matches, err := wrapper.ValidateProcessedContentCtx(stdctx.Background(), processed("content"))
	if err != nil {
		t.Fatalf("unexpected error on happy path: %v", err)
	}
	if len(matches) != 1 || matches[0].Type != "OKTYPE" {
		t.Fatalf("expected 1 OKTYPE match through the full stack, got %v", matches)
	}
}

// okDocValidator returns one match.
type okDocValidator struct{}

func (okDocValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (okDocValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (okDocValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (okDocValidator) ValidateContent(_, path string) ([]detector.Match, error) {
	return []detector.Match{{Type: "OKTYPE", Text: "x", Validator: "OK", Filename: path}}, nil
}
