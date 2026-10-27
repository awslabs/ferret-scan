// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// These tests pin #770's Track C at RunValidators, through the real detection facade the worker
// pool and core.ScanContent hand it: a cut-short's partials survive, a late partial is collected
// within the grace period, and a guard outcome is never retried.

// countingDocValidator is a document validator that counts its calls and returns n matches with
// err. The facade fans out to it under its registered name.
type countingDocValidator struct {
	calls *atomic.Int32
	typ   string
	n     int
	err   error
}

func (countingDocValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (countingDocValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (countingDocValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (v countingDocValidator) ValidateContent(_, path string) ([]detector.Match, error) {
	v.calls.Add(1)
	out := make([]detector.Match, v.n)
	for i := range out {
		out[i] = detector.Match{Type: v.typ, Text: fmt.Sprintf("%s%d", v.typ, i), LineNumber: i + 1, Validator: v.typ, Filename: path}
	}
	return out, v.err
}

// facade builds the Detector the way core.ScanContent and the worker pool do.
func facade(t *testing.T, vs map[string]detector.Validator) detector.Validator {
	t.Helper()
	d := validators.NewDetector(observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard))
	if err := d.SetupValidators(vs); err != nil {
		t.Fatalf("SetupValidators: %v", err)
	}
	return d
}

func countOf(matches []detector.Match, typ string) int {
	n := 0
	for _, m := range matches {
		if m.Type == typ {
			n++
		}
	}
	return n
}

// TestGuardOutcomeIsNotRetried is item 11. A fired budget is a context.DeadlineExceeded, which
// resilience.ClassifyError takes for a transient timeout, so under the worker pool's retry policy
// the facade -- every check for the file -- re-ran twice more, 1 s and then 2 s later: three
// passes of the cut check AND of every sibling (the issue's three email_validator records for one
// SSN budget), and the partials of the first pass thrown away. Each must run exactly once, and the
// first pass's partials must be what comes back.
func TestGuardOutcomeIsNotRetried(t *testing.T) {
	var cutCalls, sibCalls atomic.Int32
	f := facade(t, map[string]detector.Validator{
		"CUT": countingDocValidator{calls: &cutCalls, typ: "CUT", n: 5, err: context.DeadlineExceeded},
		"SIB": countingDocValidator{calls: &sibCalls, typ: "SIB", n: 1},
	})

	start := time.Now()
	matches, err := RunValidators(context.Background(), []detector.Validator{f},
		newProcessed("content", "/virtual/path"), DefaultValidatorRetryStrategy())
	elapsed := time.Since(start)

	if cutCalls.Load() != 1 || sibCalls.Load() != 1 {
		t.Errorf("the cut check ran %d time(s) and its sibling %d (in %v); want 1 and 1: a budget is a "+
			"bound, not a transient fault, and re-running the file repeats the same cut",
			cutCalls.Load(), sibCalls.Load(), elapsed.Round(time.Millisecond))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the cut-short (context.DeadlineExceeded) returned as it is", err)
	}
	if countOf(matches, "CUT") != 5 || countOf(matches, "SIB") != 1 {
		t.Errorf("got %d CUT and %d SIB matches; want 5 and 1", countOf(matches, "CUT"), countOf(matches, "SIB"))
	}
}

// TestTransientErrorIsStillRetried keeps the retry policy's reason for existing: an ordinary
// transient error, which no guard returns, is retried as before.
func TestTransientErrorIsStillRetried(t *testing.T) {
	v := &stubContentValidator{name: "flaky", err: errors.New("network timeout talking to the service")}
	s := &retryValidatorStrategy{cfg: DefaultValidatorRetryStrategy().(*retryValidatorStrategy).cfg}
	s.cfg.InitialInterval = time.Millisecond
	s.cfg.Jitter = false
	_, err := RunValidators(context.Background(), []detector.Validator{v}, newProcessed("x", "/p"), s)
	if err == nil || v.callCount != 3 {
		t.Fatalf("a transient error ran %d time(s) (err %v); want 3: MaxRetries=2 still applies to faults", v.callCount, err)
	}
}

// TestCutShortPartialsSurviveRunValidators is item 8 one layer up: a validator that returns N
// matches with a cut-short has all N back from RunValidators, through the facade.
func TestCutShortPartialsSurviveRunValidators(t *testing.T) {
	var calls atomic.Int32
	f := facade(t, map[string]detector.Validator{
		"CUT": countingDocValidator{calls: &calls, typ: "CUT", n: 9, err: context.DeadlineExceeded},
	})
	matches, err := RunValidators(context.Background(), []detector.Validator{f}, newProcessed("content", "/p"), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if got := countOf(matches, "CUT"); got != 9 {
		t.Fatalf("RunValidators returned %d of the 9 matches the validator made before its budget fired", got)
	}
}

// lateProcessedValidator is dispatched by RunValidators directly: it signals started, waits for its
// context, takes delay, and returns n matches with ctx.Err(). With release set it never returns
// until the test closes release.
type lateProcessedValidator struct {
	started chan struct{}
	delay   time.Duration
	n       int
	release chan struct{}
}

func (lateProcessedValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (lateProcessedValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (lateProcessedValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (lateProcessedValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, nil // never reached: RunValidators prefers ValidateProcessedContentCtx
}
func (v lateProcessedValidator) ValidateProcessedContentCtx(ctx context.Context, _ *preprocessors.ProcessedContent) ([]detector.Match, error) {
	close(v.started)
	if v.release != nil {
		<-v.release
		return nil, nil
	}
	<-ctx.Done()
	time.Sleep(v.delay)
	out := make([]detector.Match, v.n)
	for i := range out {
		out[i] = detector.Match{Type: "LATE", Text: fmt.Sprintf("late%d", i), LineNumber: 1}
	}
	return out, ctx.Err()
}

// TestRunValidatorsCollectsALatePartial is item 10 at this join: a partial sent 10 ms after the
// caller's deadline is kept. The drain used to stop at its first empty read.
func TestRunValidatorsCollectsALatePartial(t *testing.T) {
	late := lateProcessedValidator{started: make(chan struct{}), delay: 10 * time.Millisecond, n: 3}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-late.started; cancel() }()

	matches, err := RunValidators(ctx, []detector.Validator{late}, newProcessed("x", "/p"), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if countOf(matches, "LATE") != 3 {
		t.Fatalf("kept %d of the 3 matches sent 10 ms after the cancellation; RunValidators must keep "+
			"collecting for CancelGrace (%v)", countOf(matches, "LATE"), CancelGrace)
	}
}

// TestRunValidatorsAbandonsAValidatorThatNeverReturns bounds the grace period: one that never
// returns is abandoned once it runs out, and the healthy validator's matches come back.
func TestRunValidatorsAbandonsAValidatorThatNeverReturns(t *testing.T) {
	stuck := lateProcessedValidator{started: make(chan struct{}), release: make(chan struct{})}
	defer close(stuck.release)
	ok := &stubContentValidator{name: "ok", matches: []detector.Match{{Type: "OK", Text: "x"}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := make(chan time.Time, 1)
	go func() { <-stuck.started; time.Sleep(20 * time.Millisecond); cancelled <- time.Now(); cancel() }()

	matches, err := RunValidators(ctx, []detector.Validator{stuck, ok}, newProcessed("x", "/p"), nil)
	returned := time.Now()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if waited := returned.Sub(<-cancelled); waited > CancelGrace+time.Second {
		t.Errorf("returned %v after the cancellation; want about CancelGrace (%v)", waited, CancelGrace)
	}
	if countOf(matches, "OK") != 1 {
		t.Errorf("the healthy validator's match was lost: %v", matches)
	}
}

// TestDocumentGraceEndsInsideTheRunnerGrace holds the two grace periods together. The document
// fan-out runs inside this join and both start waiting at the same cancellation, so if the inner
// one waited as long as this one, the partials it collected would arrive after this join stopped
// listening. validators cannot import this package, so the relation is checked here.
func TestDocumentGraceEndsInsideTheRunnerGrace(t *testing.T) {
	if validators.DocumentCancelGrace >= CancelGrace {
		t.Fatalf("validators.DocumentCancelGrace (%v) must be below parallel.CancelGrace (%v)",
			validators.DocumentCancelGrace, CancelGrace)
	}
}
