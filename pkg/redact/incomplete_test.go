// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// These tests pin #770 for Engine.Redact: a scan that did not examine all of the text returns its
// partial Result AND an error wrapping ErrIncomplete. Every case below returned the input, or the
// input with only some values masked, at err == nil before the fix.

// marker is a distinctive input substring; no reason, error or audit record may contain it.
const marker = "Zq7markerXv"

func newEngine(t *testing.T, checks ...string) *Engine {
	t.Helper()
	e, err := NewEngine(EngineOptions{Checks: checks})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// assertIncomplete checks the contract for one cut-short Redact call.
func assertIncomplete(t *testing.T, res *Result, err error, cause error) {
	t.Helper()
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want one wrapping ErrIncomplete", err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Errorf("err = %v does not wrap the cause %v; a caller's errors.Is on it must keep working", err, cause)
	}
	if res == nil {
		t.Fatal("Result is nil; the partial result is returned alongside the error")
	}
	if !res.Incomplete || res.IncompleteReason == "" {
		t.Errorf("Result.Incomplete=%v IncompleteReason=%q; want true and a cause", res.Incomplete, res.IncompleteReason)
	}
	rec := res.AuditRecord()
	if !rec.Incomplete || rec.IncompleteReason != res.IncompleteReason {
		t.Errorf("AuditRecord().Incomplete=%v reason %q; want the Result's", rec.Incomplete, rec.IncompleteReason)
	}
	audit, _ := json.Marshal(rec)
	for what, s := range map[string]string{"error": err.Error(), "reason": res.IncompleteReason, "audit record": string(audit)} {
		if strings.Contains(s, marker) {
			t.Errorf("the %s carries input bytes: %q", what, s)
		}
	}
}

// TestRedactReportsADoneContext covers a ctx that is done before the scan starts: cancelled, or
// with a deadline already past.
func TestRedactReportsADoneContext(t *testing.T) {
	e := newEngine(t, "EMAIL", "SSN")
	text := "note " + marker + " reach j7.example@example.org about 517-17-1007\n"

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	past, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()

	for name, c := range map[string]struct {
		ctx   context.Context
		cause error
	}{
		"pre-cancelled": {cancelled, context.Canceled},
		"past deadline": {past, context.DeadlineExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := e.Redact(c.ctx, Request{Text: text, Label: "req-1"})
			assertIncomplete(t, res, err, c.cause)
			if len(res.Findings()) != 0 {
				t.Errorf("%d findings from a scan that never started", len(res.Findings()))
			}
		})
	}
}

// TestRedactReportsAnOversizeDecline is the >5 MiB CLOUD_RESOURCES request: the validator declines
// it with ErrContentTooLarge, so the ARNs were never looked for. It returned the text unchanged with
// zero findings at err == nil.
func TestRedactReportsAnOversizeDecline(t *testing.T) {
	e := newEngine(t, "CLOUD_RESOURCES")
	var b strings.Builder
	b.WriteString(marker + " put arn:aws:s3:::synthetic-bucket-q7x2/logs ok\n")
	for b.Len() <= 5<<20 {
		b.WriteString("heartbeat ok, queue depth nominal, all well\n")
	}
	res, err := e.Redact(context.Background(), Request{Text: b.String()})
	assertIncomplete(t, res, err, execguard.ErrContentTooLarge)
}

// stubValidator answers RunValidators with fixed matches and an error.
type stubValidator struct {
	matches []detector.Match
	err     error
}

func (stubValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (stubValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (stubValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (stubValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, nil
}
func (s stubValidator) ValidateProcessedContentCtx(_ context.Context, _ *preprocessors.ProcessedContent) ([]detector.Match, error) {
	out := make([]detector.Match, len(s.matches))
	copy(out, s.matches)
	return out, s.err
}

// TestRedactReportsAHardValidatorError: a validator error that is not a cut-short makes
// RunValidators discard that validator's matches, so its values were never reported and are still
// in Redacted. That is incomplete coverage as much as a timeout is.
func TestRedactReportsAHardValidatorError(t *testing.T) {
	e := newEngine(t, "EMAIL")
	e.validatorsList = []detector.Validator{stubValidator{err: errors.New("stub: validator failed")}}
	res, err := e.Redact(context.Background(), Request{Text: "hello " + marker + "\n"})
	assertIncomplete(t, res, err, nil)
}

// TestRedactAppliesThePartialFindings: what was found before the cut is masked, and comes back with
// the error. The partial text is the caller's to log or drop, never to release.
func TestRedactAppliesThePartialFindings(t *testing.T) {
	e := newEngine(t, "EMAIL")
	text := "first a@example.org then " + marker + " b@example.org\n"
	e.validatorsList = []detector.Validator{stubValidator{
		matches: []detector.Match{{Type: "EMAIL", Text: "a@example.org", LineNumber: 1, Confidence: 95, Validator: "email"}},
		err:     fmt.Errorf("stub: %w", context.DeadlineExceeded),
	}}
	res, err := e.Redact(context.Background(), Request{Text: text})
	assertIncomplete(t, res, err, context.DeadlineExceeded)
	if strings.Contains(res.Redacted, "a@example.org") {
		t.Errorf("the value found before the cut is still in Redacted: %q", res.Redacted)
	}
	if !strings.Contains(res.Redacted, "b@example.org") {
		t.Errorf("fixture: the value after the cut should still be in clear, which is why err is set: %q", res.Redacted)
	}
	if len(res.Findings()) != 1 {
		t.Errorf("Findings() = %d, want the 1 found before the cut", len(res.Findings()))
	}
}

// TestCompleteRedactIsUnaffected: a run that examined everything returns no error and no
// incompleteness. (Its output bytes are pinned by internal/goldencorpus TestGoldenRedact.)
func TestCompleteRedactIsUnaffected(t *testing.T) {
	e := newEngine(t, "EMAIL")
	res, err := e.Redact(context.Background(), Request{Text: "reach j7.example@example.org\n"})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Incomplete || res.IncompleteReason != "" || res.AuditRecord().Incomplete {
		t.Errorf("a complete run reports Incomplete=%v reason=%q audit=%v", res.Incomplete, res.IncompleteReason, res.AuditRecord().Incomplete)
	}
	if strings.Contains(res.Redacted, "j7.example@example.org") {
		t.Errorf("not redacted: %q", res.Redacted)
	}
}
