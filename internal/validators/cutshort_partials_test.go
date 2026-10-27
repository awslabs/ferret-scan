// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	stdctx "context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// These tests pin #770's Track C at the bridge: what a validator found before a guard fired is
// kept, scored as a complete run's finding is, and collected even when it arrives just after the
// caller's context was done.

// partialDocValidator returns one PARTIAL match per data line, n of them, with err: a validator
// whose budget, deadline or cap fired after it had found n values (err a cut-short), or one that
// finished (err nil). Confidence 60 before the bridge's contextual adjustment.
type partialDocValidator struct {
	n   int
	err error
}

func (partialDocValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (partialDocValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (partialDocValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (v partialDocValidator) ValidateContent(content, path string) ([]detector.Match, error) {
	lines := strings.Split(content, "\n")
	out := make([]detector.Match, 0, v.n)
	for i := 1; i <= v.n && i < len(lines); i++ {
		out = append(out, detector.Match{
			Type: "PARTIAL", Text: fmt.Sprintf("v%03d", i), LineNumber: i + 1, Confidence: 60,
			Validator: "PARTIAL", Filename: path, Context: detector.ContextInfo{FullLine: lines[i]},
		})
	}
	return out, v.err
}

// partialCSV is a header and n data lines. Every line has two commas, so the context analyzer
// classifies it as CSV and the bridge adds its +20 tabular adjustment to every finding: a partial
// that skipped the adjustment would read 60 where its twin reads 80.
func partialCSV(n int) string {
	var b strings.Builder
	b.WriteString("id,value,note\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "%d,v%03d,row\n", i, i)
	}
	return b.String()
}

// TestCutShortPartialsAreKeptAndScoredLikeTheirTwins is items 8 and 9: for every member of the
// cut-short family that can carry matches (read from execguard.IsCoverageCutShort's source by
// cutShortSentinels, so a new member lands here on its own), a validator that returns N matches
// with that error has all N reported, each equal -- confidence, metadata, every field -- to the
// finding the same validator makes when it finishes.
//
// Before the fix keepMatches tested ErrMatchBudgetExceeded alone, so the deadline, cancellation
// and size-cap partials were dropped (0 of N), and the one kept member reached the report before
// the contextual adjustment: confidence 60 against its twin's 80, and no validation_path,
// context_* or original_confidence metadata.
func TestCutShortPartialsAreKeptAndScoredLikeTheirTwins(t *testing.T) {
	const n = 7
	content := partialCSV(n)
	run := func(err error) ([]detector.Match, error) {
		t.Helper()
		w := buildWrapper(t, map[string]detector.Validator{"PARTIAL": partialDocValidator{n: n, err: err}})
		return w.ValidateProcessedContentCtx(stdctx.Background(), processed(content))
	}

	twins, err := run(nil)
	if err != nil || len(twins) != n {
		t.Fatalf("complete run: %d matches, err %v; want %d, nil", len(twins), err, n)
	}
	if twins[0].Confidence == 60 {
		t.Fatalf("the fixture does not exercise the contextual adjustment (twin confidence %v): "+
			"the scoring half of this test would pass vacuously", twins[0].Confidence)
	}

	for _, name := range cutShortSentinels(t) {
		p, ok := cutShortProducers[name]
		if !ok {
			t.Fatalf("no producer for %s; cutShortProducers in cutshort_without_metadata_test.go must cover it", name)
		}
		if name == "ErrValidatorPanicked" {
			// Reasoned exemption: a panic carries no matches by construction. SafeRun recovers it
			// and resets the slice to nil, so there is no partial to keep or to score.
			continue
		}
		t.Run(name, func(t *testing.T) {
			cut := fmt.Errorf("%w: test fixture", p.sentinel)
			partials, err := run(cut)
			if !errors.Is(err, p.sentinel) {
				t.Fatalf("err = %v, want one wrapping %v: the cut-short must still flag the scan incomplete", err, p.sentinel)
			}
			if len(partials) != n {
				t.Fatalf("kept %d of the %d matches the validator returned with %v", len(partials), n, p.sentinel)
			}
			for i := range partials {
				if !reflect.DeepEqual(partials[i], twins[i]) {
					t.Errorf("partial %d differs from its complete-run twin:\n  partial confidence %v, metadata keys %v\n  twin    confidence %v, metadata keys %v",
						i, partials[i].Confidence, metadataKeys(partials[i].Metadata), twins[i].Confidence, metadataKeys(twins[i].Metadata))
				}
			}
		})
	}
}

// lateDocValidator blocks until its context is done, signals started first, then takes delay to
// "finish its stride" and returns n matches with ctx.Err() -- a polling validator noticing a
// caller's cancellation. With release set it never returns until the test closes it.
type lateDocValidator struct {
	started chan struct{}
	delay   time.Duration
	n       int
	release chan struct{}
}

func (lateDocValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (lateDocValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (lateDocValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (lateDocValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, nil
}
func (v lateDocValidator) ValidateContentCtx(ctx stdctx.Context, _, path string) ([]detector.Match, error) {
	close(v.started)
	if v.release != nil {
		<-v.release
		return nil, nil
	}
	<-ctx.Done()
	time.Sleep(v.delay)
	out := make([]detector.Match, v.n)
	for i := range out {
		out[i] = detector.Match{Type: "LATE", Text: fmt.Sprintf("late%d", i), LineNumber: 1, Validator: "LATE", Filename: path}
	}
	return out, ctx.Err()
}

// TestLatePartialAfterCancellationIsCollected is item 10 at the bridge: a validator that returns its
// partial 10 ms after the caller's context is cancelled has it kept. The drain used to stop at its
// first empty read, so the partial landed in the buffered channel after the bridge had returned.
func TestLatePartialAfterCancellationIsCollected(t *testing.T) {
	late := lateDocValidator{started: make(chan struct{}), delay: 10 * time.Millisecond, n: 4}
	w := buildWrapper(t, map[string]detector.Validator{"LATE": late})

	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	defer cancel()
	go func() { <-late.started; cancel() }()

	matches, err := w.ValidateProcessedContentCtx(ctx, processed("content"))
	if !errors.Is(err, stdctx.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := countType(matches, "LATE"); got != 4 {
		t.Fatalf("kept %d of the 4 matches sent 10 ms after the cancellation; the bridge must keep "+
			"collecting for DocumentCancelGrace (%v)", got, DocumentCancelGrace)
	}
}

// TestValidatorThatNeverReturnsIsAbandonedWithinTheGrace is the other half of item 10: the grace
// period is a bound. A validator that ignores its context is abandoned once it runs out, and the
// healthy sibling's finding still arrives.
func TestValidatorThatNeverReturnsIsAbandonedWithinTheGrace(t *testing.T) {
	stuck := lateDocValidator{started: make(chan struct{}), release: make(chan struct{})}
	defer close(stuck.release)
	w := buildWrapper(t, map[string]detector.Validator{"STUCK": stuck, "OK": &okDocValidator{}})

	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	defer cancel()
	var cancelledAt time.Time
	go func() { <-stuck.started; time.Sleep(20 * time.Millisecond); cancelledAt = time.Now(); cancel() }()

	matches, err := w.ValidateProcessedContentCtx(ctx, processed("content"))
	returned := time.Now()
	if !errors.Is(err, stdctx.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if waited := returned.Sub(cancelledAt); waited > DocumentCancelGrace+time.Second {
		t.Errorf("returned %v after the cancellation; the stuck validator must be abandoned at the "+
			"%v grace bound (plus scheduling slack), not waited for", waited, DocumentCancelGrace)
	}
	if countType(matches, "OKTYPE") != 1 {
		t.Errorf("the healthy validator's finding was lost with the stuck one: %v", matches)
	}
}
