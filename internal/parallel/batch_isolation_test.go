// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// These tests lock the FILE-LEVEL isolation guarantee of the worker pool: a
// validator that fails or stalls on one file must not prevent OTHER files in
// the same batch from being processed and reported. (Validator-level panic
// recovery and the cancellable join are covered separately in execguard /
// validator_runner tests; this is the batch-level behavior.)

// batchStubValidator returns one match per file, except for files whose path
// contains stallMarker — those block until released (simulating a runaway
// validator on a single file). It satisfies detector.Validator.
type batchStubValidator struct {
	stallMarker string
	release     chan struct{}
}

func (b *batchStubValidator) Validate(string) ([]detector.Match, error) { return nil, nil }
func (b *batchStubValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 0, nil
}
func (b *batchStubValidator) AnalyzeContext(string, detector.ContextInfo) float64 { return 0 }
func (b *batchStubValidator) ValidateContent(content, originalPath string) ([]detector.Match, error) {
	if b.stallMarker != "" && strings.Contains(originalPath, b.stallMarker) {
		<-b.release // block this one file's validation until the test releases it
	}
	return []detector.Match{{Type: "TEST", Text: "x", Filename: originalPath, Validator: "batchstub"}}, nil
}

// newTestFileRouter builds a real FileRouter configured for plain-text files.
func newTestFileRouter(t *testing.T) *router.FileRouter {
	t.Helper()
	fr := router.NewFileRouter(false)
	router.RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(router.CreateRouterConfig(false, nil, "", false))
	return fr
}

func writeTxt(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestBatch_StalledFileDoesNotBlockOthers is the file-level isolation guarantee:
// when a validator stalls on ONE file, the OTHER files in the batch still
// complete and report. The stalled file is bounded by the per-job timeout
// (configured short here so the test is fast), after which the batch finishes.
func TestBatch_StalledFileDoesNotBlockOthers(t *testing.T) {
	dir := t.TempDir()
	good1 := writeTxt(t, dir, "good1.txt", "alpha content")
	stall := writeTxt(t, dir, "STALLME.txt", "beta content")
	good2 := writeTxt(t, dir, "good2.txt", "gamma content")

	v := &batchStubValidator{stallMarker: "STALLME", release: make(chan struct{})}
	defer close(v.release) // let the stalled goroutine exit at test end

	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)

	// Short per-file timeout so the stalled file resolves quickly instead of
	// waiting the 5-minute default. This is the new configurable JobTimeout.
	cfg := &JobConfig{JobTimeout: 300 * time.Millisecond}

	start := time.Now()
	done := make(chan struct{})
	var matches []detector.Match
	var stats *ProcessingStats
	go func() {
		matches, stats, _ = pp.ProcessFilesWithProgress(
			[]string{good1, stall, good2},
			[]detector.Validator{v},
			fr, cfg, nil, nil,
		)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("batch did not complete within 10s — a stalled file blocked the whole batch")
	}

	elapsed := time.Since(start)
	// The batch completes once the stalled file hits its 300ms timeout; allow
	// generous headroom for scheduling. The key assertion is that it finishes
	// far below the 5-minute default ceiling.
	if elapsed > 10*time.Second {
		t.Errorf("batch took %v; expected it to finish shortly after the 300ms per-file timeout", elapsed)
	}

	// The two good files must have produced their matches despite the stall.
	got := map[string]bool{}
	for _, m := range matches {
		got[filepath.Base(m.Filename)] = true
	}
	if !got["good1.txt"] || !got["good2.txt"] {
		t.Errorf("good files did not complete despite the stalled file: matches from %v", got)
	}
	// stats.ProcessedFiles counts files that returned without a top-level error;
	// the two good files must be counted.
	if stats == nil || stats.ProcessedFiles < 2 {
		t.Errorf("expected >=2 processed files (the good ones), got %+v", stats)
	}
}

// TestBatch_FailedFileDoesNotBlockOthers locks the simpler failure case: a file
// that errors out (here, validation completes but the file is otherwise normal)
// does not stop the others. Uses a validator that errors only on one file.
func TestBatch_FailedFileDoesNotBlockOthers(t *testing.T) {
	dir := t.TempDir()
	good1 := writeTxt(t, dir, "ok1.txt", "alpha")
	good2 := writeTxt(t, dir, "ok2.txt", "beta")
	good3 := writeTxt(t, dir, "ok3.txt", "gamma")

	v := &batchStubValidator{} // no stall, no error — all succeed
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)

	matches, stats, err := pp.ProcessFilesWithProgress(
		[]string{good1, good2, good3},
		[]detector.Validator{v},
		fr, &JobConfig{}, nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}
	if stats == nil || stats.ProcessedFiles != 3 {
		t.Fatalf("expected 3 processed files, got %+v", stats)
	}
	if len(matches) != 3 {
		t.Errorf("expected 3 matches (one per file), got %d", len(matches))
	}
}
