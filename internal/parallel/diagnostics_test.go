// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/observability"
)

// TestDiagnostics_IncompleteFileSurfacedButMatchesKept verifies the v2 Phase 4
// contract: when a validator does not complete for a file (here, a stall that
// trips the per-file timeout), that file is reported in
// ProcessingStats.IncompleteFiles, yet the partial/clean matches from ALL files
// — including the stalled one's siblings — are still returned. Degraded coverage
// is surfaced, not silently dropped, and it does not suppress other findings.
func TestDiagnostics_IncompleteFileSurfacedButMatchesKept(t *testing.T) {
	dir := t.TempDir()
	good := writeTxt(t, dir, "good.txt", "alpha content")
	stall := writeTxt(t, dir, "STALLME.txt", "beta content")

	v := &batchStubValidator{stallMarker: "STALLME", release: make(chan struct{})}
	defer close(v.release)

	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)
	cfg := &JobConfig{JobTimeout: 300 * time.Millisecond}

	done := make(chan struct{})
	var matches []detector.Match
	var stats *ProcessingStats
	go func() {
		matches, stats, _ = pp.ProcessFilesWithProgress(
			[]string{good, stall},
			[]detector.Validator{v},
			fr, cfg, nil, nil,
		)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not complete within 10s")
	}

	// The stalled file must be reported as incomplete...
	if len(stats.IncompleteFiles) != 1 {
		t.Fatalf("expected 1 incomplete file, got %d: %+v", len(stats.IncompleteFiles), stats.IncompleteFiles)
	}
	if filepath.Base(stats.IncompleteFiles[0].FilePath) != "STALLME.txt" {
		t.Errorf("wrong incomplete file: %q", stats.IncompleteFiles[0].FilePath)
	}
	if stats.IncompleteFiles[0].Reason == "" {
		t.Error("incomplete file diagnostic has no reason")
	}

	// ...but the good file's match must still be present (not discarded).
	foundGood := false
	for _, m := range matches {
		if filepath.Base(m.Filename) == "good.txt" {
			foundGood = true
		}
	}
	if !foundGood {
		t.Errorf("good file's match was dropped; matches=%v", matches)
	}
}

// TestDiagnostics_CleanScanHasNoIncompleteFiles confirms the happy-path default:
// when every file's validation completes, IncompleteFiles is empty (so
// ScanResult.Incomplete stays false and clean scans see no behavior change).
func TestDiagnostics_CleanScanHasNoIncompleteFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := writeTxt(t, dir, "a.txt", "alpha")
	f2 := writeTxt(t, dir, "b.txt", "beta")

	v := &batchStubValidator{} // no stall, no error
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)

	_, stats, err := pp.ProcessFilesWithProgress(
		[]string{f1, f2}, []detector.Validator{v}, fr, &JobConfig{}, nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stats.IncompleteFiles) != 0 {
		t.Errorf("clean scan should have no incomplete files, got %+v", stats.IncompleteFiles)
	}
}
