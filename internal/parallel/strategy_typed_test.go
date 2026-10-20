// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestRedaction_OutOfRangeStrategyIsRefusedNotDefaulted pins the worker's half of #772: the
// strategy arrives on JobConfig already parsed, and a value outside the definition is reported as a
// redaction failure for the file -- it is not mapped to some other strategy and written. Before the
// fix the field was a string, re-parsed here by a parser whose unknown branch returned
// format_preserving, so every typo upstream became masked output at this point.
func TestRedaction_OutOfRangeStrategyIsRefusedNotDefaulted(t *testing.T) {
	dir := t.TempDir()
	txt := writeTxt(t, dir, "notes.txt", "alpha content")

	v := &batchStubValidator{}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)
	out := filepath.Join(dir, "out")
	mgr := newRedactionManagerWithPlaintextOnly(t, out)

	cfg := &JobConfig{EnableRedaction: true, RedactionStrategy: redactors.RedactionStrategy(7)}
	matches, stats, err := pp.ProcessFilesWithProgress([]string{txt}, []detector.Validator{v}, fr, cfg, mgr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("the stub produced no match; the refusal below would be vacuous")
	}
	if len(stats.UnredactedFiles) != 1 {
		t.Fatalf("UnredactedFiles = %d, want 1 (the file must be reported as not redacted): %+v", len(stats.UnredactedFiles), stats.UnredactedFiles)
	}
	if !strings.Contains(stats.UnredactedFiles[0].Reason, "7") {
		t.Errorf("the diagnostic does not name the strategy value: %q", stats.UnredactedFiles[0].Reason)
	}
	var written []string
	_ = filepath.Walk(out, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr == nil && fi != nil && !fi.IsDir() {
			written = append(written, p)
		}
		return nil
	})
	if len(written) != 0 {
		t.Errorf("a redacted copy was written under a strategy that does not exist: %v", written)
	}

	// Control: the zero value is a defined strategy (simple) and redacts. A fresh processor, as
	// every test in this package uses one per ProcessFilesWithProgress call.
	cfg = &JobConfig{EnableRedaction: true}
	pp2 := NewParallelProcessor(observer)
	_, stats, err = pp2.ProcessFilesWithProgress([]string{txt}, []detector.Validator{v}, fr, cfg, newRedactionManagerWithPlaintextOnly(t, filepath.Join(dir, "out2")), nil)
	if err != nil || len(stats.UnredactedFiles) != 0 {
		t.Errorf("the zero-value strategy (simple) must redact: err=%v unredacted=%+v", err, stats.UnredactedFiles)
	}
}
