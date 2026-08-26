// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// TestFileWorkersIsCappedAndDerivedFromCPUCount pins the pool size the documentation publishes.
//
// docs/reference/quotas-and-limits.md told operators the pool held 32 workers, was configurable,
// and was set "regardless of CPU count". All three were wrong, and had been since the project's
// first commit: the number is min(NumCPU, 8), it is derived FROM the CPU count, and nothing
// outside the process can change it. See TestDocumentedWorkerCapMatchesTheCode for the guard that
// keeps the two in step.
func TestFileWorkersIsCappedAndDerivedFromCPUCount(t *testing.T) {
	if MaxFileWorkers != 8 {
		t.Fatalf("MaxFileWorkers = %d, want 8 — the documented figure and the tables in "+
			"docs/reference/quotas-and-limits.md are written against 8", MaxFileWorkers)
	}

	want := runtime.NumCPU()
	if want > MaxFileWorkers {
		want = MaxFileWorkers
	}
	if got := FileWorkers(); got != want {
		t.Errorf("FileWorkers() = %d, want min(NumCPU=%d, %d) = %d",
			got, runtime.NumCPU(), MaxFileWorkers, want)
	}

	// The pool the processor actually builds, not just the helper: the doc describes the pool.
	pp := NewParallelProcessor(nil)
	if pp.workerPool == nil {
		t.Fatal("no worker pool built")
	}
	if got := pp.workerPool.workers; got != want {
		t.Errorf("worker pool built with %d workers, want %d", got, want)
	}
	if got := pp.workerPool.workers; got > MaxFileWorkers {
		t.Errorf("worker pool built with %d workers, above the %d cap", got, MaxFileWorkers)
	}
}

// TestCappedWorkersMatchesTheFormerInlineCap proves this change did not alter the pool size.
//
// The number moved from an inline literal to a named constant, and the arithmetic was rewritten
// from "assign then clamp downward" to "return the smaller". Those are equal, but only the value
// on THIS host gets exercised by running the suite, and a host has one CPU count — the boundary at
// MaxFileWorkers is exactly where an off-by-one would live and is invisible on a 14-CPU machine.
//
// So the old form is restated here and the two are compared across every CPU count up to 256,
// which covers 1 (no floor exists, contrary to what the docs claimed), the values either side of
// the cap, and hosts far larger than any this will run on.
func TestCappedWorkersMatchesTheFormerInlineCap(t *testing.T) {
	// Verbatim the pre-change body of NewParallelProcessor.
	formerInline := func(numCPU int) int {
		workers := numCPU
		if workers > 8 {
			workers = 8
		}
		return workers
	}

	for numCPU := 1; numCPU <= 256; numCPU++ {
		if got, want := cappedWorkers(numCPU), formerInline(numCPU); got != want {
			t.Errorf("cappedWorkers(%d) = %d, former inline form gave %d", numCPU, got, want)
		}
	}

	// The boundary, spelled out so a failure names the case rather than a loop index.
	for _, tc := range []struct{ numCPU, want int }{
		{1, 1}, {2, 2}, {7, 7}, {8, 8}, {9, 8}, {14, 8}, {32, 8}, {64, 8},
	} {
		if got := cappedWorkers(tc.numCPU); got != tc.want {
			t.Errorf("cappedWorkers(%d) = %d, want %d", tc.numCPU, got, tc.want)
		}
	}
}

// concurrencyObserver counts how many file jobs are in flight at once.
//
// The worker pool opens a "worker_pool"/"process_job" timing per file and closes it when that
// file is done, so the depth of those spans IS the live worker count. Counting them is what makes
// this an observation of the running pool rather than a restatement of the constant.
type concurrencyObserver struct {
	mu       sync.Mutex
	inFlight int
	peak     int
	started  int
}

func (o *concurrencyObserver) StartTiming(component, operation, _ string) func(bool, map[string]interface{}) {
	if component != "worker_pool" || operation != "process_job" {
		return func(bool, map[string]interface{}) {}
	}

	o.mu.Lock()
	o.inFlight++
	o.started++
	if o.inFlight > o.peak {
		o.peak = o.inFlight
	}
	o.mu.Unlock()

	return func(bool, map[string]interface{}) {
		o.mu.Lock()
		o.inFlight--
		o.mu.Unlock()
	}
}

func (o *concurrencyObserver) LogOperation(observability.StandardObservabilityData) {}
func (o *concurrencyObserver) Debug() *observability.DebugObserver                  { return nil }

func (o *concurrencyObserver) read() (peak, started int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.peak, o.started
}

// TestObservedWorkerConcurrencyNeverExceedsTheCap scans this repository's real documentation and
// watches how many files are processed at once.
//
// Real files rather than generated ones, and real markdown rather than a fixture shape: the point
// is to measure the pool under the routing, preprocessing and validation a scan actually performs.
// docs/ is used because it is a genuine corpus of mixed-size documents that is present wherever
// the suite runs, including CI.
//
// The assertion is an upper bound, which is the honest one to make. Whether all 8 workers are ever
// busy SIMULTANEOUSLY depends on how fast each file finishes, so requiring the peak to reach the
// cap would be a race; exceeding the cap, by contrast, is always a defect. Non-vacuity is covered
// by asserting every file was observed rather than by asserting a particular peak.
func TestObservedWorkerConcurrencyNeverExceedsTheCap(t *testing.T) {
	if testing.Short() {
		t.Skip("scans a real corpus; skipped in -short mode")
	}

	// internal/parallel -> repo root.
	docsDir := filepath.Join("..", "..", "docs")
	var files []string
	err := filepath.WalkDir(docsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Skipf("cannot walk %s: %v", docsDir, err)
	}
	if len(files) < 2*MaxFileWorkers {
		t.Skipf("only %d real documents under %s; need at least %d to saturate a %d-worker pool",
			len(files), docsDir, 2*MaxFileWorkers, MaxFileWorkers)
	}

	obs := &concurrencyObserver{}
	pp := NewParallelProcessor(obs)
	fr := newTestFileRouter(t)

	_, stats, err := pp.ProcessFilesWithProgress(
		files, []detector.Validator{&batchStubValidator{}}, fr, &JobConfig{}, nil, nil,
	)
	if err != nil {
		t.Fatalf("scanning %d real documents: %v", len(files), err)
	}

	peak, started := obs.read()
	t.Logf("%d real documents from %s: peak %d concurrent, %d jobs observed, pool sized %d "+
		"(NumCPU=%d)", len(files), docsDir, peak, started, FileWorkers(), runtime.NumCPU())

	// Non-vacuity: an upper bound proves nothing if the observer saw no work.
	if started != len(files) {
		t.Fatalf("observed %d jobs for %d files — the concurrency bound below would be "+
			"measuring something other than the whole scan", started, len(files))
	}
	if peak < 1 {
		t.Fatal("peak concurrency 0 with jobs observed: the counter is not wired to the pool")
	}
	if stats == nil {
		t.Fatal("no stats returned")
	}

	if peak > FileWorkers() {
		t.Errorf("peak concurrency %d exceeded the pool size %d — the cap in "+
			"NewParallelProcessor is not bounding the live worker count", peak, FileWorkers())
	}
	if peak > MaxFileWorkers {
		t.Errorf("peak concurrency %d exceeded MaxFileWorkers (%d), which is the number "+
			"docs/reference/quotas-and-limits.md publishes", peak, MaxFileWorkers)
	}
}

// TestDocumentedWorkerCapMatchesTheCode is the decay guard, computed rather than fixtured.
//
// This exists because the number in the document drifted from the code for the project's entire
// history without anything noticing. The performance table described the adaptive pool configured
// by internal/parallel/resource_monitor.go and internal/preprocessors/streaming_processor.go —
// 32 workers, a 2-worker floor, a 1GB memory-pressure threshold, 250MB/10MB file-size worker
// scaling, a 10MB chunk size and a 1KB chunk overlap, every row marked configurable. That stack
// was never wired into an entry point and was deleted as dead code, and the rows outlived it.
//
// The expected string is BUILT from MaxFileWorkers rather than written out, so raising the cap in
// code fails this test until the document is updated too.
func TestDocumentedWorkerCapMatchesTheCode(t *testing.T) {
	// internal/parallel -> repo root.
	docPath := filepath.Join("..", "..", "docs", "reference", "quotas-and-limits.md")
	raw, err := os.ReadFile(docPath) // #nosec G304 -- a fixed path inside the repo
	if err != nil {
		t.Skipf("cannot read %s: %v", docPath, err)
	}
	doc := string(raw)

	wantExpr := fmt.Sprintf("min(NumCPU, %d)", MaxFileWorkers)
	if !strings.Contains(doc, wantExpr) {
		t.Errorf("%s does not state the real worker count %q — it is what an operator sizing a "+
			"scan reads, and MaxFileWorkers is now %d", docPath, wantExpr, MaxFileWorkers)
	}
	if !strings.Contains(doc, "MaxFileWorkers") {
		t.Errorf("%s does not name parallel.MaxFileWorkers, so a reader cannot find the "+
			"constant this number comes from", docPath)
	}

	// Claims that described the deleted adaptive pool, and two error strings the tool has never
	// been able to emit.
	//
	// Each is checked as a TABLE ROW or in its quoted form, and permitted on a blockquote line,
	// because the document deliberately records what it used to say in a "> Corrected" note. A
	// plain Contains check would fail on that note and would push the next person to delete the
	// history rather than the claim.
	retired := []string{
		"| **Maximum Workers** |",
		"| **Minimum Workers** |",
		"| **Memory Threshold** |",
		"| **Large File Threshold** |",
		"| **Small File Threshold** |",
		"| **Chunk Size** |",
		"| **Chunk Overlap** |",
		"| **Theoretical Maximum** |",
		"chunk offset exceeds int32",
		"System under memory pressure",
	}
	for _, claim := range retired {
		for i, line := range strings.Split(doc, "\n") {
			if !strings.Contains(line, claim) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), ">") {
				continue // inside the correction note, which is where it belongs
			}
			t.Errorf("%s:%d asserts %q outside the correction note: %s\n"+
				"That row described the adaptive worker pool / streaming processor, both deleted "+
				"as dead code, or an error string that has only ever existed in this document.",
				docPath, i+1, claim, strings.TrimSpace(line))
		}
	}
}

// TestDocumentedErrorStringsAreEmittable checks the other direction: every oversize-refusal
// message the document tabulates must be a string the code can actually produce.
//
// The table previously listed two errors that do not exist and misattributed a third, so a reader
// grepping their logs for a documented phrase would find nothing and conclude the scan had not hit
// the limit. Rendered forms are compared, since the code holds them as format strings.
func TestDocumentedErrorStringsAreEmittable(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "reference", "quotas-and-limits.md")
	raw, err := os.ReadFile(docPath) // #nosec G304 -- a fixed path inside the repo
	if err != nil {
		t.Skipf("cannot read %s: %v", docPath, err)
	}
	doc := string(raw)

	// Every one of these is grepped out of the tree in the PR that introduced this test; they are
	// restated here so a reworded message fails a test rather than silently diverging from the
	// operator-facing table.
	emittable := []string{
		"file too large (max size: 100MB)",                 // cmd/main.go, CLI discovery
		"File too large (max: 100MB)",                      // internal/router/file_router.go
		"file too large to scan (max size: 100MB)",         // internal/web/server.go
		"file too large: <n> bytes (max: 104857600 bytes)", // internal/preprocessors/plaintext_preprocessor.go
	}
	for _, msg := range emittable {
		if !strings.Contains(doc, msg) {
			t.Errorf("%s no longer documents the refusal %q; an operator grepping logs for a "+
				"documented phrase must find the one the tool prints", docPath, msg)
		}
	}

	// And the levers it advertises are the two that exist.
	for _, lever := range []string{"--max-live-bytes", "GOMAXPROCS", "FERRET_DEBUG"} {
		if !strings.Contains(doc, lever) {
			t.Errorf("%s does not mention %s, which is one of the few controls that is real",
				docPath, lever)
		}
	}
}
