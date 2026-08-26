// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// ParallelProcessor manages parallel file processing
type ParallelProcessor struct {
	workerPool *WorkerPool
	observer   observability.Observer
}

// ProcessingStats tracks parallel processing statistics
type ProcessingStats struct {
	TotalFiles     int           `json:"total_files"`
	ProcessedFiles int           `json:"processed_files"`
	TotalMatches   int           `json:"total_matches"`
	TotalDuration  time.Duration `json:"total_duration_ms"`
	WorkerCount    int           `json:"worker_count"`
	AvgFileTime    time.Duration `json:"avg_file_time_ms"`

	// IncompleteFiles lists files whose validator coverage was cut short (a
	// validator errored or the scan was cancelled/timed out). It is populated
	// from each Result.ValidationError and is empty on a fully-clean run, so
	// callers that ignore it see no behavior change (v2 Phase 4). Callers use it
	// to set ScanResult.Incomplete — distinguishing "scanned clean" from "did
	// not finish scanning".
	IncompleteFiles []FileDiagnostic `json:"incomplete_files,omitempty"`

	// EmptyExtractionFiles lists files whose extraction SUCCEEDED but produced no
	// document-body text, for a file type that carries one. These are the files a
	// scan is most likely to have silently under-covered: nothing was extracted, so
	// no validator saw anything, so the file reports clean. Populated from
	// Result.ExtractionWarning; empty on a normal run. Counted as a coverage gap
	// alongside IncompleteFiles so --fail-on-incomplete can catch it.
	EmptyExtractionFiles []FileDiagnostic `json:"empty_extraction_files,omitempty"`

	// UnredactedFiles lists files that HAVE findings but for which no redacted
	// copy could be produced (populated from Result.RedactionError; empty unless
	// --enable-redaction is on). These files' findings are reported normally —
	// the scan saw them — but the sensitive values remain in cleartext at the
	// original path with no output artifact. Callers must surface this: a
	// redaction run whose whole purpose is to produce shareable copies has
	// silently not done so for these files.
	UnredactedFiles []FileDiagnostic `json:"unredacted_files,omitempty"`

	// FailedFiles lists files whose processing returned an error, so they were
	// never scanned at all. Populated from Result.Error.
	//
	// Before this existed, such a file was counted as NEITHER processed nor
	// skipped: the collector logged Result.Error and fell through without
	// incrementing anything and without recording a diagnostic, so the file
	// simply disappeared. Measured on a directory of six files where five were
	// unparseable containers: "Files: 1 processed, 0 skipped", no warning, and
	// exit 0 even under --fail-on-incomplete. A corrupt or truncated document —
	// exactly the kind that might be hiding something — was indistinguishable
	// from a directory that had been fully scanned and found clean.
	//
	// This is the same silent-and-lossy class as EmptyExtractionFiles, so it is
	// reported the same way and counted as a coverage gap for
	// --fail-on-incomplete.
	FailedFiles []FileDiagnostic `json:"failed_files,omitempty"`
}

// sortDiagnostics orders a diagnostic list by file path so operator-visible
// output is stable across runs. Ties on path keep their relative order, which
// only matters if one path appears twice.
func sortDiagnostics(d []FileDiagnostic) {
	sort.SliceStable(d, func(i, j int) bool { return d[i].FilePath < d[j].FilePath })
}

// FileDiagnostic records that a single file's validation did not complete
// cleanly. It carries no payload bytes — only the path and a short reason.
type FileDiagnostic struct {
	FilePath string `json:"file_path"`
	Reason   string `json:"reason"`

	// Cause is why the file was not examined, as the PRODUCER knew it.
	//
	// Reason stays: it is the specific detail an operator needs ("permission denied", "the moov box
	// is N bytes and only the first 33554432 were parsed"). Cause is the coarse classification that
	// every consumer previously recovered by pattern-matching that detail, which is how a size
	// refusal came to be reported as an unsupported type and how a partly-scanned file came to be
	// described as having no text at all.
	//
	// Zero value is CauseUnset, not CauseUnreadable, so a producer that has not been updated behaves
	// exactly as before: the consumer falls back to classifying the prose.
	Cause coverage.Cause `json:"cause,omitempty"`
}

// MaxFileWorkers caps the file-level worker pool regardless of how many CPUs the host has, to
// avoid resource exhaustion: each worker fans out one goroutine per document validator, so the
// live goroutine count is workers × validators (see execguard.DefaultLimiter, which bounds the
// second factor).
//
// Named rather than inline because docs/reference/quotas-and-limits.md publishes this number to
// operators sizing a scan, and TestDocumentedWorkerCapMatchesTheCode reads both. The previous
// inline literal drifted from that document undetected for the project's whole history — the
// table there described a 32-worker adaptive pool that was deleted in 8cf13a6 as dead code.
const MaxFileWorkers = 8

// FileWorkers returns the size of the file-level worker pool on this host: NumCPU, capped at
// MaxFileWorkers. It is derived from the CPU count and has no flag, config key or environment
// variable input.
func FileWorkers() int {
	return cappedWorkers(runtime.NumCPU())
}

// cappedWorkers is the pool-size arithmetic, separated from runtime.NumCPU() so it can be checked
// at CPU counts this host does not have — the interesting values are either side of the cap, and a
// developer machine only ever exercises one of them. See TestCappedWorkersMatchesTheFormerInlineCap.
func cappedWorkers(numCPU int) int {
	if numCPU < MaxFileWorkers {
		return numCPU
	}
	return MaxFileWorkers
}

// NewParallelProcessor creates a new parallel processor
func NewParallelProcessor(observer observability.Observer) *ParallelProcessor {
	return &ParallelProcessor{
		workerPool: NewWorkerPool(FileWorkers(), observer),
		observer:   observer,
	}
}

// ProgressCallback is called when a file is completed
type ProgressCallback func(completed, total int, currentFile string)

// ProcessFiles processes multiple files in parallel
func (pp *ParallelProcessor) ProcessFiles(filePaths []string, validators []detector.Validator, fileRouter *router.FileRouter, config *JobConfig, redactionManager *redactors.RedactionManager) ([]detector.Match, *ProcessingStats, error) {
	return pp.ProcessFilesWithProgress(filePaths, validators, fileRouter, config, redactionManager, nil)
}

// ProcessFilesWithProgress processes multiple files in parallel with progress callback
func (pp *ParallelProcessor) ProcessFilesWithProgress(filePaths []string, validators []detector.Validator, fileRouter *router.FileRouter, config *JobConfig, redactionManager *redactors.RedactionManager, progressCallback ProgressCallback) ([]detector.Match, *ProcessingStats, error) {
	start := time.Now()

	var finishTiming func(bool, map[string]interface{})
	if pp.observer != nil {
		finishTiming = pp.observer.StartTiming("parallel_processor", "process_files", "batch")
	}

	// Start worker pool
	pp.workerPool.Start()
	defer pp.workerPool.Stop()

	// Submit jobs in a separate goroutine to prevent deadlock
	jobCount := len(filePaths)
	go func() {
		defer close(pp.workerPool.jobs)
		for i, filePath := range filePaths {
			job := &Job{
				FilePath:         filePath,
				Validators:       validators,
				JobID:            fmt.Sprintf("job_%d", i),
				FileRouter:       fileRouter,
				Config:           config,
				RedactionManager: redactionManager,
			}
			pp.workerPool.Submit(job)
		}
	}()

	// Collect results
	var allMatches []detector.Match
	var mu sync.Mutex
	processedCount := 0
	totalDuration := time.Duration(0)
	var incompleteFiles []FileDiagnostic
	var unredactedFiles []FileDiagnostic
	var emptyExtractionFiles []FileDiagnostic
	var failedFiles []FileDiagnostic

	for i := 0; i < jobCount; i++ {
		result := <-pp.workerPool.Results()

		mu.Lock()
		// Record degraded validator coverage (timeout/cancel/validator error)
		// independently of the fatal-error path below, so a partially-scanned
		// file still contributes its matches AND is flagged as incomplete.
		if result.ValidationError != nil {
			incompleteFiles = append(incompleteFiles, FileDiagnostic{
				FilePath: result.FilePath,
				Reason:   result.ValidationError.Error(),
				// Every reachable origin is a timeout, a cancellation, a validator budget or a
				// recovered panic, so the file is genuinely PARTLY scanned. The consumer already
				// hardcoded this for its own output; stating it here is what lets pkg/scan and the
				// web UI see the same thing instead of each deriving it again.
				Cause: coverage.CauseCutShort,
			})
		}
		// Record a file whose findings could not be redacted. Handled the same
		// way as degraded validator coverage — as a diagnostic, NOT as a fatal
		// error — so the file still contributes its matches below. Redaction
		// runs after validation, so a redaction failure says nothing about the
		// correctness of what was found; treating it as fatal is what silently
		// erased findings for every file type with no registered redactor.
		// Record a file that extracted to nothing. Not an error — the file was read
		// and its (empty) content validated — but the single strongest signal that
		// a file was not really covered, so it is collected here rather than left
		// to a debug log nobody reads.
		if result.ExtractionWarning != "" {
			emptyExtractionFiles = append(emptyExtractionFiles, FileDiagnostic{
				FilePath: result.FilePath,
				Reason:   result.ExtractionWarning,
				// The bucket's NAME is not the cause. This channel carries no-text, unparseable and
				// cut-short warnings alike, which is why the cause travels from the extractor that
				// set the warning rather than being inferred from the bucket or from the prose.
				Cause: result.ExtractionCause,
			})
		}
		if result.RedactionError != nil {
			unredactedFiles = append(unredactedFiles, FileDiagnostic{
				FilePath: result.FilePath,
				Reason:   result.RedactionError.Error(),
			})
			if pp.observer != nil {
				pp.observer.LogOperation(observability.StandardObservabilityData{
					Component: "parallel_processor",
					Operation: "file_redaction",
					FilePath:  result.FilePath,
					Success:   false,
					Error:     result.RedactionError.Error(),
				})
			}
		}
		if result.Error != nil {
			// Record it, do not just log it. A file that errored was never
			// scanned, and without this entry it is counted as neither processed
			// nor skipped — it vanishes from the run with no warning and no
			// effect on the exit code. See ProcessingStats.FailedFiles.
			failedFiles = append(failedFiles, FileDiagnostic{
				FilePath: result.FilePath,
				Reason:   result.Error.Error(),
				Cause:    result.FailureCause,
			})
			if pp.observer != nil {
				pp.observer.LogOperation(observability.StandardObservabilityData{
					Component: "parallel_processor",
					Operation: "file_processing",
					FilePath:  result.FilePath,
					Success:   false,
					Error:     result.Error.Error(),
				})
			}
		} else {
			allMatches = append(allMatches, result.Matches...)
			processedCount++
		}
		totalDuration += result.Duration

		// Call progress callback if provided
		if progressCallback != nil {
			progressCallback(i+1, jobCount, result.FilePath)
		}
		mu.Unlock()
	}

	overallDuration := time.Since(start)

	// Sort every diagnostic list by path before returning.
	//
	// These lists are appended in worker-COMPLETION order, which is scheduling
	// order, so the same scan printed the same files in a different sequence on
	// every run. Measured before this sort: 8 empty-extraction files produced 5
	// distinct orderings in 5 runs, and 5 failed files produced 6 distinct
	// orderings in 6 runs. That reaches operator-visible stderr output, so
	// diffing two scans of the same tree showed spurious changes.
	//
	// The lists are per-run and small (empty on a clean scan), so sorting costs
	// nothing measurable, and unlike the hot match path there is no natural order
	// worth preserving here — completion order carries no meaning to a reader.
	sortDiagnostics(incompleteFiles)
	sortDiagnostics(emptyExtractionFiles)
	sortDiagnostics(unredactedFiles)
	sortDiagnostics(failedFiles)

	stats := &ProcessingStats{
		TotalFiles:      jobCount,
		ProcessedFiles:  processedCount,
		TotalMatches:    len(allMatches),
		TotalDuration:   overallDuration,
		WorkerCount:     pp.workerPool.workers,
		AvgFileTime:     totalDuration / time.Duration(max(processedCount, 1)),
		IncompleteFiles: incompleteFiles,
		UnredactedFiles: unredactedFiles,

		EmptyExtractionFiles: emptyExtractionFiles,
		FailedFiles:          failedFiles,
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"total_files":     jobCount,
			"processed_files": processedCount,
			"total_matches":   len(allMatches),
			"worker_count":    pp.workerPool.workers,
			"duration_ms":     overallDuration.Milliseconds(),
		})
	}

	return allMatches, stats, nil
}
