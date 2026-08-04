// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

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
}

// NewParallelProcessor creates a new parallel processor
func NewParallelProcessor(observer observability.Observer) *ParallelProcessor {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8 // Cap at 8 workers to avoid resource exhaustion
	}

	return &ParallelProcessor{
		workerPool: NewWorkerPool(workers, observer),
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
