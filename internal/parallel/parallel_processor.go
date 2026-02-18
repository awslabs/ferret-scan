// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
	"ferret-scan/internal/router"
)

// ParallelProcessor manages parallel file processing
type ParallelProcessor struct {
	workerPool *WorkerPool
	observer   *observability.StandardObserver
}

// ProcessingStats tracks parallel processing statistics
type ProcessingStats struct {
	TotalFiles     int           `json:"total_files"`
	ProcessedFiles int           `json:"processed_files"`
	TotalMatches   int           `json:"total_matches"`
	TotalDuration  time.Duration `json:"total_duration_ms"`
	WorkerCount    int           `json:"worker_count"`
	AvgFileTime    time.Duration `json:"avg_file_time_ms"`
}

// NewParallelProcessor creates a new parallel processor
func NewParallelProcessor(observer *observability.StandardObserver) *ParallelProcessor {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8 // Cap at 8 workers to avoid resource exhaustion
	}

	return &ParallelProcessor{
		workerPool: NewWorkerPool(workers, observer),
		observer:   observer,
	}
}

// NewAdaptiveParallelProcessor creates a parallel processor with adaptive resource management
func NewAdaptiveParallelProcessor(config AdaptiveConfig, observer *observability.StandardObserver) *ParallelProcessor {
	// Use adaptive processor instead of fixed worker pool
	adaptiveProcessor := NewAdaptiveProcessor(config, observer)

	return &ParallelProcessor{
		workerPool: adaptiveProcessor.workerPool, // Use the adaptive processor's worker pool
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

	for i := 0; i < jobCount; i++ {
		result := <-pp.workerPool.Results()

		mu.Lock()
		if result.Error != nil {
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

	stats := &ProcessingStats{
		TotalFiles:     jobCount,
		ProcessedFiles: processedCount,
		TotalMatches:   len(allMatches),
		TotalDuration:  overallDuration,
		WorkerCount:    pp.workerPool.workers,
		AvgFileTime:    totalDuration / time.Duration(max(processedCount, 1)),
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
