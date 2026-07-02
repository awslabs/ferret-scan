// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/execguard"
	"github.com/awslabs/ferret-scan/internal/observability"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
	"github.com/awslabs/ferret-scan/internal/redactors"
	"github.com/awslabs/ferret-scan/internal/resilience"
	"github.com/awslabs/ferret-scan/internal/router"
)

// WorkerPool manages parallel file processing with enhanced error handling
type WorkerPool struct {
	workers        int
	jobs           chan *Job
	results        chan *Result
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	observer       *observability.StandardObserver
	retryManager   *resilience.RetryManager
	circuitBreaker *resilience.CircuitBreakerManager
}

// Job represents a file processing task
type Job struct {
	FilePath         string
	Validators       []detector.Validator
	JobID            string
	FileRouter       *router.FileRouter
	Config           *JobConfig
	RedactionManager *redactors.RedactionManager // Add redaction manager to job
}

// JobConfig holds configuration for job processing
type JobConfig struct {
	// GENAI_DISABLED: EnableGenAI    bool
	// GENAI_DISABLED: GenAIServices  map[string]bool
	// GENAI_DISABLED: TextractRegion string
	Debug bool

	// Dual-path validation configuration
	EnableDualPath bool

	// Redaction configuration
	EnableRedaction    bool
	RedactionStrategy  string
	RedactionOutputDir string

	// JobTimeout bounds the per-file processing time (preprocessing +
	// validation). The zero value falls back to DefaultJobTimeout (5 minutes),
	// preserving historical behavior. A long-running embedder (e.g. the web
	// server) can tighten this so a single pathological file cannot delay batch
	// completion for the full default window.
	JobTimeout time.Duration

	// ValidatorBudgets optionally bounds per-validator execution (time and/or
	// match count), keyed by validator name. Nil/empty = disabled = historical
	// behavior. Attached to the per-file job context so the dispatch chokepoint
	// (execguard.ValidateContent) can enforce each validator's budget.
	ValidatorBudgets map[string]execguard.ValidatorBudget
}

// DefaultJobTimeout is the per-file processing ceiling used when
// JobConfig.JobTimeout is unset. A stalled validator on one file cannot block
// the whole batch beyond this (the scan returns partial results for that file).
const DefaultJobTimeout = 5 * time.Minute

// Result represents processing results
type Result struct {
	JobID    string
	FilePath string
	Matches  []detector.Match
	Error    error
	Duration time.Duration

	// ValidationError is the error returned by the validator run for this file,
	// if any (e.g. a validator timed out or the scan context was cancelled). It
	// is ALWAYS captured — unlike the historical behavior where the validator
	// error was only retained under --debug — so callers can report degraded
	// coverage on every run (v2 Phase 4). It is kept SEPARATE from Error: a
	// validator error does not make the file's matches invalid (the file was
	// read and partially scanned), so it must not trip the matches-discard path
	// that Error drives in parallel_processor. Nil when validation completed.
	ValidationError error

	// Redaction results
	RedactionResult *redactors.RedactionResult
	RedactedPath    string
}

// NewWorkerPool creates a new worker pool with resilience features
func NewWorkerPool(workers int, observer *observability.StandardObserver) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize resilience components
	retryManager := resilience.NewRetryManager()
	circuitBreakerManager := resilience.NewCircuitBreakerManager()

	// Configure retry policies for different operations
	retryManager.SetConfig("file_processing", resilience.DefaultRetryConfig())
	retryManager.SetConfig("aws_service", resilience.AWSRetryConfig())

	return &WorkerPool{
		workers:        workers,
		jobs:           make(chan *Job, workers*2),
		results:        make(chan *Result, workers*2),
		ctx:            ctx,
		cancel:         cancel,
		observer:       observer,
		retryManager:   retryManager,
		circuitBreaker: circuitBreakerManager,
	}
}

// Start initializes worker goroutines
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	wp.wg.Wait()
	close(wp.results)
	wp.cancel()
}

// Submit adds a job to the queue, blocking until either the job is accepted
// or the pool's context is cancelled. The previous implementation had a
// `default` branch that fell into an identical inner select, which had no
// behavioral effect — both forms block until the channel has room or the
// context cancels — but obscured the intent.
func (wp *WorkerPool) Submit(job *Job) {
	select {
	case wp.jobs <- job:
	case <-wp.ctx.Done():
	}
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan *Result {
	return wp.results
}

// worker processes jobs from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for job := range wp.jobs {
		result := wp.safeProcessJob(job, id)

		select {
		case wp.results <- result:
		case <-wp.ctx.Done():
			return
		}
	}
}

// safeProcessJob wraps processJob with panic recovery to prevent worker goroutine
// death from deadlocking the result collection loop.
func (wp *WorkerPool) safeProcessJob(job *Job, workerID int) (result *Result) {
	defer func() {
		if r := recover(); r != nil {
			result = &Result{
				FilePath: job.FilePath,
				Error:    fmt.Errorf("worker %d panic processing %s: %v", workerID, job.FilePath, r),
			}
		}
	}()
	return wp.processJob(job, workerID)
}

// processJob executes a single job with resilience features
func (wp *WorkerPool) processJob(job *Job, workerID int) *Result {
	start := time.Now()

	var finishTiming func(bool, map[string]interface{})
	if wp.observer != nil {
		finishTiming = wp.observer.StartTiming("worker_pool", "process_job", job.FilePath)
	}

	var allMatches []detector.Match
	var lastError error
	var validationErr error // captured for Result.ValidationError, always (not just --debug)
	var processedContent *preprocessors.ProcessedContent

	// Wrap file processing with resilience
	processWithResilience := func(ctx context.Context) error {
		if job.FileRouter == nil {
			return resilience.NewPermanentError("no file router available", nil)
		}

		processingCtx, err := job.FileRouter.CreateProcessingContext(
			job.FilePath,
			false, // GENAI_DISABLED: job.Config.EnableGenAI,
			nil,   // GENAI_DISABLED: job.Config.GenAIServices,
			"",    // GENAI_DISABLED: job.Config.TextractRegion,
			job.Config.Debug,
		)
		if err != nil {
			return resilience.ClassifyError(err)
		}

		// GENAI_DISABLED: Process file with retry logic for GenAI operations
		// if job.Config.EnableGenAI {
		//	// Use AWS retry configuration for GenAI operations
		//	err = wp.retryManager.Retry(ctx, "aws_service", func(ctx context.Context) error {
		//		var procErr error
		//		processedContent, procErr = job.FileRouter.ProcessFile(job.FilePath, processingCtx)
		//		return procErr
		//	})
		// } else {
		// Use standard retry for local file processing
		err = wp.retryManager.Retry(ctx, "file_processing", func(ctx context.Context) error {
			var procErr error
			processedContent, procErr = job.FileRouter.ProcessFile(job.FilePath, processingCtx)
			return procErr
		})
		// }

		if err != nil {
			return err
		}

		if processedContent == nil {
			return resilience.NewTransientError("no content processed", nil)
		}

		// Run validators with error isolation. Capture the validator error
		// unconditionally into validationErr (surfaced via Result.ValidationError
		// regardless of --debug) so callers can report degraded coverage. We do
		// NOT promote it to lastError: a validator error/timeout does not make
		// this file's already-gathered matches invalid, so it must not trip the
		// fatal-error path (which discards the file's matches downstream).
		matches, verr := RunValidators(ctx, job.Validators, processedContent, DefaultValidatorRetryStrategy())
		if verr != nil {
			validationErr = verr
		}

		allMatches = matches
		return nil
	}

	// Execute with timeout context. Per-file budget is configurable; the zero
	// value preserves the historical 5-minute ceiling.
	jobTimeout := DefaultJobTimeout
	if job.Config != nil && job.Config.JobTimeout > 0 {
		jobTimeout = job.Config.JobTimeout
	}
	jobCtx, cancel := context.WithTimeout(wp.ctx, jobTimeout)
	defer cancel()
	// Attach per-validator budgets (no-op when nil/empty — byte-identical path).
	if job.Config != nil {
		jobCtx = execguard.WithBudgets(jobCtx, job.Config.ValidatorBudgets)
	}

	err := processWithResilience(jobCtx)
	if err != nil {
		lastError = err

		// Handle circuit breaker errors gracefully
		if resilience.IsCircuitBreakerError(err) {
			if job.Config.Debug {
				lastError = err
			} else {
				// Don't expose circuit breaker details to end users
				lastError = resilience.NewTransientError("service temporarily unavailable", err)
			}
		}
	}

	// Perform redaction if enabled and we have matches
	var redactionResult *redactors.RedactionResult
	var redactedPath string

	if job.Config.EnableRedaction && job.RedactionManager != nil && len(allMatches) > 0 && processedContent != nil {
		// Perform redaction using the same extracted content
		redactionResult, redactedPath, err = wp.performInlineRedaction(job, allMatches, processedContent)
		if err != nil && lastError == nil {
			// Only set error if we didn't already have one
			lastError = err
		}
	}

	duration := time.Since(start)

	if finishTiming != nil {
		finishTiming(lastError == nil, map[string]interface{}{
			"worker_id":   workerID,
			"match_count": len(allMatches),
			"duration_ms": duration.Milliseconds(),
			"had_error":   lastError != nil,
			"redacted":    redactionResult != nil,
		})
	}

	return &Result{
		JobID:           job.JobID,
		FilePath:        job.FilePath,
		Matches:         allMatches,
		Error:           lastError,
		ValidationError: validationErr,
		Duration:        duration,
		RedactionResult: redactionResult,
		RedactedPath:    redactedPath,
	}
}

// performInlineRedaction performs redaction using the already-extracted content
func (wp *WorkerPool) performInlineRedaction(job *Job, matches []detector.Match, processedContent *preprocessors.ProcessedContent) (*redactors.RedactionResult, string, error) {
	// Parse redaction strategy
	strategy := redactors.ParseRedactionStrategy(job.Config.RedactionStrategy)

	// Create output path
	outputPath, err := job.RedactionManager.GetOutputManager().CreateMirroredPath(job.FilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create output path: %w", err)
	}

	// Get appropriate redactor
	redactor, err := job.RedactionManager.GetRedactorForFile(job.FilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get redactor: %w", err)
	}

	// Check if redactor supports content-based redaction
	if contentRedactor, ok := redactor.(interface {
		RedactContent(content *preprocessors.ProcessedContent, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error)
	}); ok {
		// Use content-based redaction (new interface)
		result, err := contentRedactor.RedactContent(processedContent, outputPath, matches, strategy)
		if err == nil && result != nil {
			// Add redaction result to the redaction manager's index
			job.RedactionManager.AddRedactionResult(job.FilePath, outputPath, result)
		}
		return result, outputPath, err
	} else {
		// Fallback to file-based redaction (existing interface)
		result, err := redactor.RedactDocument(job.FilePath, outputPath, matches, strategy)
		if err == nil && result != nil {
			// Add redaction result to the redaction manager's index
			job.RedactionManager.AddRedactionResult(job.FilePath, outputPath, result)
		}
		return result, outputPath, err
	}
}
