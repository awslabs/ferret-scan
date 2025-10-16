// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/redactors"
	"ferret-scan/internal/resilience"
	"ferret-scan/internal/router"
	"ferret-scan/internal/validators/metadata"
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
	dualPathWorker *DualPathWorker // Add dual-path worker support
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
}

// Result represents processing results
type Result struct {
	JobID    string
	FilePath string
	Matches  []detector.Match
	Error    error
	Duration time.Duration

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
		dualPathWorker: NewDualPathWorker(observer), // Initialize dual-path worker
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

// Submit adds a job to the queue
func (wp *WorkerPool) Submit(job *Job) {
	select {
	case wp.jobs <- job:
	case <-wp.ctx.Done():
		return
	default:
		// Channel is full, wait and retry
		select {
		case wp.jobs <- job:
		case <-wp.ctx.Done():
		}
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
		result := wp.processJob(job, id)

		select {
		case wp.results <- result:
		case <-wp.ctx.Done():
			return
		}
	}
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

		// Run validators with error isolation
		matches, validationErr := wp.runValidatorsWithResilience(ctx, job.Validators, processedContent)
		if validationErr != nil {
			// Don't fail entire job for validator errors, just log them
			if job.Config.Debug {
				lastError = validationErr
			}
		}

		allMatches = matches
		return nil
	}

	// Execute with timeout context
	jobCtx, cancel := context.WithTimeout(wp.ctx, 5*time.Minute)
	defer cancel()

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
		Duration:        duration,
		RedactionResult: redactionResult,
		RedactedPath:    redactedPath,
	}
}

// runValidatorsWithResilience runs validators with error isolation
func (wp *WorkerPool) runValidatorsWithResilience(ctx context.Context, validators []detector.Validator, processedContent *preprocessors.ProcessedContent) ([]detector.Match, error) {
	var allMatches []detector.Match
	var wg sync.WaitGroup
	matchesChan := make(chan []detector.Match, len(validators))
	errorChan := make(chan error, len(validators))

	for _, validator := range validators {
		// Check for ProcessedContent validator first (for dual path system)
		if processedContentValidator, ok := validator.(interface {
			ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
		}); ok {
			wg.Add(1)
			go func(v detector.Validator, pcv interface {
				ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
			}) {
				defer wg.Done()

				// Wrap validator execution with retry for transient errors
				validatorOperation := func(ctx context.Context) error {
					matches, err := pcv.ValidateProcessedContent(processedContent)
					if err == nil {
						matchesChan <- matches
					} else {
						matchesChan <- []detector.Match{}
						return err
					}
					return nil
				}

				// Use shorter retry config for validators to avoid blocking
				retryConfig := resilience.DefaultRetryConfig()
				retryConfig.MaxRetries = 2
				retryConfig.MaxElapsedTime = 30 * time.Second

				err := resilience.RetryWithBackoff(ctx, retryConfig, validatorOperation)
				if err != nil {
					errorChan <- err
				}
			}(validator, processedContentValidator)
		} else if contentValidator, ok := validator.(interface {
			ValidateContent(content string, originalPath string) ([]detector.Match, error)
		}); ok {
			// Skip ONLY pure metadata content for non-metadata validators
			if _, isMetadataValidator := validator.(*metadata.Validator); !isMetadataValidator && processedContent.ProcessorType == "metadata" {
				continue
			}

			wg.Add(1)
			go func(v detector.Validator, cv interface {
				ValidateContent(content string, originalPath string) ([]detector.Match, error)
			}) {
				defer wg.Done()

				// Wrap validator execution with retry for transient errors
				validatorOperation := func(ctx context.Context) error {
					filename := processedContent.OriginalPath
					if filename == "" {
						filename = processedContent.Filename
					}

					matches, err := cv.ValidateContent(processedContent.Text, filename)
					if err == nil {
						matchesChan <- matches
					} else {
						matchesChan <- []detector.Match{}
						return err
					}
					return nil
				}

				// Use shorter retry config for validators to avoid blocking
				retryConfig := resilience.DefaultRetryConfig()
				retryConfig.MaxRetries = 2
				retryConfig.MaxElapsedTime = 30 * time.Second

				err := resilience.RetryWithBackoff(ctx, retryConfig, validatorOperation)
				if err != nil {
					errorChan <- err
				}
			}(validator, contentValidator)
		}
	}

	// Wait for all validators to complete
	wg.Wait()
	close(matchesChan)
	close(errorChan)

	// Collect results
	for matches := range matchesChan {
		allMatches = append(allMatches, matches...)
	}

	// Collect errors (for logging/debugging)
	var validationErrors []error
	for err := range errorChan {
		validationErrors = append(validationErrors, err)
	}

	if len(validationErrors) > 0 {
		// Return first error for debugging, but don't fail the entire job
		return allMatches, validationErrors[0]
	}

	return allMatches, nil
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
