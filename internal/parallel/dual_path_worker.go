// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/resilience"
	"ferret-scan/internal/validators"
)

// DualPathWorker handles validation using the dual-path bridge architecture
type DualPathWorker struct {
	dualPathIntegration *validators.DualPathIntegration
	observer            *observability.StandardObserver
	retryConfig         resilience.RetryConfig
}

// NewDualPathWorker creates a new dual-path worker
func NewDualPathWorker(observer *observability.StandardObserver) *DualPathWorker {
	retryConfig := resilience.DefaultRetryConfig()
	retryConfig.MaxRetries = 2
	retryConfig.MaxElapsedTime = 30 * time.Second

	return &DualPathWorker{
		dualPathIntegration: validators.NewDualPathIntegration(observer),
		observer:            observer,
		retryConfig:         retryConfig,
	}
}

// SetupValidators configures the dual-path worker with validators
func (dpw *DualPathWorker) SetupValidators(validatorMap map[string]detector.Validator) error {
	// Register document validators (all except metadata)
	dpw.dualPathIntegration.RegisterDocumentValidators(validatorMap)

	// Set metadata validator if it exists
	if metadataValidator, exists := validatorMap["METADATA"]; exists {
		if err := dpw.dualPathIntegration.SetMetadataValidator(metadataValidator); err != nil {
			return err
		}
	}

	return nil
}

// ProcessWithDualPath processes content using dual-path validation
func (dpw *DualPathWorker) ProcessWithDualPath(ctx context.Context, processedContent *preprocessors.ProcessedContent) ([]detector.Match, error) {
	var allMatches []detector.Match
	var processingError error

	// Use retry mechanism for resilience
	validatorOperation := func(ctx context.Context) error {
		matches, err := dpw.dualPathIntegration.ProcessContent(processedContent)
		if err != nil {
			processingError = err
			return err
		}
		allMatches = matches
		return nil
	}

	err := resilience.RetryWithBackoff(ctx, dpw.retryConfig, validatorOperation)
	if err != nil {
		return nil, processingError
	}

	return allMatches, nil
}

// GetMetrics returns dual-path metrics
func (dpw *DualPathWorker) GetMetrics() *validators.DualPathMetrics {
	return dpw.dualPathIntegration.GetMetrics()
}

// DualPathWorkerPool manages multiple dual-path workers for parallel processing
type DualPathWorkerPool struct {
	workers     []*DualPathWorker
	workerCount int
	observer    *observability.StandardObserver
}

// NewDualPathWorkerPool creates a new dual-path worker pool
func NewDualPathWorkerPool(workerCount int, observer *observability.StandardObserver) *DualPathWorkerPool {
	workers := make([]*DualPathWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		workers[i] = NewDualPathWorker(observer)
	}

	return &DualPathWorkerPool{
		workers:     workers,
		workerCount: workerCount,
		observer:    observer,
	}
}

// SetupAllWorkers configures all workers with the same validator set
func (dpwp *DualPathWorkerPool) SetupAllWorkers(validatorMap map[string]detector.Validator) error {
	for _, worker := range dpwp.workers {
		if err := worker.SetupValidators(validatorMap); err != nil {
			return err
		}
	}
	return nil
}

// ProcessBatchWithDualPath processes a batch of content using dual-path validation
func (dpwp *DualPathWorkerPool) ProcessBatchWithDualPath(ctx context.Context, contentBatch []*preprocessors.ProcessedContent) ([][]detector.Match, []error) {
	if len(contentBatch) == 0 {
		return nil, nil
	}

	results := make([][]detector.Match, len(contentBatch))
	errors := make([]error, len(contentBatch))

	// Create work channels
	workChan := make(chan workItem, len(contentBatch))
	resultChan := make(chan workResult, len(contentBatch))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < dpwp.workerCount && i < len(contentBatch); i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()
			worker := dpwp.workers[workerIndex]

			for item := range workChan {
				matches, err := worker.ProcessWithDualPath(ctx, item.content)
				resultChan <- workResult{
					index:   item.index,
					matches: matches,
					err:     err,
				}
			}
		}(i)
	}

	// Send work items
	go func() {
		for i, content := range contentBatch {
			workChan <- workItem{
				index:   i,
				content: content,
			}
		}
		close(workChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	for result := range resultChan {
		results[result.index] = result.matches
		errors[result.index] = result.err
	}

	return results, errors
}

// GetAggregatedMetrics returns aggregated metrics from all workers
func (dpwp *DualPathWorkerPool) GetAggregatedMetrics() *validators.DualPathMetrics {
	if len(dpwp.workers) == 0 {
		return &validators.DualPathMetrics{}
	}

	// Get metrics from first worker as base
	aggregated := *dpwp.workers[0].GetMetrics()

	// Aggregate metrics from remaining workers
	for i := 1; i < len(dpwp.workers); i++ {
		metrics := dpwp.workers[i].GetMetrics()

		aggregated.TotalValidations += metrics.TotalValidations
		aggregated.SuccessfulValidations += metrics.SuccessfulValidations
		aggregated.FailedValidations += metrics.FailedValidations
		aggregated.FallbackActivations += metrics.FallbackActivations
		aggregated.RoutingSuccesses += metrics.RoutingSuccesses
		aggregated.RoutingFailures += metrics.RoutingFailures
		aggregated.ContextBoosts += metrics.ContextBoosts
		aggregated.ContextPenalties += metrics.ContextPenalties

		// Average the timing metrics
		if metrics.AverageProcessingTime > 0 {
			aggregated.AverageProcessingTime = (aggregated.AverageProcessingTime + metrics.AverageProcessingTime) / 2
		}
		if metrics.DocumentPathTime > 0 {
			aggregated.DocumentPathTime = (aggregated.DocumentPathTime + metrics.DocumentPathTime) / 2
		}
		if metrics.MetadataPathTime > 0 {
			aggregated.MetadataPathTime = (aggregated.MetadataPathTime + metrics.MetadataPathTime) / 2
		}
		if metrics.RoutingTime > 0 {
			aggregated.RoutingTime = (aggregated.RoutingTime + metrics.RoutingTime) / 2
		}
		if metrics.ContextAnalysisTime > 0 {
			aggregated.ContextAnalysisTime = (aggregated.ContextAnalysisTime + metrics.ContextAnalysisTime) / 2
		}
	}

	return &aggregated
}

// workItem represents a work item for the worker pool
type workItem struct {
	index   int
	content *preprocessors.ProcessedContent
}

// workResult represents a result from a worker
type workResult struct {
	index   int
	matches []detector.Match
	err     error
}
