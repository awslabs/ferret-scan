// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"fmt"
	"os"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/router"
)

// AdaptiveProcessor manages adaptive file processing with dynamic resource management
type AdaptiveProcessor struct {
	workerPool      *WorkerPool
	resourceMonitor *ResourceMonitor
	observer        *observability.StandardObserver
	mu              sync.RWMutex
	activeWorkers   int
	maxBatchSize    int
	stats           *AdaptiveStats
}

// AdaptiveStats tracks adaptive processing statistics
type AdaptiveStats struct {
	TotalFiles        int           `json:"total_files"`
	ProcessedFiles    int           `json:"processed_files"`
	SkippedFiles      int           `json:"skipped_files"`
	TotalMatches      int           `json:"total_matches"`
	TotalDuration     time.Duration `json:"total_duration_ms"`
	InitialWorkers    int           `json:"initial_workers"`
	FinalWorkers      int           `json:"final_workers"`
	MaxWorkers        int           `json:"max_workers"`
	WorkerAdjustments int           `json:"worker_adjustments"`
	MemoryPeakMB      uint64        `json:"memory_peak_mb"`
	BatchesProcessed  int           `json:"batches_processed"`
	AvgBatchTime      time.Duration `json:"avg_batch_time_ms"`
	ResourcePressure  bool          `json:"had_resource_pressure"`
	Recommendation    string        `json:"recommendation"`
}

// AdaptiveConfig holds configuration for adaptive processing
type AdaptiveConfig struct {
	ResourceLimits        ResourceLimits `json:"resource_limits"`
	EnableAdaptiveScaling bool           `json:"enable_adaptive_scaling"`
	MaxBatchSize          int            `json:"max_batch_size"`
	MinBatchSize          int            `json:"min_batch_size"`
	ScalingCheckInterval  time.Duration  `json:"scaling_check_interval"`
	PerformanceMonitoring bool           `json:"performance_monitoring"`
}

// DefaultAdaptiveConfig returns sensible defaults for adaptive processing
func DefaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		ResourceLimits:        DefaultResourceLimits(),
		EnableAdaptiveScaling: true,
		MaxBatchSize:          100, // Process max 100 files per batch
		MinBatchSize:          10,  // Process min 10 files per batch
		ScalingCheckInterval:  2 * time.Second,
		PerformanceMonitoring: true,
	}
}

// NewAdaptiveProcessor creates a new adaptive processor
func NewAdaptiveProcessor(config AdaptiveConfig, observer *observability.StandardObserver) *AdaptiveProcessor {
	// Calculate initial worker count based on system resources
	resourceMonitor := NewResourceMonitor(config.ResourceLimits)

	// Start with optimal worker count for unknown workload
	initialWorkers := resourceMonitor.OptimalWorkerCount(50, 1024*1024) // Assume 50 files of 1MB each

	ap := &AdaptiveProcessor{
		workerPool:      NewWorkerPool(initialWorkers, observer),
		resourceMonitor: resourceMonitor,
		observer:        observer,
		activeWorkers:   initialWorkers,
		maxBatchSize:    config.MaxBatchSize,
		stats: &AdaptiveStats{
			InitialWorkers: initialWorkers,
			FinalWorkers:   initialWorkers,
		},
	}

	// Start resource monitoring if adaptive scaling is enabled
	if config.EnableAdaptiveScaling {
		resourceMonitor.Start()

		// Register callback for resource changes
		resourceMonitor.OnMetricsUpdate(ap.handleResourceMetrics)

		// Start adaptive scaling monitor
		go ap.adaptiveScalingLoop(config.ScalingCheckInterval)
	}

	return ap
}

// ProcessFiles processes files adaptively based on system resources
func (ap *AdaptiveProcessor) ProcessFiles(filePaths []string, validators []detector.Validator, fileRouter *router.FileRouter, jobConfig *JobConfig) ([]detector.Match, *AdaptiveStats, error) {
	start := time.Now()

	var finishTiming func(bool, map[string]interface{})
	if ap.observer != nil {
		finishTiming = ap.observer.StartTiming("adaptive_processor", "process_files", "adaptive_batch")
	}

	ap.stats.TotalFiles = len(filePaths)

	// Calculate file statistics for resource optimization
	avgFileSize, totalSize := ap.calculateFileStats(filePaths)

	// Optimize worker count based on workload
	optimalWorkers := ap.resourceMonitor.OptimalWorkerCount(len(filePaths), avgFileSize)
	ap.adjustWorkerCount(optimalWorkers)

	// Process files in adaptive batches
	allMatches, err := ap.processBatches(filePaths, validators, fileRouter, jobConfig, avgFileSize)
	if err != nil {
		return nil, ap.stats, err
	}

	// Finalize statistics
	ap.stats.TotalDuration = time.Since(start)
	ap.stats.TotalMatches = len(allMatches)
	ap.stats.FinalWorkers = ap.activeWorkers

	// Get resource recommendations
	resourceStats := ap.resourceMonitor.GetResourceStats(ap.activeWorkers, len(filePaths), avgFileSize)
	ap.stats.Recommendation = resourceStats.Recommendation
	ap.stats.ResourcePressure = resourceStats.MemoryPressure

	// Track peak memory usage
	metrics := ap.resourceMonitor.GetMetrics()
	ap.stats.MemoryPeakMB = maxUint64(ap.stats.MemoryPeakMB, metrics.MemoryUsed)

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"total_files":         ap.stats.TotalFiles,
			"processed_files":     ap.stats.ProcessedFiles,
			"total_matches":       ap.stats.TotalMatches,
			"initial_workers":     ap.stats.InitialWorkers,
			"final_workers":       ap.stats.FinalWorkers,
			"worker_adjustments":  ap.stats.WorkerAdjustments,
			"duration_ms":         ap.stats.TotalDuration.Milliseconds(),
			"avg_file_size_mb":    avgFileSize / 1024 / 1024,
			"total_size_mb":       totalSize / 1024 / 1024,
			"had_memory_pressure": ap.stats.ResourcePressure,
		})
	}

	return allMatches, ap.stats, nil
}

// processBatches processes files in adaptive batches
func (ap *AdaptiveProcessor) processBatches(filePaths []string, validators []detector.Validator, fileRouter *router.FileRouter, jobConfig *JobConfig, avgFileSize int64) ([]detector.Match, error) {
	var allMatches []detector.Match
	batchSize := ap.calculateOptimalBatchSize(len(filePaths), avgFileSize)

	ap.workerPool.Start()
	defer ap.workerPool.Stop()

	for i := 0; i < len(filePaths); i += batchSize {
		end := minInt(i+batchSize, len(filePaths))
		batch := filePaths[i:end]

		batchStart := time.Now()
		matches, err := ap.processBatch(batch, validators, fileRouter, jobConfig)
		batchDuration := time.Since(batchStart)

		if err != nil {
			// Log error but continue processing other batches
			if ap.observer != nil {
				ap.observer.LogOperation(observability.StandardObservabilityData{
					Component: "adaptive_processor",
					Operation: "batch_processing_error",
					Success:   false,
					Error:     err.Error(),
					Metadata: map[string]interface{}{
						"batch_size":  len(batch),
						"batch_start": i,
						"batch_end":   end,
					},
				})
			}
		} else {
			allMatches = append(allMatches, matches...)
			ap.stats.ProcessedFiles += len(batch)
		}

		ap.stats.BatchesProcessed++
		ap.stats.AvgBatchTime = (ap.stats.AvgBatchTime*time.Duration(ap.stats.BatchesProcessed-1) + batchDuration) / time.Duration(ap.stats.BatchesProcessed)

		// Check if we need to adjust batch size based on performance
		if ap.shouldAdjustBatchSize(batchDuration, len(batch), avgFileSize) {
			batchSize = ap.calculateOptimalBatchSize(len(filePaths)-end, avgFileSize)
		}
	}

	return allMatches, nil
}

// processBatch processes a single batch of files
func (ap *AdaptiveProcessor) processBatch(filePaths []string, validators []detector.Validator, fileRouter *router.FileRouter, jobConfig *JobConfig) ([]detector.Match, error) {
	var allMatches []detector.Match
	var mu sync.Mutex

	// Submit jobs for this batch
	jobCount := len(filePaths)
	jobs := make(chan *Job, jobCount)

	for i, filePath := range filePaths {
		job := &Job{
			FilePath:   filePath,
			Validators: validators,
			JobID:      fmt.Sprintf("batch_job_%d", i),
			FileRouter: fileRouter,
			Config:     jobConfig,
		}
		jobs <- job
	}
	close(jobs)

	// Submit jobs to worker pool
	go func() {
		for job := range jobs {
			ap.workerPool.Submit(job)
		}
	}()

	// Collect results
	for i := 0; i < jobCount; i++ {
		result := <-ap.workerPool.Results()

		mu.Lock()
		if result.Error == nil {
			allMatches = append(allMatches, result.Matches...)
		} else {
			ap.stats.SkippedFiles++
		}
		mu.Unlock()
	}

	return allMatches, nil
}

// calculateFileStats analyzes file characteristics for optimization
func (ap *AdaptiveProcessor) calculateFileStats(filePaths []string) (avgSize int64, totalSize int64) {
	if len(filePaths) == 0 {
		return 0, 0
	}

	var sizeSum int64
	var validFiles int

	for _, filePath := range filePaths {
		if info, err := os.Stat(filePath); err == nil {
			sizeSum += info.Size()
			validFiles++
		}
	}

	if validFiles > 0 {
		avgSize = sizeSum / int64(validFiles)
		totalSize = sizeSum
	}

	return avgSize, totalSize
}

// calculateOptimalBatchSize determines optimal batch size based on resources and file characteristics
func (ap *AdaptiveProcessor) calculateOptimalBatchSize(remainingFiles int, avgFileSize int64) int {
	// Base batch size on worker count
	baseBatchSize := ap.activeWorkers * 2

	// Adjust for memory constraints
	if ap.resourceMonitor.IsMemoryPressure() {
		baseBatchSize = maxInt(baseBatchSize/2, 5) // Minimum 5 files per batch
	}

	// Adjust for file size (larger files = smaller batches)
	if avgFileSize > 100*1024*1024 { // > 100MB files
		baseBatchSize = maxInt(baseBatchSize/4, 2)
	} else if avgFileSize > 10*1024*1024 { // > 10MB files
		baseBatchSize = maxInt(baseBatchSize/2, 5)
	}

	// Cap batch size
	maxBatch := minInt(ap.maxBatchSize, remainingFiles)
	minBatch := minInt(5, remainingFiles)

	return maxInt(minBatch, minInt(baseBatchSize, maxBatch))
}

// shouldAdjustBatchSize determines if batch size should be adjusted based on performance
func (ap *AdaptiveProcessor) shouldAdjustBatchSize(batchDuration time.Duration, batchSize int, avgFileSize int64) bool {
	// If batch took too long (> 30 seconds), consider reducing batch size
	if batchDuration > 30*time.Second && batchSize > 10 {
		return true
	}

	// If batch was very fast (< 1 second) and we have memory available, consider increasing
	if batchDuration < 1*time.Second && !ap.resourceMonitor.IsMemoryPressure() && batchSize < ap.maxBatchSize/2 {
		return true
	}

	return false
}

// adjustWorkerCount dynamically adjusts worker pool size
func (ap *AdaptiveProcessor) adjustWorkerCount(targetWorkers int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	if targetWorkers != ap.activeWorkers {
		// For now, we create a new worker pool with the target size
		// In a more advanced implementation, we would dynamically scale the existing pool
		previousWorkers := ap.activeWorkers
		ap.activeWorkers = targetWorkers
		ap.stats.WorkerAdjustments++
		ap.stats.MaxWorkers = maxInt(ap.stats.MaxWorkers, targetWorkers)

		if ap.observer != nil {
			ap.observer.LogOperation(observability.StandardObservabilityData{
				Component: "adaptive_processor",
				Operation: "worker_adjustment",
				Success:   true,
				Metadata: map[string]interface{}{
					"previous_workers": previousWorkers,
					"new_workers":      targetWorkers,
					"adjustment_count": ap.stats.WorkerAdjustments,
				},
			})
		}

		// Create new worker pool with adjusted size
		ap.workerPool = NewWorkerPool(targetWorkers, ap.observer)
	}
}

// handleResourceMetrics handles resource metric updates
func (ap *AdaptiveProcessor) handleResourceMetrics(metrics ResourceMetrics) {
	// Update peak memory tracking
	ap.mu.Lock()
	ap.stats.MemoryPeakMB = maxUint64(ap.stats.MemoryPeakMB, metrics.MemoryUsed)
	ap.mu.Unlock()
}

// adaptiveScalingLoop monitors and adjusts resources periodically
func (ap *AdaptiveProcessor) adaptiveScalingLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// Check if we should adjust worker count based on current load
		if ap.resourceMonitor.IsMemoryPressure() && ap.resourceMonitor.ShouldReduceWorkers(ap.activeWorkers) {
			newWorkerCount := maxInt(ap.activeWorkers-1, ap.resourceMonitor.GetLimits().MinWorkers)
			ap.adjustWorkerCount(newWorkerCount)
		} else if !ap.resourceMonitor.IsMemoryPressure() && ap.resourceMonitor.ShouldIncreaseWorkers(ap.activeWorkers) {
			newWorkerCount := minInt(ap.activeWorkers+1, ap.resourceMonitor.GetLimits().MaxWorkers)
			ap.adjustWorkerCount(newWorkerCount)
		}
	}
}

// Stop gracefully shuts down the adaptive processor
func (ap *AdaptiveProcessor) Stop() {
	ap.resourceMonitor.Stop()
	ap.workerPool.Stop()
}

// GetStats returns current processing statistics
func (ap *AdaptiveProcessor) GetStats() *AdaptiveStats {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	statsCopy := *ap.stats
	return &statsCopy
}

// GetResourceMetrics returns current resource metrics
func (ap *AdaptiveProcessor) GetResourceMetrics() ResourceMetrics {
	return ap.resourceMonitor.GetMetrics()
}

// Helper function for uint64 max
func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
