// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package performance

import (
	"sync"
	"time"
)

// PerformanceMetrics tracks comprehensive performance data for the enhanced architecture
type PerformanceMetrics struct {
	// Content routing metrics
	ContentRouting *ContentRoutingMetrics

	// Dual-path validation metrics
	DualPathValidation *DualPathValidationMetrics

	// Memory usage metrics
	MemoryUsage *MemoryUsageMetrics

	// Performance benchmarking metrics
	BenchmarkMetrics *BenchmarkMetrics

	// Overall system metrics
	SystemMetrics *SystemMetrics

	// Thread safety
	mu sync.RWMutex
}

// ContentRoutingMetrics tracks content router performance
type ContentRoutingMetrics struct {
	// Operation counts
	TotalRoutingOperations int64
	SuccessfulRoutingOps   int64
	FailedRoutingOps       int64
	FallbackActivations    int64

	// Timing metrics
	AverageRoutingTime time.Duration
	MinRoutingTime     time.Duration
	MaxRoutingTime     time.Duration
	TotalRoutingTime   time.Duration

	// Content separation metrics
	DocumentBodySeparations     int64
	MetadataSeparations         int64
	PreprocessorIdentifications int64

	// Error tracking
	RoutingErrors map[string]int64 // error type -> count

	// Thread safety
	mu sync.RWMutex
}

// DualPathValidationMetrics tracks dual-path validation performance
type DualPathValidationMetrics struct {
	// Path-specific metrics
	DocumentPathMetrics *ValidationPathMetrics
	MetadataPathMetrics *ValidationPathMetrics

	// Cross-path correlation metrics
	CrossPathCorrelations int64
	CorrelationBoosts     int64
	CorrelationPenalties  int64

	// Parallel processing metrics
	ParallelProcessingTime   time.Duration
	SequentialProcessingTime time.Duration
	ParallelEfficiencyRatio  float64

	// Thread safety
	mu sync.RWMutex
}

// ValidationPathMetrics tracks metrics for individual validation paths
type ValidationPathMetrics struct {
	// Operation counts
	TotalValidations      int64
	SuccessfulValidations int64
	FailedValidations     int64

	// Timing metrics
	AverageValidationTime time.Duration
	MinValidationTime     time.Duration
	MaxValidationTime     time.Duration
	TotalValidationTime   time.Duration

	// Match metrics
	TotalMatches          int64
	AverageMatchesPerFile float64
	AverageConfidence     float64

	// Context integration metrics
	ContextBoosts        int64
	ContextPenalties     int64
	AverageContextImpact float64

	// Thread safety
	mu sync.RWMutex
}

// MemoryUsageMetrics tracks memory consumption
type MemoryUsageMetrics struct {
	// Current memory usage
	CurrentHeapSize   int64
	CurrentStackSize  int64
	CurrentGoroutines int64

	// Peak memory usage
	PeakHeapSize   int64
	PeakStackSize  int64
	PeakGoroutines int64

	// Memory allocation metrics
	TotalAllocations   int64
	TotalDeallocations int64
	GCCycles           int64

	// Content-specific memory usage
	ContentRouterMemory   int64
	ValidatorBridgeMemory int64
	BenchmarkMemory       int64

	// Thread safety
	mu sync.RWMutex
}

// BenchmarkMetrics tracks performance benchmarking data
type BenchmarkMetrics struct {
	// Enhanced vs Legacy comparison
	EnhancedArchitectureTime time.Duration
	LegacyArchitectureTime   time.Duration
	PerformanceImprovement   float64

	// Benchmark sample data
	BenchmarkSamples  []BenchmarkSample
	AverageSampleTime time.Duration
	BestSampleTime    time.Duration
	WorstSampleTime   time.Duration

	// Throughput metrics
	FilesPerSecond   float64
	BytesPerSecond   float64
	MatchesPerSecond float64

	// Thread safety
	mu sync.RWMutex
}

// BenchmarkSample represents a single benchmark measurement
type BenchmarkSample struct {
	Timestamp      time.Time
	ProcessingTime time.Duration
	FileSize       int64
	MatchCount     int
	Architecture   string // "enhanced" or "legacy"
	Success        bool
}

// SystemMetrics tracks overall system performance
type SystemMetrics struct {
	// Processing throughput
	FilesProcessedPerSecond float64
	BytesProcessedPerSecond float64
	MatchesFoundPerSecond   float64

	// Resource utilization
	CPUUsagePercent    float64
	MemoryUsagePercent float64
	DiskIORate         float64

	// Performance comparison metrics
	EnhancedArchitectureTime time.Duration
	LegacyArchitectureTime   time.Duration
	PerformanceImprovement   float64

	// Error rates
	OverallErrorRate    float64
	RoutingErrorRate    float64
	ValidationErrorRate float64

	// Thread safety
	mu sync.RWMutex
}

// NewPerformanceMetrics creates a new performance metrics instance
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		ContentRouting: &ContentRoutingMetrics{
			RoutingErrors: make(map[string]int64),
		},
		DualPathValidation: &DualPathValidationMetrics{
			DocumentPathMetrics: &ValidationPathMetrics{},
			MetadataPathMetrics: &ValidationPathMetrics{},
		},
		MemoryUsage: &MemoryUsageMetrics{},
		BenchmarkMetrics: &BenchmarkMetrics{
			BenchmarkSamples: make([]BenchmarkSample, 0),
		},
		SystemMetrics: &SystemMetrics{},
	}
}

// RecordContentRoutingOperation records a content routing operation
func (pm *PerformanceMetrics) RecordContentRoutingOperation(duration time.Duration, success bool, errorType string) {
	pm.ContentRouting.mu.Lock()
	defer pm.ContentRouting.mu.Unlock()

	pm.ContentRouting.TotalRoutingOperations++
	pm.ContentRouting.TotalRoutingTime += duration

	if success {
		pm.ContentRouting.SuccessfulRoutingOps++
	} else {
		pm.ContentRouting.FailedRoutingOps++
		if errorType != "" {
			pm.ContentRouting.RoutingErrors[errorType]++
		}
	}

	// Update timing statistics
	if pm.ContentRouting.TotalRoutingOperations == 1 {
		pm.ContentRouting.MinRoutingTime = duration
		pm.ContentRouting.MaxRoutingTime = duration
		pm.ContentRouting.AverageRoutingTime = duration
	} else {
		if duration < pm.ContentRouting.MinRoutingTime {
			pm.ContentRouting.MinRoutingTime = duration
		}
		if duration > pm.ContentRouting.MaxRoutingTime {
			pm.ContentRouting.MaxRoutingTime = duration
		}
		pm.ContentRouting.AverageRoutingTime = pm.ContentRouting.TotalRoutingTime / time.Duration(pm.ContentRouting.TotalRoutingOperations)
	}
}

// RecordContentSeparation records content separation metrics
func (pm *PerformanceMetrics) RecordContentSeparation(documentBodyFound, metadataFound bool, preprocessorCount int) {
	pm.ContentRouting.mu.Lock()
	defer pm.ContentRouting.mu.Unlock()

	if documentBodyFound {
		pm.ContentRouting.DocumentBodySeparations++
	}
	if metadataFound {
		pm.ContentRouting.MetadataSeparations++
	}
	pm.ContentRouting.PreprocessorIdentifications += int64(preprocessorCount)
}

// RecordValidationPathOperation records validation path metrics
func (pm *PerformanceMetrics) RecordValidationPathOperation(isMetadataPath bool, duration time.Duration, success bool, matchCount int, avgConfidence float64) {
	pm.DualPathValidation.mu.Lock()
	defer pm.DualPathValidation.mu.Unlock()

	var pathMetrics *ValidationPathMetrics
	if isMetadataPath {
		pathMetrics = pm.DualPathValidation.MetadataPathMetrics
	} else {
		pathMetrics = pm.DualPathValidation.DocumentPathMetrics
	}

	pathMetrics.mu.Lock()
	defer pathMetrics.mu.Unlock()

	pathMetrics.TotalValidations++
	pathMetrics.TotalValidationTime += duration
	pathMetrics.TotalMatches += int64(matchCount)

	if success {
		pathMetrics.SuccessfulValidations++
	} else {
		pathMetrics.FailedValidations++
	}

	// Update timing statistics
	if pathMetrics.TotalValidations == 1 {
		pathMetrics.MinValidationTime = duration
		pathMetrics.MaxValidationTime = duration
		pathMetrics.AverageValidationTime = duration
		pathMetrics.AverageMatchesPerFile = float64(matchCount)
		pathMetrics.AverageConfidence = avgConfidence
	} else {
		if duration < pathMetrics.MinValidationTime {
			pathMetrics.MinValidationTime = duration
		}
		if duration > pathMetrics.MaxValidationTime {
			pathMetrics.MaxValidationTime = duration
		}
		pathMetrics.AverageValidationTime = pathMetrics.TotalValidationTime / time.Duration(pathMetrics.TotalValidations)
		pathMetrics.AverageMatchesPerFile = float64(pathMetrics.TotalMatches) / float64(pathMetrics.TotalValidations)

		// Running average for confidence
		pathMetrics.AverageConfidence = (pathMetrics.AverageConfidence*float64(pathMetrics.TotalValidations-1) + avgConfidence) / float64(pathMetrics.TotalValidations)
	}
}

// RecordBenchmarkSample records a benchmark measurement
func (pm *PerformanceMetrics) RecordBenchmarkSample(sample BenchmarkSample) {
	pm.BenchmarkMetrics.mu.Lock()
	defer pm.BenchmarkMetrics.mu.Unlock()

	pm.BenchmarkMetrics.BenchmarkSamples = append(pm.BenchmarkMetrics.BenchmarkSamples, sample)

	// Update timing statistics
	if len(pm.BenchmarkMetrics.BenchmarkSamples) == 1 {
		pm.BenchmarkMetrics.AverageSampleTime = sample.ProcessingTime
		pm.BenchmarkMetrics.BestSampleTime = sample.ProcessingTime
		pm.BenchmarkMetrics.WorstSampleTime = sample.ProcessingTime
	} else {
		// Update average
		totalTime := time.Duration(0)
		for _, s := range pm.BenchmarkMetrics.BenchmarkSamples {
			totalTime += s.ProcessingTime
		}
		pm.BenchmarkMetrics.AverageSampleTime = totalTime / time.Duration(len(pm.BenchmarkMetrics.BenchmarkSamples))

		// Update best/worst
		if sample.ProcessingTime < pm.BenchmarkMetrics.BestSampleTime {
			pm.BenchmarkMetrics.BestSampleTime = sample.ProcessingTime
		}
		if sample.ProcessingTime > pm.BenchmarkMetrics.WorstSampleTime {
			pm.BenchmarkMetrics.WorstSampleTime = sample.ProcessingTime
		}
	}

	// Calculate performance improvement if we have both architectures
	pm.calculatePerformanceImprovement()
}

// calculatePerformanceImprovement calculates performance improvement between architectures
func (pm *PerformanceMetrics) calculatePerformanceImprovement() {
	var enhancedTotal, legacyTotal time.Duration
	var enhancedCount, legacyCount int

	for _, sample := range pm.BenchmarkMetrics.BenchmarkSamples {
		if sample.Architecture == "enhanced" {
			enhancedTotal += sample.ProcessingTime
			enhancedCount++
		} else if sample.Architecture == "legacy" {
			legacyTotal += sample.ProcessingTime
			legacyCount++
		}
	}

	if enhancedCount > 0 && legacyCount > 0 {
		enhancedAvg := enhancedTotal / time.Duration(enhancedCount)
		legacyAvg := legacyTotal / time.Duration(legacyCount)

		pm.BenchmarkMetrics.EnhancedArchitectureTime = enhancedAvg
		pm.BenchmarkMetrics.LegacyArchitectureTime = legacyAvg

		// Calculate improvement as percentage
		if legacyAvg > 0 {
			improvement := float64(legacyAvg-enhancedAvg) / float64(legacyAvg)
			pm.BenchmarkMetrics.PerformanceImprovement = improvement
		}
	}
}

// UpdateMemoryUsage updates memory usage metrics
func (pm *PerformanceMetrics) UpdateMemoryUsage(heapSize, stackSize, goroutines int64) {
	pm.MemoryUsage.mu.Lock()
	defer pm.MemoryUsage.mu.Unlock()

	pm.MemoryUsage.CurrentHeapSize = heapSize
	pm.MemoryUsage.CurrentStackSize = stackSize
	pm.MemoryUsage.CurrentGoroutines = goroutines

	// Update peaks
	if heapSize > pm.MemoryUsage.PeakHeapSize {
		pm.MemoryUsage.PeakHeapSize = heapSize
	}
	if stackSize > pm.MemoryUsage.PeakStackSize {
		pm.MemoryUsage.PeakStackSize = stackSize
	}
	if goroutines > pm.MemoryUsage.PeakGoroutines {
		pm.MemoryUsage.PeakGoroutines = goroutines
	}
}

// GetContentRoutingMetrics returns a copy of content routing metrics
func (pm *PerformanceMetrics) GetContentRoutingMetrics() ContentRoutingMetrics {
	pm.ContentRouting.mu.RLock()
	defer pm.ContentRouting.mu.RUnlock()

	// Create a deep copy
	errorsCopy := make(map[string]int64)
	for k, v := range pm.ContentRouting.RoutingErrors {
		errorsCopy[k] = v
	}

	return ContentRoutingMetrics{
		TotalRoutingOperations:      pm.ContentRouting.TotalRoutingOperations,
		SuccessfulRoutingOps:        pm.ContentRouting.SuccessfulRoutingOps,
		FailedRoutingOps:            pm.ContentRouting.FailedRoutingOps,
		FallbackActivations:         pm.ContentRouting.FallbackActivations,
		AverageRoutingTime:          pm.ContentRouting.AverageRoutingTime,
		MinRoutingTime:              pm.ContentRouting.MinRoutingTime,
		MaxRoutingTime:              pm.ContentRouting.MaxRoutingTime,
		TotalRoutingTime:            pm.ContentRouting.TotalRoutingTime,
		DocumentBodySeparations:     pm.ContentRouting.DocumentBodySeparations,
		MetadataSeparations:         pm.ContentRouting.MetadataSeparations,
		PreprocessorIdentifications: pm.ContentRouting.PreprocessorIdentifications,
		RoutingErrors:               errorsCopy,
	}
}

// GetDualPathValidationMetrics returns a copy of dual-path validation metrics
func (pm *PerformanceMetrics) GetDualPathValidationMetrics() DualPathValidationMetrics {
	pm.DualPathValidation.mu.RLock()
	defer pm.DualPathValidation.mu.RUnlock()

	return DualPathValidationMetrics{
		DocumentPathMetrics:      pm.copyValidationPathMetrics(pm.DualPathValidation.DocumentPathMetrics),
		MetadataPathMetrics:      pm.copyValidationPathMetrics(pm.DualPathValidation.MetadataPathMetrics),
		CrossPathCorrelations:    pm.DualPathValidation.CrossPathCorrelations,
		CorrelationBoosts:        pm.DualPathValidation.CorrelationBoosts,
		CorrelationPenalties:     pm.DualPathValidation.CorrelationPenalties,
		ParallelProcessingTime:   pm.DualPathValidation.ParallelProcessingTime,
		SequentialProcessingTime: pm.DualPathValidation.SequentialProcessingTime,
		ParallelEfficiencyRatio:  pm.DualPathValidation.ParallelEfficiencyRatio,
	}
}

// copyValidationPathMetrics creates a copy of validation path metrics
func (pm *PerformanceMetrics) copyValidationPathMetrics(source *ValidationPathMetrics) *ValidationPathMetrics {
	source.mu.RLock()
	defer source.mu.RUnlock()

	return &ValidationPathMetrics{
		TotalValidations:      source.TotalValidations,
		SuccessfulValidations: source.SuccessfulValidations,
		FailedValidations:     source.FailedValidations,
		AverageValidationTime: source.AverageValidationTime,
		MinValidationTime:     source.MinValidationTime,
		MaxValidationTime:     source.MaxValidationTime,
		TotalValidationTime:   source.TotalValidationTime,
		TotalMatches:          source.TotalMatches,
		AverageMatchesPerFile: source.AverageMatchesPerFile,
		AverageConfidence:     source.AverageConfidence,
		ContextBoosts:         source.ContextBoosts,
		ContextPenalties:      source.ContextPenalties,
		AverageContextImpact:  source.AverageContextImpact,
	}
}
