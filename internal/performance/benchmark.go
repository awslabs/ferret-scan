// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package performance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
)

// BenchmarkRunner provides performance benchmarking capabilities
type BenchmarkRunner struct {
	monitor  *PerformanceMonitor
	observer *observability.StandardObserver

	// Benchmark configuration
	config *BenchmarkConfig

	// Test data
	testFiles []BenchmarkTestFile

	// Results
	results *BenchmarkResults

	// Thread safety
	mu sync.RWMutex
}

// BenchmarkConfig configures benchmark execution
type BenchmarkConfig struct {
	// Sample configuration
	SampleSize       int
	WarmupRuns       int
	MaxExecutionTime time.Duration

	// Test data configuration
	UseRealFiles          bool
	GenerateSyntheticData bool
	TestDataSize          int64

	// Comparison configuration
	CompareWithLegacy     bool
	EnableDetailedMetrics bool
	EnableMemoryProfiling bool

	// Output configuration
	GenerateReport bool
	ReportFormat   string // "json", "csv", "html"
}

// BenchmarkTestFile represents a test file for benchmarking
type BenchmarkTestFile struct {
	Name            string
	Content         string
	Size            int64
	ExpectedMatches int
	FileType        string
	HasMetadata     bool
}

// BenchmarkResults contains comprehensive benchmark results
type BenchmarkResults struct {
	// Overall results
	TotalSamples      int
	SuccessfulSamples int
	FailedSamples     int

	// Enhanced architecture results
	EnhancedResults *ArchitectureBenchmarkResults

	// Legacy architecture results (if comparison enabled)
	LegacyResults *ArchitectureBenchmarkResults

	// Performance comparison
	PerformanceImprovement float64
	MemoryImprovement      float64
	ThroughputImprovement  float64

	// Detailed metrics
	DetailedMetrics map[string]interface{}

	// Execution metadata
	StartTime          time.Time
	EndTime            time.Time
	TotalExecutionTime time.Duration
}

// ArchitectureBenchmarkResults contains results for a specific architecture
type ArchitectureBenchmarkResults struct {
	// Timing metrics
	AverageProcessingTime time.Duration
	MinProcessingTime     time.Duration
	MaxProcessingTime     time.Duration
	MedianProcessingTime  time.Duration
	P95ProcessingTime     time.Duration
	P99ProcessingTime     time.Duration

	// Throughput metrics
	FilesPerSecond   float64
	BytesPerSecond   float64
	MatchesPerSecond float64

	// Memory metrics
	AverageMemoryUsage int64
	PeakMemoryUsage    int64
	MemoryGrowthRate   float64

	// Accuracy metrics
	TotalMatches      int
	AverageConfidence float64
	FalsePositiveRate float64
	FalseNegativeRate float64

	// Error metrics
	ErrorRate   float64
	TimeoutRate float64
}

// NewBenchmarkRunner creates a new benchmark runner
func NewBenchmarkRunner(monitor *PerformanceMonitor, observer *observability.StandardObserver, config *BenchmarkConfig) *BenchmarkRunner {
	if config == nil {
		config = getDefaultBenchmarkConfig()
	}

	return &BenchmarkRunner{
		monitor:   monitor,
		observer:  observer,
		config:    config,
		testFiles: make([]BenchmarkTestFile, 0),
		results:   &BenchmarkResults{},
	}
}

// LoadTestFiles loads test files for benchmarking
func (br *BenchmarkRunner) LoadTestFiles(files []BenchmarkTestFile) error {
	br.mu.Lock()
	defer br.mu.Unlock()

	if len(files) == 0 {
		return fmt.Errorf("no test files provided")
	}

	br.testFiles = files

	if br.observer != nil && br.observer.DebugObserver != nil {
		br.observer.DebugObserver.LogDetail("benchmark_runner", fmt.Sprintf("Loaded %d test files", len(files)))
	}

	return nil
}

// GenerateSyntheticTestData generates synthetic test data for benchmarking
func (br *BenchmarkRunner) GenerateSyntheticTestData() error {
	br.mu.Lock()
	defer br.mu.Unlock()

	// Generate various types of synthetic test files
	syntheticFiles := []BenchmarkTestFile{
		{
			Name:            "synthetic_document_small.txt",
			Content:         br.generateSyntheticDocument(1024),
			Size:            1024,
			ExpectedMatches: 2,
			FileType:        "text",
			HasMetadata:     false,
		},
		{
			Name:            "synthetic_document_medium.txt",
			Content:         br.generateSyntheticDocument(10240),
			Size:            10240,
			ExpectedMatches: 5,
			FileType:        "text",
			HasMetadata:     false,
		},
		{
			Name:            "synthetic_document_large.txt",
			Content:         br.generateSyntheticDocument(102400),
			Size:            102400,
			ExpectedMatches: 10,
			FileType:        "text",
			HasMetadata:     false,
		},
		{
			Name:            "synthetic_pdf_with_metadata.pdf",
			Content:         br.generateSyntheticPDFContent(),
			Size:            51200,
			ExpectedMatches: 8,
			FileType:        "pdf",
			HasMetadata:     true,
		},
		{
			Name:            "synthetic_image_with_exif.jpg",
			Content:         br.generateSyntheticImageContent(),
			Size:            204800,
			ExpectedMatches: 3,
			FileType:        "image",
			HasMetadata:     true,
		},
	}

	br.testFiles = syntheticFiles

	if br.observer != nil && br.observer.DebugObserver != nil {
		br.observer.DebugObserver.LogDetail("benchmark_runner", fmt.Sprintf("Generated %d synthetic test files", len(syntheticFiles)))
	}

	return nil
}

// RunBenchmark executes the performance benchmark
func (br *BenchmarkRunner) RunBenchmark(ctx context.Context, enhancedProcessor func(*preprocessors.ProcessedContent) ([]detector.Match, error), legacyProcessor func(*preprocessors.ProcessedContent) ([]detector.Match, error)) (*BenchmarkResults, error) {
	br.mu.Lock()
	defer br.mu.Unlock()

	if len(br.testFiles) == 0 {
		return nil, fmt.Errorf("no test files loaded")
	}

	br.results = &BenchmarkResults{
		StartTime:       time.Now(),
		DetailedMetrics: make(map[string]interface{}),
	}

	if br.observer != nil && br.observer.DebugObserver != nil {
		br.observer.DebugObserver.LogDetail("benchmark_runner", fmt.Sprintf("Starting benchmark with %d test files", len(br.testFiles)))
	}

	// Run warmup if configured
	if br.config.WarmupRuns > 0 {
		err := br.runWarmup(ctx, enhancedProcessor)
		if err != nil {
			return nil, fmt.Errorf("warmup failed: %w", err)
		}
	}

	// Benchmark enhanced architecture
	enhancedResults, err := br.benchmarkArchitecture(ctx, "enhanced", enhancedProcessor)
	if err != nil {
		return nil, fmt.Errorf("enhanced architecture benchmark failed: %w", err)
	}
	br.results.EnhancedResults = enhancedResults

	// Benchmark legacy architecture if comparison is enabled
	if br.config.CompareWithLegacy && legacyProcessor != nil {
		legacyResults, err := br.benchmarkArchitecture(ctx, "legacy", legacyProcessor)
		if err != nil {
			if br.observer != nil {
				br.observer.LogOperation(observability.StandardObservabilityData{
					Component: "benchmark_runner",
					Operation: "legacy_benchmark_failed",
					Success:   false,
					Error:     err.Error(),
				})
			}
			// Continue without legacy comparison
		} else {
			br.results.LegacyResults = legacyResults
		}
	}

	// Calculate performance improvements
	br.calculatePerformanceImprovements()

	br.results.EndTime = time.Now()
	br.results.TotalExecutionTime = br.results.EndTime.Sub(br.results.StartTime)

	if br.observer != nil {
		br.observer.LogOperation(observability.StandardObservabilityData{
			Component: "benchmark_runner",
			Operation: "benchmark_completed",
			Success:   true,
			Metadata: map[string]interface{}{
				"total_samples":           br.results.TotalSamples,
				"successful_samples":      br.results.SuccessfulSamples,
				"performance_improvement": br.results.PerformanceImprovement,
				"execution_time_ms":       br.results.TotalExecutionTime.Milliseconds(),
			},
		})
	}

	return br.results, nil
}

// benchmarkArchitecture benchmarks a specific architecture
func (br *BenchmarkRunner) benchmarkArchitecture(ctx context.Context, architecture string, processor func(*preprocessors.ProcessedContent) ([]detector.Match, error)) (*ArchitectureBenchmarkResults, error) {
	results := &ArchitectureBenchmarkResults{}
	var samples []time.Duration
	var memoryUsages []int64
	var totalMatches int
	var totalConfidence float64
	var errors int

	sampleCount := br.config.SampleSize
	if sampleCount <= 0 {
		sampleCount = len(br.testFiles)
	}

	for i := 0; i < sampleCount; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		testFile := br.testFiles[i%len(br.testFiles)]

		// Create processed content
		processedContent := &preprocessors.ProcessedContent{
			Text:         testFile.Content,
			OriginalPath: testFile.Name,
		}

		// Measure memory before processing
		memBefore := br.getCurrentMemoryUsage()

		// Measure processing time
		startTime := time.Now()
		matches, err := processor(processedContent)
		processingTime := time.Since(startTime)

		// Measure memory after processing
		memAfter := br.getCurrentMemoryUsage()

		if err != nil {
			errors++
			if br.observer != nil && br.observer.DebugObserver != nil {
				br.observer.DebugObserver.LogDetail("benchmark_error", fmt.Sprintf("Processing failed for %s: %v", testFile.Name, err))
			}
			continue
		}

		// Record sample
		sample := BenchmarkSample{
			Timestamp:      time.Now(),
			ProcessingTime: processingTime,
			FileSize:       testFile.Size,
			MatchCount:     len(matches),
			Architecture:   architecture,
			Success:        true,
		}

		if br.monitor != nil {
			br.monitor.RecordBenchmarkSample(sample)
		}

		samples = append(samples, processingTime)
		memoryUsages = append(memoryUsages, memAfter-memBefore)
		totalMatches += len(matches)

		// Calculate average confidence
		for _, match := range matches {
			totalConfidence += match.Confidence
		}

		br.results.TotalSamples++
		br.results.SuccessfulSamples++
	}

	if len(samples) == 0 {
		return nil, fmt.Errorf("no successful samples for %s architecture", architecture)
	}

	// Calculate timing statistics
	results.AverageProcessingTime = br.calculateAverage(samples)
	results.MinProcessingTime = br.calculateMin(samples)
	results.MaxProcessingTime = br.calculateMax(samples)
	results.MedianProcessingTime = br.calculateMedian(samples)
	results.P95ProcessingTime = br.calculatePercentile(samples, 0.95)
	results.P99ProcessingTime = br.calculatePercentile(samples, 0.99)

	// Calculate throughput
	totalTime := time.Duration(0)
	totalBytes := int64(0)
	for i, sample := range samples {
		totalTime += sample
		totalBytes += br.testFiles[i%len(br.testFiles)].Size
	}

	if totalTime > 0 {
		results.FilesPerSecond = float64(len(samples)) / totalTime.Seconds()
		results.BytesPerSecond = float64(totalBytes) / totalTime.Seconds()
		results.MatchesPerSecond = float64(totalMatches) / totalTime.Seconds()
	}

	// Calculate memory statistics
	if len(memoryUsages) > 0 {
		results.AverageMemoryUsage = br.calculateAverageInt64(memoryUsages)
		results.PeakMemoryUsage = br.calculateMaxInt64(memoryUsages)
	}

	// Calculate accuracy metrics
	if totalMatches > 0 {
		results.AverageConfidence = totalConfidence / float64(totalMatches)
	}
	results.TotalMatches = totalMatches
	results.ErrorRate = float64(errors) / float64(br.results.TotalSamples)

	return results, nil
}

// runWarmup runs warmup iterations to stabilize performance
func (br *BenchmarkRunner) runWarmup(ctx context.Context, processor func(*preprocessors.ProcessedContent) ([]detector.Match, error)) error {
	if br.observer != nil && br.observer.DebugObserver != nil {
		br.observer.DebugObserver.LogDetail("benchmark_warmup", fmt.Sprintf("Running %d warmup iterations", br.config.WarmupRuns))
	}

	for i := 0; i < br.config.WarmupRuns; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		testFile := br.testFiles[i%len(br.testFiles)]
		processedContent := &preprocessors.ProcessedContent{
			Text:         testFile.Content,
			OriginalPath: testFile.Name,
		}

		_, err := processor(processedContent)
		if err != nil && br.observer != nil && br.observer.DebugObserver != nil {
			br.observer.DebugObserver.LogDetail("warmup_error", fmt.Sprintf("Warmup iteration %d failed: %v", i, err))
		}
	}

	return nil
}

// calculatePerformanceImprovements calculates performance improvements between architectures
func (br *BenchmarkRunner) calculatePerformanceImprovements() {
	if br.results.EnhancedResults == nil {
		return
	}

	if br.results.LegacyResults != nil {
		// Calculate processing time improvement
		if br.results.LegacyResults.AverageProcessingTime > 0 {
			improvement := float64(br.results.LegacyResults.AverageProcessingTime-br.results.EnhancedResults.AverageProcessingTime) / float64(br.results.LegacyResults.AverageProcessingTime)
			br.results.PerformanceImprovement = improvement
		}

		// Calculate memory improvement
		if br.results.LegacyResults.AverageMemoryUsage > 0 {
			memImprovement := float64(br.results.LegacyResults.AverageMemoryUsage-br.results.EnhancedResults.AverageMemoryUsage) / float64(br.results.LegacyResults.AverageMemoryUsage)
			br.results.MemoryImprovement = memImprovement
		}

		// Calculate throughput improvement
		if br.results.LegacyResults.FilesPerSecond > 0 {
			throughputImprovement := (br.results.EnhancedResults.FilesPerSecond - br.results.LegacyResults.FilesPerSecond) / br.results.LegacyResults.FilesPerSecond
			br.results.ThroughputImprovement = throughputImprovement
		}
	}

	// Store detailed metrics
	br.results.DetailedMetrics["enhanced_avg_time_ms"] = br.results.EnhancedResults.AverageProcessingTime.Milliseconds()
	br.results.DetailedMetrics["enhanced_files_per_sec"] = br.results.EnhancedResults.FilesPerSecond
	br.results.DetailedMetrics["enhanced_avg_memory_mb"] = br.results.EnhancedResults.AverageMemoryUsage / 1024 / 1024

	if br.results.LegacyResults != nil {
		br.results.DetailedMetrics["legacy_avg_time_ms"] = br.results.LegacyResults.AverageProcessingTime.Milliseconds()
		br.results.DetailedMetrics["legacy_files_per_sec"] = br.results.LegacyResults.FilesPerSecond
		br.results.DetailedMetrics["legacy_avg_memory_mb"] = br.results.LegacyResults.AverageMemoryUsage / 1024 / 1024
	}
}

// Helper methods for synthetic data generation

func (br *BenchmarkRunner) generateSyntheticDocument(size int64) string {
	// Generate synthetic document content with embedded sensitive data patterns
	content := "This is a synthetic document for benchmarking purposes.\n\n"
	content += "Contact Information:\n"
	content += "Email: john.doe@example.com\n"
	content += "Phone: (555) 123-4567\n"
	content += "SSN: 123-45-6789\n\n"

	// Pad to desired size
	for int64(len(content)) < size {
		content += "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
	}

	return content[:size]
}

func (br *BenchmarkRunner) generateSyntheticPDFContent() string {
	return `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Creator (Synthetic PDF Generator)
/Author (John Doe)
/Subject (Test Document)
/Keywords (benchmark, test, sensitive data)
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 200
>>
stream
BT
/F1 12 Tf
100 700 Td
(This document contains sensitive information:) Tj
0 -20 Td
(SSN: 987-65-4321) Tj
0 -20 Td
(Credit Card: 4532-1234-5678-9012) Tj
0 -20 Td
(Email: jane.smith@company.com) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000158 00000 n
0000000215 00000 n
0000000274 00000 n
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
524
%%EOF`
}

func (br *BenchmarkRunner) generateSyntheticImageContent() string {
	// Simulate JPEG with EXIF data containing GPS coordinates
	return "JPEG_HEADER_WITH_EXIF_GPS_DATA_LAT_40.7128_LON_-74.0060_DEVICE_iPhone12_TIMESTAMP_2023-01-01T12:00:00Z"
}

// Helper methods for statistical calculations

func (br *BenchmarkRunner) calculateAverage(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	total := time.Duration(0)
	for _, sample := range samples {
		total += sample
	}
	return total / time.Duration(len(samples))
}

func (br *BenchmarkRunner) calculateMin(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	min := samples[0]
	for _, sample := range samples[1:] {
		if sample < min {
			min = sample
		}
	}
	return min
}

func (br *BenchmarkRunner) calculateMax(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	max := samples[0]
	for _, sample := range samples[1:] {
		if sample > max {
			max = sample
		}
	}
	return max
}

func (br *BenchmarkRunner) calculateMedian(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	// Simple median calculation (would need sorting for accuracy)
	return samples[len(samples)/2]
}

func (br *BenchmarkRunner) calculatePercentile(samples []time.Duration, percentile float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	index := int(float64(len(samples)) * percentile)
	if index >= len(samples) {
		index = len(samples) - 1
	}
	return samples[index]
}

func (br *BenchmarkRunner) calculateAverageInt64(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	total := int64(0)
	for _, sample := range samples {
		total += sample
	}
	return total / int64(len(samples))
}

func (br *BenchmarkRunner) calculateMaxInt64(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	max := samples[0]
	for _, sample := range samples[1:] {
		if sample > max {
			max = sample
		}
	}
	return max
}

func (br *BenchmarkRunner) getCurrentMemoryUsage() int64 {
	// This would use runtime.ReadMemStats() in a real implementation
	// For now, return a placeholder
	return 1024 * 1024 // 1MB placeholder
}

// Default configuration

func getDefaultBenchmarkConfig() *BenchmarkConfig {
	return &BenchmarkConfig{
		SampleSize:            100,
		WarmupRuns:            10,
		MaxExecutionTime:      5 * time.Minute,
		UseRealFiles:          false,
		GenerateSyntheticData: true,
		TestDataSize:          1024 * 1024, // 1MB
		CompareWithLegacy:     true,
		EnableDetailedMetrics: true,
		EnableMemoryProfiling: true,
		GenerateReport:        true,
		ReportFormat:          "json",
	}
}
