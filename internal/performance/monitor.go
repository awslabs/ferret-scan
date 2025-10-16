// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package performance

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	"ferret-scan/internal/observability"
)

// PerformanceMonitor provides comprehensive performance monitoring for the enhanced architecture
type PerformanceMonitor struct {
	metrics  *PerformanceMetrics
	observer *observability.StandardObserver

	// Monitoring configuration
	config *MonitorConfig

	// Background monitoring
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	monitoring bool

	// Alerting thresholds
	alertThresholds *AlertThresholds

	// Thread safety
	mu sync.RWMutex
}

// MonitorConfig configures the performance monitor
type MonitorConfig struct {
	// Monitoring intervals
	MemoryMonitoringInterval time.Duration
	MetricsReportingInterval time.Duration
	AlertCheckInterval       time.Duration

	// Feature flags
	EnableMemoryMonitoring bool
	EnableAlerts           bool
	EnableBenchmarking     bool
	EnableDetailedLogging  bool

	// Performance comparison
	EnableLegacyComparison bool
	BenchmarkSampleSize    int
}

// AlertThresholds defines thresholds for performance alerts
type AlertThresholds struct {
	// Memory thresholds
	MaxHeapSizeMB       int64
	MaxGoroutines       int64
	MaxMemoryGrowthRate float64

	// Performance thresholds
	MaxRoutingTimeMs          int64
	MaxValidationTimeMs       int64
	MinPerformanceImprovement float64

	// Error rate thresholds
	MaxRoutingErrorRate    float64
	MaxValidationErrorRate float64
	MaxFallbackRate        float64

	// Efficiency thresholds
	MinParallelEfficiency     float64
	MaxPerformanceDegradation float64
}

// Alert represents a performance alert
type Alert struct {
	Type        string
	Severity    string
	Message     string
	Timestamp   time.Time
	Metrics     map[string]interface{}
	Threshold   interface{}
	ActualValue interface{}
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(observer *observability.StandardObserver, config *MonitorConfig) *PerformanceMonitor {
	if config == nil {
		config = getDefaultMonitorConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	monitor := &PerformanceMonitor{
		metrics:         NewPerformanceMetrics(),
		observer:        observer,
		config:          config,
		ctx:             ctx,
		cancel:          cancel,
		alertThresholds: getDefaultAlertThresholds(),
	}

	return monitor
}

// StartMonitoring begins background performance monitoring
func (pm *PerformanceMonitor) StartMonitoring() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.monitoring {
		return fmt.Errorf("performance monitoring is already running")
	}

	pm.monitoring = true

	// Start memory monitoring if enabled
	if pm.config.EnableMemoryMonitoring {
		pm.wg.Add(1)
		go pm.monitorMemoryUsage()
	}

	// Start metrics reporting if enabled
	if pm.config.MetricsReportingInterval > 0 {
		pm.wg.Add(1)
		go pm.reportMetrics()
	}

	// Start alert monitoring if enabled
	if pm.config.EnableAlerts {
		pm.wg.Add(1)
		go pm.monitorAlerts()
	}

	if pm.observer != nil && pm.observer.DebugObserver != nil {
		pm.observer.DebugObserver.LogDetail("performance_monitor", "Performance monitoring started")
	}

	return nil
}

// StopMonitoring stops background performance monitoring
func (pm *PerformanceMonitor) StopMonitoring() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.monitoring {
		return
	}

	pm.cancel()
	pm.wg.Wait()
	pm.monitoring = false

	if pm.observer != nil && pm.observer.DebugObserver != nil {
		pm.observer.DebugObserver.LogDetail("performance_monitor", "Performance monitoring stopped")
	}
}

// RecordContentRoutingOperation records a content routing operation
func (pm *PerformanceMonitor) RecordContentRoutingOperation(duration time.Duration, success bool, errorType string) {
	pm.metrics.RecordContentRoutingOperation(duration, success, errorType)

	// Check for immediate alerts
	if pm.config.EnableAlerts {
		pm.checkRoutingPerformanceAlert(duration, success, errorType)
	}
}

// RecordContentSeparation records content separation metrics
func (pm *PerformanceMonitor) RecordContentSeparation(documentBodyFound, metadataFound bool, preprocessorCount int) {
	pm.metrics.RecordContentSeparation(documentBodyFound, metadataFound, preprocessorCount)
}

// RecordValidationPathOperation records validation path metrics
func (pm *PerformanceMonitor) RecordValidationPathOperation(isMetadataPath bool, duration time.Duration, success bool, matchCount int, avgConfidence float64) {
	pm.metrics.RecordValidationPathOperation(isMetadataPath, duration, success, matchCount, avgConfidence)

	// Check for immediate alerts
	if pm.config.EnableAlerts {
		pm.checkValidationPerformanceAlert(isMetadataPath, duration, success)
	}
}

// RecordBenchmarkSample records a benchmark measurement
func (pm *PerformanceMonitor) RecordBenchmarkSample(sample BenchmarkSample) {
	pm.metrics.RecordBenchmarkSample(sample)
}

// RecordFallbackActivation records when fallback mode is activated
func (pm *PerformanceMonitor) RecordFallbackActivation(reason string) {
	pm.metrics.ContentRouting.mu.Lock()
	pm.metrics.ContentRouting.FallbackActivations++
	pm.metrics.ContentRouting.mu.Unlock()

	if pm.observer != nil {
		pm.observer.LogOperation(observability.StandardObservabilityData{
			Component: "performance_monitor",
			Operation: "fallback_activation",
			Success:   true,
			Metadata: map[string]interface{}{
				"reason":          reason,
				"total_fallbacks": pm.metrics.ContentRouting.FallbackActivations,
			},
		})
	}

	// Check fallback rate alert
	if pm.config.EnableAlerts {
		pm.checkFallbackRateAlert()
	}
}

// GetMetrics returns current performance metrics
func (pm *PerformanceMonitor) GetMetrics() *PerformanceMetrics {
	return pm.metrics
}

// GetPerformanceSummary returns a summary of current performance
func (pm *PerformanceMonitor) GetPerformanceSummary() map[string]interface{} {
	contentMetrics := pm.metrics.GetContentRoutingMetrics()
	dualPathMetrics := pm.metrics.GetDualPathValidationMetrics()

	pm.metrics.MemoryUsage.mu.RLock()
	currentHeapSize := pm.metrics.MemoryUsage.CurrentHeapSize
	peakHeapSize := pm.metrics.MemoryUsage.PeakHeapSize
	currentGoroutines := pm.metrics.MemoryUsage.CurrentGoroutines
	peakGoroutines := pm.metrics.MemoryUsage.PeakGoroutines
	pm.metrics.MemoryUsage.mu.RUnlock()

	pm.metrics.BenchmarkMetrics.mu.RLock()
	performanceImprovement := pm.metrics.BenchmarkMetrics.PerformanceImprovement
	averageSampleTime := pm.metrics.BenchmarkMetrics.AverageSampleTime
	bestSampleTime := pm.metrics.BenchmarkMetrics.BestSampleTime
	worstSampleTime := pm.metrics.BenchmarkMetrics.WorstSampleTime
	totalSamples := len(pm.metrics.BenchmarkMetrics.BenchmarkSamples)
	pm.metrics.BenchmarkMetrics.mu.RUnlock()

	return map[string]interface{}{
		"content_routing": map[string]interface{}{
			"total_operations": contentMetrics.TotalRoutingOperations,
			"success_rate":     pm.calculateSuccessRate(contentMetrics.SuccessfulRoutingOps, contentMetrics.TotalRoutingOperations),
			"average_time_ms":  contentMetrics.AverageRoutingTime.Milliseconds(),
			"fallback_rate":    pm.calculateFallbackRate(contentMetrics.FallbackActivations, contentMetrics.TotalRoutingOperations),
		},
		"dual_path_validation": map[string]interface{}{
			"document_path": map[string]interface{}{
				"total_validations": dualPathMetrics.DocumentPathMetrics.TotalValidations,
				"success_rate":      pm.calculateSuccessRate(dualPathMetrics.DocumentPathMetrics.SuccessfulValidations, dualPathMetrics.DocumentPathMetrics.TotalValidations),
				"average_time_ms":   dualPathMetrics.DocumentPathMetrics.AverageValidationTime.Milliseconds(),
				"average_matches":   dualPathMetrics.DocumentPathMetrics.AverageMatchesPerFile,
			},
			"metadata_path": map[string]interface{}{
				"total_validations": dualPathMetrics.MetadataPathMetrics.TotalValidations,
				"success_rate":      pm.calculateSuccessRate(dualPathMetrics.MetadataPathMetrics.SuccessfulValidations, dualPathMetrics.MetadataPathMetrics.TotalValidations),
				"average_time_ms":   dualPathMetrics.MetadataPathMetrics.AverageValidationTime.Milliseconds(),
				"average_matches":   dualPathMetrics.MetadataPathMetrics.AverageMatchesPerFile,
			},
		},
		"memory_usage": map[string]interface{}{
			"current_heap_mb":    currentHeapSize / 1024 / 1024,
			"peak_heap_mb":       peakHeapSize / 1024 / 1024,
			"current_goroutines": currentGoroutines,
			"peak_goroutines":    peakGoroutines,
		},
		"benchmarking": map[string]interface{}{
			"performance_improvement": performanceImprovement,
			"average_sample_time_ms":  averageSampleTime.Milliseconds(),
			"best_sample_time_ms":     bestSampleTime.Milliseconds(),
			"worst_sample_time_ms":    worstSampleTime.Milliseconds(),
			"total_samples":           totalSamples,
		},
	}
}

// monitorMemoryUsage monitors memory usage in the background
func (pm *PerformanceMonitor) monitorMemoryUsage() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.config.MemoryMonitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.updateMemoryMetrics()
		}
	}
}

// updateMemoryMetrics updates current memory usage metrics
func (pm *PerformanceMonitor) updateMemoryMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Safe conversion with bounds checking - log error and use max value if overflow
	var heapSize, stackSize int64
	if memStats.HeapInuse > math.MaxInt64 {
		if pm.observer != nil && pm.observer.DebugObserver != nil {
			pm.observer.DebugObserver.LogDetail("memory_overflow", fmt.Sprintf("heap size too large for int64: %d", memStats.HeapInuse))
		}
		heapSize = math.MaxInt64
	} else {
		heapSize = int64(memStats.HeapInuse)
	}

	if memStats.StackInuse > math.MaxInt64 {
		if pm.observer != nil && pm.observer.DebugObserver != nil {
			pm.observer.DebugObserver.LogDetail("memory_overflow", fmt.Sprintf("stack size too large for int64: %d", memStats.StackInuse))
		}
		stackSize = math.MaxInt64
	} else {
		stackSize = int64(memStats.StackInuse)
	}

	goroutines := int64(runtime.NumGoroutine())

	pm.metrics.UpdateMemoryUsage(heapSize, stackSize, goroutines)

	// Check memory alerts
	if pm.config.EnableAlerts {
		pm.checkMemoryAlerts(heapSize, stackSize, goroutines)
	}

	if pm.config.EnableDetailedLogging && pm.observer != nil && pm.observer.DebugObserver != nil {
		pm.observer.DebugObserver.LogDetail("memory_monitoring", fmt.Sprintf(
			"Heap: %d MB, Stack: %d MB, Goroutines: %d",
			heapSize/1024/1024, stackSize/1024/1024, goroutines))
	}
}

// reportMetrics reports performance metrics periodically
func (pm *PerformanceMonitor) reportMetrics() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.config.MetricsReportingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.logPerformanceReport()
		}
	}
}

// logPerformanceReport logs a comprehensive performance report
func (pm *PerformanceMonitor) logPerformanceReport() {
	if pm.observer == nil {
		return
	}

	summary := pm.GetPerformanceSummary()

	pm.observer.LogOperation(observability.StandardObservabilityData{
		Component: "performance_monitor",
		Operation: "performance_report",
		Success:   true,
		Metadata:  summary,
	})

	if pm.observer.DebugObserver != nil {
		pm.observer.DebugObserver.LogDetail("performance_report", fmt.Sprintf(
			"Content Routing: %d ops (%.1f%% success), Dual-Path: Doc=%d/Meta=%d validations",
			summary["content_routing"].(map[string]interface{})["total_operations"],
			summary["content_routing"].(map[string]interface{})["success_rate"].(float64)*100,
			summary["dual_path_validation"].(map[string]interface{})["document_path"].(map[string]interface{})["total_validations"],
			summary["dual_path_validation"].(map[string]interface{})["metadata_path"].(map[string]interface{})["total_validations"]))
	}
}

// monitorAlerts monitors for performance alerts
func (pm *PerformanceMonitor) monitorAlerts() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.config.AlertCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.checkAllAlerts()
		}
	}
}

// checkAllAlerts checks all alert conditions
func (pm *PerformanceMonitor) checkAllAlerts() {
	pm.checkBenchmarkPerformanceAlerts()
	pm.checkOverallPerformanceAlerts()
}

// checkRoutingPerformanceAlert checks for routing performance issues
func (pm *PerformanceMonitor) checkRoutingPerformanceAlert(duration time.Duration, success bool, errorType string) {
	if duration.Milliseconds() > pm.alertThresholds.MaxRoutingTimeMs {
		alert := Alert{
			Type:        "routing_performance",
			Severity:    "warning",
			Message:     fmt.Sprintf("Content routing took %d ms, exceeding threshold of %d ms", duration.Milliseconds(), pm.alertThresholds.MaxRoutingTimeMs),
			Timestamp:   time.Now(),
			Threshold:   pm.alertThresholds.MaxRoutingTimeMs,
			ActualValue: duration.Milliseconds(),
			Metrics: map[string]interface{}{
				"duration_ms": duration.Milliseconds(),
				"success":     success,
				"error_type":  errorType,
			},
		}
		pm.triggerAlert(alert)
	}
}

// checkValidationPerformanceAlert checks for validation performance issues
func (pm *PerformanceMonitor) checkValidationPerformanceAlert(isMetadataPath bool, duration time.Duration, success bool) {
	if duration.Milliseconds() > pm.alertThresholds.MaxValidationTimeMs {
		pathType := "document"
		if isMetadataPath {
			pathType = "metadata"
		}

		alert := Alert{
			Type:        "validation_performance",
			Severity:    "warning",
			Message:     fmt.Sprintf("%s validation took %d ms, exceeding threshold of %d ms", pathType, duration.Milliseconds(), pm.alertThresholds.MaxValidationTimeMs),
			Timestamp:   time.Now(),
			Threshold:   pm.alertThresholds.MaxValidationTimeMs,
			ActualValue: duration.Milliseconds(),
			Metrics: map[string]interface{}{
				"path_type":   pathType,
				"duration_ms": duration.Milliseconds(),
				"success":     success,
			},
		}
		pm.triggerAlert(alert)
	}
}

// checkMemoryAlerts checks for memory usage issues
func (pm *PerformanceMonitor) checkMemoryAlerts(heapSize, stackSize, goroutines int64) {
	heapSizeMB := heapSize / 1024 / 1024

	if heapSizeMB > pm.alertThresholds.MaxHeapSizeMB {
		alert := Alert{
			Type:        "memory_usage",
			Severity:    "critical",
			Message:     fmt.Sprintf("Heap size %d MB exceeds threshold of %d MB", heapSizeMB, pm.alertThresholds.MaxHeapSizeMB),
			Timestamp:   time.Now(),
			Threshold:   pm.alertThresholds.MaxHeapSizeMB,
			ActualValue: heapSizeMB,
			Metrics: map[string]interface{}{
				"heap_size_mb": heapSizeMB,
				"stack_size":   stackSize,
				"goroutines":   goroutines,
			},
		}
		pm.triggerAlert(alert)
	}

	if goroutines > pm.alertThresholds.MaxGoroutines {
		alert := Alert{
			Type:        "goroutine_count",
			Severity:    "warning",
			Message:     fmt.Sprintf("Goroutine count %d exceeds threshold of %d", goroutines, pm.alertThresholds.MaxGoroutines),
			Timestamp:   time.Now(),
			Threshold:   pm.alertThresholds.MaxGoroutines,
			ActualValue: goroutines,
			Metrics: map[string]interface{}{
				"goroutines":   goroutines,
				"heap_size_mb": heapSizeMB,
			},
		}
		pm.triggerAlert(alert)
	}
}

// checkBenchmarkPerformanceAlerts checks for benchmark performance issues
func (pm *PerformanceMonitor) checkBenchmarkPerformanceAlerts() {
	pm.metrics.BenchmarkMetrics.mu.RLock()
	improvement := pm.metrics.BenchmarkMetrics.PerformanceImprovement
	pm.metrics.BenchmarkMetrics.mu.RUnlock()

	if improvement < pm.alertThresholds.MinPerformanceImprovement {
		alert := Alert{
			Type:        "benchmark_performance",
			Severity:    "warning",
			Message:     fmt.Sprintf("Performance improvement %.2f%% is below threshold of %.2f%%", improvement*100, pm.alertThresholds.MinPerformanceImprovement*100),
			Timestamp:   time.Now(),
			Threshold:   pm.alertThresholds.MinPerformanceImprovement,
			ActualValue: improvement,
			Metrics: map[string]interface{}{
				"performance_improvement": improvement,
			},
		}
		pm.triggerAlert(alert)
	}
}

// checkFallbackRateAlert checks for excessive fallback usage
func (pm *PerformanceMonitor) checkFallbackRateAlert() {
	contentMetrics := pm.metrics.GetContentRoutingMetrics()
	fallbackRate := pm.calculateFallbackRate(contentMetrics.FallbackActivations, contentMetrics.TotalRoutingOperations)

	if fallbackRate > pm.alertThresholds.MaxFallbackRate {
		alert := Alert{
			Type:        "fallback_rate",
			Severity:    "critical",
			Message:     fmt.Sprintf("Fallback rate %.2f%% exceeds threshold of %.2f%%", fallbackRate*100, pm.alertThresholds.MaxFallbackRate*100),
			Timestamp:   time.Now(),
			Threshold:   pm.alertThresholds.MaxFallbackRate,
			ActualValue: fallbackRate,
			Metrics: map[string]interface{}{
				"fallback_rate":        fallbackRate,
				"fallback_activations": contentMetrics.FallbackActivations,
				"total_operations":     contentMetrics.TotalRoutingOperations,
			},
		}
		pm.triggerAlert(alert)
	}
}

// checkOverallPerformanceAlerts checks for overall performance degradation
func (pm *PerformanceMonitor) checkOverallPerformanceAlerts() {
	// This would compare against baseline performance metrics
	// Implementation depends on having baseline data
}

// triggerAlert triggers a performance alert
func (pm *PerformanceMonitor) triggerAlert(alert Alert) {
	if pm.observer != nil {
		pm.observer.LogOperation(observability.StandardObservabilityData{
			Component: "performance_monitor",
			Operation: "alert_triggered",
			Success:   true,
			Metadata: map[string]interface{}{
				"alert_type":    alert.Type,
				"severity":      alert.Severity,
				"message":       alert.Message,
				"threshold":     alert.Threshold,
				"actual_value":  alert.ActualValue,
				"alert_metrics": alert.Metrics,
			},
		})

		if pm.observer.DebugObserver != nil {
			pm.observer.DebugObserver.LogDetail("performance_alert", fmt.Sprintf(
				"[%s] %s: %s", alert.Severity, alert.Type, alert.Message))
		}
	}
}

// Helper functions

func (pm *PerformanceMonitor) calculateSuccessRate(successful, total int64) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(successful) / float64(total)
}

func (pm *PerformanceMonitor) calculateFallbackRate(fallbacks, total int64) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(fallbacks) / float64(total)
}

// Default configurations

func getDefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		MemoryMonitoringInterval: 30 * time.Second,
		MetricsReportingInterval: 5 * time.Minute,
		AlertCheckInterval:       1 * time.Minute,
		EnableMemoryMonitoring:   true,
		EnableAlerts:             true,
		EnableBenchmarking:       true,
		EnableDetailedLogging:    false,
		EnableLegacyComparison:   true,
		BenchmarkSampleSize:      100,
	}
}

func getDefaultAlertThresholds() *AlertThresholds {
	return &AlertThresholds{
		MaxHeapSizeMB:             512,
		MaxGoroutines:             1000,
		MaxMemoryGrowthRate:       0.5,
		MaxRoutingTimeMs:          100,
		MaxValidationTimeMs:       500,
		MinPerformanceImprovement: 0.1,
		MaxRoutingErrorRate:       0.05,
		MaxValidationErrorRate:    0.1,
		MaxFallbackRate:           0.1,
		MinParallelEfficiency:     0.8,
		MaxPerformanceDegradation: 0.05,
	}
}
