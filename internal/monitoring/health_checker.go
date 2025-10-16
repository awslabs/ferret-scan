// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ferret-scan/internal/observability"
	"ferret-scan/internal/performance"
)

// HealthChecker provides health checks for both document and metadata validation paths
type HealthChecker struct {
	performanceMonitor *performance.PerformanceMonitor
	observer           *observability.StandardObserver

	// Health check configuration
	config *HealthCheckConfig

	// Health status tracking
	documentPathHealth *PathHealthStatus
	metadataPathHealth *PathHealthStatus

	// Thread safety
	mu sync.RWMutex
}

// HealthCheckConfig configures health check behavior
type HealthCheckConfig struct {
	// Check intervals
	HealthCheckInterval time.Duration
	PathTestTimeout     time.Duration

	// Health thresholds
	MaxFailureRate      float64
	MaxResponseTime     time.Duration
	MinSuccessfulChecks int

	// Feature flags
	EnableContinuousChecks bool
	EnablePathTesting      bool
	EnableDetailedLogging  bool
}

// PathHealthStatus tracks health status for validation paths
type PathHealthStatus struct {
	PathName            string
	IsHealthy           bool
	LastCheckTime       time.Time
	LastError           error
	SuccessfulChecks    int
	FailedChecks        int
	AverageResponseTime time.Duration

	// Recent check history
	RecentChecks []HealthCheckResult

	// Thread safety
	mu sync.RWMutex
}

// HealthCheckResult represents a single health check result
type HealthCheckResult struct {
	Timestamp    time.Time
	Success      bool
	ResponseTime time.Duration
	Error        error
	Details      map[string]interface{}
}

// OverallHealthStatus represents the overall system health
type OverallHealthStatus struct {
	IsHealthy           bool
	DocumentPathHealthy bool
	MetadataPathHealthy bool
	LastCheckTime       time.Time
	HealthScore         float64
	Issues              []string
	Summary             map[string]interface{}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(performanceMonitor *performance.PerformanceMonitor, observer *observability.StandardObserver, config *HealthCheckConfig) *HealthChecker {
	if config == nil {
		config = getDefaultHealthCheckConfig()
	}

	return &HealthChecker{
		performanceMonitor: performanceMonitor,
		observer:           observer,
		config:             config,
		documentPathHealth: &PathHealthStatus{
			PathName:     "document_validation",
			RecentChecks: make([]HealthCheckResult, 0, 10),
		},
		metadataPathHealth: &PathHealthStatus{
			PathName:     "metadata_validation",
			RecentChecks: make([]HealthCheckResult, 0, 10),
		},
	}
}

// CheckDocumentPathHealth performs health check for document validation path
func (hc *HealthChecker) CheckDocumentPathHealth(ctx context.Context) HealthCheckResult {
	start := time.Now()

	result := HealthCheckResult{
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	// Create timeout context
	checkCtx, cancel := context.WithTimeout(ctx, hc.config.PathTestTimeout)
	defer cancel()

	// Perform health check
	err := hc.performDocumentPathCheck(checkCtx, result.Details)

	result.ResponseTime = time.Since(start)
	result.Success = err == nil
	result.Error = err

	// Update path health status
	hc.updatePathHealth(hc.documentPathHealth, result)

	// Log result
	if hc.observer != nil {
		hc.observer.LogOperation(observability.StandardObservabilityData{
			Component:  "health_checker",
			Operation:  "document_path_check",
			Success:    result.Success,
			DurationMs: result.ResponseTime.Milliseconds(),
			Error:      hc.getErrorString(err),
			Metadata:   result.Details,
		})
	}

	return result
}

// CheckMetadataPathHealth performs health check for metadata validation path
func (hc *HealthChecker) CheckMetadataPathHealth(ctx context.Context) HealthCheckResult {
	start := time.Now()

	result := HealthCheckResult{
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	// Create timeout context
	checkCtx, cancel := context.WithTimeout(ctx, hc.config.PathTestTimeout)
	defer cancel()

	// Perform health check
	err := hc.performMetadataPathCheck(checkCtx, result.Details)

	result.ResponseTime = time.Since(start)
	result.Success = err == nil
	result.Error = err

	// Update path health status
	hc.updatePathHealth(hc.metadataPathHealth, result)

	// Log result
	if hc.observer != nil {
		hc.observer.LogOperation(observability.StandardObservabilityData{
			Component:  "health_checker",
			Operation:  "metadata_path_check",
			Success:    result.Success,
			DurationMs: result.ResponseTime.Milliseconds(),
			Error:      hc.getErrorString(err),
			Metadata:   result.Details,
		})
	}

	return result
}

// CheckOverallHealth performs comprehensive health check of both paths
func (hc *HealthChecker) CheckOverallHealth(ctx context.Context) OverallHealthStatus {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Check both paths
	docResult := hc.CheckDocumentPathHealth(ctx)
	metaResult := hc.CheckMetadataPathHealth(ctx)

	// Calculate overall health
	status := OverallHealthStatus{
		DocumentPathHealthy: docResult.Success,
		MetadataPathHealthy: metaResult.Success,
		LastCheckTime:       time.Now(),
		Issues:              make([]string, 0),
		Summary:             make(map[string]interface{}),
	}

	// Determine overall health
	status.IsHealthy = status.DocumentPathHealthy && status.MetadataPathHealthy

	// Calculate health score (0.0 to 1.0)
	score := 0.0
	if status.DocumentPathHealthy {
		score += 0.5
	}
	if status.MetadataPathHealthy {
		score += 0.5
	}
	status.HealthScore = score

	// Collect issues
	if !status.DocumentPathHealthy {
		status.Issues = append(status.Issues, fmt.Sprintf("Document validation path unhealthy: %v", docResult.Error))
	}
	if !status.MetadataPathHealthy {
		status.Issues = append(status.Issues, fmt.Sprintf("Metadata validation path unhealthy: %v", metaResult.Error))
	}

	// Add performance metrics to summary
	if hc.performanceMonitor != nil {
		perfSummary := hc.performanceMonitor.GetPerformanceSummary()
		status.Summary["performance"] = perfSummary
	}

	// Add path health details
	status.Summary["document_path"] = hc.getPathHealthSummary(hc.documentPathHealth)
	status.Summary["metadata_path"] = hc.getPathHealthSummary(hc.metadataPathHealth)

	// Log overall health status
	if hc.observer != nil {
		hc.observer.LogOperation(observability.StandardObservabilityData{
			Component: "health_checker",
			Operation: "overall_health_check",
			Success:   status.IsHealthy,
			Metadata: map[string]interface{}{
				"health_score":          status.HealthScore,
				"document_path_healthy": status.DocumentPathHealthy,
				"metadata_path_healthy": status.MetadataPathHealthy,
				"issues_count":          len(status.Issues),
				"issues":                status.Issues,
			},
		})
	}

	return status
}

// performDocumentPathCheck performs the actual document path health check
func (hc *HealthChecker) performDocumentPathCheck(ctx context.Context, details map[string]interface{}) error {
	// Check if performance monitor is available
	if hc.performanceMonitor == nil {
		return fmt.Errorf("performance monitor not available")
	}

	// Get document path metrics
	metrics := hc.performanceMonitor.GetMetrics()
	if metrics == nil {
		return fmt.Errorf("unable to retrieve performance metrics")
	}

	dualPathMetrics := metrics.GetDualPathValidationMetrics()
	docMetrics := dualPathMetrics.DocumentPathMetrics

	// Check if document path has processed any validations
	if docMetrics.TotalValidations == 0 {
		details["status"] = "no_validations"
		details["message"] = "Document path has not processed any validations yet"
		return nil // This is not necessarily an error for a new system
	}

	// Calculate success rate
	successRate := float64(docMetrics.SuccessfulValidations) / float64(docMetrics.TotalValidations)
	details["success_rate"] = successRate
	details["total_validations"] = docMetrics.TotalValidations
	details["successful_validations"] = docMetrics.SuccessfulValidations
	details["average_time_ms"] = docMetrics.AverageValidationTime.Milliseconds()

	// Check if success rate is acceptable
	if successRate < (1.0 - hc.config.MaxFailureRate) {
		return fmt.Errorf("document path success rate %.2f%% below threshold %.2f%%",
			successRate*100, (1.0-hc.config.MaxFailureRate)*100)
	}

	// Check if average response time is acceptable
	if docMetrics.AverageValidationTime > hc.config.MaxResponseTime {
		return fmt.Errorf("document path average response time %v exceeds threshold %v",
			docMetrics.AverageValidationTime, hc.config.MaxResponseTime)
	}

	details["status"] = "healthy"
	return nil
}

// performMetadataPathCheck performs the actual metadata path health check
func (hc *HealthChecker) performMetadataPathCheck(ctx context.Context, details map[string]interface{}) error {
	// Check if performance monitor is available
	if hc.performanceMonitor == nil {
		return fmt.Errorf("performance monitor not available")
	}

	// Get metadata path metrics
	metrics := hc.performanceMonitor.GetMetrics()
	if metrics == nil {
		return fmt.Errorf("unable to retrieve performance metrics")
	}

	dualPathMetrics := metrics.GetDualPathValidationMetrics()
	metaMetrics := dualPathMetrics.MetadataPathMetrics

	// Check if metadata path has processed any validations
	if metaMetrics.TotalValidations == 0 {
		details["status"] = "no_validations"
		details["message"] = "Metadata path has not processed any validations yet"
		return nil // This is not necessarily an error for a new system
	}

	// Calculate success rate
	successRate := float64(metaMetrics.SuccessfulValidations) / float64(metaMetrics.TotalValidations)
	details["success_rate"] = successRate
	details["total_validations"] = metaMetrics.TotalValidations
	details["successful_validations"] = metaMetrics.SuccessfulValidations
	details["average_time_ms"] = metaMetrics.AverageValidationTime.Milliseconds()
	details["average_confidence"] = metaMetrics.AverageConfidence

	// Check if success rate is acceptable
	if successRate < (1.0 - hc.config.MaxFailureRate) {
		return fmt.Errorf("metadata path success rate %.2f%% below threshold %.2f%%",
			successRate*100, (1.0-hc.config.MaxFailureRate)*100)
	}

	// Check if average response time is acceptable
	if metaMetrics.AverageValidationTime > hc.config.MaxResponseTime {
		return fmt.Errorf("metadata path average response time %v exceeds threshold %v",
			metaMetrics.AverageValidationTime, hc.config.MaxResponseTime)
	}

	details["status"] = "healthy"
	return nil
}

// updatePathHealth updates the health status for a validation path
func (hc *HealthChecker) updatePathHealth(pathHealth *PathHealthStatus, result HealthCheckResult) {
	pathHealth.mu.Lock()
	defer pathHealth.mu.Unlock()

	pathHealth.LastCheckTime = result.Timestamp
	pathHealth.LastError = result.Error

	if result.Success {
		pathHealth.SuccessfulChecks++
	} else {
		pathHealth.FailedChecks++
	}

	// Determine health based on recent success rate
	totalChecks := pathHealth.SuccessfulChecks + pathHealth.FailedChecks
	if totalChecks >= hc.config.MinSuccessfulChecks {
		successRate := float64(pathHealth.SuccessfulChecks) / float64(totalChecks)
		pathHealth.IsHealthy = successRate >= (1.0 - hc.config.MaxFailureRate)
	} else {
		// Not enough checks yet, consider healthy if we have any successful checks
		pathHealth.IsHealthy = pathHealth.SuccessfulChecks > 0 || totalChecks == 0
	}

	// Update average response time
	if pathHealth.SuccessfulChecks+pathHealth.FailedChecks == 1 {
		pathHealth.AverageResponseTime = result.ResponseTime
	} else {
		total := pathHealth.SuccessfulChecks + pathHealth.FailedChecks
		pathHealth.AverageResponseTime = (pathHealth.AverageResponseTime*time.Duration(total-1) + result.ResponseTime) / time.Duration(total)
	}

	// Add to recent checks (keep last 10)
	pathHealth.RecentChecks = append(pathHealth.RecentChecks, result)
	if len(pathHealth.RecentChecks) > 10 {
		pathHealth.RecentChecks = pathHealth.RecentChecks[1:]
	}
}

// getPathHealthSummary returns a summary of path health status
func (hc *HealthChecker) getPathHealthSummary(pathHealth *PathHealthStatus) map[string]interface{} {
	pathHealth.mu.RLock()
	defer pathHealth.mu.RUnlock()

	totalChecks := pathHealth.SuccessfulChecks + pathHealth.FailedChecks
	successRate := 0.0
	if totalChecks > 0 {
		successRate = float64(pathHealth.SuccessfulChecks) / float64(totalChecks)
	}

	return map[string]interface{}{
		"is_healthy":            pathHealth.IsHealthy,
		"last_check_time":       pathHealth.LastCheckTime,
		"successful_checks":     pathHealth.SuccessfulChecks,
		"failed_checks":         pathHealth.FailedChecks,
		"success_rate":          successRate,
		"average_response_time": pathHealth.AverageResponseTime.Milliseconds(),
		"last_error":            hc.getErrorString(pathHealth.LastError),
		"recent_checks_count":   len(pathHealth.RecentChecks),
	}
}

// GetDocumentPathHealth returns current document path health status
func (hc *HealthChecker) GetDocumentPathHealth() PathHealthStatus {
	hc.documentPathHealth.mu.RLock()
	defer hc.documentPathHealth.mu.RUnlock()

	// Return a copy without the mutex to avoid race conditions
	return PathHealthStatus{
		PathName:            hc.documentPathHealth.PathName,
		IsHealthy:           hc.documentPathHealth.IsHealthy,
		LastCheckTime:       hc.documentPathHealth.LastCheckTime,
		LastError:           hc.documentPathHealth.LastError,
		SuccessfulChecks:    hc.documentPathHealth.SuccessfulChecks,
		FailedChecks:        hc.documentPathHealth.FailedChecks,
		AverageResponseTime: hc.documentPathHealth.AverageResponseTime,
		RecentChecks:        append([]HealthCheckResult(nil), hc.documentPathHealth.RecentChecks...),
	}
}

// GetMetadataPathHealth returns current metadata path health status
func (hc *HealthChecker) GetMetadataPathHealth() PathHealthStatus {
	hc.metadataPathHealth.mu.RLock()
	defer hc.metadataPathHealth.mu.RUnlock()

	// Return a copy without the mutex to avoid race conditions
	return PathHealthStatus{
		PathName:            hc.metadataPathHealth.PathName,
		IsHealthy:           hc.metadataPathHealth.IsHealthy,
		LastCheckTime:       hc.metadataPathHealth.LastCheckTime,
		LastError:           hc.metadataPathHealth.LastError,
		SuccessfulChecks:    hc.metadataPathHealth.SuccessfulChecks,
		FailedChecks:        hc.metadataPathHealth.FailedChecks,
		AverageResponseTime: hc.metadataPathHealth.AverageResponseTime,
		RecentChecks:        append([]HealthCheckResult(nil), hc.metadataPathHealth.RecentChecks...),
	}
}

// getErrorString safely converts error to string
func (hc *HealthChecker) getErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// getDefaultHealthCheckConfig returns default health check configuration
func getDefaultHealthCheckConfig() *HealthCheckConfig {
	return &HealthCheckConfig{
		HealthCheckInterval:    30 * time.Second,
		PathTestTimeout:        10 * time.Second,
		MaxFailureRate:         0.1, // 10% failure rate threshold
		MaxResponseTime:        5 * time.Second,
		MinSuccessfulChecks:    3,
		EnableContinuousChecks: true,
		EnablePathTesting:      true,
		EnableDetailedLogging:  false,
	}
}
