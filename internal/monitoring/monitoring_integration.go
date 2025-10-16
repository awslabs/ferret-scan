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

// MonitoringIntegration provides a unified interface for all monitoring components
type MonitoringIntegration struct {
	// Core components
	performanceMonitor *performance.PerformanceMonitor
	healthChecker      *HealthChecker
	enhancedAlerting   *EnhancedAlerting
	debugLogger        *DebugLogger
	observer           *observability.StandardObserver

	// Configuration
	config *IntegrationConfig

	// Background monitoring
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	monitoring bool

	// Thread safety
	mu sync.RWMutex
}

// IntegrationConfig configures the monitoring integration
type IntegrationConfig struct {
	// Component enablement
	EnablePerformanceMonitoring bool
	EnableHealthChecks          bool
	EnableEnhancedAlerting      bool
	EnableDebugLogging          bool

	// Monitoring intervals
	HealthCheckInterval    time.Duration
	AlertCheckInterval     time.Duration
	BaselineUpdateInterval time.Duration
	MetricsReportInterval  time.Duration

	// Integration features
	EnableCrossComponentAlerts bool
	EnableAutomaticBaseline    bool
	EnableHealthBasedAlerting  bool
	EnablePerformanceBaseline  bool

	// Reporting configuration
	EnablePeriodicReports bool
	ReportInterval        time.Duration
	ReportFormat          string // "json", "text", "summary"
}

// MonitoringStatus represents the overall monitoring system status
type MonitoringStatus struct {
	IsHealthy          bool
	ComponentStatuses  map[string]bool
	LastHealthCheck    time.Time
	ActiveAlerts       int
	PerformanceScore   float64
	SystemHealth       OverallHealthStatus
	RecentIssues       []string
	MonitoringUptime   time.Duration
	LastBaselineUpdate time.Time
}

// NewMonitoringIntegration creates a new monitoring integration
func NewMonitoringIntegration(observer *observability.StandardObserver, config *IntegrationConfig) *MonitoringIntegration {
	if config == nil {
		config = getDefaultIntegrationConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create performance monitor
	var performanceMonitor *performance.PerformanceMonitor
	if config.EnablePerformanceMonitoring {
		monitorConfig := &performance.MonitorConfig{
			MemoryMonitoringInterval: 30 * time.Second,
			MetricsReportingInterval: config.MetricsReportInterval,
			AlertCheckInterval:       config.AlertCheckInterval,
			EnableMemoryMonitoring:   true,
			EnableAlerts:             true,
			EnableBenchmarking:       true,
			EnableDetailedLogging:    false,
		}
		performanceMonitor = performance.NewPerformanceMonitor(observer, monitorConfig)
	}

	// Create health checker
	var healthChecker *HealthChecker
	if config.EnableHealthChecks {
		healthConfig := &HealthCheckConfig{
			HealthCheckInterval:    config.HealthCheckInterval,
			PathTestTimeout:        10 * time.Second,
			MaxFailureRate:         0.1,
			MaxResponseTime:        5 * time.Second,
			MinSuccessfulChecks:    3,
			EnableContinuousChecks: true,
			EnablePathTesting:      true,
			EnableDetailedLogging:  false,
		}
		healthChecker = NewHealthChecker(performanceMonitor, observer, healthConfig)
	}

	// Create enhanced alerting
	var enhancedAlerting *EnhancedAlerting
	if config.EnableEnhancedAlerting {
		alertConfig := &AlertingConfig{
			MaxAccuracyDegradation:    0.1,
			MaxConfidenceDegradation:  0.15,
			MaxMatchCountVariation:    0.2,
			MaxPerformanceDegradation: 0.25,
			MaxMemoryIncrease:         0.5,
			AlertCooldownPeriod:       5 * time.Minute,
			BaselineUpdateInterval:    config.BaselineUpdateInterval,
			AccuracyCheckInterval:     config.AlertCheckInterval,
			WarningThreshold:          0.05,
			CriticalThreshold:         0.15,
			EnableAccuracyAlerting:    true,
			EnablePerformanceAlerting: true,
			EnableMemoryAlerting:      true,
			EnableBaselineUpdates:     config.EnableAutomaticBaseline,
		}
		enhancedAlerting = NewEnhancedAlerting(performanceMonitor, observer, alertConfig)
	}

	// Create debug logger
	var debugLogger *DebugLogger
	if config.EnableDebugLogging {
		debugConfig := &DebugLoggingConfig{
			EnableRoutingDecisionLogging:   true,
			EnableValidationOutcomeLogging: true,
			EnableDetailedContentLogging:   false,
			EnablePerformanceLogging:       true,
			LogLevel:                       "info",
			MaxDecisionHistory:             1000,
			MaxOutcomeHistory:              1000,
			MaxContentLength:               200,
			LogSensitiveContent:            false,
		}
		debugLogger = NewDebugLogger(observer, debugConfig)
	}

	return &MonitoringIntegration{
		performanceMonitor: performanceMonitor,
		healthChecker:      healthChecker,
		enhancedAlerting:   enhancedAlerting,
		debugLogger:        debugLogger,
		observer:           observer,
		config:             config,
		ctx:                ctx,
		cancel:             cancel,
	}
}

// StartMonitoring starts all monitoring components
func (mi *MonitoringIntegration) StartMonitoring() error {
	mi.mu.Lock()
	defer mi.mu.Unlock()

	if mi.monitoring {
		return fmt.Errorf("monitoring integration is already running")
	}

	mi.monitoring = true

	// Start performance monitoring
	if mi.performanceMonitor != nil {
		if err := mi.performanceMonitor.StartMonitoring(); err != nil {
			return fmt.Errorf("failed to start performance monitoring: %w", err)
		}
	}

	// Start integrated monitoring loops
	if mi.config.EnableHealthChecks {
		mi.wg.Add(1)
		go mi.healthCheckLoop()
	}

	if mi.config.EnableEnhancedAlerting {
		mi.wg.Add(1)
		go mi.alertingLoop()
	}

	if mi.config.EnableAutomaticBaseline {
		mi.wg.Add(1)
		go mi.baselineUpdateLoop()
	}

	if mi.config.EnablePeriodicReports {
		mi.wg.Add(1)
		go mi.reportingLoop()
	}

	// Log startup
	if mi.observer != nil {
		mi.observer.LogOperation(observability.StandardObservabilityData{
			Component: "monitoring_integration",
			Operation: "startup",
			Success:   true,
			Metadata: map[string]interface{}{
				"performance_monitoring": mi.config.EnablePerformanceMonitoring,
				"health_checks":          mi.config.EnableHealthChecks,
				"enhanced_alerting":      mi.config.EnableEnhancedAlerting,
				"debug_logging":          mi.config.EnableDebugLogging,
			},
		})
	}

	return nil
}

// StopMonitoring stops all monitoring components
func (mi *MonitoringIntegration) StopMonitoring() {
	mi.mu.Lock()
	defer mi.mu.Unlock()

	if !mi.monitoring {
		return
	}

	// Stop performance monitoring
	if mi.performanceMonitor != nil {
		mi.performanceMonitor.StopMonitoring()
	}

	// Stop integrated monitoring loops
	mi.cancel()
	mi.wg.Wait()
	mi.monitoring = false

	// Log shutdown
	if mi.observer != nil {
		mi.observer.LogOperation(observability.StandardObservabilityData{
			Component: "monitoring_integration",
			Operation: "shutdown",
			Success:   true,
		})
	}
}

// RecordContentRoutingOperation records a content routing operation across all components
func (mi *MonitoringIntegration) RecordContentRoutingOperation(filePath string, contentLength int, preprocessorTypes []string, routingDecision string, reasoning string, duration time.Duration, success bool, errorType string) {
	// Record in performance monitor
	if mi.performanceMonitor != nil {
		mi.performanceMonitor.RecordContentRoutingOperation(duration, success, errorType)
	}

	// Record in debug logger
	if mi.debugLogger != nil {
		decision := RoutingDecision{
			Timestamp:         time.Now(),
			FilePath:          filePath,
			ContentLength:     contentLength,
			PreprocessorTypes: preprocessorTypes,
			RoutingDecision:   routingDecision,
			Reasoning:         reasoning,
			Success:           success,
			Error:             errorType,
			ProcessingTime:    duration,
			Metadata: map[string]interface{}{
				"content_length":     contentLength,
				"preprocessor_count": len(preprocessorTypes),
			},
		}
		mi.debugLogger.LogRoutingDecision(decision)
	}
}

// RecordValidationPathOperation records a validation path operation across all components
func (mi *MonitoringIntegration) RecordValidationPathOperation(filePath string, isMetadataPath bool, validatorType string, matchCount int, avgConfidence float64, duration time.Duration, success bool, matches []ValidationMatch, contextBoosts int, contextPenalties int) {
	// Record in performance monitor
	if mi.performanceMonitor != nil {
		mi.performanceMonitor.RecordValidationPathOperation(isMetadataPath, duration, success, matchCount, avgConfidence)
	}

	// Record in debug logger
	if mi.debugLogger != nil {
		pathType := "document"
		if isMetadataPath {
			pathType = "metadata"
		}

		outcome := ValidationOutcome{
			Timestamp:         time.Now(),
			FilePath:          filePath,
			ValidationPath:    pathType,
			ValidatorType:     validatorType,
			MatchCount:        matchCount,
			AverageConfidence: avgConfidence,
			ProcessingTime:    duration,
			Success:           success,
			Matches:           matches,
			ContextBoosts:     contextBoosts,
			ContextPenalties:  contextPenalties,
			Metadata: map[string]interface{}{
				"validator_type":    validatorType,
				"context_boosts":    contextBoosts,
				"context_penalties": contextPenalties,
			},
		}
		mi.debugLogger.LogValidationOutcome(outcome)
	}
}

// RecordFallbackActivation records fallback activation across all components
func (mi *MonitoringIntegration) RecordFallbackActivation(filePath string, reason string, originalError error, fallbackSuccess bool, fallbackTime time.Duration) {
	// Record in performance monitor
	if mi.performanceMonitor != nil {
		mi.performanceMonitor.RecordFallbackActivation(reason)
	}

	// Record in debug logger
	if mi.debugLogger != nil {
		mi.debugLogger.LogFallbackActivation(filePath, reason, originalError, fallbackSuccess, fallbackTime)
	}
}

// GetMonitoringStatus returns the current monitoring system status
func (mi *MonitoringIntegration) GetMonitoringStatus() MonitoringStatus {
	mi.mu.RLock()
	defer mi.mu.RUnlock()

	status := MonitoringStatus{
		ComponentStatuses: make(map[string]bool),
		RecentIssues:      make([]string, 0),
		LastHealthCheck:   time.Now(),
	}

	// Check component statuses
	status.ComponentStatuses["performance_monitor"] = mi.performanceMonitor != nil
	status.ComponentStatuses["health_checker"] = mi.healthChecker != nil
	status.ComponentStatuses["enhanced_alerting"] = mi.enhancedAlerting != nil
	status.ComponentStatuses["debug_logger"] = mi.debugLogger != nil

	// Get overall health if health checker is available
	if mi.healthChecker != nil {
		healthStatus := mi.healthChecker.CheckOverallHealth(mi.ctx)
		status.SystemHealth = healthStatus
		status.IsHealthy = healthStatus.IsHealthy
		status.PerformanceScore = healthStatus.HealthScore
		status.RecentIssues = append(status.RecentIssues, healthStatus.Issues...)
	} else {
		status.IsHealthy = true
		status.PerformanceScore = 1.0
	}

	// Get active alerts count
	if mi.enhancedAlerting != nil {
		activeAlerts := mi.enhancedAlerting.GetActiveAlerts()
		status.ActiveAlerts = len(activeAlerts)

		// Add alert messages to recent issues
		for _, alert := range activeAlerts {
			status.RecentIssues = append(status.RecentIssues, fmt.Sprintf("[%s] %s", alert.Severity, alert.Message))
		}
	}

	// Calculate monitoring uptime (simplified)
	if mi.monitoring {
		status.MonitoringUptime = time.Since(time.Now().Add(-1 * time.Hour)) // Placeholder
	}

	return status
}

// GetComprehensiveReport returns a comprehensive monitoring report
func (mi *MonitoringIntegration) GetComprehensiveReport() map[string]interface{} {
	report := make(map[string]interface{})

	// Add monitoring status
	report["monitoring_status"] = mi.GetMonitoringStatus()

	// Add performance metrics if available
	if mi.performanceMonitor != nil {
		report["performance_summary"] = mi.performanceMonitor.GetPerformanceSummary()
	}

	// Add health check results if available
	if mi.healthChecker != nil {
		report["health_status"] = mi.healthChecker.CheckOverallHealth(mi.ctx)
	}

	// Add alert information if available
	if mi.enhancedAlerting != nil {
		report["active_alerts"] = mi.enhancedAlerting.GetActiveAlerts()
		report["alert_history"] = mi.enhancedAlerting.GetAlertHistory(10)
	}

	// Add debug information if available
	if mi.debugLogger != nil {
		report["debug_summary"] = mi.debugLogger.GetDebugSummary()
	}

	// Add configuration information
	report["configuration"] = map[string]interface{}{
		"performance_monitoring": mi.config.EnablePerformanceMonitoring,
		"health_checks":          mi.config.EnableHealthChecks,
		"enhanced_alerting":      mi.config.EnableEnhancedAlerting,
		"debug_logging":          mi.config.EnableDebugLogging,
		"health_check_interval":  mi.config.HealthCheckInterval.String(),
		"alert_check_interval":   mi.config.AlertCheckInterval.String(),
	}

	return report
}

// Background monitoring loops

func (mi *MonitoringIntegration) healthCheckLoop() {
	defer mi.wg.Done()

	ticker := time.NewTicker(mi.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mi.ctx.Done():
			return
		case <-ticker.C:
			if mi.healthChecker != nil {
				healthStatus := mi.healthChecker.CheckOverallHealth(mi.ctx)

				// Trigger health-based alerts if enabled
				if mi.config.EnableHealthBasedAlerting && mi.enhancedAlerting != nil {
					mi.checkHealthBasedAlerts(healthStatus)
				}
			}
		}
	}
}

func (mi *MonitoringIntegration) alertingLoop() {
	defer mi.wg.Done()

	ticker := time.NewTicker(mi.config.AlertCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mi.ctx.Done():
			return
		case <-ticker.C:
			if mi.enhancedAlerting != nil {
				mi.enhancedAlerting.CheckValidationAccuracyDegradation()
				mi.enhancedAlerting.CheckConfidenceDegradation()
				mi.enhancedAlerting.CheckSystemErrors()
			}
		}
	}
}

func (mi *MonitoringIntegration) baselineUpdateLoop() {
	defer mi.wg.Done()

	ticker := time.NewTicker(mi.config.BaselineUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mi.ctx.Done():
			return
		case <-ticker.C:
			if mi.enhancedAlerting != nil {
				mi.enhancedAlerting.UpdateBaseline("scheduled_update")
			}
		}
	}
}

func (mi *MonitoringIntegration) reportingLoop() {
	defer mi.wg.Done()

	ticker := time.NewTicker(mi.config.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mi.ctx.Done():
			return
		case <-ticker.C:
			mi.generatePeriodicReport()
		}
	}
}

func (mi *MonitoringIntegration) checkHealthBasedAlerts(healthStatus OverallHealthStatus) {
	// This would implement health-based alerting logic
	// For example, trigger alerts when health score drops below threshold
}

func (mi *MonitoringIntegration) generatePeriodicReport() {
	if mi.observer == nil {
		return
	}

	report := mi.GetComprehensiveReport()

	mi.observer.LogOperation(observability.StandardObservabilityData{
		Component: "monitoring_integration",
		Operation: "periodic_report",
		Success:   true,
		Metadata:  report,
	})
}

// getDefaultIntegrationConfig returns default integration configuration
func getDefaultIntegrationConfig() *IntegrationConfig {
	return &IntegrationConfig{
		EnablePerformanceMonitoring: true,
		EnableHealthChecks:          true,
		EnableEnhancedAlerting:      true,
		EnableDebugLogging:          true,
		HealthCheckInterval:         30 * time.Second,
		AlertCheckInterval:          2 * time.Minute,
		BaselineUpdateInterval:      1 * time.Hour,
		MetricsReportInterval:       5 * time.Minute,
		EnableCrossComponentAlerts:  true,
		EnableAutomaticBaseline:     true,
		EnableHealthBasedAlerting:   true,
		EnablePerformanceBaseline:   true,
		EnablePeriodicReports:       true,
		ReportInterval:              15 * time.Minute,
		ReportFormat:                "json",
	}
}
