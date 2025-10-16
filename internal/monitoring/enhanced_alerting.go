// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package monitoring

import (
	"fmt"
	"sync"
	"time"

	"ferret-scan/internal/observability"
	"ferret-scan/internal/performance"
)

// EnhancedAlerting provides advanced alerting for validation accuracy degradation
type EnhancedAlerting struct {
	performanceMonitor *performance.PerformanceMonitor
	observer           *observability.StandardObserver

	// Alerting configuration
	config *AlertingConfig

	// Baseline metrics for comparison
	baselineMetrics *BaselineMetrics

	// Alert state tracking
	activeAlerts map[string]*ActiveAlert
	alertHistory []AlertEvent

	// Thread safety
	mu sync.RWMutex
}

// AlertingConfig configures enhanced alerting behavior
type AlertingConfig struct {
	// Accuracy degradation thresholds
	MaxAccuracyDegradation   float64 // Maximum allowed accuracy drop (0.0-1.0)
	MaxConfidenceDegradation float64 // Maximum allowed confidence drop (0.0-1.0)
	MaxMatchCountVariation   float64 // Maximum allowed match count variation (0.0-1.0)

	// Performance degradation thresholds
	MaxPerformanceDegradation float64 // Maximum allowed performance degradation (0.0-1.0)
	MaxMemoryIncrease         float64 // Maximum allowed memory increase (0.0-1.0)

	// Alert timing configuration
	AlertCooldownPeriod    time.Duration // Minimum time between similar alerts
	BaselineUpdateInterval time.Duration // How often to update baseline metrics
	AccuracyCheckInterval  time.Duration // How often to check accuracy

	// Alert severity thresholds
	WarningThreshold  float64 // Threshold for warning alerts
	CriticalThreshold float64 // Threshold for critical alerts

	// Feature flags
	EnableAccuracyAlerting    bool
	EnablePerformanceAlerting bool
	EnableMemoryAlerting      bool
	EnableBaselineUpdates     bool
}

// BaselineMetrics stores baseline performance and accuracy metrics
type BaselineMetrics struct {
	// Accuracy baselines
	DocumentPathAccuracy float64
	MetadataPathAccuracy float64
	AverageConfidence    float64
	AverageMatchCount    float64

	// Performance baselines
	AverageRoutingTime    time.Duration
	AverageValidationTime time.Duration
	MemoryUsageBaseline   int64

	// Baseline metadata
	LastUpdated  time.Time
	SampleCount  int64
	UpdateReason string

	// Thread safety
	mu sync.RWMutex
}

// ActiveAlert represents an active alert
type ActiveAlert struct {
	ID         string
	Type       string
	Severity   string
	Message    string
	FirstSeen  time.Time
	LastSeen   time.Time
	Count      int
	Suppressed bool
	Metadata   map[string]interface{}
}

// AlertEvent represents a historical alert event
type AlertEvent struct {
	ID        string
	Type      string
	Severity  string
	Message   string
	Timestamp time.Time
	Resolved  bool
	Duration  time.Duration
	Metadata  map[string]interface{}
}

// AccuracyDegradationAlert represents accuracy degradation detection
type AccuracyDegradationAlert struct {
	PathType              string
	CurrentAccuracy       float64
	BaselineAccuracy      float64
	DegradationPercentage float64
	SampleSize            int64
	DetectionTime         time.Time
}

// NewEnhancedAlerting creates a new enhanced alerting system
func NewEnhancedAlerting(performanceMonitor *performance.PerformanceMonitor, observer *observability.StandardObserver, config *AlertingConfig) *EnhancedAlerting {
	if config == nil {
		config = getDefaultAlertingConfig()
	}

	return &EnhancedAlerting{
		performanceMonitor: performanceMonitor,
		observer:           observer,
		config:             config,
		baselineMetrics:    &BaselineMetrics{},
		activeAlerts:       make(map[string]*ActiveAlert),
		alertHistory:       make([]AlertEvent, 0),
	}
}

// CheckValidationAccuracyDegradation checks for validation accuracy degradation
func (ea *EnhancedAlerting) CheckValidationAccuracyDegradation() []AccuracyDegradationAlert {
	if !ea.config.EnableAccuracyAlerting {
		return nil
	}

	alerts := make([]AccuracyDegradationAlert, 0)

	// Get current metrics
	if ea.performanceMonitor == nil {
		return alerts
	}

	metrics := ea.performanceMonitor.GetMetrics()
	if metrics == nil {
		return alerts
	}

	dualPathMetrics := metrics.GetDualPathValidationMetrics()

	// Check document path accuracy
	if docAlert := ea.checkPathAccuracyDegradation("document", dualPathMetrics.DocumentPathMetrics); docAlert != nil {
		alerts = append(alerts, *docAlert)
	}

	// Check metadata path accuracy
	if metaAlert := ea.checkPathAccuracyDegradation("metadata", dualPathMetrics.MetadataPathMetrics); metaAlert != nil {
		alerts = append(alerts, *metaAlert)
	}

	// Process alerts
	for _, alert := range alerts {
		ea.processAccuracyAlert(alert)
	}

	return alerts
}

// checkPathAccuracyDegradation checks accuracy degradation for a specific path
func (ea *EnhancedAlerting) checkPathAccuracyDegradation(pathType string, pathMetrics *performance.ValidationPathMetrics) *AccuracyDegradationAlert {
	if pathMetrics.TotalValidations == 0 {
		return nil // No data to compare
	}

	// Calculate current accuracy
	currentAccuracy := float64(pathMetrics.SuccessfulValidations) / float64(pathMetrics.TotalValidations)

	// Get baseline accuracy
	ea.baselineMetrics.mu.RLock()
	var baselineAccuracy float64
	if pathType == "document" {
		baselineAccuracy = ea.baselineMetrics.DocumentPathAccuracy
	} else {
		baselineAccuracy = ea.baselineMetrics.MetadataPathAccuracy
	}
	ea.baselineMetrics.mu.RUnlock()

	// Skip check if no baseline established
	if baselineAccuracy == 0.0 {
		ea.updateBaselineAccuracy(pathType, currentAccuracy)
		return nil
	}

	// Calculate degradation
	degradation := (baselineAccuracy - currentAccuracy) / baselineAccuracy

	// Check if degradation exceeds threshold
	if degradation > ea.config.MaxAccuracyDegradation {
		return &AccuracyDegradationAlert{
			PathType:              pathType,
			CurrentAccuracy:       currentAccuracy,
			BaselineAccuracy:      baselineAccuracy,
			DegradationPercentage: degradation,
			SampleSize:            pathMetrics.TotalValidations,
			DetectionTime:         time.Now(),
		}
	}

	return nil
}

// CheckConfidenceDegradation checks for confidence score degradation
func (ea *EnhancedAlerting) CheckConfidenceDegradation() {
	if !ea.config.EnableAccuracyAlerting {
		return
	}

	if ea.performanceMonitor == nil {
		return
	}

	metrics := ea.performanceMonitor.GetMetrics()
	if metrics == nil {
		return
	}

	dualPathMetrics := metrics.GetDualPathValidationMetrics()

	// Check metadata path confidence (document path doesn't have confidence scores)
	metaMetrics := dualPathMetrics.MetadataPathMetrics
	if metaMetrics.TotalValidations == 0 {
		return
	}

	currentConfidence := metaMetrics.AverageConfidence

	// Get baseline confidence
	ea.baselineMetrics.mu.RLock()
	baselineConfidence := ea.baselineMetrics.AverageConfidence
	ea.baselineMetrics.mu.RUnlock()

	// Skip check if no baseline established
	if baselineConfidence == 0.0 {
		ea.updateBaselineConfidence(currentConfidence)
		return
	}

	// Calculate degradation
	degradation := (baselineConfidence - currentConfidence) / baselineConfidence

	// Check if degradation exceeds threshold
	if degradation > ea.config.MaxConfidenceDegradation {
		alert := ActiveAlert{
			ID:       fmt.Sprintf("confidence_degradation_%d", time.Now().Unix()),
			Type:     "confidence_degradation",
			Severity: ea.getSeverity(degradation),
			Message: fmt.Sprintf("Confidence degradation detected: %.2f%% drop from baseline %.2f to current %.2f",
				degradation*100, baselineConfidence, currentConfidence),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Count:     1,
			Metadata: map[string]interface{}{
				"current_confidence":  currentConfidence,
				"baseline_confidence": baselineConfidence,
				"degradation":         degradation,
				"sample_size":         metaMetrics.TotalValidations,
			},
		}

		ea.triggerAlert(alert)
	}
}

// CheckSystemErrors checks for system errors and failures
func (ea *EnhancedAlerting) CheckSystemErrors() {
	if ea.performanceMonitor == nil {
		return
	}

	metrics := ea.performanceMonitor.GetMetrics()
	if metrics == nil {
		return
	}

	// Check content routing errors
	contentMetrics := metrics.GetContentRoutingMetrics()
	if contentMetrics.TotalRoutingOperations > 0 {
		errorRate := float64(contentMetrics.FailedRoutingOps) / float64(contentMetrics.TotalRoutingOperations)

		if errorRate > ea.config.WarningThreshold {
			alert := ActiveAlert{
				ID:       fmt.Sprintf("routing_error_rate_%d", time.Now().Unix()),
				Type:     "routing_error_rate",
				Severity: ea.getSeverity(errorRate),
				Message: fmt.Sprintf("High routing error rate detected: %.2f%% (%d failures out of %d operations)",
					errorRate*100, contentMetrics.FailedRoutingOps, contentMetrics.TotalRoutingOperations),
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Count:     1,
				Metadata: map[string]interface{}{
					"error_rate":        errorRate,
					"failed_operations": contentMetrics.FailedRoutingOps,
					"total_operations":  contentMetrics.TotalRoutingOperations,
					"routing_errors":    contentMetrics.RoutingErrors,
				},
			}

			ea.triggerAlert(alert)
		}
	}

	// Check validation path errors
	dualPathMetrics := metrics.GetDualPathValidationMetrics()

	// Document path errors
	if dualPathMetrics.DocumentPathMetrics.TotalValidations > 0 {
		errorRate := float64(dualPathMetrics.DocumentPathMetrics.FailedValidations) / float64(dualPathMetrics.DocumentPathMetrics.TotalValidations)

		if errorRate > ea.config.WarningThreshold {
			alert := ActiveAlert{
				ID:        fmt.Sprintf("document_validation_error_rate_%d", time.Now().Unix()),
				Type:      "validation_error_rate",
				Severity:  ea.getSeverity(errorRate),
				Message:   fmt.Sprintf("High document validation error rate: %.2f%%", errorRate*100),
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Count:     1,
				Metadata: map[string]interface{}{
					"path_type":          "document",
					"error_rate":         errorRate,
					"failed_validations": dualPathMetrics.DocumentPathMetrics.FailedValidations,
					"total_validations":  dualPathMetrics.DocumentPathMetrics.TotalValidations,
				},
			}

			ea.triggerAlert(alert)
		}
	}

	// Metadata path errors
	if dualPathMetrics.MetadataPathMetrics.TotalValidations > 0 {
		errorRate := float64(dualPathMetrics.MetadataPathMetrics.FailedValidations) / float64(dualPathMetrics.MetadataPathMetrics.TotalValidations)

		if errorRate > ea.config.WarningThreshold {
			alert := ActiveAlert{
				ID:        fmt.Sprintf("metadata_validation_error_rate_%d", time.Now().Unix()),
				Type:      "validation_error_rate",
				Severity:  ea.getSeverity(errorRate),
				Message:   fmt.Sprintf("High metadata validation error rate: %.2f%%", errorRate*100),
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Count:     1,
				Metadata: map[string]interface{}{
					"path_type":          "metadata",
					"error_rate":         errorRate,
					"failed_validations": dualPathMetrics.MetadataPathMetrics.FailedValidations,
					"total_validations":  dualPathMetrics.MetadataPathMetrics.TotalValidations,
				},
			}

			ea.triggerAlert(alert)
		}
	}
}

// processAccuracyAlert processes an accuracy degradation alert
func (ea *EnhancedAlerting) processAccuracyAlert(alert AccuracyDegradationAlert) {
	activeAlert := ActiveAlert{
		ID:       fmt.Sprintf("accuracy_degradation_%s_%d", alert.PathType, alert.DetectionTime.Unix()),
		Type:     "accuracy_degradation",
		Severity: ea.getSeverity(alert.DegradationPercentage),
		Message: fmt.Sprintf("%s path accuracy degradation: %.2f%% drop from baseline %.2f to current %.2f",
			alert.PathType, alert.DegradationPercentage*100, alert.BaselineAccuracy, alert.CurrentAccuracy),
		FirstSeen: alert.DetectionTime,
		LastSeen:  alert.DetectionTime,
		Count:     1,
		Metadata: map[string]interface{}{
			"path_type":         alert.PathType,
			"current_accuracy":  alert.CurrentAccuracy,
			"baseline_accuracy": alert.BaselineAccuracy,
			"degradation":       alert.DegradationPercentage,
			"sample_size":       alert.SampleSize,
		},
	}

	ea.triggerAlert(activeAlert)
}

// triggerAlert triggers an alert
func (ea *EnhancedAlerting) triggerAlert(alert ActiveAlert) {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	// Check if similar alert is already active (cooldown period)
	if existingAlert, exists := ea.activeAlerts[alert.Type]; exists {
		if time.Since(existingAlert.LastSeen) < ea.config.AlertCooldownPeriod {
			// Update existing alert
			existingAlert.LastSeen = time.Now()
			existingAlert.Count++
			return
		}
	}

	// Add to active alerts
	ea.activeAlerts[alert.ID] = &alert

	// Log alert
	if ea.observer != nil {
		ea.observer.LogOperation(observability.StandardObservabilityData{
			Component: "enhanced_alerting",
			Operation: "alert_triggered",
			Success:   true,
			Metadata: map[string]interface{}{
				"alert_id":   alert.ID,
				"alert_type": alert.Type,
				"severity":   alert.Severity,
				"message":    alert.Message,
				"metadata":   alert.Metadata,
			},
		})

		if ea.observer.DebugObserver != nil {
			ea.observer.DebugObserver.LogDetail("enhanced_alerting",
				fmt.Sprintf("[%s] %s: %s", alert.Severity, alert.Type, alert.Message))
		}
	}

	// Add to history
	ea.alertHistory = append(ea.alertHistory, AlertEvent{
		ID:        alert.ID,
		Type:      alert.Type,
		Severity:  alert.Severity,
		Message:   alert.Message,
		Timestamp: alert.FirstSeen,
		Resolved:  false,
		Metadata:  alert.Metadata,
	})

	// Keep history size manageable
	if len(ea.alertHistory) > 1000 {
		ea.alertHistory = ea.alertHistory[100:]
	}
}

// UpdateBaseline updates baseline metrics
func (ea *EnhancedAlerting) UpdateBaseline(reason string) {
	if !ea.config.EnableBaselineUpdates {
		return
	}

	if ea.performanceMonitor == nil {
		return
	}

	metrics := ea.performanceMonitor.GetMetrics()
	if metrics == nil {
		return
	}

	ea.baselineMetrics.mu.Lock()
	defer ea.baselineMetrics.mu.Unlock()

	dualPathMetrics := metrics.GetDualPathValidationMetrics()

	// Update accuracy baselines
	if dualPathMetrics.DocumentPathMetrics.TotalValidations > 0 {
		ea.baselineMetrics.DocumentPathAccuracy = float64(dualPathMetrics.DocumentPathMetrics.SuccessfulValidations) /
			float64(dualPathMetrics.DocumentPathMetrics.TotalValidations)
	}

	if dualPathMetrics.MetadataPathMetrics.TotalValidations > 0 {
		ea.baselineMetrics.MetadataPathAccuracy = float64(dualPathMetrics.MetadataPathMetrics.SuccessfulValidations) /
			float64(dualPathMetrics.MetadataPathMetrics.TotalValidations)
		ea.baselineMetrics.AverageConfidence = dualPathMetrics.MetadataPathMetrics.AverageConfidence
		ea.baselineMetrics.AverageMatchCount = dualPathMetrics.MetadataPathMetrics.AverageMatchesPerFile
	}

	// Update performance baselines
	contentMetrics := metrics.GetContentRoutingMetrics()
	ea.baselineMetrics.AverageRoutingTime = contentMetrics.AverageRoutingTime
	ea.baselineMetrics.AverageValidationTime = dualPathMetrics.DocumentPathMetrics.AverageValidationTime

	// Update memory baseline
	ea.baselineMetrics.MemoryUsageBaseline = metrics.MemoryUsage.CurrentHeapSize

	// Update metadata
	ea.baselineMetrics.LastUpdated = time.Now()
	ea.baselineMetrics.SampleCount = dualPathMetrics.DocumentPathMetrics.TotalValidations + dualPathMetrics.MetadataPathMetrics.TotalValidations
	ea.baselineMetrics.UpdateReason = reason

	// Log baseline update
	if ea.observer != nil {
		ea.observer.LogOperation(observability.StandardObservabilityData{
			Component: "enhanced_alerting",
			Operation: "baseline_updated",
			Success:   true,
			Metadata: map[string]interface{}{
				"reason":                 reason,
				"document_path_accuracy": ea.baselineMetrics.DocumentPathAccuracy,
				"metadata_path_accuracy": ea.baselineMetrics.MetadataPathAccuracy,
				"average_confidence":     ea.baselineMetrics.AverageConfidence,
				"sample_count":           ea.baselineMetrics.SampleCount,
			},
		})
	}
}

// Helper methods

func (ea *EnhancedAlerting) updateBaselineAccuracy(pathType string, accuracy float64) {
	ea.baselineMetrics.mu.Lock()
	defer ea.baselineMetrics.mu.Unlock()

	if pathType == "document" {
		ea.baselineMetrics.DocumentPathAccuracy = accuracy
	} else {
		ea.baselineMetrics.MetadataPathAccuracy = accuracy
	}
}

func (ea *EnhancedAlerting) updateBaselineConfidence(confidence float64) {
	ea.baselineMetrics.mu.Lock()
	defer ea.baselineMetrics.mu.Unlock()

	ea.baselineMetrics.AverageConfidence = confidence
}

func (ea *EnhancedAlerting) getSeverity(value float64) string {
	if value >= ea.config.CriticalThreshold {
		return "critical"
	} else if value >= ea.config.WarningThreshold {
		return "warning"
	}
	return "info"
}

// GetActiveAlerts returns current active alerts
func (ea *EnhancedAlerting) GetActiveAlerts() map[string]*ActiveAlert {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	// Return a copy to avoid race conditions
	alerts := make(map[string]*ActiveAlert)
	for k, v := range ea.activeAlerts {
		alertCopy := *v
		alerts[k] = &alertCopy
	}
	return alerts
}

// GetAlertHistory returns alert history
func (ea *EnhancedAlerting) GetAlertHistory(limit int) []AlertEvent {
	ea.mu.RLock()
	defer ea.mu.RUnlock()

	if limit <= 0 || limit > len(ea.alertHistory) {
		limit = len(ea.alertHistory)
	}

	// Return most recent alerts
	start := len(ea.alertHistory) - limit
	return ea.alertHistory[start:]
}

// getDefaultAlertingConfig returns default alerting configuration
func getDefaultAlertingConfig() *AlertingConfig {
	return &AlertingConfig{
		MaxAccuracyDegradation:    0.1,  // 10% accuracy drop
		MaxConfidenceDegradation:  0.15, // 15% confidence drop
		MaxMatchCountVariation:    0.2,  // 20% match count variation
		MaxPerformanceDegradation: 0.25, // 25% performance degradation
		MaxMemoryIncrease:         0.5,  // 50% memory increase
		AlertCooldownPeriod:       5 * time.Minute,
		BaselineUpdateInterval:    1 * time.Hour,
		AccuracyCheckInterval:     2 * time.Minute,
		WarningThreshold:          0.05, // 5% threshold for warnings
		CriticalThreshold:         0.15, // 15% threshold for critical alerts
		EnableAccuracyAlerting:    true,
		EnablePerformanceAlerting: true,
		EnableMemoryAlerting:      true,
		EnableBaselineUpdates:     true,
	}
}
