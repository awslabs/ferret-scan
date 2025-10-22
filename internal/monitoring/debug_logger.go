// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package monitoring

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"ferret-scan/internal/observability"
)

// DebugLogger provides enhanced logging for debugging content routing decisions and validation outcomes
type DebugLogger struct {
	observer *observability.StandardObserver

	// Logging configuration
	config *DebugLoggingConfig

	// Decision tracking
	routingDecisions   []RoutingDecision
	validationOutcomes []ValidationOutcome

	// Thread safety
	mu sync.RWMutex
}

// DebugLoggingConfig configures debug logging behavior
type DebugLoggingConfig struct {
	// Feature flags
	EnableRoutingDecisionLogging   bool
	EnableValidationOutcomeLogging bool
	EnableDetailedContentLogging   bool
	EnablePerformanceLogging       bool

	// Logging levels
	LogLevel           string // "debug", "info", "warn", "error"
	MaxDecisionHistory int    // Maximum routing decisions to keep in memory
	MaxOutcomeHistory  int    // Maximum validation outcomes to keep in memory

	// Content logging limits
	MaxContentLength    int  // Maximum content length to log
	LogSensitiveContent bool // Whether to log potentially sensitive content
}

// RoutingDecision represents a content routing decision
type RoutingDecision struct {
	Timestamp         time.Time
	FilePath          string
	ContentLength     int
	PreprocessorTypes []string
	RoutingDecision   string // "document_only", "metadata_only", "dual_path", "fallback"
	Reasoning         string
	Success           bool
	Error             string
	ProcessingTime    time.Duration
	Metadata          map[string]interface{}
}

// ValidationOutcome represents a validation outcome
type ValidationOutcome struct {
	Timestamp         time.Time
	FilePath          string
	ValidationPath    string // "document" or "metadata"
	ValidatorType     string
	MatchCount        int
	AverageConfidence float64
	ProcessingTime    time.Duration
	Success           bool
	Error             string
	Matches           []ValidationMatch
	ContextBoosts     int
	ContextPenalties  int
	Metadata          map[string]interface{}
}

// ValidationMatch represents a single validation match
type ValidationMatch struct {
	ValidatorType string
	MatchText     string // Redacted for sensitive content
	Confidence    float64
	Position      int
	Context       string
	Boosted       bool
	BoostReason   string
}

// NewDebugLogger creates a new debug logger
func NewDebugLogger(observer *observability.StandardObserver, config *DebugLoggingConfig) *DebugLogger {
	if config == nil {
		config = getDefaultDebugLoggingConfig()
	}

	return &DebugLogger{
		observer:           observer,
		config:             config,
		routingDecisions:   make([]RoutingDecision, 0),
		validationOutcomes: make([]ValidationOutcome, 0),
	}
}

// LogRoutingDecision logs a content routing decision
func (dl *DebugLogger) LogRoutingDecision(decision RoutingDecision) {
	if !dl.config.EnableRoutingDecisionLogging {
		return
	}

	dl.mu.Lock()
	defer dl.mu.Unlock()

	// Add to decision history
	dl.routingDecisions = append(dl.routingDecisions, decision)

	// Maintain history size
	if len(dl.routingDecisions) > dl.config.MaxDecisionHistory {
		dl.routingDecisions = dl.routingDecisions[1:]
	}

	// Log to observer
	if dl.observer != nil {
		metadata := map[string]interface{}{
			"file_path":          decision.FilePath,
			"content_length":     decision.ContentLength,
			"preprocessor_types": decision.PreprocessorTypes,
			"routing_decision":   decision.RoutingDecision,
			"reasoning":          decision.Reasoning,
			"processing_time_ms": decision.ProcessingTime.Milliseconds(),
		}

		// Add additional metadata if available
		for k, v := range decision.Metadata {
			metadata[k] = v
		}

		dl.observer.LogOperation(observability.StandardObservabilityData{
			Component:  "debug_logger",
			Operation:  "routing_decision",
			FilePath:   decision.FilePath,
			Success:    decision.Success,
			Error:      decision.Error,
			DurationMs: decision.ProcessingTime.Milliseconds(),
			Metadata:   metadata,
		})

		// Detailed debug logging
		if dl.observer.DebugObserver != nil && dl.shouldLogDetailed() {
			dl.observer.DebugObserver.LogDetail("routing_decision",
				fmt.Sprintf("File: %s, Decision: %s, Reason: %s, Time: %dms",
					decision.FilePath, decision.RoutingDecision, decision.Reasoning, decision.ProcessingTime.Milliseconds()))
		}
	}
}

// LogValidationOutcome logs a validation outcome
func (dl *DebugLogger) LogValidationOutcome(outcome ValidationOutcome) {
	if !dl.config.EnableValidationOutcomeLogging {
		return
	}

	dl.mu.Lock()
	defer dl.mu.Unlock()

	// Add to outcome history
	dl.validationOutcomes = append(dl.validationOutcomes, outcome)

	// Maintain history size
	if len(dl.validationOutcomes) > dl.config.MaxOutcomeHistory {
		dl.validationOutcomes = dl.validationOutcomes[1:]
	}

	// Prepare matches for logging (redact sensitive content)
	logMatches := make([]map[string]interface{}, 0, len(outcome.Matches))
	for _, match := range outcome.Matches {
		logMatch := map[string]interface{}{
			"validator_type": match.ValidatorType,
			"confidence":     match.Confidence,
			"position":       match.Position,
			"boosted":        match.Boosted,
			"boost_reason":   match.BoostReason,
		}

		// Only log match text if configured to do so and it's not sensitive
		if dl.config.LogSensitiveContent {
			logMatch["match_text"] = dl.redactSensitiveContent(match.MatchText)
			logMatch["context"] = dl.redactSensitiveContent(match.Context)
		}

		logMatches = append(logMatches, logMatch)
	}

	// Log to observer
	if dl.observer != nil {
		metadata := map[string]interface{}{
			"file_path":          outcome.FilePath,
			"validation_path":    outcome.ValidationPath,
			"validator_type":     outcome.ValidatorType,
			"match_count":        outcome.MatchCount,
			"average_confidence": outcome.AverageConfidence,
			"processing_time_ms": outcome.ProcessingTime.Milliseconds(),
			"context_boosts":     outcome.ContextBoosts,
			"context_penalties":  outcome.ContextPenalties,
			"matches":            logMatches,
		}

		// Add additional metadata if available
		for k, v := range outcome.Metadata {
			metadata[k] = v
		}

		dl.observer.LogOperation(observability.StandardObservabilityData{
			Component:  "debug_logger",
			Operation:  "validation_outcome",
			FilePath:   outcome.FilePath,
			Success:    outcome.Success,
			Error:      outcome.Error,
			DurationMs: outcome.ProcessingTime.Milliseconds(),
			MatchCount: outcome.MatchCount,
			Metadata:   metadata,
		})

		// Detailed debug logging
		if dl.observer.DebugObserver != nil && dl.shouldLogDetailed() {
			dl.observer.DebugObserver.LogDetail("validation_outcome",
				fmt.Sprintf("File: %s, Path: %s, Validator: %s, Matches: %d, Confidence: %.2f, Time: %dms",
					outcome.FilePath, outcome.ValidationPath, outcome.ValidatorType,
					outcome.MatchCount, outcome.AverageConfidence, outcome.ProcessingTime.Milliseconds()))
		}
	}
}

// LogContentSeparation logs content separation details
func (dl *DebugLogger) LogContentSeparation(filePath string, contentLength int, documentBodyFound bool, metadataFound bool, preprocessorTypes []string, separationTime time.Duration) {
	if !dl.config.EnableDetailedContentLogging {
		return
	}

	if dl.observer != nil {
		metadata := map[string]interface{}{
			"content_length":      contentLength,
			"document_body_found": documentBodyFound,
			"metadata_found":      metadataFound,
			"preprocessor_types":  preprocessorTypes,
			"separation_time_ms":  separationTime.Milliseconds(),
		}

		dl.observer.LogOperation(observability.StandardObservabilityData{
			Component:     "debug_logger",
			Operation:     "content_separation",
			FilePath:      filePath,
			Success:       true,
			DurationMs:    separationTime.Milliseconds(),
			ContentLength: contentLength,
			Metadata:      metadata,
		})

		if dl.observer.DebugObserver != nil && dl.shouldLogDetailed() {
			dl.observer.DebugObserver.LogDetail("content_separation",
				fmt.Sprintf("File: %s, Length: %d, DocBody: %t, Metadata: %t, Preprocessors: %v, Time: %dms",
					filePath, contentLength, documentBodyFound, metadataFound, preprocessorTypes, separationTime.Milliseconds()))
		}
	}
}

// LogContextIntegration logs context analysis integration details
func (dl *DebugLogger) LogContextIntegration(filePath string, contextBoosts int, contextPenalties int, contextImpact float64, integrationTime time.Duration) {
	if !dl.config.EnableDetailedContentLogging {
		return
	}

	if dl.observer != nil {
		metadata := map[string]interface{}{
			"context_boosts":      contextBoosts,
			"context_penalties":   contextPenalties,
			"context_impact":      contextImpact,
			"integration_time_ms": integrationTime.Milliseconds(),
		}

		dl.observer.LogOperation(observability.StandardObservabilityData{
			Component:  "debug_logger",
			Operation:  "context_integration",
			FilePath:   filePath,
			Success:    true,
			DurationMs: integrationTime.Milliseconds(),
			Metadata:   metadata,
		})

		if dl.observer.DebugObserver != nil && dl.shouldLogDetailed() {
			dl.observer.DebugObserver.LogDetail("context_integration",
				fmt.Sprintf("File: %s, Boosts: %d, Penalties: %d, Impact: %.2f, Time: %dms",
					filePath, contextBoosts, contextPenalties, contextImpact, integrationTime.Milliseconds()))
		}
	}
}

// LogPerformanceMetrics logs performance metrics
func (dl *DebugLogger) LogPerformanceMetrics(component string, operation string, metrics map[string]interface{}) {
	if !dl.config.EnablePerformanceLogging {
		return
	}

	if dl.observer != nil {
		dl.observer.LogOperation(observability.StandardObservabilityData{
			Component: "debug_logger",
			Operation: "performance_metrics",
			Success:   true,
			Metadata: map[string]interface{}{
				"target_component": component,
				"target_operation": operation,
				"metrics":          metrics,
			},
		})

		if dl.observer.DebugObserver != nil && dl.shouldLogDetailed() {
			metricsJSON, _ := json.Marshal(metrics)
			dl.observer.DebugObserver.LogDetail("performance_metrics",
				fmt.Sprintf("Component: %s, Operation: %s, Metrics: %s", component, operation, string(metricsJSON)))
		}
	}
}

// LogFallbackActivation logs when fallback mode is activated
func (dl *DebugLogger) LogFallbackActivation(filePath string, reason string, originalError error, fallbackSuccess bool, fallbackTime time.Duration) {
	if dl.observer != nil {
		errorStr := ""
		if originalError != nil {
			errorStr = originalError.Error()
		}

		metadata := map[string]interface{}{
			"fallback_reason":  reason,
			"original_error":   errorStr,
			"fallback_success": fallbackSuccess,
			"fallback_time_ms": fallbackTime.Milliseconds(),
		}

		dl.observer.LogOperation(observability.StandardObservabilityData{
			Component:  "debug_logger",
			Operation:  "fallback_activation",
			FilePath:   filePath,
			Success:    fallbackSuccess,
			Error:      errorStr,
			DurationMs: fallbackTime.Milliseconds(),
			Metadata:   metadata,
		})

		if dl.observer.DebugObserver != nil {
			dl.observer.DebugObserver.LogDetail("fallback_activation",
				fmt.Sprintf("File: %s, Reason: %s, Success: %t, Time: %dms",
					filePath, reason, fallbackSuccess, fallbackTime.Milliseconds()))
		}
	}
}

// GetRoutingDecisionHistory returns recent routing decisions
func (dl *DebugLogger) GetRoutingDecisionHistory(limit int) []RoutingDecision {
	dl.mu.RLock()
	defer dl.mu.RUnlock()

	if limit <= 0 || limit > len(dl.routingDecisions) {
		limit = len(dl.routingDecisions)
	}

	// Return most recent decisions
	start := len(dl.routingDecisions) - limit
	decisions := make([]RoutingDecision, limit)
	copy(decisions, dl.routingDecisions[start:])
	return decisions
}

// GetValidationOutcomeHistory returns recent validation outcomes
func (dl *DebugLogger) GetValidationOutcomeHistory(limit int) []ValidationOutcome {
	dl.mu.RLock()
	defer dl.mu.RUnlock()

	if limit <= 0 || limit > len(dl.validationOutcomes) {
		limit = len(dl.validationOutcomes)
	}

	// Return most recent outcomes
	start := len(dl.validationOutcomes) - limit
	outcomes := make([]ValidationOutcome, limit)
	copy(outcomes, dl.validationOutcomes[start:])
	return outcomes
}

// GetDebugSummary returns a summary of debug information
func (dl *DebugLogger) GetDebugSummary() map[string]interface{} {
	dl.mu.RLock()
	defer dl.mu.RUnlock()

	// Analyze routing decisions
	routingStats := dl.analyzeRoutingDecisions()

	// Analyze validation outcomes
	validationStats := dl.analyzeValidationOutcomes()

	return map[string]interface{}{
		"routing_decisions": map[string]interface{}{
			"total_count":    len(dl.routingDecisions),
			"success_rate":   routingStats["success_rate"],
			"decision_types": routingStats["decision_types"],
			"avg_time_ms":    routingStats["avg_time_ms"],
		},
		"validation_outcomes": map[string]interface{}{
			"total_count":       len(dl.validationOutcomes),
			"success_rate":      validationStats["success_rate"],
			"avg_matches":       validationStats["avg_matches"],
			"avg_confidence":    validationStats["avg_confidence"],
			"path_distribution": validationStats["path_distribution"],
		},
		"config": map[string]interface{}{
			"routing_logging_enabled":    dl.config.EnableRoutingDecisionLogging,
			"validation_logging_enabled": dl.config.EnableValidationOutcomeLogging,
			"detailed_logging_enabled":   dl.config.EnableDetailedContentLogging,
			"log_level":                  dl.config.LogLevel,
		},
	}
}

// Helper methods

func (dl *DebugLogger) shouldLogDetailed() bool {
	return dl.config.LogLevel == "debug" || dl.config.EnableDetailedContentLogging
}

func (dl *DebugLogger) redactSensitiveContent(content string) string {
	if !dl.config.LogSensitiveContent {
		return "[HIDDEN]"
	}

	// Limit content length
	if len(content) > dl.config.MaxContentLength {
		return content[:dl.config.MaxContentLength] + "..."
	}

	return content
}

func (dl *DebugLogger) analyzeRoutingDecisions() map[string]interface{} {
	if len(dl.routingDecisions) == 0 {
		return map[string]interface{}{
			"success_rate":   0.0,
			"decision_types": map[string]int{},
			"avg_time_ms":    0.0,
		}
	}

	successCount := 0
	decisionTypes := make(map[string]int)
	totalTime := time.Duration(0)

	for _, decision := range dl.routingDecisions {
		if decision.Success {
			successCount++
		}
		decisionTypes[decision.RoutingDecision]++
		totalTime += decision.ProcessingTime
	}

	return map[string]interface{}{
		"success_rate":   float64(successCount) / float64(len(dl.routingDecisions)),
		"decision_types": decisionTypes,
		"avg_time_ms":    totalTime.Milliseconds() / int64(len(dl.routingDecisions)),
	}
}

func (dl *DebugLogger) analyzeValidationOutcomes() map[string]interface{} {
	if len(dl.validationOutcomes) == 0 {
		return map[string]interface{}{
			"success_rate":      0.0,
			"avg_matches":       0.0,
			"avg_confidence":    0.0,
			"path_distribution": map[string]int{},
		}
	}

	successCount := 0
	totalMatches := 0
	totalConfidence := 0.0
	pathDistribution := make(map[string]int)

	for _, outcome := range dl.validationOutcomes {
		if outcome.Success {
			successCount++
		}
		totalMatches += outcome.MatchCount
		totalConfidence += outcome.AverageConfidence
		pathDistribution[outcome.ValidationPath]++
	}

	return map[string]interface{}{
		"success_rate":      float64(successCount) / float64(len(dl.validationOutcomes)),
		"avg_matches":       float64(totalMatches) / float64(len(dl.validationOutcomes)),
		"avg_confidence":    totalConfidence / float64(len(dl.validationOutcomes)),
		"path_distribution": pathDistribution,
	}
}

// getDefaultDebugLoggingConfig returns default debug logging configuration
func getDefaultDebugLoggingConfig() *DebugLoggingConfig {
	return &DebugLoggingConfig{
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
}
