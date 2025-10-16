// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package performance

import (
	"fmt"
	"sync"
	"time"

	"ferret-scan/internal/observability"
)

// ObservabilityHooks provides debugging and observability hooks for the enhanced architecture
type ObservabilityHooks struct {
	observer *observability.StandardObserver
	monitor  *PerformanceMonitor

	// Hook configuration
	config *HooksConfig

	// Active hooks
	contentRoutingHooks []ContentRoutingHook
	validationHooks     []ValidationHook
	performanceHooks    []PerformanceHook

	// Hook execution tracking
	hookExecutions map[string]*HookExecutionStats

	// Thread safety
	mu sync.RWMutex
}

// HooksConfig configures observability hooks
type HooksConfig struct {
	// Hook enablement
	EnableContentRoutingHooks bool
	EnableValidationHooks     bool
	EnablePerformanceHooks    bool
	EnableDebugHooks          bool

	// Hook execution limits
	MaxHookExecutionTime time.Duration
	MaxConcurrentHooks   int

	// Logging configuration
	LogHookExecutions  bool
	LogHookPerformance bool
}

// ContentRoutingHook provides hooks for content routing decisions
type ContentRoutingHook interface {
	OnContentRouted(routingDecision *ContentRoutingDecision)
	OnRoutingFailed(error error, content string, filePath string)
	OnFallbackActivated(reason string, filePath string)
}

// ValidationHook provides hooks for validation decisions
type ValidationHook interface {
	OnValidationStarted(validationType string, filePath string)
	OnValidationCompleted(result *ValidationResult)
	OnCrossPathCorrelation(documentMatches, metadataMatches int, correlationBoost float64)
}

// PerformanceHook provides hooks for performance monitoring
type PerformanceHook interface {
	OnPerformanceAlert(alert *Alert)
	OnBenchmarkCompleted(results *BenchmarkResults)
	OnMemoryThresholdExceeded(currentUsage, threshold int64)
}

// ContentRoutingDecision contains information about routing decisions
type ContentRoutingDecision struct {
	FilePath          string
	DocumentBodyFound bool
	MetadataFound     bool
	PreprocessorTypes []string
	RoutingTime       time.Duration
	ConfidenceScore   float64
	DecisionReasoning string

	// File type filtering information
	FileExtension      string
	CanContainMetadata bool
	MetadataType       string
	MetadataSkipped    bool
	SkipReason         string
}

// ValidationResult contains information about validation results
type ValidationResult struct {
	ValidationType    string
	FilePath          string
	MatchCount        int
	AverageConfidence float64
	ProcessingTime    time.Duration
	ContextImpact     float64
	Success           bool
	Error             error
}

// HookExecutionStats tracks statistics for hook executions
type HookExecutionStats struct {
	TotalExecutions      int64
	SuccessfulExecutions int64
	FailedExecutions     int64
	AverageExecutionTime time.Duration
	MaxExecutionTime     time.Duration
	LastExecutionTime    time.Time
	mu                   sync.RWMutex
}

// NewObservabilityHooks creates a new observability hooks instance
func NewObservabilityHooks(observer *observability.StandardObserver, monitor *PerformanceMonitor, config *HooksConfig) *ObservabilityHooks {
	if config == nil {
		config = getDefaultHooksConfig()
	}

	return &ObservabilityHooks{
		observer:            observer,
		monitor:             monitor,
		config:              config,
		contentRoutingHooks: make([]ContentRoutingHook, 0),
		validationHooks:     make([]ValidationHook, 0),
		performanceHooks:    make([]PerformanceHook, 0),
		hookExecutions:      make(map[string]*HookExecutionStats),
	}
}

// RegisterContentRoutingHook registers a content routing hook
func (oh *ObservabilityHooks) RegisterContentRoutingHook(hook ContentRoutingHook) {
	if !oh.config.EnableContentRoutingHooks {
		return
	}

	oh.mu.Lock()
	defer oh.mu.Unlock()

	oh.contentRoutingHooks = append(oh.contentRoutingHooks, hook)

	if oh.observer != nil && oh.observer.DebugObserver != nil {
		oh.observer.DebugObserver.LogDetail("observability_hooks", "Content routing hook registered")
	}
}

// RegisterValidationHook registers a validation hook
func (oh *ObservabilityHooks) RegisterValidationHook(hook ValidationHook) {
	if !oh.config.EnableValidationHooks {
		return
	}

	oh.mu.Lock()
	defer oh.mu.Unlock()

	oh.validationHooks = append(oh.validationHooks, hook)

	if oh.observer != nil && oh.observer.DebugObserver != nil {
		oh.observer.DebugObserver.LogDetail("observability_hooks", "Validation hook registered")
	}
}

// RegisterPerformanceHook registers a performance hook
func (oh *ObservabilityHooks) RegisterPerformanceHook(hook PerformanceHook) {
	if !oh.config.EnablePerformanceHooks {
		return
	}

	oh.mu.Lock()
	defer oh.mu.Unlock()

	oh.performanceHooks = append(oh.performanceHooks, hook)

	if oh.observer != nil && oh.observer.DebugObserver != nil {
		oh.observer.DebugObserver.LogDetail("observability_hooks", "Performance hook registered")
	}
}

// TriggerContentRoutingHooks triggers all registered content routing hooks
func (oh *ObservabilityHooks) TriggerContentRoutingHooks(decision *ContentRoutingDecision) {
	if !oh.config.EnableContentRoutingHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]ContentRoutingHook, len(oh.contentRoutingHooks))
	copy(hooks, oh.contentRoutingHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("content_routing", func() {
			hook.OnContentRouted(decision)
		})
	}
}

// TriggerRoutingFailedHooks triggers routing failure hooks
func (oh *ObservabilityHooks) TriggerRoutingFailedHooks(err error, content, filePath string) {
	if !oh.config.EnableContentRoutingHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]ContentRoutingHook, len(oh.contentRoutingHooks))
	copy(hooks, oh.contentRoutingHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("routing_failed", func() {
			hook.OnRoutingFailed(err, content, filePath)
		})
	}
}

// TriggerFallbackActivatedHooks triggers fallback activation hooks
func (oh *ObservabilityHooks) TriggerFallbackActivatedHooks(reason, filePath string) {
	if !oh.config.EnableContentRoutingHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]ContentRoutingHook, len(oh.contentRoutingHooks))
	copy(hooks, oh.contentRoutingHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("fallback_activated", func() {
			hook.OnFallbackActivated(reason, filePath)
		})
	}
}

// TriggerValidationStartedHooks triggers validation started hooks
func (oh *ObservabilityHooks) TriggerValidationStartedHooks(validationType, filePath string) {
	if !oh.config.EnableValidationHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]ValidationHook, len(oh.validationHooks))
	copy(hooks, oh.validationHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("validation_started", func() {
			hook.OnValidationStarted(validationType, filePath)
		})
	}
}

// TriggerValidationCompletedHooks triggers validation completed hooks
func (oh *ObservabilityHooks) TriggerValidationCompletedHooks(result *ValidationResult) {
	if !oh.config.EnableValidationHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]ValidationHook, len(oh.validationHooks))
	copy(hooks, oh.validationHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("validation_completed", func() {
			hook.OnValidationCompleted(result)
		})
	}
}

// TriggerCrossPathCorrelationHooks triggers cross-path correlation hooks
func (oh *ObservabilityHooks) TriggerCrossPathCorrelationHooks(documentMatches, metadataMatches int, correlationBoost float64) {
	if !oh.config.EnableValidationHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]ValidationHook, len(oh.validationHooks))
	copy(hooks, oh.validationHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("cross_path_correlation", func() {
			hook.OnCrossPathCorrelation(documentMatches, metadataMatches, correlationBoost)
		})
	}
}

// TriggerPerformanceAlertHooks triggers performance alert hooks
func (oh *ObservabilityHooks) TriggerPerformanceAlertHooks(alert *Alert) {
	if !oh.config.EnablePerformanceHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]PerformanceHook, len(oh.performanceHooks))
	copy(hooks, oh.performanceHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("performance_alert", func() {
			hook.OnPerformanceAlert(alert)
		})
	}
}

// TriggerBenchmarkCompletedHooks triggers benchmark completed hooks
func (oh *ObservabilityHooks) TriggerBenchmarkCompletedHooks(results *BenchmarkResults) {
	if !oh.config.EnablePerformanceHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]PerformanceHook, len(oh.performanceHooks))
	copy(hooks, oh.performanceHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("benchmark_completed", func() {
			hook.OnBenchmarkCompleted(results)
		})
	}
}

// TriggerMemoryThresholdHooks triggers memory threshold exceeded hooks
func (oh *ObservabilityHooks) TriggerMemoryThresholdHooks(currentUsage, threshold int64) {
	if !oh.config.EnablePerformanceHooks {
		return
	}

	oh.mu.RLock()
	hooks := make([]PerformanceHook, len(oh.performanceHooks))
	copy(hooks, oh.performanceHooks)
	oh.mu.RUnlock()

	for _, hook := range hooks {
		oh.executeHookSafely("memory_threshold", func() {
			hook.OnMemoryThresholdExceeded(currentUsage, threshold)
		})
	}
}

// executeHookSafely executes a hook function safely with error handling and performance tracking
func (oh *ObservabilityHooks) executeHookSafely(hookType string, hookFunc func()) {
	startTime := time.Now()

	defer func() {
		executionTime := time.Since(startTime)
		oh.updateHookExecutionStats(hookType, executionTime, recover() == nil)

		if oh.config.LogHookPerformance && oh.observer != nil && oh.observer.DebugObserver != nil {
			oh.observer.DebugObserver.LogDetail("hook_performance", fmt.Sprintf(
				"Hook %s executed in %v", hookType, executionTime))
		}
	}()

	// Recover from panics in hook execution
	defer func() {
		if r := recover(); r != nil {
			if oh.observer != nil {
				oh.observer.LogOperation(observability.StandardObservabilityData{
					Component: "observability_hooks",
					Operation: "hook_panic",
					Success:   false,
					Error:     fmt.Sprintf("Hook %s panicked: %v", hookType, r),
				})
			}
		}
	}()

	// Execute with timeout if configured
	if oh.config.MaxHookExecutionTime > 0 {
		done := make(chan bool, 1)
		go func() {
			hookFunc()
			done <- true
		}()

		select {
		case <-done:
			// Hook completed successfully
		case <-time.After(oh.config.MaxHookExecutionTime):
			if oh.observer != nil {
				oh.observer.LogOperation(observability.StandardObservabilityData{
					Component: "observability_hooks",
					Operation: "hook_timeout",
					Success:   false,
					Error:     fmt.Sprintf("Hook %s timed out after %v", hookType, oh.config.MaxHookExecutionTime),
				})
			}
		}
	} else {
		hookFunc()
	}
}

// updateHookExecutionStats updates execution statistics for a hook type
func (oh *ObservabilityHooks) updateHookExecutionStats(hookType string, executionTime time.Duration, success bool) {
	oh.mu.Lock()
	defer oh.mu.Unlock()

	stats, exists := oh.hookExecutions[hookType]
	if !exists {
		stats = &HookExecutionStats{}
		oh.hookExecutions[hookType] = stats
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.TotalExecutions++
	stats.LastExecutionTime = time.Now()

	if success {
		stats.SuccessfulExecutions++
	} else {
		stats.FailedExecutions++
	}

	// Update timing statistics
	if stats.TotalExecutions == 1 {
		stats.AverageExecutionTime = executionTime
		stats.MaxExecutionTime = executionTime
	} else {
		// Running average
		totalTime := stats.AverageExecutionTime * time.Duration(stats.TotalExecutions-1)
		stats.AverageExecutionTime = (totalTime + executionTime) / time.Duration(stats.TotalExecutions)

		if executionTime > stats.MaxExecutionTime {
			stats.MaxExecutionTime = executionTime
		}
	}
}

// GetHookExecutionStats returns execution statistics for all hooks
func (oh *ObservabilityHooks) GetHookExecutionStats() map[string]HookExecutionStats {
	oh.mu.RLock()
	defer oh.mu.RUnlock()

	stats := make(map[string]HookExecutionStats)
	for hookType, hookStats := range oh.hookExecutions {
		hookStats.mu.RLock()
		stats[hookType] = HookExecutionStats{
			TotalExecutions:      hookStats.TotalExecutions,
			SuccessfulExecutions: hookStats.SuccessfulExecutions,
			FailedExecutions:     hookStats.FailedExecutions,
			AverageExecutionTime: hookStats.AverageExecutionTime,
			MaxExecutionTime:     hookStats.MaxExecutionTime,
			LastExecutionTime:    hookStats.LastExecutionTime,
		}
		hookStats.mu.RUnlock()
	}

	return stats
}

// GetHooksSummary returns a summary of registered hooks and their performance
func (oh *ObservabilityHooks) GetHooksSummary() map[string]interface{} {
	oh.mu.RLock()
	defer oh.mu.RUnlock()

	summary := map[string]interface{}{
		"registered_hooks": map[string]interface{}{
			"content_routing": len(oh.contentRoutingHooks),
			"validation":      len(oh.validationHooks),
			"performance":     len(oh.performanceHooks),
		},
		"hook_executions": oh.GetHookExecutionStats(),
		"configuration": map[string]interface{}{
			"content_routing_enabled": oh.config.EnableContentRoutingHooks,
			"validation_enabled":      oh.config.EnableValidationHooks,
			"performance_enabled":     oh.config.EnablePerformanceHooks,
			"debug_enabled":           oh.config.EnableDebugHooks,
			"max_execution_time_ms":   oh.config.MaxHookExecutionTime.Milliseconds(),
			"max_concurrent_hooks":    oh.config.MaxConcurrentHooks,
		},
	}

	return summary
}

// Default configuration

func getDefaultHooksConfig() *HooksConfig {
	return &HooksConfig{
		EnableContentRoutingHooks: true,
		EnableValidationHooks:     true,
		EnablePerformanceHooks:    true,
		EnableDebugHooks:          true,
		MaxHookExecutionTime:      1 * time.Second,
		MaxConcurrentHooks:        10,
		LogHookExecutions:         false,
		LogHookPerformance:        false,
	}
}

// Built-in hook implementations

// DebugContentRoutingHook provides debug logging for content routing
type DebugContentRoutingHook struct {
	observer *observability.StandardObserver
}

// NewDebugContentRoutingHook creates a new debug content routing hook
func NewDebugContentRoutingHook(observer *observability.StandardObserver) *DebugContentRoutingHook {
	return &DebugContentRoutingHook{observer: observer}
}

func (h *DebugContentRoutingHook) OnContentRouted(decision *ContentRoutingDecision) {
	if h.observer != nil && h.observer.DebugObserver != nil {
		baseInfo := fmt.Sprintf(
			"File: %s, DocumentBody: %t, Metadata: %t, Preprocessors: %v, Time: %v, Confidence: %.2f",
			decision.FilePath, decision.DocumentBodyFound, decision.MetadataFound,
			decision.PreprocessorTypes, decision.RoutingTime, decision.ConfidenceScore)

		// Add file type filtering information
		filterInfo := fmt.Sprintf(
			"FileExt: %s, CanContainMetadata: %t, MetadataType: %s, MetadataSkipped: %t, SkipReason: %s",
			decision.FileExtension, decision.CanContainMetadata, decision.MetadataType,
			decision.MetadataSkipped, decision.SkipReason)

		h.observer.DebugObserver.LogDetail("content_routing_decision", baseInfo)
		h.observer.DebugObserver.LogDetail("file_type_filtering", filterInfo)
	}
}

func (h *DebugContentRoutingHook) OnRoutingFailed(err error, content, filePath string) {
	if h.observer != nil && h.observer.DebugObserver != nil {
		h.observer.DebugObserver.LogDetail("routing_failure", fmt.Sprintf(
			"File: %s, Error: %v, ContentLength: %d", filePath, err, len(content)))
	}
}

func (h *DebugContentRoutingHook) OnFallbackActivated(reason, filePath string) {
	if h.observer != nil && h.observer.DebugObserver != nil {
		h.observer.DebugObserver.LogDetail("fallback_activation", fmt.Sprintf(
			"File: %s, Reason: %s", filePath, reason))
	}
}

// DebugValidationHook provides debug logging for validation
type DebugValidationHook struct {
	observer *observability.StandardObserver
}

// NewDebugValidationHook creates a new debug validation hook
func NewDebugValidationHook(observer *observability.StandardObserver) *DebugValidationHook {
	return &DebugValidationHook{observer: observer}
}

func (h *DebugValidationHook) OnValidationStarted(validationType, filePath string) {
	if h.observer != nil && h.observer.DebugObserver != nil {
		h.observer.DebugObserver.LogDetail("validation_started", fmt.Sprintf(
			"Type: %s, File: %s", validationType, filePath))
	}
}

func (h *DebugValidationHook) OnValidationCompleted(result *ValidationResult) {
	if h.observer != nil && h.observer.DebugObserver != nil {
		h.observer.DebugObserver.LogDetail("validation_completed", fmt.Sprintf(
			"Type: %s, File: %s, Matches: %d, AvgConfidence: %.2f, Time: %v, Success: %t",
			result.ValidationType, result.FilePath, result.MatchCount,
			result.AverageConfidence, result.ProcessingTime, result.Success))
	}
}

func (h *DebugValidationHook) OnCrossPathCorrelation(documentMatches, metadataMatches int, correlationBoost float64) {
	if h.observer != nil && h.observer.DebugObserver != nil {
		h.observer.DebugObserver.LogDetail("cross_path_correlation", fmt.Sprintf(
			"DocumentMatches: %d, MetadataMatches: %d, CorrelationBoost: %.2f",
			documentMatches, metadataMatches, correlationBoost))
	}
}
