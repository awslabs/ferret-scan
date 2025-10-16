// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/performance"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/router"
)

// EnhancedValidatorBridge supports both document and metadata validation paths
type EnhancedValidatorBridge struct {
	// Core components
	documentBridge  *DocumentValidatorBridge
	metadataBridge  *MetadataValidatorBridge
	contentRouter   *router.ContentRouter
	contextAnalyzer *context.ContextAnalyzer
	observer        *observability.StandardObserver

	// Configuration
	config *DualPathConfig

	// Metrics and monitoring
	metrics            *DualPathMetrics
	performanceMonitor *performance.PerformanceMonitor
	observabilityHooks *performance.ObservabilityHooks

	// Thread safety
	mu sync.RWMutex
}

// DocumentValidatorBridge routes document body content to non-metadata validators
type DocumentValidatorBridge struct {
	validators      []detector.Validator
	contextAnalyzer *context.ContextAnalyzer
	observer        *observability.StandardObserver
	metrics         *DocumentValidationMetrics
	mu              sync.RWMutex
}

// MetadataValidatorBridge routes metadata content exclusively to metadata validator
type MetadataValidatorBridge struct {
	metadataValidator PreprocessorAwareValidator
	contextAnalyzer   *context.ContextAnalyzer
	observer          *observability.StandardObserver
	metrics           *MetadataValidationMetrics
	mu                sync.RWMutex
}

// PreprocessorAwareValidator interface for metadata validator
type PreprocessorAwareValidator interface {
	detector.Validator
	ValidateMetadataContent(content router.MetadataContent) ([]detector.Match, error)
	GetSupportedPreprocessors() []string
	SetPreprocessorValidationRules(rules map[string]ValidationRule)
}

// ValidationRule defines validation rules for specific preprocessor types
type ValidationRule struct {
	SensitiveFields  []string           // Fields to focus validation on
	ConfidenceBoosts map[string]float64 // Confidence boosts for specific field types
	PatternOverrides map[string]string  // Custom patterns for specific fields
}

// DualPathConfig configures the dual-path validation system
type DualPathConfig struct {
	EnableContextIntegration bool
	EnableFallbackMode       bool
	EnableMetrics            bool
	EnableDebugLogging       bool
	MaxRetries               int
	TimeoutDuration          time.Duration
}

// DualPathMetrics tracks metrics for both validation paths
type DualPathMetrics struct {
	// Overall metrics
	TotalValidations      int64
	SuccessfulValidations int64
	FailedValidations     int64
	FallbackActivations   int64

	// Performance metrics
	AverageProcessingTime time.Duration
	DocumentPathTime      time.Duration
	MetadataPathTime      time.Duration
	RoutingTime           time.Duration

	// Content routing metrics
	RoutingSuccesses int64
	RoutingFailures  int64

	// Context integration metrics
	ContextAnalysisTime time.Duration
	ContextBoosts       int64
	ContextPenalties    int64

	// Thread safety
	mu sync.RWMutex
}

// DocumentValidationMetrics tracks document validation path metrics
type DocumentValidationMetrics struct {
	ValidationsProcessed int64
	MatchesFound         int64
	AverageConfidence    float64
	ProcessingTime       time.Duration
	ContextImpact        float64
	mu                   sync.RWMutex
}

// MetadataValidationMetrics tracks metadata validation path metrics
type MetadataValidationMetrics struct {
	MetadataItemsProcessed int64
	MatchesFound           int64
	AverageConfidence      float64
	ProcessingTime         time.Duration
	PreprocessorBreakdown  map[string]int64
	ContextImpact          float64

	// File type filtering metrics
	FilesSkipped int64
	SkipReasons  map[string]int64 // Track reasons for skipping

	mu sync.RWMutex
}

// DualPathValidationResult contains results from both validation paths
type DualPathValidationResult struct {
	DocumentMatches []detector.Match
	MetadataMatches []detector.Match
	AllMatches      []detector.Match
	ContextInsights context.ContextInsights
	ProcessingTime  time.Duration
	RoutingSuccess  bool
	FallbackUsed    bool
	Metrics         *DualPathMetrics
}

// NewEnhancedValidatorBridge creates a new dual-path validator bridge
func NewEnhancedValidatorBridge(config *DualPathConfig) *EnhancedValidatorBridge {
	if config == nil {
		config = getDefaultDualPathConfig()
	}

	bridge := &EnhancedValidatorBridge{
		contentRouter:   router.NewContentRouter(),
		contextAnalyzer: context.NewContextAnalyzer(),
		config:          config,
		metrics:         &DualPathMetrics{},
	}

	// Initialize sub-bridges
	bridge.documentBridge = NewDocumentValidatorBridge()
	bridge.metadataBridge = NewMetadataValidatorBridge()

	return bridge
}

// NewDocumentValidatorBridge creates a new document validator bridge
func NewDocumentValidatorBridge() *DocumentValidatorBridge {
	return &DocumentValidatorBridge{
		validators:      make([]detector.Validator, 0),
		contextAnalyzer: context.NewContextAnalyzer(),
		metrics:         &DocumentValidationMetrics{},
	}
}

// NewMetadataValidatorBridge creates a new metadata validator bridge
func NewMetadataValidatorBridge() *MetadataValidatorBridge {
	return &MetadataValidatorBridge{
		contextAnalyzer: context.NewContextAnalyzer(),
		metrics: &MetadataValidationMetrics{
			PreprocessorBreakdown: make(map[string]int64),
			SkipReasons:           make(map[string]int64),
		},
	}
}

// SetObserver sets the observability component for all bridges
func (evb *EnhancedValidatorBridge) SetObserver(observer *observability.StandardObserver) {
	evb.observer = observer
	evb.contentRouter.SetObserver(observer)
	evb.documentBridge.SetObserver(observer)
	evb.metadataBridge.SetObserver(observer)
}

// SetPerformanceMonitor sets the performance monitor for the bridge
func (evb *EnhancedValidatorBridge) SetPerformanceMonitor(monitor *performance.PerformanceMonitor) {
	evb.performanceMonitor = monitor
}

// SetObservabilityHooks sets the observability hooks for the bridge
func (evb *EnhancedValidatorBridge) SetObservabilityHooks(hooks *performance.ObservabilityHooks) {
	evb.observabilityHooks = hooks
}

// RegisterDocumentValidator registers a validator for document body content
func (evb *EnhancedValidatorBridge) RegisterDocumentValidator(validator detector.Validator) {
	evb.documentBridge.RegisterValidator(validator)
}

// SetMetadataValidator sets the metadata validator
func (evb *EnhancedValidatorBridge) SetMetadataValidator(validator PreprocessorAwareValidator) {
	evb.metadataBridge.SetValidator(validator)
}

// ProcessContent processes content using the dual-path validation system
func (evb *EnhancedValidatorBridge) ProcessContent(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	if content == nil {
		return nil, fmt.Errorf("processed content is nil")
	}

	startTime := time.Now()

	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if evb.observer != nil {
		finishTiming = evb.observer.StartTiming("enhanced_validator_bridge", "process_content", content.OriginalPath)
		if evb.observer.DebugObserver != nil {
			finishStep = evb.observer.DebugObserver.StartStep("enhanced_validator_bridge", "process_content", content.OriginalPath)
		}
	}

	// Perform context analysis if enabled
	var contextInsights context.ContextInsights
	if evb.config.EnableContextIntegration {
		contextStartTime := time.Now()
		contextInsights = evb.contextAnalyzer.AnalyzeContext(content.Text, content.OriginalPath)
		evb.updateContextMetrics(time.Since(contextStartTime))

		if evb.observer != nil && evb.observer.DebugObserver != nil {
			evb.observer.DebugObserver.LogDetail("context_analysis", fmt.Sprintf("Domain: %s, DocumentType: %s, Confidence: %.2f",
				contextInsights.Domain, contextInsights.DocumentType, contextInsights.DomainConfidence))
		}
	}

	// Route content using Content Router with retry logic
	routingStartTime := time.Now()
	routedContent, err := evb.routeContentWithRetry(content)
	routingTime := time.Since(routingStartTime)
	evb.updateRoutingMetrics(routingTime, err == nil)

	// Record performance metrics for content routing
	if evb.performanceMonitor != nil {
		errorType := ""
		if err != nil {
			errorType = "routing_failure"
		}
		evb.performanceMonitor.RecordContentRoutingOperation(routingTime, err == nil, errorType)

		if routedContent != nil {
			evb.performanceMonitor.RecordContentSeparation(
				routedContent.DocumentBody != "",
				len(routedContent.Metadata) > 0,
				len(routedContent.Metadata))
		}
	}

	// Trigger observability hooks for content routing
	if evb.observabilityHooks != nil && routedContent != nil {
		// Extract file type filtering information
		fileExt := strings.ToLower(filepath.Ext(content.OriginalPath))
		metadataSkipped := len(routedContent.Metadata) == 0 && routedContent.DocumentBody != ""
		skipReason := ""
		if metadataSkipped {
			skipReason = "file_type_no_metadata"
		}

		decision := &performance.ContentRoutingDecision{
			FilePath:          content.OriginalPath,
			DocumentBodyFound: routedContent.DocumentBody != "",
			MetadataFound:     len(routedContent.Metadata) > 0,
			PreprocessorTypes: evb.extractPreprocessorTypes(routedContent.Metadata),
			RoutingTime:       routingTime,
			ConfidenceScore:   evb.calculateRoutingConfidence(routedContent),
			DecisionReasoning: evb.generateRoutingReasoning(routedContent),

			// File type filtering information
			FileExtension:      fileExt,
			CanContainMetadata: len(routedContent.Metadata) > 0 || !metadataSkipped,
			MetadataType:       evb.determineMetadataTypeFromContent(routedContent),
			MetadataSkipped:    metadataSkipped,
			SkipReason:         skipReason,
		}
		evb.observabilityHooks.TriggerContentRoutingHooks(decision)
	}

	if err != nil {
		// Fallback to legacy aggregation behavior
		if evb.config.EnableFallbackMode {
			if evb.observer != nil {
				evb.observer.LogOperation(observability.StandardObservabilityData{
					Component: "enhanced_validator_bridge",
					Operation: "fallback_activation",
					FilePath:  content.OriginalPath,
					Success:   true,
					Error:     fmt.Sprintf("Content routing failed: %v", err),
				})
			}

			evb.metrics.mu.Lock()
			evb.metrics.FallbackActivations++
			evb.metrics.mu.Unlock()

			return evb.processContentLegacy(content, contextInsights)
		}

		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error(), "fallback_used": false})
		}
		if finishStep != nil {
			finishStep(false, fmt.Sprintf("Content routing failed: %v", err))
		}
		return nil, fmt.Errorf("content routing failed and fallback disabled: %w", err)
	}

	// Process content through dual paths
	result, err := evb.processDualPath(routedContent, contextInsights)
	if err != nil {
		// Try fallback if dual path processing fails
		if evb.config.EnableFallbackMode {
			if evb.observer != nil {
				evb.observer.LogOperation(observability.StandardObservabilityData{
					Component: "enhanced_validator_bridge",
					Operation: "dual_path_fallback",
					FilePath:  content.OriginalPath,
					Success:   true,
					Error:     fmt.Sprintf("Dual path processing failed: %v", err),
				})
			}

			evb.metrics.mu.Lock()
			evb.metrics.FallbackActivations++
			evb.metrics.mu.Unlock()

			// Record fallback activation
			evb.recordFallbackActivation(fmt.Sprintf("dual_path_processing_failed: %v", err))

			return evb.processContentLegacy(content, contextInsights)
		}

		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		if finishStep != nil {
			finishStep(false, fmt.Sprintf("Dual path processing failed: %v", err))
		}
		return nil, err
	}

	// Update overall metrics
	evb.updateOverallMetrics(time.Since(startTime), true)

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"total_matches":    len(result.AllMatches),
			"document_matches": len(result.DocumentMatches),
			"metadata_matches": len(result.MetadataMatches),
			"routing_success":  result.RoutingSuccess,
			"fallback_used":    result.FallbackUsed,
			"processing_time":  result.ProcessingTime.Milliseconds(),
		})
	}
	if finishStep != nil {
		finishStep(true, fmt.Sprintf("Processed %d total matches (%d document, %d metadata)",
			len(result.AllMatches), len(result.DocumentMatches), len(result.MetadataMatches)))
	}

	return result.AllMatches, nil
}

// processDualPath processes content through both validation paths
func (evb *EnhancedValidatorBridge) processDualPath(routedContent *router.RoutedContent, contextInsights context.ContextInsights) (*DualPathValidationResult, error) {
	startTime := time.Now()

	result := &DualPathValidationResult{
		ContextInsights: contextInsights,
		RoutingSuccess:  true,
		FallbackUsed:    false,
		ProcessingTime:  0, // Will be set at the end
	}

	var wg sync.WaitGroup
	var documentErr, metadataErr error
	var documentProcessingTime, metadataProcessingTime time.Duration

	// Process document body content in parallel
	if routedContent.DocumentBody != "" {
		// Trigger validation started hook for document path
		evb.triggerValidationHooks("document", routedContent.OriginalPath, nil)

		wg.Add(1)
		go func() {
			defer wg.Done()
			docStartTime := time.Now()
			matches, err := evb.documentBridge.ProcessDocumentContent(routedContent.DocumentBody, routedContent.OriginalPath, contextInsights)
			documentProcessingTime = time.Since(docStartTime)

			// Record performance metrics for document path
			avgConfidence := 0.0
			if len(matches) > 0 {
				totalConfidence := 0.0
				for _, match := range matches {
					totalConfidence += match.Confidence
				}
				avgConfidence = totalConfidence / float64(len(matches))
			}
			evb.recordValidationPathPerformance(false, documentProcessingTime, err == nil, len(matches), avgConfidence)

			// Trigger validation completed hook for document path
			validationResult := &performance.ValidationResult{
				ValidationType:    "document",
				FilePath:          routedContent.OriginalPath,
				MatchCount:        len(matches),
				AverageConfidence: avgConfidence,
				ProcessingTime:    documentProcessingTime,
				Success:           err == nil,
				Error:             err,
			}
			evb.triggerValidationHooks("document", routedContent.OriginalPath, validationResult)

			if err != nil {
				documentErr = err
				if evb.observer != nil {
					evb.observer.LogOperation(observability.StandardObservabilityData{
						Component: "enhanced_validator_bridge",
						Operation: "document_path_error",
						FilePath:  routedContent.OriginalPath,
						Success:   false,
						Error:     err.Error(),
					})
				}
				return
			}
			result.DocumentMatches = matches
		}()
	}

	// Process metadata content in parallel
	if len(routedContent.Metadata) > 0 {
		// Trigger validation started hook for metadata path
		evb.triggerValidationHooks("metadata", routedContent.OriginalPath, nil)

		wg.Add(1)
		go func() {
			defer wg.Done()
			metaStartTime := time.Now()
			matches, err := evb.metadataBridge.ProcessMetadataContent(routedContent.Metadata, contextInsights)
			metadataProcessingTime = time.Since(metaStartTime)

			// Record performance metrics for metadata path
			avgConfidence := 0.0
			if len(matches) > 0 {
				totalConfidence := 0.0
				for _, match := range matches {
					totalConfidence += match.Confidence
				}
				avgConfidence = totalConfidence / float64(len(matches))
			}
			evb.recordValidationPathPerformance(true, metadataProcessingTime, err == nil, len(matches), avgConfidence)

			// Trigger validation completed hook for metadata path
			validationResult := &performance.ValidationResult{
				ValidationType:    "metadata",
				FilePath:          routedContent.OriginalPath,
				MatchCount:        len(matches),
				AverageConfidence: avgConfidence,
				ProcessingTime:    metadataProcessingTime,
				Success:           err == nil,
				Error:             err,
			}
			evb.triggerValidationHooks("metadata", routedContent.OriginalPath, validationResult)

			if err != nil {
				metadataErr = err
				if evb.observer != nil {
					evb.observer.LogOperation(observability.StandardObservabilityData{
						Component: "enhanced_validator_bridge",
						Operation: "metadata_path_error",
						FilePath:  routedContent.OriginalPath,
						Success:   false,
						Error:     err.Error(),
					})
				}
				return
			}
			result.MetadataMatches = matches
		}()
	}

	// Wait for both paths to complete
	wg.Wait()

	// Update path-specific timing metrics
	evb.metrics.mu.Lock()
	evb.metrics.DocumentPathTime = documentProcessingTime
	evb.metrics.MetadataPathTime = metadataProcessingTime
	evb.metrics.mu.Unlock()

	// Handle errors with partial success capability
	var processingErrors []error
	if documentErr != nil {
		processingErrors = append(processingErrors, fmt.Errorf("document validation failed: %w", documentErr))
	}
	if metadataErr != nil {
		processingErrors = append(processingErrors, fmt.Errorf("metadata validation failed: %w", metadataErr))
	}

	// If both paths failed, return error
	if len(processingErrors) == 2 {
		return nil, fmt.Errorf("both validation paths failed: document=%v, metadata=%v", documentErr, metadataErr)
	}

	// Log partial failures but continue with successful results
	if len(processingErrors) > 0 && evb.observer != nil && evb.observer.DebugObserver != nil {
		for _, procErr := range processingErrors {
			evb.observer.DebugObserver.LogDetail("partial_validation_failure", procErr.Error())
		}
	}

	// Combine all matches
	result.AllMatches = make([]detector.Match, 0, len(result.DocumentMatches)+len(result.MetadataMatches))
	result.AllMatches = append(result.AllMatches, result.DocumentMatches...)
	result.AllMatches = append(result.AllMatches, result.MetadataMatches...)

	// Apply cross-path confidence adjustments based on context
	result.AllMatches = evb.applyCrossPathConfidenceAdjustments(result.AllMatches, contextInsights)

	// Trigger cross-path correlation hooks if both paths found matches
	if evb.observabilityHooks != nil && len(result.DocumentMatches) > 0 && len(result.MetadataMatches) > 0 {
		correlationBoost := 5.0 // This should match the boost applied in applyCrossPathConfidenceAdjustments
		evb.observabilityHooks.TriggerCrossPathCorrelationHooks(len(result.DocumentMatches), len(result.MetadataMatches), correlationBoost)
	}

	result.ProcessingTime = time.Since(startTime)
	return result, nil
}

// applyCrossPathConfidenceAdjustments applies confidence adjustments based on cross-path analysis
func (evb *EnhancedValidatorBridge) applyCrossPathConfidenceAdjustments(matches []detector.Match, contextInsights context.ContextInsights) []detector.Match {
	if len(matches) == 0 {
		return matches
	}

	// Group matches by validation path
	documentMatches := make([]detector.Match, 0)
	metadataMatches := make([]detector.Match, 0)

	for _, match := range matches {
		if match.Metadata != nil {
			if preprocessorType, exists := match.Metadata["preprocessor_type"]; exists && preprocessorType != nil {
				metadataMatches = append(metadataMatches, match)
			} else {
				documentMatches = append(documentMatches, match)
			}
		} else {
			documentMatches = append(documentMatches, match)
		}
	}

	// Apply cross-path correlation boosts
	if len(documentMatches) > 0 && len(metadataMatches) > 0 {
		// Both paths found matches - apply correlation boost
		correlationBoost := 5.0

		for i := range matches {
			originalConfidence := matches[i].Confidence
			matches[i].Confidence += correlationBoost

			// Ensure confidence stays within bounds
			if matches[i].Confidence > 100 {
				matches[i].Confidence = 100
			}

			// Add correlation information to metadata
			if matches[i].Metadata == nil {
				matches[i].Metadata = make(map[string]interface{})
			}
			matches[i].Metadata["cross_path_correlation"] = true
			matches[i].Metadata["correlation_boost"] = correlationBoost
			matches[i].Metadata["original_confidence"] = originalConfidence
		}

		if evb.observer != nil && evb.observer.DebugObserver != nil {
			evb.observer.DebugObserver.LogDetail("cross_path_correlation",
				fmt.Sprintf("Applied %.1f correlation boost to %d matches", correlationBoost, len(matches)))
		}
	}

	return matches
}

// routeContentWithRetry attempts content routing with retry logic
func (evb *EnhancedValidatorBridge) routeContentWithRetry(content *preprocessors.ProcessedContent) (*router.RoutedContent, error) {
	var lastErr error
	maxRetries := evb.config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		routedContent, err := evb.contentRouter.RouteContent(content)
		if err == nil {
			return routedContent, nil
		}

		lastErr = err
		if evb.observer != nil && evb.observer.DebugObserver != nil {
			evb.observer.DebugObserver.LogDetail("routing_retry",
				fmt.Sprintf("Routing attempt %d/%d failed: %v", attempt, maxRetries, err))
		}

		// Don't retry on certain types of errors
		if strings.Contains(err.Error(), "nil") || strings.Contains(err.Error(), "invalid") {
			break
		}
	}

	return nil, fmt.Errorf("content routing failed after %d attempts: %w", maxRetries, lastErr)
}

// processContentLegacy provides fallback to legacy aggregation behavior
func (evb *EnhancedValidatorBridge) processContentLegacy(content *preprocessors.ProcessedContent, contextInsights context.ContextInsights) ([]detector.Match, error) {
	if evb.observer != nil && evb.observer.DebugObserver != nil {
		evb.observer.DebugObserver.LogDetail("fallback", "Using legacy content aggregation")
	}

	// Process content with all validators using legacy approach
	var allMatches []detector.Match
	var processingErrors []error

	// Process with document validators
	documentMatches, err := evb.documentBridge.ProcessDocumentContent(content.Text, content.OriginalPath, contextInsights)
	if err != nil {
		processingErrors = append(processingErrors, fmt.Errorf("document validation failed: %w", err))
		if evb.observer != nil {
			evb.observer.LogOperation(observability.StandardObservabilityData{
				Component: "enhanced_validator_bridge",
				Operation: "legacy_document_error",
				FilePath:  content.OriginalPath,
				Success:   false,
				Error:     err.Error(),
			})
		}
	} else {
		allMatches = append(allMatches, documentMatches...)
	}

	// Process with metadata validator if available
	if evb.metadataBridge.metadataValidator != nil {
		metadataMatches, err := evb.metadataBridge.metadataValidator.ValidateContent(content.Text, content.OriginalPath)
		if err != nil {
			processingErrors = append(processingErrors, fmt.Errorf("metadata validation failed: %w", err))
			if evb.observer != nil {
				evb.observer.LogOperation(observability.StandardObservabilityData{
					Component: "enhanced_validator_bridge",
					Operation: "legacy_metadata_error",
					FilePath:  content.OriginalPath,
					Success:   false,
					Error:     err.Error(),
				})
			}
		} else {
			allMatches = append(allMatches, metadataMatches...)
		}
	}

	// Log processing errors but don't fail completely
	if len(processingErrors) > 0 && evb.observer != nil && evb.observer.DebugObserver != nil {
		for _, procErr := range processingErrors {
			evb.observer.DebugObserver.LogDetail("legacy_processing_errors", procErr.Error())
		}
	}

	return allMatches, nil
}

// RegisterValidator registers a validator for document body content (legacy compatibility)
func (dvb *DocumentValidatorBridge) RegisterValidator(validator detector.Validator) {
	dvb.mu.Lock()
	defer dvb.mu.Unlock()
	dvb.validators = append(dvb.validators, validator)
}

// SetObserver sets the observability component
func (dvb *DocumentValidatorBridge) SetObserver(observer *observability.StandardObserver) {
	dvb.observer = observer
}

// ProcessDocumentContent processes document body content with non-metadata validators
func (dvb *DocumentValidatorBridge) ProcessDocumentContent(content, filePath string, contextInsights context.ContextInsights) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if dvb.observer != nil {
		finishTiming = dvb.observer.StartTiming("document_validator_bridge", "process_content", filePath)
	}

	var allMatches []detector.Match
	startTime := time.Now()

	dvb.mu.RLock()
	validators := make([]detector.Validator, len(dvb.validators))
	copy(validators, dvb.validators)
	dvb.mu.RUnlock()

	if len(validators) == 0 {
		if dvb.observer != nil && dvb.observer.DebugObserver != nil {
			dvb.observer.DebugObserver.LogDetail("document_bridge", "No document validators registered")
		}
		return allMatches, nil
	}

	// Process content with each validator
	validationErrors := make([]error, 0)
	for _, validator := range validators {
		matches, err := validator.ValidateContent(content, filePath)
		if err != nil {
			validationErrors = append(validationErrors, err)
			if dvb.observer != nil {
				dvb.observer.LogOperation(observability.StandardObservabilityData{
					Component: "document_validator_bridge",
					Operation: "validator_error",
					FilePath:  filePath,
					Success:   false,
					Error:     err.Error(),
				})
			}
			continue
		}

		// Apply context-based confidence adjustments if context integration is enabled
		if contextInsights.Domain != "" {
			for i := range matches {
				// Get validator name for context adjustment
				validatorName := matches[i].Validator
				if validatorName == "" {
					validatorName = "unknown"
				}

				adjustment := dvb.contextAnalyzer.GetConfidenceAdjustment(contextInsights, validatorName)
				originalConfidence := matches[i].Confidence
				matches[i].Confidence += adjustment

				// Ensure confidence stays within bounds
				if matches[i].Confidence > 100 {
					matches[i].Confidence = 100
				} else if matches[i].Confidence < 0 {
					matches[i].Confidence = 0
				}

				// Add context information to metadata
				if matches[i].Metadata == nil {
					matches[i].Metadata = make(map[string]interface{})
				}
				matches[i].Metadata["context_domain"] = contextInsights.Domain
				matches[i].Metadata["context_doctype"] = contextInsights.DocumentType
				matches[i].Metadata["context_confidence"] = contextInsights.DomainConfidence
				matches[i].Metadata["confidence_adjustment"] = adjustment
				matches[i].Metadata["original_confidence"] = originalConfidence
				matches[i].Metadata["validation_path"] = "document"

				// Add semantic context information
				if len(contextInsights.SemanticContext) > 0 {
					matches[i].Metadata["semantic_context"] = contextInsights.SemanticContext
				}
			}
		} else {
			// Even without context, mark as document path
			for i := range matches {
				if matches[i].Metadata == nil {
					matches[i].Metadata = make(map[string]interface{})
				}
				matches[i].Metadata["validation_path"] = "document"
			}
		}

		allMatches = append(allMatches, matches...)
	}

	// Log validation errors but don't fail completely if some validators succeeded
	if len(validationErrors) > 0 && dvb.observer != nil && dvb.observer.DebugObserver != nil {
		dvb.observer.DebugObserver.LogDetail("document_validation_errors",
			fmt.Sprintf("%d out of %d validators failed", len(validationErrors), len(validators)))
	}

	// Update metrics
	dvb.updateMetrics(len(allMatches), time.Since(startTime))

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":       len(allMatches),
			"validator_count":   len(validators),
			"processing_time":   time.Since(startTime).Milliseconds(),
			"validation_errors": len(validationErrors),
		})
	}

	return allMatches, nil
}

// SetValidator sets the metadata validator
func (mvb *MetadataValidatorBridge) SetValidator(validator PreprocessorAwareValidator) {
	mvb.mu.Lock()
	defer mvb.mu.Unlock()
	mvb.metadataValidator = validator
}

// SetObserver sets the observability component
func (mvb *MetadataValidatorBridge) SetObserver(observer *observability.StandardObserver) {
	mvb.observer = observer
}

// ProcessMetadataContent processes metadata content exclusively with metadata validator
func (mvb *MetadataValidatorBridge) ProcessMetadataContent(metadataItems []router.MetadataContent, contextInsights context.ContextInsights) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if mvb.observer != nil {
		finishTiming = mvb.observer.StartTiming("metadata_validator_bridge", "process_content", "metadata")
	}

	mvb.mu.RLock()
	validator := mvb.metadataValidator
	mvb.mu.RUnlock()

	if validator == nil {
		if mvb.observer != nil && mvb.observer.DebugObserver != nil {
			mvb.observer.DebugObserver.LogDetail("metadata_bridge", "No metadata validator configured")
		}
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": "no metadata validator configured"})
		}
		return []detector.Match{}, fmt.Errorf("no metadata validator configured")
	}

	if len(metadataItems) == 0 {
		if mvb.observer != nil && mvb.observer.DebugObserver != nil {
			mvb.observer.DebugObserver.LogDetail("metadata_bridge", "No metadata items to process - file type does not support metadata validation")
			mvb.observer.DebugObserver.LogMetric("metadata_validator_skip", "files_skipped_no_metadata", 1)
		}

		// Update skip metrics
		mvb.updateSkipMetrics("no_metadata_items")

		if finishTiming != nil {
			finishTiming(true, map[string]interface{}{
				"match_count":    0,
				"metadata_items": 0,
				"skipped_reason": "no_metadata_items",
				"skip_category":  "file_type_filtering",
			})
		}
		return []detector.Match{}, nil
	}

	var allMatches []detector.Match
	startTime := time.Now()
	validationErrors := make([]error, 0)

	// Process each metadata item
	for _, metadataItem := range metadataItems {
		matches, err := validator.ValidateMetadataContent(metadataItem)
		if err != nil {
			validationErrors = append(validationErrors, err)
			if mvb.observer != nil {
				mvb.observer.LogOperation(observability.StandardObservabilityData{
					Component: "metadata_validator_bridge",
					Operation: "validation_error",
					FilePath:  metadataItem.SourceFile,
					Success:   false,
					Error:     err.Error(),
				})
			}
			continue
		}

		// Apply context-based confidence adjustments if context integration is enabled
		if contextInsights.Domain != "" {
			for i := range matches {
				// Use metadata-specific context adjustment
				adjustment := mvb.contextAnalyzer.GetConfidenceAdjustment(contextInsights, "metadata")

				// Apply preprocessor-specific adjustments
				preprocessorAdjustment := mvb.getPreprocessorSpecificAdjustment(metadataItem.PreprocessorType, contextInsights)
				totalAdjustment := adjustment + preprocessorAdjustment

				originalConfidence := matches[i].Confidence
				matches[i].Confidence += totalAdjustment

				// Ensure confidence stays within bounds
				if matches[i].Confidence > 100 {
					matches[i].Confidence = 100
				} else if matches[i].Confidence < 0 {
					matches[i].Confidence = 0
				}

				// Add comprehensive context and preprocessor information to metadata
				if matches[i].Metadata == nil {
					matches[i].Metadata = make(map[string]interface{})
				}
				matches[i].Metadata["context_domain"] = contextInsights.Domain
				matches[i].Metadata["context_doctype"] = contextInsights.DocumentType
				matches[i].Metadata["context_confidence"] = contextInsights.DomainConfidence
				matches[i].Metadata["confidence_adjustment"] = adjustment
				matches[i].Metadata["preprocessor_adjustment"] = preprocessorAdjustment
				matches[i].Metadata["total_adjustment"] = totalAdjustment
				matches[i].Metadata["original_confidence"] = originalConfidence
				matches[i].Metadata["preprocessor_type"] = metadataItem.PreprocessorType
				matches[i].Metadata["preprocessor_name"] = metadataItem.PreprocessorName
				matches[i].Metadata["validation_path"] = "metadata"

				// Add semantic context information
				if len(contextInsights.SemanticContext) > 0 {
					matches[i].Metadata["semantic_context"] = contextInsights.SemanticContext
				}

				// Add cross-validator signals if available
				if len(contextInsights.CrossValidatorSignals) > 0 {
					matches[i].Metadata["cross_validator_signals"] = len(contextInsights.CrossValidatorSignals)
				}
			}
		} else {
			// Even without context, add preprocessor information
			for i := range matches {
				if matches[i].Metadata == nil {
					matches[i].Metadata = make(map[string]interface{})
				}
				matches[i].Metadata["preprocessor_type"] = metadataItem.PreprocessorType
				matches[i].Metadata["preprocessor_name"] = metadataItem.PreprocessorName
				matches[i].Metadata["validation_path"] = "metadata"
			}
		}

		allMatches = append(allMatches, matches...)

		// Update preprocessor breakdown metrics
		mvb.metrics.mu.Lock()
		mvb.metrics.PreprocessorBreakdown[metadataItem.PreprocessorType] += int64(len(matches))
		mvb.metrics.mu.Unlock()
	}

	// Log validation errors but don't fail completely if some items succeeded
	if len(validationErrors) > 0 && mvb.observer != nil && mvb.observer.DebugObserver != nil {
		mvb.observer.DebugObserver.LogDetail("metadata_validation_errors",
			fmt.Sprintf("%d out of %d metadata items failed validation", len(validationErrors), len(metadataItems)))
	}

	// Update metrics
	mvb.updateMetrics(int64(len(metadataItems)), len(allMatches), time.Since(startTime))

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":       len(allMatches),
			"metadata_items":    len(metadataItems),
			"processing_time":   time.Since(startTime).Milliseconds(),
			"validation_errors": len(validationErrors),
		})
	}

	return allMatches, nil
}

// getPreprocessorSpecificAdjustment returns confidence adjustments specific to preprocessor types
func (mvb *MetadataValidatorBridge) getPreprocessorSpecificAdjustment(preprocessorType string, contextInsights context.ContextInsights) float64 {
	adjustment := 0.0

	// Apply domain-specific preprocessor adjustments
	switch contextInsights.Domain {
	case "Healthcare":
		switch preprocessorType {
		case router.PreprocessorTypeDocumentMetadata:
			adjustment += 10.0 // Healthcare documents often have sensitive metadata
		case router.PreprocessorTypeImageMetadata:
			adjustment += 15.0 // Medical images often contain GPS/device info
		}
	case "Financial":
		switch preprocessorType {
		case router.PreprocessorTypeDocumentMetadata:
			adjustment += 12.0 // Financial documents have sensitive author/company info
		}
	case "HR_Payroll":
		switch preprocessorType {
		case router.PreprocessorTypeDocumentMetadata:
			adjustment += 15.0 // HR documents have highly sensitive metadata
		}
	}

	// Apply document type specific adjustments
	switch contextInsights.DocumentType {
	case "Report":
		adjustment += 5.0 // Reports often have sensitive metadata
	case "Email":
		adjustment += 8.0 // Email metadata is often sensitive
	}

	return adjustment
}

// Helper methods for metrics updates

func (evb *EnhancedValidatorBridge) updateOverallMetrics(processingTime time.Duration, success bool) {
	evb.metrics.mu.Lock()
	defer evb.metrics.mu.Unlock()

	evb.metrics.TotalValidations++
	if success {
		evb.metrics.SuccessfulValidations++
	} else {
		evb.metrics.FailedValidations++
	}

	// Update average processing time
	if evb.metrics.TotalValidations == 1 {
		evb.metrics.AverageProcessingTime = processingTime
	} else {
		// Running average
		evb.metrics.AverageProcessingTime = time.Duration(
			(int64(evb.metrics.AverageProcessingTime)*int64(evb.metrics.TotalValidations-1) +
				int64(processingTime)) / int64(evb.metrics.TotalValidations))
	}
}

func (evb *EnhancedValidatorBridge) updateRoutingMetrics(routingTime time.Duration, success bool) {
	evb.metrics.mu.Lock()
	defer evb.metrics.mu.Unlock()

	evb.metrics.RoutingTime = routingTime
	if success {
		evb.metrics.RoutingSuccesses++
	} else {
		evb.metrics.RoutingFailures++
	}
}

func (evb *EnhancedValidatorBridge) updateContextMetrics(contextTime time.Duration) {
	evb.metrics.mu.Lock()
	defer evb.metrics.mu.Unlock()
	evb.metrics.ContextAnalysisTime = contextTime
}

func (dvb *DocumentValidatorBridge) updateMetrics(matchCount int, processingTime time.Duration) {
	dvb.metrics.mu.Lock()
	defer dvb.metrics.mu.Unlock()

	dvb.metrics.ValidationsProcessed++
	dvb.metrics.MatchesFound += int64(matchCount)
	dvb.metrics.ProcessingTime = processingTime

	// Update average confidence if matches were found
	if matchCount > 0 {
		// This is a simplified average - in a real implementation you'd track actual confidence values
		dvb.metrics.AverageConfidence = (dvb.metrics.AverageConfidence + 70.0) / 2.0 // Placeholder calculation
	}
}

func (mvb *MetadataValidatorBridge) updateMetrics(itemsProcessed int64, matchCount int, processingTime time.Duration) {
	mvb.metrics.mu.Lock()
	defer mvb.metrics.mu.Unlock()

	mvb.metrics.MetadataItemsProcessed += itemsProcessed
	mvb.metrics.MatchesFound += int64(matchCount)
	mvb.metrics.ProcessingTime = processingTime

	// Update average confidence if matches were found
	if matchCount > 0 {
		// This is a simplified average - in a real implementation you'd track actual confidence values
		mvb.metrics.AverageConfidence = (mvb.metrics.AverageConfidence + 75.0) / 2.0 // Placeholder calculation
	}
}

// updateSkipMetrics tracks when metadata validation is skipped due to file type filtering
func (mvb *MetadataValidatorBridge) updateSkipMetrics(reason string) {
	mvb.metrics.mu.Lock()
	defer mvb.metrics.mu.Unlock()

	mvb.metrics.FilesSkipped++
	mvb.metrics.SkipReasons[reason]++
}

// GetMetrics returns current metrics for monitoring
func (evb *EnhancedValidatorBridge) GetMetrics() *DualPathMetrics {
	evb.metrics.mu.RLock()
	defer evb.metrics.mu.RUnlock()

	// Return a copy to avoid race conditions, excluding the mutex
	metricsCopy := DualPathMetrics{
		TotalValidations:      evb.metrics.TotalValidations,
		SuccessfulValidations: evb.metrics.SuccessfulValidations,
		FailedValidations:     evb.metrics.FailedValidations,
		FallbackActivations:   evb.metrics.FallbackActivations,
		AverageProcessingTime: evb.metrics.AverageProcessingTime,
		DocumentPathTime:      evb.metrics.DocumentPathTime,
		MetadataPathTime:      evb.metrics.MetadataPathTime,
		RoutingTime:           evb.metrics.RoutingTime,
		RoutingSuccesses:      evb.metrics.RoutingSuccesses,
		RoutingFailures:       evb.metrics.RoutingFailures,
		ContextAnalysisTime:   evb.metrics.ContextAnalysisTime,
		ContextBoosts:         evb.metrics.ContextBoosts,
		ContextPenalties:      evb.metrics.ContextPenalties,
		// Note: mu field is intentionally omitted to avoid copying the mutex
	}
	return &metricsCopy
}

// GetDetailedMetrics returns comprehensive metrics from all bridges
func (evb *EnhancedValidatorBridge) GetDetailedMetrics() map[string]interface{} {
	evb.metrics.mu.RLock()
	defer evb.metrics.mu.RUnlock()

	metrics := make(map[string]interface{})

	// Overall metrics
	metrics["total_validations"] = evb.metrics.TotalValidations
	metrics["successful_validations"] = evb.metrics.SuccessfulValidations
	metrics["failed_validations"] = evb.metrics.FailedValidations
	metrics["fallback_activations"] = evb.metrics.FallbackActivations
	metrics["average_processing_time_ms"] = evb.metrics.AverageProcessingTime.Milliseconds()

	// Path-specific metrics
	metrics["document_path_time_ms"] = evb.metrics.DocumentPathTime.Milliseconds()
	metrics["metadata_path_time_ms"] = evb.metrics.MetadataPathTime.Milliseconds()
	metrics["routing_time_ms"] = evb.metrics.RoutingTime.Milliseconds()

	// Routing metrics
	metrics["routing_successes"] = evb.metrics.RoutingSuccesses
	metrics["routing_failures"] = evb.metrics.RoutingFailures
	if evb.metrics.RoutingSuccesses+evb.metrics.RoutingFailures > 0 {
		metrics["routing_success_rate"] = float64(evb.metrics.RoutingSuccesses) / float64(evb.metrics.RoutingSuccesses+evb.metrics.RoutingFailures)
	}

	// Context metrics
	metrics["context_analysis_time_ms"] = evb.metrics.ContextAnalysisTime.Milliseconds()
	metrics["context_boosts"] = evb.metrics.ContextBoosts
	metrics["context_penalties"] = evb.metrics.ContextPenalties

	// Document bridge metrics
	if evb.documentBridge != nil {
		evb.documentBridge.metrics.mu.RLock()
		metrics["document_validations_processed"] = evb.documentBridge.metrics.ValidationsProcessed
		metrics["document_matches_found"] = evb.documentBridge.metrics.MatchesFound
		metrics["document_average_confidence"] = evb.documentBridge.metrics.AverageConfidence
		metrics["document_processing_time_ms"] = evb.documentBridge.metrics.ProcessingTime.Milliseconds()
		evb.documentBridge.metrics.mu.RUnlock()
	}

	// Metadata bridge metrics
	if evb.metadataBridge != nil {
		evb.metadataBridge.metrics.mu.RLock()
		metrics["metadata_items_processed"] = evb.metadataBridge.metrics.MetadataItemsProcessed
		metrics["metadata_matches_found"] = evb.metadataBridge.metrics.MatchesFound
		metrics["metadata_average_confidence"] = evb.metadataBridge.metrics.AverageConfidence
		metrics["metadata_processing_time_ms"] = evb.metadataBridge.metrics.ProcessingTime.Milliseconds()
		metrics["preprocessor_breakdown"] = evb.metadataBridge.metrics.PreprocessorBreakdown

		// File type filtering metrics
		metrics["metadata_files_skipped"] = evb.metadataBridge.metrics.FilesSkipped
		metrics["metadata_skip_reasons"] = evb.metadataBridge.metrics.SkipReasons

		evb.metadataBridge.metrics.mu.RUnlock()
	}

	return metrics
}

// ResetMetrics resets all metrics counters
func (evb *EnhancedValidatorBridge) ResetMetrics() {
	evb.metrics.mu.Lock()
	defer evb.metrics.mu.Unlock()

	evb.metrics.TotalValidations = 0
	evb.metrics.SuccessfulValidations = 0
	evb.metrics.FailedValidations = 0
	evb.metrics.FallbackActivations = 0
	evb.metrics.RoutingSuccesses = 0
	evb.metrics.RoutingFailures = 0
	evb.metrics.ContextBoosts = 0
	evb.metrics.ContextPenalties = 0

	// Reset sub-bridge metrics
	if evb.documentBridge != nil {
		evb.documentBridge.metrics.mu.Lock()
		evb.documentBridge.metrics.ValidationsProcessed = 0
		evb.documentBridge.metrics.MatchesFound = 0
		evb.documentBridge.metrics.AverageConfidence = 0
		evb.documentBridge.metrics.mu.Unlock()
	}

	if evb.metadataBridge != nil {
		evb.metadataBridge.metrics.mu.Lock()
		evb.metadataBridge.metrics.MetadataItemsProcessed = 0
		evb.metadataBridge.metrics.MatchesFound = 0
		evb.metadataBridge.metrics.AverageConfidence = 0
		evb.metadataBridge.metrics.PreprocessorBreakdown = make(map[string]int64)

		// Reset file type filtering metrics
		evb.metadataBridge.metrics.FilesSkipped = 0
		evb.metadataBridge.metrics.SkipReasons = make(map[string]int64)

		evb.metadataBridge.metrics.mu.Unlock()
	}
}

// LogOperationalStatus logs the current operational status for monitoring
func (evb *EnhancedValidatorBridge) LogOperationalStatus() {
	if evb.observer == nil || evb.observer.DebugObserver == nil {
		return
	}

	metrics := evb.GetDetailedMetrics()

	evb.observer.DebugObserver.LogDetail("operational_status", "Enhanced Validator Bridge Status:")
	evb.observer.DebugObserver.LogDetail("operational_status", fmt.Sprintf("  Total Validations: %v", metrics["total_validations"]))
	evb.observer.DebugObserver.LogDetail("operational_status", fmt.Sprintf("  Success Rate: %.2f%%",
		float64(metrics["successful_validations"].(int64))/float64(metrics["total_validations"].(int64))*100))
	evb.observer.DebugObserver.LogDetail("operational_status", fmt.Sprintf("  Fallback Activations: %v", metrics["fallback_activations"]))
	evb.observer.DebugObserver.LogDetail("operational_status", fmt.Sprintf("  Routing Success Rate: %.2f%%",
		metrics["routing_success_rate"].(float64)*100))
	evb.observer.DebugObserver.LogDetail("operational_status", fmt.Sprintf("  Average Processing Time: %vms", metrics["average_processing_time_ms"]))
}

// getDefaultDualPathConfig returns default configuration
func getDefaultDualPathConfig() *DualPathConfig {
	return &DualPathConfig{
		EnableContextIntegration: true,
		EnableFallbackMode:       true,
		EnableMetrics:            true,
		EnableDebugLogging:       true,
		MaxRetries:               3,
		TimeoutDuration:          30 * time.Second,
	}
}

// Helper methods for performance monitoring and observability hooks

// extractPreprocessorTypes extracts preprocessor types from metadata content
func (evb *EnhancedValidatorBridge) extractPreprocessorTypes(metadata []router.MetadataContent) []string {
	types := make([]string, 0, len(metadata))
	for _, item := range metadata {
		types = append(types, item.PreprocessorType)
	}
	return types
}

// determineMetadataTypeFromContent determines the metadata type from routed content
func (evb *EnhancedValidatorBridge) determineMetadataTypeFromContent(routedContent *router.RoutedContent) string {
	if len(routedContent.Metadata) == 0 {
		return "none"
	}

	// Return the first metadata type found, or "mixed" if multiple types
	if len(routedContent.Metadata) == 1 {
		return routedContent.Metadata[0].PreprocessorType
	}

	// Check if all metadata items have the same type
	firstType := routedContent.Metadata[0].PreprocessorType
	for _, item := range routedContent.Metadata[1:] {
		if item.PreprocessorType != firstType {
			return "mixed"
		}
	}

	return firstType
}

// calculateRoutingConfidence calculates a confidence score for routing decisions
func (evb *EnhancedValidatorBridge) calculateRoutingConfidence(routedContent *router.RoutedContent) float64 {
	confidence := 0.0

	// Base confidence for successful routing
	confidence += 50.0

	// Boost for document body found
	if routedContent.DocumentBody != "" {
		confidence += 25.0
	}

	// Boost for metadata found
	if len(routedContent.Metadata) > 0 {
		confidence += 25.0

		// Additional boost for multiple preprocessor types
		if len(routedContent.Metadata) > 1 {
			confidence += 10.0
		}
	}

	// Ensure confidence is within bounds
	if confidence > 100.0 {
		confidence = 100.0
	}

	return confidence
}

// generateRoutingReasoning generates human-readable reasoning for routing decisions
func (evb *EnhancedValidatorBridge) generateRoutingReasoning(routedContent *router.RoutedContent) string {
	reasoning := "Content routing completed: "

	if routedContent.DocumentBody != "" {
		reasoning += "document body extracted, "
	}

	if len(routedContent.Metadata) > 0 {
		reasoning += fmt.Sprintf("%d metadata items found (%v)",
			len(routedContent.Metadata),
			evb.extractPreprocessorTypes(routedContent.Metadata))
	} else {
		reasoning += "no metadata found"
	}

	return reasoning
}

// recordValidationPathPerformance records performance metrics for validation paths
func (evb *EnhancedValidatorBridge) recordValidationPathPerformance(isMetadataPath bool, duration time.Duration, success bool, matchCount int, avgConfidence float64) {
	if evb.performanceMonitor != nil {
		evb.performanceMonitor.RecordValidationPathOperation(isMetadataPath, duration, success, matchCount, avgConfidence)
	}
}

// triggerValidationHooks triggers validation observability hooks
func (evb *EnhancedValidatorBridge) triggerValidationHooks(validationType, filePath string, result *performance.ValidationResult) {
	if evb.observabilityHooks != nil {
		if result == nil {
			evb.observabilityHooks.TriggerValidationStartedHooks(validationType, filePath)
		} else {
			evb.observabilityHooks.TriggerValidationCompletedHooks(result)
		}
	}
}

// recordFallbackActivation records when fallback mode is activated
func (evb *EnhancedValidatorBridge) recordFallbackActivation(reason string) {
	if evb.performanceMonitor != nil {
		evb.performanceMonitor.RecordFallbackActivation(reason)
	}

	if evb.observabilityHooks != nil {
		evb.observabilityHooks.TriggerFallbackActivatedHooks(reason, "")
	}
}
