// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	stdctx "context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/internal/context"
	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/execguard"
	"github.com/awslabs/ferret-scan/internal/observability"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
	"github.com/awslabs/ferret-scan/internal/router"
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

	// Metrics
	metrics *DualPathMetrics

	// Thread safety
	mu sync.RWMutex
}

// namedValidator pairs a document validator with its logical check name (e.g.
// "SSN", "IP_ADDRESS") so the dispatch chokepoint can key per-validator budgets
// and diagnostics by the operator-facing name rather than the Go type.
type namedValidator struct {
	name string
	v    detector.Validator
}

// DocumentValidatorBridge routes document body content to non-metadata validators
type DocumentValidatorBridge struct {
	validators      []namedValidator
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
		validators:      make([]namedValidator, 0),
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

// RegisterDocumentValidator registers a validator for document body content under
// its logical check name (e.g. "SSN"), used for per-validator budget keying and
// diagnostics at the dispatch chokepoint.
func (evb *EnhancedValidatorBridge) RegisterDocumentValidator(name string, validator detector.Validator) {
	evb.documentBridge.RegisterValidator(name, validator)
}

// SetMetadataValidator sets the metadata validator
func (evb *EnhancedValidatorBridge) SetMetadataValidator(validator PreprocessorAwareValidator) {
	evb.metadataBridge.SetValidator(validator)
}

// ProcessContent processes content using the dual-path validation system. It is
// a backward-compatible shim that runs with a background context.
func (evb *EnhancedValidatorBridge) ProcessContent(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	return evb.ProcessContentCtx(stdctx.Background(), content)
}

// ProcessContentCtx is the context-aware form of ProcessContent. The ctx is
// threaded down to the per-validator dispatch chokepoint so a deadline or
// cancellation can stop new validator work and recover panics.
func (evb *EnhancedValidatorBridge) ProcessContentCtx(ctx stdctx.Context, content *preprocessors.ProcessedContent) ([]detector.Match, error) {
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

			return evb.processContentLegacy(ctx, content, contextInsights)
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
	result, err := evb.processDualPath(ctx, routedContent, contextInsights)
	if err != nil {
		// A context cancellation/timeout OR a per-validator budget outcome (v2 Move
		// C: time/match budget) is terminal: do NOT fall back to a legacy re-run —
		// for a cancel it would re-invoke the same runaway validator and stall
		// again; for a budget it would wastefully re-scan and double-count. Return
		// the partial matches gathered so far with the error so callers can report
		// incomplete coverage.
		if ctxErr := ctx.Err(); ctxErr != nil || firstBudgetError([]error{err}) != nil {
			var partial []detector.Match
			if result != nil {
				partial = result.AllMatches
			}
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"error": err.Error(), "cancelled": true})
			}
			return partial, err
		}

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

			return evb.processContentLegacy(ctx, content, contextInsights)
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

// processDualPath processes content through both validation paths. ctx is
// threaded to the document-path dispatch chokepoint.
func (evb *EnhancedValidatorBridge) processDualPath(ctx stdctx.Context, routedContent *router.RoutedContent, contextInsights context.ContextInsights) (*DualPathValidationResult, error) {
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			docStartTime := time.Now()
			matches, err := evb.documentBridge.ProcessDocumentContentCtx(ctx, routedContent.DocumentBody, routedContent.OriginalPath, contextInsights)
			documentProcessingTime = time.Since(docStartTime)

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
				// A per-validator budget outcome (v2 Move C: match cap or time
				// budget) still carries the genuine matches gathered before the
				// budget fired — keep them (the error is recorded in documentErr so
				// the scan is flagged incomplete). Other errors discard the slice,
				// preserving historical behavior.
				if firstBudgetError([]error{err}) != nil {
					result.DocumentMatches = matches
				}
				return
			}
			result.DocumentMatches = matches
		}()
	}

	// Process metadata content in parallel
	if len(routedContent.Metadata) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metaStartTime := time.Now()
			matches, err := evb.metadataBridge.ProcessMetadataContentCtx(ctx, routedContent.Metadata, contextInsights)
			metadataProcessingTime = time.Since(metaStartTime)

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

	// If the run was cancelled/timed out, surface that as a scan-level error
	// carrying whatever partial matches we gathered. This is NOT a per-validator
	// "partial failure" to absorb — coverage is incomplete, and the caller must
	// propagate it (and must NOT fall back to a re-run, which would re-stall on
	// the same runaway validator). Checked before cross-path adjustments since
	// those assume a complete result set.
	if cerr := ctx.Err(); cerr != nil {
		result.ProcessingTime = time.Since(startTime)
		return result, cerr
	}

	// Apply cross-path confidence adjustments based on context
	result.AllMatches = evb.applyCrossPathConfidenceAdjustments(result.AllMatches, contextInsights)

	result.ProcessingTime = time.Since(startTime)

	// Surface a per-validator BUDGET outcome (v2 Move C) that occurred on a single
	// path: the matches gathered so far are complete and returned in result, but the
	// caller must flag ScanResult.Incomplete because a validator's time/match budget
	// cut its coverage short. (Full cancellation is handled at ctx.Err() above; both
	// paths failing is handled earlier.) No budgets configured => budgetErr nil =>
	// byte-identical return.
	if budgetErr := firstBudgetError([]error{documentErr, metadataErr}); budgetErr != nil {
		return result, budgetErr
	}
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

// processContentLegacy provides fallback to legacy aggregation behavior. ctx is
// threaded to the document-path dispatch chokepoint.
func (evb *EnhancedValidatorBridge) processContentLegacy(ctx stdctx.Context, content *preprocessors.ProcessedContent, contextInsights context.ContextInsights) ([]detector.Match, error) {
	if evb.observer != nil && evb.observer.DebugObserver != nil {
		evb.observer.DebugObserver.LogDetail("fallback", "Using legacy content aggregation")
	}

	// Process content with all validators using legacy approach
	var allMatches []detector.Match
	var processingErrors []error

	// Process with document validators
	documentMatches, err := evb.documentBridge.ProcessDocumentContentCtx(ctx, content.Text, content.OriginalPath, contextInsights)
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

	// Process with metadata validator if available. Dispatch through execguard
	// so a panic in the metadata validator is recovered rather than crashing
	// the process (v2 gap 1.3), matching the document path.
	if evb.metadataBridge.metadataValidator != nil {
		mv := evb.metadataBridge.metadataValidator
		metadataMatches, err := execguard.ValidateContent(ctx, fmt.Sprintf("%T", mv), mv, content.Text, content.OriginalPath)
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

// RegisterValidator registers a validator for document body content under its
// logical check name (e.g. "SSN"), preserved for budget keying and diagnostics.
func (dvb *DocumentValidatorBridge) RegisterValidator(name string, validator detector.Validator) {
	dvb.mu.Lock()
	defer dvb.mu.Unlock()
	dvb.validators = append(dvb.validators, namedValidator{name: name, v: validator})
}

// SetObserver sets the observability component
func (dvb *DocumentValidatorBridge) SetObserver(observer *observability.StandardObserver) {
	dvb.observer = observer
}

// validatorResult holds the result from a single validator execution
type validatorResult struct {
	matches []detector.Match
	err     error
}

// validatorName derives a stable, payload-free label for a validator from its
// concrete type, used only for diagnostics in execguard errors/logs. The
// detector.Validator interface exposes no name, so the type name is the best
// stable identifier available without changing the interface in Phase 1.
func validatorName(v detector.Validator) string {
	return fmt.Sprintf("%T", v)
}

// firstBudgetError returns the first error that represents a per-validator budget
// outcome — a time budget (context.DeadlineExceeded/Canceled) or a match-count cap
// (execguard.ErrMatchBudgetExceeded) — or nil if none. These are the errors that
// mean "coverage was cut short" and should surface as ScanResult.Incomplete;
// ordinary validator errors are deliberately excluded (historical behavior).
func firstBudgetError(errs []error) error {
	for _, err := range errs {
		if errors.Is(err, stdctx.DeadlineExceeded) ||
			errors.Is(err, stdctx.Canceled) ||
			errors.Is(err, execguard.ErrMatchBudgetExceeded) {
			return err
		}
	}
	return nil
}

// ProcessDocumentContent processes document body content with non-metadata
// validators. It is a backward-compatible shim that runs with a background
// context; new callers should use ProcessDocumentContentCtx so a deadline or
// cancellation can reach the dispatch boundary.
func (dvb *DocumentValidatorBridge) ProcessDocumentContent(content, filePath string, contextInsights context.ContextInsights) ([]detector.Match, error) {
	return dvb.ProcessDocumentContentCtx(stdctx.Background(), content, filePath, contextInsights)
}

// ProcessDocumentContentCtx is the context-aware form of ProcessDocumentContent.
// The ctx is threaded to the per-validator dispatch chokepoint (execguard), which
// (a) recovers panics so one validator cannot crash the process and (b) skips
// launching a validator once ctx is cancelled/expired. Validators that implement
// execguard.ContextAwareValidator additionally receive ctx to poll mid-run.
func (dvb *DocumentValidatorBridge) ProcessDocumentContentCtx(ctx stdctx.Context, content, filePath string, contextInsights context.ContextInsights) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if dvb.observer != nil {
		finishTiming = dvb.observer.StartTiming("document_validator_bridge", "process_content", filePath)
	}

	var allMatches []detector.Match
	startTime := time.Now()

	dvb.mu.RLock()
	validators := make([]namedValidator, len(dvb.validators))
	copy(validators, dvb.validators)
	dvb.mu.RUnlock()

	if len(validators) == 0 {
		if dvb.observer != nil && dvb.observer.DebugObserver != nil {
			dvb.observer.DebugObserver.LogDetail("document_bridge", "No document validators registered")
		}
		return allMatches, nil
	}

	// Create channel for results and WaitGroup for synchronization
	resultsChan := make(chan validatorResult, len(validators))
	var wg sync.WaitGroup
	var errorsMu sync.Mutex
	validationErrors := make([]error, 0)

	// Launch goroutines for each validator
	for _, validator := range validators {
		wg.Add(1)
		go func(nv namedValidator) {
			defer wg.Done()

			// Bound process-wide concurrent validator work (v2 gap 2.1): file
			// workers each fan out here, so without a shared cap the live
			// goroutine count is workers × validators. Acquire a token before
			// running; if ctx is cancelled while waiting, skip this validator
			// (no Release) and record the error — same outcome as the execguard
			// skip-on-cancel path. The token is held only for the validate call,
			// then released, so a stalled validator holds at most one slot.
			if lerr := execguard.DefaultLimiter.Acquire(ctx); lerr != nil {
				errorsMu.Lock()
				validationErrors = append(validationErrors, lerr)
				errorsMu.Unlock()
				resultsChan <- validatorResult{matches: nil, err: lerr}
				return
			}

			// Dispatch through the execguard chokepoint: recovers panics
			// (so one validator cannot crash the whole process — v2 gap 1.3),
			// threads ctx to context-aware validators / skips launch once ctx is
			// cancelled (v2 gap 1.1), and enforces the per-validator budget keyed
			// by the logical check name (v2 Move C). Behavior is unchanged for the
			// common success path.
			name := nv.name
			if name == "" {
				name = validatorName(nv.v) // fallback: Go type (unnamed registration)
			}
			matches, err := execguard.ValidateContent(ctx, name, nv.v, content, filePath)
			execguard.DefaultLimiter.Release()
			if err != nil {
				errorsMu.Lock()
				validationErrors = append(validationErrors, err)
				errorsMu.Unlock()

				if dvb.observer != nil {
					dvb.observer.LogOperation(observability.StandardObservabilityData{
						Component: "document_validator_bridge",
						Operation: "validator_error",
						FilePath:  filePath,
						Success:   false,
						Error:     err.Error(),
					})
				}
				// A match-budget hit is a "soft" outcome (v2 Move C): the truncated
				// matches are genuine findings and must be kept, unlike a real
				// validator error (which discards its partial slice). The error is
				// still recorded above so the scan is flagged incomplete.
				if errors.Is(err, execguard.ErrMatchBudgetExceeded) {
					resultsChan <- validatorResult{matches: matches, err: err}
					return
				}
				resultsChan <- validatorResult{matches: nil, err: err}
				return
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

			resultsChan <- validatorResult{matches: matches, err: nil}
		}(validator)
	}

	// Wait for all goroutines to complete, but do not block indefinitely on a
	// stalled validator: if ctx is cancelled/expired first, drain what has
	// arrived and return so the nested validation stack can unwind. This bounds
	// the goroutine/content leak from a runaway validator to the single
	// still-running leaf goroutine, instead of holding this join (and every
	// frame above it) forever. resultsChan is buffered to len(validators), so a
	// late goroutine can still send without blocking — we therefore do NOT
	// close it on the cancellation path, and we avoid reading the
	// mutex-guarded validationErrors slice there (a late append would race).
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// keepMatches reports whether a validator result's matches should be collected:
	// on success, or on a match-budget hit (the truncated matches are real findings
	// — v2 Move C). A real validator error still discards its partial slice.
	keepMatches := func(r validatorResult) bool {
		return r.matches != nil && (r.err == nil || errors.Is(r.err, execguard.ErrMatchBudgetExceeded))
	}

	select {
	case <-done:
		close(resultsChan)
		for result := range resultsChan {
			if keepMatches(result) {
				allMatches = append(allMatches, result.matches...)
			}
		}
	case <-ctx.Done():
		for draining := true; draining; {
			select {
			case result := <-resultsChan:
				if keepMatches(result) {
					allMatches = append(allMatches, result.matches...)
				}
			default:
				draining = false
			}
		}
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{
				"match_count":     len(allMatches),
				"validator_count": len(validators),
				"cancelled":       true,
			})
		}
		return allMatches, ctx.Err()
	}

	// Log validation errors but don't fail completely if some validators succeeded
	if len(validationErrors) > 0 && dvb.observer != nil && dvb.observer.DebugObserver != nil {
		dvb.observer.DebugObserver.LogDetail("document_validation_errors",
			fmt.Sprintf("%d out of %d validators failed", len(validationErrors), len(validators)))
	}

	// Surface a per-validator BUDGET or DEADLINE outcome (v2 Move C) so the caller
	// can flag ScanResult.Incomplete: a validator's own time budget (child
	// context.DeadlineExceeded) or match-count cap (ErrMatchBudgetExceeded) means
	// coverage was cut short even though the overall scan completed. Ordinary
	// validator errors keep the historical behavior (logged, not surfaced) so a
	// single failing validator does not by itself mark the scan incomplete. When
	// no budgets are configured there are no such errors — byte-identical path.
	if budgetErr := firstBudgetError(validationErrors); budgetErr != nil {
		return allMatches, budgetErr
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

// ProcessMetadataContent processes metadata content exclusively with the
// metadata validator. Backward-compatible shim that runs with a background
// context; new callers should use ProcessMetadataContentCtx.
func (mvb *MetadataValidatorBridge) ProcessMetadataContent(metadataItems []router.MetadataContent, contextInsights context.ContextInsights) ([]detector.Match, error) {
	return mvb.ProcessMetadataContentCtx(stdctx.Background(), metadataItems, contextInsights)
}

// ProcessMetadataContentCtx is the context-aware form of ProcessMetadataContent.
// Each metadata validator invocation is dispatched through the execguard
// chokepoint so a panic in the (large, complex) metadata validator is recovered
// rather than crashing the process (v2 gap 1.3), and the per-item loop stops
// early once ctx is cancelled/expired (v2 gap 1.1).
func (mvb *MetadataValidatorBridge) ProcessMetadataContentCtx(ctx stdctx.Context, metadataItems []router.MetadataContent, contextInsights context.ContextInsights) ([]detector.Match, error) {
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
		// Stop early if the deadline/cancellation has fired; surface ctx.Err()
		// so the caller can report incomplete coverage rather than a clean run.
		if cerr := ctx.Err(); cerr != nil {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"match_count": len(allMatches), "cancelled": true})
			}
			return allMatches, cerr
		}

		// Dispatch through execguard so a panic in the metadata validator is
		// recovered into a non-retryable error instead of crashing the process.
		item := metadataItem
		matches, err := execguard.SafeRun(ctx, fmt.Sprintf("%T", validator), func() ([]detector.Match, error) {
			return validator.ValidateMetadataContent(item)
		})
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
