// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
)

// EnhancedValidatorManager manages enhanced validators with streamlined features (no caching)
type EnhancedValidatorManager struct {
	// Core components
	contextAnalyzer *context.ContextAnalyzer
	observer        *observability.StandardObserver

	// Validators with enhanced capabilities
	enhancedValidators map[string]EnhancedValidator
	validatorMetrics   map[string]*ValidatorMetrics

	// Dual path integration for metadata routing
	dualPathHelper *ValidatorIntegrationHelper

	// Advanced features (session-only)
	crossValidatorSignals *CrossValidatorSignalProcessor
	confidenceCalibrator  *ConfidenceCalibrator

	// Multi-language support
	languageDetector *LanguageDetector

	// Configuration
	config *EnhancedValidatorConfig

	// Thread safety
	mu sync.RWMutex
}

// EnhancedValidator extends the standard validator interface with context capabilities
type EnhancedValidator interface {
	detector.Validator

	// Enhanced validation with context
	ValidateWithContext(content string, filePath string, contextInsights context.ContextInsights) ([]detector.Match, error)

	// Multi-language support
	SetLanguage(lang string) error
	GetSupportedLanguages() []string
}

// ValidationItem represents an item to be validated
type ValidationItem struct {
	Content  string
	FilePath string
	Context  context.ContextInsights
	Priority int
	Metadata map[string]interface{}
}

// BatchValidationResult contains results from validation
type BatchValidationResult struct {
	Item           ValidationItem
	Matches        []detector.Match
	Error          error
	ProcessingTime time.Duration
}

// ValidatorMetrics tracks performance and accuracy metrics (session-only)
type ValidatorMetrics struct {
	// Performance metrics
	TotalValidations      int64
	AverageProcessingTime time.Duration

	// Accuracy metrics
	TruePositives  int64
	FalsePositives int64
	TrueNegatives  int64
	FalseNegatives int64

	// Confidence metrics
	AverageConfidence  float64
	ConfidenceVariance float64

	// Context effectiveness
	ContextImpactPositive int64
	ContextImpactNegative int64

	// Thread safety
	mu sync.RWMutex
}

// CrossValidatorSignalProcessor analyzes signals across validators (session-only)
type CrossValidatorSignalProcessor struct {
	// Signal correlation matrix (current session only)
	correlations map[string]map[string]float64

	// Signal history for current session analysis
	signalHistory []CrossValidatorSignal

	mu sync.RWMutex
}

// CrossValidatorSignal represents a signal from validator interactions
type CrossValidatorSignal struct {
	Timestamp   time.Time
	Validators  []string
	Content     string
	Matches     []detector.Match
	Context     context.ContextInsights
	Correlation float64
}

// ConfidenceCalibrator calibrates confidence scores (statistical, no persistence)
type ConfidenceCalibrator struct {
	// Calibration parameters
	smoothingFactor float64
	minDataPoints   int

	mu sync.RWMutex
}

// LanguageDetector detects content language for multi-language support
type LanguageDetector struct {
	// Default language
	defaultLanguage string
}

// ValidationFeedback provides feedback for learning (session-only)
type ValidationFeedback struct {
	Match      detector.Match
	IsCorrect  bool
	ActualType string
	Context    string
	Validator  string
	Confidence float64
	Timestamp  time.Time
}

// ConfidenceFeedback provides feedback for confidence calibration
type ConfidenceFeedback struct {
	Original  float64
	Actual    bool
	Context   string
	Validator string
	Timestamp time.Time
}

// EnhancedValidatorConfig configures the enhanced validator system (caching removed)
type EnhancedValidatorConfig struct {
	// Performance settings (no caching)
	EnableBatchProcessing    bool
	BatchSize                int
	EnableParallelProcessing bool
	MaxWorkers               int

	// Context analysis settings
	EnableContextAnalysis        bool
	ContextWindowSize            int
	EnableCrossValidatorAnalysis bool

	// Multi-language settings
	EnableLanguageDetection bool
	DefaultLanguage         string
	SupportedLanguages      []string

	// Advanced features
	EnableAdvancedAnalytics     bool
	EnableRealTimeMetrics       bool
	EnableConfidenceCalibration bool
}

// NewEnhancedValidatorManager creates a new enhanced validator manager (no caching)
func NewEnhancedValidatorManager(config *EnhancedValidatorConfig) *EnhancedValidatorManager {
	if config == nil {
		config = getDefaultConfig()
	}

	manager := &EnhancedValidatorManager{
		contextAnalyzer:       context.NewContextAnalyzer(),
		enhancedValidators:    make(map[string]EnhancedValidator),
		validatorMetrics:      make(map[string]*ValidatorMetrics),
		crossValidatorSignals: NewCrossValidatorSignalProcessor(),
		confidenceCalibrator:  NewConfidenceCalibrator(),
		languageDetector:      NewLanguageDetector(config.DefaultLanguage),
		config:                config,
	}

	return manager
}

// SetDualPathHelper sets the dual path integration helper
func (m *EnhancedValidatorManager) SetDualPathHelper(helper *ValidatorIntegrationHelper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dualPathHelper = helper
}

// RegisterValidator registers an enhanced validator with the manager
func (m *EnhancedValidatorManager) RegisterValidator(name string, validator EnhancedValidator) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.enhancedValidators[name] = validator
	m.validatorMetrics[name] = &ValidatorMetrics{}

	return nil
}

// ValidateWithAdvancedFeatures performs validation with streamlined advanced features
func (m *EnhancedValidatorManager) ValidateWithAdvancedFeatures(content, filePath string) (*AdvancedValidationResult, error) {
	startTime := time.Now()

	// 1. Detect language if enabled
	var detectedLanguage string
	if m.config.EnableLanguageDetection {
		detectedLanguage = m.languageDetector.DetectLanguage(content)
	} else {
		detectedLanguage = m.config.DefaultLanguage
	}

	// 2. Perform context analysis
	var contextInsights context.ContextInsights
	if m.config.EnableContextAnalysis {
		contextInsights = m.contextAnalyzer.AnalyzeContext(content, filePath)
	}

	// 3. Prepare validation items
	validationItems := m.prepareValidationItems(content, filePath, contextInsights, detectedLanguage)

	// 4. Run validators
	validationResults, err := m.runEnhancedValidation(validationItems)
	if err != nil {
		return nil, fmt.Errorf("enhanced validation failed: %w", err)
	}

	// 5. Apply cross-validator signal analysis (session-only)
	if m.config.EnableCrossValidatorAnalysis {
		m.analyzeCrossValidatorSignals(validationResults, contextInsights)
	}

	// 6. Calibrate confidence scores (statistical, no persistence)
	if m.config.EnableConfidenceCalibration {
		m.calibrateConfidenceScores(validationResults)
	}

	// 7. Generate analytics
	analytics := m.generateAdvancedAnalytics(validationResults, contextInsights)

	// 8. Update metrics (session-only)
	m.updateValidatorMetrics(validationResults, time.Since(startTime))

	return &AdvancedValidationResult{
		Results:          validationResults,
		ContextInsights:  contextInsights,
		DetectedLanguage: detectedLanguage,
		Analytics:        analytics,
		ProcessingTime:   time.Since(startTime),
		ValidatorsUsed:   m.getValidatorNames(),
		CrossSignals:     m.crossValidatorSignals.GetRecentSignals(10),
		Recommendations:  m.generateRecommendations(validationResults, contextInsights),
	}, nil
}

// ValidateContentWithDualPath processes content using dual-path validation when available
func (m *EnhancedValidatorManager) ValidateContentWithDualPath(processedContent *preprocessors.ProcessedContent) ([]detector.Match, error) {
	m.mu.RLock()
	dualPathHelper := m.dualPathHelper
	m.mu.RUnlock()

	// If dual path helper is available, use it for proper metadata routing
	if dualPathHelper != nil {
		return dualPathHelper.ProcessContentWithDualPath(processedContent)
	}

	// Fallback to legacy behavior if dual path is not available
	return m.validateContentLegacy(processedContent.Text, processedContent.OriginalPath)
}

// validateContentLegacy provides fallback validation using the enhanced validators
func (m *EnhancedValidatorManager) validateContentLegacy(content, filePath string) ([]detector.Match, error) {
	var allMatches []detector.Match

	// Perform context analysis
	var contextInsights context.ContextInsights
	if m.config.EnableContextAnalysis {
		contextInsights = m.contextAnalyzer.AnalyzeContext(content, filePath)
	}

	// Run all registered validators
	m.mu.RLock()
	for _, validator := range m.enhancedValidators {
		matches, err := validator.ValidateWithContext(content, filePath, contextInsights)
		if err != nil {
			// Log error but continue with other validators
			if m.observer != nil && m.observer.DebugObserver != nil {
				m.observer.DebugObserver.LogDetail("enhanced_legacy", fmt.Sprintf("Validator error: %v", err))
			}
			continue
		}
		allMatches = append(allMatches, matches...)
	}
	m.mu.RUnlock()

	return allMatches, nil
}

// AdvancedValidationResult contains comprehensive validation results
type AdvancedValidationResult struct {
	Results          []BatchValidationResult
	ContextInsights  context.ContextInsights
	DetectedLanguage string
	Analytics        *AdvancedAnalytics
	ProcessingTime   time.Duration
	ValidatorsUsed   []string
	CrossSignals     []CrossValidatorSignal
	Recommendations  []ValidationRecommendation
}

// AdvancedAnalytics provides detailed analytics about the validation
type AdvancedAnalytics struct {
	TotalMatches           int
	ConfidenceDistribution map[string]int // confidence ranges -> count
	ValidatorPerformance   map[string]ValidatorPerformance
	ContextEffectiveness   ContextEffectivenessAnalysis
}

// ValidatorPerformance tracks individual validator performance
type ValidatorPerformance struct {
	Name              string
	MatchCount        int
	AverageConfidence float64
	ProcessingTime    time.Duration
	ContextImpact     float64
}

// ContextEffectivenessAnalysis analyzes how context affected validation
type ContextEffectivenessAnalysis struct {
	DomainImpact         map[string]float64
	DocumentTypeImpact   map[string]float64
	OverallImpact        float64
	MostEffectiveContext string
}

// ValidationRecommendation provides recommendations for improving validation
type ValidationRecommendation struct {
	Type         string
	Title        string
	Description  string
	Priority     int
	ActionItems  []string
	ExpectedGain float64
}

// getDefaultConfig returns default configuration (caching disabled)
func getDefaultConfig() *EnhancedValidatorConfig {
	return &EnhancedValidatorConfig{
		EnableBatchProcessing:        true,
		BatchSize:                    100,
		EnableParallelProcessing:     true,
		MaxWorkers:                   8,
		EnableContextAnalysis:        true,
		ContextWindowSize:            500,
		EnableCrossValidatorAnalysis: true,
		EnableLanguageDetection:      true,
		DefaultLanguage:              "en",
		SupportedLanguages:           []string{"en", "es", "fr", "de", "it", "pt", "ja", "zh", "ko"},
		EnableAdvancedAnalytics:      true,
		EnableRealTimeMetrics:        true,
		EnableConfidenceCalibration:  true,
	}
}

// Initialize supporting components (simplified, no caching)
func NewCrossValidatorSignalProcessor() *CrossValidatorSignalProcessor {
	return &CrossValidatorSignalProcessor{
		correlations:  make(map[string]map[string]float64),
		signalHistory: make([]CrossValidatorSignal, 0, 100), // Smaller session buffer
	}
}

func NewConfidenceCalibrator() *ConfidenceCalibrator {
	return &ConfidenceCalibrator{
		smoothingFactor: 0.1,
		minDataPoints:   10, // Lower threshold for session-only
	}
}

func NewLanguageDetector(defaultLang string) *LanguageDetector {
	return &LanguageDetector{
		defaultLanguage: defaultLang,
	}
}

// Core methods (simplified)
func (m *EnhancedValidatorManager) prepareValidationItems(content, filePath string, context context.ContextInsights, language string) []ValidationItem {
	return []ValidationItem{{
		Content:  content,
		FilePath: filePath,
		Context:  context,
		Priority: 1,
		Metadata: map[string]interface{}{"language": language},
	}}
}

func (m *EnhancedValidatorManager) runEnhancedValidation(items []ValidationItem) ([]BatchValidationResult, error) {
	results := make([]BatchValidationResult, 0, len(items))

	for _, item := range items {
		startTime := time.Now()
		var allMatches []detector.Match

		// Run all registered validators on this item
		m.mu.RLock()
		for _, validator := range m.enhancedValidators {
			matches, err := validator.ValidateWithContext(item.Content, item.FilePath, item.Context)
			if err != nil {
				// Log error but continue with other validators
				fmt.Printf("   → enhanced: Validator error: %v\n", err)
				continue
			}
			allMatches = append(allMatches, matches...)
		}
		m.mu.RUnlock()

		result := BatchValidationResult{
			Item:           item,
			Matches:        allMatches,
			ProcessingTime: time.Since(startTime),
		}
		results = append(results, result)
	}

	return results, nil
}

func (m *EnhancedValidatorManager) analyzeCrossValidatorSignals(results []BatchValidationResult, context context.ContextInsights) {
	// Session-only cross-validator signal analysis
	if !m.config.EnableCrossValidatorAnalysis {
		return
	}

	// Group matches by validator type for correlation analysis
	validatorMatches := make(map[string][]detector.Match)
	for _, result := range results {
		if result.Error == nil {
			for _, match := range result.Matches {
				validatorMatches[match.Validator] = append(validatorMatches[match.Validator], match)
			}
		}
	}

	// Detect cross-validator patterns (session-only)
	m.crossValidatorSignals.mu.Lock()
	defer m.crossValidatorSignals.mu.Unlock()

	// Pattern 1: Multiple PII types in same document (high correlation)
	if len(validatorMatches) >= 2 {
		var validators []string
		var totalConfidence float64
		matchCount := 0

		for validator, matches := range validatorMatches {
			if len(matches) > 0 {
				validators = append(validators, validator)
				for _, match := range matches {
					totalConfidence += match.Confidence
					matchCount++
				}
			}
		}

		if matchCount > 0 {
			avgConfidence := totalConfidence / float64(matchCount)
			signal := CrossValidatorSignal{
				Timestamp:   time.Now(),
				Validators:  validators,
				Content:     fmt.Sprintf("Multiple PII types detected: %v", validators),
				Correlation: avgConfidence / 100.0,
			}

			// Apply confidence boost based on correlation
			if len(validators) >= 3 {
				signal.Correlation += 0.15 // High correlation boost
			} else if len(validators) == 2 {
				signal.Correlation += 0.10 // Medium correlation boost
			}

			m.crossValidatorSignals.signalHistory = append(m.crossValidatorSignals.signalHistory, signal)
		}
	}

	// Pattern 2: Financial document correlation (Credit Card + SSN + Financial context)
	if creditCardMatches, hasCreditCard := validatorMatches["CREDIT_CARD"]; hasCreditCard {
		if ssnMatches, hasSSN := validatorMatches["SSN"]; hasSSN {
			if context.Domain == "Financial" || context.Domain == "HR_Payroll" {
				signal := CrossValidatorSignal{
					Timestamp:   time.Now(),
					Validators:  []string{"CREDIT_CARD", "SSN"},
					Content:     fmt.Sprintf("Financial correlation: %d credit cards, %d SSNs in %s context", len(creditCardMatches), len(ssnMatches), context.Domain),
					Correlation: 0.20, // Strong financial correlation
				}
				m.crossValidatorSignals.signalHistory = append(m.crossValidatorSignals.signalHistory, signal)
			}
		}
	}

	// Maintain signal history (keep last 100 signals for session)
	if len(m.crossValidatorSignals.signalHistory) > 100 {
		m.crossValidatorSignals.signalHistory = m.crossValidatorSignals.signalHistory[len(m.crossValidatorSignals.signalHistory)-100:]
	}
}

func (m *EnhancedValidatorManager) calibrateConfidenceScores(results []BatchValidationResult) {
	// Statistical confidence calibration (no persistence)
	if !m.config.EnableConfidenceCalibration {
		return
	}

	m.confidenceCalibrator.mu.Lock()
	defer m.confidenceCalibrator.mu.Unlock()

	for i := range results {
		if results[i].Error != nil {
			continue
		}

		for j := range results[i].Matches {
			match := &results[i].Matches[j]

			// Apply statistical calibration based on confidence range
			originalConfidence := match.Confidence
			calibratedConfidence := originalConfidence

			// Statistical calibration logic
			switch {
			case originalConfidence >= 90:
				// High confidence matches - typically very accurate, slight boost
				calibratedConfidence = originalConfidence * 1.02
			case originalConfidence >= 70:
				// Medium-high confidence - generally reliable
				calibratedConfidence = originalConfidence * 1.01
			case originalConfidence >= 50:
				// Medium confidence - more conservative approach
				calibratedConfidence = originalConfidence * 0.98
			default:
				// Low confidence - apply penalty
				calibratedConfidence = originalConfidence * 0.95
			}

			// Ensure bounds
			if calibratedConfidence > 100 {
				calibratedConfidence = 100
			}
			if calibratedConfidence < 0 {
				calibratedConfidence = 0
			}

			// Update match confidence
			match.Confidence = calibratedConfidence

			// Track calibration in metadata
			if match.Metadata == nil {
				match.Metadata = make(map[string]interface{})
			}
			match.Metadata["original_confidence"] = originalConfidence
			match.Metadata["calibration_applied"] = calibratedConfidence - originalConfidence
			match.Metadata["calibration_method"] = "statistical"
		}
	}
}

func (m *EnhancedValidatorManager) generateAdvancedAnalytics(results []BatchValidationResult, context context.ContextInsights) *AdvancedAnalytics {
	return &AdvancedAnalytics{
		TotalMatches:           len(results),
		ConfidenceDistribution: make(map[string]int),
		ValidatorPerformance:   make(map[string]ValidatorPerformance),
	}
}

func (m *EnhancedValidatorManager) updateValidatorMetrics(results []BatchValidationResult, processingTime time.Duration) {
	// Session-only validator metrics tracking
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update global processing metrics
	totalMatches := 0

	for _, result := range results {
		if result.Error != nil {
			continue
		}

		totalMatches += len(result.Matches)

		// Update per-validator metrics
		for _, match := range result.Matches {
			validator := match.Validator
			metrics, exists := m.validatorMetrics[validator]
			if !exists {
				metrics = &ValidatorMetrics{}
				m.validatorMetrics[validator] = metrics
			}

			metrics.mu.Lock()

			// Update basic metrics
			metrics.TotalValidations++

			// Update average processing time (running average)
			if metrics.TotalValidations == 1 {
				metrics.AverageProcessingTime = result.ProcessingTime
			} else {
				// Running average formula
				metrics.AverageProcessingTime = time.Duration(
					(int64(metrics.AverageProcessingTime)*int64(metrics.TotalValidations-1) +
						int64(result.ProcessingTime)) / int64(metrics.TotalValidations))
			}

			// Update confidence metrics
			confidence := match.Confidence
			if metrics.TotalValidations == 1 {
				metrics.AverageConfidence = confidence
				metrics.ConfidenceVariance = 0.0
			} else {
				// Update running average confidence
				prevAvg := metrics.AverageConfidence
				metrics.AverageConfidence = (prevAvg*float64(metrics.TotalValidations-1) + confidence) / float64(metrics.TotalValidations)

				// Update variance (simplified calculation)
				diff := confidence - metrics.AverageConfidence
				metrics.ConfidenceVariance = (metrics.ConfidenceVariance*float64(metrics.TotalValidations-1) + diff*diff) / float64(metrics.TotalValidations)
			}

			// Track context impact
			if match.Metadata != nil {
				if contextImpact, exists := match.Metadata["context_impact"]; exists {
					if impact, ok := contextImpact.(float64); ok {
						if impact > 0 {
							metrics.ContextImpactPositive++
						} else if impact < 0 {
							metrics.ContextImpactNegative++
						}
					}
				}
			}

			// Confidence-based classification for accuracy tracking
			if confidence >= 70 {
				metrics.TruePositives++
			} else {
				metrics.TrueNegatives++
			}

			metrics.mu.Unlock()
		}
	}

	// Log metrics if debug observer is available
	if m.observer != nil && m.observer.DebugObserver != nil {
		m.observer.DebugObserver.LogDetail("metrics", fmt.Sprintf("Updated metrics for %d validators", len(m.validatorMetrics)))
		m.observer.DebugObserver.LogDetail("metrics", fmt.Sprintf("Total processing time: %v", processingTime))
		m.observer.DebugObserver.LogDetail("metrics", fmt.Sprintf("Total matches: %d", totalMatches))

		// Log per-validator summary
		for validator, metrics := range m.validatorMetrics {
			metrics.mu.RLock()
			m.observer.DebugObserver.LogDetail("metrics", fmt.Sprintf("%s: %d validations, %.1f avg confidence",
				validator, metrics.TotalValidations, metrics.AverageConfidence))
			metrics.mu.RUnlock()
		}
	}
}

func (m *EnhancedValidatorManager) getValidatorNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.enhancedValidators))
	for name := range m.enhancedValidators {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (m *EnhancedValidatorManager) generateRecommendations(results []BatchValidationResult, context context.ContextInsights) []ValidationRecommendation {
	return []ValidationRecommendation{}
}

func (c *CrossValidatorSignalProcessor) GetRecentSignals(count int) []CrossValidatorSignal {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.signalHistory) == 0 {
		return []CrossValidatorSignal{}
	}

	start := len(c.signalHistory) - count
	if start < 0 {
		start = 0
	}

	return c.signalHistory[start:]
}

func (l *LanguageDetector) DetectLanguage(content string) string {
	// Simple placeholder - returns default language
	return l.defaultLanguage
}
