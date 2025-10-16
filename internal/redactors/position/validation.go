// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"fmt"
	"strings"
	"unicode"
)

// PositionValidator provides validation and confidence scoring for position correlations
type PositionValidator interface {
	// ValidateCorrelation validates a position correlation and returns detailed results
	ValidateCorrelation(correlation *PositionCorrelation, originalContent []byte, extractedText string) (*ValidationResult, error)

	// ValidateCorrelations validates multiple position correlations
	ValidateCorrelations(correlations []*PositionCorrelation, originalContent []byte, extractedText string) ([]*ValidationResult, error)

	// CalculateConfidenceScore calculates a confidence score for a position correlation
	CalculateConfidenceScore(correlation *PositionCorrelation, originalContent []byte, extractedText string) (float64, error)

	// SetConfidenceThreshold sets the minimum confidence threshold for validation
	SetConfidenceThreshold(threshold float64)

	// GetConfidenceThreshold returns the current confidence threshold
	GetConfidenceThreshold() float64

	// SetValidationRules sets custom validation rules
	SetValidationRules(rules ValidationRules)

	// GetValidationRules returns the current validation rules
	GetValidationRules() ValidationRules
}

// ValidationResult contains the results of position validation
type ValidationResult struct {
	// Correlation is the original correlation being validated
	Correlation *PositionCorrelation

	// IsValid indicates whether the correlation passed validation
	IsValid bool

	// ConfidenceScore is the calculated confidence score (0.0 to 1.0)
	ConfidenceScore float64

	// ValidationErrors contains any validation errors found
	ValidationErrors []ValidationError

	// ValidationWarnings contains any validation warnings
	ValidationWarnings []ValidationWarning

	// ConfidenceFactors contains detailed confidence scoring factors
	ConfidenceFactors []ConfidenceFactor

	// AlternativeCorrelations contains suggested alternative correlations
	AlternativeCorrelations []*PositionCorrelation

	// ValidationMetadata contains additional validation information
	ValidationMetadata map[string]interface{}
}

// ValidationError represents a validation error
type ValidationError struct {
	// Type is the type of validation error
	Type ValidationErrorType

	// Message is a human-readable error message
	Message string

	// Severity indicates the severity of the error
	Severity ErrorSeverity

	// Context provides additional context about the error
	Context map[string]interface{}
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	// Type is the type of validation warning
	Type ValidationWarningType

	// Message is a human-readable warning message
	Message string

	// Recommendation provides a recommended action
	Recommendation string

	// Context provides additional context about the warning
	Context map[string]interface{}
}

// ConfidenceFactor represents a factor that contributes to the confidence score
type ConfidenceFactor struct {
	// Name is the name of the confidence factor
	Name string

	// Weight is the weight of this factor in the overall score (0.0 to 1.0)
	Weight float64

	// Score is the score for this factor (0.0 to 1.0)
	Score float64

	// Description explains what this factor measures
	Description string

	// Details provides additional details about the factor calculation
	Details map[string]interface{}
}

// ValidationRules defines rules for position validation
type ValidationRules struct {
	// MinConfidenceThreshold is the minimum confidence required for validation
	MinConfidenceThreshold float64

	// MaxPositionDeviation is the maximum allowed deviation in position (characters)
	MaxPositionDeviation int

	// RequireContextMatch indicates whether context matching is required
	RequireContextMatch bool

	// MinContextSimilarity is the minimum required context similarity (0.0 to 1.0)
	MinContextSimilarity float64

	// MaxEditDistance is the maximum allowed edit distance for text matching
	MaxEditDistance int

	// RequireExactMatch indicates whether exact text matching is required
	RequireExactMatch bool

	// AllowFuzzyMatching indicates whether fuzzy matching is allowed
	AllowFuzzyMatching bool

	// ConfidenceWeights defines weights for different confidence factors
	ConfidenceWeights ConfidenceWeights
}

// ConfidenceWeights defines weights for confidence calculation factors
type ConfidenceWeights struct {
	// TextSimilarity weight for text similarity factor
	TextSimilarity float64

	// ContextSimilarity weight for context similarity factor
	ContextSimilarity float64

	// PositionAccuracy weight for position accuracy factor
	PositionAccuracy float64

	// MethodReliability weight for correlation method reliability
	MethodReliability float64

	// DocumentStructure weight for document structure consistency
	DocumentStructure float64
}

// ValidationErrorType represents types of validation errors
type ValidationErrorType int

const (
	// ErrorInvalidPosition indicates an invalid position
	ErrorInvalidPosition ValidationErrorType = iota
	// ErrorTextMismatch indicates text content doesn't match
	ErrorTextMismatch
	// ErrorContextMismatch indicates context doesn't match
	ErrorContextMismatch
	// ErrorLowConfidence indicates confidence is below threshold
	ErrorLowConfidence
	// ErrorPositionOutOfBounds indicates position is out of document bounds
	ErrorPositionOutOfBounds
	// ErrorInconsistentMapping indicates inconsistent position mapping
	ErrorInconsistentMapping
)

// ValidationWarningType represents types of validation warnings
type ValidationWarningType int

const (
	// WarningLowConfidence indicates confidence is low but above threshold
	WarningLowConfidence ValidationWarningType = iota
	// WarningFuzzyMatch indicates a fuzzy match was used
	WarningFuzzyMatch
	// WarningEstimatedPosition indicates position was estimated
	WarningEstimatedPosition
	// WarningPartialContext indicates only partial context matching
	WarningPartialContext
	// WarningMultipleMatches indicates multiple possible matches found
	WarningMultipleMatches
)

// ErrorSeverity represents the severity of validation errors
type ErrorSeverity int

const (
	// SeverityLow indicates a low severity error
	SeverityLow ErrorSeverity = iota
	// SeverityMedium indicates a medium severity error
	SeverityMedium
	// SeverityHigh indicates a high severity error
	SeverityHigh
	// SeverityCritical indicates a critical error
	SeverityCritical
)

// String returns the string representation of ValidationErrorType
func (vet ValidationErrorType) String() string {
	switch vet {
	case ErrorInvalidPosition:
		return "invalid_position"
	case ErrorTextMismatch:
		return "text_mismatch"
	case ErrorContextMismatch:
		return "context_mismatch"
	case ErrorLowConfidence:
		return "low_confidence"
	case ErrorPositionOutOfBounds:
		return "position_out_of_bounds"
	case ErrorInconsistentMapping:
		return "inconsistent_mapping"
	default:
		return "unknown_error"
	}
}

// String returns the string representation of ValidationWarningType
func (vwt ValidationWarningType) String() string {
	switch vwt {
	case WarningLowConfidence:
		return "low_confidence"
	case WarningFuzzyMatch:
		return "fuzzy_match"
	case WarningEstimatedPosition:
		return "estimated_position"
	case WarningPartialContext:
		return "partial_context"
	case WarningMultipleMatches:
		return "multiple_matches"
	default:
		return "unknown_warning"
	}
}

// String returns the string representation of ErrorSeverity
func (es ErrorSeverity) String() string {
	switch es {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// DefaultPositionValidator implements the PositionValidator interface
type DefaultPositionValidator struct {
	// confidenceThreshold is the minimum confidence threshold
	confidenceThreshold float64

	// validationRules contains the validation rules
	validationRules ValidationRules

	// correlator is used for alternative correlation suggestions
	correlator PositionCorrelator
}

// NewDefaultPositionValidator creates a new default position validator
func NewDefaultPositionValidator(correlator PositionCorrelator) *DefaultPositionValidator {
	return &DefaultPositionValidator{
		confidenceThreshold: 0.8,
		validationRules:     getDefaultValidationRules(),
		correlator:          correlator,
	}
}

// getDefaultValidationRules returns default validation rules
func getDefaultValidationRules() ValidationRules {
	return ValidationRules{
		MinConfidenceThreshold: 0.8,
		MaxPositionDeviation:   50,
		RequireContextMatch:    true,
		MinContextSimilarity:   0.7,
		MaxEditDistance:        3,
		RequireExactMatch:      false,
		AllowFuzzyMatching:     true,
		ConfidenceWeights: ConfidenceWeights{
			TextSimilarity:    0.3,
			ContextSimilarity: 0.25,
			PositionAccuracy:  0.2,
			MethodReliability: 0.15,
			DocumentStructure: 0.1,
		},
	}
}

// ValidateCorrelation validates a single position correlation
func (dpv *DefaultPositionValidator) ValidateCorrelation(correlation *PositionCorrelation, originalContent []byte, extractedText string) (*ValidationResult, error) {
	if correlation == nil {
		return nil, fmt.Errorf("correlation cannot be nil")
	}

	result := &ValidationResult{
		Correlation:             correlation,
		IsValid:                 true,
		ValidationErrors:        make([]ValidationError, 0),
		ValidationWarnings:      make([]ValidationWarning, 0),
		ConfidenceFactors:       make([]ConfidenceFactor, 0),
		AlternativeCorrelations: make([]*PositionCorrelation, 0),
		ValidationMetadata:      make(map[string]interface{}),
	}

	// Calculate confidence score
	confidenceScore, err := dpv.CalculateConfidenceScore(correlation, originalContent, extractedText)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate confidence score: %w", err)
	}
	result.ConfidenceScore = confidenceScore

	// Perform validation checks
	dpv.validatePosition(correlation, result)
	dpv.validateTextMatch(correlation, originalContent, extractedText, result)
	dpv.validateContext(correlation, originalContent, extractedText, result)
	dpv.validateConfidence(correlation, result)
	dpv.validateDocumentBounds(correlation, originalContent, result)

	// Check if validation passed
	result.IsValid = len(result.ValidationErrors) == 0

	// Add metadata
	result.ValidationMetadata["validation_timestamp"] = "now" // Would use time.Now() in real implementation
	result.ValidationMetadata["validator_version"] = "1.0.0"
	result.ValidationMetadata["correlation_method"] = correlation.Method.String()

	return result, nil
}

// ValidateCorrelations validates multiple position correlations
func (dpv *DefaultPositionValidator) ValidateCorrelations(correlations []*PositionCorrelation, originalContent []byte, extractedText string) ([]*ValidationResult, error) {
	if len(correlations) == 0 {
		return []*ValidationResult{}, nil
	}

	results := make([]*ValidationResult, 0, len(correlations))

	for i, correlation := range correlations {
		result, err := dpv.ValidateCorrelation(correlation, originalContent, extractedText)
		if err != nil {
			return nil, fmt.Errorf("failed to validate correlation %d: %w", i, err)
		}
		results = append(results, result)
	}

	// Perform cross-correlation validation
	dpv.validateCorrelationConsistency(results, originalContent, extractedText)

	return results, nil
}

// CalculateConfidenceScore calculates a confidence score for a position correlation
func (dpv *DefaultPositionValidator) CalculateConfidenceScore(correlation *PositionCorrelation, originalContent []byte, extractedText string) (float64, error) {
	if correlation == nil {
		return 0.0, fmt.Errorf("correlation cannot be nil")
	}

	weights := dpv.validationRules.ConfidenceWeights
	totalWeight := weights.TextSimilarity + weights.ContextSimilarity + weights.PositionAccuracy + weights.MethodReliability + weights.DocumentStructure

	if totalWeight == 0 {
		return 0.0, fmt.Errorf("total confidence weight cannot be zero")
	}

	// Calculate individual factor scores
	textScore := dpv.calculateTextSimilarityScore(correlation, originalContent, extractedText)
	contextScore := dpv.calculateContextSimilarityScore(correlation, originalContent, extractedText)
	positionScore := dpv.calculatePositionAccuracyScore(correlation, originalContent, extractedText)
	methodScore := dpv.calculateMethodReliabilityScore(correlation)
	structureScore := dpv.calculateDocumentStructureScore(correlation, originalContent)

	// Calculate weighted average
	weightedScore := (textScore*weights.TextSimilarity +
		contextScore*weights.ContextSimilarity +
		positionScore*weights.PositionAccuracy +
		methodScore*weights.MethodReliability +
		structureScore*weights.DocumentStructure) / totalWeight

	// Ensure score is within valid range
	if weightedScore < 0.0 {
		weightedScore = 0.0
	}
	if weightedScore > 1.0 {
		weightedScore = 1.0
	}

	return weightedScore, nil
}

// SetConfidenceThreshold sets the minimum confidence threshold
func (dpv *DefaultPositionValidator) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		dpv.confidenceThreshold = threshold
		dpv.validationRules.MinConfidenceThreshold = threshold
	}
}

// GetConfidenceThreshold returns the current confidence threshold
func (dpv *DefaultPositionValidator) GetConfidenceThreshold() float64 {
	return dpv.confidenceThreshold
}

// SetValidationRules sets custom validation rules
func (dpv *DefaultPositionValidator) SetValidationRules(rules ValidationRules) {
	dpv.validationRules = rules
	dpv.confidenceThreshold = rules.MinConfidenceThreshold
}

// GetValidationRules returns the current validation rules
func (dpv *DefaultPositionValidator) GetValidationRules() ValidationRules {
	return dpv.validationRules
}

// Helper methods for validation checks

// validatePosition validates the position information
func (dpv *DefaultPositionValidator) validatePosition(correlation *PositionCorrelation, result *ValidationResult) {
	// Validate extracted position
	if correlation.ExtractedPosition.Line < 1 {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Type:     ErrorInvalidPosition,
			Message:  fmt.Sprintf("Invalid extracted position line: %d (must be >= 1)", correlation.ExtractedPosition.Line),
			Severity: SeverityHigh,
			Context:  map[string]interface{}{"line": correlation.ExtractedPosition.Line},
		})
	}

	if correlation.ExtractedPosition.StartChar < 0 {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Type:     ErrorInvalidPosition,
			Message:  fmt.Sprintf("Invalid extracted position start char: %d (must be >= 0)", correlation.ExtractedPosition.StartChar),
			Severity: SeverityHigh,
			Context:  map[string]interface{}{"start_char": correlation.ExtractedPosition.StartChar},
		})
	}

	if correlation.ExtractedPosition.EndChar < correlation.ExtractedPosition.StartChar {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Type:     ErrorInvalidPosition,
			Message:  fmt.Sprintf("Invalid extracted position: end char (%d) < start char (%d)", correlation.ExtractedPosition.EndChar, correlation.ExtractedPosition.StartChar),
			Severity: SeverityHigh,
			Context: map[string]interface{}{
				"start_char": correlation.ExtractedPosition.StartChar,
				"end_char":   correlation.ExtractedPosition.EndChar,
			},
		})
	}

	// Validate original position if present
	if correlation.OriginalPosition != nil {
		if correlation.OriginalPosition.Page < 0 {
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Type:     ErrorInvalidPosition,
				Message:  fmt.Sprintf("Invalid original position page: %d (must be >= 0)", correlation.OriginalPosition.Page),
				Severity: SeverityMedium,
				Context:  map[string]interface{}{"page": correlation.OriginalPosition.Page},
			})
		}

		if correlation.OriginalPosition.CharOffset < 0 {
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Type:     ErrorInvalidPosition,
				Message:  fmt.Sprintf("Invalid original position char offset: %d (must be >= 0)", correlation.OriginalPosition.CharOffset),
				Severity: SeverityMedium,
				Context:  map[string]interface{}{"char_offset": correlation.OriginalPosition.CharOffset},
			})
		}
	}
}

// Additional validation methods will be implemented in the next part...
// validateTextMatch validates that the text content matches
func (dpv *DefaultPositionValidator) validateTextMatch(correlation *PositionCorrelation, originalContent []byte, extractedText string, result *ValidationResult) {
	if correlation.MatchedText == "" {
		result.ValidationWarnings = append(result.ValidationWarnings, ValidationWarning{
			Type:           WarningEstimatedPosition,
			Message:        "No matched text available for validation",
			Recommendation: "Consider using a more precise correlation method",
			Context:        map[string]interface{}{"method": correlation.Method.String()},
		})
		return
	}

	// Extract the text at the correlated position from original content
	originalText := string(originalContent)
	if correlation.OriginalPosition != nil && correlation.OriginalPosition.CharOffset >= 0 {
		startOffset := correlation.OriginalPosition.CharOffset
		endOffset := startOffset + len(correlation.MatchedText)

		if endOffset <= len(originalText) {
			actualText := originalText[startOffset:endOffset]

			// Check for exact match
			if actualText == correlation.MatchedText {
				// Perfect match - add positive confidence factor
				result.ConfidenceFactors = append(result.ConfidenceFactors, ConfidenceFactor{
					Name:        "exact_text_match",
					Weight:      dpv.validationRules.ConfidenceWeights.TextSimilarity,
					Score:       1.0,
					Description: "Text matches exactly at correlated position",
					Details:     map[string]interface{}{"matched_text": correlation.MatchedText},
				})
			} else {
				// Calculate similarity for fuzzy match
				similarity := dpv.calculateStringSimilarity(actualText, correlation.MatchedText)

				if similarity >= 0.8 {
					result.ConfidenceFactors = append(result.ConfidenceFactors, ConfidenceFactor{
						Name:        "fuzzy_text_match",
						Weight:      dpv.validationRules.ConfidenceWeights.TextSimilarity,
						Score:       similarity,
						Description: "Text matches with high similarity at correlated position",
						Details: map[string]interface{}{
							"expected_text": correlation.MatchedText,
							"actual_text":   actualText,
							"similarity":    similarity,
						},
					})

					result.ValidationWarnings = append(result.ValidationWarnings, ValidationWarning{
						Type:           WarningFuzzyMatch,
						Message:        fmt.Sprintf("Text similarity is %.2f (fuzzy match)", similarity),
						Recommendation: "Verify the correlation accuracy",
						Context: map[string]interface{}{
							"expected":   correlation.MatchedText,
							"actual":     actualText,
							"similarity": similarity,
						},
					})
				} else {
					result.ValidationErrors = append(result.ValidationErrors, ValidationError{
						Type:     ErrorTextMismatch,
						Message:  fmt.Sprintf("Text mismatch at correlated position (similarity: %.2f)", similarity),
						Severity: SeverityHigh,
						Context: map[string]interface{}{
							"expected":   correlation.MatchedText,
							"actual":     actualText,
							"similarity": similarity,
						},
					})
				}
			}
		} else {
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Type:     ErrorPositionOutOfBounds,
				Message:  "Correlated position extends beyond document bounds",
				Severity: SeverityCritical,
				Context: map[string]interface{}{
					"start_offset":    startOffset,
					"end_offset":      endOffset,
					"document_length": len(originalText),
				},
			})
		}
	}
}

// validateContext validates the context around the correlated position
func (dpv *DefaultPositionValidator) validateContext(correlation *PositionCorrelation, originalContent []byte, extractedText string, result *ValidationResult) {
	if !dpv.validationRules.RequireContextMatch {
		return
	}

	if correlation.Context == "" {
		result.ValidationWarnings = append(result.ValidationWarnings, ValidationWarning{
			Type:           WarningPartialContext,
			Message:        "No context available for validation",
			Recommendation: "Consider using a correlation method that provides context",
			Context:        map[string]interface{}{"method": correlation.Method.String()},
		})
		return
	}

	// Extract context from original content around the correlated position
	originalText := string(originalContent)
	if correlation.OriginalPosition != nil && correlation.OriginalPosition.CharOffset >= 0 {
		contextSize := len(correlation.Context) / 2 // Assume context is centered
		startOffset := max(0, correlation.OriginalPosition.CharOffset-contextSize)
		endOffset := min(len(originalText), correlation.OriginalPosition.CharOffset+len(correlation.MatchedText)+contextSize)

		if startOffset < endOffset {
			actualContext := originalText[startOffset:endOffset]
			similarity := dpv.calculateStringSimilarity(correlation.Context, actualContext)

			if similarity >= dpv.validationRules.MinContextSimilarity {
				result.ConfidenceFactors = append(result.ConfidenceFactors, ConfidenceFactor{
					Name:        "context_similarity",
					Weight:      dpv.validationRules.ConfidenceWeights.ContextSimilarity,
					Score:       similarity,
					Description: "Context similarity around correlated position",
					Details: map[string]interface{}{
						"expected_context": correlation.Context,
						"actual_context":   actualContext,
						"similarity":       similarity,
					},
				})
			} else {
				result.ValidationErrors = append(result.ValidationErrors, ValidationError{
					Type:     ErrorContextMismatch,
					Message:  fmt.Sprintf("Context similarity too low: %.2f (required: %.2f)", similarity, dpv.validationRules.MinContextSimilarity),
					Severity: SeverityMedium,
					Context: map[string]interface{}{
						"expected_context": correlation.Context,
						"actual_context":   actualContext,
						"similarity":       similarity,
						"required":         dpv.validationRules.MinContextSimilarity,
					},
				})
			}
		}
	}
}

// validateConfidence validates the confidence score
func (dpv *DefaultPositionValidator) validateConfidence(correlation *PositionCorrelation, result *ValidationResult) {
	if correlation.ConfidenceScore < dpv.validationRules.MinConfidenceThreshold {
		result.ValidationErrors = append(result.ValidationErrors, ValidationError{
			Type:     ErrorLowConfidence,
			Message:  fmt.Sprintf("Confidence score %.2f below threshold %.2f", correlation.ConfidenceScore, dpv.validationRules.MinConfidenceThreshold),
			Severity: SeverityMedium,
			Context: map[string]interface{}{
				"confidence": correlation.ConfidenceScore,
				"threshold":  dpv.validationRules.MinConfidenceThreshold,
			},
		})
	} else if correlation.ConfidenceScore < dpv.validationRules.MinConfidenceThreshold+0.1 {
		result.ValidationWarnings = append(result.ValidationWarnings, ValidationWarning{
			Type:           WarningLowConfidence,
			Message:        fmt.Sprintf("Confidence score %.2f is close to threshold %.2f", correlation.ConfidenceScore, dpv.validationRules.MinConfidenceThreshold),
			Recommendation: "Consider using additional validation or a more reliable correlation method",
			Context: map[string]interface{}{
				"confidence": correlation.ConfidenceScore,
				"threshold":  dpv.validationRules.MinConfidenceThreshold,
			},
		})
	}
}

// validateDocumentBounds validates that positions are within document bounds
func (dpv *DefaultPositionValidator) validateDocumentBounds(correlation *PositionCorrelation, originalContent []byte, result *ValidationResult) {
	originalText := string(originalContent)

	// Validate original position bounds
	if correlation.OriginalPosition != nil {
		if correlation.OriginalPosition.CharOffset >= len(originalText) {
			result.ValidationErrors = append(result.ValidationErrors, ValidationError{
				Type:     ErrorPositionOutOfBounds,
				Message:  fmt.Sprintf("Original position char offset %d exceeds document length %d", correlation.OriginalPosition.CharOffset, len(originalText)),
				Severity: SeverityCritical,
				Context: map[string]interface{}{
					"char_offset":     correlation.OriginalPosition.CharOffset,
					"document_length": len(originalText),
				},
			})
		}
	}
}

// validateCorrelationConsistency validates consistency across multiple correlations
func (dpv *DefaultPositionValidator) validateCorrelationConsistency(results []*ValidationResult, originalContent []byte, extractedText string) {
	if len(results) < 2 {
		return
	}

	// Check for overlapping positions
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			result1 := results[i]
			result2 := results[j]

			if dpv.positionsOverlap(result1.Correlation, result2.Correlation) {
				warning := ValidationWarning{
					Type:           WarningMultipleMatches,
					Message:        "Multiple correlations have overlapping positions",
					Recommendation: "Review correlations for potential conflicts",
					Context: map[string]interface{}{
						"correlation1_line": result1.Correlation.ExtractedPosition.Line,
						"correlation2_line": result2.Correlation.ExtractedPosition.Line,
					},
				}

				result1.ValidationWarnings = append(result1.ValidationWarnings, warning)
				result2.ValidationWarnings = append(result2.ValidationWarnings, warning)
			}
		}
	}
}

// Helper methods for confidence calculation

// calculateTextSimilarityScore calculates the text similarity confidence factor
func (dpv *DefaultPositionValidator) calculateTextSimilarityScore(correlation *PositionCorrelation, originalContent []byte, extractedText string) float64 {
	if correlation.MatchedText == "" {
		return 0.5 // Neutral score when no text available
	}

	// Extract text from original content at the correlated position
	originalText := string(originalContent)
	if correlation.OriginalPosition != nil && correlation.OriginalPosition.CharOffset >= 0 {
		startOffset := correlation.OriginalPosition.CharOffset
		endOffset := startOffset + len(correlation.MatchedText)

		if endOffset <= len(originalText) {
			actualText := originalText[startOffset:endOffset]
			return dpv.calculateStringSimilarity(correlation.MatchedText, actualText)
		}
	}

	return 0.3 // Low score when position is invalid
}

// calculateContextSimilarityScore calculates the context similarity confidence factor
func (dpv *DefaultPositionValidator) calculateContextSimilarityScore(correlation *PositionCorrelation, originalContent []byte, extractedText string) float64 {
	if correlation.Context == "" {
		return 0.5 // Neutral score when no context available
	}

	originalText := string(originalContent)
	if correlation.OriginalPosition != nil && correlation.OriginalPosition.CharOffset >= 0 {
		contextSize := len(correlation.Context) / 2
		startOffset := max(0, correlation.OriginalPosition.CharOffset-contextSize)
		endOffset := min(len(originalText), correlation.OriginalPosition.CharOffset+len(correlation.MatchedText)+contextSize)

		if startOffset < endOffset {
			actualContext := originalText[startOffset:endOffset]
			return dpv.calculateStringSimilarity(correlation.Context, actualContext)
		}
	}

	return 0.3 // Low score when context cannot be validated
}

// calculatePositionAccuracyScore calculates the position accuracy confidence factor
func (dpv *DefaultPositionValidator) calculatePositionAccuracyScore(correlation *PositionCorrelation, originalContent []byte, extractedText string) float64 {
	// For now, use the correlation's confidence score as a proxy for position accuracy
	// In a more sophisticated implementation, this would analyze position consistency
	return correlation.ConfidenceScore
}

// calculateMethodReliabilityScore calculates the correlation method reliability factor
func (dpv *DefaultPositionValidator) calculateMethodReliabilityScore(correlation *PositionCorrelation) float64 {
	switch correlation.Method {
	case CorrelationExact:
		return 1.0 // Highest reliability
	case CorrelationFuzzy:
		return 0.8 // High reliability
	case CorrelationContextual:
		return 0.7 // Good reliability
	case CorrelationHeuristic:
		return 0.5 // Moderate reliability
	default:
		return 0.3 // Low reliability for unknown methods
	}
}

// calculateDocumentStructureScore calculates the document structure consistency factor
func (dpv *DefaultPositionValidator) calculateDocumentStructureScore(correlation *PositionCorrelation, originalContent []byte) float64 {
	// For now, return a neutral score
	// In a more sophisticated implementation, this would analyze document structure consistency
	return 0.7
}

// calculateStringSimilarity calculates similarity between two strings
func (dpv *DefaultPositionValidator) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Use a simple similarity metric based on common characters
	s1Lower := strings.ToLower(s1)
	s2Lower := strings.ToLower(s2)

	// Count common characters
	commonChars := 0
	s1Chars := make(map[rune]int)
	s2Chars := make(map[rune]int)

	for _, r := range s1Lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			s1Chars[r]++
		}
	}

	for _, r := range s2Lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			s2Chars[r]++
		}
	}

	for r, count1 := range s1Chars {
		if count2, exists := s2Chars[r]; exists {
			commonChars += min(count1, count2)
		}
	}

	totalChars := len(s1Chars) + len(s2Chars)
	if totalChars == 0 {
		return 0.0
	}

	return float64(commonChars*2) / float64(totalChars)
}

// positionsOverlap checks if two correlations have overlapping positions
func (dpv *DefaultPositionValidator) positionsOverlap(corr1, corr2 *PositionCorrelation) bool {
	// Check if extracted positions overlap
	if corr1.ExtractedPosition.Line == corr2.ExtractedPosition.Line {
		return !(corr1.ExtractedPosition.EndChar <= corr2.ExtractedPosition.StartChar ||
			corr2.ExtractedPosition.EndChar <= corr1.ExtractedPosition.StartChar)
	}
	return false
}

// Helper functions are defined in correlator.go
