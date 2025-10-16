// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package strategies

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
)

// RedactionStrategyImplementation defines the interface for redaction strategy implementations
type RedactionStrategyImplementation interface {
	// GetStrategyType returns the redaction strategy type
	GetStrategyType() redactors.RedactionStrategy

	// RedactText redacts the given text based on the data type and strategy
	RedactText(originalText, dataType string, context RedactionContext) (*RedactionResult, error)

	// GetSupportedDataTypes returns the data types this strategy can handle
	GetSupportedDataTypes() []string

	// GetStrategyName returns the name of the strategy implementation
	GetStrategyName() string

	// ValidateRedaction validates that the redaction was performed correctly
	ValidateRedaction(original, redacted, dataType string) (*ValidationResult, error)
}

// RedactionContext provides context for redaction operations
type RedactionContext struct {
	// Match contains the original detector match information
	Match detector.Match

	// PreserveFormat indicates whether to preserve the original format
	PreserveFormat bool

	// PreserveLength indicates whether to preserve the original length
	PreserveLength bool

	// SecurityLevel indicates the required security level (1-5, 5 being highest)
	SecurityLevel int

	// Seed provides a seed for deterministic generation (optional)
	Seed string

	// Metadata contains additional context metadata
	Metadata map[string]interface{}
}

// RedactionResult represents the result of a redaction operation
type RedactionResult struct {
	// RedactedText is the redacted version of the original text
	RedactedText string

	// Strategy is the strategy that was used
	Strategy redactors.RedactionStrategy

	// DataType is the detected data type
	DataType string

	// Confidence is the confidence level of the redaction (0.0 to 1.0)
	Confidence float64

	// PreservedFormat indicates whether the format was preserved
	PreservedFormat bool

	// PreservedLength indicates whether the length was preserved
	PreservedLength bool

	// SecurityLevel is the security level achieved
	SecurityLevel int

	// Metadata contains additional redaction metadata
	Metadata map[string]interface{}

	// Error contains any redaction error
	Error error
}

// ValidationResult represents the result of redaction validation
type ValidationResult struct {
	// Valid indicates whether the redaction is valid
	Valid bool

	// Issues contains any validation issues
	Issues []ValidationIssue

	// SecurityScore is the security score of the redaction (0.0 to 1.0)
	SecurityScore float64

	// FormatScore is the format preservation score (0.0 to 1.0)
	FormatScore float64

	// Confidence is the overall validation confidence (0.0 to 1.0)
	Confidence float64
}

// ValidationIssue represents a validation issue
type ValidationIssue struct {
	// Severity is the severity of the issue
	Severity IssueSeverity

	// Type is the type of issue
	Type IssueType

	// Description is a human-readable description
	Description string

	// Suggestion is a suggested fix
	Suggestion string
}

// IssueSeverity represents the severity of a validation issue
type IssueSeverity int

const (
	// SeverityInfo represents informational issues
	SeverityInfo IssueSeverity = iota
	// SeverityWarning represents warning-level issues
	SeverityWarning
	// SeverityError represents error-level issues
	SeverityError
	// SeverityCritical represents critical security issues
	SeverityCritical
)

// String returns the string representation of the severity
func (s IssueSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// IssueType represents the type of validation issue
type IssueType int

const (
	// IssueTypeSecurity represents security-related issues
	IssueTypeSecurity IssueType = iota
	// IssueTypeFormat represents format preservation issues
	IssueTypeFormat
	// IssueTypeLength represents length preservation issues
	IssueTypeLength
	// IssueTypePattern represents pattern matching issues
	IssueTypePattern
	// IssueTypeReversibility represents reversibility issues
	IssueTypeReversibility
)

// String returns the string representation of the issue type
func (t IssueType) String() string {
	switch t {
	case IssueTypeSecurity:
		return "security"
	case IssueTypeFormat:
		return "format"
	case IssueTypeLength:
		return "length"
	case IssueTypePattern:
		return "pattern"
	case IssueTypeReversibility:
		return "reversibility"
	default:
		return "unknown"
	}
}

// StrategyManager manages redaction strategy implementations
type StrategyManager struct {
	// strategies maps strategy types to their implementations
	strategies map[redactors.RedactionStrategy]RedactionStrategyImplementation

	// observer handles observability and metrics
	observer *observability.StandardObserver

	// config contains strategy configuration
	config *StrategyConfig

	// stats tracks strategy statistics
	stats *StrategyStats
}

// StrategyConfig contains configuration for redaction strategies
type StrategyConfig struct {
	// DefaultSecurityLevel is the default security level (1-5)
	DefaultSecurityLevel int

	// EnableFormatPreservation enables format preservation by default
	EnableFormatPreservation bool

	// EnableLengthPreservation enables length preservation by default
	EnableLengthPreservation bool

	// CryptographicSeed is the seed for cryptographic operations
	CryptographicSeed string

	// ValidationEnabled enables redaction validation
	ValidationEnabled bool

	// SecurityTestingEnabled enables security testing
	SecurityTestingEnabled bool
}

// StrategyStats tracks statistics for redaction strategies
type StrategyStats struct {
	// TotalRedactions is the total number of redactions performed
	TotalRedactions int64

	// SuccessfulRedactions is the number of successful redactions
	SuccessfulRedactions int64

	// FailedRedactions is the number of failed redactions
	FailedRedactions int64

	// RedactionsByStrategy tracks redactions per strategy
	RedactionsByStrategy map[redactors.RedactionStrategy]int64

	// RedactionsByDataType tracks redactions per data type
	RedactionsByDataType map[string]int64

	// AverageConfidence is the average redaction confidence
	AverageConfidence float64

	// SecurityScores tracks security scores
	SecurityScores []float64

	// FormatPreservationRate is the rate of successful format preservation
	FormatPreservationRate float64

	// LengthPreservationRate is the rate of successful length preservation
	LengthPreservationRate float64
}

// NewStrategyManager creates a new StrategyManager
func NewStrategyManager(observer *observability.StandardObserver) *StrategyManager {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	config := &StrategyConfig{
		DefaultSecurityLevel:     3,
		EnableFormatPreservation: true,
		EnableLengthPreservation: true,
		CryptographicSeed:        generateCryptographicSeed(),
		ValidationEnabled:        true,
		SecurityTestingEnabled:   true,
	}

	stats := &StrategyStats{
		RedactionsByStrategy: make(map[redactors.RedactionStrategy]int64),
		RedactionsByDataType: make(map[string]int64),
		SecurityScores:       make([]float64, 0),
	}

	return &StrategyManager{
		strategies: make(map[redactors.RedactionStrategy]RedactionStrategyImplementation),
		observer:   observer,
		config:     config,
		stats:      stats,
	}
}

// RegisterStrategy registers a redaction strategy implementation
func (sm *StrategyManager) RegisterStrategy(strategy RedactionStrategyImplementation) error {
	if strategy == nil {
		return fmt.Errorf("strategy cannot be nil")
	}

	strategyType := strategy.GetStrategyType()
	sm.strategies[strategyType] = strategy

	sm.logEvent("strategy_registered", true, map[string]interface{}{
		"strategy_type":   strategyType.String(),
		"strategy_name":   strategy.GetStrategyName(),
		"supported_types": strategy.GetSupportedDataTypes(),
	})

	return nil
}

// RedactText performs redaction using the specified strategy
func (sm *StrategyManager) RedactText(originalText, dataType string, strategy redactors.RedactionStrategy, context RedactionContext) (*RedactionResult, error) {
	strategyImpl, exists := sm.strategies[strategy]
	if !exists {
		return nil, fmt.Errorf("strategy %s not registered", strategy.String())
	}

	// Check if strategy supports the data type
	supportedTypes := strategyImpl.GetSupportedDataTypes()
	supported := false
	for _, supportedType := range supportedTypes {
		if supportedType == dataType || supportedType == "*" {
			supported = true
			break
		}
	}

	if !supported {
		return nil, fmt.Errorf("strategy %s does not support data type %s", strategy.String(), dataType)
	}

	// Apply default configuration to context
	if context.SecurityLevel == 0 {
		context.SecurityLevel = sm.config.DefaultSecurityLevel
	}
	if !context.PreserveFormat && sm.config.EnableFormatPreservation {
		context.PreserveFormat = true
	}
	if !context.PreserveLength && sm.config.EnableLengthPreservation {
		context.PreserveLength = true
	}

	// Perform redaction
	result, err := strategyImpl.RedactText(originalText, dataType, context)
	if err != nil {
		sm.updateStats(func(stats *StrategyStats) {
			stats.TotalRedactions++
			stats.FailedRedactions++
			stats.RedactionsByStrategy[strategy]++
			stats.RedactionsByDataType[dataType]++
		})
		return nil, fmt.Errorf("redaction failed: %w", err)
	}

	// Validate redaction if enabled
	if sm.config.ValidationEnabled {
		validation, err := strategyImpl.ValidateRedaction(originalText, result.RedactedText, dataType)
		if err != nil {
			sm.logEvent("validation_failed", false, map[string]interface{}{
				"strategy":  strategy.String(),
				"data_type": dataType,
				"error":     err.Error(),
			})
		} else {
			result.Confidence = validation.Confidence
			result.SecurityLevel = int(validation.SecurityScore * 5) // Convert to 1-5 scale
		}
	}

	// Update statistics
	sm.updateStats(func(stats *StrategyStats) {
		stats.TotalRedactions++
		stats.SuccessfulRedactions++
		stats.RedactionsByStrategy[strategy]++
		stats.RedactionsByDataType[dataType]++

		// Update average confidence
		totalConfidence := stats.AverageConfidence * float64(stats.SuccessfulRedactions-1)
		stats.AverageConfidence = (totalConfidence + result.Confidence) / float64(stats.SuccessfulRedactions)

		// Track security scores
		if result.SecurityLevel > 0 {
			stats.SecurityScores = append(stats.SecurityScores, float64(result.SecurityLevel)/5.0)
		}

		// Update preservation rates
		if result.PreservedFormat {
			stats.FormatPreservationRate = (stats.FormatPreservationRate*float64(stats.SuccessfulRedactions-1) + 1.0) / float64(stats.SuccessfulRedactions)
		} else {
			stats.FormatPreservationRate = (stats.FormatPreservationRate * float64(stats.SuccessfulRedactions-1)) / float64(stats.SuccessfulRedactions)
		}

		if result.PreservedLength {
			stats.LengthPreservationRate = (stats.LengthPreservationRate*float64(stats.SuccessfulRedactions-1) + 1.0) / float64(stats.SuccessfulRedactions)
		} else {
			stats.LengthPreservationRate = (stats.LengthPreservationRate * float64(stats.SuccessfulRedactions-1)) / float64(stats.SuccessfulRedactions)
		}
	})

	sm.logEvent("redaction_completed", true, map[string]interface{}{
		"strategy":         strategy.String(),
		"data_type":        dataType,
		"original_length":  len(originalText),
		"redacted_length":  len(result.RedactedText),
		"confidence":       result.Confidence,
		"security_level":   result.SecurityLevel,
		"preserved_format": result.PreservedFormat,
		"preserved_length": result.PreservedLength,
	})

	return result, nil
}

// GetStats returns current strategy statistics
func (sm *StrategyManager) GetStats() *StrategyStats {
	// Return a copy to avoid race conditions
	stats := &StrategyStats{
		TotalRedactions:        sm.stats.TotalRedactions,
		SuccessfulRedactions:   sm.stats.SuccessfulRedactions,
		FailedRedactions:       sm.stats.FailedRedactions,
		AverageConfidence:      sm.stats.AverageConfidence,
		FormatPreservationRate: sm.stats.FormatPreservationRate,
		LengthPreservationRate: sm.stats.LengthPreservationRate,
		RedactionsByStrategy:   make(map[redactors.RedactionStrategy]int64),
		RedactionsByDataType:   make(map[string]int64),
		SecurityScores:         make([]float64, len(sm.stats.SecurityScores)),
	}

	// Copy maps and slices
	for strategy, count := range sm.stats.RedactionsByStrategy {
		stats.RedactionsByStrategy[strategy] = count
	}
	for dataType, count := range sm.stats.RedactionsByDataType {
		stats.RedactionsByDataType[dataType] = count
	}
	copy(stats.SecurityScores, sm.stats.SecurityScores)

	return stats
}

// updateStats safely updates statistics using a callback function
func (sm *StrategyManager) updateStats(updateFunc func(*StrategyStats)) {
	// Note: In a real implementation, this should use proper synchronization
	updateFunc(sm.stats)
}

// logEvent logs an event if observer is available
func (sm *StrategyManager) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if sm.observer != nil {
		sm.observer.StartTiming("strategy_manager", operation, "")(success, metadata)
	}
}

// generateCryptographicSeed generates a cryptographically secure seed
func generateCryptographicSeed() string {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to time-based seed if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Hash the random bytes to create a consistent seed
	hash := sha256.Sum256(bytes)
	return fmt.Sprintf("%x", hash)
}

// generateSecureRandom generates a cryptographically secure random number in the given range
func generateSecureRandom(min, max int64) (int64, error) {
	if min >= max {
		return 0, fmt.Errorf("invalid range: min (%d) must be less than max (%d)", min, max)
	}

	// Calculate the range
	rangeSize := max - min

	// Generate a random number in the range [0, rangeSize)
	randomBig, err := rand.Int(rand.Reader, big.NewInt(rangeSize))
	if err != nil {
		return 0, fmt.Errorf("failed to generate secure random number: %w", err)
	}

	return randomBig.Int64() + min, nil
}

// preserveFormat preserves the format of the original text in the redacted text
func preserveFormat(original, replacement string) string {
	if len(original) == 0 {
		return replacement
	}

	result := make([]rune, 0, len(original))
	replacementRunes := []rune(replacement)
	replacementIndex := 0

	for _, char := range original {
		if replacementIndex >= len(replacementRunes) {
			// If we've used all replacement characters, repeat the pattern
			replacementIndex = 0
		}

		switch {
		case char >= '0' && char <= '9':
			// Preserve numeric positions
			if replacementIndex < len(replacementRunes) {
				replacementChar := replacementRunes[replacementIndex]
				if replacementChar >= '0' && replacementChar <= '9' {
					result = append(result, replacementChar)
				} else {
					result = append(result, '0') // Default to 0 if replacement isn't numeric
				}
				replacementIndex++
			} else {
				result = append(result, '0')
			}
		case (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z'):
			// Preserve alphabetic positions
			if replacementIndex < len(replacementRunes) {
				replacementChar := replacementRunes[replacementIndex]
				if (replacementChar >= 'a' && replacementChar <= 'z') || (replacementChar >= 'A' && replacementChar <= 'Z') {
					// Preserve case
					if char >= 'A' && char <= 'Z' {
						result = append(result, toUpper(replacementChar))
					} else {
						result = append(result, toLower(replacementChar))
					}
				} else {
					// Default to 'X' for uppercase, 'x' for lowercase
					if char >= 'A' && char <= 'Z' {
						result = append(result, 'X')
					} else {
						result = append(result, 'x')
					}
				}
				replacementIndex++
			} else {
				if char >= 'A' && char <= 'Z' {
					result = append(result, 'X')
				} else {
					result = append(result, 'x')
				}
			}
		default:
			// Preserve special characters and spaces
			result = append(result, char)
		}
	}

	return string(result)
}

// toUpper converts a character to uppercase
func toUpper(char rune) rune {
	if char >= 'a' && char <= 'z' {
		return char - 'a' + 'A'
	}
	return char
}

// toLower converts a character to lowercase
func toLower(char rune) rune {
	if char >= 'A' && char <= 'Z' {
		return char - 'A' + 'a'
	}
	return char
}

// validatePattern validates that a string matches a given pattern
func validatePattern(text, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return regex.MatchString(text)
}
