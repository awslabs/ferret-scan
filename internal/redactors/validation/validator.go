// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
)

// DocumentValidator defines the interface for document validation
type DocumentValidator interface {
	// ValidateStructure validates the structural integrity of a document
	ValidateStructure(filePath string) (*ValidationResult, error)

	// ValidateRedaction validates that redaction was performed correctly
	ValidateRedaction(originalPath, redactedPath string, redactionResult *redactors.RedactionResult) (*ValidationResult, error)

	// GetSupportedTypes returns the file types this validator can handle
	GetSupportedTypes() []string

	// GetValidatorName returns the name of the validator
	GetValidatorName() string

	// GetComponentName returns the component name for observability
	GetComponentName() string
}

// ValidationResult represents the result of a document validation
type ValidationResult struct {
	// Success indicates whether validation passed
	Success bool

	// ValidationTime is the time taken for validation
	ValidationTime time.Duration

	// Confidence is the confidence level of the validation (0.0 to 1.0)
	Confidence float64

	// Issues contains any validation issues found
	Issues []ValidationIssue

	// Metrics contains validation metrics
	Metrics ValidationMetrics

	// Metadata contains additional validation metadata
	Metadata map[string]interface{}

	// Error contains any validation error
	Error error
}

// ValidationIssue represents a specific validation issue
type ValidationIssue struct {
	// Severity indicates the severity of the issue
	Severity IssueSeverity

	// Type categorizes the type of issue
	Type IssueType

	// Description provides a human-readable description
	Description string

	// Location indicates where the issue was found
	Location IssueLocation

	// Suggestion provides a suggested fix or action
	Suggestion string

	// Metadata contains additional issue-specific data
	Metadata map[string]interface{}
}

// IssueSeverity represents the severity level of a validation issue
type IssueSeverity int

const (
	// SeverityInfo represents informational issues
	SeverityInfo IssueSeverity = iota
	// SeverityWarning represents warning-level issues
	SeverityWarning
	// SeverityError represents error-level issues
	SeverityError
	// SeverityCritical represents critical issues that prevent processing
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
	// IssueTypeStructural represents structural integrity issues
	IssueTypeStructural IssueType = iota
	// IssueTypeFormat represents format validation issues
	IssueTypeFormat
	// IssueTypeContent represents content validation issues
	IssueTypeContent
	// IssueTypeRedaction represents redaction-specific issues
	IssueTypeRedaction
	// IssueTypeMetadata represents metadata validation issues
	IssueTypeMetadata
	// IssueTypeCorruption represents file corruption issues
	IssueTypeCorruption
)

// String returns the string representation of the issue type
func (t IssueType) String() string {
	switch t {
	case IssueTypeStructural:
		return "structural"
	case IssueTypeFormat:
		return "format"
	case IssueTypeContent:
		return "content"
	case IssueTypeRedaction:
		return "redaction"
	case IssueTypeMetadata:
		return "metadata"
	case IssueTypeCorruption:
		return "corruption"
	default:
		return "unknown"
	}
}

// IssueLocation represents the location of a validation issue
type IssueLocation struct {
	// FilePath is the path to the file where the issue was found
	FilePath string

	// Component identifies the document component (e.g., "header", "body", "metadata")
	Component string

	// Line indicates the line number (if applicable)
	Line int

	// Column indicates the column number (if applicable)
	Column int

	// Offset indicates the byte offset (if applicable)
	Offset int64

	// Context provides additional location context
	Context string
}

// ValidationMetrics contains metrics about the validation process
type ValidationMetrics struct {
	// FileSize is the size of the validated file
	FileSize int64

	// ProcessingTime is the time taken for validation
	ProcessingTime time.Duration

	// ChecksPerformed is the number of validation checks performed
	ChecksPerformed int

	// IssuesFound is the number of issues found
	IssuesFound int

	// StructuralChecks is the number of structural checks performed
	StructuralChecks int

	// FormatChecks is the number of format checks performed
	FormatChecks int

	// ContentChecks is the number of content checks performed
	ContentChecks int

	// RedactionChecks is the number of redaction-specific checks performed
	RedactionChecks int
}

// ValidationManager manages document validation across multiple validators
type ValidationManager struct {
	// validators maps file extensions to their corresponding validators
	validators map[string]DocumentValidator

	// observer handles observability and metrics
	observer *observability.StandardObserver

	// config contains validation configuration
	config *ValidationConfig

	// stats tracks validation statistics
	stats *ValidationStats
}

// ValidationConfig contains configuration for document validation
type ValidationConfig struct {
	// EnableStructuralValidation enables structural integrity checks
	EnableStructuralValidation bool

	// EnableFormatValidation enables format validation checks
	EnableFormatValidation bool

	// EnableContentValidation enables content validation checks
	EnableContentValidation bool

	// EnableRedactionValidation enables redaction-specific validation
	EnableRedactionValidation bool

	// StrictMode enables strict validation (fail on warnings)
	StrictMode bool

	// MaxValidationTime is the maximum time allowed for validation
	MaxValidationTime time.Duration

	// RecoveryEnabled enables automatic recovery attempts
	RecoveryEnabled bool

	// RecoveryAttempts is the number of recovery attempts to make
	RecoveryAttempts int

	// ValidationCacheEnabled enables caching of validation results
	ValidationCacheEnabled bool

	// ValidationCacheTTL is the time-to-live for cached validation results
	ValidationCacheTTL time.Duration
}

// ValidationStats tracks statistics for validation operations
type ValidationStats struct {
	// TotalValidations is the total number of validations performed
	TotalValidations int64

	// SuccessfulValidations is the number of successful validations
	SuccessfulValidations int64

	// FailedValidations is the number of failed validations
	FailedValidations int64

	// TotalIssuesFound is the total number of issues found
	TotalIssuesFound int64

	// CriticalIssuesFound is the number of critical issues found
	CriticalIssuesFound int64

	// RecoveryAttempts is the number of recovery attempts made
	RecoveryAttempts int64

	// SuccessfulRecoveries is the number of successful recoveries
	SuccessfulRecoveries int64

	// TotalValidationTime is the total time spent on validation
	TotalValidationTime time.Duration

	// ValidatorStats tracks statistics per validator type
	ValidatorStats map[string]*ValidatorStats
}

// ValidatorStats tracks statistics for a specific validator
type ValidatorStats struct {
	// ValidationsPerformed is the number of validations performed
	ValidationsPerformed int64

	// SuccessfulValidations is the number of successful validations
	SuccessfulValidations int64

	// FailedValidations is the number of failed validations
	FailedValidations int64

	// IssuesFound is the number of issues found
	IssuesFound int64

	// AverageValidationTime is the average time per validation
	AverageValidationTime time.Duration

	// LastValidationTime is the time of the last validation
	LastValidationTime time.Time
}

// NewValidationManager creates a new ValidationManager
func NewValidationManager(observer *observability.StandardObserver) *ValidationManager {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	config := &ValidationConfig{
		EnableStructuralValidation: true,
		EnableFormatValidation:     true,
		EnableContentValidation:    true,
		EnableRedactionValidation:  true,
		StrictMode:                 false,
		MaxValidationTime:          time.Minute * 5,
		RecoveryEnabled:            true,
		RecoveryAttempts:           3,
		ValidationCacheEnabled:     true,
		ValidationCacheTTL:         time.Hour * 24,
	}

	stats := &ValidationStats{
		ValidatorStats: make(map[string]*ValidatorStats),
	}

	return &ValidationManager{
		validators: make(map[string]DocumentValidator),
		observer:   observer,
		config:     config,
		stats:      stats,
	}
}

// RegisterValidator registers a document validator for specific file types
func (vm *ValidationManager) RegisterValidator(validator DocumentValidator) error {
	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}

	supportedTypes := validator.GetSupportedTypes()
	if len(supportedTypes) == 0 {
		return fmt.Errorf("validator must support at least one file type")
	}

	// Register validator for each supported type
	for _, fileType := range supportedTypes {
		// Normalize file type (ensure it starts with a dot for extensions)
		normalizedType := fileType
		if !strings.HasPrefix(normalizedType, ".") {
			normalizedType = "." + normalizedType
		}

		vm.validators[normalizedType] = validator
	}

	// Initialize stats for this validator
	vm.stats.ValidatorStats[validator.GetValidatorName()] = &ValidatorStats{
		LastValidationTime: time.Now(),
	}

	vm.logEvent("validator_registered", true, map[string]interface{}{
		"validator_name":   validator.GetValidatorName(),
		"supported_types":  supportedTypes,
		"total_validators": len(vm.validators),
	})

	return nil
}

// GetValidatorForFile returns the appropriate validator for a given file
func (vm *ValidationManager) GetValidatorForFile(filePath string) (DocumentValidator, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return nil, fmt.Errorf("file has no extension: %s", filePath)
	}

	validator, exists := vm.validators[ext]
	if !exists {
		return nil, fmt.Errorf("no validator registered for file type: %s", ext)
	}

	return validator, nil
}

// ValidateDocument validates a document using the appropriate validator
func (vm *ValidationManager) ValidateDocument(filePath string) (*ValidationResult, error) {
	startTime := time.Now()

	validator, err := vm.GetValidatorForFile(filePath)
	if err != nil {
		vm.updateStats(func(stats *ValidationStats) {
			stats.TotalValidations++
			stats.FailedValidations++
		})
		return nil, fmt.Errorf("failed to get validator for file %s: %w", filePath, err)
	}

	// Perform validation with timeout
	resultChan := make(chan *ValidationResult, 1)
	errorChan := make(chan error, 1)

	go func() {
		result, err := validator.ValidateStructure(filePath)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()

	var result *ValidationResult
	select {
	case result = <-resultChan:
		// Validation completed successfully
	case err = <-errorChan:
		// Validation failed
		vm.updateStats(func(stats *ValidationStats) {
			stats.TotalValidations++
			stats.FailedValidations++
		})
		return nil, fmt.Errorf("validation failed: %w", err)
	case <-time.After(vm.config.MaxValidationTime):
		// Validation timed out
		vm.updateStats(func(stats *ValidationStats) {
			stats.TotalValidations++
			stats.FailedValidations++
		})
		return nil, fmt.Errorf("validation timed out after %v", vm.config.MaxValidationTime)
	}

	processingTime := time.Since(startTime)

	// Update statistics
	vm.updateStats(func(stats *ValidationStats) {
		stats.TotalValidations++
		stats.TotalValidationTime += processingTime

		validatorName := validator.GetValidatorName()
		validatorStats, exists := stats.ValidatorStats[validatorName]
		if !exists {
			validatorStats = &ValidatorStats{}
			stats.ValidatorStats[validatorName] = validatorStats
		}

		validatorStats.ValidationsPerformed++
		validatorStats.LastValidationTime = time.Now()

		if result.Success {
			stats.SuccessfulValidations++
			validatorStats.SuccessfulValidations++
		} else {
			stats.FailedValidations++
			validatorStats.FailedValidations++
		}

		issuesFound := int64(len(result.Issues))
		stats.TotalIssuesFound += issuesFound
		validatorStats.IssuesFound += issuesFound

		// Count critical issues
		for _, issue := range result.Issues {
			if issue.Severity == SeverityCritical {
				stats.CriticalIssuesFound++
			}
		}

		// Update average validation time
		if validatorStats.ValidationsPerformed > 0 {
			validatorStats.AverageValidationTime = time.Duration(
				(int64(validatorStats.AverageValidationTime)*validatorStats.ValidationsPerformed + int64(processingTime)) /
					(validatorStats.ValidationsPerformed + 1),
			)
		}
	})

	vm.logEvent("document_validated", result.Success, map[string]interface{}{
		"file_path":       filePath,
		"validator_name":  validator.GetValidatorName(),
		"validation_time": processingTime,
		"issues_found":    len(result.Issues),
		"confidence":      result.Confidence,
		"success":         result.Success,
	})

	return result, nil
}

// ValidateRedaction validates that redaction was performed correctly
func (vm *ValidationManager) ValidateRedaction(originalPath, redactedPath string, redactionResult *redactors.RedactionResult) (*ValidationResult, error) {
	validator, err := vm.GetValidatorForFile(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get validator for file %s: %w", originalPath, err)
	}

	startTime := time.Now()
	result, err := validator.ValidateRedaction(originalPath, redactedPath, redactionResult)
	processingTime := time.Since(startTime)

	if err != nil {
		vm.updateStats(func(stats *ValidationStats) {
			stats.TotalValidations++
			stats.FailedValidations++
		})
		return nil, fmt.Errorf("redaction validation failed: %w", err)
	}

	// Update statistics
	vm.updateStats(func(stats *ValidationStats) {
		stats.TotalValidations++
		stats.TotalValidationTime += processingTime

		if result.Success {
			stats.SuccessfulValidations++
		} else {
			stats.FailedValidations++
		}

		stats.TotalIssuesFound += int64(len(result.Issues))
	})

	vm.logEvent("redaction_validated", result.Success, map[string]interface{}{
		"original_path":   originalPath,
		"redacted_path":   redactedPath,
		"validator_name":  validator.GetValidatorName(),
		"validation_time": processingTime,
		"issues_found":    len(result.Issues),
		"confidence":      result.Confidence,
	})

	return result, nil
}

// GetStats returns current validation statistics
func (vm *ValidationManager) GetStats() *ValidationStats {
	// Return a copy to avoid race conditions
	stats := &ValidationStats{
		TotalValidations:      vm.stats.TotalValidations,
		SuccessfulValidations: vm.stats.SuccessfulValidations,
		FailedValidations:     vm.stats.FailedValidations,
		TotalIssuesFound:      vm.stats.TotalIssuesFound,
		CriticalIssuesFound:   vm.stats.CriticalIssuesFound,
		RecoveryAttempts:      vm.stats.RecoveryAttempts,
		SuccessfulRecoveries:  vm.stats.SuccessfulRecoveries,
		TotalValidationTime:   vm.stats.TotalValidationTime,
		ValidatorStats:        make(map[string]*ValidatorStats),
	}

	// Copy validator stats
	for name, validatorStats := range vm.stats.ValidatorStats {
		stats.ValidatorStats[name] = &ValidatorStats{
			ValidationsPerformed:  validatorStats.ValidationsPerformed,
			SuccessfulValidations: validatorStats.SuccessfulValidations,
			FailedValidations:     validatorStats.FailedValidations,
			IssuesFound:           validatorStats.IssuesFound,
			AverageValidationTime: validatorStats.AverageValidationTime,
			LastValidationTime:    validatorStats.LastValidationTime,
		}
	}

	return stats
}

// updateStats safely updates statistics using a callback function
func (vm *ValidationManager) updateStats(updateFunc func(*ValidationStats)) {
	// Note: In a real implementation, this should use proper synchronization
	updateFunc(vm.stats)
}

// logEvent logs an event if observer is available
func (vm *ValidationManager) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if vm.observer != nil {
		vm.observer.StartTiming("validation_manager", operation, "")(success, metadata)
	}
}

// GetComponentName returns the component name for observability
func (vm *ValidationManager) GetComponentName() string {
	return "validation_manager"
}
