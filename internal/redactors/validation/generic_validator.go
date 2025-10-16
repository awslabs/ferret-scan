// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
)

// GenericDocumentValidator provides basic validation for any document type
type GenericDocumentValidator struct {
	// observer handles observability and metrics
	observer *observability.StandardObserver

	// supportedTypes lists the file types this validator can handle
	supportedTypes []string

	// validatorName is the name of this validator
	validatorName string
}

// NewGenericDocumentValidator creates a new generic document validator
func NewGenericDocumentValidator(observer *observability.StandardObserver) *GenericDocumentValidator {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	// Generic validator supports all common document types
	supportedTypes := []string{
		".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".csv",
		".pdf", ".docx", ".xlsx", ".pptx",
		".jpg", ".jpeg", ".png", ".gif", ".tiff", ".bmp", ".webp",
	}

	return &GenericDocumentValidator{
		observer:       observer,
		supportedTypes: supportedTypes,
		validatorName:  "generic_document_validator",
	}
}

// GetValidatorName returns the name of the validator
func (gdv *GenericDocumentValidator) GetValidatorName() string {
	return gdv.validatorName
}

// GetSupportedTypes returns the file types this validator can handle
func (gdv *GenericDocumentValidator) GetSupportedTypes() []string {
	return gdv.supportedTypes
}

// GetComponentName returns the component name for observability
func (gdv *GenericDocumentValidator) GetComponentName() string {
	return "generic_document_validator"
}

// ValidateStructure validates the structural integrity of a document
func (gdv *GenericDocumentValidator) ValidateStructure(filePath string) (*ValidationResult, error) {
	startTime := time.Now()

	result := &ValidationResult{
		Success:    true,
		Confidence: 1.0,
		Issues:     []ValidationIssue{},
		Metrics: ValidationMetrics{
			ProcessingTime: 0,
		},
		Metadata: make(map[string]interface{}),
	}

	// Basic file existence and accessibility checks
	issues := []ValidationIssue{}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityCritical,
				Type:        IssueTypeStructural,
				Description: "File does not exist",
				Location: IssueLocation{
					FilePath: filePath,
				},
				Suggestion: "Ensure the file path is correct and the file exists",
				Metadata: map[string]interface{}{
					"error": err.Error(),
				},
			})
		} else {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityError,
				Type:        IssueTypeStructural,
				Description: "Cannot access file",
				Location: IssueLocation{
					FilePath: filePath,
				},
				Suggestion: "Check file permissions and accessibility",
				Metadata: map[string]interface{}{
					"error": err.Error(),
				},
			})
		}
		result.Success = false
		result.Confidence = 0.0
	} else {
		// File exists, perform basic checks
		result.Metrics.FileSize = fileInfo.Size()

		// Check if file is empty
		if fileInfo.Size() == 0 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeContent,
				Description: "File is empty",
				Location: IssueLocation{
					FilePath: filePath,
				},
				Suggestion: "Verify that the file should contain content",
				Metadata: map[string]interface{}{
					"file_size": fileInfo.Size(),
				},
			})
			result.Confidence = 0.5
		}

		// Check if file is unusually large (potential corruption indicator)
		if fileInfo.Size() > 100*1024*1024 { // 100MB
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeStructural,
				Description: "File is unusually large",
				Location: IssueLocation{
					FilePath: filePath,
				},
				Suggestion: "Verify file integrity and consider if size is expected",
				Metadata: map[string]interface{}{
					"file_size": fileInfo.Size(),
					"size_mb":   fileInfo.Size() / (1024 * 1024),
				},
			})
		}

		// Check file extension consistency
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == "" {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeFormat,
				Description: "File has no extension",
				Location: IssueLocation{
					FilePath: filePath,
				},
				Suggestion: "Consider adding appropriate file extension",
				Metadata: map[string]interface{}{
					"filename": filepath.Base(filePath),
				},
			})
		}

		// Try to read the file to check for basic accessibility
		file, err := os.Open(filePath)
		if err != nil {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityError,
				Type:        IssueTypeStructural,
				Description: "Cannot open file for reading",
				Location: IssueLocation{
					FilePath: filePath,
				},
				Suggestion: "Check file permissions and locks",
				Metadata: map[string]interface{}{
					"error": err.Error(),
				},
			})
			result.Success = false
			result.Confidence = 0.2
		} else {
			file.Close()

			// Perform basic content validation based on file type
			contentIssues := gdv.validateContentByType(filePath, ext)
			issues = append(issues, contentIssues...)
		}
	}

	// Update result
	result.Issues = issues
	result.ValidationTime = time.Since(startTime)
	result.Metrics.ProcessingTime = result.ValidationTime
	result.Metrics.ChecksPerformed = len(issues) + 3 // Basic checks performed
	result.Metrics.IssuesFound = len(issues)

	// Categorize checks
	for _, issue := range issues {
		switch issue.Type {
		case IssueTypeStructural:
			result.Metrics.StructuralChecks++
		case IssueTypeFormat:
			result.Metrics.FormatChecks++
		case IssueTypeContent:
			result.Metrics.ContentChecks++
		}
	}

	// Adjust success based on critical issues
	hasCriticalIssues := false
	for _, issue := range issues {
		if issue.Severity == SeverityCritical {
			hasCriticalIssues = true
			break
		}
	}

	if hasCriticalIssues {
		result.Success = false
	}

	gdv.logEvent("structure_validated", result.Success, map[string]interface{}{
		"file_path":       filePath,
		"file_size":       result.Metrics.FileSize,
		"issues_found":    len(issues),
		"validation_time": result.ValidationTime,
		"confidence":      result.Confidence,
	})

	return result, nil
}

// validateContentByType performs basic content validation based on file type
func (gdv *GenericDocumentValidator) validateContentByType(filePath, ext string) []ValidationIssue {
	var issues []ValidationIssue

	switch ext {
	case ".json":
		issues = append(issues, gdv.validateJSONContent(filePath)...)
	case ".yaml", ".yml":
		issues = append(issues, gdv.validateYAMLContent(filePath)...)
	case ".xml":
		issues = append(issues, gdv.validateXMLContent(filePath)...)
	case ".csv":
		issues = append(issues, gdv.validateCSVContent(filePath)...)
	default:
		// For other file types, perform basic text validation
		issues = append(issues, gdv.validateTextContent(filePath)...)
	}

	return issues
}

// validateJSONContent performs basic JSON validation
func (gdv *GenericDocumentValidator) validateJSONContent(filePath string) []ValidationIssue {
	var issues []ValidationIssue

	content, err := os.ReadFile(filePath)
	if err != nil {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypeContent,
			Description: "Cannot read file content",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Check file accessibility",
			Metadata:    map[string]interface{}{"error": err.Error()},
		})
		return issues
	}

	// Basic JSON structure check
	contentStr := string(content)
	if !strings.HasPrefix(strings.TrimSpace(contentStr), "{") && !strings.HasPrefix(strings.TrimSpace(contentStr), "[") {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypeFormat,
			Description: "File does not appear to contain valid JSON structure",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Verify JSON format and structure",
		})
	}

	return issues
}

// validateYAMLContent performs basic YAML validation
func (gdv *GenericDocumentValidator) validateYAMLContent(filePath string) []ValidationIssue {
	var issues []ValidationIssue

	content, err := os.ReadFile(filePath)
	if err != nil {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypeContent,
			Description: "Cannot read file content",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Check file accessibility",
			Metadata:    map[string]interface{}{"error": err.Error()},
		})
		return issues
	}

	// Basic YAML structure check (very basic)
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Check for basic YAML syntax issues
		if strings.Contains(line, "\t") {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeFormat,
				Description: "YAML file contains tabs (should use spaces)",
				Location:    IssueLocation{FilePath: filePath, Line: i + 1},
				Suggestion:  "Replace tabs with spaces for YAML compatibility",
			})
		}
	}

	return issues
}

// validateXMLContent performs basic XML validation
func (gdv *GenericDocumentValidator) validateXMLContent(filePath string) []ValidationIssue {
	var issues []ValidationIssue

	content, err := os.ReadFile(filePath)
	if err != nil {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypeContent,
			Description: "Cannot read file content",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Check file accessibility",
			Metadata:    map[string]interface{}{"error": err.Error()},
		})
		return issues
	}

	// Basic XML structure check
	contentStr := strings.TrimSpace(string(content))
	if !strings.HasPrefix(contentStr, "<?xml") && !strings.HasPrefix(contentStr, "<") {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypeFormat,
			Description: "File does not appear to contain valid XML structure",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Verify XML format and structure",
		})
	}

	return issues
}

// validateCSVContent performs basic CSV validation
func (gdv *GenericDocumentValidator) validateCSVContent(filePath string) []ValidationIssue {
	var issues []ValidationIssue

	content, err := os.ReadFile(filePath)
	if err != nil {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypeContent,
			Description: "Cannot read file content",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Check file accessibility",
			Metadata:    map[string]interface{}{"error": err.Error()},
		})
		return issues
	}

	// Basic CSV structure check
	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypeContent,
			Description: "CSV file has fewer than 2 lines (may be missing header or data)",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Verify CSV structure and content",
			Metadata:    map[string]interface{}{"line_count": len(lines)},
		})
	}

	return issues
}

// validateTextContent performs basic text validation
func (gdv *GenericDocumentValidator) validateTextContent(filePath string) []ValidationIssue {
	var issues []ValidationIssue

	content, err := os.ReadFile(filePath)
	if err != nil {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypeContent,
			Description: "Cannot read file content",
			Location:    IssueLocation{FilePath: filePath},
			Suggestion:  "Check file accessibility",
			Metadata:    map[string]interface{}{"error": err.Error()},
		})
		return issues
	}

	// Check for binary content in text files
	for i, b := range content {
		if b == 0 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeContent,
				Description: "File contains null bytes (may be binary content)",
				Location:    IssueLocation{FilePath: filePath, Offset: int64(i)},
				Suggestion:  "Verify file type and content",
			})
			break
		}
	}

	return issues
}

// ValidateRedaction validates that redaction was performed correctly
func (gdv *GenericDocumentValidator) ValidateRedaction(originalPath, redactedPath string, redactionResult *redactors.RedactionResult) (*ValidationResult, error) {
	startTime := time.Now()

	result := &ValidationResult{
		Success:    true,
		Confidence: 1.0,
		Issues:     []ValidationIssue{},
		Metrics: ValidationMetrics{
			ProcessingTime: 0,
		},
		Metadata: make(map[string]interface{}),
	}

	var issues []ValidationIssue

	// Validate that both files exist
	if _, err := os.Stat(originalPath); os.IsNotExist(err) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityCritical,
			Type:        IssueTypeRedaction,
			Description: "Original file does not exist",
			Location:    IssueLocation{FilePath: originalPath},
			Suggestion:  "Ensure original file path is correct",
		})
	}

	if _, err := os.Stat(redactedPath); os.IsNotExist(err) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityCritical,
			Type:        IssueTypeRedaction,
			Description: "Redacted file does not exist",
			Location:    IssueLocation{FilePath: redactedPath},
			Suggestion:  "Ensure redaction process completed successfully",
		})
	}

	// If redaction result is provided, validate it
	if redactionResult != nil {
		// Check if redaction was successful
		if !redactionResult.Success {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityError,
				Type:        IssueTypeRedaction,
				Description: "Redaction process reported failure",
				Location:    IssueLocation{FilePath: originalPath},
				Suggestion:  "Review redaction process and error details",
				Metadata: map[string]interface{}{
					"redaction_error": redactionResult.Error,
				},
			})
		}

		// Validate redaction mappings
		if len(redactionResult.RedactionMap) == 0 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeRedaction,
				Description: "No redaction mappings found",
				Location:    IssueLocation{FilePath: originalPath},
				Suggestion:  "Verify that sensitive data was detected and redacted",
			})
		}

		// Check redaction confidence
		if redactionResult.Confidence < 0.5 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeRedaction,
				Description: "Low redaction confidence",
				Location:    IssueLocation{FilePath: originalPath},
				Suggestion:  "Review redaction results for accuracy",
				Metadata: map[string]interface{}{
					"confidence": redactionResult.Confidence,
				},
			})
		}
	}

	// Basic file size comparison
	originalInfo, err1 := os.Stat(originalPath)
	redactedInfo, err2 := os.Stat(redactedPath)

	if err1 == nil && err2 == nil {
		originalSize := originalInfo.Size()
		redactedSize := redactedInfo.Size()

		result.Metrics.FileSize = redactedSize

		// Check if redacted file is significantly larger (potential issue)
		if redactedSize > originalSize*2 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypeRedaction,
				Description: "Redacted file is significantly larger than original",
				Location:    IssueLocation{FilePath: redactedPath},
				Suggestion:  "Review redaction process for potential issues",
				Metadata: map[string]interface{}{
					"original_size": originalSize,
					"redacted_size": redactedSize,
					"size_ratio":    float64(redactedSize) / float64(originalSize),
				},
			})
		}

		// Check if redacted file is empty when original wasn't
		if originalSize > 0 && redactedSize == 0 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityError,
				Type:        IssueTypeRedaction,
				Description: "Redacted file is empty while original contained data",
				Location:    IssueLocation{FilePath: redactedPath},
				Suggestion:  "Review redaction process for data loss",
				Metadata: map[string]interface{}{
					"original_size": originalSize,
					"redacted_size": redactedSize,
				},
			})
			result.Success = false
		}
	}

	// Update result
	result.Issues = issues
	result.ValidationTime = time.Since(startTime)
	result.Metrics.ProcessingTime = result.ValidationTime
	result.Metrics.ChecksPerformed = len(issues) + 2 // Basic checks performed
	result.Metrics.IssuesFound = len(issues)
	result.Metrics.RedactionChecks = len(issues)

	// Adjust success based on critical issues
	hasCriticalIssues := false
	for _, issue := range issues {
		if issue.Severity == SeverityCritical {
			hasCriticalIssues = true
			break
		}
	}

	if hasCriticalIssues {
		result.Success = false
		result.Confidence = 0.0
	} else if len(issues) > 0 {
		// Reduce confidence based on number of issues
		result.Confidence = 1.0 - (float64(len(issues)) * 0.1)
		if result.Confidence < 0.1 {
			result.Confidence = 0.1
		}
	}

	gdv.logEvent("redaction_validated", result.Success, map[string]interface{}{
		"original_path":   originalPath,
		"redacted_path":   redactedPath,
		"issues_found":    len(issues),
		"validation_time": result.ValidationTime,
		"confidence":      result.Confidence,
	})

	return result, nil
}

// logEvent logs an event if observer is available
func (gdv *GenericDocumentValidator) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if gdv.observer != nil {
		gdv.observer.StartTiming("generic_document_validator", operation, "")(success, metadata)
	}
}
