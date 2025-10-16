// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"time"
)

// RedactionErrorType defines the type of redaction error
type RedactionErrorType int

const (
	// ErrorPositionMapping indicates a position mapping failure
	ErrorPositionMapping RedactionErrorType = iota

	// ErrorDocumentProcessing indicates a document processing failure
	ErrorDocumentProcessing

	// ErrorFileSystem indicates a file system operation failure
	ErrorFileSystem

	// ErrorConfiguration indicates a configuration error
	ErrorConfiguration

	// ErrorValidation indicates a validation error
	ErrorValidation

	// ErrorMemory indicates a memory-related error
	ErrorMemory

	// ErrorSecurity indicates a security-related error
	ErrorSecurity
)

// String returns the string representation of the error type
func (ret RedactionErrorType) String() string {
	switch ret {
	case ErrorPositionMapping:
		return "position_mapping"
	case ErrorDocumentProcessing:
		return "document_processing"
	case ErrorFileSystem:
		return "file_system"
	case ErrorConfiguration:
		return "configuration"
	case ErrorValidation:
		return "validation"
	case ErrorMemory:
		return "memory"
	case ErrorSecurity:
		return "security"
	default:
		return "unknown"
	}
}

// RedactionError represents an error that occurred during redaction
type RedactionError struct {
	// Type is the type of error
	Type RedactionErrorType

	// Message is the error message
	Message string

	// FilePath is the path to the file being processed when the error occurred
	FilePath string

	// Component is the component that generated the error
	Component string

	// Recoverable indicates whether the error is recoverable
	Recoverable bool

	// Timestamp is when the error occurred
	Timestamp time.Time

	// Cause is the underlying error that caused this error
	Cause error
}

// Error implements the error interface
func (re *RedactionError) Error() string {
	if re.FilePath != "" {
		return fmt.Sprintf("[%s] %s (file: %s, component: %s): %s",
			re.Type.String(), re.Message, re.FilePath, re.Component, re.getCauseMessage())
	}
	return fmt.Sprintf("[%s] %s (component: %s): %s",
		re.Type.String(), re.Message, re.Component, re.getCauseMessage())
}

// getCauseMessage returns the cause error message if available
func (re *RedactionError) getCauseMessage() string {
	if re.Cause != nil {
		return re.Cause.Error()
	}
	return ""
}

// Unwrap returns the underlying error for error unwrapping
func (re *RedactionError) Unwrap() error {
	return re.Cause
}

// NewRedactionError creates a new RedactionError
func NewRedactionError(errorType RedactionErrorType, message, filePath, component string, cause error) *RedactionError {
	return &RedactionError{
		Type:        errorType,
		Message:     message,
		FilePath:    filePath,
		Component:   component,
		Recoverable: isRecoverable(errorType),
		Timestamp:   time.Now(),
		Cause:       cause,
	}
}

// isRecoverable determines if an error type is recoverable
func isRecoverable(errorType RedactionErrorType) bool {
	switch errorType {
	case ErrorPositionMapping:
		return true // Can fall back to simple text redaction
	case ErrorDocumentProcessing:
		return true // Can continue with other files
	case ErrorFileSystem:
		return true // Can retry or skip
	case ErrorConfiguration:
		return false // Configuration errors are not recoverable
	case ErrorValidation:
		return true // Can skip invalid data
	case ErrorMemory:
		return false // Memory errors are typically not recoverable
	case ErrorSecurity:
		return false // Security errors should not be ignored
	default:
		return false
	}
}

// RedactionErrorCollection manages a collection of redaction errors
type RedactionErrorCollection struct {
	errors []RedactionError
}

// NewRedactionErrorCollection creates a new error collection
func NewRedactionErrorCollection() *RedactionErrorCollection {
	return &RedactionErrorCollection{
		errors: make([]RedactionError, 0),
	}
}

// Add adds an error to the collection
func (rec *RedactionErrorCollection) Add(err RedactionError) {
	rec.errors = append(rec.errors, err)
}

// AddError adds an error with the specified parameters
func (rec *RedactionErrorCollection) AddError(errorType RedactionErrorType, message, filePath, component string, cause error) {
	rec.Add(*NewRedactionError(errorType, message, filePath, component, cause))
}

// GetErrors returns all errors in the collection
func (rec *RedactionErrorCollection) GetErrors() []RedactionError {
	return rec.errors
}

// HasErrors returns true if the collection contains any errors
func (rec *RedactionErrorCollection) HasErrors() bool {
	return len(rec.errors) > 0
}

// HasRecoverableErrors returns true if the collection contains any recoverable errors
func (rec *RedactionErrorCollection) HasRecoverableErrors() bool {
	for _, err := range rec.errors {
		if err.Recoverable {
			return true
		}
	}
	return false
}

// HasUnrecoverableErrors returns true if the collection contains any unrecoverable errors
func (rec *RedactionErrorCollection) HasUnrecoverableErrors() bool {
	for _, err := range rec.errors {
		if !err.Recoverable {
			return true
		}
	}
	return false
}

// GetErrorsByType returns all errors of the specified type
func (rec *RedactionErrorCollection) GetErrorsByType(errorType RedactionErrorType) []RedactionError {
	var result []RedactionError
	for _, err := range rec.errors {
		if err.Type == errorType {
			result = append(result, err)
		}
	}
	return result
}

// GetErrorsByFile returns all errors for the specified file
func (rec *RedactionErrorCollection) GetErrorsByFile(filePath string) []RedactionError {
	var result []RedactionError
	for _, err := range rec.errors {
		if err.FilePath == filePath {
			result = append(result, err)
		}
	}
	return result
}

// Clear removes all errors from the collection
func (rec *RedactionErrorCollection) Clear() {
	rec.errors = rec.errors[:0]
}

// Count returns the number of errors in the collection
func (rec *RedactionErrorCollection) Count() int {
	return len(rec.errors)
}
