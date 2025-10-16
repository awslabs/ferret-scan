// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import "fmt"

// FormatterError represents errors that occur during formatting
type FormatterError struct {
	Message string
	Cause   error
}

// NewFormatterError creates a new formatter error
func NewFormatterError(message string, cause error) *FormatterError {
	return &FormatterError{
		Message: message,
		Cause:   cause,
	}
}

// Error implements the error interface
func (e *FormatterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("formatter error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("formatter error: %s", e.Message)
}

// Unwrap returns the underlying cause
func (e *FormatterError) Unwrap() error {
	return e.Cause
}

// ValidationError represents schema validation errors
type ValidationError struct {
	Message string
}

// NewValidationError creates a new validation error
func NewValidationError(format string, args ...interface{}) *ValidationError {
	return &ValidationError{
		Message: fmt.Sprintf(format, args...),
	}
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s", e.Message)
}

// MappingError represents errors during vulnerability mapping
type MappingError struct {
	Message string
}

// NewMappingError creates a new mapping error
func NewMappingError(message string) *MappingError {
	return &MappingError{
		Message: message,
	}
}

// Error implements the error interface
func (e *MappingError) Error() string {
	return fmt.Sprintf("mapping error: %s", e.Message)
}

// SanitizationError represents errors during data sanitization
type SanitizationError struct {
	Message string
}

// NewSanitizationError creates a new sanitization error
func NewSanitizationError(message string) *SanitizationError {
	return &SanitizationError{
		Message: message,
	}
}

// Error implements the error interface
func (e *SanitizationError) Error() string {
	return fmt.Sprintf("sanitization error: %s", e.Message)
}
