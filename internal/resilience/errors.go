// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// ErrorType represents different types of errors for handling strategies
type ErrorType int

const (
	ErrorTypeUnknown            ErrorType = iota
	ErrorTypeTransient                    // Temporary network issues, rate limits
	ErrorTypePermanent                    // Invalid credentials, permissions
	ErrorTypeTimeout                      // Request timeouts
	ErrorTypeRateLimit                    // API rate limiting
	ErrorTypeQuotaExceeded                // Service quotas exceeded
	ErrorTypeServiceUnavailable           // Service downtime
	ErrorTypeInvalidInput                 // Bad input data
	ErrorTypeResourceNotFound             // Missing resources
)

// ClassifiedError wraps an error with type information
type ClassifiedError struct {
	Original  error
	Type      ErrorType
	Message   string
	Retryable bool
}

func (e *ClassifiedError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Original.Error()
}

func (e *ClassifiedError) Unwrap() error {
	return e.Original
}

// IsRetryable returns whether this error should be retried
func (e *ClassifiedError) IsRetryable() bool {
	return e.Retryable
}

// ClassifyError categorizes an error for appropriate handling
func ClassifyError(err error) *ClassifiedError {
	if err == nil {
		return nil
	}

	// Check if already classified
	if classified, ok := err.(*ClassifiedError); ok {
		return classified
	}

	errStr := strings.ToLower(err.Error())

	// Network-related errors (transient)
	if isNetworkError(err) {
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeTransient,
			Message:   fmt.Sprintf("Network error: %v", err),
			Retryable: true,
		}
	}

	// Timeout errors (transient)
	if isTimeoutError(err) {
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeTimeout,
			Message:   fmt.Sprintf("Timeout error: %v", err),
			Retryable: true,
		}
	}

	// AWS-specific error patterns
	switch {
	case strings.Contains(errStr, "throttling") || strings.Contains(errStr, "rate limit"):
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeRateLimit,
			Message:   fmt.Sprintf("Rate limit exceeded: %v", err),
			Retryable: true,
		}

	case strings.Contains(errStr, "service unavailable") || strings.Contains(errStr, "internal server error"):
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeServiceUnavailable,
			Message:   fmt.Sprintf("Service unavailable: %v", err),
			Retryable: true,
		}

	case strings.Contains(errStr, "quota exceeded") || strings.Contains(errStr, "limit exceeded"):
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeQuotaExceeded,
			Message:   fmt.Sprintf("Quota exceeded: %v", err),
			Retryable: false,
		}

	case strings.Contains(errStr, "access denied") || strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "invalid credentials") || strings.Contains(errStr, "forbidden"):
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypePermanent,
			Message:   fmt.Sprintf("Authentication/authorization error: %v", err),
			Retryable: false,
		}

	case strings.Contains(errStr, "not found") || strings.Contains(errStr, "does not exist"):
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeResourceNotFound,
			Message:   fmt.Sprintf("Resource not found: %v", err),
			Retryable: false,
		}

	case strings.Contains(errStr, "invalid") || strings.Contains(errStr, "malformed") ||
		strings.Contains(errStr, "bad request"):
		return &ClassifiedError{
			Original:  err,
			Type:      ErrorTypeInvalidInput,
			Message:   fmt.Sprintf("Invalid input: %v", err),
			Retryable: false,
		}
	}

	// Default to unknown, non-retryable
	return &ClassifiedError{
		Original:  err,
		Type:      ErrorTypeUnknown,
		Message:   fmt.Sprintf("Unknown error: %v", err),
		Retryable: false,
	}
}

// isNetworkError checks if an error is network-related
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for net.Error interface
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}

	// Check for specific network error types
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// Check for DNS errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// Check for connection errors
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return true
	}

	return false
}

// isTimeoutError checks if an error is timeout-related
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// Check for net.Error timeout
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// Check error message for timeout indicators
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "context deadline exceeded")
}

// NewTransientError creates a new transient error
func NewTransientError(message string, cause error) *ClassifiedError {
	return &ClassifiedError{
		Original:  cause,
		Type:      ErrorTypeTransient,
		Message:   message,
		Retryable: true,
	}
}

// NewPermanentError creates a new permanent error
func NewPermanentError(message string, cause error) *ClassifiedError {
	return &ClassifiedError{
		Original:  cause,
		Type:      ErrorTypePermanent,
		Message:   message,
		Retryable: false,
	}
}
