// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

// GENAI_DISABLED: This file provides minimal stub implementations for resilience features
// The backoff/v4 dependency has been removed, so retry functionality is simplified
// to basic error handling without exponential backoff.

import (
	"context"
	"fmt"
	"time"
)

// RetryConfig holds retry configuration (simplified version)
type RetryConfig struct {
	MaxRetries      int                          // Maximum number of retry attempts
	InitialInterval time.Duration                // Initial retry interval
	MaxInterval     time.Duration                // Maximum retry interval
	Multiplier      float64                      // Backoff multiplier
	MaxElapsedTime  time.Duration                // Maximum total time for all retries
	Jitter          bool                         // Add randomization to intervals
	OnRetry         func(attempt int, err error) // Callback on retry
}

// DefaultRetryConfig returns sensible defaults for retry behavior
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		MaxElapsedTime:  2 * time.Minute,
		Jitter:          true,
		OnRetry: func(attempt int, err error) {
			// Default: no-op, can be overridden for logging
		},
	}
}

// AWSRetryConfig returns retry configuration optimized for AWS services
func AWSRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      5,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     16 * time.Second,
		Multiplier:      2.0,
		MaxElapsedTime:  5 * time.Minute,
		Jitter:          true,
		OnRetry: func(attempt int, err error) {
			// Default: no-op, can be overridden for logging
		},
	}
}

// RetryableOperation represents an operation that can be retried
type RetryableOperation func(ctx context.Context) error

// RetryWithBackoff executes an operation with simple retry logic (no exponential backoff)
// GENAI_DISABLED: Simplified implementation without backoff library
func RetryWithBackoff(ctx context.Context, config RetryConfig, operation RetryableOperation) error {
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Simple linear backoff instead of exponential
			delay := config.InitialInterval * time.Duration(attempt)
			if delay > config.MaxInterval {
				delay = config.MaxInterval
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}

			if config.OnRetry != nil {
				config.OnRetry(attempt, lastErr)
			}
		}

		err := operation(ctx)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		classified := ClassifyError(err)
		if !classified.IsRetryable() {
			return err
		}
	}

	return lastErr
}

// RetryStats holds statistics about retry operations
type RetryStats struct {
	TotalAttempts   int           `json:"total_attempts"`
	SuccessfulAfter int           `json:"successful_after"` // 0 if failed, attempt number if succeeded
	TotalDuration   time.Duration `json:"total_duration"`
	LastError       string        `json:"last_error,omitempty"`
	ErrorTypes      []string      `json:"error_types,omitempty"`
}

// RetryWithStats executes an operation with retry and collects statistics
func RetryWithStats(ctx context.Context, config RetryConfig, operation RetryableOperation) (*RetryStats, error) {
	stats := &RetryStats{
		ErrorTypes: make([]string, 0),
	}

	start := time.Now()

	// Wrap operation to collect stats
	wrappedOperation := func(ctx context.Context) error {
		stats.TotalAttempts++
		err := operation(ctx)

		if err != nil {
			classified := ClassifyError(err)
			stats.LastError = err.Error()
			stats.ErrorTypes = append(stats.ErrorTypes, classified.Type.String())
		}

		return err
	}

	// Wrap config callback to collect stats
	originalOnRetry := config.OnRetry
	config.OnRetry = func(attempt int, err error) {
		if originalOnRetry != nil {
			originalOnRetry(attempt, err)
		}
	}

	err := RetryWithBackoff(ctx, config, wrappedOperation)

	stats.TotalDuration = time.Since(start)
	if err == nil {
		stats.SuccessfulAfter = stats.TotalAttempts
	}

	return stats, err
}

// RetryWithCircuitBreaker combines retry logic with circuit breaker protection
func RetryWithCircuitBreaker(ctx context.Context, retryConfig RetryConfig, cb *CircuitBreaker, operation RetryableOperation) error {
	wrappedOperation := func(ctx context.Context) error {
		return cb.Execute(ctx, operation)
	}

	return RetryWithBackoff(ctx, retryConfig, wrappedOperation)
}

// ErrorType extensions for retry logic
func (et ErrorType) String() string {
	switch et {
	case ErrorTypeUnknown:
		return "Unknown"
	case ErrorTypeTransient:
		return "Transient"
	case ErrorTypePermanent:
		return "Permanent"
	case ErrorTypeTimeout:
		return "Timeout"
	case ErrorTypeRateLimit:
		return "RateLimit"
	case ErrorTypeQuotaExceeded:
		return "QuotaExceeded"
	case ErrorTypeServiceUnavailable:
		return "ServiceUnavailable"
	case ErrorTypeInvalidInput:
		return "InvalidInput"
	case ErrorTypeResourceNotFound:
		return "ResourceNotFound"
	default:
		return fmt.Sprintf("ErrorType(%d)", int(et))
	}
}

// RetryableFunc is a convenience type for retryable functions
type RetryableFunc[T any] func(ctx context.Context) (T, error)

// RetryWithResult executes a function that returns a result and error with retry logic
func RetryWithResult[T any](ctx context.Context, config RetryConfig, fn RetryableFunc[T]) (T, error) {
	var result T

	operation := func(ctx context.Context) error {
		var err error
		result, err = fn(ctx)
		return err
	}

	err := RetryWithBackoff(ctx, config, operation)
	if err != nil {
		return result, err
	}

	return result, nil
}

// IsRetryable is a helper function to check if an error should be retried
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	classified := ClassifyError(err)
	return classified.IsRetryable()
}

// ShouldRetryAfter extracts retry-after information from errors (e.g., rate limit responses)
func ShouldRetryAfter(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}

	// This could be extended to parse retry-after headers from HTTP responses
	// For now, return default backoff behavior
	classified := ClassifyError(err)

	switch classified.Type {
	case ErrorTypeRateLimit:
		return 30 * time.Second, true
	case ErrorTypeServiceUnavailable:
		return 10 * time.Second, true
	case ErrorTypeTimeout:
		return 5 * time.Second, true
	default:
		return 0, false
	}
}

// RetryManager manages retry configurations for different services
type RetryManager struct {
	configs map[string]RetryConfig
}

// NewRetryManager creates a new retry manager
func NewRetryManager() *RetryManager {
	return &RetryManager{
		configs: make(map[string]RetryConfig),
	}
}

// SetConfig sets retry configuration for a service
func (rm *RetryManager) SetConfig(serviceName string, config RetryConfig) {
	rm.configs[serviceName] = config
}

// GetConfig gets retry configuration for a service, returns default if not found
func (rm *RetryManager) GetConfig(serviceName string) RetryConfig {
	if config, exists := rm.configs[serviceName]; exists {
		return config
	}
	return DefaultRetryConfig()
}

// Retry executes an operation with service-specific retry configuration
func (rm *RetryManager) Retry(ctx context.Context, serviceName string, operation RetryableOperation) error {
	config := rm.GetConfig(serviceName)
	return RetryWithBackoff(ctx, config, operation)
}
