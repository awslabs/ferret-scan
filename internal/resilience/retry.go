// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// RetryConfig holds retry configuration.
type RetryConfig struct {
	MaxRetries      int                          // Maximum number of retry attempts
	InitialInterval time.Duration                // Initial retry interval
	MaxInterval     time.Duration                // Maximum retry interval
	Multiplier      float64                      // Exponential backoff multiplier (e.g. 2.0 doubles each attempt)
	MaxElapsedTime  time.Duration                // Maximum total time for all retries
	Jitter          bool                         // Add up to 25% random jitter to spread retries
	OnRetry         func(attempt int, err error) // Optional callback invoked before each retry
}

// DefaultRetryConfig returns sensible defaults for retry behavior.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		MaxElapsedTime:  2 * time.Minute,
		Jitter:          true,
		OnRetry:         func(attempt int, err error) {},
	}
}

// AWSRetryConfig returns retry configuration optimized for AWS services.
func AWSRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      5,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     16 * time.Second,
		Multiplier:      2.0,
		MaxElapsedTime:  5 * time.Minute,
		Jitter:          true,
		OnRetry:         func(attempt int, err error) {},
	}
}

// RetryableOperation represents an operation that can be retried.
type RetryableOperation func(ctx context.Context) error

// RetryWithBackoff executes an operation with exponential backoff and optional jitter.
// The delay before attempt n is: InitialInterval * Multiplier^(n-1), capped at MaxInterval.
// When Jitter is true, up to 25% random noise is added to spread concurrent retries.
func RetryWithBackoff(ctx context.Context, config RetryConfig, operation RetryableOperation) error {
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: InitialInterval * Multiplier^(attempt-1)
			delay := float64(config.InitialInterval)
			for i := 1; i < attempt; i++ {
				delay *= config.Multiplier
			}
			if config.Jitter {
				delay += delay * 0.25 * rand.Float64()
			}
			capped := min(time.Duration(delay), config.MaxInterval)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(capped):
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

		classified := ClassifyError(err)
		if !classified.IsRetryable() {
			return err
		}
	}

	return lastErr
}

// RetryStats holds statistics about retry operations.
type RetryStats struct {
	TotalAttempts   int           `json:"total_attempts"`
	SuccessfulAfter int           `json:"successful_after"` // 0 if failed, attempt number if succeeded
	TotalDuration   time.Duration `json:"total_duration"`
	LastError       string        `json:"last_error,omitempty"`
	ErrorTypes      []string      `json:"error_types,omitempty"`
}

// RetryWithStats executes an operation with retry and collects statistics.
func RetryWithStats(ctx context.Context, config RetryConfig, operation RetryableOperation) (*RetryStats, error) {
	stats := &RetryStats{
		ErrorTypes: make([]string, 0),
	}

	start := time.Now()

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

// RetryWithCircuitBreaker combines retry logic with circuit breaker protection.
func RetryWithCircuitBreaker(ctx context.Context, retryConfig RetryConfig, cb *CircuitBreaker, operation RetryableOperation) error {
	return RetryWithBackoff(ctx, retryConfig, func(ctx context.Context) error {
		return cb.Execute(ctx, operation)
	})
}

// ErrorType extensions for retry logic.
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

// RetryableFunc is a convenience type for retryable functions that return a value.
type RetryableFunc[T any] func(ctx context.Context) (T, error)

// RetryWithResult executes a function that returns a result and error with retry logic.
func RetryWithResult[T any](ctx context.Context, config RetryConfig, fn RetryableFunc[T]) (T, error) {
	var result T
	err := RetryWithBackoff(ctx, config, func(ctx context.Context) error {
		var e error
		result, e = fn(ctx)
		return e
	})
	return result, err
}

// IsRetryable reports whether an error should be retried.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	return ClassifyError(err).IsRetryable()
}

// ShouldRetryAfter returns a suggested wait duration for rate-limit style errors.
func ShouldRetryAfter(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
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

// RetryManager manages retry configurations for different services.
type RetryManager struct {
	configs map[string]RetryConfig
}

// NewRetryManager creates a new retry manager.
func NewRetryManager() *RetryManager {
	return &RetryManager{configs: make(map[string]RetryConfig)}
}

// SetConfig sets retry configuration for a named service.
func (rm *RetryManager) SetConfig(serviceName string, config RetryConfig) {
	rm.configs[serviceName] = config
}

// GetConfig returns retry configuration for a service, falling back to defaults.
func (rm *RetryManager) GetConfig(serviceName string) RetryConfig {
	if config, exists := rm.configs[serviceName]; exists {
		return config
	}
	return DefaultRetryConfig()
}

// Retry executes an operation with service-specific retry configuration.
func (rm *RetryManager) Retry(ctx context.Context, serviceName string, operation RetryableOperation) error {
	return RetryWithBackoff(ctx, rm.GetConfig(serviceName), operation)
}
