// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
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
				// #nosec G404 -- jitter spreads concurrent retries; not a
				// security boundary. crypto/rand would add cost without
				// benefit here.
				delay += delay * 0.25 * rand.Float64()
			}
			// MaxInterval = 0 means "no cap" — treat the zero value as
			// disabled rather than clamping every delay to zero, which
			// silently turns off backoff for callers who forget to set it.
			capped := time.Duration(delay)
			if config.MaxInterval > 0 && capped > config.MaxInterval {
				capped = config.MaxInterval
			}

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

// IsRetryable reports whether an error should be retried.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	return ClassifyError(err).IsRetryable()
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
