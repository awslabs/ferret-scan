// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	StateClosed   CircuitBreakerState = iota // Normal operation
	StateOpen                                // Failing fast
	StateHalfOpen                            // Testing if service recovered
)

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	Name             string                                          // Name for logging/metrics
	FailureThreshold int                                             // Number of failures before opening
	SuccessThreshold int                                             // Number of successes to close from half-open
	Timeout          time.Duration                                   // How long to wait before trying half-open
	MaxRequests      int                                             // Max requests in half-open state
	IsFailure        func(error) bool                                // Custom failure detection
	OnStateChange    func(name string, from, to CircuitBreakerState) // State change callback
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config CircuitBreakerConfig
	mu     sync.RWMutex

	state           CircuitBreakerState
	failureCount    int
	successCount    int
	lastFailureTime time.Time
	requestCount    int // For half-open state
}

// CircuitBreakerError is returned when circuit breaker prevents execution
type CircuitBreakerError struct {
	Name    string
	State   CircuitBreakerState
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}

// IsCircuitBreakerError checks if an error is a circuit breaker error
func IsCircuitBreakerError(err error) bool {
	_, ok := err.(*CircuitBreakerError)
	return ok
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}
