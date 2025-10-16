// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"fmt"
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

func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

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

// DefaultCircuitBreakerConfig returns sensible defaults
func DefaultCircuitBreakerConfig(name string) CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Name:             name,
		FailureThreshold: 5,
		SuccessThreshold: 3,
		Timeout:          30 * time.Second,
		MaxRequests:      3,
		IsFailure: func(err error) bool {
			if err == nil {
				return false
			}
			classified := ClassifyError(err)
			// Only count retryable errors as circuit breaker failures
			// Non-retryable errors (like auth failures) shouldn't trigger circuit breaker
			return classified.Retryable
		},
		OnStateChange: func(name string, from, to CircuitBreakerState) {
			// Default: no-op, can be overridden for logging/metrics
		},
	}
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

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	err := fn(ctx)
	cb.afterRequest(err)
	return err
}

// beforeRequest checks if the request should be allowed
func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		// Normal operation
		return nil

	case StateOpen:
		// Check if timeout has elapsed
		if now.Sub(cb.lastFailureTime) >= cb.config.Timeout {
			cb.setState(StateHalfOpen)
			cb.requestCount = 0
			return nil
		}
		return &CircuitBreakerError{
			Name:  cb.config.Name,
			State: cb.state,
			Message: fmt.Sprintf("Circuit breaker '%s' is OPEN (failed %d times, last failure: %v ago)",
				cb.config.Name, cb.failureCount, now.Sub(cb.lastFailureTime).Round(time.Second)),
		}

	case StateHalfOpen:
		// Allow limited requests to test if service recovered
		if cb.requestCount >= cb.config.MaxRequests {
			return &CircuitBreakerError{
				Name:  cb.config.Name,
				State: cb.state,
				Message: fmt.Sprintf("Circuit breaker '%s' is HALF_OPEN and at max requests (%d)",
					cb.config.Name, cb.config.MaxRequests),
			}
		}
		cb.requestCount++
		return nil

	default:
		return fmt.Errorf("unknown circuit breaker state: %v", cb.state)
	}
}

// afterRequest handles the response and updates circuit breaker state
func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.config.IsFailure(err) {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
}

// onFailure handles a failed request
func (cb *CircuitBreaker) onFailure() {
	cb.failureCount++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		if cb.failureCount >= cb.config.FailureThreshold {
			cb.setState(StateOpen)
		}

	case StateHalfOpen:
		// Any failure in half-open immediately opens the circuit
		cb.setState(StateOpen)
		cb.requestCount = 0
	}
}

// onSuccess handles a successful request
func (cb *CircuitBreaker) onSuccess() {
	switch cb.state {
	case StateClosed:
		// Reset failure count on success
		cb.failureCount = 0

	case StateHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.config.SuccessThreshold {
			cb.setState(StateClosed)
			cb.failureCount = 0
			cb.successCount = 0
			cb.requestCount = 0
		}
	}
}

// setState changes the circuit breaker state and triggers callback
func (cb *CircuitBreaker) setState(newState CircuitBreakerState) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState

	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(cb.config.Name, oldState, newState)
	}
}

// GetState returns the current state (thread-safe)
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns current circuit breaker statistics
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerStats{
		Name:            cb.config.Name,
		State:           cb.state,
		FailureCount:    cb.failureCount,
		SuccessCount:    cb.successCount,
		RequestCount:    cb.requestCount,
		LastFailureTime: cb.lastFailureTime,
	}
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	oldState := cb.state
	cb.setState(StateClosed)
	cb.failureCount = 0
	cb.successCount = 0
	cb.requestCount = 0
	cb.lastFailureTime = time.Time{}

	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(cb.config.Name, oldState, StateClosed)
	}
}

// CircuitBreakerStats holds circuit breaker statistics
type CircuitBreakerStats struct {
	Name            string              `json:"name"`
	State           CircuitBreakerState `json:"state"`
	FailureCount    int                 `json:"failure_count"`
	SuccessCount    int                 `json:"success_count"`
	RequestCount    int                 `json:"request_count"`
	LastFailureTime time.Time           `json:"last_failure_time"`
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

// GetOrCreate gets an existing circuit breaker or creates a new one
func (cbm *CircuitBreakerManager) GetOrCreate(name string, config CircuitBreakerConfig) *CircuitBreaker {
	cbm.mu.RLock()
	if cb, exists := cbm.breakers[name]; exists {
		cbm.mu.RUnlock()
		return cb
	}
	cbm.mu.RUnlock()

	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, exists := cbm.breakers[name]; exists {
		return cb
	}

	config.Name = name
	cb := NewCircuitBreaker(config)
	cbm.breakers[name] = cb
	return cb
}

// GetStats returns stats for all circuit breakers
func (cbm *CircuitBreakerManager) GetStats() map[string]CircuitBreakerStats {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	stats := make(map[string]CircuitBreakerStats)
	for name, cb := range cbm.breakers {
		stats[name] = cb.GetStats()
	}
	return stats
}

// ResetAll resets all circuit breakers
func (cbm *CircuitBreakerManager) ResetAll() {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	for _, cb := range cbm.breakers {
		cb.Reset()
	}
}
