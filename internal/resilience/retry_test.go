// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resilience

import (
	"context"
	"testing"
	"time"
)

func TestRetryWithBackoff_SucceedsFirstAttempt(t *testing.T) {
	calls := 0
	err := RetryWithBackoff(context.Background(), RetryConfig{MaxRetries: 3}, func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryWithBackoff_RetriesOnTransientError(t *testing.T) {
	calls := 0
	transient := NewTransientError("temporary failure", nil)

	err := RetryWithBackoff(context.Background(), RetryConfig{
		MaxRetries:      3,
		InitialInterval: time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      2.0,
	}, func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return transient
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestRetryWithBackoff_StopsOnPermanentError(t *testing.T) {
	calls := 0
	permanent := NewPermanentError("permanent failure", nil)

	err := RetryWithBackoff(context.Background(), RetryConfig{
		MaxRetries:      5,
		InitialInterval: time.Millisecond,
		Multiplier:      2.0,
	}, func(ctx context.Context) error {
		calls++
		return permanent
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 1 {
		t.Errorf("expected 1 call (no retries on permanent error), got %d", calls)
	}
}

func TestRetryWithBackoff_ExhaustsRetries(t *testing.T) {
	calls := 0
	transient := NewTransientError("always fails", nil)

	err := RetryWithBackoff(context.Background(), RetryConfig{
		MaxRetries:      3,
		InitialInterval: time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      2.0,
	}, func(ctx context.Context) error {
		calls++
		return transient
	})

	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if calls != 4 { // initial + 3 retries
		t.Errorf("expected 4 calls, got %d", calls)
	}
}

func TestRetryWithBackoff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	calls := 0
	// Cancel from inside the operation on the second call. The retry loop's
	// first action after the operation returns is a select on ctx.Done — so
	// once we cancel, the loop must observe cancellation before the next
	// operation runs. This makes the assertion deterministic instead of
	// relying on Go's randomized select ordering between two ready channels.
	err := RetryWithBackoff(ctx, RetryConfig{
		MaxRetries:      10,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     1 * time.Second, // explicit cap so backoff is real
		Multiplier:      1.0,
	}, func(ctx context.Context) error {
		calls++
		if calls == 2 {
			cancel()
		}
		return NewTransientError("fail", nil)
	})

	if err == nil {
		t.Fatal("expected an error")
	}
	// Exactly two calls: one initial, one retry. The retry loop's pre-delay
	// ctx.Done check exits before a third call can happen.
	if calls != 2 {
		t.Errorf("expected exactly 2 calls, got %d", calls)
	}
}

func TestRetryWithBackoff_OnRetryCallback(t *testing.T) {
	retryCalls := 0
	transient := NewTransientError("fail", nil)

	RetryWithBackoff(context.Background(), RetryConfig{
		MaxRetries:      2,
		InitialInterval: time.Millisecond,
		Multiplier:      2.0,
		OnRetry: func(attempt int, err error) {
			retryCalls++
		},
	}, func(ctx context.Context) error {
		return transient
	})

	if retryCalls != 2 {
		t.Errorf("expected OnRetry called 2 times, got %d", retryCalls)
	}
}

func TestRetryWithBackoff_ExponentialDelayGrowth(t *testing.T) {
	// Verify that delays grow exponentially by measuring timing.
	//
	// Intervals are deliberately well above Windows' default 15.6 ms timer
	// resolution: with InitialInterval=50ms the expected delays are ~50ms,
	// 100ms, 200ms — gaps wide enough that quantization noise can't push
	// delay[2] below delay[0]. The earlier 10ms baseline produced ~16ms /
	// ~16-31ms delays on Windows runners, where adjacent values landed in
	// the same noisy band and the strict delay[1] >= delay[0] assertion
	// flaked. We now check the broader monotonic property delay[2] > delay[0]
	// (a 4× growth ratio, easy to satisfy even with scheduler jitter) which
	// is what "exponential growth" actually means.
	delays := []time.Duration{}
	transient := NewTransientError("fail", nil)
	lastTime := time.Now()

	RetryWithBackoff(context.Background(), RetryConfig{
		MaxRetries:      3,
		InitialInterval: 50 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      2.0,
		Jitter:          false, // disable jitter for deterministic test
		OnRetry: func(attempt int, err error) {
			now := time.Now()
			delays = append(delays, now.Sub(lastTime))
			lastTime = now
		},
	}, func(ctx context.Context) error {
		return transient
	})

	if len(delays) != 3 {
		t.Fatalf("expected 3 delays, got %d", len(delays))
	}
	// delay[2] is expected to be ~4× delay[0] (200ms vs 50ms). Asserting it
	// is at least 1.5× larger keeps the test sensitive to the exponential
	// shape while tolerating scheduler jitter on slow CI runners.
	if delays[2] < delays[0]*3/2 {
		t.Errorf("expected exponential growth: delay[2] (%v) should be >= 1.5 * delay[0] (%v); all delays: %v",
			delays[2], delays[0], delays)
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()
	if cfg.MaxRetries <= 0 {
		t.Error("MaxRetries should be positive")
	}
	if cfg.Multiplier <= 1.0 {
		t.Error("Multiplier should be > 1.0 for exponential backoff")
	}
	if cfg.InitialInterval <= 0 {
		t.Error("InitialInterval should be positive")
	}
	if cfg.MaxInterval < cfg.InitialInterval {
		t.Error("MaxInterval should be >= InitialInterval")
	}
}

func TestRetryManager_UsesServiceConfig(t *testing.T) {
	rm := NewRetryManager()
	custom := RetryConfig{MaxRetries: 7, InitialInterval: time.Millisecond, Multiplier: 2.0}
	rm.SetConfig("my-service", custom)

	got := rm.GetConfig("my-service")
	if got.MaxRetries != 7 {
		t.Errorf("expected MaxRetries=7, got %d", got.MaxRetries)
	}
}

func TestRetryManager_FallsBackToDefault(t *testing.T) {
	rm := NewRetryManager()
	got := rm.GetConfig("nonexistent-service")
	def := DefaultRetryConfig()
	if got.MaxRetries != def.MaxRetries {
		t.Errorf("expected default MaxRetries=%d, got %d", def.MaxRetries, got.MaxRetries)
	}
}

func TestIsRetryable(t *testing.T) {
	if IsRetryable(nil) {
		t.Error("nil error should not be retryable")
	}
	if !IsRetryable(NewTransientError("temp", nil)) {
		t.Error("transient error should be retryable")
	}
	if IsRetryable(NewPermanentError("perm", nil)) {
		t.Error("permanent error should not be retryable")
	}
}
