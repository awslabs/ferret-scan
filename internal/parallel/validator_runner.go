// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
	"github.com/awslabs/ferret-scan/internal/resilience"
	"github.com/awslabs/ferret-scan/internal/validators/metadata"
)

// ValidatorStrategy controls how a single validator invocation is executed.
// A nil strategy invokes the operation once with no wrapping; the worker pool
// passes a retry-backed strategy, while in-memory callers (e.g. ScanContent)
// pass nil to keep validator execution fast and deterministic.
type ValidatorStrategy interface {
	Run(ctx context.Context, op func(context.Context) error) error
}

// retryValidatorStrategy wraps each validator invocation with bounded retry/backoff.
type retryValidatorStrategy struct {
	cfg resilience.RetryConfig
}

// Run executes op under the configured retry policy.
func (s *retryValidatorStrategy) Run(ctx context.Context, op func(context.Context) error) error {
	return resilience.RetryWithBackoff(ctx, s.cfg, op)
}

// DefaultValidatorRetryStrategy returns the retry policy used by the worker
// pool: short, bounded retries appropriate for transient validator errors
// (e.g. flaky AWS calls). It is intentionally tighter than the file-processing
// retry policy to avoid blocking job completion.
func DefaultValidatorRetryStrategy() ValidatorStrategy {
	cfg := resilience.DefaultRetryConfig()
	cfg.MaxRetries = 2
	cfg.MaxElapsedTime = 30 * time.Second
	return &retryValidatorStrategy{cfg: cfg}
}

// RunValidators executes each validator against the supplied processed
// content and returns the union of matches. Validators run in parallel,
// each wrapped by strategy (or invoked directly when strategy is nil).
//
// The returned error is the first validator error observed (if any); a
// non-nil error does not imply that no matches were produced — callers
// typically log the error and continue.
//
// Behavioral rules preserved from the worker-pool implementation:
//   - Validators implementing ValidateProcessedContent take precedence
//     over the legacy ValidateContent path (dual-path support).
//   - Pure-metadata content (ProcessedContent.ProcessorType == "metadata")
//     is fed only to the metadata validator; other validators skip it.
//   - When ValidateContent is invoked, the originalPath argument falls back
//     to ProcessedContent.Filename if OriginalPath is empty.
func RunValidators(
	ctx context.Context,
	validators []detector.Validator,
	processedContent *preprocessors.ProcessedContent,
	strategy ValidatorStrategy,
) ([]detector.Match, error) {
	runOne := func(ctx context.Context, op func(context.Context) error) error {
		if strategy == nil {
			return op(ctx)
		}
		return strategy.Run(ctx, op)
	}

	var wg sync.WaitGroup
	matchesChan := make(chan []detector.Match, len(validators))
	errorChan := make(chan error, len(validators))

	for _, validator := range validators {
		// Prefer the context-aware ProcessedContent path when available: it
		// threads ctx all the way to the per-validator dispatch chokepoint so
		// a deadline/cancellation can stop new validator work and panics are
		// recovered (v2 Phase 1). Falls back to the legacy ctx-less method.
		if pccv, ok := validator.(interface {
			ValidateProcessedContentCtx(ctx context.Context, content *preprocessors.ProcessedContent) ([]detector.Match, error)
		}); ok {
			wg.Add(1)
			go func(pccv interface {
				ValidateProcessedContentCtx(ctx context.Context, content *preprocessors.ProcessedContent) ([]detector.Match, error)
			}) {
				defer wg.Done()

				// Capture the result in the closure and send to the channels
				// exactly once, AFTER runOne returns. Sending inside op would
				// push once per retry attempt; with the channels buffered to
				// len(validators) (one send budgeted per validator) a retried
				// validator would block on its 2nd send and never finish.
				var matches []detector.Match
				op := func(ctx context.Context) error {
					m, err := pccv.ValidateProcessedContentCtx(ctx, processedContent)
					matches = m
					return err
				}

				if err := runOne(ctx, op); err != nil {
					matchesChan <- []detector.Match{}
					errorChan <- err
					return
				}
				matchesChan <- matches
			}(pccv)
			continue
		}

		if processedContentValidator, ok := validator.(interface {
			ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
		}); ok {
			wg.Add(1)
			go func(pcv interface {
				ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
			}) {
				defer wg.Done()

				// Send once, after runOne (see the ctx-aware branch above for
				// why sending inside a retried op would deadlock).
				var matches []detector.Match
				op := func(ctx context.Context) error {
					m, err := pcv.ValidateProcessedContent(processedContent)
					matches = m
					return err
				}

				if err := runOne(ctx, op); err != nil {
					matchesChan <- []detector.Match{}
					errorChan <- err
					return
				}
				matchesChan <- matches
			}(processedContentValidator)
			continue
		}

		if contentValidator, ok := validator.(interface {
			ValidateContent(content string, originalPath string) ([]detector.Match, error)
		}); ok {
			// Skip ONLY pure metadata content for non-metadata validators.
			if _, isMetadataValidator := validator.(*metadata.Validator); !isMetadataValidator && processedContent.ProcessorType == "metadata" {
				continue
			}

			wg.Add(1)
			go func(cv interface {
				ValidateContent(content string, originalPath string) ([]detector.Match, error)
			}) {
				defer wg.Done()

				// Send once, after runOne (see the ctx-aware branch above for
				// why sending inside a retried op would deadlock).
				var matches []detector.Match
				op := func(ctx context.Context) error {
					filename := processedContent.OriginalPath
					if filename == "" {
						filename = processedContent.Filename
					}

					m, err := cv.ValidateContent(processedContent.Text, filename)
					matches = m
					return err
				}

				if err := runOne(ctx, op); err != nil {
					matchesChan <- []detector.Match{}
					errorChan <- err
					return
				}
				matchesChan <- matches
			}(contentValidator)
		}
	}

	// Wait for all validators to finish, but do not block indefinitely on a
	// stalled one: if ctx is cancelled/expired first, return promptly with
	// whatever results have arrived (v2 Phase 1, gap 1.1). The matches/error
	// channels are buffered to len(validators), so a goroutine that finishes
	// AFTER an early return can still send without blocking or panicking — we
	// must therefore NOT close the channels on the cancellation path. The
	// stalled goroutine itself cannot be killed in Phase 1 (Go has no
	// goroutine kill); honoring ctx in the validator body is Phase 3. What
	// changes now is that the SCAN no longer hangs waiting for it.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var allMatches []detector.Match
	var firstErr error

	select {
	case <-done:
		// All validators completed: safe to close and drain fully (the
		// pre-existing behavior, byte-for-byte).
		close(matchesChan)
		close(errorChan)
		for matches := range matchesChan {
			allMatches = append(allMatches, matches...)
		}
		for err := range errorChan {
			if firstErr == nil {
				firstErr = err
			}
		}
		return allMatches, firstErr

	case <-ctx.Done():
		// Deadline/cancellation tripped while at least one validator is still
		// running. Drain what is buffered without closing (a late goroutine may
		// still send), and surface the context error so callers can report
		// degraded/incomplete coverage rather than a silent clean result.
		for draining := true; draining; {
			select {
			case matches := <-matchesChan:
				allMatches = append(allMatches, matches...)
			case err := <-errorChan:
				if firstErr == nil {
					firstErr = err
				}
			default:
				draining = false
			}
		}
		if firstErr == nil {
			firstErr = ctx.Err()
		}
		return allMatches, firstErr
	}
}
