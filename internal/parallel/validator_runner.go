// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/resilience"
	"ferret-scan/internal/validators/metadata"
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
		if processedContentValidator, ok := validator.(interface {
			ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
		}); ok {
			wg.Add(1)
			go func(pcv interface {
				ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
			}) {
				defer wg.Done()

				op := func(ctx context.Context) error {
					matches, err := pcv.ValidateProcessedContent(processedContent)
					if err == nil {
						matchesChan <- matches
						return nil
					}
					matchesChan <- []detector.Match{}
					return err
				}

				if err := runOne(ctx, op); err != nil {
					errorChan <- err
				}
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

				op := func(ctx context.Context) error {
					filename := processedContent.OriginalPath
					if filename == "" {
						filename = processedContent.Filename
					}

					matches, err := cv.ValidateContent(processedContent.Text, filename)
					if err == nil {
						matchesChan <- matches
						return nil
					}
					matchesChan <- []detector.Match{}
					return err
				}

				if err := runOne(ctx, op); err != nil {
					errorChan <- err
				}
			}(contentValidator)
		}
	}

	wg.Wait()
	close(matchesChan)
	close(errorChan)

	var allMatches []detector.Match
	for matches := range matchesChan {
		allMatches = append(allMatches, matches...)
	}

	var firstErr error
	for err := range errorChan {
		if firstErr == nil {
			firstErr = err
		}
	}

	return allMatches, firstErr
}
