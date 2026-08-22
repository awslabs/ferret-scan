// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/resilience"
	"github.com/awslabs/ferret-scan/v2/internal/validators/metadata"
)

// partialMatchesSurvive reports whether an error is a per-validator BUDGET or
// DEADLINE outcome (v2 Move C / Phase 3) rather than a hard validator failure.
// For these, the matches gathered before the budget fired are genuine findings
// and must be preserved (the error is still propagated so the scan is flagged
// incomplete). A hard error keeps the historical behavior of discarding its
// partial slice.
func partialMatchesSurvive(err error) bool {
	return execguard.IsCoverageCutShort(err)
}

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
	// Results carry the launch slot they belong to. Draining the channel appends
	// in goroutine-completion order, which varies run to run; the slot lets the
	// collector restore the caller's validator order. See collectMatches.
	type indexedMatches struct {
		slot    int
		matches []detector.Match
	}
	matchesChan := make(chan indexedMatches, len(validators))
	errorChan := make(chan error, len(validators))

	// launched counts the goroutines actually started. It is NOT the loop index:
	// a validator that matches no dispatch interface, or a non-metadata validator
	// skipped on pure-metadata content, launches nothing and must not consume a
	// slot (an unused slot would be a harmless empty gap, but keeping the count
	// exact means len(slots) == number of results expected).
	launched := 0

	for _, validator := range validators {
		// Prefer the context-aware ProcessedContent path when available: it
		// threads ctx all the way to the per-validator dispatch chokepoint so
		// a deadline/cancellation can stop new validator work and panics are
		// recovered (v2 Phase 1). Falls back to the legacy ctx-less method.
		if pccv, ok := validator.(interface {
			ValidateProcessedContentCtx(ctx context.Context, content *preprocessors.ProcessedContent) ([]detector.Match, error)
		}); ok {
			wg.Add(1)
			slot := launched
			launched++
			go func(slot int, pccv interface {
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
					// Preserve partial matches on a budget/deadline outcome; drop
					// them on a hard error (historical behavior).
					if partialMatchesSurvive(err) {
						matchesChan <- indexedMatches{slot: slot, matches: matches}
					} else {
						matchesChan <- indexedMatches{slot: slot, matches: []detector.Match{}}
					}
					errorChan <- err
					return
				}
				matchesChan <- indexedMatches{slot: slot, matches: matches}
			}(slot, pccv)
			continue
		}

		if processedContentValidator, ok := validator.(interface {
			ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
		}); ok {
			wg.Add(1)
			slot := launched
			launched++
			go func(slot int, pcv interface {
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
					if partialMatchesSurvive(err) {
						matchesChan <- indexedMatches{slot: slot, matches: matches}
					} else {
						matchesChan <- indexedMatches{slot: slot, matches: []detector.Match{}}
					}
					errorChan <- err
					return
				}
				matchesChan <- indexedMatches{slot: slot, matches: matches}
			}(slot, processedContentValidator)
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
			slot := launched
			launched++
			go func(slot int, cv interface {
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
					if partialMatchesSurvive(err) {
						matchesChan <- indexedMatches{slot: slot, matches: matches}
					} else {
						matchesChan <- indexedMatches{slot: slot, matches: []detector.Match{}}
					}
					errorChan <- err
					return
				}
				matchesChan <- indexedMatches{slot: slot, matches: matches}
			}(slot, contentValidator)
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

	// slots holds each goroutine's matches in its launch position, so the union
	// is concatenated in the caller's validator order rather than in the order
	// the goroutines happened to finish. Arrival order is a race: the same
	// content validated twice yielded its matches in a different sequence, and
	// downstream that is not cosmetic — the redactors apply matches by searching
	// for each match's text in turn, so of two partially overlapping matches
	// (neither contained in the other, so both survive overlap resolution)
	// whichever is applied second can no longer be found, leaving a different
	// substring in cleartext depending on which goroutine won.
	slots := make([][]detector.Match, launched)
	collect := func(im indexedMatches) {
		if im.slot < 0 || im.slot >= len(slots) {
			// Defensive: never expected, and appending beats panicking or dropping.
			allMatches = append(allMatches, im.matches...)
			return
		}
		slots[im.slot] = im.matches
	}
	// flatten concatenates the slots in launch order. Called on both the
	// completed and the cancelled path (the latter returns early).
	flatten := func() {
		total := len(allMatches)
		for _, m := range slots {
			total += len(m)
		}
		out := make([]detector.Match, 0, total)
		for _, m := range slots {
			out = append(out, m...)
		}
		allMatches = append(out, allMatches...)

		// Record where each match sits on its line, now that the union is
		// assembled in a deterministic order.
		//
		// This is the one point every match in the system passes through: the
		// worker pool calls RunValidators per file (so the CLI, core.ScanFile and
		// the redaction path all arrive here) and core.ScanContent calls it
		// directly. Doing it here rather than at each of those four producers is
		// what keeps a single definition of "where is this match".
		//
		// It must run AFTER flatten, not per slot: two validators can report the
		// same value on the same line, and the occurrence cursor has to see them
		// in one pass to give them different columns. It also depends on the launch
		// order restored above — assigning occurrences in goroutine-completion
		// order would hand the same finding a different column run to run.
		detector.AssignLineColumns(allMatches)

		// Detach the findings from the extracted buffer, for the same reason the line
		// columns are assigned here: this is the one point every match passes through.
		//
		// Every string on a match is a substring of processedContent.Text, and a Go
		// substring retains its parent's WHOLE backing array — so without this, one
		// 16-byte finding keeps that file's entire extracted content alive for as long
		// as the finding lives, which is until the process exits. Measured on 64 files
		// of 2 MB with one EMAIL each: 130 MB of live heap held by 64 findings.
		//
		// It must run AFTER AssignLineColumns, which is why it sits here rather than
		// earlier: the column assignment walks the original strings, and the detach
		// gives every match on a line the SAME copy, so the line identity that
		// AssignLineColumns and the redaction-path overlap resolver depend on is
		// preserved rather than fragmented.
		//
		// DetachMatches declines when the finding-bearing text is most of the buffer
		// (a single-line minified document), because there the copy is as large as what
		// it would free. That case is a deliberate non-improvement, not an oversight.
		detector.DetachMatches(allMatches, processedContent.Text)
	}

	select {
	case <-done:
		// All validators completed: safe to close and drain fully.
		close(matchesChan)
		close(errorChan)
		for im := range matchesChan {
			collect(im)
		}
		flatten()
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
			case im := <-matchesChan:
				collect(im)
			case err := <-errorChan:
				if firstErr == nil {
					firstErr = err
				}
			default:
				draining = false
			}
		}
		flatten()
		if firstErr == nil {
			firstErr = ctx.Err()
		}
		return allMatches, firstErr
	}
}
