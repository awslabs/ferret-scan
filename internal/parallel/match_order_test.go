// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// orderProbeValidator returns exactly one match tagged with its own name, after
// a delay derived from its position. The delays are chosen to invert the
// registration order: the validator registered first sleeps longest, so a
// collector that appends in completion order produces the reverse of the wanted
// sequence rather than a coin flip. That makes the bug deterministic in the test
// while remaining a faithful model of it — real validators finish in an order
// set by how long their patterns take on the content, which the caller does not
// control.
type orderProbeValidator struct {
	name  string
	delay time.Duration
}

func (v *orderProbeValidator) ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	time.Sleep(v.delay)
	return []detector.Match{{
		Text:       v.name + "-value",
		Type:       strings.ToUpper(v.name),
		LineNumber: 1,
		Confidence: 90,
		Validator:  v.name,
	}}, nil
}

func (v *orderProbeValidator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return nil, nil
}

func (v *orderProbeValidator) CalculateConfidence(match string) (float64, map[string]bool) {
	return 90, nil
}

func (v *orderProbeValidator) AnalyzeContext(match string, ctx detector.ContextInfo) float64 {
	return 0
}

// matchTypes renders a match slice as a comparable string.
func matchTypes(matches []detector.Match) string {
	parts := make([]string, 0, len(matches))
	for _, m := range matches {
		parts = append(parts, m.Type)
	}
	return strings.Join(parts, ",")
}

// TestRunValidators_MatchOrderFollowsValidatorOrder locks the union order to the
// caller's validator order. RunValidators collects each validator's matches off
// a buffered channel; draining it appended in goroutine-completion order, so the
// same content validated twice yielded its matches in a different sequence.
//
// That is not a cosmetic problem. The redactors apply matches by searching for
// each match's text in turn, so given two partially overlapping matches (neither
// contained in the other, so both survive overlap resolution) whichever is
// applied second can no longer be found — a different substring is left in
// cleartext depending on which goroutine won the race.
func TestRunValidators_MatchOrderFollowsValidatorOrder(t *testing.T) {
	// Descending delays: first registered finishes last.
	names := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	validators := make([]detector.Validator, 0, len(names))
	for i, n := range names {
		validators = append(validators, &orderProbeValidator{
			name:  n,
			delay: time.Duration(len(names)-i) * 2 * time.Millisecond,
		})
	}

	want := "ALPHA,BRAVO,CHARLIE,DELTA,ECHO"
	content := &preprocessors.ProcessedContent{
		Text:         "probe content",
		OriginalPath: "/probe/input.txt",
		Filename:     "input.txt",
	}

	for i := 0; i < 10; i++ {
		matches, err := RunValidators(context.Background(), validators, content, nil)
		if err != nil {
			t.Fatalf("iteration %d: RunValidators: %v", i, err)
		}
		if got := matchTypes(matches); got != want {
			t.Fatalf("iteration %d: match order = %s, want %s", i, got, want)
		}
	}
}

// TestRunValidators_MatchOrderStableUnderContention runs validators whose
// finishing order is genuinely unpredictable (equal, tiny delays) and requires
// every run to agree. This is the property that matters in production, where
// completion order is decided by the scheduler and by how long each validator's
// patterns take on the content.
func TestRunValidators_MatchOrderStableUnderContention(t *testing.T) {
	names := []string{"one", "two", "three", "four", "five", "six", "seven", "eight"}
	validators := make([]detector.Validator, 0, len(names))
	for _, n := range names {
		validators = append(validators, &orderProbeValidator{name: n, delay: 50 * time.Microsecond})
	}

	content := &preprocessors.ProcessedContent{
		Text:         "probe content",
		OriginalPath: "/probe/input.txt",
		Filename:     "input.txt",
	}

	seen := make(map[string]int)
	const iterations = 200
	for i := 0; i < iterations; i++ {
		matches, err := RunValidators(context.Background(), validators, content, nil)
		if err != nil {
			t.Fatalf("iteration %d: RunValidators: %v", i, err)
		}
		seen[matchTypes(matches)]++
	}

	if len(seen) != 1 {
		var sample []string
		for k := range seen {
			sample = append(sample, k)
			if len(sample) == 3 {
				break
			}
		}
		t.Fatalf("validating one unchanged input %d times produced %d distinct match orders, want 1\nexamples:\n  %s",
			iterations, len(seen), strings.Join(sample, "\n  "))
	}
}

// TestRunValidators_KeepsEveryValidatorsMatches guards the fix against the
// trivially wrong version of itself: a slot-indexed collector that mis-sizes or
// mis-indexes its slots would silently drop a validator's findings, which for a
// scanner means an undetected secret.
func TestRunValidators_KeepsEveryValidatorsMatches(t *testing.T) {
	const n = 12
	validators := make([]detector.Validator, 0, n)
	for i := 0; i < n; i++ {
		validators = append(validators, &orderProbeValidator{
			name:  fmt.Sprintf("v%02d", i),
			delay: time.Duration(i%3) * time.Millisecond,
		})
	}

	content := &preprocessors.ProcessedContent{
		Text:         "probe content",
		OriginalPath: "/probe/input.txt",
		Filename:     "input.txt",
	}

	matches, err := RunValidators(context.Background(), validators, content, nil)
	if err != nil {
		t.Fatalf("RunValidators: %v", err)
	}
	if len(matches) != n {
		t.Fatalf("got %d matches from %d validators, want %d: %s", len(matches), n, n, matchTypes(matches))
	}
	for i, m := range matches {
		want := strings.ToUpper(fmt.Sprintf("v%02d", i))
		if m.Type != want {
			t.Fatalf("match %d = %s, want %s\nfull order: %s", i, m.Type, want, matchTypes(matches))
		}
	}
}
