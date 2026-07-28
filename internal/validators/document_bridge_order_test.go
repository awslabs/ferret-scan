// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	stdctx "context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// bridgeOrderValidator returns one match tagged with its own name after a
// per-instance delay. The document fan-out launches one goroutine per registered
// validator and collects the results through a channel, so the delay decides
// arrival order.
type bridgeOrderValidator struct {
	name  string
	delay time.Duration
}

func (v *bridgeOrderValidator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	time.Sleep(v.delay)
	return []detector.Match{{
		Text:       v.name + "-value",
		Type:       strings.ToUpper(v.name),
		LineNumber: 1,
		Confidence: 90,
		Validator:  v.name,
	}}, nil
}

func (v *bridgeOrderValidator) CalculateConfidence(match string) (float64, map[string]bool) {
	return 90, nil
}

func (v *bridgeOrderValidator) AnalyzeContext(match string, ctx detector.ContextInfo) float64 {
	return 0
}

func bridgeMatchTypes(matches []detector.Match) string {
	parts := make([]string, 0, len(matches))
	for _, m := range matches {
		parts = append(parts, m.Type)
	}
	return strings.Join(parts, ",")
}

// TestDocumentBridge_MatchOrderFollowsRegistrationOrder locks the document
// fan-out's match order to the order validators were registered in. This is the
// fan-out the CLI actually uses: the scan passes a single Detector facade, which
// expands here into one goroutine per check. Results were collected off a
// channel and appended as they arrived, so completion order — decided by the
// scheduler and by how long each validator's patterns take on the content —
// determined the order of a file's findings.
//
// Delays descend so the validator registered first finishes last, making the
// pre-fix behavior the exact reverse of the wanted order rather than a coin flip.
func TestDocumentBridge_MatchOrderFollowsRegistrationOrder(t *testing.T) {
	names := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	dvb := NewDocumentValidatorBridge()
	for i, n := range names {
		dvb.RegisterValidator(strings.ToUpper(n), &bridgeOrderValidator{
			name:  n,
			delay: time.Duration(len(names)-i) * 2 * time.Millisecond,
		})
	}

	want := "ALPHA,BRAVO,CHARLIE,DELTA,ECHO"
	for i := 0; i < 10; i++ {
		matches, err := dvb.ProcessDocumentContentCtx(
			stdctx.Background(), "probe content", "/probe/input.txt", context.ContextInsights{})
		if err != nil {
			t.Fatalf("iteration %d: ProcessDocumentContentCtx: %v", i, err)
		}
		if got := bridgeMatchTypes(matches); got != want {
			t.Fatalf("iteration %d: match order = %s, want %s", i, got, want)
		}
	}
}

// TestDocumentBridge_MatchOrderStableUnderContention is the property that
// matters in production: with equal, tiny delays the finishing order is
// genuinely unpredictable, and every run must still agree.
func TestDocumentBridge_MatchOrderStableUnderContention(t *testing.T) {
	names := []string{"one", "two", "three", "four", "five", "six", "seven", "eight"}
	dvb := NewDocumentValidatorBridge()
	for _, n := range names {
		dvb.RegisterValidator(strings.ToUpper(n), &bridgeOrderValidator{name: n, delay: 50 * time.Microsecond})
	}

	seen := make(map[string]int)
	const iterations = 200
	for i := 0; i < iterations; i++ {
		matches, err := dvb.ProcessDocumentContentCtx(
			stdctx.Background(), "probe content", "/probe/input.txt", context.ContextInsights{})
		if err != nil {
			t.Fatalf("iteration %d: ProcessDocumentContentCtx: %v", i, err)
		}
		seen[bridgeMatchTypes(matches)]++
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

// TestDocumentBridge_KeepsEveryValidatorsMatches guards against the trivially
// wrong version of the fix: a slot-indexed collector that mis-sizes or
// mis-indexes its slots would silently drop a validator's findings. For a
// secret scanner a dropped finding is an undetected secret, so losing one is
// strictly worse than the ordering bug being fixed.
func TestDocumentBridge_KeepsEveryValidatorsMatches(t *testing.T) {
	const n = 12
	dvb := NewDocumentValidatorBridge()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("v%02d", i)
		dvb.RegisterValidator(strings.ToUpper(name), &bridgeOrderValidator{
			name:  name,
			delay: time.Duration(i%3) * time.Millisecond,
		})
	}

	matches, err := dvb.ProcessDocumentContentCtx(
		stdctx.Background(), "probe content", "/probe/input.txt", context.ContextInsights{})
	if err != nil {
		t.Fatalf("ProcessDocumentContentCtx: %v", err)
	}
	if len(matches) != n {
		t.Fatalf("got %d matches from %d validators, want %d: %s",
			len(matches), n, n, bridgeMatchTypes(matches))
	}
	for i, m := range matches {
		want := strings.ToUpper(fmt.Sprintf("v%02d", i))
		if m.Type != want {
			t.Fatalf("match %d = %s, want %s\nfull order: %s", i, m.Type, want, bridgeMatchTypes(matches))
		}
	}
}
