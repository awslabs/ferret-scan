// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestARecoveredPanicIsCoverageCutShort is the whole of the #656 disclosure fix,
// stated at the one place that decides it.
//
// Recovering a validator panic is correct: one bad validator must not kill a
// scan. But the recovered error's only consumer was a --debug log line, so a
// panicking validator produced zero findings for the whole file and the tool
// reported a clean, complete scan — files_processed 1, files_skipped 0, exit 0,
// and `--fail-on-incomplete` ALSO 0. Because only reported findings reach the
// redactor, that is a redaction bypass whose defining feature is silence.
//
// IsCoverageCutShort is a single predicate precisely so this family cannot drift
// (see its doc comment and #414). A panic was missing from it.
func TestARecoveredPanicIsCoverageCutShort(t *testing.T) {
	_, err := SafeRun(context.Background(), "exploding", func() ([]detector.Match, error) {
		var m map[string]string
		m["boom"] = "nil map write" // panics
		return nil, nil
	})
	if err == nil {
		t.Fatal("SafeRun returned nil error for a panicking function")
	}
	if !errors.Is(err, ErrValidatorPanicked) {
		t.Errorf("errors.Is(err, ErrValidatorPanicked) = false for %v.\n"+
			"The sentinel must be reachable through Unwrap, not matched on message text.", err)
	}
	if !IsCoverageCutShort(err) {
		t.Errorf("IsCoverageCutShort(%v) = false. A validator that panicked returned ZERO "+
			"matches for the whole file, so coverage was cut short — without this the "+
			"scan is reported as clean and complete.", err)
	}
}

// TestPanicErrorNamesTheValidatorAndNotThePayload keeps the disclosure message
// safe to emit. It reaches SARIF and stderr, so it may name the validator and
// the failure, never matched bytes (BSC4).
func TestPanicErrorNamesTheValidatorAndNotThePayload(t *testing.T) {
	const secret = "4111111111111111"
	_, err := SafeRun(context.Background(), "namedvalidator", func() ([]detector.Match, error) {
		s := "short"
		_ = s[:len(s)+len(secret)] // slice bounds panic; the runtime message carries no payload
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "namedvalidator") {
		t.Errorf("error %q does not name the validator, so the disclosure cannot say what failed", msg)
	}
	if strings.Contains(msg, secret) {
		t.Errorf("error message contains payload bytes: %q", msg)
	}
}

// TestAPanicDoesNotSurfacePartialMatches pins the other half of SafeRun's
// contract: matches collected before the panic are discarded rather than
// returned as if the scan had finished.
//
// Both halves are needed. Returning the partial slice with an error would be
// defensible; returning it WITHOUT one, as a complete result, is what the whole
// disclosure fix exists to prevent.
func TestAPanicDoesNotSurfacePartialMatches(t *testing.T) {
	got, err := SafeRun(context.Background(), "partial", func() ([]detector.Match, error) {
		found := []detector.Match{{Text: "first", Type: "SSN"}}
		_ = found
		panic("after collecting one match")
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got != nil {
		t.Errorf("SafeRun returned %d matches alongside a panic; a partial slice must not be "+
			"surfaced as if it were complete", len(got))
	}
}

// TestTheOtherCutShortSentinelsStillQualify guards against a fix that widens the
// predicate by replacing it. All five members must hold.
func TestTheOtherCutShortSentinelsStillQualify(t *testing.T) {
	for _, e := range []error{
		context.DeadlineExceeded,
		context.Canceled,
		ErrMatchBudgetExceeded,
		ErrContentTooLarge,
		ErrValidatorPanicked,
	} {
		if !IsCoverageCutShort(e) {
			t.Errorf("IsCoverageCutShort(%v) = false, want true", e)
		}
	}
	// And an ordinary error must still NOT qualify, or every validator failure
	// marks every scan incomplete and the signal becomes noise.
	if IsCoverageCutShort(errors.New("some ordinary validator error")) {
		t.Error("IsCoverageCutShort said true for an ordinary error")
	}
}
