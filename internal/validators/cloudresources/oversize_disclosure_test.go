// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"errors"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/execguard"
)

// oversizeContent builds content past maxContentBytes whose FIRST line is a real ARN, so a
// validator that actually scanned it would find something.
func oversizeContent() string {
	var b strings.Builder
	b.WriteString("arn:aws:iam::123456789012:role/ProdAdminRole\n")
	pad := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 100) + "\n"
	for b.Len() <= maxContentBytes {
		b.WriteString(pad)
	}
	return b.String()
}

// Declining oversize content must be an ERROR, not an empty result.
//
// `return nil, nil` is indistinguishable from "scanned it, found nothing", so nothing downstream
// could tell that coverage was lost. Measured before this: the same ARN on line 1 scored a finding
// in a 1MB file and NOTHING in a 6MB one, with files_processed=1, no files_not_examined and exit 0
// in both — the tool reported a clean, complete scan of content it never examined. 5MB is small for
// the file types that carry infrastructure identifiers: Terraform plans, CloudTrail exports, build
// logs, support bundles (#414).
//
// The cap itself stays. It guards a measured DoS; the defect was the silence.
func TestOversizeContentIsRefusedWithAnError(t *testing.T) {
	v := NewValidator()

	// Control first: under the cap, the ARN is found. Without this the assertion below could
	// pass on a validator that finds nothing at any size.
	under, err := v.ValidateContent("arn:aws:iam::123456789012:role/ProdAdminRole\n", "small.tf")
	if err != nil {
		t.Fatalf("under the cap: unexpected error %v", err)
	}
	if len(under) == 0 {
		t.Fatal("the control ARN produced no finding, so this test cannot detect a silent skip")
	}

	matches, err := v.ValidateContent(oversizeContent(), "big.tf")

	if err == nil {
		t.Fatal("oversize content was declined with a nil error: a caller cannot distinguish that " +
			"from a completed scan that found nothing, so the lost coverage is invisible and the " +
			"scan exits 0 reporting clean")
	}
	if !errors.Is(err, execguard.ErrContentTooLarge) {
		t.Errorf("error = %v, want it to wrap execguard.ErrContentTooLarge: the scanner recognises "+
			"that sentinel to mark the scan incomplete, and an unrecognised error is logged and "+
			"dropped", err)
	}
	if len(matches) != 0 {
		t.Errorf("declined content returned %d matches, want 0", len(matches))
	}
}

// The refusal message must name sizes only — never the path, never any content. It reaches stderr
// and every machine format with no --show-match to gate it.
func TestOversizeRefusalMessageIsPayloadFree(t *testing.T) {
	v := NewValidator()
	_, err := v.ValidateContent(oversizeContent(), "/home/someone/secret-project/main.tf")
	if err == nil {
		t.Fatal("no error, so there is no message to check")
	}

	msg := err.Error()
	for _, forbidden := range []string{
		"ProdAdminRole",   // content
		"123456789012",    // content
		"secret-project",  // path
		"/home/someone",   // path
		"quick brown fox", // content
	} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("refusal message contains %q: %q. This string reaches stderr and every "+
				"machine format with no --show-match to gate it", forbidden, msg)
		}
	}
	// It must still say enough to act on.
	if !strings.Contains(msg, "cap") {
		t.Errorf("message %q does not mention the cap, so an operator cannot tell why the "+
			"validator declined", msg)
	}
}

// The cap must not fire below it, or the disclosure would appear on ordinary files and train
// operators to ignore it.
func TestContentUnderTheCapIsScannedSilently(t *testing.T) {
	v := NewValidator()

	var b strings.Builder
	b.WriteString("arn:aws:iam::123456789012:role/ProdAdminRole\n")
	pad := strings.Repeat("ordinary infrastructure notes. ", 100) + "\n"
	for b.Len() < maxContentBytes-len(pad)-1 {
		b.WriteString(pad)
	}

	matches, err := v.ValidateContent(b.String(), "just-under.tf")
	if err != nil {
		t.Errorf("content just under the cap (%d bytes vs cap %d) returned %v: the guard is "+
			"firing early, which would report lost coverage on ordinary files", b.Len(),
			maxContentBytes, err)
	}
	if len(matches) == 0 {
		t.Error("content just under the cap produced no finding, so the boundary check above is " +
			"vacuous")
	}
}

// The whole family of "a guard fired, coverage is partial" sentinels must be recognised by one
// predicate.
//
// This family was enumerated in FOUR places — parallel.partialMatchesSurvive,
// validators.firstBudgetError, the dual-path bridge's match-preservation branch, and
// core.ScanContent. Adding a member meant finding all four, and missing one was silent: the
// sentinel was returned correctly, recorded by the bridge, then DROPPED by firstBudgetError, so
// the refusal was logged and never disclosed. This pins the predicate's membership.
func TestCoverageCutShortRecognisesTheWholeFamily(t *testing.T) {
	if !execguard.IsCoverageCutShort(execguard.ErrContentTooLarge) {
		t.Error("ErrContentTooLarge is not recognised as cutting coverage short, so a validator " +
			"declining its input is logged and dropped instead of disclosed")
	}
	if !execguard.IsCoverageCutShort(execguard.ErrMatchBudgetExceeded) {
		t.Error("ErrMatchBudgetExceeded is no longer recognised — a pre-existing member was lost")
	}
	// A wrapped sentinel must still be recognised: every producer wraps with %w to add detail.
	wrapped := errors.New("outer: " + execguard.ErrContentTooLarge.Error())
	if execguard.IsCoverageCutShort(wrapped) {
		t.Error("a look-alike error with no wrapped sentinel was accepted; matching must be on " +
			"errors.Is, not on message text")
	}
	if !execguard.IsCoverageCutShort(errWrap(execguard.ErrContentTooLarge)) {
		t.Error("a properly wrapped sentinel was not recognised, so the %w producers below it " +
			"would be dropped")
	}
	// An ordinary validator failure must NOT be in the family: it does not by itself make the
	// scan partial, which is the historical behaviour this must not change.
	if execguard.IsCoverageCutShort(errors.New("some validator blew up")) {
		t.Error("an ordinary error was treated as cut-short coverage; that would flag every " +
			"transient validator failure as lost coverage")
	}
}

func errWrap(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "context: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
