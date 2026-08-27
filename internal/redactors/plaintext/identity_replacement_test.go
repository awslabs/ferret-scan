// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// TestIdentityReplacementIsNotCountedAsARedaction is the guard half of #522.
//
// `replacement.FormatPreserving`'s default arm returns `strings.Repeat("*", len(original))`. When the
// value is ALREADY a run of asterisks, replacement == original: the output is byte-identical to the
// input while `Success` is true, rc is 0, and the audit log records an `original_file_hash` equal to
// its `redacted_file_hash` — the compliance artefact attesting to work that did not happen.
//
// The detection half of #522 makes that trigger unreachable, so this test constructs it directly. It
// is kept precisely because the trigger is gone: the next value type whose mask equals itself must
// not quietly re-enter the audit trail as a redaction.
func TestIdentityReplacementIsNotCountedAsARedaction(t *testing.T) {
	// A type with no special branch in FormatPreserving, so the default all-asterisk arm runs, and a
	// value that is already exactly that.
	value := strings.Repeat("*", 24)
	content := "api_secret=" + value + " trailing"
	matches := []detector.Match{{
		Text: value, Type: "API_KEY_OR_SECRET", LineNumber: 1, Confidence: 75, Validator: "secrets",
		Context: detector.ContextInfo{FullLine: content},
	}}

	var log bytes.Buffer
	debugObs := observability.NewDebugObserver(&log)
	observer := debugObs.StandardObserver
	observer.DebugObserver = debugObs

	ptr := NewPlainTextRedactor(nil, observer)
	redacted, mappings, err := ptr.RedactString(content, matches, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}

	// Non-vacuity: the replacement really must be identical, or this test is exercising nothing.
	// If FormatPreserving ever stops returning the value unchanged here, this fails loudly rather
	// than passing for the wrong reason.
	if got := replacement.FormatPreserving(value, "API_KEY_OR_SECRET"); got != value {
		t.Fatalf("the fixture no longer produces an identity replacement (%q -> %q); this test needs "+
			"one to exercise the guard", value, got)
	}

	if len(mappings) != 0 {
		t.Errorf("an identity replacement was recorded as %d redaction(s); counting it attests to "+
			"work that did not happen", len(mappings))
	}
	if redacted != content {
		t.Errorf("the content changed, which contradicts the replacement being identical:\n  in : %q\n  out: %q",
			content, redacted)
	}
	if !strings.Contains(log.String(), "replacement_identical_to_original") {
		t.Error("the no-op was not recorded; it must be visible as its own cause rather than " +
			"disappearing or being reported as a redaction")
	}
}

// TestARealReplacementIsStillCountedKeepsTheGuardNarrow.
//
// The guard skips a replacement equal to what it replaces. If it ever widened to skip more than that
// — a length comparison, or a "looks like a mask" test — it would silently stop redacting real
// values, which is the one outcome worse than the defect it fixes.
func TestARealReplacementIsStillCountedKeepsTheGuardNarrow(t *testing.T) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	content := "Employee taxpayer SSN " + ssn + "."
	matches := []detector.Match{{
		Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		Context: detector.ContextInfo{FullLine: content},
	}}

	for _, strategy := range []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	} {
		t.Run(strategy.String(), func(t *testing.T) {
			ptr := NewPlainTextRedactor(nil, nil)
			redacted, mappings, err := ptr.RedactString(content, matches, strategy)
			if err != nil {
				t.Fatalf("RedactString: %v", err)
			}
			if len(mappings) != 1 {
				t.Errorf("a real replacement recorded %d mappings, want 1", len(mappings))
			}
			if strings.Contains(redacted, ssn) {
				t.Errorf("the value survived: %q", redacted)
			}
		})
	}
}

// TestAValueContainingMaskCharactersIsStillRedacted is the other narrowness control.
//
// A credential with asterisks IN it is a real credential. The guard compares the whole replacement
// with the whole original, so this must be unaffected — the detection-side suppressor has the
// matching test for the reporting half.
func TestAValueContainingMaskCharactersIsStillRedacted(t *testing.T) {
	value := "abc**defGHIjklMNOpqrs123456789"
	content := "api_token=" + value
	matches := []detector.Match{{
		Text: value, Type: "API_KEY_OR_SECRET", LineNumber: 1, Confidence: 100, Validator: "secrets",
		Context: detector.ContextInfo{FullLine: content},
	}}

	ptr := NewPlainTextRedactor(nil, nil)
	redacted, mappings, err := ptr.RedactString(content, matches, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("recorded %d mappings, want 1 — a value that merely CONTAINS mask characters must "+
			"still be redacted", len(mappings))
	}
	if strings.Contains(redacted, value) {
		t.Errorf("the value survived: %q", redacted)
	}
}
