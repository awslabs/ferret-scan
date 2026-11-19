// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
)

// oneReplacementScope is a real scope whose every draw yields the same replacement, so the second
// distinct value of a family exhausts it exactly as a full family does: the error is the scope's own.
type oneReplacementScope struct{ inner redactors.SyntheticScope }

func (s oneReplacementScope) Resolve(family, canonical string, distinct bool, _ redactors.SyntheticDraw) (string, error) {
	return s.inner.Resolve(family, canonical, distinct, func(io.Reader, int) (string, error) { return "000000000", nil })
}

// An exhausted synthetic family reaches the report under a cause of its own (#886), classified by
// the error (errors.Is), not by its prose.
func TestAnExhaustedSyntheticFamilyIsClassifiedByItsError(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "people.txt"), filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte("SSN 234-56-0001\nSSN 234-56-0002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	matches := []detector.Match{
		{Text: "234-56-0001", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: in},
		{Text: "234-56-0002", Type: "SSN", Confidence: 100, LineNumber: 2, Filename: in},
	}
	ptr := plaintext.NewPlainTextRedactor(nil, nil)
	ptr.SetSyntheticScope(oneReplacementScope{inner: redactors.NewSyntheticScope()})
	_, err := ptr.RedactDocument(in, out, matches, redactors.RedactionSynthetic)
	if !errors.Is(err, redactors.ErrSyntheticSpaceExhausted) {
		t.Fatalf("redactor err = %v, want ErrSyntheticSpaceExhausted", err)
	}

	// What internal/parallel records for an unredacted file: the prose and the typed error.
	diags := []parallel.FileDiagnostic{{FilePath: in, Reason: err.Error(), Err: err}}
	got := toFormatterUnredacted(diags, matches)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Cause != formatters.UnredactedSyntheticExhausted {
		t.Errorf("cause = %v (%s), want UnredactedSyntheticExhausted", got[0].Cause, got[0].Cause)
	}
	if got[0].ReportedValues != 2 {
		t.Errorf("ReportedValues = %d, want 2", got[0].ReportedValues)
	}

	// The prose alone is not the classifier: the same Reason with no typed error keeps the
	// generic cause, so rewording the message cannot assert this cause, nor lose it.
	if c := classifyRedaction(nil, err.Error()); c != formatters.UnredactedRefused {
		t.Errorf("Reason without Err classified as %v, want the generic UnredactedRefused", c)
	}
	// Every other typed error keeps the string classifier's answer.
	if c := classifyRedaction(errors.New("x"), "PDF redaction is not implemented"); c != formatters.UnredactedNoRedactor {
		t.Errorf("an unrelated error changed the string classification: %v", c)
	}
}
