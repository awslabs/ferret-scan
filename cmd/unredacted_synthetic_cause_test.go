// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// oneReplacementScope is a real scope whose every draw yields the same replacement, so the second
// distinct value of a family exhausts it exactly as a full family does: the error is the scope's own.
type oneReplacementScope struct{ inner redactors.SyntheticScope }

func (s oneReplacementScope) Resolve(family, canonical string, distinct bool, _ redactors.SyntheticDraw) (string, error) {
	return s.inner.Resolve(family, canonical, distinct, func(io.Reader, int) (string, error) { return "000000000", nil })
}

// An exhausted synthetic family reaches the report under a cause of its own (#886), classified by
// the error (errors.Is), not by its prose. The file goes through the pipeline the CLI runs -- the
// detector, the worker pool and the default redaction manager -- so the typed error is the one that
// survives every wrap between the scope and parallel.FileDiagnostic.Err.
func TestAnExhaustedSyntheticFamilyIsClassifiedByItsError(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "people.txt")
	if err := os.WriteFile(in, []byte("SSN: 449-87-4100\nSSN: 449-87-4101\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	facade := validators.NewDetector(observer)
	if err := facade.SetupValidators(core.BuildValidatorSet(core.ParseChecksToRun([]string{"SSN"}), nil, nil)); err != nil {
		t.Fatal(err)
	}
	fileRouter := router.NewFileRouter(false)
	router.RegisterDefaultPreprocessors(fileRouter)
	fileRouter.InitializePreprocessors(router.CreateRouterConfig(true))
	facade.SetFileRouter(fileRouter)
	manager, _, err := core.NewDefaultRedactionManager(filepath.Join(dir, "out"), redactors.RedactionSynthetic, observer)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetSyntheticScope(oneReplacementScope{inner: redactors.NewSyntheticScope()})

	matches, stats, err := parallel.NewParallelProcessor(observer).ProcessFilesWithProgressCtx(context.Background(),
		[]string{in}, []detector.Validator{facade}, fileRouter,
		&parallel.JobConfig{EnableRedaction: true, RedactionStrategy: redactors.RedactionSynthetic}, manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) < 2 {
		t.Fatalf("the scan found %d SSNs, want 2: the fixture does not reach the synthetic family", len(matches))
	}
	if stats == nil || len(stats.UnredactedFiles) != 1 {
		t.Fatalf("unredacted files = %+v, want the one refused file", stats)
	}
	d := stats.UnredactedFiles[0]
	if !errors.Is(d.Err, redactors.ErrSyntheticSpaceExhausted) {
		t.Fatalf("FileDiagnostic.Err = %v, want ErrSyntheticSpaceExhausted", d.Err)
	}

	got := toFormatterUnredacted(stats.UnredactedFiles, matches)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Cause != formatters.UnredactedSyntheticExhausted {
		t.Errorf("cause = %v (%s), want UnredactedSyntheticExhausted", got[0].Cause, got[0].Cause)
	}
	if got[0].ReportedValues != len(matches) {
		t.Errorf("ReportedValues = %d, want %d", got[0].ReportedValues, len(matches))
	}

	// The prose alone is not the classifier: the same Reason with no typed error keeps the
	// generic cause, so rewording the message can neither assert this cause nor lose it.
	if c := classifyRedaction(nil, d.Reason); c != formatters.UnredactedRefused {
		t.Errorf("Reason without Err classified as %v, want the generic UnredactedRefused", c)
	}
	// Any other typed error keeps the string classifier's answer.
	if c := classifyRedaction(errors.New("x"), "PDF redaction is not implemented"); c != formatters.UnredactedNoRedactor {
		t.Errorf("an unrelated error changed the string classification: %v", c)
	}
}
