// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// The worker pool's dispatch -- the one every top-level file of the CLI and of core.RedactFile goes
// through -- now enforces the declaration (#863). A top-level .doc, .xls or .ppt asked for synthetic
// was written with a same-length mask at exit 0: the embedded dispatcher refused it, the top-level
// one did not ask.
func TestTheTopLevelDispatchRefusesSyntheticForLegacyOffice(t *testing.T) {
	body := "Email " + e2eEmail + "\rPhone " + e2ePhone + "\rCard " + e2eCard + "\r"
	files := map[string][]byte{
		"w.doc": olefixture.LegacyDoc(body, nil),
		"x.xls": olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamWorkbook, Data: []byte(body)}}),
		"p.ppt": olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamPowerPoint, Data: []byte(body)}}),
	}
	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			src := write(t, name, data)
			_, out, err := redactFile(t, src, redactors.RedactionSynthetic, e2eChecks)
			if err == nil || !strings.Contains(err.Error(), "not synthetic") ||
				!strings.Contains(err.Error(), "simple and format_preserving") {
				t.Fatalf("synthetic: err = %v, want a refusal naming synthetic and the strategies the format takes", err)
			}
			if len(out) != 0 {
				t.Errorf("a refused file produced %d bytes of output", len(out))
			}
			// The declared strategies still redact.
			_, b, err := redactFile(t, src, redactors.RedactionSimple, e2eChecks)
			if err != nil {
				t.Fatalf("simple: %v", err)
			}
			assertMasked(t, name, b)
		})
	}
}

// formatPreservingOnly is a redactor that declares one strategy and does NOT check it itself, so only
// the dispatcher can refuse the others.
type formatPreservingOnly struct{ called []redactors.RedactionStrategy }

func (s *formatPreservingOnly) GetName() string             { return "fp_only_stub" }
func (s *formatPreservingOnly) GetComponentName() string    { return "fp_only_stub" }
func (s *formatPreservingOnly) GetSupportedTypes() []string { return []string{".txt"} }
func (s *formatPreservingOnly) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{redactors.RedactionFormatPreserving}
}
func (s *formatPreservingOnly) RedactDocument(in, out string, _ []detector.Match, st redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	s.called = append(s.called, st)
	b, err := os.ReadFile(in)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return nil, err
	}
	// Writes the SSN masked, so the dispatcher's own residue check passes on a declared strategy.
	return &redactors.RedactionResult{Success: true, RedactedFilePath: out},
		os.WriteFile(out, bytes.ReplaceAll(b, []byte(dispatchSSN), []byte("***-**-0001")), 0o600)
}

const dispatchSSN = "234-56-0001"

// dispatchThroughTheWorkerPool runs one .txt holding an SSN through the worker pool, exactly as
// core.RedactFile wires it, with the stub as the only redactor.
func dispatchThroughTheWorkerPool(t *testing.T, stub *formatPreservingOnly, st redactors.RedactionStrategy) *parallel.ProcessingStats {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "record.txt")
	if err := os.WriteFile(src, []byte("Employee SSN: "+dispatchSSN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	om, err := redactors.NewOutputStructureManager(filepath.Join(dir, "out"), observer)
	if err != nil {
		t.Fatal(err)
	}
	mgr := redactors.NewRedactionManagerWithConfig(om, observer, &redactors.RedactionManagerConfig{DefaultStrategy: st, RetryAttempts: 1})
	if err := mgr.RegisterRedactor(stub); err != nil {
		t.Fatal(err)
	}
	facade := validators.NewDetector(observer)
	if err := facade.SetupValidators(core.BuildValidatorSet(core.ParseChecksToRun([]string{"SSN"}), config.LoadConfigOrDefault(""), nil)); err != nil {
		t.Fatal(err)
	}
	fr := router.NewFileRouter(false)
	router.RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(router.CreateRouterConfig(true))
	facade.SetFileRouter(fr)
	matches, stats, err := parallel.NewParallelProcessor(observer).ProcessFilesWithProgressCtx(context.Background(),
		[]string{src}, []detector.Validator{facade}, fr, &parallel.JobConfig{EnableRedaction: true, RedactionStrategy: st}, mgr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("the fixture reported nothing; the dispatch was never asked to redact")
	}
	return stats
}

// The worker pool asks RedactorFor, so a redactor that does not check the strategy itself is still
// never handed one it does not declare. It used to call GetRedactorForFile and hand it anything.
func TestTheWorkerPoolRefusesAnUndeclaredStrategy(t *testing.T) {
	stub := &formatPreservingOnly{}
	stats := dispatchThroughTheWorkerPool(t, stub, redactors.RedactionSynthetic)
	if len(stub.called) != 0 {
		t.Fatalf("the redactor was handed %v, which it does not declare", stub.called)
	}
	if len(stats.UnredactedFiles) != 1 || !strings.Contains(stats.UnredactedFiles[0].Reason, "not synthetic") ||
		strings.Contains(stats.UnredactedFiles[0].Reason, "failed to get redactor") {
		t.Fatalf("unredacted files %+v, want the file refused with the gate's reason", stats.UnredactedFiles)
	}

	stub = &formatPreservingOnly{}
	stats = dispatchThroughTheWorkerPool(t, stub, redactors.RedactionFormatPreserving)
	if len(stub.called) != 1 || len(stats.UnredactedFiles) != 0 {
		t.Fatalf("a declared strategy: called %v, unredacted %+v", stub.called, stats.UnredactedFiles)
	}
}

// The refusal the dispatchers make, before the redactor is called, says why a same-length format
// cannot take the strategy, as the redactor's own refusal did. Moving the worker pool to RedactorFor
// dropped that reason from the CLI's message, because the redactor's check, which added it, is no
// longer reached.
func TestTheDispatchRefusalSaysWhy(t *testing.T) {
	rm, _, err := core.NewDefaultRedactionManager(filepath.Join(t.TempDir(), "out"), redactors.RedactionSynthetic, nil)
	if err != nil {
		t.Fatal(err)
	}
	matches := []detector.Match{{Text: e2eEmail, Type: "EMAIL", Confidence: 90}}
	for _, name := range []string{"clip.wav", "movie.mp4", "w.doc", "x.xls", "p.ppt"} {
		_, err := rm.RedactorFor(filepath.Join(t.TempDir(), name), redactors.RedactionSynthetic, matches)
		if !errors.Is(err, redactors.ErrStrategyNotSupported) || !strings.Contains(err.Error(), "own byte length") {
			t.Errorf("%s: RedactorFor(synthetic) = %v, want the refusal with the same-length reason", name, err)
		}
	}
}

// The gate refuses a dispatch carrying matches only: a clean legacy file is not refused under synthetic.
func TestTheTopLevelDispatchDoesNotRefuseACleanFile(t *testing.T) {
	src := write(t, "clean.doc", olefixture.LegacyDoc("Quarterly notes, nothing sensitive here.\r", nil))
	_, _, err := redactFile(t, src, redactors.RedactionSynthetic, e2eChecks)
	if errors.Is(err, redactors.ErrStrategyNotSupported) || (err != nil && strings.Contains(err.Error(), "not supported")) {
		t.Fatalf("a clean file was refused: %v", err)
	}
}
