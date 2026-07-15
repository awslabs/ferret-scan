// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/image"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/office"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/pdf"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// RedactConfig configures a single-file redaction pass.
type RedactConfig struct {
	// FilePath is the file to scan and redact.
	FilePath string
	// OutputDir is the base directory where the redacted copy is written. The
	// redactor mirrors the input's path structure beneath this directory.
	OutputDir string
	// Strategy is one of "simple", "format_preserving" (default), or "synthetic".
	Strategy string
	// Checks selects validators; empty or ["all"] runs every validator.
	Checks []string
	// Config is the loaded engine config (use config.LoadConfigOrDefault("")).
	Config *config.Config
	// LogWriter receives payload-free progress output; defaults to io.Discard
	// here so in-process callers never leak to stderr.
	LogWriter io.Writer
}

// RedactResult reports the outcome of a redaction.
type RedactResult struct {
	// RedactedFilePath is the path to the written redacted document.
	RedactedFilePath string
	// RedactionCount is the number of sensitive values redacted.
	RedactionCount int
	// Strategy is the strategy actually applied.
	Strategy string
	// Matches are the detections that drove the redaction (payload-free unless
	// the caller inspects Text).
	Matches []detector.Match
}

// RedactFile scans a single file and writes a redacted copy to OutputDir using
// the appropriate format-aware redactor (plaintext/CSV/JSON, PDF, Office,
// image-metadata). It mirrors the CLI's redaction wiring, which core.ScanFile
// intentionally leaves to the caller (ScanFile passes a nil redaction manager).
//
// A redacted .docx stays a .docx, a .pdf stays a .pdf, and image redaction
// strips EXIF/GPS metadata — the output is a real file of the same type, safe
// to share.
func RedactFile(cfg RedactConfig) (*RedactResult, error) {
	logWriter := resolveLogWriter(cfg.LogWriter)
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, logWriter)

	// Build the filtered validator set + detection facade (same as ScanFile).
	enabledChecks := ParseChecksToRun(cfg.Checks)
	standardValidators := BuildValidatorSet(enabledChecks, cfg.Config, nil)
	detectorFacade := validators.NewDetector(observer)
	if err := detectorFacade.SetupValidators(standardValidators); err != nil {
		return nil, fmt.Errorf("failed to set up validators: %w", err)
	}
	validatorsList := []detector.Validator{detectorFacade}

	// Router with preprocessors enabled so PDF/DOCX/image content is extracted.
	fileRouter := router.NewFileRouter(false)
	router.RegisterDefaultPreprocessors(fileRouter)
	fileRouter.InitializePreprocessors(router.CreateRouterConfig(false, nil, "", true))
	detectorFacade.SetFileRouter(fileRouter)

	if canProcess, reason := fileRouter.CanProcessFile(cfg.FilePath, true, false); !canProcess {
		return nil, fmt.Errorf("file type not supported for redaction: %s (%s)", cfg.FilePath, reason)
	}

	// Build the redaction manager with all default redactors registered. This
	// is the SAME shared factory the CLI uses (NewDefaultRedactionManager), so
	// manager config and the set of registered redactors live in one place.
	strategy := redactors.ParseRedactionStrategy(cfg.Strategy)
	redactionManager, outputManager, err := NewDefaultRedactionManager(cfg.OutputDir, strategy, observer)
	if err != nil {
		return nil, err
	}

	// The worker pool writes the redacted copy to the mirrored output path
	// (GetOutputManager().CreateMirroredPath). Compute it up front so we can
	// report and verify it — the manager keeps only an audit trail, not a
	// queryable path index.
	redactedPath, err := outputManager.CreateMirroredPath(cfg.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute output path: %w", err)
	}

	// Run the worker pool WITH the redaction manager so it performs inline
	// redaction and writes the output file.
	jobConfig := &parallel.JobConfig{
		EnableRedaction:   true,
		RedactionStrategy: cfg.Strategy,
	}
	pp := parallel.NewParallelProcessor(observer)
	matches, _, err := pp.ProcessFilesWithProgress(
		[]string{cfg.FilePath}, validatorsList, fileRouter, jobConfig, redactionManager, nil)
	if err != nil {
		return nil, fmt.Errorf("redaction processing failed: %w", err)
	}

	// The worker pool only writes an output file when there is at least one
	// match to redact. For a clean file (no findings), copy the original to the
	// output path so callers always have a file to hand off — a clean document
	// is safe to share as-is.
	if _, statErr := os.Stat(redactedPath); statErr != nil {
		if len(matches) == 0 {
			if copyErr := copyFile(cfg.FilePath, redactedPath); copyErr != nil {
				return nil, fmt.Errorf("failed to copy clean file to output: %w", copyErr)
			}
		} else {
			return nil, fmt.Errorf("redaction did not produce an output file at %s: %w", redactedPath, statErr)
		}
	}

	return &RedactResult{
		RedactedFilePath: redactedPath,
		RedactionCount:   len(matches),
		Strategy:         strategy.String(),
		Matches:          matches,
	}, nil
}

// copyFile copies src to dst, creating parent directories as needed. Used to
// pass through a clean (no-findings) file so there is always an output to share.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 - src is a caller-provided scan target
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst) // #nosec G304 - dst is under the caller's output dir
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// NewDefaultRedactionManager builds a RedactionManager with the standard
// manager config and all format-aware redactors registered (plaintext/CSV/JSON,
// PDF, Office, image-metadata). It is the single source of truth for redaction
// setup, shared by the CLI (cmd/main.go) and core.RedactFile so the manager
// config and the set of registered redactors never drift between them.
//
// Adding a new redactor or changing manager tuning is a one-line change here.
// It returns the manager and its output manager (callers need the latter to
// compute mirrored output paths).
func NewDefaultRedactionManager(outputDir string, strategy redactors.RedactionStrategy,
	observer observability.Observer) (*redactors.RedactionManager, *redactors.OutputStructureManager, error) {

	outputManager, err := redactors.NewOutputStructureManager(outputDir, observer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output manager: %w", err)
	}

	manager := redactors.NewRedactionManagerWithConfig(outputManager, observer,
		&redactors.RedactionManagerConfig{
			DefaultStrategy:         strategy,
			MaxConcurrentRedactions: 4,
			EnableBatchProcessing:   true,
			BatchSize:               100,
			RetryAttempts:           3,
			RetryDelay:              time.Second * 2,
			EnableAuditTrail:        true,
			FailureHandling:         redactors.FailureHandlingGraceful,
		})

	for _, r := range []redactors.Redactor{
		plaintext.NewPlainTextRedactor(outputManager, observer),
		pdf.NewPDFRedactor(outputManager, observer),
		office.NewOfficeRedactor(outputManager, observer),
		image.NewImageMetadataRedactor(outputManager, observer),
	} {
		if err := manager.RegisterRedactor(r); err != nil {
			return nil, nil, fmt.Errorf("failed to register redactor %s: %w", r.GetName(), err)
		}
	}
	return manager, outputManager, nil
}
