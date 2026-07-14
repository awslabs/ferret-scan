// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// ScanConfig holds configuration for scanning operations.
type ScanConfig struct {
	FilePath            string
	Checks              []string
	Debug               bool
	Verbose             bool
	Recursive           bool
	EnablePreprocessors bool
	EnableRedaction     bool
	RedactionStrategy   string
	RedactionOutputDir  string
	// MaxLiveBytes optionally caps the total bytes of extracted content held in
	// memory across concurrently validating files (v2 gap 2.3 "admission"
	// slice). Zero/negative = disabled = historical behavior (bounded only by
	// the per-file 100MB size gate × worker count). An in-process embedder on a
	// memory-constrained host (e.g. a Lambda handler scanning a directory) sets
	// this so many large files cannot multiply memory past a fixed envelope. It
	// is forwarded verbatim to the worker pool's JobConfig; the mirror of the
	// CLI's --max-live-bytes flag.
	MaxLiveBytes int64
	// Explain, when true, attaches an advisory explanation (plain-language
	// rationale, verdict gloss, drafted suppression reason) to each surfaced
	// match via internal/explain. Off by default; opt-in like the historical
	// --enable-genai. It never mutates Confidence and never auto-suppresses.
	Explain bool
	Config  *config.Config
	Profile *config.Profile
	// SuppressionManager, when non-nil, is applied to matches before returning.
	// ScanResult.SuppressedCount and SuppressedMatches are populated accordingly.
	SuppressionManager *suppressions.SuppressionManager
	// LogWriter receives observability output (progress lines, debug messages).
	// Defaults to os.Stderr when nil to preserve existing CLI behavior; pass
	// io.Discard to silence all output, or wire a custom writer to route the
	// internal observer through a structured logger.
	//
	// Critically, the observer writes payload-free progress strings only —
	// it does NOT log matched substrings or input bytes. LogWriter exists
	// to give callers (Lambda handlers, sidecars, etc.) a chokepoint to
	// enforce no-payload-bytes at the destination, futureproofing the
	// no-leak guarantee against any change that might accidentally start
	// logging content. In-process callers should pass io.Discard or a
	// structured logger writer that filters payload bytes; the internal
	// observer never emits PII today, but LogWriter is the chokepoint
	// that makes the no-leak property enforceable rather than aspirational.
	LogWriter io.Writer
}

// ScanResult holds the results of a scanning operation.
type ScanResult struct {
	Matches           []detector.Match
	SuppressedMatches []detector.SuppressedMatch
	SuppressedCount   int
	ProcessedFiles    int
	Error             error

	// Incomplete reports that validator coverage was cut short — e.g. a
	// validator timed out or the scan context was cancelled — so Matches may be
	// a partial result. It defaults to false, preserving existing behavior for
	// callers that ignore it. For a DLP tool this distinguishes "scanned clean"
	// from "did not finish scanning", which must never look the same.
	// IncompleteReason carries a short, payload-free explanation when set.
	//
	// Populated on BOTH the in-memory path (ScanContent) and the file/worker-pool
	// path (ScanFile): ScanFile aggregates per-file validator-completion status
	// from ProcessingStats.IncompleteFiles (v2 Phase 4). On the file path,
	// IncompleteReason names the single offending file or counts them when more
	// than one did not complete.
	Incomplete       bool
	IncompleteReason string
}

// resolveLogWriter returns the writer to use for observability output:
// the caller-supplied LogWriter when non-nil, or os.Stderr to preserve
// existing CLI behavior. Pass io.Discard to silence output entirely.
func resolveLogWriter(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stderr
}

// ScanFile performs the core scanning logic shared by the CLI and the web server.
func ScanFile(scanConfig ScanConfig) (*ScanResult, error) {
	// Build observer. LogWriter defaults to os.Stderr when nil so existing
	// CLI callers see the same output they always have; in-process callers
	// (Lambda, sidecars) pass io.Discard or a structured logger writer.
	logWriter := resolveLogWriter(scanConfig.LogWriter)
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, logWriter)
	if scanConfig.Debug {
		debugObs := observability.NewDebugObserver(logWriter)
		observer = debugObs.StandardObserver
		observer.DebugObserver = debugObs
	}

	// Build the filtered validator set via the shared factory
	enabledChecks := ParseChecksToRun(scanConfig.Checks)
	standardValidators := BuildValidatorSet(enabledChecks, scanConfig.Config, scanConfig.Profile)

	// Set up the detection facade (dual-path: document body + metadata).
	detectorFacade := validators.NewDetector(observer)
	if err := detectorFacade.SetupValidators(standardValidators); err != nil {
		return nil, fmt.Errorf("failed to setup dual path validation: %w", err)
	}
	validatorsList := []detector.Validator{detectorFacade}

	// Initialize file router
	fileRouter := router.NewFileRouter(scanConfig.Debug)
	router.RegisterDefaultPreprocessors(fileRouter)
	fileRouter.InitializePreprocessors(router.CreateRouterConfig(false, nil, "", scanConfig.EnableRedaction))
	detectorFacade.SetFileRouter(fileRouter)

	// Validate the target file is processable
	canProcess, _ := fileRouter.CanProcessFile(scanConfig.FilePath, scanConfig.EnablePreprocessors, false)
	if !canProcess {
		return nil, fmt.Errorf("file type not supported for processing: %s", scanConfig.FilePath)
	}

	// Process the file
	jobConfig := &parallel.JobConfig{
		Debug:              scanConfig.Debug,
		EnableRedaction:    scanConfig.EnableRedaction,
		RedactionStrategy:  scanConfig.RedactionStrategy,
		RedactionOutputDir: scanConfig.RedactionOutputDir,
		MaxLiveBytes:       scanConfig.MaxLiveBytes,
	}

	parallelProcessor := parallel.NewParallelProcessor(observer)
	parallelMatches, stats, err := parallelProcessor.ProcessFilesWithProgress(
		[]string{scanConfig.FilePath},
		validatorsList,
		fileRouter,
		jobConfig,
		nil, // redaction manager handled by caller
		nil, // progress callback handled by caller
	)
	if err != nil {
		return nil, fmt.Errorf("parallel processing failed: %w", err)
	}

	// Apply suppressions if a manager was provided
	var unsuppressed []detector.Match
	var suppressed []detector.SuppressedMatch
	if scanConfig.SuppressionManager != nil {
		for _, match := range parallelMatches {
			if isSuppressed, rule := scanConfig.SuppressionManager.IsSuppressed(match); isSuppressed {
				suppressed = append(suppressed, detector.SuppressedMatch{
					Match:        match,
					SuppressedBy: rule.ID,
					RuleReason:   rule.Reason,
					ExpiresAt:    rule.ExpiresAt,
				})
			} else {
				unsuppressed = append(unsuppressed, match)
			}
		}
	} else {
		unsuppressed = parallelMatches
	}

	// Advisory explanation pass. Runs AFTER suppression so it only annotates
	// findings that will surface and cannot affect suppression-hash identity
	// (the hash depends on Confidence, which Annotate never mutates).
	if scanConfig.Explain {
		explain.Annotate(unsuppressed, explain.NewSignalSynthesizer())
	}

	// Surface degraded validator coverage (v2 Phase 4): if any file's validation
	// did not complete (timeout/cancel/validator error), flag the result as
	// Incomplete so a partially-scanned run is never mistaken for a clean one.
	// Matches are still returned (the worker pool keeps the partial results);
	// this only adds the signal. Defaults false when every file completed.
	incomplete := false
	incompleteReason := ""
	if stats != nil && len(stats.IncompleteFiles) > 0 {
		incomplete = true
		if len(stats.IncompleteFiles) == 1 {
			incompleteReason = fmt.Sprintf("validation did not complete for %s: %s",
				stats.IncompleteFiles[0].FilePath, stats.IncompleteFiles[0].Reason)
		} else {
			incompleteReason = fmt.Sprintf("validation did not complete for %d of %d files",
				len(stats.IncompleteFiles), stats.TotalFiles)
		}
	}

	return &ScanResult{
		Matches:           unsuppressed,
		SuppressedMatches: suppressed,
		SuppressedCount:   len(suppressed),
		ProcessedFiles:    stats.ProcessedFiles,
		Incomplete:        incomplete,
		IncompleteReason:  incompleteReason,
	}, nil
}

// ContentScanConfig holds configuration for an in-memory content scan.
// It deliberately omits FilePath/Recursive/Redaction settings since virtual
// sources (stdin, in-memory buffers) have no filesystem location to write
// redacted output to.
type ContentScanConfig struct {
	// VirtualPath is the synthetic label used as Match.Filename and for
	// suppression keying. Conventionally "<stdin>" for stdin input.
	VirtualPath string

	// Format names the source format for display purposes (e.g. "Plain Text").
	// Empty defaults to "Plain Text".
	Format string

	// Checks selects which validators to run; same semantics as ScanConfig.Checks.
	Checks []string

	Debug   bool
	Verbose bool
	Config  *config.Config
	Profile *config.Profile

	// Explain, when true, attaches an advisory explanation to each surfaced
	// match via internal/explain. Same semantics as ScanConfig.Explain.
	Explain bool

	// SuppressionManager, when non-nil, is applied to matches before returning.
	SuppressionManager *suppressions.SuppressionManager

	// LogWriter receives observability output (progress lines, debug
	// messages). Defaults to os.Stderr when nil to preserve existing CLI
	// behavior; pass io.Discard to silence all output, or wire a custom
	// writer to route the internal observer through a structured logger.
	// See ScanConfig.LogWriter for the no-payload-bytes contract.
	LogWriter io.Writer

	// ValidatorBudgets optionally bounds per-validator execution (time and/or
	// match count), keyed by validator name (e.g. "SSN", "IP_ADDRESS"). Nil/empty
	// = disabled = historical behavior (byte-identical). When a budget fires, the
	// scan returns partial matches and ScanResult.Incomplete is set. See
	// execguard.ValidatorBudget.
	ValidatorBudgets map[string]execguard.ValidatorBudget
}

// ScanContent scans an in-memory content buffer using the same validator
// pipeline as ScanFile, bypassing the FileRouter (which is path-driven).
// Every produced match is stamped with detector.SourceKindVirtual and its
// Filename is set to cfg.VirtualPath.
//
// This is the entry point for stdin and any future in-process callers
// (e.g. lambda handlers, gRPC endpoints) that already have content in memory.
func ScanContent(content string, cfg ContentScanConfig) (*ScanResult, error) {
	if cfg.VirtualPath == "" {
		cfg.VirtualPath = "<stdin>"
	}
	if cfg.Format == "" {
		cfg.Format = "Plain Text"
	}

	// Build observer (mirrors ScanFile). LogWriter defaults to os.Stderr
	// when nil; in-process callers (Lambda, sidecars) pass io.Discard or
	// a structured logger writer.
	logWriter := resolveLogWriter(cfg.LogWriter)
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, logWriter)
	if cfg.Debug {
		debugObs := observability.NewDebugObserver(logWriter)
		observer = debugObs.StandardObserver
		observer.DebugObserver = debugObs
	}

	// Build the filtered validator set.
	enabledChecks := ParseChecksToRun(cfg.Checks)
	standardValidators := BuildValidatorSet(enabledChecks, cfg.Config, cfg.Profile)

	// In-memory content cannot drive metadata extraction (no filesystem path
	// for the metadata extractors to read), so omit the metadata validator.
	// Callers that need it can scan a file instead.
	delete(standardValidators, "METADATA")

	// Set up the detection facade so contextual analysis behaves identically to
	// ScanFile. No FileRouter is configured; for plaintext
	// (ProcessorType="plaintext") it never reaches the metadata extraction path.
	detectorFacade := validators.NewDetector(observer)
	if err := detectorFacade.SetupValidators(standardValidators); err != nil {
		return nil, fmt.Errorf("failed to setup dual path validation: %w", err)
	}
	validatorsList := []detector.Validator{detectorFacade}

	// Synthesize ProcessedContent. Position tracking is not enabled for
	// virtual content (no source document to map back to).
	processed := &preprocessors.ProcessedContent{
		OriginalPath:            cfg.VirtualPath,
		Filename:                cfg.VirtualPath,
		Text:                    content,
		Format:                  cfg.Format,
		ProcessorType:           "plaintext",
		Success:                 true,
		PositionTrackingEnabled: false,
	}

	// Run validators with no resilience strategy — in-memory content has no
	// transient failure mode worth retrying for.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Attach per-validator budgets (no-op when nil/empty — byte-identical path).
	ctx = execguard.WithBudgets(ctx, cfg.ValidatorBudgets)

	matches, validationErr := parallel.RunValidators(ctx, validatorsList, processed, nil)
	if validationErr != nil && cfg.Debug {
		fmt.Fprintf(logWriter, "validator error during ScanContent: %v\n", validationErr)
	}

	// A context cancellation/timeout means validator coverage was cut short and
	// Matches may be partial. Surface that explicitly so a timed-out scan is
	// never mistaken for a clean one (see ScanResult.Incomplete). Non-context
	// validator errors keep the prior behavior (logged in debug, not flagged),
	// because a single validator returning an ordinary error does not by itself
	// make the overall result partial in the same load-bearing way.
	incomplete := false
	incompleteReason := ""
	if validationErr != nil && (errors.Is(validationErr, context.DeadlineExceeded) || errors.Is(validationErr, context.Canceled)) {
		incomplete = true
		incompleteReason = "validator execution did not complete: " + validationErr.Error()
	} else if validationErr != nil && errors.Is(validationErr, execguard.ErrMatchBudgetExceeded) {
		// A per-validator match cap fired: results are truncated, so coverage is
		// partial in the same load-bearing way as a timeout.
		incomplete = true
		incompleteReason = "validator match budget exceeded: " + validationErr.Error()
	}

	// Stamp every match as virtual and ensure the filename is the synthetic
	// label (some validators may carry the OriginalPath through unchanged,
	// which is what we want; this normalizes the rest).
	for i := range matches {
		matches[i].SourceKind = detector.SourceKindVirtual
		if matches[i].Filename == "" {
			matches[i].Filename = cfg.VirtualPath
		}
	}

	// Apply suppressions if a manager was provided (mirrors ScanFile).
	var unsuppressed []detector.Match
	var suppressed []detector.SuppressedMatch
	if cfg.SuppressionManager != nil {
		for _, match := range matches {
			if isSuppressed, rule := cfg.SuppressionManager.IsSuppressed(match); isSuppressed {
				suppressed = append(suppressed, detector.SuppressedMatch{
					Match:        match,
					SuppressedBy: rule.ID,
					RuleReason:   rule.Reason,
					ExpiresAt:    rule.ExpiresAt,
				})
			} else {
				unsuppressed = append(unsuppressed, match)
			}
		}
	} else {
		unsuppressed = matches
	}

	// Advisory explanation pass (see ScanFile for the after-suppression rationale).
	if cfg.Explain {
		explain.Annotate(unsuppressed, explain.NewSignalSynthesizer())
	}

	return &ScanResult{
		Matches:           unsuppressed,
		SuppressedMatches: suppressed,
		SuppressedCount:   len(suppressed),
		ProcessedFiles:    1,
		Incomplete:        incomplete,
		IncompleteReason:  incompleteReason,
	}, nil
}

// ParseChecksToRun converts a slice of check names into an enabled-checks map.
// An empty slice or ["all"] enables every check.
func ParseChecksToRun(checks []string) map[string]bool {
	// Seed every known validator to false from the single source of truth
	// (validatorConstructors). Keeping this in sync with BuildValidatorSet
	// by construction prevents a validator from being parseable but never
	// built, or vice versa.
	result := make(map[string]bool, len(validatorConstructors))
	for name := range validatorConstructors {
		result[name] = false
	}

	if len(checks) == 0 || (len(checks) == 1 && checks[0] == "all") {
		for key := range result {
			result[key] = true
		}
		return result
	}

	for _, check := range checks {
		if checkStr := strings.TrimSpace(check); checkStr != "" {
			if _, exists := result[checkStr]; exists {
				result[checkStr] = true
			}
		}
	}

	return result
}

// ParseConfidenceLevels converts a comma-separated confidence level string into a map.
// "all" or empty string enables every level.
func ParseConfidenceLevels(levels string) map[string]bool {
	result := map[string]bool{
		"high":   false,
		"medium": false,
		"low":    false,
	}

	if levels == "all" || levels == "" {
		result["high"] = true
		result["medium"] = true
		result["low"] = true
		return result
	}

	for _, level := range strings.Split(levels, ",") {
		switch strings.ToLower(strings.TrimSpace(level)) {
		case "high", "medium", "low":
			result[strings.ToLower(strings.TrimSpace(level))] = true
		}
	}

	return result
}
