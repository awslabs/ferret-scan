// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"ferret-scan/internal/config"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/parallel"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/router"
	"ferret-scan/internal/suppressions"
	"ferret-scan/internal/validators"
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
	Config              *config.Config
	Profile             *config.Profile
	// SuppressionManager, when non-nil, is applied to matches before returning.
	// ScanResult.SuppressedCount and SuppressedMatches are populated accordingly.
	SuppressionManager *suppressions.SuppressionManager
}

// ScanResult holds the results of a scanning operation.
type ScanResult struct {
	Matches           []detector.Match
	SuppressedMatches []detector.SuppressedMatch
	SuppressedCount   int
	ProcessedFiles    int
	Error             error
}

// ScanFile performs the core scanning logic shared by the CLI and the web server.
func ScanFile(scanConfig ScanConfig) (*ScanResult, error) {
	// Build observer
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
	if scanConfig.Debug {
		debugObs := observability.NewDebugObserver(os.Stderr)
		observer = debugObs.StandardObserver
		observer.DebugObserver = debugObs
	}

	// Initialize enhanced validator manager from shared defaults
	evCfg := validators.DefaultEnhancedValidatorConfig()
	evCfg.EnableRealTimeMetrics = scanConfig.Debug
	enhancedManager := validators.NewEnhancedValidatorManager(evCfg)

	// Build the filtered validator set via the shared factory
	enabledChecks := ParseChecksToRun(scanConfig.Checks)
	standardValidators := BuildValidatorSet(enabledChecks, scanConfig.Config, scanConfig.Profile)

	// Set up dual-path validation (separates document body from metadata)
	dualPathHelper := validators.NewValidatorIntegrationHelper(observer)
	if err := dualPathHelper.SetupDualPathValidation(standardValidators); err != nil {
		return nil, fmt.Errorf("failed to setup dual path validation: %w", err)
	}
	enhancedManager.SetDualPathHelper(dualPathHelper)

	// Register all non-metadata validators with the enhanced manager
	for name, validator := range standardValidators {
		if name == "METADATA" {
			continue // handled by the dual-path system
		}
		bridge := validators.NewValidatorBridge(name, validator)
		if err := enhancedManager.RegisterValidator(name, bridge); err != nil {
			return nil, fmt.Errorf("failed to register enhanced validator %s: %w", name, err)
		}
	}

	enhancedWrapper := validators.NewEnhancedManagerWrapper(enhancedManager)
	validatorsList := []detector.Validator{enhancedWrapper}

	// Initialize file router
	fileRouter := router.NewFileRouter(scanConfig.Debug)
	router.RegisterDefaultPreprocessors(fileRouter)
	fileRouter.InitializePreprocessors(router.CreateRouterConfig(false, nil, "", scanConfig.EnableRedaction))
	dualPathHelper.SetFileRouter(fileRouter)

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

	return &ScanResult{
		Matches:           unsuppressed,
		SuppressedMatches: suppressed,
		SuppressedCount:   len(suppressed),
		ProcessedFiles:    stats.ProcessedFiles,
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

	// SuppressionManager, when non-nil, is applied to matches before returning.
	SuppressionManager *suppressions.SuppressionManager
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

	// Build observer (mirrors ScanFile)
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
	if cfg.Debug {
		debugObs := observability.NewDebugObserver(os.Stderr)
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

	// Set up the enhanced manager + dual-path bridge so contextual analysis
	// behaves identically to ScanFile. The dual-path helper is configured
	// without a FileRouter; for plaintext (ProcessorType="plaintext") it
	// never reaches the metadata extraction path.
	evCfg := validators.DefaultEnhancedValidatorConfig()
	evCfg.EnableRealTimeMetrics = cfg.Debug
	enhancedManager := validators.NewEnhancedValidatorManager(evCfg)

	dualPathHelper := validators.NewValidatorIntegrationHelper(observer)
	if err := dualPathHelper.SetupDualPathValidation(standardValidators); err != nil {
		return nil, fmt.Errorf("failed to setup dual path validation: %w", err)
	}
	enhancedManager.SetDualPathHelper(dualPathHelper)

	for name, validator := range standardValidators {
		bridge := validators.NewValidatorBridge(name, validator)
		if err := enhancedManager.RegisterValidator(name, bridge); err != nil {
			return nil, fmt.Errorf("failed to register enhanced validator %s: %w", name, err)
		}
	}
	enhancedWrapper := validators.NewEnhancedManagerWrapper(enhancedManager)
	validatorsList := []detector.Validator{enhancedWrapper}

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

	matches, validationErr := parallel.RunValidators(ctx, validatorsList, processed, nil)
	if validationErr != nil && cfg.Debug {
		fmt.Fprintf(os.Stderr, "validator error during ScanContent: %v\n", validationErr)
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

	return &ScanResult{
		Matches:           unsuppressed,
		SuppressedMatches: suppressed,
		SuppressedCount:   len(suppressed),
		ProcessedFiles:    1,
	}, nil
}

// ParseChecksToRun converts a slice of check names into an enabled-checks map.
// An empty slice or ["all"] enables every check.
func ParseChecksToRun(checks []string) map[string]bool {
	result := map[string]bool{
		"CREDIT_CARD":           false,
		"EMAIL":                 false,
		"PHONE":                 false,
		"IP_ADDRESS":            false,
		"PASSPORT":              false,
		"METADATA":              false,
		"INTELLECTUAL_PROPERTY": false,
		"SOCIAL_MEDIA":          false,
		"SSN":                   false,
		"SECRETS":               false,
		"PERSON_NAME":           false,
		"VIN":                   false,
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
