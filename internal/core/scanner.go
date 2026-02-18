// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"os"
	"strings"

	"ferret-scan/internal/config"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/parallel"
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
