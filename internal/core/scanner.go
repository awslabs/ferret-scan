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
	"ferret-scan/internal/validators"
	"ferret-scan/internal/validators/creditcard"
	"ferret-scan/internal/validators/email"
	"ferret-scan/internal/validators/intellectualproperty"
	"ferret-scan/internal/validators/ipaddress"
	"ferret-scan/internal/validators/metadata"
	"ferret-scan/internal/validators/passport"
	"ferret-scan/internal/validators/personname"
	"ferret-scan/internal/validators/phone"
	"ferret-scan/internal/validators/secrets"
	"ferret-scan/internal/validators/socialmedia"
	"ferret-scan/internal/validators/ssn"
)

// ScanConfig holds configuration for scanning operations
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
}

// ScanResult holds the results of a scanning operation
type ScanResult struct {
	Matches         []detector.Match
	SuppressedCount int
	ProcessedFiles  int
	Error           error
}

// ScanFile performs the core scanning logic that both CLI and web server use
func ScanFile(scanConfig ScanConfig) (*ScanResult, error) {
	// Initialize enhanced validator manager (same as CLI)
	enhancedManager := validators.NewEnhancedValidatorManager(&validators.EnhancedValidatorConfig{
		EnableBatchProcessing:        true,
		BatchSize:                    100,
		EnableParallelProcessing:     true,
		MaxWorkers:                   8,
		EnableContextAnalysis:        true,
		ContextWindowSize:            500,
		EnableCrossValidatorAnalysis: true,
		EnableConfidenceCalibration:  true,
		EnableLanguageDetection:      true,
		DefaultLanguage:              "en",
		SupportedLanguages:           []string{"en"},
		EnableAdvancedAnalytics:      true,
		EnableRealTimeMetrics:        scanConfig.Debug,
	})

	// Initialize standard validators (same as CLI)
	standardValidators := map[string]detector.Validator{
		"CREDIT_CARD":           creditcard.NewValidator(),
		"EMAIL":                 email.NewValidator(),
		"PHONE":                 phone.NewValidator(),
		"IP_ADDRESS":            ipaddress.NewValidator(),
		"PASSPORT":              passport.NewValidator(),
		"PERSON_NAME":           personname.NewValidator(),
		"METADATA":              metadata.NewValidator(),
		"INTELLECTUAL_PROPERTY": intellectualproperty.NewValidator(),
		"SOCIAL_MEDIA":          socialmedia.NewValidator(),
		"SSN":                   ssn.NewValidator(),
		"SECRETS":               secrets.NewValidator(),
	}

	// Set up dual path validation integration (same as CLI)
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
	if scanConfig.Debug {
		debugObs := observability.NewDebugObserver(os.Stderr)
		observer = debugObs.StandardObserver
		observer.DebugObserver = debugObs
	}

	dualPathHelper := validators.NewValidatorIntegrationHelper(observer)
	err := dualPathHelper.SetupDualPathValidation(standardValidators)
	if err != nil {
		return nil, fmt.Errorf("failed to setup dual path validation: %v", err)
	}

	// Connect dual path helper to enhanced manager
	enhancedManager.SetDualPathHelper(dualPathHelper)

	// Filter validators based on checks parameter (same logic as CLI)
	enabledChecks := ParseChecksToRun(scanConfig.Checks)
	filteredValidators := make(map[string]detector.Validator)
	for checkName, enabled := range enabledChecks {
		if enabled {
			if validator, exists := standardValidators[checkName]; exists {
				filteredValidators[checkName] = validator
			}
		}
	}

	// Configure validators with settings from config file (same as CLI)
	if scanConfig.Config != nil {
		if ipValidator, ok := filteredValidators["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok {
			ipValidator.Configure(scanConfig.Config)
		}
		if smValidator, ok := filteredValidators["SOCIAL_MEDIA"].(*socialmedia.Validator); ok {
			smValidator.Configure(scanConfig.Config)
		}
	}

	// Apply profile-specific configurations if a profile is active (same as CLI)
	if scanConfig.Profile != nil && scanConfig.Profile.Validators != nil {
		profileConfig := &config.Config{
			Validators: scanConfig.Profile.Validators,
		}
		if ipValidator, ok := filteredValidators["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok {
			ipValidator.Configure(profileConfig)
		}
	}

	// Register enhanced validators with the manager (excluding metadata validator)
	for name, validator := range filteredValidators {
		// Skip metadata validator - it's handled by dual path system
		if name == "METADATA" {
			continue
		}

		bridge := validators.NewValidatorBridge(name, validator)
		err := enhancedManager.RegisterValidator(name, bridge)
		if err != nil {
			return nil, fmt.Errorf("failed to register enhanced validator %s: %v", name, err)
		}
	}

	// Create enhanced wrapper (same as CLI)
	enhancedWrapper := validators.NewEnhancedManagerWrapper(enhancedManager)
	validatorsList := []detector.Validator{enhancedWrapper}

	// Initialize file router (same as CLI)
	fileRouter := router.NewFileRouter(scanConfig.Debug)
	router.RegisterDefaultPreprocessors(fileRouter)

	// Configure router with same settings as CLI
	routerConfig := router.CreateRouterConfig(
		false, // enableGenAI disabled
		nil,   // genAI services
		"",    // textract region
	)
	fileRouter.InitializePreprocessors(routerConfig)

	// Connect file router to dual path system for metadata filtering
	dualPathHelper.SetFileRouter(fileRouter)

	// Use parallel processing (same as CLI)
	parallelProcessor := parallel.NewParallelProcessor(observer)

	// Filter supported files
	var supportedFiles []string
	canProcess, _ := fileRouter.CanProcessFile(scanConfig.FilePath, scanConfig.EnablePreprocessors, false)
	if canProcess {
		supportedFiles = append(supportedFiles, scanConfig.FilePath)
	} else {
		return nil, fmt.Errorf("file type not supported for processing: %s", scanConfig.FilePath)
	}

	if len(supportedFiles) == 0 {
		return &ScanResult{
			Matches:         []detector.Match{},
			SuppressedCount: 0,
			ProcessedFiles:  0,
		}, nil
	}

	// Create job config (same as CLI)
	jobConfig := &parallel.JobConfig{
		Debug:              scanConfig.Debug,
		EnableRedaction:    scanConfig.EnableRedaction,
		RedactionStrategy:  scanConfig.RedactionStrategy,
		RedactionOutputDir: scanConfig.RedactionOutputDir,
	}

	// Process files using parallel processor (same as CLI)
	parallelMatches, stats, err := parallelProcessor.ProcessFilesWithProgress(
		supportedFiles,
		validatorsList,
		fileRouter,
		jobConfig,
		nil, // redaction manager handled by caller
		nil, // progress callback handled by caller
	)
	if err != nil {
		return nil, fmt.Errorf("parallel processing failed: %v", err)
	}

	return &ScanResult{
		Matches:         parallelMatches,
		SuppressedCount: 0, // TODO: Implement suppression handling
		ProcessedFiles:  stats.ProcessedFiles,
	}, nil
}

// ParseChecksToRun converts the checks configuration into a map of enabled checks (same logic as CLI)
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
	}

	// If no checks specified or "all", enable all
	if len(checks) == 0 || (len(checks) == 1 && checks[0] == "all") {
		for key := range result {
			result[key] = true
		}
		return result
	}

	// Parse specific checks
	for _, check := range checks {
		checkStr := strings.TrimSpace(check)
		if checkStr != "" {
			if _, exists := result[checkStr]; exists {
				result[checkStr] = true
			}
		}
	}

	return result
}

// ParseConfidenceLevels converts a comma-separated string of confidence levels
// into a map of confidence level thresholds (same logic as CLI)
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

	// Process each confidence level
	for _, level := range strings.Split(levels, ",") {
		levelStr := strings.ToLower(strings.TrimSpace(level))
		if levelStr == "high" || levelStr == "medium" || levelStr == "low" {
			result[levelStr] = true
		}
	}

	return result
}
