// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
)

// RecoveryManager handles document processing failure recovery
type RecoveryManager struct {
	// observer handles observability and metrics
	observer *observability.StandardObserver

	// config contains recovery configuration
	config *RecoveryConfig

	// stats tracks recovery statistics
	stats *RecoveryStats
}

// RecoveryConfig contains configuration for recovery operations
type RecoveryConfig struct {
	// EnableAutoRecovery enables automatic recovery attempts
	EnableAutoRecovery bool

	// MaxRecoveryAttempts is the maximum number of recovery attempts
	MaxRecoveryAttempts int

	// RecoveryTimeout is the maximum time allowed for recovery
	RecoveryTimeout time.Duration

	// BackupEnabled enables creation of backup files before recovery
	BackupEnabled bool

	// BackupDirectory is the directory for backup files
	BackupDirectory string

	// RecoveryStrategies defines the recovery strategies to attempt
	RecoveryStrategies []RecoveryStrategy

	// FailsafeMode enables failsafe recovery (copy original if all else fails)
	FailsafeMode bool
}

// RecoveryStrategy represents a recovery strategy
type RecoveryStrategy int

const (
	// RecoveryStrategyReprocess attempts to reprocess the document
	RecoveryStrategyReprocess RecoveryStrategy = iota
	// RecoveryStrategyFallback uses a simpler redaction strategy
	RecoveryStrategyFallback
	// RecoveryStrategyPartial attempts partial redaction
	RecoveryStrategyPartial
	// RecoveryStrategyCopy copies the original file as fallback
	RecoveryStrategyCopy
	// RecoveryStrategySkip skips the file and continues processing
	RecoveryStrategySkip
)

// String returns the string representation of the recovery strategy
func (rs RecoveryStrategy) String() string {
	switch rs {
	case RecoveryStrategyReprocess:
		return "reprocess"
	case RecoveryStrategyFallback:
		return "fallback"
	case RecoveryStrategyPartial:
		return "partial"
	case RecoveryStrategyCopy:
		return "copy"
	case RecoveryStrategySkip:
		return "skip"
	default:
		return "unknown"
	}
}

// RecoveryStats tracks statistics for recovery operations
type RecoveryStats struct {
	// TotalRecoveryAttempts is the total number of recovery attempts
	TotalRecoveryAttempts int64

	// SuccessfulRecoveries is the number of successful recoveries
	SuccessfulRecoveries int64

	// FailedRecoveries is the number of failed recoveries
	FailedRecoveries int64

	// RecoveryStrategiesUsed tracks usage of each recovery strategy
	RecoveryStrategiesUsed map[RecoveryStrategy]int64

	// TotalRecoveryTime is the total time spent on recovery operations
	TotalRecoveryTime time.Duration

	// AverageRecoveryTime is the average time per recovery attempt
	AverageRecoveryTime time.Duration
}

// RecoveryResult represents the result of a recovery operation
type RecoveryResult struct {
	// Success indicates whether recovery was successful
	Success bool

	// StrategyUsed is the recovery strategy that was successful
	StrategyUsed RecoveryStrategy

	// RecoveryTime is the time taken for recovery
	RecoveryTime time.Duration

	// RecoveredFilePath is the path to the recovered file
	RecoveredFilePath string

	// BackupFilePath is the path to the backup file (if created)
	BackupFilePath string

	// Issues contains any issues encountered during recovery
	Issues []ValidationIssue

	// Metadata contains additional recovery metadata
	Metadata map[string]interface{}

	// Error contains any recovery error
	Error error
}

// NewRecoveryManager creates a new RecoveryManager
func NewRecoveryManager(observer *observability.StandardObserver) *RecoveryManager {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	config := &RecoveryConfig{
		EnableAutoRecovery:  true,
		MaxRecoveryAttempts: 3,
		RecoveryTimeout:     time.Minute * 10,
		BackupEnabled:       true,
		BackupDirectory:     "",
		RecoveryStrategies: []RecoveryStrategy{
			RecoveryStrategyReprocess,
			RecoveryStrategyFallback,
			RecoveryStrategyPartial,
			RecoveryStrategyCopy,
		},
		FailsafeMode: true,
	}

	stats := &RecoveryStats{
		RecoveryStrategiesUsed: make(map[RecoveryStrategy]int64),
	}

	return &RecoveryManager{
		observer: observer,
		config:   config,
		stats:    stats,
	}
}

// AttemptRecovery attempts to recover from a document processing failure
func (rm *RecoveryManager) AttemptRecovery(originalPath, failedOutputPath string, redactionManager *redactors.RedactionManager, matches []detector.Match, strategy redactors.RedactionStrategy) (*RecoveryResult, error) {
	if !rm.config.EnableAutoRecovery {
		return nil, fmt.Errorf("auto recovery is disabled")
	}

	startTime := time.Now()

	result := &RecoveryResult{
		Success:  false,
		Metadata: make(map[string]interface{}),
		Issues:   []ValidationIssue{},
	}

	rm.stats.TotalRecoveryAttempts++

	// Create backup if enabled
	var backupPath string
	if rm.config.BackupEnabled {
		var err error
		backupPath, err = rm.createBackup(originalPath)
		if err != nil {
			rm.logEvent("backup_failed", false, map[string]interface{}{
				"original_path": originalPath,
				"error":         err.Error(),
			})
			// Continue without backup
		} else {
			result.BackupFilePath = backupPath
		}
	}

	// Attempt recovery using configured strategies
	for attempt := 0; attempt < rm.config.MaxRecoveryAttempts; attempt++ {
		for _, recoveryStrategy := range rm.config.RecoveryStrategies {
			rm.stats.RecoveryStrategiesUsed[recoveryStrategy]++

			recoveryResult, err := rm.executeRecoveryStrategy(
				recoveryStrategy,
				originalPath,
				failedOutputPath,
				redactionManager,
				matches,
				strategy,
			)

			if err == nil && recoveryResult != nil {
				// Recovery successful
				result.Success = true
				result.StrategyUsed = recoveryStrategy
				result.RecoveredFilePath = recoveryResult.RecoveredFilePath
				result.RecoveryTime = time.Since(startTime)
				result.Metadata["recovery_attempt"] = attempt + 1
				result.Metadata["strategy_used"] = recoveryStrategy.String()

				rm.stats.SuccessfulRecoveries++
				rm.updateRecoveryTime(result.RecoveryTime)

				rm.logEvent("recovery_successful", true, map[string]interface{}{
					"original_path":  originalPath,
					"recovered_path": result.RecoveredFilePath,
					"strategy_used":  recoveryStrategy.String(),
					"recovery_time":  result.RecoveryTime,
					"attempt_number": attempt + 1,
				})

				return result, nil
			}

			// Log failed attempt
			rm.logEvent("recovery_attempt_failed", false, map[string]interface{}{
				"original_path": originalPath,
				"strategy":      recoveryStrategy.String(),
				"attempt":       attempt + 1,
				"error":         err,
			})
		}

		// Check timeout
		if time.Since(startTime) > rm.config.RecoveryTimeout {
			break
		}
	}

	// All recovery attempts failed
	result.RecoveryTime = time.Since(startTime)
	result.Error = fmt.Errorf("all recovery attempts failed")
	rm.stats.FailedRecoveries++
	rm.updateRecoveryTime(result.RecoveryTime)

	rm.logEvent("recovery_failed", false, map[string]interface{}{
		"original_path": originalPath,
		"recovery_time": result.RecoveryTime,
		"attempts_made": rm.config.MaxRecoveryAttempts,
	})

	return result, result.Error
}

// executeRecoveryStrategy executes a specific recovery strategy
func (rm *RecoveryManager) executeRecoveryStrategy(
	strategy RecoveryStrategy,
	originalPath, failedOutputPath string,
	redactionManager *redactors.RedactionManager,
	matches []detector.Match,
	redactionStrategy redactors.RedactionStrategy,
) (*RecoveryResult, error) {
	switch strategy {
	case RecoveryStrategyReprocess:
		return rm.reprocessDocument(originalPath, failedOutputPath, redactionManager, matches, redactionStrategy)
	case RecoveryStrategyFallback:
		return rm.fallbackRedaction(originalPath, failedOutputPath, redactionManager, matches)
	case RecoveryStrategyPartial:
		return rm.partialRedaction(originalPath, failedOutputPath, redactionManager, matches, redactionStrategy)
	case RecoveryStrategyCopy:
		return rm.copyOriginal(originalPath, failedOutputPath)
	case RecoveryStrategySkip:
		return rm.skipFile(originalPath, failedOutputPath)
	default:
		return nil, fmt.Errorf("unknown recovery strategy: %v", strategy)
	}
}

// reprocessDocument attempts to reprocess the document with the same parameters
func (rm *RecoveryManager) reprocessDocument(originalPath, outputPath string, redactionManager *redactors.RedactionManager, matches []detector.Match, strategy redactors.RedactionStrategy) (*RecoveryResult, error) {
	// Remove failed output file if it exists
	if _, err := os.Stat(outputPath); err == nil {
		os.Remove(outputPath)
	}

	// Attempt redaction again
	redactionResult, err := redactionManager.RedactFile(originalPath, outputPath, matches, strategy)
	if err != nil {
		return nil, fmt.Errorf("reprocessing failed: %w", err)
	}

	if !redactionResult.Success {
		return nil, fmt.Errorf("reprocessing unsuccessful")
	}

	return &RecoveryResult{
		Success:           true,
		RecoveredFilePath: outputPath,
		Metadata: map[string]interface{}{
			"redaction_result": redactionResult,
		},
	}, nil
}

// fallbackRedaction attempts redaction with a simpler strategy
func (rm *RecoveryManager) fallbackRedaction(originalPath, outputPath string, redactionManager *redactors.RedactionManager, matches []detector.Match) (*RecoveryResult, error) {
	// Remove failed output file if it exists
	if _, err := os.Stat(outputPath); err == nil {
		os.Remove(outputPath)
	}

	// Try with simple redaction strategy
	redactionResult, err := redactionManager.RedactFile(originalPath, outputPath, matches, redactors.RedactionSimple)
	if err != nil {
		return nil, fmt.Errorf("fallback redaction failed: %w", err)
	}

	if !redactionResult.Success {
		return nil, fmt.Errorf("fallback redaction unsuccessful")
	}

	return &RecoveryResult{
		Success:           true,
		RecoveredFilePath: outputPath,
		Metadata: map[string]interface{}{
			"fallback_strategy": "simple",
			"redaction_result":  redactionResult,
		},
	}, nil
}

// partialRedaction attempts redaction with a subset of matches
func (rm *RecoveryManager) partialRedaction(originalPath, outputPath string, redactionManager *redactors.RedactionManager, matches []detector.Match, strategy redactors.RedactionStrategy) (*RecoveryResult, error) {
	// Remove failed output file if it exists
	if _, err := os.Stat(outputPath); err == nil {
		os.Remove(outputPath)
	}

	// Try with high-confidence matches only
	highConfidenceMatches := []detector.Match{}
	for _, match := range matches {
		if match.Confidence >= 0.8 {
			highConfidenceMatches = append(highConfidenceMatches, match)
		}
	}

	if len(highConfidenceMatches) == 0 {
		return nil, fmt.Errorf("no high-confidence matches for partial redaction")
	}

	redactionResult, err := redactionManager.RedactFile(originalPath, outputPath, highConfidenceMatches, strategy)
	if err != nil {
		return nil, fmt.Errorf("partial redaction failed: %w", err)
	}

	if !redactionResult.Success {
		return nil, fmt.Errorf("partial redaction unsuccessful")
	}

	return &RecoveryResult{
		Success:           true,
		RecoveredFilePath: outputPath,
		Metadata: map[string]interface{}{
			"partial_matches":  len(highConfidenceMatches),
			"original_matches": len(matches),
			"redaction_result": redactionResult,
		},
	}, nil
}

// copyOriginal copies the original file as a fallback
func (rm *RecoveryManager) copyOriginal(originalPath, outputPath string) (*RecoveryResult, error) {
	// Remove failed output file if it exists
	if _, err := os.Stat(outputPath); err == nil {
		os.Remove(outputPath)
	}

	// Copy original file
	originalContent, err := os.ReadFile(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read original file: %w", err)
	}

	err = os.WriteFile(outputPath, originalContent, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to copy original file: %w", err)
	}

	return &RecoveryResult{
		Success:           true,
		RecoveredFilePath: outputPath,
		Metadata: map[string]interface{}{
			"recovery_type": "original_copy",
			"warning":       "File was copied without redaction due to processing failure",
		},
	}, nil
}

// skipFile skips the file and creates a placeholder
func (rm *RecoveryManager) skipFile(originalPath, outputPath string) (*RecoveryResult, error) {
	// Create a placeholder file indicating the file was skipped
	skipMessage := fmt.Sprintf("File skipped due to processing failure: %s\nOriginal file: %s\nTimestamp: %s\n",
		filepath.Base(originalPath),
		originalPath,
		time.Now().Format(time.RFC3339),
	)

	err := os.WriteFile(outputPath, []byte(skipMessage), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create skip placeholder: %w", err)
	}

	return &RecoveryResult{
		Success:           true,
		RecoveredFilePath: outputPath,
		Metadata: map[string]interface{}{
			"recovery_type": "skip",
			"warning":       "File was skipped due to processing failure",
		},
	}, nil
}

// createBackup creates a backup of the original file
func (rm *RecoveryManager) createBackup(originalPath string) (string, error) {
	backupDir := rm.config.BackupDirectory
	if backupDir == "" {
		backupDir = filepath.Dir(originalPath)
	}

	// Ensure backup directory exists with secure permissions (owner only)
	err := os.MkdirAll(backupDir, 0700)
	if err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup filename with timestamp
	originalName := filepath.Base(originalPath)
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("%s.backup_%s", originalName, timestamp)
	backupPath := filepath.Join(backupDir, backupName)

	// Copy original file to backup location
	originalContent, err := os.ReadFile(originalPath)
	if err != nil {
		return "", fmt.Errorf("failed to read original file: %w", err)
	}

	err = os.WriteFile(backupPath, originalContent, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}

	return backupPath, nil
}

// updateRecoveryTime updates the average recovery time
func (rm *RecoveryManager) updateRecoveryTime(recoveryTime time.Duration) {
	rm.stats.TotalRecoveryTime += recoveryTime
	if rm.stats.TotalRecoveryAttempts > 0 {
		rm.stats.AverageRecoveryTime = time.Duration(int64(rm.stats.TotalRecoveryTime) / rm.stats.TotalRecoveryAttempts)
	}
}

// GetStats returns current recovery statistics
func (rm *RecoveryManager) GetStats() *RecoveryStats {
	// Return a copy to avoid race conditions
	stats := &RecoveryStats{
		TotalRecoveryAttempts:  rm.stats.TotalRecoveryAttempts,
		SuccessfulRecoveries:   rm.stats.SuccessfulRecoveries,
		FailedRecoveries:       rm.stats.FailedRecoveries,
		TotalRecoveryTime:      rm.stats.TotalRecoveryTime,
		AverageRecoveryTime:    rm.stats.AverageRecoveryTime,
		RecoveryStrategiesUsed: make(map[RecoveryStrategy]int64),
	}

	// Copy strategy usage stats
	for strategy, count := range rm.stats.RecoveryStrategiesUsed {
		stats.RecoveryStrategiesUsed[strategy] = count
	}

	return stats
}

// logEvent logs an event if observer is available
func (rm *RecoveryManager) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if rm.observer != nil {
		rm.observer.StartTiming("recovery_manager", operation, "")(success, metadata)
	}
}

// GetComponentName returns the component name for observability
func (rm *RecoveryManager) GetComponentName() string {
	return "recovery_manager"
}
