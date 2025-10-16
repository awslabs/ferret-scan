// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// RedactionManager coordinates all redaction operations and manages multiple redactors
type RedactionManager struct {
	// redactors maps file extensions to their corresponding redactors
	redactors map[string]Redactor

	// observer handles observability and metrics
	observer *observability.StandardObserver

	// outputManager handles file system operations
	outputManager *OutputStructureManager

	// auditLogManager handles redaction audit log management
	auditLogManager *RedactionAuditLogManager

	// config contains redaction policies and settings
	config *RedactionManagerConfig

	// mutex protects concurrent access to redactors map
	mu sync.RWMutex

	// stats tracks redaction statistics
	stats *RedactionStats
}

// RedactionManagerConfig contains configuration for the redaction manager
type RedactionManagerConfig struct {
	// DefaultStrategy is the default redaction strategy to use
	DefaultStrategy RedactionStrategy

	// MaxConcurrentRedactions limits the number of concurrent redaction operations
	MaxConcurrentRedactions int

	// EnableBatchProcessing enables batch processing capabilities
	EnableBatchProcessing bool

	// BatchSize is the maximum number of files to process in a single batch
	BatchSize int

	// RetryAttempts is the number of retry attempts for failed redactions
	RetryAttempts int

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration

	// EnableAuditTrail enables audit trail logging
	EnableAuditTrail bool

	// AuditLogPath is the path to the audit log file
	AuditLogPath string

	// FailureHandling defines how to handle redaction failures
	FailureHandling FailureHandlingMode
}

// FailureHandlingMode defines how to handle redaction failures
type FailureHandlingMode int

const (
	// FailureHandlingStrict stops processing on any failure
	FailureHandlingStrict FailureHandlingMode = iota
	// FailureHandlingContinue continues processing despite failures
	FailureHandlingContinue
	// FailureHandlingGraceful attempts graceful degradation
	FailureHandlingGraceful
)

// String returns the string representation of the failure handling mode
func (fhm FailureHandlingMode) String() string {
	switch fhm {
	case FailureHandlingStrict:
		return "strict"
	case FailureHandlingContinue:
		return "continue"
	case FailureHandlingGraceful:
		return "graceful"
	default:
		return "unknown"
	}
}

// RedactionStats tracks statistics for redaction operations
type RedactionStats struct {
	mu sync.RWMutex

	// TotalFiles is the total number of files processed
	TotalFiles int64

	// SuccessfulRedactions is the number of successful redactions
	SuccessfulRedactions int64

	// FailedRedactions is the number of failed redactions
	FailedRedactions int64

	// TotalMatches is the total number of matches found
	TotalMatches int64

	// TotalRedactions is the total number of redactions applied
	TotalRedactions int64

	// ProcessingTime is the total time spent on redaction operations
	ProcessingTime time.Duration

	// RedactorStats tracks statistics per redactor type
	RedactorStats map[string]*RedactorStats

	// StartTime is when the redaction manager was created
	StartTime time.Time
}

// RedactorStats tracks statistics for a specific redactor
type RedactorStats struct {
	FilesProcessed  int64
	SuccessfulCount int64
	FailedCount     int64
	TotalMatches    int64
	TotalRedactions int64
	ProcessingTime  time.Duration
	AverageFileSize int64
	LastProcessedAt time.Time
}

// BatchRedactionRequest represents a batch redaction request
type BatchRedactionRequest struct {
	// Files is the list of files to redact
	Files []FileRedactionRequest

	// Strategy is the redaction strategy to use for all files
	Strategy RedactionStrategy

	// OutputDirectory is the base output directory
	OutputDirectory string

	// Metadata contains additional metadata for the batch
	Metadata map[string]interface{}
}

// FileRedactionRequest represents a single file redaction request
type FileRedactionRequest struct {
	// InputPath is the path to the input file
	InputPath string

	// OutputPath is the path for the redacted output file
	OutputPath string

	// Matches are the sensitive data matches to redact
	Matches []detector.Match

	// Strategy is the redaction strategy (overrides batch strategy if set)
	Strategy *RedactionStrategy

	// Metadata contains additional metadata for this file
	Metadata map[string]interface{}
}

// BatchRedactionResult represents the result of a batch redaction operation
type BatchRedactionResult struct {
	// Success indicates if the entire batch was successful
	Success bool

	// Results contains the results for each file
	Results []FileRedactionResult

	// TotalFiles is the total number of files in the batch
	TotalFiles int

	// SuccessfulFiles is the number of successfully processed files
	SuccessfulFiles int

	// FailedFiles is the number of failed files
	FailedFiles int

	// TotalProcessingTime is the total time for the batch
	TotalProcessingTime time.Duration

	// Errors contains any batch-level errors
	Errors []error

	// Metadata contains additional result metadata
	Metadata map[string]interface{}
}

// FileRedactionResult represents the result of a single file redaction
type FileRedactionResult struct {
	// InputPath is the path to the input file
	InputPath string

	// Result is the redaction result (nil if failed)
	Result *RedactionResult

	// Error is the error if redaction failed
	Error error

	// RedactorUsed is the name of the redactor that processed this file
	RedactorUsed string

	// ProcessingTime is the time taken to process this file
	ProcessingTime time.Duration

	// RetryAttempts is the number of retry attempts made
	RetryAttempts int
}

// NewRedactionManager creates a new RedactionManager with default configuration
func NewRedactionManager(outputManager *OutputStructureManager, observer *observability.StandardObserver) *RedactionManager {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	config := &RedactionManagerConfig{
		DefaultStrategy:         RedactionFormatPreserving,
		MaxConcurrentRedactions: 4,
		EnableBatchProcessing:   true,
		BatchSize:               100,
		RetryAttempts:           3,
		RetryDelay:              time.Second * 2,
		EnableAuditTrail:        true,
		FailureHandling:         FailureHandlingGraceful,
	}

	stats := &RedactionStats{
		RedactorStats: make(map[string]*RedactorStats),
		StartTime:     time.Now(),
	}

	// Create audit log manager
	auditLogManager := NewRedactionAuditLogManager("v1.0.0", outputManager.baseOutputDir)

	return &RedactionManager{
		redactors:       make(map[string]Redactor),
		observer:        observer,
		outputManager:   outputManager,
		auditLogManager: auditLogManager,
		config:          config,
		stats:           stats,
	}
}

// NewRedactionManagerWithConfig creates a new RedactionManager with custom configuration
func NewRedactionManagerWithConfig(outputManager *OutputStructureManager, observer *observability.StandardObserver, config *RedactionManagerConfig) *RedactionManager {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	if config == nil {
		config = &RedactionManagerConfig{
			DefaultStrategy:         RedactionFormatPreserving,
			MaxConcurrentRedactions: 4,
			EnableBatchProcessing:   true,
			BatchSize:               100,
			RetryAttempts:           3,
			RetryDelay:              time.Second * 2,
			EnableAuditTrail:        true,
			FailureHandling:         FailureHandlingGraceful,
		}
	}

	stats := &RedactionStats{
		RedactorStats: make(map[string]*RedactorStats),
		StartTime:     time.Now(),
	}

	// Create audit log manager
	auditLogManager := NewRedactionAuditLogManager("v1.0.0", outputManager.baseOutputDir)

	return &RedactionManager{
		redactors:       make(map[string]Redactor),
		observer:        observer,
		outputManager:   outputManager,
		auditLogManager: auditLogManager,
		config:          config,
		stats:           stats,
	}
}

// RegisterRedactor registers a redactor for specific file types
func (rm *RedactionManager) RegisterRedactor(redactor Redactor) error {
	if redactor == nil {
		return fmt.Errorf("redactor cannot be nil")
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	supportedTypes := redactor.GetSupportedTypes()
	if len(supportedTypes) == 0 {
		return fmt.Errorf("redactor must support at least one file type")
	}

	// Register redactor for each supported type
	for _, fileType := range supportedTypes {
		// Normalize file type (ensure it starts with a dot for extensions)
		normalizedType := strings.ToLower(fileType)
		if !strings.HasPrefix(normalizedType, ".") {
			normalizedType = "." + normalizedType
		}

		rm.redactors[normalizedType] = redactor
	}

	// Initialize stats for this redactor
	rm.stats.mu.Lock()
	rm.stats.RedactorStats[redactor.GetName()] = &RedactorStats{
		LastProcessedAt: time.Now(),
	}
	rm.stats.mu.Unlock()

	rm.logEvent("redactor_registered", true, map[string]interface{}{
		"redactor_name":   redactor.GetName(),
		"supported_types": supportedTypes,
		"total_redactors": len(rm.redactors),
	})

	return nil
}

// UnregisterRedactor removes a redactor from the manager
func (rm *RedactionManager) UnregisterRedactor(redactorName string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Find and remove all registrations for this redactor
	removedTypes := []string{}
	for fileType, redactor := range rm.redactors {
		if redactor.GetName() == redactorName {
			delete(rm.redactors, fileType)
			removedTypes = append(removedTypes, fileType)
		}
	}

	if len(removedTypes) == 0 {
		return fmt.Errorf("redactor %s not found", redactorName)
	}

	// Remove stats for this redactor
	rm.stats.mu.Lock()
	delete(rm.stats.RedactorStats, redactorName)
	rm.stats.mu.Unlock()

	rm.logEvent("redactor_unregistered", true, map[string]interface{}{
		"redactor_name":   redactorName,
		"removed_types":   removedTypes,
		"total_redactors": len(rm.redactors),
	})

	return nil
}

// GetRedactorForFile returns the appropriate redactor for a given file
func (rm *RedactionManager) GetRedactorForFile(filePath string) (Redactor, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return nil, fmt.Errorf("file has no extension: %s", filePath)
	}

	redactor, exists := rm.redactors[ext]
	if !exists {
		return nil, fmt.Errorf("no redactor registered for file type: %s", ext)
	}

	return redactor, nil
}

// GetRegisteredRedactors returns a list of all registered redactors
func (rm *RedactionManager) GetRegisteredRedactors() map[string][]string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	redactorTypes := make(map[string][]string)
	for fileType, redactor := range rm.redactors {
		redactorName := redactor.GetName()
		redactorTypes[redactorName] = append(redactorTypes[redactorName], fileType)
	}

	return redactorTypes
}

// RedactFile redacts a single file using the appropriate redactor
func (rm *RedactionManager) RedactFile(inputPath, outputPath string, matches []detector.Match, strategy RedactionStrategy) (*RedactionResult, error) {
	startTime := time.Now()

	// Get appropriate redactor
	redactor, err := rm.GetRedactorForFile(inputPath)
	if err != nil {
		rm.updateStats(func(stats *RedactionStats) {
			stats.TotalFiles++
			stats.FailedRedactions++
		})
		return nil, fmt.Errorf("failed to get redactor for file %s: %w", inputPath, err)
	}

	// Perform redaction with retry logic
	var result *RedactionResult
	var lastErr error
	for attempt := 0; attempt <= rm.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			rm.logEvent("redaction_retry", false, map[string]interface{}{
				"file_path": inputPath,
				"attempt":   attempt,
				"error":     lastErr.Error(),
			})
			time.Sleep(rm.config.RetryDelay)
		}

		result, lastErr = redactor.RedactDocument(inputPath, outputPath, matches, strategy)
		if lastErr == nil {
			break
		}
	}

	processingTime := time.Since(startTime)

	// Update statistics
	rm.updateStats(func(stats *RedactionStats) {
		stats.TotalFiles++
		stats.ProcessingTime += processingTime
		stats.TotalMatches += int64(len(matches))

		redactorName := redactor.GetName()
		redactorStats, exists := stats.RedactorStats[redactorName]
		if !exists {
			redactorStats = &RedactorStats{}
			stats.RedactorStats[redactorName] = redactorStats
		}

		redactorStats.FilesProcessed++
		redactorStats.ProcessingTime += processingTime
		redactorStats.TotalMatches += int64(len(matches))
		redactorStats.LastProcessedAt = time.Now()

		if lastErr == nil {
			stats.SuccessfulRedactions++
			redactorStats.SuccessfulCount++
			if result != nil {
				stats.TotalRedactions += int64(len(result.RedactionMap))
				redactorStats.TotalRedactions += int64(len(result.RedactionMap))
			}
		} else {
			stats.FailedRedactions++
			redactorStats.FailedCount++
		}
	})

	if lastErr != nil {
		rm.logEvent("redaction_failed", false, map[string]interface{}{
			"file_path":       inputPath,
			"redactor_name":   redactor.GetName(),
			"retry_attempts":  rm.config.RetryAttempts,
			"error":           lastErr.Error(),
			"processing_time": processingTime,
		})
		return nil, fmt.Errorf("redaction failed after %d attempts: %w", rm.config.RetryAttempts+1, lastErr)
	}

	rm.logEvent("redaction_successful", true, map[string]interface{}{
		"file_path":        inputPath,
		"output_path":      outputPath,
		"redactor_name":    redactor.GetName(),
		"matches_count":    len(matches),
		"redactions_count": len(result.RedactionMap),
		"processing_time":  processingTime,
		"strategy":         strategy.String(),
	})

	return result, nil
}

// RedactBatch processes multiple files in a batch operation
func (rm *RedactionManager) RedactBatch(request *BatchRedactionRequest) (*BatchRedactionResult, error) {
	if !rm.config.EnableBatchProcessing {
		return nil, fmt.Errorf("batch processing is disabled")
	}

	if request == nil || len(request.Files) == 0 {
		return nil, fmt.Errorf("batch request is empty")
	}

	startTime := time.Now()

	rm.logEvent("batch_redaction_started", true, map[string]interface{}{
		"total_files":      len(request.Files),
		"strategy":         request.Strategy.String(),
		"output_directory": request.OutputDirectory,
		"batch_size":       rm.config.BatchSize,
	})

	// Process files in batches
	results := make([]FileRedactionResult, len(request.Files))
	successCount := 0
	failCount := 0
	batchErrors := []error{}

	// Create semaphore for concurrent processing
	semaphore := make(chan struct{}, rm.config.MaxConcurrentRedactions)
	var wg sync.WaitGroup
	var resultsMu sync.Mutex

	for i, fileRequest := range request.Files {
		wg.Add(1)
		go func(index int, req FileRedactionRequest) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Process single file
			fileResult := rm.processSingleFileInBatch(req, request.Strategy)

			// Update results
			resultsMu.Lock()
			results[index] = fileResult
			if fileResult.Error == nil {
				successCount++
			} else {
				failCount++
				// Handle failure based on configuration
				if rm.config.FailureHandling == FailureHandlingStrict {
					batchErrors = append(batchErrors, fmt.Errorf("file %s failed: %w", req.InputPath, fileResult.Error))
				}
			}
			resultsMu.Unlock()
		}(i, fileRequest)
	}

	// Wait for all files to complete
	wg.Wait()

	totalProcessingTime := time.Since(startTime)

	// Update overall statistics based on batch results
	rm.updateStats(func(stats *RedactionStats) {
		for _, fileResult := range results {
			stats.TotalFiles++
			if fileResult.Error == nil {
				stats.SuccessfulRedactions++
				if fileResult.Result != nil {
					stats.TotalRedactions += int64(len(fileResult.Result.RedactionMap))
				}
			} else {
				stats.FailedRedactions++
			}
			stats.ProcessingTime += fileResult.ProcessingTime
		}
	})

	// Check if batch should be considered successful
	batchSuccess := true
	switch rm.config.FailureHandling {
	case FailureHandlingStrict:
		batchSuccess = failCount == 0
	case FailureHandlingContinue:
		batchSuccess = successCount > 0
	case FailureHandlingGraceful:
		batchSuccess = float64(successCount)/float64(len(request.Files)) >= 0.5 // At least 50% success
	}

	result := &BatchRedactionResult{
		Success:             batchSuccess,
		Results:             results,
		TotalFiles:          len(request.Files),
		SuccessfulFiles:     successCount,
		FailedFiles:         failCount,
		TotalProcessingTime: totalProcessingTime,
		Errors:              batchErrors,
		Metadata:            request.Metadata,
	}

	rm.logEvent("batch_redaction_completed", batchSuccess, map[string]interface{}{
		"total_files":           len(request.Files),
		"successful_files":      successCount,
		"failed_files":          failCount,
		"success_rate":          float64(successCount) / float64(len(request.Files)),
		"total_processing_time": totalProcessingTime,
		"batch_success":         batchSuccess,
		"failure_handling":      rm.config.FailureHandling.String(),
	})

	return result, nil
}

// processSingleFileInBatch processes a single file within a batch operation
func (rm *RedactionManager) processSingleFileInBatch(request FileRedactionRequest, defaultStrategy RedactionStrategy) FileRedactionResult {
	startTime := time.Now()

	// Determine strategy to use
	strategy := defaultStrategy
	if request.Strategy != nil {
		strategy = *request.Strategy
	}

	// Get redactor for file
	redactor, err := rm.GetRedactorForFile(request.InputPath)
	if err != nil {
		return FileRedactionResult{
			InputPath:      request.InputPath,
			Result:         nil,
			Error:          fmt.Errorf("failed to get redactor: %w", err),
			RedactorUsed:   "none",
			ProcessingTime: time.Since(startTime),
			RetryAttempts:  0,
		}
	}

	// Perform redaction with retry logic
	var result *RedactionResult
	var lastErr error
	retryAttempts := 0

	for attempt := 0; attempt <= rm.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			retryAttempts++
			time.Sleep(rm.config.RetryDelay)
		}

		result, lastErr = redactor.RedactDocument(request.InputPath, request.OutputPath, request.Matches, strategy)
		if lastErr == nil {
			break
		}
	}

	// Update redactor-specific statistics
	rm.updateStats(func(stats *RedactionStats) {
		redactorName := redactor.GetName()
		redactorStats, exists := stats.RedactorStats[redactorName]
		if !exists {
			redactorStats = &RedactorStats{}
			stats.RedactorStats[redactorName] = redactorStats
		}

		redactorStats.FilesProcessed++
		redactorStats.ProcessingTime += time.Since(startTime)
		redactorStats.TotalMatches += int64(len(request.Matches))
		redactorStats.LastProcessedAt = time.Now()

		if lastErr == nil {
			redactorStats.SuccessfulCount++
			if result != nil {
				redactorStats.TotalRedactions += int64(len(result.RedactionMap))
			}
		} else {
			redactorStats.FailedCount++
		}

		// Also update total matches for the manager
		stats.TotalMatches += int64(len(request.Matches))
	})

	return FileRedactionResult{
		InputPath:      request.InputPath,
		Result:         result,
		Error:          lastErr,
		RedactorUsed:   redactor.GetName(),
		ProcessingTime: time.Since(startTime),
		RetryAttempts:  retryAttempts,
	}
}

// GetStats returns current redaction statistics
func (rm *RedactionManager) GetStats() *RedactionStats {
	rm.stats.mu.RLock()
	defer rm.stats.mu.RUnlock()

	// Create a copy of stats to avoid race conditions
	stats := &RedactionStats{
		TotalFiles:           rm.stats.TotalFiles,
		SuccessfulRedactions: rm.stats.SuccessfulRedactions,
		FailedRedactions:     rm.stats.FailedRedactions,
		TotalMatches:         rm.stats.TotalMatches,
		TotalRedactions:      rm.stats.TotalRedactions,
		ProcessingTime:       rm.stats.ProcessingTime,
		StartTime:            rm.stats.StartTime,
		RedactorStats:        make(map[string]*RedactorStats),
	}

	// Copy redactor stats
	for name, redactorStats := range rm.stats.RedactorStats {
		stats.RedactorStats[name] = &RedactorStats{
			FilesProcessed:  redactorStats.FilesProcessed,
			SuccessfulCount: redactorStats.SuccessfulCount,
			FailedCount:     redactorStats.FailedCount,
			TotalMatches:    redactorStats.TotalMatches,
			TotalRedactions: redactorStats.TotalRedactions,
			ProcessingTime:  redactorStats.ProcessingTime,
			AverageFileSize: redactorStats.AverageFileSize,
			LastProcessedAt: redactorStats.LastProcessedAt,
		}
	}

	return stats
}

// ResetStats resets all statistics
func (rm *RedactionManager) ResetStats() {
	rm.stats.mu.Lock()
	defer rm.stats.mu.Unlock()

	rm.stats.TotalFiles = 0
	rm.stats.SuccessfulRedactions = 0
	rm.stats.FailedRedactions = 0
	rm.stats.TotalMatches = 0
	rm.stats.TotalRedactions = 0
	rm.stats.ProcessingTime = 0
	rm.stats.StartTime = time.Now()

	// Reset redactor stats
	for name := range rm.stats.RedactorStats {
		rm.stats.RedactorStats[name] = &RedactorStats{
			LastProcessedAt: time.Now(),
		}
	}

	rm.logEvent("stats_reset", true, map[string]interface{}{
		"reset_time": time.Now(),
	})
}

// GetConfig returns the current configuration
func (rm *RedactionManager) GetConfig() *RedactionManagerConfig {
	// Return a copy to prevent external modification
	return &RedactionManagerConfig{
		DefaultStrategy:         rm.config.DefaultStrategy,
		MaxConcurrentRedactions: rm.config.MaxConcurrentRedactions,
		EnableBatchProcessing:   rm.config.EnableBatchProcessing,
		BatchSize:               rm.config.BatchSize,
		RetryAttempts:           rm.config.RetryAttempts,
		RetryDelay:              rm.config.RetryDelay,
		EnableAuditTrail:        rm.config.EnableAuditTrail,
		AuditLogPath:            rm.config.AuditLogPath,
		FailureHandling:         rm.config.FailureHandling,
	}
}

// UpdateConfig updates the manager configuration
func (rm *RedactionManager) UpdateConfig(config *RedactionManagerConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate configuration
	if config.MaxConcurrentRedactions <= 0 {
		return fmt.Errorf("MaxConcurrentRedactions must be positive")
	}
	if config.BatchSize <= 0 {
		return fmt.Errorf("BatchSize must be positive")
	}
	if config.RetryAttempts < 0 {
		return fmt.Errorf("RetryAttempts cannot be negative")
	}
	if config.RetryDelay < 0 {
		return fmt.Errorf("RetryDelay cannot be negative")
	}

	rm.config = &RedactionManagerConfig{
		DefaultStrategy:         config.DefaultStrategy,
		MaxConcurrentRedactions: config.MaxConcurrentRedactions,
		EnableBatchProcessing:   config.EnableBatchProcessing,
		BatchSize:               config.BatchSize,
		RetryAttempts:           config.RetryAttempts,
		RetryDelay:              config.RetryDelay,
		EnableAuditTrail:        config.EnableAuditTrail,
		AuditLogPath:            config.AuditLogPath,
		FailureHandling:         config.FailureHandling,
	}

	rm.logEvent("config_updated", true, map[string]interface{}{
		"default_strategy":          config.DefaultStrategy.String(),
		"max_concurrent_redactions": config.MaxConcurrentRedactions,
		"enable_batch_processing":   config.EnableBatchProcessing,
		"batch_size":                config.BatchSize,
		"retry_attempts":            config.RetryAttempts,
		"retry_delay":               config.RetryDelay,
		"enable_audit_trail":        config.EnableAuditTrail,
		"failure_handling":          config.FailureHandling.String(),
	})

	return nil
}

// updateStats safely updates statistics using a callback function
func (rm *RedactionManager) updateStats(updateFunc func(*RedactionStats)) {
	rm.stats.mu.Lock()
	defer rm.stats.mu.Unlock()
	updateFunc(rm.stats)
}

// logEvent logs an event if observer is available
func (rm *RedactionManager) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if rm.observer != nil {
		rm.observer.StartTiming("redaction_manager", operation, "")(success, metadata)
	}
}

// GetComponentName returns the component name for observability
func (rm *RedactionManager) GetComponentName() string {
	return "redaction_manager"
}

// Shutdown gracefully shuts down the redaction manager
func (rm *RedactionManager) Shutdown() error {
	rm.logEvent("shutdown_initiated", true, map[string]interface{}{
		"uptime":                time.Since(rm.stats.StartTime),
		"total_files_processed": rm.stats.TotalFiles,
	})

	// TODO: Implement graceful shutdown logic
	// - Wait for ongoing redactions to complete
	// - Close audit log files
	// - Clean up resources

	rm.logEvent("shutdown_completed", true, map[string]interface{}{
		"shutdown_time": time.Now(),
	})

	return nil
}

// GetOutputManager returns the output manager for use by external redactor registration
func (rm *RedactionManager) GetOutputManager() *OutputStructureManager {
	return rm.outputManager
}

// GetObserver returns the observer for use by external redactor registration
func (rm *RedactionManager) GetObserver() *observability.StandardObserver {
	return rm.observer
}

// AddRedactionResult adds a redaction result to the index manager
func (rm *RedactionManager) AddRedactionResult(originalPath, redactedPath string, result *RedactionResult) {
	if rm.auditLogManager != nil && result != nil {
		// Generate document ID
		documentID := fmt.Sprintf("doc_%d", time.Now().UnixNano())

		// Create audit log for this document
		_, err := rm.auditLogManager.CreateAuditLog(documentID, originalPath, redactedPath)
		if err != nil {
			rm.logEvent("index_creation_failed", false, map[string]interface{}{
				"error":       err.Error(),
				"document_id": documentID,
			})
			return
		}

		// Add each redaction to the index
		for i, redactionMapping := range result.RedactionMap {
			contentRedaction := ContentRedaction{
				ID:           fmt.Sprintf("%s_redaction_%d", documentID, i),
				TargetType:   "parent_document",
				DataType:     redactionMapping.DataType,
				RedactedText: redactionMapping.RedactedText,
				Strategy:     redactionMapping.Strategy,
				Confidence:   redactionMapping.Confidence / 100.0, // Convert to 0-1 range
				Timestamp:    time.Now(),
			}

			err := rm.auditLogManager.AddContentRedaction(documentID, contentRedaction)
			if err != nil {
				rm.logEvent("redaction_add_failed", false, map[string]interface{}{
					"error":       err.Error(),
					"document_id": documentID,
				})
			}
		}

		// Update statistics
		rm.updateStats(func(stats *RedactionStats) {
			stats.TotalRedactions += int64(len(result.RedactionMap))
			stats.SuccessfulRedactions++
		})

		rm.logEvent("redaction_result_added", true, map[string]interface{}{
			"original_path":   originalPath,
			"redacted_path":   redactedPath,
			"redaction_count": len(result.RedactionMap),
			"document_id":     documentID,
		})
	}
}

// ProcessMatches processes validation matches and performs redaction on the associated files
func (rm *RedactionManager) ProcessMatches(matches []detector.Match, filePaths []string) (*RedactionResults, error) {
	if len(matches) == 0 {
		return &RedactionResults{
			ProcessedFiles:  []ProcessedFile{},
			TotalRedactions: 0,
			ProcessingTime:  0,
			Errors:          []RedactionError{},
		}, nil
	}

	startTime := time.Now()

	// Group matches by file path
	matchesByFile := make(map[string][]detector.Match)
	for _, match := range matches {
		filePath := match.Filename
		matchesByFile[filePath] = append(matchesByFile[filePath], match)
	}

	// Process each file with its matches
	var processedFiles []ProcessedFile
	var allErrors []RedactionError
	totalRedactions := 0

	for filePath, fileMatches := range matchesByFile {
		// Create output path
		outputPath, err := rm.outputManager.CreateMirroredPath(filePath)
		if err != nil {
			allErrors = append(allErrors, RedactionError{
				Type:      ErrorFileSystem,
				Message:   fmt.Sprintf("failed to create output path: %v", err),
				FilePath:  filePath,
				Component: "redaction_manager",
			})
			continue
		}

		// Redact the file
		result, err := rm.RedactFile(filePath, outputPath, fileMatches, rm.config.DefaultStrategy)
		if err != nil {
			allErrors = append(allErrors, RedactionError{
				Type:      ErrorDocumentProcessing,
				Message:   fmt.Sprintf("redaction failed: %v", err),
				FilePath:  filePath,
				Component: "redaction_manager",
			})
			processedFiles = append(processedFiles, ProcessedFile{
				OriginalPath:   filePath,
				RedactedPath:   outputPath,
				RedactionCount: 0,
				ProcessingTime: 0,
				Success:        false,
				Error:          err,
			})
			continue
		}

		// Create redaction audit log for this file
		if rm.auditLogManager != nil {
			documentID := fmt.Sprintf("doc_%d", len(processedFiles))
			auditLog, err := rm.auditLogManager.CreateAuditLog(documentID, filePath, outputPath)
			if err == nil {
				// Add content redactions to the audit log
				for i, redactionMapping := range result.RedactionMap {
					contentRedaction := ContentRedaction{
						ID:           fmt.Sprintf("%s_redaction_%d", documentID, i),
						TargetType:   "parent_document",
						DataType:     redactionMapping.DataType,
						RedactedText: redactionMapping.RedactedText,
						Strategy:     redactionMapping.Strategy,
						Confidence:   redactionMapping.Confidence,
						Timestamp:    time.Now(),
					}
					auditLog.AddContentRedaction(contentRedaction)
				}

				// Calculate and store hash of the redacted file
				if redactedContent, err := os.ReadFile(outputPath); err == nil {
					redactedHash := GenerateDocumentHash(redactedContent)
					auditLog.SetRedactedFileHash(redactedHash)
				}
			}
		}

		// Record successful processing
		processedFiles = append(processedFiles, ProcessedFile{
			OriginalPath:   filePath,
			RedactedPath:   outputPath,
			RedactionCount: len(result.RedactionMap),
			ProcessingTime: result.ProcessingTime,
			Success:        true,
			Error:          nil,
		})

		totalRedactions += len(result.RedactionMap)
	}

	processingTime := time.Since(startTime)

	return &RedactionResults{
		ProcessedFiles:  processedFiles,
		TotalRedactions: totalRedactions,
		ProcessingTime:  processingTime,
		Errors:          allErrors,
	}, nil
}

// ExportAuditLog exports the redaction audit log to the specified file path
func (rm *RedactionManager) ExportAuditLog(auditLogPath string) error {
	if rm.auditLogManager == nil {
		return fmt.Errorf("audit log manager not initialized")
	}

	// Export all audit logs to JSON
	data, err := rm.auditLogManager.ExportAllAuditLogs()
	if err != nil {
		return fmt.Errorf("failed to export audit logs: %w", err)
	}

	// Write to file with secure permissions (owner read/write only)
	if err := os.WriteFile(auditLogPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write audit log file: %w", err)
	}

	return nil
}
