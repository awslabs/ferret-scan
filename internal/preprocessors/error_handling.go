// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"context"
	"fmt"
	"strings"
)

// ErrorType represents different types of processing errors
type ErrorType string

const (
	// File-related errors
	ErrorTypeFileAccess    ErrorType = "file_access"
	ErrorTypeFileSize      ErrorType = "file_size"
	ErrorTypeFileCorrupted ErrorType = "file_corrupted"

	// Format-related errors
	ErrorTypeUnsupportedFormat ErrorType = "unsupported_format"
	ErrorTypeInvalidFormat     ErrorType = "invalid_format"
	ErrorTypeFormatCorrupted   ErrorType = "format_corrupted"

	// Processing-related errors
	ErrorTypeTimeout          ErrorType = "timeout"
	ErrorTypeMemoryLimit      ErrorType = "memory_limit"
	ErrorTypeParsingFailed    ErrorType = "parsing_failed"
	ErrorTypeExtractionFailed ErrorType = "extraction_failed"

	// Context-related errors
	ErrorTypeCancelled ErrorType = "cancelled"

	// Unknown errors
	ErrorTypeUnknown ErrorType = "unknown"
)

// MediaProcessingError represents a comprehensive error during media processing
type MediaProcessingError struct {
	FilePath    string
	FileType    string
	ErrorType   ErrorType
	Message     string
	Cause       error
	Recoverable bool
	Context     map[string]interface{}
}

// Error implements the error interface
func (mpe *MediaProcessingError) Error() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("media processing failed for %s", mpe.FilePath))

	if mpe.FileType != "" {
		parts = append(parts, fmt.Sprintf("type=%s", mpe.FileType))
	}

	parts = append(parts, fmt.Sprintf("error=%s", mpe.ErrorType))

	if mpe.Message != "" {
		parts = append(parts, fmt.Sprintf("message=%s", mpe.Message))
	}

	if mpe.Cause != nil {
		parts = append(parts, fmt.Sprintf("cause=%v", mpe.Cause))
	}

	return strings.Join(parts, " ")
}

// Unwrap returns the underlying error
func (mpe *MediaProcessingError) Unwrap() error {
	return mpe.Cause
}

// IsRecoverable returns whether the error is recoverable
func (mpe *MediaProcessingError) IsRecoverable() bool {
	return mpe.Recoverable
}

// GetErrorType returns the error type
func (mpe *MediaProcessingError) GetErrorType() ErrorType {
	return mpe.ErrorType
}

// GetContext returns the error context
func (mpe *MediaProcessingError) GetContext() map[string]interface{} {
	return mpe.Context
}

// NewMediaProcessingError creates a new media processing error
func NewMediaProcessingError(filePath, fileType string, errorType ErrorType, message string, cause error) *MediaProcessingError {
	return &MediaProcessingError{
		FilePath:    filePath,
		FileType:    fileType,
		ErrorType:   errorType,
		Message:     message,
		Cause:       cause,
		Recoverable: isRecoverableError(errorType),
		Context:     make(map[string]interface{}),
	}
}

// WithContext adds context to the error
func (mpe *MediaProcessingError) WithContext(key string, value interface{}) *MediaProcessingError {
	mpe.Context[key] = value
	return mpe
}

// isRecoverableError determines if an error type is recoverable
func isRecoverableError(errorType ErrorType) bool {
	switch errorType {
	case ErrorTypeFileAccess, ErrorTypeTimeout, ErrorTypeCancelled:
		return true
	case ErrorTypeFileSize, ErrorTypeUnsupportedFormat, ErrorTypeMemoryLimit:
		return false
	case ErrorTypeFileCorrupted, ErrorTypeInvalidFormat, ErrorTypeFormatCorrupted:
		return false
	case ErrorTypeParsingFailed, ErrorTypeExtractionFailed:
		return true // Might work with different approach
	default:
		return false
	}
}

// ErrorClassifier classifies errors into appropriate types
type ErrorClassifier struct{}

// NewErrorClassifier creates a new error classifier
func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

// ClassifyError classifies an error into an appropriate ErrorType
func (ec *ErrorClassifier) ClassifyError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	errStr := strings.ToLower(err.Error())

	// Context errors
	if err == context.DeadlineExceeded {
		return ErrorTypeTimeout
	}
	if err == context.Canceled {
		return ErrorTypeCancelled
	}

	// File access errors
	if strings.Contains(errStr, "no such file") || strings.Contains(errStr, "permission denied") {
		return ErrorTypeFileAccess
	}

	// File size errors
	if strings.Contains(errStr, "file too large") || strings.Contains(errStr, "size limit") {
		return ErrorTypeFileSize
	}

	// Memory errors
	if strings.Contains(errStr, "memory limit") || strings.Contains(errStr, "out of memory") {
		return ErrorTypeMemoryLimit
	}

	// Format errors
	if strings.Contains(errStr, "unsupported format") || strings.Contains(errStr, "unsupported") {
		return ErrorTypeUnsupportedFormat
	}
	if strings.Contains(errStr, "invalid format") || strings.Contains(errStr, "not a valid") {
		return ErrorTypeInvalidFormat
	}
	if strings.Contains(errStr, "corrupted") || strings.Contains(errStr, "malformed") {
		return ErrorTypeFormatCorrupted
	}

	// Parsing errors
	if strings.Contains(errStr, "failed to parse") || strings.Contains(errStr, "parsing failed") {
		return ErrorTypeParsingFailed
	}

	// Extraction errors
	if strings.Contains(errStr, "failed to extract") || strings.Contains(errStr, "extraction failed") {
		return ErrorTypeExtractionFailed
	}

	return ErrorTypeUnknown
}

// GracefulDegradationHandler handles graceful degradation for different error types
type GracefulDegradationHandler struct {
	classifier *ErrorClassifier
}

// NewGracefulDegradationHandler creates a new graceful degradation handler
func NewGracefulDegradationHandler() *GracefulDegradationHandler {
	return &GracefulDegradationHandler{
		classifier: NewErrorClassifier(),
	}
}

// HandleError handles an error with graceful degradation
func (gdh *GracefulDegradationHandler) HandleError(filePath, fileType string, err error) *ProcessedContent {
	if err == nil {
		return nil
	}

	errorType := gdh.classifier.ClassifyError(err)

	// Create base processed content for failed processing
	content := &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      getFileName(filePath),
		ProcessorType: "metadata",
		Success:       false,
		Text:          "",
		Format:        fmt.Sprintf("%s_metadata", fileType),
		WordCount:     0,
		CharCount:     0,
		LineCount:     0,
	}

	// Create comprehensive error
	mediaErr := NewMediaProcessingError(filePath, fileType, errorType, err.Error(), err)

	// Add context based on error type
	switch errorType {
	case ErrorTypeFileSize:
		mediaErr.WithContext("suggestion", "File exceeds size limits for metadata extraction")
	case ErrorTypeUnsupportedFormat:
		mediaErr.WithContext("suggestion", "File format is not supported for metadata extraction")
	case ErrorTypeTimeout:
		mediaErr.WithContext("suggestion", "Processing took too long, try with a smaller file")
	case ErrorTypeMemoryLimit:
		mediaErr.WithContext("suggestion", "File requires too much memory for processing")
	case ErrorTypeFileCorrupted:
		mediaErr.WithContext("suggestion", "File appears to be corrupted or malformed")
	case ErrorTypeParsingFailed:
		mediaErr.WithContext("suggestion", "Metadata structure could not be parsed")
	case ErrorTypeExtractionFailed:
		mediaErr.WithContext("suggestion", "Metadata extraction encountered an error")
	}

	content.Error = mediaErr
	return content
}

// getFileName extracts filename from path
func getFileName(filePath string) string {
	parts := strings.Split(filePath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return filePath
}

// ErrorLogger provides structured logging for media processing errors
type ErrorLogger struct {
	logLevel LogLevel
}

// LogLevel represents different log levels
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// NewErrorLogger creates a new error logger
func NewErrorLogger(level LogLevel) *ErrorLogger {
	return &ErrorLogger{
		logLevel: level,
	}
}

// LogError logs a media processing error with appropriate level
func (el *ErrorLogger) LogError(err *MediaProcessingError) {
	level := el.getLogLevelForError(err)

	if level < el.logLevel {
		return
	}

	message := fmt.Sprintf("[%s] %s", el.getLevelString(level), err.Error())

	// Add context information
	if len(err.Context) > 0 {
		var contextParts []string
		for key, value := range err.Context {
			contextParts = append(contextParts, fmt.Sprintf("%s=%v", key, value))
		}
		message += fmt.Sprintf(" context=[%s]", strings.Join(contextParts, " "))
	}

	// In a real implementation, this would use a proper logging framework
	fmt.Printf("%s\n", message)
}

// getLogLevelForError determines appropriate log level for error type
func (el *ErrorLogger) getLogLevelForError(err *MediaProcessingError) LogLevel {
	switch err.ErrorType {
	case ErrorTypeFileAccess, ErrorTypeUnsupportedFormat:
		return LogLevelInfo
	case ErrorTypeFileSize, ErrorTypeTimeout:
		return LogLevelWarn
	case ErrorTypeFileCorrupted, ErrorTypeFormatCorrupted, ErrorTypeParsingFailed:
		return LogLevelError
	case ErrorTypeMemoryLimit, ErrorTypeExtractionFailed:
		return LogLevelError
	default:
		return LogLevelError
	}
}

// getLevelString returns string representation of log level
func (el *ErrorLogger) getLevelString(level LogLevel) string {
	switch level {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// RecoveryStrategy represents different recovery strategies
type RecoveryStrategy int

const (
	RecoveryStrategyNone RecoveryStrategy = iota
	RecoveryStrategyRetry
	RecoveryStrategyFallback
	RecoveryStrategySkip
)

// ErrorRecoveryManager manages error recovery strategies
type ErrorRecoveryManager struct {
	maxRetries int
	strategies map[ErrorType]RecoveryStrategy
}

// NewErrorRecoveryManager creates a new error recovery manager
func NewErrorRecoveryManager() *ErrorRecoveryManager {
	return &ErrorRecoveryManager{
		maxRetries: 3,
		strategies: map[ErrorType]RecoveryStrategy{
			ErrorTypeFileAccess:        RecoveryStrategyRetry,
			ErrorTypeTimeout:           RecoveryStrategyRetry,
			ErrorTypeCancelled:         RecoveryStrategySkip,
			ErrorTypeFileSize:          RecoveryStrategySkip,
			ErrorTypeUnsupportedFormat: RecoveryStrategySkip,
			ErrorTypeMemoryLimit:       RecoveryStrategySkip,
			ErrorTypeParsingFailed:     RecoveryStrategyFallback,
			ErrorTypeExtractionFailed:  RecoveryStrategyFallback,
			ErrorTypeFileCorrupted:     RecoveryStrategySkip,
			ErrorTypeFormatCorrupted:   RecoveryStrategySkip,
		},
	}
}

// GetRecoveryStrategy returns the recovery strategy for an error type
func (erm *ErrorRecoveryManager) GetRecoveryStrategy(errorType ErrorType) RecoveryStrategy {
	if strategy, exists := erm.strategies[errorType]; exists {
		return strategy
	}
	return RecoveryStrategyNone
}

// ShouldRetry determines if an error should trigger a retry
func (erm *ErrorRecoveryManager) ShouldRetry(errorType ErrorType, attemptCount int) bool {
	if attemptCount >= erm.maxRetries {
		return false
	}

	strategy := erm.GetRecoveryStrategy(errorType)
	return strategy == RecoveryStrategyRetry
}

// GetMaxRetries returns the maximum number of retries
func (erm *ErrorRecoveryManager) GetMaxRetries() int {
	return erm.maxRetries
}

// SetMaxRetries sets the maximum number of retries
func (erm *ErrorRecoveryManager) SetMaxRetries(maxRetries int) {
	erm.maxRetries = maxRetries
}
