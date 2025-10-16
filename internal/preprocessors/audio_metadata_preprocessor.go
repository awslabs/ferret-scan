// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
	audiolib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-audiolib"
)

// AudioMetadataPreprocessor extracts metadata from audio files
type AudioMetadataPreprocessor struct {
	name            string
	observer        *observability.StandardObserver
	resourceManager *MediaResourceManager
	errorHandler    *GracefulDegradationHandler
	errorLogger     *ErrorLogger
	recoveryManager *ErrorRecoveryManager
	sharedUtils     *SharedUtilities
	audioExtractor  *audiolib.AudioExtractor
}

// NewAudioMetadataPreprocessor creates a new audio metadata preprocessor
func NewAudioMetadataPreprocessor() *AudioMetadataPreprocessor {
	return &AudioMetadataPreprocessor{
		name:            "audio_metadata",
		resourceManager: NewMediaResourceManager(),
		errorHandler:    NewGracefulDegradationHandler(),
		errorLogger:     NewErrorLogger(LogLevelWarn),
		recoveryManager: NewErrorRecoveryManager(),
		sharedUtils:     NewSharedUtilities(),
		audioExtractor:  audiolib.NewAudioExtractor(),
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (amp *AudioMetadataPreprocessor) CanProcess(filePath string) bool {
	return amp.sharedUtils.ExtensionValidator.IsAudioFile(filePath)
}

// Process extracts metadata from audio files
func (amp *AudioMetadataPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	return amp.processAudioMetadataWithRetry(filePath, 0)
}

// processAudioMetadataWithRetry processes audio metadata with retry logic
func (amp *AudioMetadataPreprocessor) processAudioMetadataWithRetry(filePath string, attemptCount int) (*ProcessedContent, error) {
	// Validate file size before processing (using audio-specific limits)
	if err := amp.validateAudioFile(filePath); err != nil {
		content := amp.errorHandler.HandleError(filePath, "audio", err)
		// Fix the ProcessorType to match this specific preprocessor
		content.ProcessorType = "audio_metadata"
		if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
			amp.errorLogger.LogError(mediaErr)
		}
		return content, err
	}

	// Create processing context with timeout
	ctx, cancel := amp.resourceManager.CreateProcessingContext()
	defer cancel()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		err := NewMediaProcessingError(filePath, "audio", ErrorTypeCancelled, "processing cancelled", ctx.Err())
		content := amp.errorHandler.HandleError(filePath, "audio", err)
		// Fix the ProcessorType to match this specific preprocessor
		content.ProcessorType = "audio_metadata"
		amp.errorLogger.LogError(err)
		return content, err
	default:
	}

	// Extract audio metadata with enhanced error handling
	audioMeta, err := amp.extractAudioMetadataWithFallback(ctx, filePath)
	if err != nil {
		// Classify and handle the error
		errorType := amp.classifyAudioError(err)
		mediaErr := NewMediaProcessingError(filePath, "audio", errorType, err.Error(), err)

		// Add audio-specific context
		amp.addAudioErrorContext(mediaErr, filePath)

		content := amp.errorHandler.HandleError(filePath, "audio", mediaErr)
		// Fix the ProcessorType to match this specific preprocessor
		content.ProcessorType = "audio_metadata"
		amp.errorLogger.LogError(mediaErr)

		// Check if we should retry
		if amp.recoveryManager.ShouldRetry(errorType, attemptCount) {
			// Log retry attempt
			if amp.observer != nil && amp.observer.DebugObserver != nil {
				amp.observer.DebugObserver.LogDetail("audio_metadata_preprocessor",
					fmt.Sprintf("Retrying audio metadata extraction for %s (attempt %d)", filePath, attemptCount+1))
			}

			// Add exponential backoff delay
			delay := time.Millisecond * 100 * time.Duration((attemptCount+1)*(attemptCount+1))
			time.Sleep(delay)
			return amp.processAudioMetadataWithRetry(filePath, attemptCount+1)
		}

		return content, mediaErr
	}

	// Log successful processing with detailed information
	if amp.observer != nil && amp.observer.DebugObserver != nil {
		amp.logSuccessfulProcessing(filePath, audioMeta)
	}

	// Convert audio metadata to text format for validation
	text := audioMeta.ToProcessedContent()

	// Build successful content using shared utilities
	return amp.sharedUtils.ContentBuilder.BuildSuccessContent(
		filePath,
		text,
		"audio_metadata",
		"audio_metadata",
		0, // Audio files don't have page count
	), nil
}

// GetName returns the name of this preprocessor
func (amp *AudioMetadataPreprocessor) GetName() string {
	return amp.name
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (amp *AudioMetadataPreprocessor) GetSupportedExtensions() []string {
	return amp.sharedUtils.ExtensionValidator.GetAudioExtensions()
}

// SetObserver sets the observability component
func (amp *AudioMetadataPreprocessor) SetObserver(observer *observability.StandardObserver) {
	amp.observer = observer
}

// validateAudioFile performs audio-specific validation
func (amp *AudioMetadataPreprocessor) validateAudioFile(filePath string) error {
	// Check file accessibility
	if _, err := filepath.Abs(filePath); err != nil {
		return NewMediaProcessingError(filePath, "audio", ErrorTypeFileAccess, "invalid file path", err)
	}

	// Validate file size (use audio-specific limits)
	if err := amp.resourceManager.ValidateFileSize(filePath, false); err != nil {
		return NewMediaProcessingError(filePath, "audio", ErrorTypeFileSize, "file size exceeds limits", err)
	}

	// Check if the audio extractor can process this file
	if !amp.audioExtractor.CanProcess(filePath) {
		ext := strings.ToLower(filepath.Ext(filePath))
		return NewMediaProcessingError(filePath, "audio", ErrorTypeUnsupportedFormat,
			fmt.Sprintf("unsupported audio format: %s", ext), nil)
	}

	return nil
}

// extractAudioMetadataWithFallback attempts to extract metadata with fallback strategies
func (amp *AudioMetadataPreprocessor) extractAudioMetadataWithFallback(ctx context.Context, filePath string) (*audiolib.AudioMetadata, error) {
	// Primary extraction attempt using context-aware extraction
	audioMeta, err := amp.audioExtractor.ExtractMetadataWithContext(ctx, filePath)
	if err == nil {
		return audioMeta, nil
	}

	// Analyze the error to determine if it's recoverable
	errStr := strings.ToLower(err.Error())

	// File access errors - not recoverable
	if strings.Contains(errStr, "no such file") || strings.Contains(errStr, "permission denied") {
		return nil, err
	}

	// File format errors - not recoverable
	if strings.Contains(errStr, "unsupported format") || strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "malformed") {
		return nil, err
	}

	// Timeout errors - potentially recoverable
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline exceeded") {
		return nil, err
	}

	// Check for "no metadata" cases - handle gracefully
	// Check if the error message indicates tag extraction failure
	if strings.Contains(errStr, "(tag_extraction)") ||
		strings.Contains(errStr, "failed to extract id3 tags") ||
		strings.Contains(errStr, "no metadata") || strings.Contains(errStr, "no tags") ||
		strings.Contains(errStr, "no id3v2 header found") || strings.Contains(errStr, "no id3v1 tag found") ||
		(strings.Contains(errStr, "seek") && strings.Contains(errStr, "invalid argument")) {
		// Create minimal metadata for files without tags or with seek issues (empty/invalid files)
		return amp.createMinimalAudioMetadata(filePath)
	}

	// For corrupted header cases, try to extract basic file information
	if strings.Contains(errStr, "corrupted header") || strings.Contains(errStr, "tag extraction") {
		// Attempt to create basic metadata
		if basicMeta, basicErr := amp.createMinimalAudioMetadata(filePath); basicErr == nil {
			return basicMeta, nil
		}
	}

	// For all other errors, return the original error
	return nil, err
}

// createMinimalAudioMetadata creates basic metadata for audio files without tags
func (amp *AudioMetadataPreprocessor) createMinimalAudioMetadata(filePath string) (*audiolib.AudioMetadata, error) {
	// Get file information
	fileInfo, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	// Create basic metadata structure
	audioMeta := &audiolib.AudioMetadata{
		Filename:   filepath.Base(filePath),
		Properties: make(map[string]string),
	}

	// Add basic file information
	ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(filePath), "."))
	audioMeta.Properties["FileExtension"] = ext
	audioMeta.Properties["FilePath"] = fileInfo

	// Determine MIME type based on extension
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".mp3":
		audioMeta.MimeType = "audio/mpeg"
	case ".flac":
		audioMeta.MimeType = "audio/flac"
	case ".wav":
		audioMeta.MimeType = "audio/wav"
	case ".m4a":
		audioMeta.MimeType = "audio/mp4"
	default:
		audioMeta.MimeType = "audio/unknown"
	}

	// Add a note about missing metadata
	audioMeta.Properties["MetadataNote"] = "No audio metadata tags available for this file"

	return audioMeta, nil
}

// classifyAudioError classifies audio-specific errors
func (amp *AudioMetadataPreprocessor) classifyAudioError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	errStr := strings.ToLower(err.Error())

	// Audio-specific error patterns
	if strings.Contains(errStr, "corrupted") || strings.Contains(errStr, "invalid audio") {
		return ErrorTypeFileCorrupted
	}
	if strings.Contains(errStr, "unsupported audio format") || strings.Contains(errStr, "unsupported format") {
		return ErrorTypeUnsupportedFormat
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline exceeded") {
		return ErrorTypeTimeout
	}
	if strings.Contains(errStr, "file too large") || strings.Contains(errStr, "file size") {
		return ErrorTypeFileSize
	}
	if strings.Contains(errStr, "tag extraction") || strings.Contains(errStr, "corrupted header") {
		return ErrorTypeFormatCorrupted
	}
	if strings.Contains(errStr, "no metadata") || strings.Contains(errStr, "no tags") {
		return ErrorTypeExtractionFailed // This will be handled gracefully
	}

	// Use base classifier for common errors
	classifier := NewErrorClassifier()
	return classifier.ClassifyError(err)
}

// addAudioErrorContext adds audio-specific context to errors
func (amp *AudioMetadataPreprocessor) addAudioErrorContext(mediaErr *MediaProcessingError, filePath string) {
	// Add file extension context
	ext := strings.ToLower(filepath.Ext(filePath))
	mediaErr.WithContext("file_extension", ext)

	// Add format-specific suggestions
	switch mediaErr.GetErrorType() {
	case ErrorTypeFileCorrupted:
		mediaErr.WithContext("suggestion", "Audio file may be corrupted or have damaged headers")
	case ErrorTypeUnsupportedFormat:
		mediaErr.WithContext("suggestion", fmt.Sprintf("Audio format %s is not supported for metadata extraction", ext))
	case ErrorTypeTimeout:
		mediaErr.WithContext("suggestion", "Audio file processing timed out, file may be too large or complex")
	case ErrorTypeExtractionFailed:
		if strings.Contains(mediaErr.Message, "no metadata") || strings.Contains(mediaErr.Message, "no tags") {
			mediaErr.WithContext("suggestion", "Audio file contains no metadata tags (this is normal for some files)")
		} else {
			mediaErr.WithContext("suggestion", "Audio metadata extraction failed, file may have non-standard tags")
		}
	case ErrorTypeFileSize:
		mediaErr.WithContext("suggestion", "Audio file is too large for metadata extraction")
	case ErrorTypeFormatCorrupted:
		mediaErr.WithContext("suggestion", "Audio file has corrupted metadata headers but may still be playable")
	}
}

// logSuccessfulProcessing logs detailed information about successful processing
func (amp *AudioMetadataPreprocessor) logSuccessfulProcessing(filePath string, audioMeta *audiolib.AudioMetadata) {
	ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(filePath), "."))

	amp.observer.DebugObserver.LogDetail("audio_metadata_preprocessor",
		fmt.Sprintf("Successfully extracted audio metadata from %s file: %s", ext, filepath.Base(filePath)))

	// Log technical specifications if available
	if audioMeta.Duration > 0 {
		amp.observer.DebugObserver.LogDetail("audio_metadata_preprocessor",
			fmt.Sprintf("Audio specs - Duration: %s, Bitrate: %d, Sample Rate: %d, Channels: %d",
				audioMeta.Duration.String(), audioMeta.Bitrate, audioMeta.SampleRate, audioMeta.Channels))
	}

	// Log interesting metadata if present (but be careful about privacy-sensitive information)
	if audioMeta.Artist != "" && audioMeta.Title != "" {
		amp.observer.DebugObserver.LogDetail("audio_metadata_preprocessor",
			fmt.Sprintf("Track info found: %s - %s", audioMeta.Artist, audioMeta.Title))
	}

	if audioMeta.Album != "" && audioMeta.Year > 0 {
		amp.observer.DebugObserver.LogDetail("audio_metadata_preprocessor",
			fmt.Sprintf("Album info: %s (%d)", audioMeta.Album, audioMeta.Year))
	}
}
