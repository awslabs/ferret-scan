// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Constants for audio processing limits
const (
	MaxAudioFileSize  = 100 * 1024 * 1024 // 100MB limit
	MaxMetadataRead   = 1 * 1024 * 1024   // Only read first 1MB for metadata
	ProcessingTimeout = 15 * time.Second  // 15 second timeout
)

// AudioProcessingError represents an error during audio processing
type AudioProcessingError struct {
	FilePath    string
	ErrorType   string
	Message     string
	Err         error
	Recoverable bool
	Context     map[string]interface{}
}

func (e *AudioProcessingError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("audio processing failed for %s (%s): %s - %v",
			e.FilePath, e.ErrorType, e.Message, e.Err)
	}
	return fmt.Sprintf("audio processing failed for %s (%s): %s",
		e.FilePath, e.ErrorType, e.Message)
}

func (e *AudioProcessingError) Unwrap() error {
	return e.Err
}

func (e *AudioProcessingError) IsRecoverable() bool {
	return e.Recoverable
}

func (e *AudioProcessingError) WithContext(key string, value interface{}) *AudioProcessingError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// NewAudioProcessingError creates a new audio processing error
func NewAudioProcessingError(filePath, errorType, message string, err error) *AudioProcessingError {
	return &AudioProcessingError{
		FilePath:    filePath,
		ErrorType:   errorType,
		Message:     message,
		Err:         err,
		Recoverable: isAudioErrorRecoverable(errorType),
		Context:     make(map[string]interface{}),
	}
}

// isAudioErrorRecoverable determines if an audio error is recoverable
func isAudioErrorRecoverable(errorType string) bool {
	switch errorType {
	case "file_access", "timeout":
		return true
	case "file_size", "unsupported_format", "tag_extraction":
		return false
	default:
		return false
	}
}

// AudioExtractor provides a unified interface for audio metadata extraction
type AudioExtractor struct {
	extractors map[string]AudioMetadataExtractor
}

// NewAudioExtractor creates a new audio extractor with all supported formats
func NewAudioExtractor() *AudioExtractor {
	return &AudioExtractor{
		extractors: map[string]AudioMetadataExtractor{
			".mp3":  &MP3Extractor{},
			".flac": &FLACExtractor{},
			".wav":  &WAVExtractor{},
			".m4a":  &M4AExtractor{},
		},
	}
}

// ExtractMetadata extracts metadata from an audio file
func (e *AudioExtractor) ExtractMetadata(filePath string) (*AudioMetadata, error) {
	return e.ExtractMetadataWithContext(context.Background(), filePath)
}

// ExtractMetadataWithContext extracts metadata from an audio file with context and resource limits
func (e *AudioExtractor) ExtractMetadataWithContext(ctx context.Context, filePath string) (*AudioMetadata, error) {
	// Create processing context with timeout
	processCtx, cancel := context.WithTimeout(ctx, ProcessingTimeout)
	defer cancel()

	// Validate file size
	if err := e.validateFileSize(filePath); err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	extractor, exists := e.extractors[ext]
	if !exists {
		return nil, NewAudioProcessingError(filePath, "unsupported_format",
			fmt.Sprintf("unsupported audio format: %s", ext), nil)
	}

	// Check if extractor supports context
	if contextExtractor, ok := extractor.(AudioMetadataExtractorWithContext); ok {
		return contextExtractor.ExtractMetadataWithContext(processCtx, filePath)
	}

	// Fallback to regular extraction (with timeout via context)
	done := make(chan struct {
		metadata *AudioMetadata
		err      error
	}, 1)

	go func() {
		metadata, err := extractor.ExtractMetadata(filePath)
		done <- struct {
			metadata *AudioMetadata
			err      error
		}{metadata, err}
	}()

	select {
	case result := <-done:
		return result.metadata, result.err
	case <-processCtx.Done():
		return nil, NewAudioProcessingError(filePath, "timeout", "processing timeout exceeded", processCtx.Err())
	}
}

// validateFileSize checks if the audio file size is within limits
func (e *AudioExtractor) validateFileSize(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return NewAudioProcessingError(filePath, "file_access", "failed to get file info", err)
	}

	if fileInfo.Size() > MaxAudioFileSize {
		return NewAudioProcessingError(filePath, "file_size",
			fmt.Sprintf("file too large: %d bytes (max %d)", fileInfo.Size(), MaxAudioFileSize), nil)
	}

	return nil
}

// CanProcess checks if the file can be processed
func (e *AudioExtractor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	_, exists := e.extractors[ext]
	return exists
}

// GetSupportedFormats returns all supported audio formats
func (e *AudioExtractor) GetSupportedFormats() []string {
	formats := make([]string, 0, len(e.extractors))
	for ext := range e.extractors {
		formats = append(formats, ext)
	}
	return formats
}
