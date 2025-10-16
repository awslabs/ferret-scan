// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"context"
	"fmt"
	"os"
	"time"
)

// ResourceLimits defines limits for media file processing
type ResourceLimits struct {
	MaxVideoFileSize  int64         // Maximum video file size in bytes
	MaxAudioFileSize  int64         // Maximum audio file size in bytes
	ProcessingTimeout time.Duration // Maximum processing time per file
	MaxMemoryUsage    int64         // Maximum memory usage per file
}

// DefaultResourceLimits returns the default resource limits for media processing
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxVideoFileSize:  500 * 1024 * 1024, // 500MB
		MaxAudioFileSize:  100 * 1024 * 1024, // 100MB
		ProcessingTimeout: 30 * time.Second,  // 30 seconds
		MaxMemoryUsage:    50 * 1024 * 1024,  // 50MB
	}
}

// MediaResourceManager manages resource limits for media file processing
type MediaResourceManager struct {
	limits *ResourceLimits
}

// NewMediaResourceManager creates a new resource manager with default limits
func NewMediaResourceManager() *MediaResourceManager {
	return &MediaResourceManager{
		limits: DefaultResourceLimits(),
	}
}

// NewMediaResourceManagerWithLimits creates a new resource manager with custom limits
func NewMediaResourceManagerWithLimits(limits *ResourceLimits) *MediaResourceManager {
	return &MediaResourceManager{
		limits: limits,
	}
}

// ValidateFileSize checks if the file size is within limits
func (rm *MediaResourceManager) ValidateFileSize(filePath string, isVideo bool) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	fileSize := fileInfo.Size()
	var maxSize int64

	if isVideo {
		maxSize = rm.limits.MaxVideoFileSize
	} else {
		maxSize = rm.limits.MaxAudioFileSize
	}

	if fileSize > maxSize {
		return fmt.Errorf("file too large: %d bytes (max %d bytes for %s files)",
			fileSize, maxSize, getFileTypeString(isVideo))
	}

	return nil
}

// CreateProcessingContext creates a context with timeout for processing
func (rm *MediaResourceManager) CreateProcessingContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rm.limits.ProcessingTimeout)
}

// GetLimits returns the current resource limits
func (rm *MediaResourceManager) GetLimits() *ResourceLimits {
	return rm.limits
}

// SetLimits updates the resource limits
func (rm *MediaResourceManager) SetLimits(limits *ResourceLimits) {
	rm.limits = limits
}

// getFileTypeString returns a string representation of the file type
func getFileTypeString(isVideo bool) string {
	if isVideo {
		return "video"
	}
	return "audio"
}

// ProcessingError represents an error that occurred during media processing
type ProcessingError struct {
	FilePath string
	FileType string
	Reason   string
	Err      error
}

// Error implements the error interface
func (pe *ProcessingError) Error() string {
	if pe.Err != nil {
		return fmt.Sprintf("processing failed for %s (%s): %s - %v",
			pe.FilePath, pe.FileType, pe.Reason, pe.Err)
	}
	return fmt.Sprintf("processing failed for %s (%s): %s",
		pe.FilePath, pe.FileType, pe.Reason)
}

// Unwrap returns the underlying error
func (pe *ProcessingError) Unwrap() error {
	return pe.Err
}

// NewProcessingError creates a new processing error
func NewProcessingError(filePath, fileType, reason string, err error) *ProcessingError {
	return &ProcessingError{
		FilePath: filePath,
		FileType: fileType,
		Reason:   reason,
		Err:      err,
	}
}

// IsTimeoutError checks if the error is a timeout error
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	return err == context.DeadlineExceeded
}

// IsFileSizeError checks if the error is a file size limit error
func IsFileSizeError(err error) bool {
	if err == nil {
		return false
	}
	return fmt.Sprintf("%v", err) == "file too large"
}
