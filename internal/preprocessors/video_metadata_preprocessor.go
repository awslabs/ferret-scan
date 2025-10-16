// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"ferret-scan/internal/observability"
	meta_extract_videolib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-videolib"
)

// VideoMetadataPreprocessor extracts metadata from video files
type VideoMetadataPreprocessor struct {
	*BaseMetadataPreprocessor
}

// NewVideoMetadataPreprocessor creates a new video metadata preprocessor
func NewVideoMetadataPreprocessor() *VideoMetadataPreprocessor {
	base := NewBaseMetadataPreprocessor("video_metadata", "video_metadata")
	return &VideoMetadataPreprocessor{
		BaseMetadataPreprocessor: base,
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (vmp *VideoMetadataPreprocessor) CanProcess(filePath string) bool {
	return vmp.GetUtilities().ExtensionValidator.IsVideoFile(filePath)
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (vmp *VideoMetadataPreprocessor) GetSupportedExtensions() []string {
	return vmp.GetUtilities().ExtensionValidator.GetVideoExtensions()
}

// Process extracts metadata from video files with comprehensive error handling and retry logic
func (vmp *VideoMetadataPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	return vmp.ProcessWithRetry(filePath, func() (*ProcessedContent, error) {
		return vmp.processVideoMetadata(filePath)
	})
}

// processVideoMetadata extracts metadata from video files
func (vmp *VideoMetadataPreprocessor) processVideoMetadata(filePath string) (*ProcessedContent, error) {
	// Validate file size before processing (video files have higher limits)
	if err := vmp.ValidateFileSize(filePath, true); err != nil {
		return vmp.HandleError(filePath, "video", err), err
	}

	// Create processing context with timeout
	ctx, cancel := vmp.CreateProcessingContext()
	defer cancel()

	// Extract metadata with context and resource limits
	meta, err := meta_extract_videolib.ExtractVideoMetadataWithContext(ctx, filePath)
	if err != nil {
		return vmp.HandleError(filePath, "video", err), err
	}

	// Log file system information for observability (excluded from validator content)
	vmp.LogFileSystemInfo(meta.Filename, meta.FileSize, meta.MimeType)

	// Log successful processing
	vmp.LogSuccessfulProcessing(meta.Filename, meta.FileSize, meta.MimeType)

	// Convert video metadata to text format for validation
	text := meta.ToProcessedContent()

	return vmp.BuildSuccessContent(filePath, text, "video_metadata", 0), nil
}

// SetObserver sets the observability component
func (vmp *VideoMetadataPreprocessor) SetObserver(observer *observability.StandardObserver) {
	vmp.BaseMetadataPreprocessor.SetObserver(observer)
}

// SetRouter sets the router instance (not used for video metadata but required by interface)
func (vmp *VideoMetadataPreprocessor) SetRouter(router RouterInterface) {
	vmp.BaseMetadataPreprocessor.SetRouter(router)
}
