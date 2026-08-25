// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	meta_extract_videolib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-videolib"
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

	content := vmp.BuildSuccessContent(filePath, text, "video_metadata", 0)

	// Carry an extraction caveat forward, so a file whose box layout could not be followed to the
	// end is not reported as clean.
	//
	// Deliberately NOT an Error, for the same reason as the audio path above: extraction succeeded
	// and may have produced findings, and failing the file would discard them. Only
	// ExtractionWarning survives the router's combine step. Without this, a movie whose moov the
	// walk never reached printed "No matches found." and exited 0 — output byte-identical to a
	// genuinely clean file, and unchanged even under --fail-on-incomplete (#398).
	if content != nil && meta.ExtractionWarning != "" {
		content.ExtractionWarning = meta.ExtractionWarning
		// "video metadata may be incomplete: ..." — the file WAS read and some metadata recovered, so
		// this is partial coverage, not an absence of text. Reported as no-text it would tell an
		// operator to expect nothing from the file when findings may already have come from it.
		content.ExtractionCause = coverage.CauseCutShort
	}
	return content, nil
}

// SetObserver sets the observability component
func (vmp *VideoMetadataPreprocessor) SetObserver(observer observability.Observer) {
	vmp.BaseMetadataPreprocessor.SetObserver(observer)
}

// SetRouter sets the router instance (not used for video metadata but required by interface)
func (vmp *VideoMetadataPreprocessor) SetRouter(router RouterInterface) {
	vmp.BaseMetadataPreprocessor.SetRouter(router)
}
