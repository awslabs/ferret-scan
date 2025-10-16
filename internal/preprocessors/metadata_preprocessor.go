// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// DEPRECATED FILE: This entire file is deprecated and will be removed in a future version.
//
// This monolithic metadata preprocessor has been replaced by specialized preprocessors:
// - ImageMetadataPreprocessor (internal/preprocessors/image_metadata_preprocessor.go)
// - PDFMetadataPreprocessor (internal/preprocessors/pdf_metadata_preprocessor.go)
// - OfficeMetadataPreprocessor (internal/preprocessors/office_metadata_preprocessor.go)
// - AudioMetadataPreprocessor (internal/preprocessors/audio_metadata_preprocessor.go)
// - VideoMetadataPreprocessor (internal/preprocessors/video_metadata_preprocessor.go)
//
// The specialized preprocessors are automatically registered through the router system
// and provide the same functionality with improved maintainability and testing.
//
// DO NOT USE THIS FILE FOR NEW DEVELOPMENT.

package preprocessors

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
	audiolib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-audiolib"
	meta_extract_exiflib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-exiflib"
	meta_extract_officelib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-officelib"
	meta_extract_pdflib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-pdflib"
	meta_extract_videolib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-videolib"
)

// DEPRECATED: MetadataPreprocessor is deprecated and will be removed in a future version.
// This monolithic preprocessor has been replaced by specialized preprocessors for better
// maintainability and adherence to the single responsibility principle.
//
// Migration Guide:
// - ImageMetadataPreprocessor: For image files (.jpg, .jpeg, .tiff, .tif, .png, .gif, .bmp, .webp)
// - PDFMetadataPreprocessor: For PDF files (.pdf)
// - OfficeMetadataPreprocessor: For Office documents (.docx, .xlsx, .pptx, .odt, .ods, .odp)
// - AudioMetadataPreprocessor: For audio files (.mp3, .flac, .wav, .m4a)
// - VideoMetadataPreprocessor: For video files (.mp4, .m4v, .mov)
//
// The specialized preprocessors provide the same functionality with improved:
// - Code organization and maintainability
// - Error handling and resource management
// - Testing and debugging capabilities
// - ProcessorType identification for validators
//
// No code changes are required - the router system automatically uses the specialized
// preprocessors when they are registered.

// RouterInterface defines the interface for router functionality needed by preprocessors
type RouterInterface interface {
	ProcessFile(filePath string, context interface{}) (*ProcessedContent, error)
}

// MetadataPreprocessor extracts metadata from various file types
// DEPRECATED: Use specialized preprocessors instead (ImageMetadataPreprocessor,
// PDFMetadataPreprocessor, OfficeMetadataPreprocessor, AudioMetadataPreprocessor,
// VideoMetadataPreprocessor)
type MetadataPreprocessor struct {
	name            string
	observer        *observability.StandardObserver
	router          RouterInterface
	resourceManager *MediaResourceManager
	errorHandler    *GracefulDegradationHandler
	errorLogger     *ErrorLogger
	recoveryManager *ErrorRecoveryManager
}

// NewMetadataPreprocessor creates a new metadata preprocessor
// DEPRECATED: Use specialized preprocessor constructors instead:
// - NewImageMetadataPreprocessor()
// - NewPDFMetadataPreprocessor()
// - NewOfficeMetadataPreprocessor()
// - NewAudioMetadataPreprocessor()
// - NewVideoMetadataPreprocessor()
func NewMetadataPreprocessor() *MetadataPreprocessor {
	return &MetadataPreprocessor{
		name:            "metadata",
		resourceManager: NewMediaResourceManager(),
		errorHandler:    NewGracefulDegradationHandler(),
		errorLogger:     NewErrorLogger(LogLevelWarn),
		recoveryManager: NewErrorRecoveryManager(),
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (mp *MetadataPreprocessor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Supported file formats for metadata extraction
	supportedExtensions := map[string]bool{
		// Image formats (EXIF extraction)
		".jpg":  true,
		".jpeg": true,
		".tiff": true,
		".tif":  true,
		".png":  true,
		".gif":  true,
		".bmp":  true,
		".webp": true,
		// PDF documents (metadata extraction)
		".pdf": true,
		// Office document formats
		".docx": true,
		".xlsx": true,
		".pptx": true,
		".odt":  true,
		".ods":  true,
		".odp":  true,
		// Video formats (metadata extraction)
		".mp4": true,
		".m4v": true,
		".mov": true,
		// Audio formats (metadata extraction)
		".mp3":  true,
		".flac": true,
		".wav":  true,
		".m4a":  true,
	}

	return supportedExtensions[ext]
}

// Process extracts metadata from the file based on its type
func (mp *MetadataPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Route to appropriate metadata extractor based on file type
	switch {
	case ext == ".jpg" || ext == ".jpeg" || ext == ".tiff" || ext == ".tif" || ext == ".png" || ext == ".gif" || ext == ".bmp" || ext == ".webp":
		return mp.processImageMetadata(filePath)
	case ext == ".pdf":
		return mp.processPDFMetadata(filePath)
	case ext == ".docx" || ext == ".xlsx" || ext == ".pptx" || ext == ".odt" || ext == ".ods" || ext == ".odp":
		return mp.processOfficeMetadata(filePath)
	case ext == ".mp4" || ext == ".m4v" || ext == ".mov":
		return mp.processVideoMetadata(filePath)
	case ext == ".mp3" || ext == ".flac" || ext == ".wav" || ext == ".m4a":
		return mp.processAudioMetadata(filePath)
	default:
		return &ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			Text:          "",
			Format:        "metadata",
			WordCount:     0,
			CharCount:     0,
			LineCount:     0,
			ProcessorType: mp.name,
			Success:       false,
			Metadata:      make(map[string]interface{}),
		}, fmt.Errorf("unsupported file type for metadata extraction: %s", ext)
	}
}

// processImageMetadata extracts EXIF metadata from image files
func (mp *MetadataPreprocessor) processImageMetadata(filePath string) (*ProcessedContent, error) {
	exifData, err := meta_extract_exiflib.ExtractExif(filePath)
	if err != nil {
		return &ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			ProcessorType: mp.name,
			Success:       false,
			Error:         fmt.Errorf("failed to extract EXIF metadata: %w", err),
		}, err
	}

	// Convert EXIF data to text format for validation
	var metadataText strings.Builder

	// Get sorted keys for consistent output
	sortedKeys := exifData.GetSortedKeys()
	for _, key := range sortedKeys {
		value := exifData.Tags[key]
		metadataText.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	text := metadataText.String()

	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          text,
		Format:        "image_metadata",
		WordCount:     len(strings.Fields(text)),
		CharCount:     len(text),
		LineCount:     len(strings.Split(text, "\n")),
		ProcessorType: mp.name,
		Success:       true,
	}, nil
}

// processOfficeMetadata extracts metadata from Office documents
func (mp *MetadataPreprocessor) processOfficeMetadata(filePath string) (*ProcessedContent, error) {
	meta, err := meta_extract_officelib.ExtractMetadata(filePath)
	if err != nil {
		return &ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			ProcessorType: mp.name,
			Success:       false,
			Error:         fmt.Errorf("failed to extract Office metadata: %w", err),
		}, err
	}

	// Log file system information for observability (but exclude from validator content)
	if mp.observer != nil && mp.observer.DebugObserver != nil {
		mp.observer.DebugObserver.LogDetail("metadata_preprocessor", fmt.Sprintf("File system info - Name: %s, Size: %d bytes, Type: %s", meta.Filename, meta.FileSize, meta.MimeType))
	}

	// Convert Office metadata to text format for validation
	var metadataText strings.Builder

	// Skip file system information - only include object metadata

	// Document properties
	if meta.Title != "" {
		metadataText.WriteString(fmt.Sprintf("Title: %s\n", meta.Title))
	}
	if meta.Subject != "" {
		metadataText.WriteString(fmt.Sprintf("Subject: %s\n", meta.Subject))
	}
	if meta.Author != "" {
		metadataText.WriteString(fmt.Sprintf("Author: %s\n", meta.Author))
	}
	if meta.Creator != "" && meta.Creator != meta.Author {
		metadataText.WriteString(fmt.Sprintf("Creator: %s\n", meta.Creator))
	}
	if meta.Description != "" {
		metadataText.WriteString(fmt.Sprintf("Description: %s\n", meta.Description))
	}
	if meta.Keywords != "" {
		metadataText.WriteString(fmt.Sprintf("Keywords: %s\n", meta.Keywords))
	}
	if meta.Category != "" {
		metadataText.WriteString(fmt.Sprintf("Category: %s\n", meta.Category))
	}
	if meta.Application != "" {
		metadataText.WriteString(fmt.Sprintf("Application: %s\n", meta.Application))
	}
	if meta.AppVersion != "" {
		metadataText.WriteString(fmt.Sprintf("ApplicationVersion: %s\n", meta.AppVersion))
	}
	if meta.Company != "" {
		metadataText.WriteString(fmt.Sprintf("Company: %s\n", meta.Company))
	}
	if meta.LastModifiedBy != "" {
		metadataText.WriteString(fmt.Sprintf("LastModifiedBy: %s\n", meta.LastModifiedBy))
	}
	if meta.Manager != "" {
		metadataText.WriteString(fmt.Sprintf("Manager: %s\n", meta.Manager))
	}
	if meta.Comments != "" {
		metadataText.WriteString(fmt.Sprintf("Comments: %s\n", meta.Comments))
	}
	if meta.ContentStatus != "" {
		metadataText.WriteString(fmt.Sprintf("ContentStatus: %s\n", meta.ContentStatus))
	}
	if meta.Identifier != "" {
		metadataText.WriteString(fmt.Sprintf("Identifier: %s\n", meta.Identifier))
	}
	if meta.Language != "" {
		metadataText.WriteString(fmt.Sprintf("Language: %s\n", meta.Language))
	}
	if meta.Revision != "" {
		metadataText.WriteString(fmt.Sprintf("Revision: %s\n", meta.Revision))
	}

	// Dates
	if !meta.Created.IsZero() {
		metadataText.WriteString(fmt.Sprintf("CreationDate: %s\n", meta.Created.Format("2006:01:02 15:04:05-07:00")))
	}
	if !meta.Modified.IsZero() {
		metadataText.WriteString(fmt.Sprintf("ModificationDate: %s\n", meta.Modified.Format("2006:01:02 15:04:05-07:00")))
	}

	// Document statistics
	if meta.PageCount > 0 {
		metadataText.WriteString(fmt.Sprintf("PageCount: %d\n", meta.PageCount))
	}
	if meta.WordCount > 0 {
		metadataText.WriteString(fmt.Sprintf("WordCount: %d\n", meta.WordCount))
	}
	if meta.CharCount > 0 {
		metadataText.WriteString(fmt.Sprintf("CharacterCount: %d\n", meta.CharCount))
	}

	// Additional properties
	for key, value := range meta.Properties {
		metadataText.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// Process embedded media through router
	embeddedMedia, err := meta_extract_officelib.ExtractEmbeddedMediaForProcessing(filePath)
	if err == nil && len(embeddedMedia) > 0 {
		defer meta_extract_officelib.CleanupEmbeddedMedia(embeddedMedia)

		for i, media := range embeddedMedia {
			if mp.router != nil {
				// Create context showing original file relationship
				embeddedPath := fmt.Sprintf("%s -> %s", filepath.Base(filePath), media.OriginalName)
				// Reprocess embedded media through router
				if processed, err := mp.router.ProcessFile(media.TempFilePath, nil); err == nil && processed != nil && processed.Success {
					// Update processed content to show original file relationship
					processed.OriginalPath = embeddedPath
					processed.Filename = embeddedPath
					metadataText.WriteString(fmt.Sprintf("\n--- Embedded Media %d (%s) ---\n", i+1, media.OriginalName))
					metadataText.WriteString(processed.Text)
				}
			}
		}
	}

	text := metadataText.String()

	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          text,
		Format:        "office_metadata",
		WordCount:     len(strings.Fields(text)),
		CharCount:     len(text),
		LineCount:     len(strings.Split(text, "\n")),
		PageCount:     meta.PageCount,
		ProcessorType: mp.name,
		Success:       true,
	}, nil
}

// processVideoMetadata extracts metadata from video files with comprehensive error handling
func (mp *MetadataPreprocessor) processVideoMetadata(filePath string) (*ProcessedContent, error) {
	return mp.processVideoMetadataWithRetry(filePath, 0)
}

// processVideoMetadataWithRetry processes video metadata with retry logic
func (mp *MetadataPreprocessor) processVideoMetadataWithRetry(filePath string, attemptCount int) (*ProcessedContent, error) {
	// Validate file size before processing
	if err := mp.resourceManager.ValidateFileSize(filePath, true); err != nil {
		content := mp.errorHandler.HandleError(filePath, "video", err)
		if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
			mp.errorLogger.LogError(mediaErr)
		}
		return content, err
	}

	// Create processing context with timeout
	ctx, cancel := mp.resourceManager.CreateProcessingContext()
	defer cancel()

	// Extract metadata with context and resource limits
	meta, err := meta_extract_videolib.ExtractVideoMetadataWithContext(ctx, filePath)
	if err != nil {
		// Handle error with comprehensive error handling
		content := mp.errorHandler.HandleError(filePath, "video", err)

		if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
			mp.errorLogger.LogError(mediaErr)

			// Check if we should retry
			if mp.recoveryManager.ShouldRetry(mediaErr.GetErrorType(), attemptCount) {
				// Log retry attempt
				if mp.observer != nil && mp.observer.DebugObserver != nil {
					mp.observer.DebugObserver.LogDetail("metadata_preprocessor",
						fmt.Sprintf("Retrying video metadata extraction for %s (attempt %d)", filePath, attemptCount+1))
				}

				// Add small delay before retry
				time.Sleep(time.Millisecond * 100 * time.Duration(attemptCount+1))
				return mp.processVideoMetadataWithRetry(filePath, attemptCount+1)
			}
		}

		return content, err
	}

	// Log successful processing
	if mp.observer != nil && mp.observer.DebugObserver != nil {
		mp.observer.DebugObserver.LogDetail("metadata_preprocessor",
			fmt.Sprintf("Successfully extracted video metadata - Name: %s, Size: %d bytes, Type: %s",
				meta.Filename, meta.FileSize, meta.MimeType))
	}

	// Convert video metadata to text format for validation
	text := meta.ToProcessedContent()

	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          text,
		Format:        "video_metadata",
		WordCount:     len(strings.Fields(text)),
		CharCount:     len(text),
		LineCount:     len(strings.Split(text, "\n")),
		ProcessorType: mp.name,
		Success:       true,
	}, nil
}

// processAudioMetadata extracts metadata from audio files with comprehensive error handling
func (mp *MetadataPreprocessor) processAudioMetadata(filePath string) (*ProcessedContent, error) {
	return mp.processAudioMetadataWithRetry(filePath, 0)
}

// processAudioMetadataWithRetry processes audio metadata with retry logic
func (mp *MetadataPreprocessor) processAudioMetadataWithRetry(filePath string, attemptCount int) (*ProcessedContent, error) {
	// Validate file size before processing
	if err := mp.resourceManager.ValidateFileSize(filePath, false); err != nil {
		content := mp.errorHandler.HandleError(filePath, "audio", err)
		if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
			mp.errorLogger.LogError(mediaErr)
		}
		return content, err
	}

	// Create processing context with timeout
	ctx, cancel := mp.resourceManager.CreateProcessingContext()
	defer cancel()

	// Create audio extractor
	extractor := audiolib.NewAudioExtractor()

	// Extract metadata with context and resource limits
	meta, err := extractor.ExtractMetadataWithContext(ctx, filePath)
	if err != nil {
		// Handle error with comprehensive error handling
		content := mp.errorHandler.HandleError(filePath, "audio", err)

		if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
			mp.errorLogger.LogError(mediaErr)

			// Check if we should retry
			if mp.recoveryManager.ShouldRetry(mediaErr.GetErrorType(), attemptCount) {
				// Log retry attempt
				if mp.observer != nil && mp.observer.DebugObserver != nil {
					mp.observer.DebugObserver.LogDetail("metadata_preprocessor",
						fmt.Sprintf("Retrying audio metadata extraction for %s (attempt %d)", filePath, attemptCount+1))
				}

				// Add small delay before retry
				time.Sleep(time.Millisecond * 100 * time.Duration(attemptCount+1))
				return mp.processAudioMetadataWithRetry(filePath, attemptCount+1)
			}
		}

		return content, err
	}

	// Log successful processing
	if mp.observer != nil && mp.observer.DebugObserver != nil {
		mp.observer.DebugObserver.LogDetail("metadata_preprocessor",
			fmt.Sprintf("Successfully extracted audio metadata - Name: %s, Size: %d bytes, Type: %s",
				meta.Filename, meta.FileSize, meta.MimeType))
	}

	// Convert audio metadata to text format for validation
	text := meta.ToProcessedContent()

	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          text,
		Format:        "audio_metadata",
		WordCount:     len(strings.Fields(text)),
		CharCount:     len(text),
		LineCount:     len(strings.Split(text, "\n")),
		ProcessorType: mp.name,
		Success:       true,
	}, nil
}

// processPDFMetadata extracts metadata from PDF documents
func (mp *MetadataPreprocessor) processPDFMetadata(filePath string) (*ProcessedContent, error) {
	meta, err := meta_extract_pdflib.ExtractMetadata(filePath)
	if err != nil {
		return &ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			ProcessorType: mp.name,
			Success:       false,
			Error:         fmt.Errorf("failed to extract PDF metadata: %w", err),
		}, err
	}

	// Log file system information for observability (but exclude from validator content)
	if mp.observer != nil && mp.observer.DebugObserver != nil {
		mp.observer.DebugObserver.LogDetail("metadata_preprocessor", fmt.Sprintf("File system info - Name: %s, Size: %d bytes, Type: %s", meta.Filename, meta.FileSize, meta.MimeType))
	}

	// Convert PDF metadata to text format for validation
	var metadataText strings.Builder

	// Skip file system information - only include object metadata
	metadataText.WriteString(fmt.Sprintf("PDFVersion: %s\n", meta.Version))

	if meta.Encrypted {
		metadataText.WriteString("Encrypted: true\n")
	}

	// Document properties
	if meta.Title != "" {
		metadataText.WriteString(fmt.Sprintf("Title: %s\n", meta.Title))
	}
	if meta.Author != "" {
		metadataText.WriteString(fmt.Sprintf("Author: %s\n", meta.Author))
	}
	if meta.Subject != "" {
		metadataText.WriteString(fmt.Sprintf("Subject: %s\n", meta.Subject))
	}
	if meta.Keywords != "" {
		metadataText.WriteString(fmt.Sprintf("Keywords: %s\n", meta.Keywords))
	}
	if meta.Creator != "" {
		metadataText.WriteString(fmt.Sprintf("Creator: %s\n", meta.Creator))
	}
	if meta.Producer != "" {
		metadataText.WriteString(fmt.Sprintf("Producer: %s\n", meta.Producer))
		if mp.observer != nil && mp.observer.DebugObserver != nil {
			mp.observer.DebugObserver.LogDetail("metadata_preprocessor", fmt.Sprintf("Adding Producer to metadata content: %s", meta.Producer))
		}
	}

	// Dates
	if !meta.CreatedDate.IsZero() {
		metadataText.WriteString(fmt.Sprintf("CreationDate: %s\n", meta.CreatedDate.Format("2006:01:02 15:04:05-07:00")))
	}
	if !meta.ModDate.IsZero() {
		metadataText.WriteString(fmt.Sprintf("ModificationDate: %s\n", meta.ModDate.Format("2006:01:02 15:04:05-07:00")))
	}

	// Page count
	if meta.PageCount > 0 {
		metadataText.WriteString(fmt.Sprintf("PageCount: %d\n", meta.PageCount))
	}

	// Additional properties
	for key, value := range meta.Properties {
		// Skip properties we've already displayed
		if key == "CreationDate" || key == "ModificationDate" {
			continue
		}
		metadataText.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	text := metadataText.String()

	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          text,
		Format:        "pdf_metadata",
		WordCount:     len(strings.Fields(text)),
		CharCount:     len(text),
		LineCount:     len(strings.Split(text, "\n")),
		PageCount:     meta.PageCount,
		ProcessorType: mp.name,
		Success:       true,
	}, nil
}

// GetName returns the name of this preprocessor
func (mp *MetadataPreprocessor) GetName() string {
	return mp.name
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (mp *MetadataPreprocessor) GetSupportedExtensions() []string {
	return []string{
		// Image formats (currently supported)
		".jpg", ".jpeg", ".tiff", ".tif", ".png", ".gif", ".bmp", ".webp",
		// PDF documents
		".pdf",
		// Office document formats
		".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
		// Video formats
		".mp4", ".m4v", ".mov",
		// Audio formats
		".mp3", ".flac", ".wav", ".m4a",
	}
}

// MetadataExtractorInterface defines the interface for metadata extraction
// This is used by the metadata validator for compatibility
type MetadataExtractorInterface interface {
	ProcessFile(filePath string) (string, error)
	ExtractMetadata(filePath string) (string, error)
}

// MetadataExtractor implements the interface expected by the metadata validator
// DEPRECATED: This wrapper around the monolithic MetadataPreprocessor is deprecated.
// Use the router system with specialized preprocessors instead.
//
// This interface is maintained only for backward compatibility and will be removed
// in a future version. New code should use the router system which automatically
// routes files to the appropriate specialized preprocessors.
type MetadataExtractor struct {
	Preprocessor *MetadataPreprocessor
}

// NewMetadataExtractor creates a new metadata extractor for validator compatibility
// DEPRECATED: Use the router system with specialized preprocessors instead.
func NewMetadataExtractor() *MetadataExtractor {
	return &MetadataExtractor{
		Preprocessor: NewMetadataPreprocessor(),
	}
}

// ProcessFile extracts metadata and returns it as a string
func (me *MetadataExtractor) ProcessFile(filePath string) (string, error) {
	if !me.Preprocessor.CanProcess(filePath) {
		return "", fmt.Errorf("file type not supported for metadata extraction: %s", filePath)
	}

	content, err := me.Preprocessor.Process(filePath)
	if err != nil {
		return "", err
	}

	if !content.Success {
		return "", content.Error
	}

	return content.Text, nil
}

// ExtractMetadata is an alias for ProcessFile for compatibility
func (me *MetadataExtractor) ExtractMetadata(filePath string) (string, error) {
	return me.ProcessFile(filePath)
}

// SetObserver sets the observability component
func (mp *MetadataPreprocessor) SetObserver(observer *observability.StandardObserver) {
	mp.observer = observer
}

// SetRouter sets the router instance for reprocessing embedded media
func (mp *MetadataPreprocessor) SetRouter(router RouterInterface) {
	mp.router = router
}
