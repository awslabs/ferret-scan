// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
	meta_extract_exiflib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-exiflib"
)

// ImageMetadataPreprocessor extracts metadata from image files
type ImageMetadataPreprocessor struct {
	name            string
	observer        *observability.StandardObserver
	resourceManager *MediaResourceManager
	errorHandler    *GracefulDegradationHandler
	errorLogger     *ErrorLogger
	recoveryManager *ErrorRecoveryManager
	sharedUtils     *SharedUtilities
}

// NewImageMetadataPreprocessor creates a new image metadata preprocessor
func NewImageMetadataPreprocessor() *ImageMetadataPreprocessor {
	return &ImageMetadataPreprocessor{
		name:            "image_metadata",
		resourceManager: NewMediaResourceManager(),
		errorHandler:    NewGracefulDegradationHandler(),
		errorLogger:     NewErrorLogger(LogLevelWarn),
		recoveryManager: NewErrorRecoveryManager(),
		sharedUtils:     NewSharedUtilities(),
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (imp *ImageMetadataPreprocessor) CanProcess(filePath string) bool {
	return imp.sharedUtils.ExtensionValidator.IsImageFile(filePath)
}

// Process extracts metadata from image files
func (imp *ImageMetadataPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	return imp.processImageMetadataWithRetry(filePath, 0)
}

// processImageMetadataWithRetry processes image metadata with retry logic
func (imp *ImageMetadataPreprocessor) processImageMetadataWithRetry(filePath string, attemptCount int) (*ProcessedContent, error) {
	// Validate file size before processing (using standard limits, not video-specific)
	if err := imp.validateImageFile(filePath); err != nil {
		content := imp.errorHandler.HandleError(filePath, "image", err)
		// Fix the ProcessorType to match this specific preprocessor
		content.ProcessorType = "image_metadata"
		if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
			imp.errorLogger.LogError(mediaErr)
		}
		return content, err
	}

	// Create processing context with timeout
	ctx, cancel := imp.resourceManager.CreateProcessingContext()
	defer cancel()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		err := NewMediaProcessingError(filePath, "image", ErrorTypeCancelled, "processing cancelled", ctx.Err())
		content := imp.errorHandler.HandleError(filePath, "image", err)
		// Fix the ProcessorType to match this specific preprocessor
		content.ProcessorType = "image_metadata"
		imp.errorLogger.LogError(err)
		return content, err
	default:
	}

	// Extract EXIF metadata with enhanced error handling
	exifData, err := imp.extractImageMetadataWithFallback(filePath)
	if err != nil {
		// Classify and handle the error
		errorType := imp.classifyImageError(err)
		mediaErr := NewMediaProcessingError(filePath, "image", errorType, err.Error(), err)

		// Add image-specific context
		imp.addImageErrorContext(mediaErr, filePath)

		content := imp.errorHandler.HandleError(filePath, "image", mediaErr)
		// Fix the ProcessorType to match this specific preprocessor
		content.ProcessorType = "image_metadata"
		imp.errorLogger.LogError(mediaErr)

		// Check if we should retry
		if imp.recoveryManager.ShouldRetry(errorType, attemptCount) {
			// Log retry attempt
			if imp.observer != nil && imp.observer.DebugObserver != nil {
				imp.observer.DebugObserver.LogDetail("image_metadata_preprocessor",
					fmt.Sprintf("Retrying image metadata extraction for %s (attempt %d)", filePath, attemptCount+1))
			}

			// Add exponential backoff delay
			delay := time.Millisecond * 100 * time.Duration((attemptCount+1)*(attemptCount+1))
			time.Sleep(delay)
			return imp.processImageMetadataWithRetry(filePath, attemptCount+1)
		}

		return content, mediaErr
	}

	// Log successful processing with detailed information
	if imp.observer != nil && imp.observer.DebugObserver != nil {
		imp.logSuccessfulProcessing(filePath, exifData)
	}

	// Convert EXIF data to text format for validation
	text := imp.formatImageMetadata(exifData)

	// Build successful content using shared utilities
	return imp.sharedUtils.ContentBuilder.BuildSuccessContent(
		filePath,
		text,
		"image_metadata",
		"image_metadata",
		0, // Images don't have page count
	), nil
}

// formatImageMetadata converts EXIF data to formatted text
func (imp *ImageMetadataPreprocessor) formatImageMetadata(exifData *meta_extract_exiflib.ExifData) string {
	var metadataText strings.Builder

	// Debug: Log all GPS-related tags
	if imp.observer != nil && imp.observer.DebugObserver != nil {
		for key, value := range exifData.Tags {
			if strings.Contains(strings.ToLower(key), "gps") {
				imp.observer.DebugObserver.LogDetail("image_metadata_preprocessor",
					fmt.Sprintf("GPS tag found: %s = %s", key, value))
			}
		}
	}

	// First, handle GPS consolidation if both latitude and longitude are present
	if gpsLat, hasLat := exifData.Tags["GPSLatitudeDecimal"]; hasLat {
		if gpsLong, hasLong := exifData.Tags["GPSLongitudeDecimal"]; hasLong {
			// Create consolidated GPS coordinate entry
			consolidatedGPS := fmt.Sprintf("%s, %s", gpsLat, gpsLong)

			// Add altitude if available
			if altitude, hasAlt := exifData.Tags["GPSAltitude"]; hasAlt {
				consolidatedGPS = fmt.Sprintf("%s, %s", consolidatedGPS, altitude)
			}

			metadataText.WriteString(imp.sharedUtils.Formatter.FormatMetadataField("GPS_Coordinates", consolidatedGPS))

			// Remove individual GPS coordinate entries from being processed separately
			delete(exifData.Tags, "GPSLatitudeDecimal")
			delete(exifData.Tags, "GPSLongitudeDecimal")
			delete(exifData.Tags, "GPSLatitudeRef")
			delete(exifData.Tags, "GPSLongitudeRef")
			delete(exifData.Tags, "GPSAltitude")
			delete(exifData.Tags, "GPSAltitudeRef")

			// Also remove other GPS-related fields that are less sensitive
			delete(exifData.Tags, "GPSDateStamp")
			delete(exifData.Tags, "GPSDestBearing")
			delete(exifData.Tags, "GPSDestBearingRef")
			delete(exifData.Tags, "GPSImgDirection")
			delete(exifData.Tags, "GPSImgDirectionRef")
			delete(exifData.Tags, "GPSInfoIFDPointer")
			delete(exifData.Tags, "GPSSpeed")
			delete(exifData.Tags, "GPSSpeedRef")

			if imp.observer != nil && imp.observer.DebugObserver != nil {
				imp.observer.DebugObserver.LogDetail("image_metadata_preprocessor",
					fmt.Sprintf("Consolidated GPS coordinates: %s", consolidatedGPS))
			}
		}
	}

	// Get sorted keys for consistent output (after GPS consolidation)
	sortedKeys := exifData.GetSortedKeys()
	for _, key := range sortedKeys {
		value := exifData.Tags[key]
		metadataText.WriteString(imp.sharedUtils.Formatter.FormatMetadataField(key, value))
	}

	return metadataText.String()
}

// GetName returns the name of this preprocessor
func (imp *ImageMetadataPreprocessor) GetName() string {
	return imp.name
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (imp *ImageMetadataPreprocessor) GetSupportedExtensions() []string {
	return imp.sharedUtils.ExtensionValidator.GetImageExtensions()
}

// SetObserver sets the observability component
func (imp *ImageMetadataPreprocessor) SetObserver(observer *observability.StandardObserver) {
	imp.observer = observer
}

// validateImageFile performs image-specific validation
func (imp *ImageMetadataPreprocessor) validateImageFile(filePath string) error {
	// Check file accessibility
	if _, err := filepath.Abs(filePath); err != nil {
		return NewMediaProcessingError(filePath, "image", ErrorTypeFileAccess, "invalid file path", err)
	}

	// Validate file size (use audio limits as they're more appropriate for images than video limits)
	if err := imp.resourceManager.ValidateFileSize(filePath, false); err != nil {
		return NewMediaProcessingError(filePath, "image", ErrorTypeFileSize, "file size exceeds limits", err)
	}

	return nil
}

// extractImageMetadataWithFallback attempts to extract metadata with fallback strategies
func (imp *ImageMetadataPreprocessor) extractImageMetadataWithFallback(filePath string) (*meta_extract_exiflib.ExifData, error) {
	// Primary extraction attempt
	exifData, err := meta_extract_exiflib.ExtractExif(filePath)
	if err == nil {
		return exifData, nil
	}

	// Analyze the error to determine if it's recoverable
	errStr := strings.ToLower(err.Error())

	// File access errors - not recoverable
	if strings.Contains(errStr, "no such file") || strings.Contains(errStr, "permission denied") {
		return nil, err
	}

	// File format errors - not recoverable
	if strings.Contains(errStr, "error opening file") || strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "not a jpeg") || strings.Contains(errStr, "malformed") {
		return nil, err
	}

	// Check for "no EXIF data" cases - need to distinguish between valid and invalid files
	if strings.Contains(errStr, "no exif data found") {
		// Check for specific error patterns that indicate file corruption
		if strings.Contains(errStr, "error reading 4 byte header, got 0") {
			// Empty file - definitely invalid
			return nil, err
		}

		// For EOF errors, check if the file has valid image format headers
		if strings.Contains(errStr, "eof") {
			if !imp.isValidImageFormat(filePath) {
				// File doesn't have valid image headers - treat as invalid
				return nil, err
			}
		}

		// For other "no EXIF data" cases (including minimal valid JPEGs), handle gracefully
		// This includes cases where the file is a valid image format but just lacks EXIF data
		return imp.createMinimalImageMetadata(filePath)
	}

	// For all other errors, return the original error
	return nil, err
}

// createMinimalImageMetadata creates basic metadata for images without EXIF data
func (imp *ImageMetadataPreprocessor) createMinimalImageMetadata(filePath string) (*meta_extract_exiflib.ExifData, error) {
	// Create basic metadata structure
	exifData := &meta_extract_exiflib.ExifData{
		FilePath: filePath,
		Tags:     make(map[string]string),
	}

	// Add basic file information
	if stat, err := filepath.Abs(filePath); err == nil {
		exifData.Tags["FileName"] = filepath.Base(stat)
		exifData.Tags["FileExtension"] = strings.ToUpper(strings.TrimPrefix(filepath.Ext(stat), "."))
	}

	// Add file system metadata if available
	if stat, err := filepath.Abs(filePath); err == nil {
		if fileInfo, err := filepath.Abs(stat); err == nil {
			exifData.Tags["FilePath"] = fileInfo
		}
	}

	// Add a note about missing EXIF data
	exifData.Tags["MetadataNote"] = "No EXIF data available for this image format"

	return exifData, nil
}

// classifyImageError classifies image-specific errors
func (imp *ImageMetadataPreprocessor) classifyImageError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	errStr := strings.ToLower(err.Error())

	// Image-specific error patterns
	if strings.Contains(errStr, "corrupted") || strings.Contains(errStr, "invalid image") {
		return ErrorTypeFileCorrupted
	}
	if strings.Contains(errStr, "unsupported image format") {
		return ErrorTypeUnsupportedFormat
	}
	if strings.Contains(errStr, "exif") && strings.Contains(errStr, "corrupted") {
		return ErrorTypeFormatCorrupted
	}
	if strings.Contains(errStr, "no exif data") {
		return ErrorTypeExtractionFailed // This will be handled gracefully
	}

	// Use base classifier for common errors
	classifier := NewErrorClassifier()
	return classifier.ClassifyError(err)
}

// addImageErrorContext adds image-specific context to errors
func (imp *ImageMetadataPreprocessor) addImageErrorContext(mediaErr *MediaProcessingError, filePath string) {
	// Add file extension context
	ext := strings.ToLower(filepath.Ext(filePath))
	mediaErr.WithContext("file_extension", ext)

	// Add format-specific suggestions
	switch mediaErr.GetErrorType() {
	case ErrorTypeFileCorrupted:
		mediaErr.WithContext("suggestion", "Image file may be corrupted or truncated")
	case ErrorTypeUnsupportedFormat:
		mediaErr.WithContext("suggestion", fmt.Sprintf("Image format %s may not support EXIF metadata", ext))
	case ErrorTypeExtractionFailed:
		if strings.Contains(mediaErr.Message, "no exif data") {
			mediaErr.WithContext("suggestion", "Image contains no EXIF metadata (this is normal for some formats)")
		} else {
			mediaErr.WithContext("suggestion", "EXIF metadata extraction failed, image may have non-standard metadata")
		}
	case ErrorTypeFileSize:
		mediaErr.WithContext("suggestion", "Image file is too large for metadata extraction")
	}
}

// isValidImageFormat checks if a file has valid image format headers
func (imp *ImageMetadataPreprocessor) isValidImageFormat(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first few bytes to check for image format signatures
	header := make([]byte, 16)
	n, err := file.Read(header)
	if err != nil || n < 2 {
		return false
	}

	// Check for common image format signatures
	// JPEG: FF D8
	if n >= 2 && header[0] == 0xFF && header[1] == 0xD8 {
		return true
	}

	// PNG: 89 50 4E 47 0D 0A 1A 0A
	if n >= 8 && header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 {
		return true
	}

	// GIF: 47 49 46 38 (GIF8)
	if n >= 4 && header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38 {
		return true
	}

	// BMP: 42 4D (BM)
	if n >= 2 && header[0] == 0x42 && header[1] == 0x4D {
		return true
	}

	// TIFF: 49 49 2A 00 (little endian) or 4D 4D 00 2A (big endian)
	if n >= 4 && ((header[0] == 0x49 && header[1] == 0x49 && header[2] == 0x2A && header[3] == 0x00) ||
		(header[0] == 0x4D && header[1] == 0x4D && header[2] == 0x00 && header[3] == 0x2A)) {
		return true
	}

	// WebP: 52 49 46 46 ... 57 45 42 50 (RIFF...WEBP)
	if n >= 12 && header[0] == 0x52 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x46 &&
		header[8] == 0x57 && header[9] == 0x45 && header[10] == 0x42 && header[11] == 0x50 {
		return true
	}

	return false
}

// logSuccessfulProcessing logs detailed information about successful processing
func (imp *ImageMetadataPreprocessor) logSuccessfulProcessing(filePath string, exifData *meta_extract_exiflib.ExifData) {
	tagCount := len(exifData.Tags)
	ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(filePath), "."))

	imp.observer.DebugObserver.LogDetail("image_metadata_preprocessor",
		fmt.Sprintf("Successfully extracted %d metadata tags from %s image: %s", tagCount, ext, filepath.Base(filePath)))

	// Log interesting metadata if present
	if camera, exists := exifData.Tags["Make"]; exists {
		if model, exists := exifData.Tags["Model"]; exists {
			imp.observer.DebugObserver.LogDetail("image_metadata_preprocessor",
				fmt.Sprintf("Camera info: %s %s", camera, model))
		}
	}

	if gpsLat, hasLat := exifData.Tags["GPSLatitudeDecimal"]; hasLat {
		if gpsLong, hasLong := exifData.Tags["GPSLongitudeDecimal"]; hasLong {
			imp.observer.DebugObserver.LogDetail("image_metadata_preprocessor",
				fmt.Sprintf("GPS coordinates found: %s, %s", gpsLat, gpsLong))
		}
	}
}
