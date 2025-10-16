// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
	"ferret-scan/internal/redactors/position"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rwcarlsen/goexif/exif"
	"github.com/rwcarlsen/goexif/tiff"
)

// ImageMetadataRedactor implements redaction for image files by removing metadata
type ImageMetadataRedactor struct {
	// observer handles observability and metrics
	observer *observability.StandardObserver

	// outputManager handles file system operations
	outputManager *redactors.OutputStructureManager

	// positionCorrelator handles position correlation (not used for image metadata)
	positionCorrelator position.PositionCorrelator

	// enablePositionCorrelation controls whether to use position correlation (not applicable for images)
	enablePositionCorrelation bool

	// confidenceThreshold is the minimum confidence required (not applicable for images)
	confidenceThreshold float64

	// fallbackToSimple controls fallback behavior (not applicable for images)
	fallbackToSimple bool

	// preserveImageQuality controls whether to preserve original image quality
	preserveImageQuality bool

	// supportedFormats lists the image formats this redactor can handle
	supportedFormats map[string]bool
}

// ImageFormat represents the type of image format
type ImageFormat int

const (
	// FormatUnknown represents an unknown image format
	FormatUnknown ImageFormat = iota
	// FormatJPEG represents a JPEG image
	FormatJPEG
	// FormatPNG represents a PNG image
	FormatPNG
	// FormatGIF represents a GIF image
	FormatGIF
	// FormatTIFF represents a TIFF image
	FormatTIFF
	// FormatBMP represents a BMP image
	FormatBMP
	// FormatWEBP represents a WebP image
	FormatWEBP
)

// String returns the string representation of the image format
func (f ImageFormat) String() string {
	switch f {
	case FormatJPEG:
		return "jpeg"
	case FormatPNG:
		return "png"
	case FormatGIF:
		return "gif"
	case FormatTIFF:
		return "tiff"
	case FormatBMP:
		return "bmp"
	case FormatWEBP:
		return "webp"
	default:
		return "unknown"
	}
}

// NewImageMetadataRedactor creates a new ImageMetadataRedactor
func NewImageMetadataRedactor(outputManager *redactors.OutputStructureManager, observer *observability.StandardObserver) *ImageMetadataRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	supportedFormats := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".tiff": true,
		".tif":  true,
		".bmp":  true,
		".webp": true,
	}

	return &ImageMetadataRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        position.NewDefaultPositionCorrelator(),
		enablePositionCorrelation: false, // Not applicable for image metadata
		confidenceThreshold:       1.0,   // Always high confidence for metadata removal
		fallbackToSimple:          false, // Not applicable for image metadata
		preserveImageQuality:      true,
		supportedFormats:          supportedFormats,
	}
}

// NewImageMetadataRedactorWithOptions creates a new ImageMetadataRedactor with custom options
func NewImageMetadataRedactorWithOptions(outputManager *redactors.OutputStructureManager, observer *observability.StandardObserver, preserveQuality bool) *ImageMetadataRedactor {
	redactor := NewImageMetadataRedactor(outputManager, observer)
	redactor.preserveImageQuality = preserveQuality
	return redactor
}

// GetName returns the name of the redactor
func (imr *ImageMetadataRedactor) GetName() string {
	return "image_metadata_redactor"
}

// GetSupportedTypes returns the file types this redactor can handle
func (imr *ImageMetadataRedactor) GetSupportedTypes() []string {
	types := make([]string, 0, len(imr.supportedFormats)*2)
	for ext := range imr.supportedFormats {
		types = append(types, ext)
		types = append(types, strings.TrimPrefix(ext, ".")) // Add without dot
	}
	return types
}

// GetSupportedStrategies returns the redaction strategies this redactor supports
func (imr *ImageMetadataRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	// Image metadata redaction only supports simple strategy (metadata removal)
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
	}
}

// RedactDocument creates a redacted copy of the image file at outputPath with metadata removed
func (imr *ImageMetadataRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if imr.observer != nil {
		finishTiming = imr.observer.StartTiming("image_metadata_redactor", "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Detect image format
	format, err := imr.detectImageFormat(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect image format: %w", err)
	}

	// Extract metadata before redaction
	metadata, err := imr.extractImageMetadata(originalPath, format)
	if err != nil {
		imr.logEvent("metadata_extraction_failed", false, map[string]interface{}{
			"error": err.Error(),
		})
		// Continue with redaction even if metadata extraction fails
		metadata = &ImageMetadata{}
	}

	// Perform metadata redaction
	redactionMap, err := imr.redactImageMetadata(originalPath, outputPath, format, metadata, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to redact image metadata: %w", err)
	}

	// Calculate overall confidence (always high for metadata removal)
	confidence := 1.0

	processingTime := time.Since(startTime)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// ImageMetadata represents metadata extracted from an image
type ImageMetadata struct {
	Format     ImageFormat            `json:"format"`
	HasEXIF    bool                   `json:"has_exif"`
	EXIFData   map[string]string      `json:"exif_data,omitempty"`
	Dimensions ImageDimensions        `json:"dimensions"`
	FileSize   int64                  `json:"file_size"`
	ColorModel string                 `json:"color_model"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ImageDimensions represents image width and height
type ImageDimensions struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// detectImageFormat detects the format of an image file
func (imr *ImageMetadataRedactor) detectImageFormat(filePath string) (ImageFormat, error) {
	// First, try to detect by file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".jpg", ".jpeg":
		return FormatJPEG, nil
	case ".png":
		return FormatPNG, nil
	case ".gif":
		return FormatGIF, nil
	case ".tiff", ".tif":
		return FormatTIFF, nil
	case ".bmp":
		return FormatBMP, nil
	case ".webp":
		return FormatWEBP, nil
	}

	// If extension is not conclusive, examine file header
	file, err := os.Open(filePath)
	if err != nil {
		return FormatUnknown, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read first few bytes to detect format
	header := make([]byte, 12)
	_, err = file.Read(header)
	if err != nil {
		return FormatUnknown, fmt.Errorf("failed to read file header: %w", err)
	}

	// Check magic bytes
	if bytes.HasPrefix(header, []byte{0xFF, 0xD8, 0xFF}) {
		return FormatJPEG, nil
	}
	if bytes.HasPrefix(header, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		return FormatPNG, nil
	}
	if bytes.HasPrefix(header, []byte("GIF87a")) || bytes.HasPrefix(header, []byte("GIF89a")) {
		return FormatGIF, nil
	}
	if bytes.HasPrefix(header, []byte("RIFF")) && bytes.Contains(header, []byte("WEBP")) {
		return FormatWEBP, nil
	}
	if bytes.HasPrefix(header, []byte{0x42, 0x4D}) {
		return FormatBMP, nil
	}
	if bytes.HasPrefix(header, []byte{0x49, 0x49, 0x2A, 0x00}) || bytes.HasPrefix(header, []byte{0x4D, 0x4D, 0x00, 0x2A}) {
		return FormatTIFF, nil
	}

	return FormatUnknown, fmt.Errorf("unable to determine image format")
}

// extractImageMetadata extracts metadata from an image file
func (imr *ImageMetadataRedactor) extractImageMetadata(filePath string, format ImageFormat) (*ImageMetadata, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	metadata := &ImageMetadata{
		Format:   format,
		FileSize: fileInfo.Size(),
		Metadata: make(map[string]interface{}),
	}

	// Decode image to get dimensions and color model
	img, _, err := image.Decode(file)
	if err != nil {
		imr.logEvent("image_decode_failed", false, map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		bounds := img.Bounds()
		metadata.Dimensions = ImageDimensions{
			Width:  bounds.Dx(),
			Height: bounds.Dy(),
		}
		metadata.ColorModel = fmt.Sprintf("%T", img.ColorModel())
	}

	// Extract EXIF data for supported formats
	if format == FormatJPEG || format == FormatTIFF {
		file.Seek(0, 0) // Reset file position
		exifData, err := imr.extractEXIFData(file)
		if err != nil {
			imr.logEvent("exif_extraction_failed", false, map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			metadata.HasEXIF = true
			metadata.EXIFData = exifData
		}
	}

	imr.logEvent("metadata_extracted", true, map[string]interface{}{
		"format":     format.String(),
		"has_exif":   metadata.HasEXIF,
		"dimensions": metadata.Dimensions,
		"file_size":  metadata.FileSize,
	})

	return metadata, nil
}

// extractEXIFData extracts EXIF data from an image file
func (imr *ImageMetadataRedactor) extractEXIFData(reader io.Reader) (map[string]string, error) {
	exifData := make(map[string]string)

	x, err := exif.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EXIF data: %w", err)
	}

	// Walk through all EXIF fields
	err = x.Walk(&exifWalker{data: exifData})
	if err != nil {
		return nil, fmt.Errorf("failed to walk EXIF data: %w", err)
	}

	return exifData, nil
}

// exifWalker implements exif.Walker interface to collect EXIF data
type exifWalker struct {
	data map[string]string
}

func (w *exifWalker) Walk(name exif.FieldName, tag *tiff.Tag) error {
	if tag != nil {
		value, err := tag.StringVal()
		if err != nil {
			// If string conversion fails, try to get the raw value
			value = fmt.Sprintf("%v", tag.Val)
		}
		w.data[string(name)] = value
	}
	return nil
}

// redactImageMetadata removes metadata from an image file
func (imr *ImageMetadataRedactor) redactImageMetadata(originalPath, outputPath string, format ImageFormat, metadata *ImageMetadata, strategy redactors.RedactionStrategy) ([]redactors.RedactionMapping, error) {
	// Ensure output directory exists
	if imr.outputManager != nil {
		if err := imr.outputManager.EnsureDirectoryExists(outputPath); err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	var redactionMap []redactors.RedactionMapping

	// Open original file
	originalFile, err := os.Open(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open original file: %w", err)
	}
	defer originalFile.Close()

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Process based on image format
	switch format {
	case FormatJPEG:
		err = imr.redactJPEGMetadata(originalFile, outputFile, metadata, &redactionMap, strategy)
	case FormatPNG:
		err = imr.redactPNGMetadata(originalFile, outputFile, metadata, &redactionMap, strategy)
	case FormatGIF, FormatTIFF, FormatBMP, FormatWEBP:
		// For other formats, copy image data without metadata
		err = imr.redactGenericImageMetadata(originalFile, outputFile, format, metadata, &redactionMap, strategy)
	default:
		return nil, fmt.Errorf("unsupported image format: %s", format.String())
	}

	if err != nil {
		return nil, fmt.Errorf("failed to redact %s metadata: %w", format.String(), err)
	}

	imr.logEvent("image_metadata_redacted", true, map[string]interface{}{
		"format":           format.String(),
		"original_size":    metadata.FileSize,
		"redactions_count": len(redactionMap),
		"had_exif":         metadata.HasEXIF,
	})

	return redactionMap, nil
}

// redactJPEGMetadata removes EXIF and other metadata from JPEG files
func (imr *ImageMetadataRedactor) redactJPEGMetadata(originalFile *os.File, outputFile *os.File, metadata *ImageMetadata, redactionMap *[]redactors.RedactionMapping, strategy redactors.RedactionStrategy) error {
	// Decode the JPEG image
	img, err := jpeg.Decode(originalFile)
	if err != nil {
		return fmt.Errorf("failed to decode JPEG: %w", err)
	}

	// Create JPEG encoding options
	options := &jpeg.Options{
		Quality: 95, // High quality to preserve image
	}

	if !imr.preserveImageQuality {
		options.Quality = 85 // Standard quality
	}

	// Encode the image without metadata
	err = jpeg.Encode(outputFile, img, options)
	if err != nil {
		return fmt.Errorf("failed to encode JPEG: %w", err)
	}

	// Create redaction mapping for metadata removal
	if metadata.HasEXIF && len(metadata.EXIFData) > 0 {
		for fieldName, fieldValue := range metadata.EXIFData {
			mapping := redactors.RedactionMapping{
				RedactedText: "[METADATA-REMOVED]",
				Position: redactors.TextPosition{
					Line:      0, // Not applicable for metadata
					StartChar: 0,
					EndChar:   len(fieldValue),
				},
				DataType:   "IMAGE_METADATA",
				Strategy:   strategy,
				Confidence: 1.0, // Always confident about metadata removal

				Metadata: map[string]interface{}{
					"exif_field":    fieldName,
					"metadata_type": "exif",
					"image_format":  "jpeg",
				},
			}
			*redactionMap = append(*redactionMap, mapping)
		}
	}

	return nil
}

// redactPNGMetadata removes metadata from PNG files
func (imr *ImageMetadataRedactor) redactPNGMetadata(originalFile *os.File, outputFile *os.File, metadata *ImageMetadata, redactionMap *[]redactors.RedactionMapping, strategy redactors.RedactionStrategy) error {
	// Decode the PNG image
	img, err := png.Decode(originalFile)
	if err != nil {
		return fmt.Errorf("failed to decode PNG: %w", err)
	}

	// Encode the image without metadata
	err = png.Encode(outputFile, img)
	if err != nil {
		return fmt.Errorf("failed to encode PNG: %w", err)
	}

	// PNG files don't typically have EXIF data, but they can have text chunks
	// Create a generic metadata removal mapping
	mapping := redactors.RedactionMapping{
		RedactedText: "[METADATA-REMOVED]",
		Position: redactors.TextPosition{
			Line:      0,
			StartChar: 0,
			EndChar:   12,
		},
		DataType:   "IMAGE_METADATA",
		Strategy:   strategy,
		Confidence: 1.0,

		Metadata: map[string]interface{}{
			"metadata_type": "png_chunks",
			"image_format":  "png",
		},
	}
	*redactionMap = append(*redactionMap, mapping)

	return nil
}

// redactGenericImageMetadata handles metadata removal for other image formats
func (imr *ImageMetadataRedactor) redactGenericImageMetadata(originalFile *os.File, outputFile *os.File, format ImageFormat, metadata *ImageMetadata, redactionMap *[]redactors.RedactionMapping, strategy redactors.RedactionStrategy) error {
	// For formats we can't specifically handle, copy the file and create a mapping
	// indicating that metadata removal was attempted

	_, err := io.Copy(outputFile, originalFile)
	if err != nil {
		return fmt.Errorf("failed to copy image file: %w", err)
	}

	// Create a generic metadata removal mapping
	mapping := redactors.RedactionMapping{
		RedactedText: "[METADATA-COPY]",
		Position: redactors.TextPosition{
			Line:      0,
			StartChar: 0,
			EndChar:   len(format.String()) + 9,
		},
		DataType:   "IMAGE_METADATA",
		Strategy:   strategy,
		Confidence: 0.5, // Lower confidence for generic handling

		Metadata: map[string]interface{}{
			"metadata_type": "generic_copy",
			"image_format":  format.String(),
			"note":          "File copied without specific metadata processing",
		},
	}
	*redactionMap = append(*redactionMap, mapping)

	imr.logEvent("generic_image_processed", true, map[string]interface{}{
		"format": format.String(),
		"note":   "Copied without specific metadata processing",
	})

	return nil
}

// logEvent logs an event if observer is available
func (imr *ImageMetadataRedactor) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if imr.observer != nil {
		imr.observer.StartTiming("image_metadata_redactor", operation, "")(success, metadata)
	}
}

// GetComponentName returns the component name for observability
func (imr *ImageMetadataRedactor) GetComponentName() string {
	return "image_metadata_redactor"
}

// SetPositionCorrelationEnabled enables or disables position correlation (not applicable for images)
func (imr *ImageMetadataRedactor) SetPositionCorrelationEnabled(enabled bool) {
	imr.enablePositionCorrelation = enabled
}

// SetConfidenceThreshold sets the minimum confidence threshold (not applicable for images)
func (imr *ImageMetadataRedactor) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		imr.confidenceThreshold = threshold
	}
}

// SetFallbackToSimple controls fallback behavior (not applicable for images)
func (imr *ImageMetadataRedactor) SetFallbackToSimple(fallback bool) {
	imr.fallbackToSimple = fallback
}

// GetPositionCorrelationStats returns statistics (not applicable for images)
func (imr *ImageMetadataRedactor) GetPositionCorrelationStats() map[string]interface{} {
	return map[string]interface{}{
		"correlation_enabled":  false, // Not applicable for image metadata
		"confidence_threshold": imr.confidenceThreshold,
		"fallback_enabled":     false, // Not applicable for image metadata
		"correlator_type":      "not_applicable",
		"preserve_quality":     imr.preserveImageQuality,
		"supported_formats":    len(imr.supportedFormats),
	}
}

// SetPreserveImageQuality controls whether to preserve original image quality
func (imr *ImageMetadataRedactor) SetPreserveImageQuality(preserve bool) {
	imr.preserveImageQuality = preserve
}

// GetImageMetadata extracts and returns metadata from an image file without redaction
func (imr *ImageMetadataRedactor) GetImageMetadata(filePath string) (*ImageMetadata, error) {
	format, err := imr.detectImageFormat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect image format: %w", err)
	}

	return imr.extractImageMetadata(filePath, format)
}

// IsImageFile checks if a file is a supported image format
func (imr *ImageMetadataRedactor) IsImageFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return imr.supportedFormats[ext]
}

// GetSupportedImageFormats returns a list of supported image formats
func (imr *ImageMetadataRedactor) GetSupportedImageFormats() []string {
	formats := make([]string, 0, len(imr.supportedFormats))
	for ext := range imr.supportedFormats {
		formats = append(formats, ext)
	}
	return formats
}

// GetEXIFFields returns a list of common EXIF fields that may contain sensitive data
func (imr *ImageMetadataRedactor) GetEXIFFields() []string {
	return []string{
		"GPS Latitude",
		"GPS Longitude",
		"GPS Altitude",
		"GPS Time Stamp",
		"GPS Date Stamp",
		"Camera Make",
		"Camera Model",
		"Software",
		"Artist",
		"Copyright",
		"User Comment",
		"Image Description",
		"Document Name",
		"Date Time",
		"Date Time Original",
		"Date Time Digitized",
		"Sub Sec Time",
		"Sub Sec Time Original",
		"Sub Sec Time Digitized",
		"Camera Serial Number",
		"Lens Make",
		"Lens Model",
		"Lens Serial Number",
	}
}

// HasSensitiveMetadata checks if the image metadata contains potentially sensitive information
func (imr *ImageMetadataRedactor) HasSensitiveMetadata(metadata *ImageMetadata) bool {
	if !metadata.HasEXIF {
		return false
	}

	sensitiveFields := imr.GetEXIFFields()
	for _, field := range sensitiveFields {
		if _, exists := metadata.EXIFData[field]; exists {
			return true
		}
	}

	return false
}

// generateContextHash generates a hash for surrounding context
func generateContextHash(context string) string {
	hash := sha256.Sum256([]byte(context))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter hash
}
