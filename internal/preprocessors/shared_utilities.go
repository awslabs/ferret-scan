// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// MetadataFormatter provides common metadata formatting functions
type MetadataFormatter struct{}

// NewMetadataFormatter creates a new metadata formatter
func NewMetadataFormatter() *MetadataFormatter {
	return &MetadataFormatter{}
}

// FormatMetadataField formats a metadata field with proper key-value formatting
func (mf *MetadataFormatter) FormatMetadataField(key, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s: %s\n", key, value)
}

// FormatDateField formats a date field with consistent formatting
func (mf *MetadataFormatter) FormatDateField(key string, date time.Time) string {
	if date.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s: %s\n", key, date.Format("2006:01:02 15:04:05-07:00"))
}

// FormatNumericField formats a numeric field, only including it if greater than zero
func (mf *MetadataFormatter) FormatNumericField(key string, value int) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%s: %d\n", key, value)
}

// FormatBooleanField formats a boolean field, only including it if true
func (mf *MetadataFormatter) FormatBooleanField(key string, value bool) string {
	if !value {
		return ""
	}
	return fmt.Sprintf("%s: true\n", key)
}

// FormatPropertiesMap formats a map of additional properties
func (mf *MetadataFormatter) FormatPropertiesMap(properties map[string]string, excludeKeys []string) string {
	var result strings.Builder

	// Create exclusion map for faster lookup
	exclude := make(map[string]bool)
	for _, key := range excludeKeys {
		exclude[key] = true
	}

	for key, value := range properties {
		if !exclude[key] && value != "" {
			result.WriteString(mf.FormatMetadataField(key, value))
		}
	}

	return result.String()
}

// CalculateTextMetrics calculates word count, character count, and line count for text
func (mf *MetadataFormatter) CalculateTextMetrics(text string) (wordCount, charCount, lineCount int) {
	wordCount = len(strings.Fields(text))
	charCount = len(text)
	lineCount = len(strings.Split(text, "\n"))
	return
}

// FileExtensionValidator provides common file extension validation functions
type FileExtensionValidator struct {
	imageExtensions  map[string]bool
	pdfExtensions    map[string]bool
	officeExtensions map[string]bool
	audioExtensions  map[string]bool
	videoExtensions  map[string]bool
}

// NewFileExtensionValidator creates a new file extension validator
func NewFileExtensionValidator() *FileExtensionValidator {
	return &FileExtensionValidator{
		imageExtensions: map[string]bool{
			".jpg":  true,
			".jpeg": true,
			".tiff": true,
			".tif":  true,
			".png":  true,
			".gif":  true,
			".bmp":  true,
			".webp": true,
		},
		pdfExtensions: map[string]bool{
			".pdf": true,
		},
		officeExtensions: map[string]bool{
			".docx": true,
			".xlsx": true,
			".pptx": true,
			".odt":  true,
			".ods":  true,
			".odp":  true,
		},
		audioExtensions: map[string]bool{
			".mp3":  true,
			".flac": true,
			".wav":  true,
			".m4a":  true,
		},
		videoExtensions: map[string]bool{
			".mp4": true,
			".m4v": true,
			".mov": true,
		},
	}
}

// IsImageFile checks if the file is an image file
func (fev *FileExtensionValidator) IsImageFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return fev.imageExtensions[ext]
}

// IsPDFFile checks if the file is a PDF file
func (fev *FileExtensionValidator) IsPDFFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return fev.pdfExtensions[ext]
}

// IsOfficeFile checks if the file is an Office document
func (fev *FileExtensionValidator) IsOfficeFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return fev.officeExtensions[ext]
}

// IsAudioFile checks if the file is an audio file
func (fev *FileExtensionValidator) IsAudioFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return fev.audioExtensions[ext]
}

// IsVideoFile checks if the file is a video file
func (fev *FileExtensionValidator) IsVideoFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return fev.videoExtensions[ext]
}

// GetImageExtensions returns all supported image extensions
func (fev *FileExtensionValidator) GetImageExtensions() []string {
	return fev.getExtensionsFromMap(fev.imageExtensions)
}

// GetPDFExtensions returns all supported PDF extensions
func (fev *FileExtensionValidator) GetPDFExtensions() []string {
	return fev.getExtensionsFromMap(fev.pdfExtensions)
}

// GetOfficeExtensions returns all supported Office extensions
func (fev *FileExtensionValidator) GetOfficeExtensions() []string {
	return fev.getExtensionsFromMap(fev.officeExtensions)
}

// GetAudioExtensions returns all supported audio extensions
func (fev *FileExtensionValidator) GetAudioExtensions() []string {
	return fev.getExtensionsFromMap(fev.audioExtensions)
}

// GetVideoExtensions returns all supported video extensions
func (fev *FileExtensionValidator) GetVideoExtensions() []string {
	return fev.getExtensionsFromMap(fev.videoExtensions)
}

// getExtensionsFromMap converts a map of extensions to a slice
func (fev *FileExtensionValidator) getExtensionsFromMap(extMap map[string]bool) []string {
	var extensions []string
	for ext := range extMap {
		extensions = append(extensions, ext)
	}
	return extensions
}

// GetFileExtension returns the lowercase file extension
func (fev *FileExtensionValidator) GetFileExtension(filePath string) string {
	return strings.ToLower(filepath.Ext(filePath))
}

// GetFileName extracts the filename from a file path
func (fev *FileExtensionValidator) GetFileName(filePath string) string {
	return filepath.Base(filePath)
}

// ProcessedContentBuilder helps build ProcessedContent structures consistently
type ProcessedContentBuilder struct {
	formatter *MetadataFormatter
}

// NewProcessedContentBuilder creates a new processed content builder
func NewProcessedContentBuilder() *ProcessedContentBuilder {
	return &ProcessedContentBuilder{
		formatter: NewMetadataFormatter(),
	}
}

// BuildSuccessContent creates a successful ProcessedContent structure
func (pcb *ProcessedContentBuilder) BuildSuccessContent(filePath, text, format, processorType string, pageCount int) *ProcessedContent {
	wordCount, charCount, lineCount := pcb.formatter.CalculateTextMetrics(text)

	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          text,
		Format:        format,
		WordCount:     wordCount,
		CharCount:     charCount,
		LineCount:     lineCount,
		PageCount:     pageCount,
		ProcessorType: processorType,
		Success:       true,
		Metadata:      make(map[string]interface{}),
	}
}

// BuildErrorContent creates a failed ProcessedContent structure
func (pcb *ProcessedContentBuilder) BuildErrorContent(filePath, format, processorType string, err error) *ProcessedContent {
	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          "",
		Format:        format,
		WordCount:     0,
		CharCount:     0,
		LineCount:     0,
		ProcessorType: processorType,
		Success:       false,
		Error:         err,
		Metadata:      make(map[string]interface{}),
	}
}

// RouterIntegrationHelper provides utilities for router integration
type RouterIntegrationHelper struct{}

// NewRouterIntegrationHelper creates a new router integration helper
func NewRouterIntegrationHelper() *RouterIntegrationHelper {
	return &RouterIntegrationHelper{}
}

// CreateEmbeddedMediaPath creates a path showing the relationship between original file and embedded media
func (rih *RouterIntegrationHelper) CreateEmbeddedMediaPath(originalFilePath, embeddedFileName string) string {
	return fmt.Sprintf("%s -> %s", filepath.Base(originalFilePath), embeddedFileName)
}

// FormatEmbeddedMediaSection formats embedded media content for inclusion in metadata text
func (rih *RouterIntegrationHelper) FormatEmbeddedMediaSection(index int, mediaName, content string) string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("\n--- Embedded Media %d (%s) ---\n", index+1, mediaName))
	result.WriteString(content)
	return result.String()
}

// SharedUtilities provides a centralized access point for all shared utilities
type SharedUtilities struct {
	Formatter          *MetadataFormatter
	ExtensionValidator *FileExtensionValidator
	ContentBuilder     *ProcessedContentBuilder
	RouterHelper       *RouterIntegrationHelper
}

// NewSharedUtilities creates a new shared utilities instance
func NewSharedUtilities() *SharedUtilities {
	return &SharedUtilities{
		Formatter:          NewMetadataFormatter(),
		ExtensionValidator: NewFileExtensionValidator(),
		ContentBuilder:     NewProcessedContentBuilder(),
		RouterHelper:       NewRouterIntegrationHelper(),
	}
}
