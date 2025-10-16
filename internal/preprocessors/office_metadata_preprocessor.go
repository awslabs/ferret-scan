// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"strings"

	"ferret-scan/internal/observability"
	meta_extract_officelib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-officelib"
)

// OfficeMetadataPreprocessor extracts metadata from Office documents
type OfficeMetadataPreprocessor struct {
	*BaseMetadataPreprocessor
}

// NewOfficeMetadataPreprocessor creates a new Office metadata preprocessor
func NewOfficeMetadataPreprocessor() *OfficeMetadataPreprocessor {
	return &OfficeMetadataPreprocessor{
		BaseMetadataPreprocessor: NewBaseMetadataPreprocessor("office_metadata", "office_metadata"),
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (omp *OfficeMetadataPreprocessor) CanProcess(filePath string) bool {
	return omp.GetUtilities().ExtensionValidator.IsOfficeFile(filePath)
}

// Process extracts metadata from Office documents
func (omp *OfficeMetadataPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	return omp.ProcessWithRetry(filePath, func() (*ProcessedContent, error) {
		return omp.processOfficeMetadata(filePath)
	})
}

// processOfficeMetadata extracts metadata from Office documents with comprehensive error handling
func (omp *OfficeMetadataPreprocessor) processOfficeMetadata(filePath string) (*ProcessedContent, error) {
	// Extract metadata using the Office library
	meta, err := meta_extract_officelib.ExtractMetadata(filePath)
	if err != nil {
		return omp.BuildErrorContent(filePath, "office_metadata",
			fmt.Errorf("failed to extract Office metadata: %w", err)), err
	}

	// Log file system information for observability (excluded from validator content)
	omp.LogFileSystemInfo(meta.Filename, meta.FileSize, meta.MimeType)

	// Convert Office metadata to text format for validation
	text := omp.formatOfficeMetadata(meta)

	// Process embedded media through router if available
	embeddedText := omp.processEmbeddedMedia(filePath)
	if embeddedText != "" {
		text += embeddedText
	}

	// Log successful processing
	omp.LogSuccessfulProcessing(meta.Filename, meta.FileSize, meta.MimeType)

	return omp.BuildSuccessContent(filePath, text, "office_metadata", meta.PageCount), nil
}

// formatOfficeMetadata formats Office metadata into text format for validation
func (omp *OfficeMetadataPreprocessor) formatOfficeMetadata(meta *meta_extract_officelib.Metadata) string {
	formatter := omp.GetUtilities().Formatter
	var result strings.Builder

	// Document properties
	result.WriteString(formatter.FormatMetadataField("Title", meta.Title))
	result.WriteString(formatter.FormatMetadataField("Subject", meta.Subject))
	result.WriteString(formatter.FormatMetadataField("Author", meta.Author))

	// Only include Creator if it's different from Author
	if meta.Creator != "" && meta.Creator != meta.Author {
		result.WriteString(formatter.FormatMetadataField("Creator", meta.Creator))
	}

	result.WriteString(formatter.FormatMetadataField("Description", meta.Description))
	result.WriteString(formatter.FormatMetadataField("Keywords", meta.Keywords))
	result.WriteString(formatter.FormatMetadataField("Category", meta.Category))
	result.WriteString(formatter.FormatMetadataField("Application", meta.Application))
	result.WriteString(formatter.FormatMetadataField("ApplicationVersion", meta.AppVersion))
	result.WriteString(formatter.FormatMetadataField("Company", meta.Company))
	result.WriteString(formatter.FormatMetadataField("LastModifiedBy", meta.LastModifiedBy))
	result.WriteString(formatter.FormatMetadataField("Manager", meta.Manager))
	result.WriteString(formatter.FormatMetadataField("Comments", meta.Comments))
	result.WriteString(formatter.FormatMetadataField("ContentStatus", meta.ContentStatus))
	result.WriteString(formatter.FormatMetadataField("Identifier", meta.Identifier))
	result.WriteString(formatter.FormatMetadataField("Language", meta.Language))
	result.WriteString(formatter.FormatMetadataField("Revision", meta.Revision))

	// HIGH-RISK FIELDS: Template path (critical for security analysis)
	result.WriteString(formatter.FormatMetadataField("Template", meta.Template))

	// Dates
	result.WriteString(formatter.FormatDateField("CreationDate", meta.Created))
	result.WriteString(formatter.FormatDateField("ModificationDate", meta.Modified))

	// Document statistics
	result.WriteString(formatter.FormatNumericField("PageCount", meta.PageCount))
	result.WriteString(formatter.FormatNumericField("WordCount", meta.WordCount))
	result.WriteString(formatter.FormatNumericField("CharacterCount", meta.CharCount))

	// HIGH-RISK FIELDS: Enhanced metadata fields
	if meta.TotalEditTime != "" {
		result.WriteString(formatter.FormatMetadataField("TotalEditTime", meta.TotalEditTime))
	}
	if meta.HiddenSlides > 0 {
		result.WriteString(formatter.FormatNumericField("HiddenSlides", meta.HiddenSlides))
	}
	if meta.HyperlinksChanged {
		result.WriteString(formatter.FormatMetadataField("HyperlinksChanged", "true"))
	}
	if meta.SharedDocument {
		result.WriteString(formatter.FormatMetadataField("SharedDocument", "true"))
	}

	// HIGH-RISK FIELDS: Custom properties (critical organizational metadata)
	if len(meta.CustomProps) > 0 {
		result.WriteString("\n--- Custom Properties ---\n")
		for key, value := range meta.CustomProps {
			result.WriteString(formatter.FormatMetadataField("Custom_"+key, value))
		}
	}

	// Additional properties (excluding already displayed ones)
	excludeKeys := []string{"CreationDate", "ModificationDate", "Template"}
	result.WriteString(formatter.FormatPropertiesMap(meta.Properties, excludeKeys))

	return result.String()
}

// processEmbeddedMedia processes embedded media through router integration
func (omp *OfficeMetadataPreprocessor) processEmbeddedMedia(filePath string) string {
	// Extract embedded media for processing
	embeddedMedia, err := meta_extract_officelib.ExtractEmbeddedMediaForProcessing(filePath)
	if err != nil || len(embeddedMedia) == 0 {
		return ""
	}

	// Ensure cleanup of temporary files
	defer meta_extract_officelib.CleanupEmbeddedMedia(embeddedMedia)

	// Convert to base preprocessor format
	baseEmbeddedMedia := make([]EmbeddedMedia, len(embeddedMedia))
	for i, media := range embeddedMedia {
		baseEmbeddedMedia[i] = EmbeddedMedia{
			OriginalName: media.OriginalName,
			TempFilePath: media.TempFilePath,
			MediaType:    media.MediaType,
		}
	}

	// Process through base preprocessor's embedded media handler
	return omp.ProcessEmbeddedMedia(filePath, baseEmbeddedMedia)
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (omp *OfficeMetadataPreprocessor) GetSupportedExtensions() []string {
	return omp.GetUtilities().ExtensionValidator.GetOfficeExtensions()
}

// SetObserver sets the observability component
func (omp *OfficeMetadataPreprocessor) SetObserver(observer *observability.StandardObserver) {
	omp.BaseMetadataPreprocessor.SetObserver(observer)
}

// SetRouter sets the router instance for reprocessing embedded media
func (omp *OfficeMetadataPreprocessor) SetRouter(router RouterInterface) {
	omp.BaseMetadataPreprocessor.SetRouter(router)
}
