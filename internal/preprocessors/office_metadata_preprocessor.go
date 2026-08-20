// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
	meta_extract_officelib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-officelib"
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
	embeddedText, embeddedSections, embeddedWarnings := omp.processEmbeddedMedia(filePath)

	// Declare this extractor's own structure out of band. The container's own
	// property block is one office_metadata section; each embedded item is its own
	// section carrying the rule set of whichever extractor read it (a .wav's
	// "Artist:" field is on the audio list, not the office one).
	//
	// Built here rather than in the router because only this function knows the
	// split point: the router sees one opaque string from this preprocessor.
	sections := []ContentSection{{
		Name:       omp.GetName(),
		Kind:       SectionKindMetadata,
		Type:       ProcessorTypeOfficeMetadata,
		SourceFile: filePath,
		Text:       text,
		LineOffset: 0,
	}}
	if embeddedText != "" {
		// The embedded sections were anchored relative to embeddedText, which is
		// appended after the property block.
		shift := strings.Count(text, "\n")
		for _, s := range embeddedSections {
			s.LineOffset += shift
			sections = append(sections, s)
		}
		text += embeddedText
	}

	// Log successful processing
	omp.LogSuccessfulProcessing(meta.Filename, meta.FileSize, meta.MimeType)

	content := omp.BuildSuccessContent(filePath, text, "office_metadata", meta.PageCount)

	// Surface embedded items we declined to descend into.
	//
	// ExtractionWarning is the channel that survives FileRouter's combine step -- it is
	// gathered regardless of a preprocessor's error, unlike Error itself. Hitting the
	// nesting bound means that item's content was never examined, so it has to reach
	// the operator; a bound that truncates silently just relocates the gap it was added
	// to close (#297).
	if len(embeddedWarnings) > 0 {
		if content.ExtractionWarning != "" {
			content.ExtractionWarning += "; "
		}
		content.ExtractionWarning += strings.Join(embeddedWarnings, "; ")
	}
	content.Sections = sections
	return content, nil
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
		// Sorted, not map order: see FormatPropertiesMap. Purview/SharePoint
		// labelled documents carry a dozen-plus sibling keys here, so a random
		// permutation moves every line below this block.
		customKeys := make([]string, 0, len(meta.CustomProps))
		for key := range meta.CustomProps {
			customKeys = append(customKeys, key)
		}
		sort.Strings(customKeys)
		for _, key := range customKeys {
			result.WriteString(formatter.FormatMetadataField("Custom_"+key, meta.CustomProps[key]))
		}
	}

	// Additional properties (excluding already displayed ones)
	excludeKeys := []string{"CreationDate", "ModificationDate", "Template"}
	result.WriteString(formatter.FormatPropertiesMap(meta.Properties, excludeKeys))

	return result.String()
}

// processEmbeddedMedia processes embedded media through router integration,
// returning the text to append and the out-of-band sections describing it.
func (omp *OfficeMetadataPreprocessor) processEmbeddedMedia(filePath string) (string, []ContentSection, []string) {
	// Extract embedded media for processing
	embeddedMedia, notExamined, err := meta_extract_officelib.ExtractEmbeddedMediaForProcessing(filePath)
	if err != nil {
		// The only error here is "this file is not a ZIP", and processOfficeMetadata has
		// already called ExtractMetadata on the same path, which opens the same archive and
		// returns an error content for exactly that case. So the file is reported as
		// unparseable through its own channel and there is nothing left to disclose here.
		return "", nil, nil
	}
	// A part that could not be extracted is disclosed even when NOTHING extracted.
	//
	// The early return used to cover len(embeddedMedia) == 0 as well, which threw the
	// notes away in precisely the case that matters most: a document whose only embedded
	// part is the one refused for size leaves an empty media slice, so the refusal was
	// dropped one line after being detected. Measured before this: 0 findings, exit 0,
	// exit 0 again under --fail-on-incomplete, nothing on stderr, while the same inner
	// document under the cap reported its SSN at HIGH 100. See #374.
	if len(embeddedMedia) == 0 {
		return "", nil, notExamined
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
	text, sections, warnings := omp.ProcessEmbeddedMedia(filePath, baseEmbeddedMedia)

	// Extraction refusals first, then the descent's own warnings. Both are the same kind
	// of statement — "this item's content was not examined" — and they are joined by the
	// caller into one ExtractionWarning, so ordering them puts the parts that never
	// reached the router ahead of the ones that reached it and were declined.
	return text, sections, append(notExamined, warnings...)
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (omp *OfficeMetadataPreprocessor) GetSupportedExtensions() []string {
	return omp.GetUtilities().ExtensionValidator.GetOfficeExtensions()
}

// SetObserver sets the observability component
func (omp *OfficeMetadataPreprocessor) SetObserver(observer observability.Observer) {
	omp.BaseMetadataPreprocessor.SetObserver(observer)
}

// SetRouter sets the router instance for reprocessing embedded media
func (omp *OfficeMetadataPreprocessor) SetRouter(router RouterInterface) {
	omp.BaseMetadataPreprocessor.SetRouter(router)
}
