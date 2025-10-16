// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"fmt"
	"path/filepath"
	"strings"

	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
)

// ContentRouter intelligently separates metadata from document body content
type ContentRouter struct {
	observer   *observability.StandardObserver
	fileRouter *FileRouter // Reference to FileRouter for file type detection
}

// RoutedContent represents content that has been separated into document body and metadata
type RoutedContent struct {
	DocumentBody string            // Combined plain text + document text
	Metadata     []MetadataContent // Separated metadata by preprocessor
	OriginalPath string
}

// MetadataContent represents metadata content with preprocessor context
type MetadataContent struct {
	Content          string                 // The actual metadata content
	PreprocessorType string                 // "image_metadata", "document_metadata", etc.
	PreprocessorName string                 // Human-readable name
	SourceFile       string                 // Original file path
	Metadata         map[string]interface{} // Additional metadata about the content
}

// ContentRouterError represents errors that occur during content routing
type ContentRouterError struct {
	Operation string
	FilePath  string
	Cause     error
}

func (e *ContentRouterError) Error() string {
	return fmt.Sprintf("content router %s failed for %s: %v", e.Operation, e.FilePath, e.Cause)
}

// Preprocessor type constants for identification
const (
	PreprocessorTypeImageMetadata    = "image_metadata"
	PreprocessorTypeDocumentMetadata = "document_metadata"
	PreprocessorTypeOfficeMetadata   = "office_metadata"
	PreprocessorTypeAudioMetadata    = "audio_metadata"
	PreprocessorTypeVideoMetadata    = "video_metadata"
	PreprocessorTypePlainText        = "plain_text"
	PreprocessorTypeDocumentText     = "document_text"
	PreprocessorTypeMixedContent     = "mixed_content"
)

// NewContentRouter creates a new content router
func NewContentRouter() *ContentRouter {
	return &ContentRouter{}
}

// NewContentRouterWithFileRouter creates a new content router with FileRouter reference
func NewContentRouterWithFileRouter(fileRouter *FileRouter) *ContentRouter {
	return &ContentRouter{
		fileRouter: fileRouter,
	}
}

// SetFileRouter sets the FileRouter reference for metadata capability detection
func (cr *ContentRouter) SetFileRouter(fileRouter *FileRouter) {
	cr.fileRouter = fileRouter
}

// SetObserver sets the observability component
func (cr *ContentRouter) SetObserver(observer *observability.StandardObserver) {
	cr.observer = observer
}

// RouteContent separates and routes content to appropriate validators
func (cr *ContentRouter) RouteContent(processedContent *preprocessors.ProcessedContent) (*RoutedContent, error) {
	// Check for nil input first
	if processedContent == nil {
		err := &ContentRouterError{
			Operation: "route_content",
			FilePath:  "unknown",
			Cause:     fmt.Errorf("processed content is nil"),
		}
		// Start timing with unknown path for nil input
		if cr.observer != nil {
			finishTiming := cr.observer.StartTiming("content_router", "route_content", "unknown")
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, err
	}

	// Now we can safely access processedContent fields
	var finishTiming func(bool, map[string]interface{})
	if cr.observer != nil {
		finishTiming = cr.observer.StartTiming("content_router", "route_content", processedContent.OriginalPath)
	}

	// Initialize routed content
	routedContent := &RoutedContent{
		OriginalPath: processedContent.OriginalPath,
		Metadata:     make([]MetadataContent, 0),
	}

	// Check if file can contain metadata using FileRouter
	if cr.fileRouter != nil && !cr.fileRouter.CanContainMetadata(processedContent.OriginalPath) {
		// Skip metadata content creation entirely for non-metadata files
		routedContent.DocumentBody = processedContent.Text

		// Debug logging for file type filtering decision
		if cr.observer != nil && cr.observer.DebugObserver != nil {
			ext := strings.ToLower(filepath.Ext(processedContent.OriginalPath))
			cr.observer.DebugObserver.LogDetail("file_type_filtering",
				fmt.Sprintf("Metadata validation skipped - File: %s, Extension: %s, Reason: file type does not support metadata",
					filepath.Base(processedContent.OriginalPath), ext))
		}

		if finishTiming != nil {
			finishTiming(true, map[string]interface{}{
				"metadata_skipped":     true,
				"reason":               "file_type_no_metadata",
				"document_body_length": len(routedContent.DocumentBody),
				"metadata_items":       0,
				"file_extension":       strings.ToLower(filepath.Ext(processedContent.OriginalPath)),
			})
		}

		return routedContent, nil
	}

	// Determine preprocessor type and route accordingly
	preprocessorType := cr.identifyPreprocessorType(processedContent)

	switch preprocessorType {
	case PreprocessorTypeImageMetadata, PreprocessorTypeDocumentMetadata, PreprocessorTypeOfficeMetadata,
		PreprocessorTypeAudioMetadata, PreprocessorTypeVideoMetadata:
		// This is metadata content - extract and route to metadata validator
		metadataContent, err := cr.extractMetadataContent(processedContent, preprocessorType)
		if err != nil {
			// Graceful degradation - log error but continue
			if cr.observer != nil {
				cr.observer.LogOperation(observability.StandardObservabilityData{
					Component: "content_router",
					Operation: "extract_metadata",
					FilePath:  processedContent.OriginalPath,
					Success:   false,
					Error:     err.Error(),
				})
			}
		} else {
			routedContent.Metadata = append(routedContent.Metadata, *metadataContent)
		}

		// No document body content for pure metadata
		routedContent.DocumentBody = ""

	case PreprocessorTypePlainText, PreprocessorTypeDocumentText:
		// This is document body content - route to document validators
		routedContent.DocumentBody = processedContent.Text

	case "combined_preprocessors":
		// This is combined output from multiple preprocessors - separate them
		documentBody, metadataItems, err := cr.separateMixedContent(processedContent)
		if err != nil {
			// Graceful degradation - treat as document body content
			if cr.observer != nil {
				cr.observer.LogOperation(observability.StandardObservabilityData{
					Component: "content_router",
					Operation: "separate_combined_preprocessors",
					FilePath:  processedContent.OriginalPath,
					Success:   false,
					Error:     err.Error(),
				})
			}
			routedContent.DocumentBody = processedContent.Text
		} else {
			routedContent.DocumentBody = documentBody
			routedContent.Metadata = metadataItems
		}

	default:
		// Mixed content or unknown type - attempt to separate
		documentBody, metadataItems, err := cr.separateMixedContent(processedContent)
		if err != nil {
			// Graceful degradation - treat as document body content
			if cr.observer != nil {
				cr.observer.LogOperation(observability.StandardObservabilityData{
					Component: "content_router",
					Operation: "separate_mixed_content",
					FilePath:  processedContent.OriginalPath,
					Success:   false,
					Error:     err.Error(),
				})
			}
			routedContent.DocumentBody = processedContent.Text
		} else {
			routedContent.DocumentBody = documentBody
			routedContent.Metadata = metadataItems
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"preprocessor_type":    preprocessorType,
			"document_body_length": len(routedContent.DocumentBody),
			"metadata_items":       len(routedContent.Metadata),
		})
	}

	return routedContent, nil
}

// identifyPreprocessorType determines the type of preprocessor that generated the content
func (cr *ContentRouter) identifyPreprocessorType(processedContent *preprocessors.ProcessedContent) string {
	// Check ProcessorType field first
	if processedContent.ProcessorType != "" {
		// Handle combined processor types (e.g., "pdf_metadata+text")
		if strings.Contains(processedContent.ProcessorType, "+") {
			return "combined_preprocessors"
		}

		switch strings.ToLower(processedContent.ProcessorType) {
		case "image_metadata", "image-metadata", "imagemetadata":
			return PreprocessorTypeImageMetadata
		case "document_metadata", "document-metadata", "documentmetadata":
			return PreprocessorTypeDocumentMetadata
		case "pdf_metadata", "pdf-metadata", "pdfmetadata":
			return PreprocessorTypeDocumentMetadata
		case "office_metadata", "office-metadata", "officemetadata":
			return PreprocessorTypeOfficeMetadata
		case "audio_metadata", "audio-metadata", "audiometadata":
			return PreprocessorTypeAudioMetadata
		case "video_metadata", "video-metadata", "videometadata":
			return PreprocessorTypeVideoMetadata
		case "plain_text", "plain-text", "plaintext":
			return PreprocessorTypePlainText
		case "document_text", "document-text", "documenttext":
			return PreprocessorTypeDocumentText
		case "mixed":
			return PreprocessorTypeMixedContent
		}
	}

	// Analyze content patterns to identify type
	content := processedContent.Text
	if content == "" {
		return PreprocessorTypePlainText
	}

	// Check for metadata section markers
	if cr.containsMetadataSections(content) {
		return PreprocessorTypeMixedContent
	}

	// Check for specific metadata patterns
	if cr.containsImageMetadataPatterns(content) {
		return PreprocessorTypeImageMetadata
	}

	if cr.containsAudioMetadataPatterns(content) {
		return PreprocessorTypeAudioMetadata
	}

	if cr.containsVideoMetadataPatterns(content) {
		return PreprocessorTypeVideoMetadata
	}

	if cr.containsDocumentMetadataPatterns(content) {
		return PreprocessorTypeDocumentMetadata
	}

	// Default to plain text if no specific patterns found
	return PreprocessorTypePlainText
}

// extractMetadataContent creates a MetadataContent struct from processed content
func (cr *ContentRouter) extractMetadataContent(processedContent *preprocessors.ProcessedContent, preprocessorType string) (*MetadataContent, error) {
	if processedContent.Text == "" {
		return nil, fmt.Errorf("no content to extract")
	}

	// Create human-readable preprocessor name
	preprocessorName := cr.getPreprocessorName(preprocessorType)

	metadataContent := &MetadataContent{
		Content:          processedContent.Text,
		PreprocessorType: preprocessorType,
		PreprocessorName: preprocessorName,
		SourceFile:       processedContent.OriginalPath,
		Metadata: map[string]interface{}{
			"processor_type": processedContent.ProcessorType,
			"format":         processedContent.Format,
			"success":        processedContent.Success,
		},
	}

	// Add additional metadata if available
	if processedContent.Metadata != nil {
		for key, value := range processedContent.Metadata {
			metadataContent.Metadata[key] = value
		}
	}

	return metadataContent, nil
}

// separateMixedContent separates mixed content into document body and metadata sections
func (cr *ContentRouter) separateMixedContent(processedContent *preprocessors.ProcessedContent) (string, []MetadataContent, error) {
	content := processedContent.Text

	// First, check if this is combined preprocessor output from file router
	if cr.isCombinedPreprocessorOutput(processedContent) {
		return cr.separateCombinedPreprocessorOutput(processedContent)
	}

	var documentBody strings.Builder
	var metadataItems []MetadataContent

	// Split content by lines for processing
	lines := strings.Split(content, "\n")
	currentSection := ""
	var currentMetadataLines []string
	inMetadataSection := false

	for _, line := range lines {
		// Check for metadata section markers
		if metadataSection := cr.detectMetadataSection(line); metadataSection != "" {
			// Save previous section if it was metadata
			if inMetadataSection && currentSection != "" && len(currentMetadataLines) > 0 {
				// Extract embedded media path from the first line of the previous section
				sourceFile := processedContent.OriginalPath
				if len(currentMetadataLines) > 0 {
					sourceFile = cr.extractEmbeddedMediaPath(currentMetadataLines[0], processedContent.OriginalPath)
				}
				metadataContent := cr.createMetadataFromLines(currentMetadataLines, currentSection, sourceFile)
				if metadataContent != nil {
					metadataItems = append(metadataItems, *metadataContent)
				}
			}

			// Start new metadata section
			currentSection = metadataSection
			currentMetadataLines = []string{line}
			inMetadataSection = true
			continue
		}

		// Determine if this line should be added to document body or metadata
		addToDocumentBody := false

		if inMetadataSection {
			// Check if this line ends the metadata section BEFORE adding it to metadata
			isEndMarker := cr.isMetadataSectionEnd(line)
			if isEndMarker {
				// End the current metadata section
				sourceFile := processedContent.OriginalPath
				if len(currentMetadataLines) > 0 {
					sourceFile = cr.extractEmbeddedMediaPath(currentMetadataLines[0], processedContent.OriginalPath)
				}
				metadataContent := cr.createMetadataFromLines(currentMetadataLines, currentSection, sourceFile)
				if metadataContent != nil {
					metadataItems = append(metadataItems, *metadataContent)
				}
				inMetadataSection = false
				currentSection = ""
				currentMetadataLines = nil
				addToDocumentBody = true
			} else {
				// Continue collecting metadata lines
				currentMetadataLines = append(currentMetadataLines, line)
			}
		} else {
			// This is document body content
			addToDocumentBody = true
		}

		// Add line to document body if determined above
		if addToDocumentBody {
			documentBody.WriteString(line)
			documentBody.WriteString("\n")
		}
	}

	// Handle any remaining metadata section
	if inMetadataSection && currentSection != "" && len(currentMetadataLines) > 0 {
		// Check if the last few lines should be treated as document content
		var finalMetadataLines []string
		var documentLines []string

		// Go through the metadata lines from the end and check if they should be document content
		for i := len(currentMetadataLines) - 1; i >= 0; i-- {
			line := currentMetadataLines[i]
			if cr.isMetadataSectionEnd(line) {
				// This line and all following lines should be document content
				documentLines = append([]string{line}, documentLines...)
			} else {
				// This line and all previous lines are metadata
				finalMetadataLines = currentMetadataLines[:i+1]
				break
			}
		}

		// If we found document lines at the end, add them to document body
		if len(documentLines) > 0 {
			for _, line := range documentLines {
				documentBody.WriteString(line)
				documentBody.WriteString("\n")
			}
		}

		// Save the remaining metadata if any
		if len(finalMetadataLines) > 0 {
			sourceFile := processedContent.OriginalPath
			if len(finalMetadataLines) > 0 {
				sourceFile = cr.extractEmbeddedMediaPath(finalMetadataLines[0], processedContent.OriginalPath)
			}
			metadataContent := cr.createMetadataFromLines(finalMetadataLines, currentSection, sourceFile)
			if metadataContent != nil {
				metadataItems = append(metadataItems, *metadataContent)
			}
		} else if len(documentLines) == 0 {
			// No document lines found, save all as metadata (original behavior)
			sourceFile := processedContent.OriginalPath
			if len(currentMetadataLines) > 0 {
				sourceFile = cr.extractEmbeddedMediaPath(currentMetadataLines[0], processedContent.OriginalPath)
			}
			metadataContent := cr.createMetadataFromLines(currentMetadataLines, currentSection, sourceFile)
			if metadataContent != nil {
				metadataItems = append(metadataItems, *metadataContent)
			}
		}
	}

	// Post-process metadata items to move obvious document content to document body
	var finalMetadataItems []MetadataContent
	for _, item := range metadataItems {
		cleanedContent, documentContent := cr.cleanMetadataContent(item.Content)
		if cleanedContent != "" {
			// Create new metadata item with cleaned content
			cleanedItem := item
			cleanedItem.Content = cleanedContent
			finalMetadataItems = append(finalMetadataItems, cleanedItem)
		}
		if documentContent != "" {
			// Add document content to document body
			if documentBody.Len() > 0 {
				documentBody.WriteString("\n\n") // Add extra newline to preserve spacing
			}
			documentBody.WriteString(documentContent)
		}
	}

	return strings.TrimSpace(documentBody.String()), finalMetadataItems, nil
}

// cleanMetadataContent separates metadata content from document content
func (cr *ContentRouter) cleanMetadataContent(content string) (string, string) {
	lines := strings.Split(content, "\n")
	var metadataLines []string
	var documentLines []string

	// Find the last metadata line by going backwards
	lastMetadataIndex := -1
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		lineTrimmed := strings.TrimSpace(line)

		// Skip empty lines at the end
		if lineTrimmed == "" {
			continue
		}

		// If this line looks like document content, everything from here to the end is document content
		if !strings.HasPrefix(lineTrimmed, "---") && cr.isMetadataSectionEnd(line) {
			// This line and all following lines are document content
			documentLines = lines[i:]
			lastMetadataIndex = i - 1
			break
		}
	}

	// If we found document content, separate it
	if lastMetadataIndex >= 0 {
		metadataLines = lines[:lastMetadataIndex+1]
	} else {
		// No document content found, all lines are metadata
		metadataLines = lines
	}

	metadataContent := strings.TrimSpace(strings.Join(metadataLines, "\n"))
	documentContent := strings.TrimSpace(strings.Join(documentLines, "\n"))

	return metadataContent, documentContent
}

// Helper methods for content analysis

// containsMetadataSections checks if content contains metadata section markers
func (cr *ContentRouter) containsMetadataSections(content string) bool {
	metadataMarkers := []string{
		"--- image_metadata ---",
		"--- document_metadata ---",
		"--- audio_metadata ---",
		"--- video_metadata ---",
		"--- Embedded Media",
		"=== METADATA ===",
		"=== IMAGE METADATA ===",
		"=== DOCUMENT METADATA ===",
	}

	contentLower := strings.ToLower(content)
	for _, marker := range metadataMarkers {
		if strings.Contains(contentLower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

// containsImageMetadataPatterns checks for image-specific metadata patterns
func (cr *ContentRouter) containsImageMetadataPatterns(content string) bool {
	imagePatterns := []string{
		"gpslatitude", "gpslongitude", "gpsaltitude",
		"camera_make", "camera_model", "exif",
		"image_width", "image_height", "orientation",
		"flash", "focal_length", "iso_speed",
	}

	contentLower := strings.ToLower(content)
	patternCount := 0
	for _, pattern := range imagePatterns {
		if strings.Contains(contentLower, pattern) {
			patternCount++
		}
	}

	// Require at least 2 image-specific patterns to classify as image metadata
	return patternCount >= 2
}

// containsAudioMetadataPatterns checks for audio-specific metadata patterns
func (cr *ContentRouter) containsAudioMetadataPatterns(content string) bool {
	audioPatterns := []string{
		"artist:", "album:", "track:", "genre:",
		"duration:", "bitrate:", "sample_rate:",
		"tpe1:", "tpe2:", "tpe3:", "tpe4:",
		"composer:", "performer:", "conductor:",
	}

	contentLower := strings.ToLower(content)
	patternCount := 0
	for _, pattern := range audioPatterns {
		if strings.Contains(contentLower, pattern) {
			patternCount++
		}
	}

	// Require at least 2 audio-specific patterns
	return patternCount >= 2
}

// containsVideoMetadataPatterns checks for video-specific metadata patterns
func (cr *ContentRouter) containsVideoMetadataPatterns(content string) bool {
	videoPatterns := []string{
		"video_codec:", "audio_codec:", "frame_rate:",
		"resolution:", "duration:", "recording_device:",
		"xyz:", "creation_time:", "encoder:",
		"major_brand:", "minor_version:",
	}

	contentLower := strings.ToLower(content)
	patternCount := 0
	for _, pattern := range videoPatterns {
		if strings.Contains(contentLower, pattern) {
			patternCount++
		}
	}

	// Require at least 2 video-specific patterns
	return patternCount >= 2
}

// containsDocumentMetadataPatterns checks for document-specific metadata patterns
func (cr *ContentRouter) containsDocumentMetadataPatterns(content string) bool {
	documentPatterns := []string{
		"author:", "creator:", "title:", "subject:",
		"keywords:", "comments:", "description:",
		"lastmodifiedby:", "manager:", "company:",
		"creation_date:", "modification_date:",
	}

	contentLower := strings.ToLower(content)
	patternCount := 0
	for _, pattern := range documentPatterns {
		if strings.Contains(contentLower, pattern) {
			patternCount++
		}
	}

	// Require at least 2 document-specific patterns
	return patternCount >= 2
}

// detectMetadataSection detects the start of a metadata section and returns its type
func (cr *ContentRouter) detectMetadataSection(line string) string {
	lineLower := strings.ToLower(strings.TrimSpace(line))

	// Check for explicit metadata section markers
	if strings.Contains(lineLower, "--- image_metadata ---") {
		return PreprocessorTypeImageMetadata
	}
	if strings.Contains(lineLower, "--- document_metadata ---") {
		return PreprocessorTypeDocumentMetadata
	}
	if strings.Contains(lineLower, "--- office_metadata ---") {
		return PreprocessorTypeOfficeMetadata
	}
	if strings.Contains(lineLower, "--- audio_metadata ---") {
		return PreprocessorTypeAudioMetadata
	}
	if strings.Contains(lineLower, "--- video_metadata ---") {
		return PreprocessorTypeVideoMetadata
	}
	if strings.Contains(lineLower, "--- embedded media") {
		// Determine type based on file extension in the line
		if strings.Contains(lineLower, ".jpg") || strings.Contains(lineLower, ".png") ||
			strings.Contains(lineLower, ".gif") || strings.Contains(lineLower, ".jpeg") {
			return PreprocessorTypeImageMetadata
		}
		if strings.Contains(lineLower, ".mp3") || strings.Contains(lineLower, ".wav") ||
			strings.Contains(lineLower, ".flac") || strings.Contains(lineLower, ".m4a") {
			return PreprocessorTypeAudioMetadata
		}
		if strings.Contains(lineLower, ".mp4") || strings.Contains(lineLower, ".mov") ||
			strings.Contains(lineLower, ".avi") || strings.Contains(lineLower, ".m4v") {
			return PreprocessorTypeVideoMetadata
		}
		// Default to image for embedded media
		return PreprocessorTypeImageMetadata
	}

	return ""
}

// extractEmbeddedMediaPath extracts the embedded media file path from a section header
func (cr *ContentRouter) extractEmbeddedMediaPath(line, originalPath string) string {
	// Look for patterns like "--- Embedded Media 1 (image1.jpg) ---"
	lineTrimmed := strings.TrimSpace(line)

	// Find the filename in parentheses
	start := strings.Index(lineTrimmed, "(")
	end := strings.Index(lineTrimmed, ")")

	if start != -1 && end != -1 && end > start {
		mediaName := lineTrimmed[start+1 : end]
		// Extract just the filename from the media path (remove word/media/ etc.)
		justFilename := filepath.Base(mediaName)
		// Create the embedded path format: "originalfile.docx -> image1.jpg"
		return fmt.Sprintf("%s -> %s", filepath.Base(originalPath), justFilename)
	}

	// Fallback to original path if we can't extract the media name
	return originalPath
}

// isMetadataSectionEnd checks if a line marks the end of a metadata section
func (cr *ContentRouter) isMetadataSectionEnd(line string) bool {
	lineTrimmed := strings.TrimSpace(line)

	// Don't end on empty lines - metadata sections can have empty lines between fields
	if lineTrimmed == "" {
		return false
	}

	// Check for new section separators (but let the main loop handle them)
	if strings.HasPrefix(lineTrimmed, "---") {
		// This is a new section header - let the main loop detect it
		return false
	}

	// Check if this line looks like a metadata field (key: value format)
	if cr.looksLikeMetadataField(lineTrimmed) {
		return false // Continue metadata section
	}

	// Check for start of document content (common patterns)
	lineLower := strings.ToLower(lineTrimmed)
	documentStartPatterns := []string{
		"chapter", "section", "introduction", "abstract",
		"summary", "overview", "content", "body",
	}

	for _, pattern := range documentStartPatterns {
		if strings.HasPrefix(lineLower, pattern) {
			return true
		}
	}

	// If the line doesn't look like metadata and contains multiple words, it's likely document content
	// This handles cases where document content follows metadata without clear markers
	words := strings.Fields(lineTrimmed)
	if len(words) >= 3 && !cr.looksLikeMetadataField(lineTrimmed) {
		return true
	}

	return false
}

// looksLikeMetadataField checks if a line looks like a metadata field (key: value format)
func (cr *ContentRouter) looksLikeMetadataField(line string) bool {
	// Check for key: value pattern
	if strings.Contains(line, ":") && !strings.HasPrefix(line, "http") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Key should be reasonably short and not contain spaces (or very few)
			keyWords := strings.Fields(key)
			if len(keyWords) <= 3 && len(key) <= 50 && value != "" {
				return true
			}
		}
	}

	return false
}

// createMetadataFromLines creates a MetadataContent from collected lines
func (cr *ContentRouter) createMetadataFromLines(lines []string, sectionType, sourceFile string) *MetadataContent {
	if len(lines) == 0 {
		return nil
	}

	content := strings.Join(lines, "\n")
	preprocessorName := cr.getPreprocessorName(sectionType)

	return &MetadataContent{
		Content:          content,
		PreprocessorType: sectionType,
		PreprocessorName: preprocessorName,
		SourceFile:       sourceFile,
		Metadata: map[string]interface{}{
			"section_lines":  len(lines),
			"extracted_from": "mixed_content",
		},
	}
}

// getPreprocessorName returns a human-readable name for a preprocessor type
func (cr *ContentRouter) getPreprocessorName(preprocessorType string) string {
	switch preprocessorType {
	case PreprocessorTypeImageMetadata:
		return "Image Metadata Extractor"
	case PreprocessorTypeDocumentMetadata:
		return "Document Metadata Extractor"
	case PreprocessorTypeOfficeMetadata:
		return "Office Metadata Extractor"
	case PreprocessorTypeAudioMetadata:
		return "Audio Metadata Extractor"
	case PreprocessorTypeVideoMetadata:
		return "Video Metadata Extractor"
	case PreprocessorTypePlainText:
		return "Plain Text Preprocessor"
	case PreprocessorTypeDocumentText:
		return "Document Text Extractor"
	default:
		return "Unknown Preprocessor"
	}
}

// isCombinedPreprocessorOutput checks if the content is from multiple preprocessors combined by file router
func (cr *ContentRouter) isCombinedPreprocessorOutput(processedContent *preprocessors.ProcessedContent) bool {
	// Check if ProcessorType contains multiple processors (e.g., "pdf_metadata+text")
	if strings.Contains(processedContent.ProcessorType, "+") {
		return true
	}

	// Check if content contains preprocessor separator markers
	return strings.Contains(processedContent.Text, "--- ") &&
		(strings.Contains(processedContent.Text, " ---") || strings.Contains(processedContent.Text, "---\n"))
}

// separateCombinedPreprocessorOutput separates combined preprocessor output into document body and metadata
func (cr *ContentRouter) separateCombinedPreprocessorOutput(processedContent *preprocessors.ProcessedContent) (string, []MetadataContent, error) {
	content := processedContent.Text
	var documentBody strings.Builder
	var metadataItems []MetadataContent

	// Split by preprocessor separators (e.g., "--- pdf_metadata ---", "--- text ---")
	sections := cr.splitByPreprocessorSeparators(content)

	for _, section := range sections {
		if section.preprocessorName == "" {
			// Content before any separator - likely metadata
			if cr.looksLikeMetadata(section.content) {
				metadataContent := cr.createMetadataContentFromSection(section.content, "document_metadata", processedContent.OriginalPath)
				if metadataContent != nil {
					metadataItems = append(metadataItems, *metadataContent)
				}
			} else {
				documentBody.WriteString(section.content)
			}
		} else if cr.isMetadataPreprocessor(section.preprocessorName) {
			// This is metadata content - determine the correct preprocessor type
			preprocessorType := cr.determinePreprocessorTypeFromName(section.preprocessorName)
			sourceFile := processedContent.OriginalPath

			// For embedded media, extract the media file path for better source tracking
			if strings.Contains(strings.ToLower(section.preprocessorName), "embedded media") {
				sourceFile = cr.extractEmbeddedMediaPath("--- "+section.preprocessorName+" ---", processedContent.OriginalPath)
			}

			metadataContent := cr.createMetadataContentFromSection(section.content, preprocessorType, sourceFile)
			if metadataContent != nil {
				metadataItems = append(metadataItems, *metadataContent)
			}
		} else {
			// This is document body content
			documentBody.WriteString(section.content)
		}
	}

	return strings.TrimSpace(documentBody.String()), metadataItems, nil
}

// preprocessorSection represents a section of content from a specific preprocessor
type preprocessorSection struct {
	preprocessorName string
	content          string
}

// splitByPreprocessorSeparators splits content by preprocessor separator markers
func (cr *ContentRouter) splitByPreprocessorSeparators(content string) []preprocessorSection {
	var sections []preprocessorSection
	lines := strings.Split(content, "\n")

	var currentSection strings.Builder
	currentPreprocessor := ""

	for _, line := range lines {
		// Check for preprocessor separator (e.g., "--- pdf_metadata ---", "--- text ---")
		if strings.HasPrefix(line, "--- ") && strings.HasSuffix(line, " ---") {
			// Save previous section
			if currentSection.Len() > 0 {
				sections = append(sections, preprocessorSection{
					preprocessorName: currentPreprocessor,
					content:          strings.TrimSpace(currentSection.String()),
				})
				currentSection.Reset()
			}

			// Extract preprocessor name
			preprocessorName := strings.TrimSpace(line[4 : len(line)-4])
			currentPreprocessor = preprocessorName
		} else {
			// Add line to current section
			if currentSection.Len() > 0 {
				currentSection.WriteString("\n")
			}
			currentSection.WriteString(line)
		}
	}

	// Add final section
	if currentSection.Len() > 0 {
		sections = append(sections, preprocessorSection{
			preprocessorName: currentPreprocessor,
			content:          strings.TrimSpace(currentSection.String()),
		})
	}

	return sections
}

// isMetadataPreprocessor checks if a preprocessor name indicates metadata extraction
func (cr *ContentRouter) isMetadataPreprocessor(preprocessorName string) bool {
	metadataPreprocessors := []string{
		"pdf_metadata", "image_metadata", "audio_metadata", "video_metadata",
		"office_metadata", "document_metadata", "metadata",
	}

	preprocessorLower := strings.ToLower(preprocessorName)

	// Check for embedded media sections (e.g., "Embedded Media 3 (word/media/image18.jpeg)")
	if strings.Contains(preprocessorLower, "embedded media") {
		return true
	}

	for _, metaProcessor := range metadataPreprocessors {
		if strings.Contains(preprocessorLower, metaProcessor) {
			return true
		}
	}

	return false
}

// looksLikeMetadata checks if content appears to be metadata rather than document text
func (cr *ContentRouter) looksLikeMetadata(content string) bool {
	lines := strings.Split(content, "\n")
	metadataFieldCount := 0
	totalLines := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		totalLines++

		// Check for metadata field patterns (key: value)
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "http") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				// Check if key looks like a metadata field name
				if cr.isMetadataFieldName(key) {
					metadataFieldCount++
				}
			}
		}
	}

	// Consider it metadata if more than 50% of lines are metadata fields
	return totalLines > 0 && float64(metadataFieldCount)/float64(totalLines) > 0.5
}

// isMetadataFieldName checks if a string looks like a metadata field name
func (cr *ContentRouter) isMetadataFieldName(fieldName string) bool {
	fieldLower := strings.ToLower(fieldName)
	metadataFields := []string{
		"title", "author", "creator", "producer", "subject", "keywords",
		"creationdate", "modificationdate", "pagecount", "encrypted",
		"pdfversion", "application", "company", "lastmodifiedby",
		"camera", "device", "gps", "latitude", "longitude", "altitude",
		"artist", "album", "genre", "year", "track", "duration",
	}

	for _, field := range metadataFields {
		if strings.Contains(fieldLower, field) {
			return true
		}
	}

	return false
}

// determinePreprocessorTypeFromName determines the preprocessor type from the section name
func (cr *ContentRouter) determinePreprocessorTypeFromName(sectionName string) string {
	sectionLower := strings.ToLower(sectionName)

	// Check for embedded media sections
	if strings.Contains(sectionLower, "embedded media") {
		// Determine type based on file extension in the section name
		if strings.Contains(sectionLower, ".jpg") || strings.Contains(sectionLower, ".jpeg") ||
			strings.Contains(sectionLower, ".png") || strings.Contains(sectionLower, ".gif") ||
			strings.Contains(sectionLower, ".bmp") || strings.Contains(sectionLower, ".tiff") ||
			strings.Contains(sectionLower, ".webp") {
			return PreprocessorTypeImageMetadata
		}
		if strings.Contains(sectionLower, ".mp3") || strings.Contains(sectionLower, ".wav") ||
			strings.Contains(sectionLower, ".flac") || strings.Contains(sectionLower, ".m4a") {
			return PreprocessorTypeAudioMetadata
		}
		if strings.Contains(sectionLower, ".mp4") || strings.Contains(sectionLower, ".mov") ||
			strings.Contains(sectionLower, ".avi") || strings.Contains(sectionLower, ".m4v") {
			return PreprocessorTypeVideoMetadata
		}
		// Default to image for embedded media
		return PreprocessorTypeImageMetadata
	}

	// Check for specific preprocessor types
	if strings.Contains(sectionLower, "office_metadata") {
		return PreprocessorTypeOfficeMetadata
	}
	if strings.Contains(sectionLower, "pdf_metadata") {
		return PreprocessorTypeDocumentMetadata
	}
	if strings.Contains(sectionLower, "image_metadata") {
		return PreprocessorTypeImageMetadata
	}
	if strings.Contains(sectionLower, "audio_metadata") {
		return PreprocessorTypeAudioMetadata
	}
	if strings.Contains(sectionLower, "video_metadata") {
		return PreprocessorTypeVideoMetadata
	}

	// Default to document metadata
	return PreprocessorTypeDocumentMetadata
}

// createMetadataContentFromSection creates MetadataContent from a content section
func (cr *ContentRouter) createMetadataContentFromSection(content, preprocessorType, sourceFile string) *MetadataContent {
	if strings.TrimSpace(content) == "" {
		return nil
	}

	return &MetadataContent{
		Content:          content,
		PreprocessorType: preprocessorType,
		PreprocessorName: cr.getPreprocessorName(preprocessorType),
		SourceFile:       sourceFile,
		Metadata: map[string]interface{}{
			"separated_from_combined": true,
		},
	}
}
