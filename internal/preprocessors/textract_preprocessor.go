// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

// GENAI_DISABLED: This entire file has been disabled as part of GenAI feature removal
// The textract-extractor-lib dependency and AWS SDK v2 required for this functionality
// have been removed from go.mod to reduce binary size and eliminate cloud service dependencies.

/*
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ferret-scan/internal/observability"
	textract_extractor_lib "ferret-scan/internal/preprocessors/text-extractors/textract-extractor-lib"
)
*/

/*
// TextractPreprocessor handles OCR text extraction using Amazon Textract
type TextractPreprocessor struct {
	name                string
	supportedExtensions []string
	region              string
	enabled             bool
}

// NewTextractPreprocessor creates a new Textract preprocessor
func NewTextractPreprocessor(region string) *TextractPreprocessor {
	if region == "" {
		region = "us-east-1" // Default region
	}

	return &TextractPreprocessor{
		name:   "Amazon Textract OCR",
		region: region,
		supportedExtensions: []string{
			".pdf", ".png", ".jpg", ".jpeg", ".tiff", ".tif",
		},
		enabled: true,
	}
}

// GetName returns the name of this preprocessor
func (tp *TextractPreprocessor) GetName() string {
	return tp.name
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (tp *TextractPreprocessor) GetSupportedExtensions() []string {
	return tp.supportedExtensions
}

// CanProcess checks if this preprocessor can handle the given file
func (tp *TextractPreprocessor) CanProcess(filePath string) bool {
	if !tp.enabled {
		return false
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	for _, supportedExt := range tp.supportedExtensions {
		if ext == supportedExt {
			return textract_extractor_lib.IsSupportedFileType(filePath)
		}
	}
	return false
}

// Process extracts text content from the file using Amazon Textract
func (tp *TextractPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Textract Process() called for: %s\n", filepath.Base(filePath))
	}

	content := &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		ProcessorType: tp.name,
		Success:       false,
	}

	// Check if AWS credentials are available
	if err := textract_extractor_lib.ValidateAWSCredentials(tp.region); err != nil {
		content.Error = fmt.Errorf("AWS credentials validation failed: %w", err)
		return content, content.Error
	}

	// Estimate cost and warn user
	if cost, err := textract_extractor_lib.EstimateTextractCost(filePath); err == nil {
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[DEBUG] Textract estimated cost for %s: $%.4f\n", filepath.Base(filePath), cost)
		}
	}

	// Extract text using Textract
	textractContent, err := textract_extractor_lib.ExtractText(filePath, tp.region)
	if err != nil {
		content.Error = fmt.Errorf("Textract extraction failed: %w", err)
		return content, content.Error
	}

	// Map Textract content to ProcessedContent
	content.Text = textractContent.Text
	content.Format = textractContent.DocumentType
	content.PageCount = textractContent.PageCount
	content.WordCount = textractContent.WordCount
	content.CharCount = textractContent.CharCount
	content.LineCount = textractContent.LineCount
	content.Success = true

	// Enable position tracking for Textract OCR
	content.EnablePositionTracking()
	content.SetPositionConfidence(0.9) // High confidence for Textract OCR

	// Create position mappings for Textract content
	tp.createTextractPositionMappings(content, textractContent)

	return content, nil
}

// SetRegion updates the AWS region for Textract calls
func (tp *TextractPreprocessor) SetRegion(region string) {
	tp.region = region
}

// GetRegion returns the current AWS region
func (tp *TextractPreprocessor) GetRegion() string {
	return tp.region
}

// SetEnabled enables or disables the Textract preprocessor
func (tp *TextractPreprocessor) SetEnabled(enabled bool) {
	tp.enabled = enabled
}

// IsEnabled returns whether the Textract preprocessor is enabled
func (tp *TextractPreprocessor) IsEnabled() bool {
	return tp.enabled
}

// SetObserver sets the observability component (minimal implementation)
func (tp *TextractPreprocessor) SetObserver(observer *observability.StandardObserver) {
	// Minimal implementation for interface compliance
}

// createTextractPositionMappings creates position mappings for Textract OCR content
func (tp *TextractPreprocessor) createTextractPositionMappings(content *ProcessedContent, textractContent interface{}) {
	// For now, create basic line-based mappings
	// In a real implementation, this would use Textract's bounding box information
	tp.createOCRLineMappings(content, "textract_ocr")

	// Add Textract-specific metadata
	content.AddPositionMetadata("extraction_method", "amazon_textract_ocr")
	content.AddPositionMetadata("aws_region", tp.region)
	content.AddPositionMetadata("confidence_reason", "textract_bounding_box_coordinates")
	content.AddPositionMetadata("ocr_engine", "amazon_textract")

	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Created %d position mappings for Textract OCR with %d pages\n",
			len(content.PositionMappings), content.PageCount)
	}
}

// createOCRLineMappings creates position mappings for OCR-extracted content
func (tp *TextractPreprocessor) createOCRLineMappings(content *ProcessedContent, method string) {
	lines := splitLines(content.Text)

	for lineNum, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue // Skip empty lines
		}

		// Create a mapping for each non-empty line
		extractedPos := TextPosition{
			Line:           lineNum + 1,
			StartChar:      0,
			EndChar:        len(line),
			AbsoluteOffset: CalculateAbsoluteOffset(content.Text, lineNum+1, 0),
		}

		// For OCR content, we estimate the original position based on page layout
		// In a real implementation, this would use Textract's bounding box coordinates
		originalPos := DocumentPosition{
			Page:       tp.estimatePageNumber(lineNum, content.LineCount, content.PageCount),
			CharOffset: CalculateAbsoluteOffset(content.Text, lineNum+1, 0),
			LineNumber: lineNum + 1,
			// In a real implementation, we would include bounding box from Textract
			BoundingBox: &BoundingBox{
				X:      0.0,                     // Would be from Textract bounding box
				Y:      float64(lineNum) * 0.02, // Estimated line height
				Width:  1.0,                     // Would be from Textract bounding box
				Height: 0.02,                    // Estimated line height
				Unit:   "normalized",
			},
		}

		mapping := PositionMapping{
			ExtractedPosition: extractedPos,
			OriginalPosition:  originalPos,
			ConfidenceScore:   content.PositionConfidence,
			Context:           tp.getLineContext(lines, lineNum),
			Method:            method,
		}

		content.AddPositionMapping(mapping)
	}
}

// estimatePageNumber estimates which page a line belongs to for OCR content
func (tp *TextractPreprocessor) estimatePageNumber(lineNum, totalLines, pageCount int) int {
	if pageCount <= 1 {
		return 1
	}

	// Simple estimation: distribute lines evenly across pages
	linesPerPage := float64(totalLines) / float64(pageCount)
	estimatedPage := int(float64(lineNum)/linesPerPage) + 1

	if estimatedPage > pageCount {
		estimatedPage = pageCount
	}

	return estimatedPage
}

// getLineContext returns context around a line for position verification
func (tp *TextractPreprocessor) getLineContext(lines []string, lineIndex int) string {
	contextLines := 2 // Lines before and after
	start := lineIndex - contextLines
	end := lineIndex + contextLines + 1

	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}

	contextLines_slice := lines[start:end]
	return strings.Join(contextLines_slice, "\n")
}
*/
