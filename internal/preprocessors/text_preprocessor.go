// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"path/filepath"
	"strings"

	"ferret-scan/internal/observability"
	textextractofficetextlib "ferret-scan/internal/preprocessors/text-extractors/text-extract-officetextlib"
	textextractpdftextlib "ferret-scan/internal/preprocessors/text-extractors/text-extract-pdftextlib"
)

// TextPreprocessor handles text extraction from various document formats
type TextPreprocessor struct {
	name                string
	supportedExtensions []string
	observer            *observability.StandardObserver
}

// NewTextPreprocessor creates a new text preprocessor
func NewTextPreprocessor() *TextPreprocessor {
	return &TextPreprocessor{
		name: "Text Extractor",
		supportedExtensions: []string{
			".pdf",
			".docx", ".xlsx", ".pptx",
			".odt", ".ods", ".odp",
		},
	}
}

// SetObserver sets the observability component
func (tp *TextPreprocessor) SetObserver(observer *observability.StandardObserver) {
	tp.observer = observer
}

// GetName returns the name of this preprocessor
func (tp *TextPreprocessor) GetName() string {
	return tp.name
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (tp *TextPreprocessor) GetSupportedExtensions() []string {
	return tp.supportedExtensions
}

// CanProcess checks if this preprocessor can handle the given file
func (tp *TextPreprocessor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	for _, supportedExt := range tp.supportedExtensions {
		if ext == supportedExt {
			return true
		}
	}

	return false
}

// Process extracts text content from the file
func (tp *TextPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if tp.observer != nil {
		finishTiming = tp.observer.StartTiming("text_preprocessor", "process_file", filePath)
		if tp.observer.DebugObserver != nil {
			finishStep = tp.observer.DebugObserver.StartStep("text_preprocessor", "process_file", filePath)
		}
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	content := &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		ProcessorType: tp.name,
		Success:       false,
	}

	var result *ProcessedContent
	var err error

	switch ext {
	case ".pdf":
		result, err = tp.processPDF(filePath, content)
	case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp":
		result, err = tp.processOffice(filePath, content)
	default:
		err = fmt.Errorf("unsupported file extension: %s", ext)
		content.Error = err
		result = content
	}

	if finishTiming != nil {
		success := err == nil && result != nil && result.Success
		metadata := map[string]interface{}{
			"file_ext": ext,
		}
		if success && result != nil {
			metadata["word_count"] = result.WordCount
			metadata["char_count"] = result.CharCount
			metadata["line_count"] = result.LineCount
		}
		if err != nil {
			metadata["error"] = err.Error()
		}
		finishTiming(success, metadata)
	}
	if finishStep != nil {
		if err != nil {
			finishStep(false, fmt.Sprintf("Failed to extract text: %v", err))
		} else if result != nil && result.Success {
			finishStep(true, fmt.Sprintf("Extracted text: %d words, %d lines", result.WordCount, result.LineCount))
		} else {
			finishStep(false, "Text extraction failed")
		}
	}

	return result, err
}

// processPDF extracts text from PDF documents
func (tp *TextPreprocessor) processPDF(filePath string, content *ProcessedContent) (*ProcessedContent, error) {
	pdfContent, err := textextractpdftextlib.ExtractText(filePath)
	if err != nil {
		content.Error = fmt.Errorf("failed to extract text from PDF: %w", err)
		return content, content.Error
	}

	// Map PDF content to ProcessedContent
	content.Text = pdfContent.Text
	content.Format = "PDF Document"
	content.PageCount = pdfContent.PageCount
	content.WordCount = pdfContent.WordCount
	content.CharCount = pdfContent.CharCount
	content.LineCount = pdfContent.LineCount
	content.Success = true

	// Enable position tracking for PDF documents
	content.EnablePositionTracking()
	content.SetPositionConfidence(0.8) // Good confidence for PDF text extraction

	// Create position mappings for PDF content
	tp.createPDFPositionMappings(content, pdfContent)

	return content, nil
}

// processOffice extracts text from Office documents
func (tp *TextPreprocessor) processOffice(filePath string, content *ProcessedContent) (*ProcessedContent, error) {
	officeContent, err := textextractofficetextlib.ExtractText(filePath)
	if err != nil {
		content.Error = fmt.Errorf("failed to extract text from Office document: %w", err)
		return content, content.Error
	}

	// Map Office content to ProcessedContent
	content.Text = officeContent.Text
	content.Format = officeContent.Format
	content.PageCount = officeContent.PageCount
	content.WordCount = officeContent.WordCount
	content.CharCount = officeContent.CharCount
	content.LineCount = officeContent.LineCount
	content.Paragraphs = officeContent.Paragraphs
	content.Success = true

	// Enable position tracking for Office documents
	content.EnablePositionTracking()
	content.SetPositionConfidence(0.7) // Moderate confidence for Office text extraction

	// Create position mappings for Office content
	tp.createOfficePositionMappings(content, officeContent)

	return content, nil
}

// createPDFPositionMappings creates position mappings for PDF content
func (tp *TextPreprocessor) createPDFPositionMappings(content *ProcessedContent, _ any) {
	// For now, create basic line-based mappings
	// In a real implementation, this would use the PDF structure information
	tp.createBasicLineMappings(content, "pdf_extraction")

	// Add PDF-specific metadata
	content.AddPositionMetadata("extraction_method", "pdf_text_extraction")
	content.AddPositionMetadata("page_count", content.PageCount)
	content.AddPositionMetadata("confidence_reason", "pdf_text_layer_extraction")

	if tp.observer != nil && tp.observer.DebugObserver != nil {
		tp.observer.DebugObserver.LogDetail("text_preprocessor",
			fmt.Sprintf("Created %d position mappings for PDF with %d pages",
				len(content.PositionMappings), content.PageCount))
	}
}

// createOfficePositionMappings creates position mappings for Office content
func (tp *TextPreprocessor) createOfficePositionMappings(content *ProcessedContent, _ any) {
	// For now, create basic line-based mappings
	// In a real implementation, this would use the Office document structure
	tp.createBasicLineMappings(content, "office_extraction")

	// Add Office-specific metadata
	content.AddPositionMetadata("extraction_method", "office_document_extraction")
	content.AddPositionMetadata("document_format", content.Format)
	content.AddPositionMetadata("confidence_reason", "office_xml_structure_extraction")

	if tp.observer != nil && tp.observer.DebugObserver != nil {
		tp.observer.DebugObserver.LogDetail("text_preprocessor",
			fmt.Sprintf("Created %d position mappings for %s document",
				len(content.PositionMappings), content.Format))
	}
}

// createBasicLineMappings creates basic line-based position mappings
func (tp *TextPreprocessor) createBasicLineMappings(content *ProcessedContent, method string) {
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

		// For extracted documents, we estimate the original position
		// In a real implementation, this would use document structure information
		originalPos := DocumentPosition{
			Page:       tp.estimatePageNumber(lineNum, content.LineCount, content.PageCount),
			CharOffset: CalculateAbsoluteOffset(content.Text, lineNum+1, 0),
			LineNumber: lineNum + 1,
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

// estimatePageNumber estimates which page a line belongs to
func (tp *TextPreprocessor) estimatePageNumber(lineNum, totalLines, pageCount int) int {
	if pageCount <= 1 {
		return 1
	}

	// Simple estimation: distribute lines evenly across pages
	linesPerPage := float64(totalLines) / float64(pageCount)
	estimatedPage := int(float64(lineNum)/linesPerPage) + 1

	estimatedPage = min(estimatedPage, pageCount)

	return estimatedPage
}

// getLineContext returns context around a line for position verification
func (tp *TextPreprocessor) getLineContext(lines []string, lineIndex int) string {
	contextLines := 2 // Lines before and after
	start := lineIndex - contextLines
	end := lineIndex + contextLines + 1

	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}

	contextLinesSlice := lines[start:end]
	return strings.Join(contextLinesSlice, "\n")
}
