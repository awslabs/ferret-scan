// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ferret-scan/internal/observability"
	metaextractpdflib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-pdflib"
)

// PDFMetadataPreprocessor extracts metadata from PDF documents
type PDFMetadataPreprocessor struct {
	*BaseMetadataPreprocessor
}

// NewPDFMetadataPreprocessor creates a new PDF metadata preprocessor
func NewPDFMetadataPreprocessor() *PDFMetadataPreprocessor {
	return &PDFMetadataPreprocessor{
		BaseMetadataPreprocessor: NewBaseMetadataPreprocessor("pdf_metadata", "pdf_metadata"),
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (pmp *PDFMetadataPreprocessor) CanProcess(filePath string) bool {
	return pmp.GetUtilities().ExtensionValidator.IsPDFFile(filePath)
}

// Process extracts metadata from the PDF file
func (pmp *PDFMetadataPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	return pmp.ProcessWithRetry(filePath, func() (*ProcessedContent, error) {
		return pmp.processPDFMetadata(filePath)
	})
}

// processPDFMetadata extracts metadata from PDF documents with comprehensive error handling
func (pmp *PDFMetadataPreprocessor) processPDFMetadata(filePath string) (*ProcessedContent, error) {
	// Validate file size before processing (using standard document limits, not video limits)
	if err := pmp.ValidateFileSize(filePath, false); err != nil {
		return pmp.HandleError(filePath, "pdf", err), err
	}

	// Create processing context with timeout
	ctx, cancel := pmp.CreateProcessingContext()
	defer cancel()

	// Extract metadata using the PDF library with context monitoring
	meta, err := pmp.extractPDFMetadataWithContext(ctx, filePath)
	if err != nil {
		// Check if this is an encrypted PDF error - attempt graceful degradation
		if mediaErr, ok := err.(*MediaProcessingError); ok &&
			mediaErr.GetErrorType() == ErrorTypeFileCorrupted &&
			strings.Contains(strings.ToLower(mediaErr.Message), "encrypted") {

			// For encrypted PDFs, try to extract basic file information
			if basicMeta := pmp.extractBasicPDFInfo(filePath); basicMeta != nil {
				pmp.LogDebugInfo("Extracted basic metadata from encrypted PDF")
				text := pmp.buildPDFMetadataText(basicMeta)
				return pmp.BuildSuccessContent(filePath, text, "pdf_metadata", basicMeta.PageCount), nil
			}
		}

		return pmp.HandleError(filePath, "pdf", fmt.Errorf("failed to extract PDF metadata: %w", err)), err
	}

	// Log file system information for observability (excluded from validator content)
	pmp.LogFileSystemInfo(meta.Filename, meta.FileSize, meta.MimeType)

	// Convert PDF metadata to text format for validation using shared utilities
	text := pmp.buildPDFMetadataText(meta)

	// Log successful processing
	pmp.LogSuccessfulProcessing(meta.Filename, meta.FileSize, meta.MimeType)

	// Build successful content using shared utilities
	return pmp.BuildSuccessContent(filePath, text, "pdf_metadata", meta.PageCount), nil
}

// extractPDFMetadataWithContext extracts PDF metadata with context monitoring for timeout handling
func (pmp *PDFMetadataPreprocessor) extractPDFMetadataWithContext(ctx context.Context, filePath string) (*metaextractpdflib.Metadata, error) {
	// Channel to receive the result
	type result struct {
		meta *metaextractpdflib.Metadata
		err  error
	}
	resultChan := make(chan result, 1)

	// Run extraction in a goroutine
	go func() {
		meta, err := metaextractpdflib.ExtractMetadata(filePath)

		// Handle PDF-specific errors with enhanced error classification
		if err != nil {
			err = pmp.handlePDFSpecificErrors(err, filePath)
		}

		resultChan <- result{meta: meta, err: err}
	}()

	// Wait for either completion or context cancellation
	select {
	case res := <-resultChan:
		return res.meta, res.err
	case <-ctx.Done():
		return nil, pmp.handleContextError(ctx.Err(), filePath)
	}
}

// handleContextError handles context-related errors (timeout, cancellation)
func (pmp *PDFMetadataPreprocessor) handleContextError(err error, filePath string) error {
	switch err {
	case context.DeadlineExceeded:
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeTimeout,
			"PDF metadata extraction timed out", err)
	case context.Canceled:
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeCancelled,
			"PDF metadata extraction was cancelled", err)
	default:
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeUnknown,
			"PDF metadata extraction context error", err)
	}
}

// handlePDFSpecificErrors handles PDF-specific error scenarios with graceful degradation
func (pmp *PDFMetadataPreprocessor) handlePDFSpecificErrors(err error, filePath string) error {
	errStr := strings.ToLower(err.Error())

	// Handle encrypted PDF scenarios
	if strings.Contains(errStr, "encrypted") || strings.Contains(errStr, "password") {
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeFileCorrupted,
			"PDF is encrypted or password-protected - limited metadata extraction available", err).
			WithContext("suggestion", "Encrypted PDFs may have limited metadata available")
	}

	// Handle corrupted PDF structure
	if strings.Contains(errStr, "corrupted") || strings.Contains(errStr, "malformed") ||
		strings.Contains(errStr, "invalid pdf") || strings.Contains(errStr, "not a valid pdf") {
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeFormatCorrupted,
			"PDF structure appears to be corrupted or malformed", err).
			WithContext("suggestion", "File may be corrupted or not a valid PDF")
	}

	// Handle parsing failures
	if strings.Contains(errStr, "failed to parse") || strings.Contains(errStr, "parsing failed") {
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeParsingFailed,
			"PDF metadata structure could not be parsed", err).
			WithContext("suggestion", "PDF metadata may be in an unsupported format")
	}

	// Handle extraction failures
	if strings.Contains(errStr, "failed to extract") || strings.Contains(errStr, "extraction failed") {
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeExtractionFailed,
			"PDF metadata extraction encountered an error", err).
			WithContext("suggestion", "Some PDF metadata may be inaccessible")
	}

	// Handle file access issues
	if strings.Contains(errStr, "no such file") || strings.Contains(errStr, "permission denied") {
		return NewMediaProcessingError(filePath, "pdf", ErrorTypeFileAccess,
			"Cannot access PDF file", err).
			WithContext("suggestion", "Check file permissions and path")
	}

	// Default to extraction failed for unknown PDF errors
	return NewMediaProcessingError(filePath, "pdf", ErrorTypeExtractionFailed,
		"PDF metadata extraction failed", err)
}

// buildPDFMetadataText converts PDF metadata to text format using shared utilities
func (pmp *PDFMetadataPreprocessor) buildPDFMetadataText(meta *metaextractpdflib.Metadata) string {
	var metadataText strings.Builder
	formatter := pmp.GetUtilities().Formatter

	// Skip file system information - only include object metadata
	metadataText.WriteString(formatter.FormatMetadataField("PDFVersion", meta.Version))

	// Encryption status
	metadataText.WriteString(formatter.FormatBooleanField("Encrypted", meta.Encrypted))

	// Document properties
	metadataText.WriteString(formatter.FormatMetadataField("Title", meta.Title))
	metadataText.WriteString(formatter.FormatMetadataField("Author", meta.Author))
	metadataText.WriteString(formatter.FormatMetadataField("Subject", meta.Subject))
	metadataText.WriteString(formatter.FormatMetadataField("Keywords", meta.Keywords))
	metadataText.WriteString(formatter.FormatMetadataField("Creator", meta.Creator))

	// Producer field with debug logging
	if meta.Producer != "" {
		metadataText.WriteString(formatter.FormatMetadataField("Producer", meta.Producer))
		pmp.LogDebugInfo(fmt.Sprintf("Adding Producer to metadata content: %s", meta.Producer))
	}

	// Dates
	metadataText.WriteString(formatter.FormatDateField("CreationDate", meta.CreatedDate))
	metadataText.WriteString(formatter.FormatDateField("ModificationDate", meta.ModDate))

	// Page count
	metadataText.WriteString(formatter.FormatNumericField("PageCount", meta.PageCount))

	// Additional properties (excluding already displayed dates)
	excludeKeys := []string{"CreationDate", "ModificationDate"}
	metadataText.WriteString(formatter.FormatPropertiesMap(meta.Properties, excludeKeys))

	return metadataText.String()
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (pmp *PDFMetadataPreprocessor) GetSupportedExtensions() []string {
	return pmp.GetUtilities().ExtensionValidator.GetPDFExtensions()
}

// SetObserver sets the observability component
func (pmp *PDFMetadataPreprocessor) SetObserver(observer *observability.StandardObserver) {
	pmp.BaseMetadataPreprocessor.SetObserver(observer)
}

// SetRouter sets the router instance for reprocessing embedded media
func (pmp *PDFMetadataPreprocessor) SetRouter(router RouterInterface) {
	pmp.BaseMetadataPreprocessor.SetRouter(router)
}

// extractBasicPDFInfo attempts to extract basic file information from encrypted or problematic PDFs
func (pmp *PDFMetadataPreprocessor) extractBasicPDFInfo(filePath string) *metaextractpdflib.Metadata {
	// Get basic file information
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil
	}

	// Create minimal metadata with file system information
	metadata := &metaextractpdflib.Metadata{
		Filename:   filepath.Base(filePath),
		FileSize:   fileInfo.Size(),
		ModTime:    fileInfo.ModTime(),
		MimeType:   "application/pdf",
		Version:    "Unknown",
		Encrypted:  true, // Assume encrypted if we can't read metadata
		PageCount:  0,    // Unknown for encrypted files
		Properties: make(map[string]string),
	}

	// Add a note about encryption
	metadata.Properties["EncryptionNote"] = "Limited metadata available due to encryption"

	return metadata
}
