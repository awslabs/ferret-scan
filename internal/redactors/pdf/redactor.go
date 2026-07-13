// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"fmt"
	"os"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// PDFRedactor implements the redactors.ContentRedactor interface for PDF files.
//
// NOTE: real PDF content redaction is NOT implemented. RedactDocument and
// RedactContent deliberately fail (see those methods) rather than emit a copy
// of the input that would falsely report a successful redaction. The earlier
// implementation contained placeholder text extraction and logging-only
// "redaction" stubs that produced byte-for-byte copies of the input while
// reporting Success:true; that misleading scaffolding has been removed. When
// real redaction is added, restore the content-stream extraction/redaction
// pipeline here.
type PDFRedactor struct {
	// observer handles observability and metrics
	observer observability.Observer

	// pdfConfig contains PDF-specific configuration used for validation
	pdfConfig *model.Configuration
}

// NewPDFRedactor creates a new PDFRedactor.
//
// outputManager is currently unused because no document is produced (redaction
// is unimplemented); it is retained in the signature so the call site does not
// change when real redaction — which needs the output manager — is added.
func NewPDFRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *PDFRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	return &PDFRedactor{
		observer:  observer,
		pdfConfig: model.NewDefaultConfiguration(),
	}
}

// GetName returns the name of the redactor
func (pr *PDFRedactor) GetName() string {
	return "pdf_redactor"
}

// GetSupportedTypes returns the file types this redactor can handle
func (pr *PDFRedactor) GetSupportedTypes() []string {
	return []string{"pdf", ".pdf"}
}

// GetSupportedStrategies returns the redaction strategies this redactor supports
func (pr *PDFRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument creates a redacted copy of the PDF document at outputPath.
//
// FAIL-SAFE: PDF content redaction is not implemented. Refusing here prevents
// emitting an unredacted document that would falsely report Success:true and
// give callers false assurance that sensitive data was removed.
func (pr *PDFRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if pr.observer != nil {
		finishTiming = pr.observer.StartTiming("pdf_redactor", "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(false, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	// Validate input file so a non-PDF input gets a clear, specific error.
	if err := pr.validatePDFFile(originalPath); err != nil {
		return nil, fmt.Errorf("PDF validation failed: %w", err)
	}

	pr.logEvent("pdf_redaction_not_implemented", false, map[string]interface{}{
		"original_path": originalPath,
		"output_path":   outputPath,
		"match_count":   len(matches),
	})
	return nil, fmt.Errorf("PDF redaction is not implemented: refusing to produce an output that was not redacted but would falsely report success")
}

// RedactContent implements the ContentRedactor interface.
//
// FAIL-SAFE: see RedactDocument. The content-based path is equally
// unimplemented and must not report a successful redaction.
func (pr *PDFRedactor) RedactContent(content *preprocessors.ProcessedContent, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if pr.observer != nil {
		finishTiming = pr.observer.StartTiming("pdf_redactor", "redact_content", content.OriginalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(false, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	pr.logEvent("pdf_redaction_not_implemented", false, map[string]interface{}{
		"original_path": content.OriginalPath,
		"output_path":   outputPath,
		"match_count":   len(matches),
	})
	return nil, fmt.Errorf("PDF redaction is not implemented: refusing to produce an output that was not redacted but would falsely report success")
}

// GetComponentName returns the component name for observability
func (pr *PDFRedactor) GetComponentName() string {
	return "pdf_redactor"
}

// validatePDFFile validates that the file exists and is a parseable PDF.
func (pr *PDFRedactor) validatePDFFile(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	if err := api.ValidateFile(filePath, pr.pdfConfig); err != nil {
		return fmt.Errorf("invalid PDF file: %w", err)
	}

	return nil
}

// logEvent logs an event if observer is available
func (pr *PDFRedactor) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if pr.observer != nil {
		pr.observer.StartTiming("pdf_redactor", operation, "")(success, metadata)
	}
}
