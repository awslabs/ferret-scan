// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/preprocessors"
)

// RedactionStrategy defines the type of redaction to apply
type RedactionStrategy int

const (
	// RedactionSimple replaces sensitive data with placeholder text
	RedactionSimple RedactionStrategy = iota
	// RedactionFormatPreserving maintains original format and length
	RedactionFormatPreserving
	// RedactionSynthetic generates realistic but fake data of the same type
	RedactionSynthetic
)

// String returns the string representation of the redaction strategy
func (rs RedactionStrategy) String() string {
	switch rs {
	case RedactionSimple:
		return "simple"
	case RedactionFormatPreserving:
		return "format_preserving"
	case RedactionSynthetic:
		return "synthetic"
	default:
		return "unknown"
	}
}

// ParseRedactionStrategy converts a string to RedactionStrategy
func ParseRedactionStrategy(s string) RedactionStrategy {
	switch s {
	case "simple":
		return RedactionSimple
	case "format_preserving":
		return RedactionFormatPreserving
	case "synthetic":
		return RedactionSynthetic
	default:
		return RedactionFormatPreserving // Default fallback
	}
}

// Redactor interface defines the contract for all redactor implementations
type Redactor interface {
	// GetName returns the name of the redactor
	GetName() string

	// GetSupportedTypes returns the file types this redactor can handle
	GetSupportedTypes() []string

	// GetSupportedStrategies returns the redaction strategies this redactor supports
	GetSupportedStrategies() []RedactionStrategy

	// RedactDocument creates a redacted copy of the document at outputPath
	RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy RedactionStrategy) (*RedactionResult, error)

	// GetComponentName returns the component name for observability
	GetComponentName() string
}

// ContentRedactor interface extends Redactor to support content-based redaction
// This eliminates the need for duplicate text extraction
type ContentRedactor interface {
	Redactor

	// RedactContent creates a redacted copy using already-extracted content
	// This is more efficient as it avoids re-extracting text that was already processed
	RedactContent(content *preprocessors.ProcessedContent, outputPath string, matches []detector.Match, strategy RedactionStrategy) (*RedactionResult, error)
}

// RedactionResult contains the results of a redaction operation
type RedactionResult struct {
	// Success indicates whether the redaction was successful
	Success bool

	// RedactedFilePath is the path to the redacted document
	RedactedFilePath string

	// RedactionMap contains details of all redactions performed
	RedactionMap []RedactionMapping

	// ProcessingTime is the time taken to perform the redaction
	ProcessingTime time.Duration

	// Confidence is the overall confidence score for the redaction accuracy
	Confidence float64

	// Error contains any error that occurred during redaction
	Error error
}

// RedactionMapping represents a single redaction operation
type RedactionMapping struct {
	// RedactedText is the replacement text
	RedactedText string

	// Position is the position in the extracted text
	Position TextPosition

	// DataType is the type of sensitive data (e.g., "CREDIT_CARD", "SSN")
	DataType string

	// Strategy is the redaction strategy used
	Strategy RedactionStrategy

	// Confidence is the confidence score for this specific redaction
	Confidence float64

	// Metadata contains additional information about the redaction
	Metadata map[string]interface{}
}

// TextPosition represents a position in text content
type TextPosition struct {
	// Line is the line number (1-based)
	Line int

	// StartChar is the starting character position in the line (0-based)
	StartChar int

	// EndChar is the ending character position in the line (0-based)
	EndChar int
}

// DocumentPosition represents a position in the original document
type DocumentPosition struct {
	// Page is the page number (1-based, 0 for single-page documents)
	Page int

	// BoundingBox defines the rectangular area in the document
	BoundingBox BoundingBox

	// TextRun is the text run identifier (for structured documents)
	TextRun int

	// CharOffset is the character offset within the text run
	CharOffset int
}

// BoundingBox represents a rectangular area in a document
type BoundingBox struct {
	// X is the left coordinate
	X float64

	// Y is the top coordinate
	Y float64

	// Width is the width of the box
	Width float64

	// Height is the height of the box
	Height float64
}

// PositionMapping maps extracted text positions to original document positions
type PositionMapping struct {
	// ExtractedPosition is the position in the extracted text
	ExtractedPosition TextPosition

	// OriginalPosition is the corresponding position in the original document
	OriginalPosition DocumentPosition

	// DocumentType is the type of document (PDF, DOCX, etc.)
	DocumentType string

	// PageNumber is the page number for multi-page documents
	PageNumber int

	// Region is the bounding box for the mapped region
	Region BoundingBox

	// ConfidenceScore is the confidence in this position mapping
	ConfidenceScore float64
}

// RedactionResults contains the overall results of redaction processing
type RedactionResults struct {
	// ProcessedFiles contains results for each processed file
	ProcessedFiles []ProcessedFile

	// RedactionAuditLog contains the comprehensive redaction audit log
	RedactionAuditLog *RedactionAuditLog

	// TotalRedactions is the total number of redactions performed
	TotalRedactions int

	// ProcessingTime is the total time taken for all redactions
	ProcessingTime time.Duration

	// Errors contains any errors that occurred during processing
	Errors []RedactionError
}

// ProcessedFile contains the results for a single processed file
type ProcessedFile struct {
	// OriginalPath is the path to the original file
	OriginalPath string

	// RedactedPath is the path to the redacted file
	RedactedPath string

	// RedactionCount is the number of redactions performed on this file
	RedactionCount int

	// ProcessingTime is the time taken to process this file
	ProcessingTime time.Duration

	// Success indicates whether processing was successful
	Success bool

	// Error contains any error that occurred during processing
	Error error
}
