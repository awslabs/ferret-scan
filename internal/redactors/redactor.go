// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
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

// RedactionStrategyNames are the exact spellings a strategy may be given as, in
// the order the documentation lists them. Exported so that error messages, the
// config schema's agreement test and the CLI help all derive from one list.
var RedactionStrategyNames = []string{"simple", "format_preserving", "synthetic"}

// Valid reports whether rs is one of the three defined strategies. A
// RedactionStrategy is an int, so a caller can hold a value outside the
// definition (a cast, a zero-filled struct from another package); every
// consumer that applies a strategy checks this first and refuses otherwise.
func (rs RedactionStrategy) Valid() bool {
	return rs >= RedactionSimple && rs <= RedactionSynthetic
}

// ParseRedactionStrategy converts a strategy name to a RedactionStrategy, or
// returns an error naming the value, the valid names and, when a case or
// whitespace variant of a valid name was given, the name it may have meant.
//
// EXACT match only: no case folding, no trimming, no comma lists (#772). This
// used to fall back to format_preserving for any unrecognised value, with no
// error return, so `--redaction-strategy SIMPLE` wrote masked output (`***-**-8901`)
// where `simple` writes a placeholder, at exit 0 with an empty stderr; a config
// file's `strategy: simple` was discarded by a typo on the flag; and no report
// named the strategy applied. Folding `SIMPLE` to `simple` instead would silently
// change what an existing run writes; refusing keeps every run that exits 0
// today byte-identical, and makes the others loud. The empty string is refused
// too: "unset" is a decision for the caller's precedence logic, not for the
// parser, so a caller that reaches here with "" has a bug.
func ParseRedactionStrategy(s string) (RedactionStrategy, error) {
	switch s {
	case "simple":
		return RedactionSimple, nil
	case "format_preserving":
		return RedactionFormatPreserving, nil
	case "synthetic":
		return RedactionSynthetic, nil
	}
	hint := ""
	if folded := strings.ToLower(strings.TrimSpace(s)); folded != s {
		if _, err := ParseRedactionStrategy(folded); err == nil {
			hint = fmt.Sprintf(" (did you mean %q?)", folded)
		}
	}
	return RedactionFormatPreserving, fmt.Errorf("invalid redaction strategy %q: valid values are %s%s",
		s, strings.Join(RedactionStrategyNames, ", "), hint)
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
