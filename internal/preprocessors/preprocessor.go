// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"path/filepath"

	"ferret-scan/internal/observability"
)

// ProcessedContent represents content that has been processed by a preprocessor
type ProcessedContent struct {
	// Original file information
	OriginalPath string
	Filename     string

	// Extracted content
	Text string

	// Content metadata
	Format     string
	PageCount  int
	WordCount  int
	CharCount  int
	LineCount  int
	Paragraphs int

	// Processing information
	ProcessorType string
	Success       bool
	Error         error

	// Position mapping information for redaction
	PositionMappings []PositionMapping `json:"position_mappings,omitempty"`

	// Position tracking metadata
	PositionTrackingEnabled bool                   `json:"position_tracking_enabled"`
	PositionConfidence      float64                `json:"position_confidence"`
	PositionMetadata        map[string]interface{} `json:"position_metadata,omitempty"`

	// Additional metadata for embedded media and other extensions
	Metadata map[string]interface{}
}

// PositionMapping represents a mapping between extracted text positions and original document positions
type PositionMapping struct {
	// ExtractedPosition is the position in the extracted text
	ExtractedPosition TextPosition `json:"extracted_position"`

	// OriginalPosition is the corresponding position in the original document
	OriginalPosition DocumentPosition `json:"original_position"`

	// ConfidenceScore is the confidence in this position mapping (0.0 to 1.0)
	ConfidenceScore float64 `json:"confidence_score"`

	// Context is surrounding text for verification
	Context string `json:"context,omitempty"`

	// Method describes how this mapping was determined
	Method string `json:"method"`
}

// TextPosition represents a position in extracted text
type TextPosition struct {
	// Line is the line number (1-based)
	Line int `json:"line"`

	// StartChar is the starting character position in the line (0-based)
	StartChar int `json:"start_char"`

	// EndChar is the ending character position in the line (0-based)
	EndChar int `json:"end_char"`

	// AbsoluteOffset is the absolute character offset from the beginning of the text
	AbsoluteOffset int `json:"absolute_offset"`
}

// DocumentPosition represents a position in the original document
type DocumentPosition struct {
	// Page is the page number (1-based, 0 for single-page documents)
	Page int `json:"page"`

	// BoundingBox defines the rectangular area in the document (for PDFs, images, etc.)
	BoundingBox *BoundingBox `json:"bounding_box,omitempty"`

	// TextRun is the text run identifier (for structured documents)
	TextRun int `json:"text_run,omitempty"`

	// CharOffset is the character offset within the original document
	CharOffset int `json:"char_offset"`

	// LineNumber is the line number in the original document (if applicable)
	LineNumber int `json:"line_number,omitempty"`
}

// BoundingBox represents a rectangular area in a document
type BoundingBox struct {
	// X is the left coordinate (normalized 0.0-1.0 or absolute pixels)
	X float64 `json:"x"`

	// Y is the top coordinate (normalized 0.0-1.0 or absolute pixels)
	Y float64 `json:"y"`

	// Width is the width of the box
	Width float64 `json:"width"`

	// Height is the height of the box
	Height float64 `json:"height"`

	// Unit indicates the coordinate system ("normalized", "pixels", "points")
	Unit string `json:"unit,omitempty"`
}

// Preprocessor interface defines methods for preprocessing files
type Preprocessor interface {
	// CanProcess checks if this preprocessor can handle the given file
	CanProcess(filePath string) bool

	// Process extracts content from the file
	Process(filePath string) (*ProcessedContent, error)

	// GetName returns the name of this preprocessor
	GetName() string

	// GetSupportedExtensions returns the file extensions this preprocessor supports
	GetSupportedExtensions() []string

	// SetObserver sets the observability component
	SetObserver(observer *observability.StandardObserver)
}

// PreprocessorManager manages all available preprocessors
type PreprocessorManager struct {
	preprocessors []Preprocessor
}

// NewPreprocessorManager creates a new preprocessor manager
func NewPreprocessorManager() *PreprocessorManager {
	return &PreprocessorManager{
		preprocessors: make([]Preprocessor, 0),
	}
}

// RegisterPreprocessor adds a preprocessor to the manager
func (pm *PreprocessorManager) RegisterPreprocessor(p Preprocessor) {
	pm.preprocessors = append(pm.preprocessors, p)
}

// GetPreprocessor returns the appropriate preprocessor for a file, or nil if none found
func (pm *PreprocessorManager) GetPreprocessor(filePath string) Preprocessor {
	for _, p := range pm.preprocessors {
		if p.CanProcess(filePath) {
			return p
		}
	}
	return nil
}

// ProcessFile processes a file with all appropriate preprocessors
func (pm *PreprocessorManager) ProcessFile(filePath string) (*ProcessedContent, error) {
	// Get all preprocessors that can handle this file
	var availablePreprocessors []Preprocessor
	for _, p := range pm.preprocessors {
		if p.CanProcess(filePath) {
			availablePreprocessors = append(availablePreprocessors, p)
		}
	}

	if len(availablePreprocessors) == 0 {
		// No preprocessor available, return original file content as-is
		return &ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			Text:          "", // Will be read by validators directly
			ProcessorType: "none",
			Success:       true,
		}, nil
	}

	// Use the first successful preprocessor (maintaining backward compatibility)
	var lastError error
	for _, preprocessor := range availablePreprocessors {
		result, err := preprocessor.Process(filePath)
		if err == nil && result != nil && result.Success {
			return result, nil
		}
		lastError = err
	}

	// All preprocessors failed, return the last error
	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		ProcessorType: "failed",
		Success:       false,
		Error:         lastError,
	}, lastError
}

// GetAvailablePreprocessors returns all registered preprocessors
func (pm *PreprocessorManager) GetAvailablePreprocessors() []Preprocessor {
	return pm.preprocessors
}

// AddPositionMapping adds a position mapping to the processed content
func (pc *ProcessedContent) AddPositionMapping(mapping PositionMapping) {
	if pc.PositionMappings == nil {
		pc.PositionMappings = make([]PositionMapping, 0)
	}
	pc.PositionMappings = append(pc.PositionMappings, mapping)
}

// GetPositionMappingsForRange returns position mappings that overlap with the given text range
func (pc *ProcessedContent) GetPositionMappingsForRange(startLine, startChar, endLine, endChar int) []PositionMapping {
	var result []PositionMapping

	for _, mapping := range pc.PositionMappings {
		// Check if the mapping overlaps with the requested range
		if pc.positionOverlaps(mapping.ExtractedPosition, startLine, startChar, endLine, endChar) {
			result = append(result, mapping)
		}
	}

	return result
}

// EnablePositionTracking enables position tracking for this content
func (pc *ProcessedContent) EnablePositionTracking() {
	pc.PositionTrackingEnabled = true
	if pc.PositionMetadata == nil {
		pc.PositionMetadata = make(map[string]interface{})
	}
}

// SetPositionConfidence sets the overall confidence for position mappings
func (pc *ProcessedContent) SetPositionConfidence(confidence float64) {
	pc.PositionConfidence = confidence
}

// AddPositionMetadata adds metadata related to position tracking
func (pc *ProcessedContent) AddPositionMetadata(key string, value interface{}) {
	if pc.PositionMetadata == nil {
		pc.PositionMetadata = make(map[string]interface{})
	}
	pc.PositionMetadata[key] = value
}

// positionOverlaps checks if a position overlaps with a given range
func (pc *ProcessedContent) positionOverlaps(pos TextPosition, startLine, startChar, endLine, endChar int) bool {
	// Single line case
	if startLine == endLine {
		return pos.Line == startLine &&
			pos.EndChar >= startChar &&
			pos.StartChar <= endChar
	}

	// Multi-line case
	if pos.Line < startLine || pos.Line > endLine {
		return false
	}

	if pos.Line == startLine {
		return pos.EndChar >= startChar
	}

	if pos.Line == endLine {
		return pos.StartChar <= endChar
	}

	// Position is on a line between start and end
	return true
}

// CalculateAbsoluteOffset calculates the absolute character offset for a text position
func CalculateAbsoluteOffset(text string, line, charPos int) int {
	if line < 1 {
		return 0
	}

	lines := splitLines(text)
	if line > len(lines) {
		return len(text)
	}

	offset := 0
	// Add lengths of all previous lines (including newlines)
	for i := 0; i < line-1; i++ {
		offset += len(lines[i]) + 1 // +1 for newline character
	}

	// Add character position within the current line
	lineText := lines[line-1]
	if charPos > len(lineText) {
		charPos = len(lineText)
	}
	offset += charPos

	return offset
}

// splitLines splits text into lines, preserving empty lines
func splitLines(text string) []string {
	if text == "" {
		return []string{""}
	}

	var lines []string
	start := 0

	for i, r := range text {
		if r == '\n' {
			lines = append(lines, text[start:i])
			start = i + 1
		}
	}

	// Add the last line if it doesn't end with newline
	if start < len(text) {
		lines = append(lines, text[start:])
	} else if start == len(text) && len(lines) > 0 {
		// Text ends with newline, add empty line
		lines = append(lines, "")
	}

	return lines
}

// ShouldPreprocess checks if a file should be preprocessed based on its extension
// Now returns true for all files since we have a plain text preprocessor that handles all file types
func ShouldPreprocess(filePath string) bool {
	// All files should be preprocessed now - the plain text preprocessor handles text files,
	// document preprocessor handles documents, and metadata preprocessor handles images/media
	return true
}
