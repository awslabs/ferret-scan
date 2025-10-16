// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"fmt"
	"math"
	"strings"

	"ferret-scan/internal/redactors"
)

// PositionCorrelator interface defines the contract for position correlation algorithms
type PositionCorrelator interface {
	// CorrelatePosition maps an extracted text position to the original document position
	CorrelatePosition(extractedPos redactors.TextPosition, extractedText string, originalContent []byte, documentType string) (*PositionCorrelation, error)

	// CorrelatePositions maps multiple extracted text positions to original document positions
	CorrelatePositions(positions []redactors.TextPosition, extractedText string, originalContent []byte, documentType string) ([]*PositionCorrelation, error)

	// SetConfidenceThreshold sets the minimum confidence threshold for position correlation
	SetConfidenceThreshold(threshold float64)

	// GetConfidenceThreshold returns the current confidence threshold
	GetConfidenceThreshold() float64

	// SetContextWindowSize sets the size of the context window for correlation
	SetContextWindowSize(size int)

	// GetContextWindowSize returns the current context window size
	GetContextWindowSize() int

	// EnableFuzzyMatching enables or disables fuzzy matching algorithms
	EnableFuzzyMatching(enabled bool)

	// IsFuzzyMatchingEnabled returns whether fuzzy matching is enabled
	IsFuzzyMatchingEnabled() bool

	// ValidateCorrelation validates a position correlation result
	ValidateCorrelation(correlation *PositionCorrelation) error
}

// PositionCorrelation represents the result of position correlation
type PositionCorrelation struct {
	// ExtractedPosition is the position in the extracted text
	ExtractedPosition redactors.TextPosition

	// OriginalPosition is the corresponding position in the original document
	OriginalPosition *redactors.DocumentPosition

	// ConfidenceScore is the confidence in this position mapping (0.0 to 1.0)
	ConfidenceScore float64

	// MatchedText is the text that was matched in the original document
	MatchedText string

	// Context is the surrounding context used for correlation
	Context string

	// Method is the correlation method used (exact, fuzzy, contextual)
	Method CorrelationMethod

	// DocumentType is the type of document being processed
	DocumentType string

	// Metadata contains additional correlation metadata
	Metadata map[string]interface{}
}

// CorrelationMethod represents the method used for position correlation
type CorrelationMethod int

const (
	// CorrelationExact indicates exact text matching
	CorrelationExact CorrelationMethod = iota
	// CorrelationFuzzy indicates fuzzy text matching
	CorrelationFuzzy
	// CorrelationContextual indicates context-based matching
	CorrelationContextual
	// CorrelationHeuristic indicates heuristic-based matching
	CorrelationHeuristic
)

// String returns the string representation of the correlation method
func (cm CorrelationMethod) String() string {
	switch cm {
	case CorrelationExact:
		return "exact"
	case CorrelationFuzzy:
		return "fuzzy"
	case CorrelationContextual:
		return "contextual"
	case CorrelationHeuristic:
		return "heuristic"
	default:
		return "unknown"
	}
}

// DefaultPositionCorrelator implements the PositionCorrelator interface
type DefaultPositionCorrelator struct {
	// confidenceThreshold is the minimum confidence threshold
	confidenceThreshold float64

	// contextWindowSize is the size of the context window
	contextWindowSize int

	// fuzzyMatchingEnabled indicates whether fuzzy matching is enabled
	fuzzyMatchingEnabled bool

	// maxEditDistance is the maximum edit distance for fuzzy matching
	maxEditDistance int

	// minMatchLength is the minimum length for text matching
	minMatchLength int
}

// NewDefaultPositionCorrelator creates a new default position correlator
func NewDefaultPositionCorrelator() *DefaultPositionCorrelator {
	return &DefaultPositionCorrelator{
		confidenceThreshold:  0.8,
		contextWindowSize:    500,
		fuzzyMatchingEnabled: true,
		maxEditDistance:      3,
		minMatchLength:       5,
	}
}

// CorrelatePosition maps an extracted text position to the original document position
func (dpc *DefaultPositionCorrelator) CorrelatePosition(extractedPos redactors.TextPosition, extractedText string, originalContent []byte, documentType string) (*PositionCorrelation, error) {
	if len(originalContent) == 0 {
		return nil, fmt.Errorf("original content is empty")
	}

	// Extract the text at the specified position
	targetText, err := dpc.extractTextAtPosition(extractedPos, extractedText)
	if err != nil {
		return nil, fmt.Errorf("failed to extract text at position: %w", err)
	}

	if len(targetText) < dpc.minMatchLength {
		return nil, fmt.Errorf("target text too short for reliable correlation: %d < %d", len(targetText), dpc.minMatchLength)
	}

	originalText := string(originalContent)

	// Try exact matching first
	if correlation := dpc.tryExactMatch(extractedPos, targetText, originalText, documentType); correlation != nil {
		if correlation.ConfidenceScore >= dpc.confidenceThreshold {
			return correlation, nil
		}
	}

	// Try fuzzy matching if enabled
	if dpc.fuzzyMatchingEnabled {
		if correlation := dpc.tryFuzzyMatch(extractedPos, targetText, originalText, documentType); correlation != nil {
			if correlation.ConfidenceScore >= dpc.confidenceThreshold {
				return correlation, nil
			}
		}
	}

	// Try contextual matching
	if correlation := dpc.tryContextualMatch(extractedPos, targetText, extractedText, originalText, documentType); correlation != nil {
		if correlation.ConfidenceScore >= dpc.confidenceThreshold {
			return correlation, nil
		}
	}

	// Return best effort result even if below threshold
	bestCorrelation := dpc.tryHeuristicMatch(extractedPos, targetText, originalText, documentType)
	if bestCorrelation == nil {
		return nil, fmt.Errorf("no correlation found for position %+v", extractedPos)
	}

	return bestCorrelation, nil
}

// CorrelatePositions maps multiple extracted text positions to original document positions
func (dpc *DefaultPositionCorrelator) CorrelatePositions(positions []redactors.TextPosition, extractedText string, originalContent []byte, documentType string) ([]*PositionCorrelation, error) {
	if len(positions) == 0 {
		return nil, fmt.Errorf("no positions provided")
	}

	correlations := make([]*PositionCorrelation, 0, len(positions))

	for i, pos := range positions {
		correlation, err := dpc.CorrelatePosition(pos, extractedText, originalContent, documentType)
		if err != nil {
			// Log error but continue with other positions
			correlation = &PositionCorrelation{
				ExtractedPosition: pos,
				OriginalPosition:  nil,
				ConfidenceScore:   0.0,
				Method:            CorrelationHeuristic,
				DocumentType:      documentType,
				Metadata: map[string]interface{}{
					"error":    err.Error(),
					"position": i,
				},
			}
		}
		correlations = append(correlations, correlation)
	}

	return correlations, nil
}

// SetConfidenceThreshold sets the minimum confidence threshold
func (dpc *DefaultPositionCorrelator) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		dpc.confidenceThreshold = threshold
	}
}

// GetConfidenceThreshold returns the current confidence threshold
func (dpc *DefaultPositionCorrelator) GetConfidenceThreshold() float64 {
	return dpc.confidenceThreshold
}

// SetContextWindowSize sets the size of the context window
func (dpc *DefaultPositionCorrelator) SetContextWindowSize(size int) {
	if size > 0 {
		dpc.contextWindowSize = size
	}
}

// GetContextWindowSize returns the current context window size
func (dpc *DefaultPositionCorrelator) GetContextWindowSize() int {
	return dpc.contextWindowSize
}

// EnableFuzzyMatching enables or disables fuzzy matching
func (dpc *DefaultPositionCorrelator) EnableFuzzyMatching(enabled bool) {
	dpc.fuzzyMatchingEnabled = enabled
}

// IsFuzzyMatchingEnabled returns whether fuzzy matching is enabled
func (dpc *DefaultPositionCorrelator) IsFuzzyMatchingEnabled() bool {
	return dpc.fuzzyMatchingEnabled
}

// ValidateCorrelation validates a position correlation result
func (dpc *DefaultPositionCorrelator) ValidateCorrelation(correlation *PositionCorrelation) error {
	if correlation == nil {
		return fmt.Errorf("correlation is nil")
	}

	if correlation.ConfidenceScore < 0.0 || correlation.ConfidenceScore > 1.0 {
		return fmt.Errorf("confidence score must be between 0.0 and 1.0, got %f", correlation.ConfidenceScore)
	}

	if correlation.ExtractedPosition.Line < 1 {
		return fmt.Errorf("extracted position line must be >= 1, got %d", correlation.ExtractedPosition.Line)
	}

	if correlation.ExtractedPosition.StartChar < 0 {
		return fmt.Errorf("extracted position start char must be >= 0, got %d", correlation.ExtractedPosition.StartChar)
	}

	if correlation.ExtractedPosition.EndChar < correlation.ExtractedPosition.StartChar {
		return fmt.Errorf("extracted position end char must be >= start char, got %d < %d",
			correlation.ExtractedPosition.EndChar, correlation.ExtractedPosition.StartChar)
	}

	return nil
}

// extractTextAtPosition extracts text at the specified position
func (dpc *DefaultPositionCorrelator) extractTextAtPosition(pos redactors.TextPosition, text string) (string, error) {
	lines := strings.Split(text, "\n")

	if pos.Line < 1 || pos.Line > len(lines) {
		return "", fmt.Errorf("line %d is out of range (1-%d)", pos.Line, len(lines))
	}

	line := lines[pos.Line-1] // Convert to 0-based indexing

	if pos.StartChar < 0 || pos.StartChar >= len(line) {
		return "", fmt.Errorf("start char %d is out of range (0-%d)", pos.StartChar, len(line)-1)
	}

	if pos.EndChar < pos.StartChar || pos.EndChar > len(line) {
		return "", fmt.Errorf("end char %d is out of range (%d-%d)", pos.EndChar, pos.StartChar, len(line))
	}

	return line[pos.StartChar:pos.EndChar], nil
}

// tryExactMatch attempts exact text matching
func (dpc *DefaultPositionCorrelator) tryExactMatch(extractedPos redactors.TextPosition, targetText, originalText, documentType string) *PositionCorrelation {
	index := strings.Index(originalText, targetText)
	if index == -1 {
		return nil
	}

	// Calculate document position
	docPos := dpc.calculateDocumentPosition(index, len(targetText), originalText, documentType)

	// Calculate confidence based on text uniqueness
	confidence := dpc.calculateExactMatchConfidence(targetText, originalText)

	return &PositionCorrelation{
		ExtractedPosition: extractedPos,
		OriginalPosition:  docPos,
		ConfidenceScore:   confidence,
		MatchedText:       targetText,
		Context:           dpc.extractContext(index, originalText),
		Method:            CorrelationExact,
		DocumentType:      documentType,
		Metadata: map[string]interface{}{
			"match_index": index,
			"match_count": strings.Count(originalText, targetText),
		},
	}
}

// tryFuzzyMatch attempts fuzzy text matching
func (dpc *DefaultPositionCorrelator) tryFuzzyMatch(extractedPos redactors.TextPosition, targetText, originalText, documentType string) *PositionCorrelation {
	bestMatch := dpc.findBestFuzzyMatch(targetText, originalText)
	if bestMatch == nil {
		return nil
	}

	// Calculate document position
	docPos := dpc.calculateDocumentPosition(bestMatch.Index, len(bestMatch.Text), originalText, documentType)

	// Calculate confidence based on edit distance and text similarity
	confidence := dpc.calculateFuzzyMatchConfidence(targetText, bestMatch.Text, bestMatch.EditDistance)

	return &PositionCorrelation{
		ExtractedPosition: extractedPos,
		OriginalPosition:  docPos,
		ConfidenceScore:   confidence,
		MatchedText:       bestMatch.Text,
		Context:           dpc.extractContext(bestMatch.Index, originalText),
		Method:            CorrelationFuzzy,
		DocumentType:      documentType,
		Metadata: map[string]interface{}{
			"match_index":   bestMatch.Index,
			"edit_distance": bestMatch.EditDistance,
			"similarity":    bestMatch.Similarity,
		},
	}
}

// tryContextualMatch attempts context-based matching
func (dpc *DefaultPositionCorrelator) tryContextualMatch(extractedPos redactors.TextPosition, targetText, extractedText, originalText, documentType string) *PositionCorrelation {
	// Extract context around the target text in extracted content
	extractedContext := dpc.extractExtractedContext(extractedPos, extractedText)
	if extractedContext == "" {
		return nil
	}

	// Find the best contextual match in original text
	contextMatch := dpc.findBestContextualMatch(extractedContext, targetText, originalText)
	if contextMatch == nil {
		return nil
	}

	// Calculate document position
	docPos := dpc.calculateDocumentPosition(contextMatch.Index, len(targetText), originalText, documentType)

	// Calculate confidence based on context similarity
	confidence := dpc.calculateContextualMatchConfidence(extractedContext, contextMatch.Context, targetText)

	return &PositionCorrelation{
		ExtractedPosition: extractedPos,
		OriginalPosition:  docPos,
		ConfidenceScore:   confidence,
		MatchedText:       targetText,
		Context:           contextMatch.Context,
		Method:            CorrelationContextual,
		DocumentType:      documentType,
		Metadata: map[string]interface{}{
			"match_index":        contextMatch.Index,
			"context_similarity": contextMatch.Similarity,
			"extracted_context":  extractedContext,
		},
	}
}

// tryHeuristicMatch attempts heuristic-based matching as a fallback
func (dpc *DefaultPositionCorrelator) tryHeuristicMatch(extractedPos redactors.TextPosition, targetText, originalText, documentType string) *PositionCorrelation {
	// Use simple heuristics like position estimation based on line numbers
	estimatedIndex := dpc.estimatePositionByLine(extractedPos, originalText)

	// Find the closest match near the estimated position
	searchStart := max(0, estimatedIndex-dpc.contextWindowSize/2)
	searchEnd := min(len(originalText), estimatedIndex+dpc.contextWindowSize/2)
	searchText := originalText[searchStart:searchEnd]

	// Try to find the target text in the search window
	relativeIndex := strings.Index(searchText, targetText)
	if relativeIndex == -1 {
		// No match found, return low-confidence result
		docPos := dpc.calculateDocumentPosition(estimatedIndex, len(targetText), originalText, documentType)
		return &PositionCorrelation{
			ExtractedPosition: extractedPos,
			OriginalPosition:  docPos,
			ConfidenceScore:   0.1, // Very low confidence
			MatchedText:       "",
			Context:           dpc.extractContext(estimatedIndex, originalText),
			Method:            CorrelationHeuristic,
			DocumentType:      documentType,
			Metadata: map[string]interface{}{
				"estimated_index": estimatedIndex,
				"search_window":   fmt.Sprintf("%d-%d", searchStart, searchEnd),
			},
		}
	}

	actualIndex := searchStart + relativeIndex
	docPos := dpc.calculateDocumentPosition(actualIndex, len(targetText), originalText, documentType)

	// Calculate confidence based on distance from estimated position
	confidence := dpc.calculateHeuristicMatchConfidence(estimatedIndex, actualIndex, targetText)

	return &PositionCorrelation{
		ExtractedPosition: extractedPos,
		OriginalPosition:  docPos,
		ConfidenceScore:   confidence,
		MatchedText:       targetText,
		Context:           dpc.extractContext(actualIndex, originalText),
		Method:            CorrelationHeuristic,
		DocumentType:      documentType,
		Metadata: map[string]interface{}{
			"estimated_index": estimatedIndex,
			"actual_index":    actualIndex,
			"distance":        abs(estimatedIndex - actualIndex),
		},
	}
}

// calculateDocumentPosition calculates the document position from text index
func (dpc *DefaultPositionCorrelator) calculateDocumentPosition(index, length int, text, documentType string) *redactors.DocumentPosition {
	// Count lines and calculate position
	lines := strings.Split(text[:index], "\n")
	line := len(lines)
	charInLine := len(lines[len(lines)-1])

	// For simple text documents, we don't have page/bounding box info
	return &redactors.DocumentPosition{
		Page: 1, // Assume single page for text documents
		BoundingBox: redactors.BoundingBox{
			X:      float64(charInLine),
			Y:      float64(line),
			Width:  float64(length),
			Height: 1.0,
		},
		TextRun:    0,
		CharOffset: index,
	}
}

// Helper functions for confidence calculation and matching algorithms

func (dpc *DefaultPositionCorrelator) calculateExactMatchConfidence(targetText, originalText string) float64 {
	// Base confidence for exact match
	baseConfidence := 0.95

	// Adjust based on text uniqueness
	matchCount := strings.Count(originalText, targetText)
	if matchCount == 1 {
		return baseConfidence
	}

	// Reduce confidence for non-unique matches
	uniquenessScore := 1.0 / float64(matchCount)
	return baseConfidence * (0.5 + 0.5*uniquenessScore)
}

func (dpc *DefaultPositionCorrelator) calculateFuzzyMatchConfidence(targetText, matchedText string, editDistance int) float64 {
	// Calculate similarity based on edit distance
	maxLen := max(len(targetText), len(matchedText))
	if maxLen == 0 {
		return 0.0
	}

	similarity := 1.0 - float64(editDistance)/float64(maxLen)

	// Base confidence for fuzzy match is lower than exact match
	baseConfidence := 0.8

	return baseConfidence * similarity
}

func (dpc *DefaultPositionCorrelator) calculateContextualMatchConfidence(extractedContext, originalContext, targetText string) float64 {
	// Calculate context similarity
	contextSimilarity := dpc.calculateStringSimilarity(extractedContext, originalContext)

	// Base confidence for contextual match
	baseConfidence := 0.75

	// Adjust based on context similarity and target text length
	lengthBonus := math.Min(1.0, float64(len(targetText))/20.0) // Longer text gets higher confidence

	return baseConfidence * contextSimilarity * (0.8 + 0.2*lengthBonus)
}

func (dpc *DefaultPositionCorrelator) calculateHeuristicMatchConfidence(estimatedIndex, actualIndex int, targetText string) float64 {
	// Calculate confidence based on distance from estimated position
	distance := abs(estimatedIndex - actualIndex)
	maxDistance := dpc.contextWindowSize / 2

	if distance > maxDistance {
		return 0.1 // Very low confidence for matches far from estimate
	}

	// Base confidence for heuristic match is low
	baseConfidence := 0.6

	// Reduce confidence based on distance
	distanceScore := 1.0 - float64(distance)/float64(maxDistance)

	return baseConfidence * distanceScore
}

// Additional helper functions will be implemented in the next part...

// FuzzyMatch represents a fuzzy match result
type FuzzyMatch struct {
	Text         string
	Index        int
	EditDistance int
	Similarity   float64
}

// ContextMatch represents a contextual match result
type ContextMatch struct {
	Index      int
	Context    string
	Similarity float64
}

// Helper functions for string operations
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
