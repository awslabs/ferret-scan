// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"fmt"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
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

	// Method is the correlation method used (exact, fuzzy, heuristic)
	Method CorrelationMethod

	// DocumentType is the type of document being processed
	DocumentType string

	// Metadata contains additional correlation metadata
	Metadata map[string]interface{}
}

// CorrelationMethod represents the method used for position correlation
type CorrelationMethod int

// There is deliberately no contextual method. A CorrelationContextual value and a
// tryContextualMatch step between fuzzy and heuristic existed here and could never be
// returned; see CorrelatePosition for the two independent measurements (#383).
const (
	// CorrelationExact indicates exact text matching
	CorrelationExact CorrelationMethod = iota
	// CorrelationFuzzy indicates fuzzy text matching
	CorrelationFuzzy
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

	// There is no contextual step between fuzzy and heuristic. One was here, and it was
	// dead two ways over — either reason alone is sufficient, so restoring it would need
	// both to be answered (#383).
	//
	// 1. Arithmetic. Its scorer returned 0.75 * contextSimilarity * (0.8 + 0.2*lengthBonus).
	//    calculateStringSimilarity is a convex combination of three metrics each bounded by
	//    1, and lengthBonus was math.Min(1.0, len/20), so the analytic ceiling was 0.75 —
	//    below the confidenceThreshold of 0.8 it was measured against. Maximising the scorer
	//    over 20,001 inputs, including identical contexts with a 200-byte target, returned
	//    0.75 exactly. Nothing in the tree calls SetConfidenceThreshold, so the gate is
	//    always 0.8: instrumenting this function recorded threshold=0.8 on all 6,655
	//    correlations performed by the full test suite plus a 17-file redaction corpus.
	//
	// 2. Structure. The step could only be reached when neither exact nor fuzzy cleared the
	//    gate. Whenever tryExactMatch resolves at all, targetText occurs verbatim in
	//    originalText, so findBestFuzzyMatch finds it at edit distance 0 and
	//    calculateFuzzyMatchConfidence returns 0.8*1.0 — clearing this `>=` gate exactly.
	//    So the step was only reachable when targetText was absent from the document, and
	//    findBestContextualMatch required at least one verbatim occurrence and therefore
	//    returned nil in precisely that case. The same instrumentation recorded the branch
	//    entered 0 times in 6,655 correlations.
	//
	// The only production caller (PlainTextRedactor.correlateMatchPosition) passes the same
	// string as extractedText and originalContent, and derives targetText from a line of it,
	// so case 2 holds by construction there.

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

// lineAt returns the 1-based line of text without allocating, and ok=false when
// the line number is out of range. Splitting the whole document to reach one
// line is what made the per-match correlation path quadratic.
func lineAt(text string, lineNumber int) (string, bool) {
	if lineNumber < 1 {
		return "", false
	}
	start := 0
	for n := 1; ; n++ {
		idx := strings.IndexByte(text[start:], '\n')
		if n == lineNumber {
			if idx < 0 {
				// Final line, no trailing newline. strings.Split yields a
				// trailing empty element for text ending in "\n", so an empty
				// final segment must remain addressable to preserve behaviour.
				return text[start:], true
			}
			return text[start : start+idx], true
		}
		if idx < 0 {
			return "", false
		}
		start += idx + 1
	}
}

// countLines reports the number of lines strings.Split(text, "\n") would yield,
// so range errors keep reporting the same bound as before.
func countLines(text string) int {
	return strings.Count(text, "\n") + 1
}

// lineAndColumnAt returns the 1-based line number containing byte offset index
// and the number of bytes between the start of that line and index. It replaces
// a strings.Split(text[:index], "\n") that allocated every preceding line on
// every call.
func lineAndColumnAt(text string, index int) (line, column int) {
	if index > len(text) {
		index = len(text)
	}
	line = strings.Count(text[:index], "\n") + 1
	if nl := strings.LastIndexByte(text[:index], '\n'); nl >= 0 {
		return line, index - nl - 1
	}
	return line, index
}

// extractTextAtPosition extracts text at the specified position.
//
// The requested line is located by walking newlines rather than by
// strings.Split of the whole document. Callers correlate one match at a time, so
// splitting here allocated a slice of every line in the document per match —
// one of three sites that together made redaction quadratic in
// (matches x content bytes). Walking is O(offset of the line) with no
// allocation, and the out-of-range error keeps its original 1-based line count.
func (dpc *DefaultPositionCorrelator) extractTextAtPosition(pos redactors.TextPosition, text string) (string, error) {
	line, ok := lineAt(text, pos.Line)
	if !ok {
		return "", fmt.Errorf("line %d is out of range (1-%d)", pos.Line, countLines(text))
	}

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
	// Search the match's OWN LINE first. See searchScope: resolving document-wide
	// returns the first occurrence anywhere, which is the wrong one whenever the
	// value occurs more than once — and that wrong offset reached the redactor as a
	// cleartext leak (#519).
	index, matchCount, ok := exactMatchInScope(extractedPos, targetText, originalText)
	if !ok {
		return nil
	}

	// Calculate document position
	docPos := dpc.calculateDocumentPosition(index, len(targetText), originalText, documentType)

	// Calculate confidence based on text uniqueness
	confidence := exactMatchConfidence(matchCount)

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
			"match_count": matchCount,
		},
	}
}

// searchScope returns the byte range of originalText that a match reported on
// extractedPos.Line should be resolved within, and whether that range is usable.
//
// # Why resolution must be scoped to the line
//
// This function exists because both matchers below used to resolve with a
// document-wide search and therefore always returned the FIRST occurrence of the
// value, whatever line it was reported on. When a value occurs more than once that
// answer is wrong, and the wrong answer reached the redactor: a PHONE reported at
// HIGH 100 on line 2 was resolved to an occurrence on line 1, so line 2 was never
// rewritten and the reported value shipped in the "redacted" output in cleartext at
// exit 0 (#519).
//
// The line number is the one piece of information that disambiguates the
// occurrences, and it was already being passed in and ignored.
//
// Scoping is also strictly CHEAPER, which is worth stating because a correctness fix
// that cost performance would be a trade. Resolving document-wide took two whole
// passes per match — one strings.Index plus one strings.Count — so a document with m
// matches paid 2m passes. Locating the line is one pass, and the Index and Count that
// follow run over one line rather than the document.
//
// ok is false when the line cannot be located, which is not an error: a bounded or
// consolidated match, or line-number drift from an extractor, leaves a match whose
// recorded line does not contain its text. Callers fall back to the document-wide
// search in that case, so such a match is still located and still redacted exactly as
// before — the same policy PlainTextRedactor.findMatchPosition already documents.
func searchScope(extractedPos redactors.TextPosition, originalText string) (start, end int, ok bool) {
	if extractedPos.Line < 1 {
		return 0, 0, false
	}
	start = 0
	for line := 1; line < extractedPos.Line; line++ {
		nl := strings.IndexByte(originalText[start:], '\n')
		if nl < 0 {
			return 0, 0, false
		}
		start += nl + 1
	}
	end = len(originalText)
	if nl := strings.IndexByte(originalText[start:], '\n'); nl >= 0 {
		end = start + nl
	}
	return start, end, true
}

// exactMatchInScope resolves targetText to a document offset, preferring the line it
// was reported on, and returns the occurrence count within whichever scope answered.
//
// The count feeds exactMatchConfidence, and counting within the scope that produced
// the offset is the point: a value occurring once on its own line is unambiguously
// located there however many times it appears elsewhere in the document, so it earns
// the unique-match confidence rather than being de-rated for copies that were never
// candidates.
func exactMatchInScope(extractedPos redactors.TextPosition, targetText, originalText string) (index, matchCount int, ok bool) {
	if start, end, scoped := searchScope(extractedPos, originalText); scoped {
		if i := strings.Index(originalText[start:end], targetText); i >= 0 {
			return start + i, strings.Count(originalText[start:end], targetText), true
		}
	}

	// The reported line does not hold the text; fall back to the document.
	index = strings.Index(originalText, targetText)
	if index == -1 {
		return 0, 0, false
	}
	return index, strings.Count(originalText, targetText), true
}

// tryFuzzyMatch attempts fuzzy text matching
func (dpc *DefaultPositionCorrelator) tryFuzzyMatch(extractedPos redactors.TextPosition, targetText, originalText, documentType string) *PositionCorrelation {
	// Scoped to the reported line for the same reason as the exact matcher, and this
	// path is the one that actually shipped the leak in #519: for a value occurring
	// twice, exactMatchConfidence correctly de-rated it to 0.7125 and the caller's 0.8
	// gate rejected it — but calculateFuzzyMatchConfidence returns 0.8*1.0 = 0.8 for an
	// edit distance of 0, which clears a `>=` 0.8 gate by exactly nothing and admitted
	// the same document-wide offset the exact path had just refused.
	searchText, offset := originalText, 0
	if start, end, scoped := searchScope(extractedPos, originalText); scoped {
		if strings.Contains(originalText[start:end], targetText) {
			searchText, offset = originalText[start:end], start
		}
	}

	bestMatch := dpc.findBestFuzzyMatch(targetText, searchText)
	if bestMatch == nil {
		return nil
	}
	bestMatch.Index += offset

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
	// Count lines and calculate position. See lineAndColumnAt: this used to
	// strings.Split everything before index on every call, once per match.
	line, charInLine := lineAndColumnAt(text, index)

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
	return exactMatchConfidence(strings.Count(originalText, targetText))
}

// exactMatchConfidence scores an exact match from how many times its text occurs
// in the document: a unique occurrence is trusted, a repeated one is discounted.
//
// Split out from calculateExactMatchConfidence so a caller that already knows the
// occurrence count does not have to rescan the document to recompute it. The
// arithmetic is unchanged.
func exactMatchConfidence(matchCount int) float64 {
	// Base confidence for exact match
	baseConfidence := 0.95

	if matchCount <= 1 {
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
