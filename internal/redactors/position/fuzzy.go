// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"ferret-scan/internal/redactors"
	"math"
	"strings"
	"unicode"
)

// findBestFuzzyMatch finds the best fuzzy match for the target text in the original text
func (dpc *DefaultPositionCorrelator) findBestFuzzyMatch(targetText, originalText string) *FuzzyMatch {
	if len(targetText) == 0 || len(originalText) == 0 {
		return nil
	}

	bestMatch := &FuzzyMatch{
		EditDistance: math.MaxInt32,
		Similarity:   0.0,
	}

	targetLen := len(targetText)
	searchWindowSize := targetLen + dpc.maxEditDistance*2

	// Slide a window across the original text
	for i := 0; i <= len(originalText)-targetLen; i++ {
		// Extract candidate text
		endPos := min(i+searchWindowSize, len(originalText))
		candidateText := originalText[i:endPos]

		// Find the best match within this candidate
		match := dpc.findBestMatchInCandidate(targetText, candidateText, i)
		if match != nil && match.EditDistance < bestMatch.EditDistance {
			*bestMatch = *match
		}

		// Early termination if we find an exact match
		if bestMatch.EditDistance == 0 {
			break
		}
	}

	// Return nil if no reasonable match found
	if bestMatch.EditDistance > dpc.maxEditDistance {
		return nil
	}

	return bestMatch
}

// findBestMatchInCandidate finds the best match within a candidate text segment
func (dpc *DefaultPositionCorrelator) findBestMatchInCandidate(targetText, candidateText string, baseIndex int) *FuzzyMatch {
	targetLen := len(targetText)
	bestMatch := &FuzzyMatch{
		EditDistance: math.MaxInt32,
		Similarity:   0.0,
	}

	// Try different substring lengths around the target length
	for length := max(1, targetLen-dpc.maxEditDistance); length <= min(len(candidateText), targetLen+dpc.maxEditDistance); length++ {
		for start := 0; start <= len(candidateText)-length; start++ {
			substring := candidateText[start : start+length]
			editDistance := dpc.calculateEditDistance(targetText, substring)

			if editDistance < bestMatch.EditDistance {
				similarity := dpc.calculateStringSimilarity(targetText, substring)
				bestMatch = &FuzzyMatch{
					Text:         substring,
					Index:        baseIndex + start,
					EditDistance: editDistance,
					Similarity:   similarity,
				}
			}

			// Early termination for exact matches
			if editDistance == 0 {
				return bestMatch
			}
		}
	}

	return bestMatch
}

// calculateEditDistance calculates the Levenshtein distance between two strings
func (dpc *DefaultPositionCorrelator) calculateEditDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create a matrix for dynamic programming
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	// Initialize first row and column
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	// Fill the matrix
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min3(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// calculateStringSimilarity calculates similarity between two strings using multiple metrics
func (dpc *DefaultPositionCorrelator) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Normalize strings for comparison
	norm1 := dpc.normalizeString(s1)
	norm2 := dpc.normalizeString(s2)

	// Calculate multiple similarity metrics and combine them
	editSimilarity := dpc.calculateEditSimilarity(norm1, norm2)
	jaccardSimilarity := dpc.calculateJaccardSimilarity(norm1, norm2)
	longestCommonSimilarity := dpc.calculateLongestCommonSubsequenceSimilarity(norm1, norm2)

	// Weighted combination of similarities
	return 0.5*editSimilarity + 0.3*jaccardSimilarity + 0.2*longestCommonSimilarity
}

// calculateEditSimilarity calculates similarity based on edit distance
func (dpc *DefaultPositionCorrelator) calculateEditSimilarity(s1, s2 string) float64 {
	editDistance := dpc.calculateEditDistance(s1, s2)
	maxLen := max(len(s1), len(s2))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - float64(editDistance)/float64(maxLen)
}

// calculateJaccardSimilarity calculates Jaccard similarity based on character n-grams
func (dpc *DefaultPositionCorrelator) calculateJaccardSimilarity(s1, s2 string) float64 {
	// Use character bigrams for similarity calculation
	ngrams1 := dpc.extractNGrams(s1, 2)
	ngrams2 := dpc.extractNGrams(s2, 2)

	if len(ngrams1) == 0 && len(ngrams2) == 0 {
		return 1.0
	}

	intersection := 0
	union := make(map[string]bool)

	// Add all ngrams to union
	for ngram := range ngrams1 {
		union[ngram] = true
	}
	for ngram := range ngrams2 {
		union[ngram] = true
	}

	// Count intersection
	for ngram := range ngrams1 {
		if ngrams2[ngram] {
			intersection++
		}
	}

	if len(union) == 0 {
		return 0.0
	}

	return float64(intersection) / float64(len(union))
}

// calculateLongestCommonSubsequenceSimilarity calculates similarity based on LCS
func (dpc *DefaultPositionCorrelator) calculateLongestCommonSubsequenceSimilarity(s1, s2 string) float64 {
	lcsLength := dpc.calculateLCS(s1, s2)
	maxLen := max(len(s1), len(s2))

	if maxLen == 0 {
		return 1.0
	}

	return float64(lcsLength) / float64(maxLen)
}

// calculateLCS calculates the length of the longest common subsequence
func (dpc *DefaultPositionCorrelator) calculateLCS(s1, s2 string) int {
	m, n := len(s1), len(s2)
	if m == 0 || n == 0 {
		return 0
	}

	// Create LCS table
	lcs := make([][]int, m+1)
	for i := range lcs {
		lcs[i] = make([]int, n+1)
	}

	// Fill LCS table
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				lcs[i][j] = lcs[i-1][j-1] + 1
			} else {
				lcs[i][j] = max(lcs[i-1][j], lcs[i][j-1])
			}
		}
	}

	return lcs[m][n]
}

// extractNGrams extracts n-grams from a string
func (dpc *DefaultPositionCorrelator) extractNGrams(s string, n int) map[string]bool {
	ngrams := make(map[string]bool)

	if len(s) < n {
		ngrams[s] = true
		return ngrams
	}

	for i := 0; i <= len(s)-n; i++ {
		ngram := s[i : i+n]
		ngrams[ngram] = true
	}

	return ngrams
}

// normalizeString normalizes a string for comparison
func (dpc *DefaultPositionCorrelator) normalizeString(s string) string {
	// Convert to lowercase and remove extra whitespace
	s = strings.ToLower(s)
	s = strings.TrimSpace(s)

	// Replace multiple whitespace with single space
	words := strings.Fields(s)
	normalized := strings.Join(words, " ")

	// Remove non-alphanumeric characters except spaces
	var result strings.Builder
	for _, r := range normalized {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// findBestContextualMatch finds the best contextual match for the target text
func (dpc *DefaultPositionCorrelator) findBestContextualMatch(extractedContext, targetText, originalText string) *ContextMatch {
	if len(extractedContext) == 0 || len(targetText) == 0 || len(originalText) == 0 {
		return nil
	}

	bestMatch := &ContextMatch{
		Similarity: 0.0,
	}

	// Search for the target text in the original text
	targetIndices := dpc.findAllOccurrences(targetText, originalText)
	if len(targetIndices) == 0 {
		return nil
	}

	// For each occurrence, extract context and compare with extracted context
	for _, index := range targetIndices {
		originalContext := dpc.extractContext(index, originalText)
		similarity := dpc.calculateStringSimilarity(extractedContext, originalContext)

		if similarity > bestMatch.Similarity {
			bestMatch = &ContextMatch{
				Index:      index,
				Context:    originalContext,
				Similarity: similarity,
			}
		}
	}

	// Return nil if similarity is too low
	if bestMatch.Similarity < 0.3 {
		return nil
	}

	return bestMatch
}

// findAllOccurrences finds all occurrences of a substring in a string
func (dpc *DefaultPositionCorrelator) findAllOccurrences(substring, text string) []int {
	var indices []int

	if len(substring) == 0 {
		return indices
	}

	start := 0

	for start < len(text) {
		index := strings.Index(text[start:], substring)
		if index == -1 {
			break
		}

		actualIndex := start + index
		indices = append(indices, actualIndex)
		start = actualIndex + 1
	}

	return indices
}

// extractContext extracts context around a position in text
func (dpc *DefaultPositionCorrelator) extractContext(index int, text string) string {
	halfWindow := dpc.contextWindowSize / 2

	start := max(0, index-halfWindow)
	end := min(len(text), index+halfWindow)

	return text[start:end]
}

// extractExtractedContext extracts context around a position in extracted text
func (dpc *DefaultPositionCorrelator) extractExtractedContext(pos redactors.TextPosition, extractedText string) string {
	lines := strings.Split(extractedText, "\n")

	if pos.Line < 1 || pos.Line > len(lines) {
		return ""
	}

	// Calculate character index in the full text
	charIndex := 0
	for i := 0; i < pos.Line-1; i++ {
		charIndex += len(lines[i]) + 1 // +1 for newline
	}
	charIndex += pos.StartChar

	return dpc.extractContext(charIndex, extractedText)
}

// estimatePositionByLine estimates position in original text based on line number
func (dpc *DefaultPositionCorrelator) estimatePositionByLine(pos redactors.TextPosition, originalText string) int {
	lines := strings.Split(originalText, "\n")

	if pos.Line < 1 {
		return 0
	}

	if pos.Line > len(lines) {
		return len(originalText)
	}

	// Calculate character index up to the target line
	charIndex := 0
	for i := 0; i < pos.Line-1 && i < len(lines); i++ {
		charIndex += len(lines[i]) + 1 // +1 for newline
	}

	// Add character offset within the line
	if pos.Line <= len(lines) {
		lineLength := len(lines[pos.Line-1])
		charOffset := min(pos.StartChar, lineLength)
		charIndex += charOffset
	}

	return min(charIndex, len(originalText))
}

// Helper function for minimum of three integers
func min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}
