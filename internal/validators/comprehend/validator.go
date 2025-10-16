// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package comprehend

// GENAI_DISABLED: This entire file has been disabled as part of GenAI feature removal
// The comprehend-analyzer-lib dependency and AWS SDK v2 required for this functionality
// have been removed from go.mod to reduce binary size and eliminate cloud service dependencies.

/*
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ferret-scan/internal/detector"
	comprehend_analyzer_lib "ferret-scan/internal/validators/comprehend/comprehend-analyzer-lib"
)
*/

/*
// Validator implements PII detection using Amazon Comprehend
type Validator struct{
	name      string
	enabled   bool
	awsRegion string
}

// NewValidator creates a new Comprehend validator
func NewValidator() *Validator {
	return &Validator{
		name:      "COMPREHEND_PII",
		enabled:   false, // Disabled by default, requires --enable-genai
		awsRegion: "us-east-1",
	}
}

// SetEnabled enables or disables the Comprehend validator
func (v *Validator) SetEnabled(enabled bool) {
	v.enabled = enabled
}

// SetRegion sets the AWS region for Comprehend
func (v *Validator) SetRegion(region string) {
	v.awsRegion = region
}

// Validate processes a file for PII detection by reading its content
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	if !v.enabled {
		return []detector.Match{}, nil
	}

	// Read file content
	cleanPath := filepath.Clean(filePath)
	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return []detector.Match{}, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Use ValidateContent to analyze the text
	return v.ValidateContent(string(content), filePath)
}

// ValidateContent analyzes text content for PII using Amazon Comprehend
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	if !v.enabled {
		return []detector.Match{}, nil
	}

	if strings.TrimSpace(content) == "" {
		return []detector.Match{}, nil
	}

	// Validate AWS credentials
	if err := comprehend_analyzer_lib.ValidateAWSCredentials(v.awsRegion); err != nil {
		return []detector.Match{}, fmt.Errorf("AWS credentials validation failed: %w", err)
	}

	// Use the same modified text that will be sent to Comprehend
	modifiedContent := content

	// Estimate and log cost in debug mode
	if os.Getenv("FERRET_DEBUG") == "1" {
		cost := comprehend_analyzer_lib.EstimateComprehendCost(len(modifiedContent))
		fmt.Fprintf(os.Stderr, "[DEBUG] Comprehend estimated cost for %s: $%.6f\n", filepath.Base(originalPath), cost)
	}

	// Chunk text if it exceeds Comprehend's 100KB limit
	const maxChunkSize = 100000 // 100KB limit
	var allEntities []comprehend_analyzer_lib.PIIEntity

	if len(modifiedContent) <= maxChunkSize {
		result, err := comprehend_analyzer_lib.AnalyzePII(modifiedContent, filepath.Base(originalPath), v.awsRegion)
		if err != nil {
			return []detector.Match{}, fmt.Errorf("Comprehend PII analysis failed: %w", err)
		}
		allEntities = result.PIIEntities
	} else {
		// Process in chunks
		for offset := 0; offset < len(modifiedContent); offset += maxChunkSize {
			end := offset + maxChunkSize
			if end > len(modifiedContent) {
				end = len(modifiedContent)
			}

			chunk := modifiedContent[offset:end]
			result, err := comprehend_analyzer_lib.AnalyzePII(chunk, filepath.Base(originalPath), v.awsRegion)
			if err != nil {
				return []detector.Match{}, fmt.Errorf("Comprehend PII analysis failed on chunk: %w", err)
			}

			// Adjust offsets for the chunk position
			for _, entity := range result.PIIEntities {
				// Check for potential overflow before conversion
				if offset > int(^uint32(0)>>1) { // Max int32 value
					return []detector.Match{}, fmt.Errorf("file too large: chunk offset %d exceeds int32 maximum", offset)
				}
				// #nosec G115 - integer overflow protection implemented above with max int32 value check
				entity.BeginOffset += int32(offset)
				// #nosec G115 - integer overflow protection implemented above with max int32 value check
				entity.EndOffset += int32(offset)
				allEntities = append(allEntities, entity)
			}
		}
	}

	// Convert PII entities to matches with filtering
	var matches []detector.Match
	for _, entity := range allEntities {
		// Use the original text that Comprehend found
		originalText := entity.Text

		// Filter out nonsensical detections
		if !v.isValidPII(strings.TrimSpace(originalText), entity.Type) {
			continue
		}

		confidence := v.calculateConfidence(entity)

		match := detector.Match{
			Text:       strings.ReplaceAll(strings.TrimSpace(originalText), "\n", " "),
			LineNumber: v.calculateLineNumber(modifiedContent, int(entity.BeginOffset)),
			Type:       fmt.Sprintf("PII_%s", entity.Type),
			Confidence: float64(confidence),
			Validator:  "comprehend",
			Metadata: map[string]any{
				"pii_type":     entity.Type,
				"begin_offset": entity.BeginOffset,
				"end_offset":   entity.EndOffset,
				"description":  fmt.Sprintf("Amazon Comprehend detected %s with %.1f%% confidence", entity.Type, entity.Confidence*100),
			},
			Filename: originalPath,
			Context:  v.buildContextInfo(modifiedContent, int(entity.BeginOffset), int(entity.EndOffset)),
		}

		matches = append(matches, match)
	}

	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Comprehend found %d PII entities\n", len(allEntities))
		for i, entity := range allEntities {
			if i >= 3 {
				break
			}
			begin, end := int(entity.BeginOffset), int(entity.EndOffset)
			actual := ""
			if begin >= 0 && end <= len(modifiedContent) {
				actual = modifiedContent[begin:end]
			}
			match := entity.Text == actual
			fmt.Fprintf(os.Stderr, "[DEBUG] %d: Type=%s, Offset=%d-%d, Match=%v\n",
				i+1, entity.Type, begin, end, match)
		}
	}

	return matches, nil
}

// calculateLineNumber calculates the line number for a given character offset
func (v *Validator) calculateLineNumber(content string, offset int) int {
	if offset < 0 || offset >= len(content) {
		return 1
	}

	// Count newlines up to the offset
	lineNumber := 1
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			lineNumber++
		}
	}

	return lineNumber
}

// calculateConfidence converts Comprehend confidence to our confidence levels
func (v *Validator) calculateConfidence(entity comprehend_analyzer_lib.PIIEntity) int {
	// Comprehend confidence is 0-1, convert to 0-100
	baseConfidence := entity.Confidence * 100

	// Adjust based on PII type sensitivity
	highSensitivityTypes := map[string]bool{
		"SSN":                 true,
		"CREDIT_DEBIT_NUMBER": true,
		"AWS_ACCESS_KEY":      true,
		"AWS_SECRET_KEY":      true,
		"PASSWORD":            true,
		"PASSPORT":            true,
	}

	if highSensitivityTypes[entity.Type] {
		// Boost confidence for high-sensitivity PII
		baseConfidence = baseConfidence * 1.1
		if baseConfidence > 100 {
			baseConfidence = 100
		}
	}

	return int(baseConfidence)
}

// buildContextInfo creates a ContextInfo structure for a match
func (v *Validator) buildContextInfo(content string, beginOffset, endOffset int) detector.ContextInfo {
	const contextLength = 50

	start := beginOffset - contextLength
	if start < 0 {
		start = 0
	}

	end := endOffset + contextLength
	if end > len(content) {
		end = len(content)
	}

	// Extract before and after text
	beforeText := content[start:beginOffset]
	afterText := content[endOffset:end]

	// Create full line context with PII redacted
	fullContext := content[start:end]
	if beginOffset >= start && endOffset <= end {
		relativeBegin := beginOffset - start
		relativeEnd := endOffset - start
		fullContext = fullContext[:relativeBegin] + "[REDACTED]" + fullContext[relativeEnd:]
	}

	// Clean up context (remove newlines, extra spaces)
	beforeText = strings.Join(strings.Fields(beforeText), " ")
	afterText = strings.Join(strings.Fields(afterText), " ")
	fullContext = strings.Join(strings.Fields(fullContext), " ")

	return detector.ContextInfo{
		BeforeText: beforeText,
		AfterText:  afterText,
		FullLine:   fullContext,
	}
}

// isValidPII filters out nonsensical PII detections
func (v *Validator) isValidPII(text, piiType string) bool {
	text = strings.TrimSpace(text)

	// Filter out very short or empty text
	if len(text) < 2 {
		return false
	}

	// Type-specific validation
	switch piiType {
	case "EMAIL":
		// Must contain @ and reasonable length
		return len(text) >= 5 && strings.Contains(text, "@") && containsLetter(text)
	case "PHONE":
		// Must contain digits and reasonable length
		return len(text) >= 7 && containsDigit(text) && !strings.Contains(text, "@")
	case "NAME":
		// Must have letters and reasonable length, no digits or special chars
		return len(text) >= 3 && containsLetter(text) && !containsDigit(text) && !strings.Contains(text, "@")
	case "ADDRESS":
		// Must be reasonable length
		return len(text) >= 8
	case "DATE_TIME":
		// Must be reasonable length
		return len(text) >= 4
	default:
		return len(text) >= 3
	}
}

// containsLetter checks if text contains at least one letter
func containsLetter(text string) bool {
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// containsDigit checks if text contains at least one digit
func containsDigit(text string) bool {
	for _, r := range text {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// CalculateConfidence calculates confidence for a match (required by Validator interface)
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// This method is not used for Comprehend since it provides its own confidence
	return 0.0, map[string]bool{}
}

// AnalyzeContext analyzes context for confidence adjustment (required by Validator interface)
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Comprehend provides its own context analysis, so no additional adjustment needed
	return 0.0
}
*/
