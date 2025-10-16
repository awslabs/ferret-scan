// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"ferret-scan/internal/detector"
)

// Validator is a starting point for creating new validators
// Rename this struct and customize it for your specific validator
type Validator struct {
	// Define your regex pattern(s) for detecting sensitive data
	pattern string

	// Keywords that suggest this is the type of data you're looking for
	positiveKeywords []string

	// Keywords that suggest this is NOT the type of data you're looking for
	negativeKeywords []string

	// Add any other fields specific to your validator
}

// IMPORTANT: When implementing your own validator:
// 1. Create a new package with a unique name (e.g., "ssn" instead of "template")
// 2. Keep the function name as NewValidator() but rename Validator to your own type
//
// NewValidator creates a new template validator instance
// This is the function that will be called from main.go
func NewValidator() *Validator {
	return &Validator{
		// Define your regex pattern for detecting sensitive data
		pattern: `\b(your-regex-pattern-here)\b`,

		// Define keywords that suggest this is the type of data you're looking for
		positiveKeywords: []string{
			"keyword1", "keyword2", "keyword3",
			// Add more positive keywords as needed
		},

		// Define keywords that suggest this is NOT the type of data you're looking for
		negativeKeywords: []string{
			"keyword4", "keyword5", "keyword6",
			// Add more negative keywords as needed
		},

		// Initialize any other fields specific to your validator
	}
}

// Validate implements the detector.Validator interface
// This method scans a file for potential matches and returns a list of matches with confidence scores
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var matches []detector.Match
	scanner := bufio.NewScanner(file)
	lineNum := 0
	re := regexp.MustCompile(v.pattern)

	// Create a context extractor
	contextExtractor := detector.NewContextExtractor()

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		foundMatches := re.FindAllString(line, -1)

		for _, match := range foundMatches {
			// Calculate base confidence
			confidence, checks := v.CalculateConfidence(match)

			// Extract context
			contextInfo, err := contextExtractor.ExtractContext(filePath, lineNum, match)
			if err == nil {
				// Analyze context and adjust confidence
				contextImpact := v.AnalyzeContext(match, contextInfo)
				confidence += contextImpact

				// Ensure confidence stays within bounds
				if confidence > 100 {
					confidence = 100
				} else if confidence < 0 {
					confidence = 0
				}

				// Store keywords found in context
				contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
				contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
				contextInfo.ConfidenceImpact = contextImpact
			}

			// Skip matches with 0% confidence - they are false positives
			if confidence <= 0 {
				continue
			}

			// Only include matches with reasonable confidence
			// You can adjust this threshold as needed
			if confidence > 40 {
				matches = append(matches, detector.Match{
					Text:       match,
					LineNumber: lineNum,
					Type:       "SAMPLE_CHECK", // Change this to your check type
					Confidence: confidence,
					Context:    contextInfo,
					Metadata: map[string]any{
						"validation_checks": checks,
						"context_impact":    contextInfo.ConfidenceImpact,
						// Add any other metadata specific to your validator
					},
				})
			}
		}
	}

	return matches, scanner.Err()
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Combine all context text for analysis
	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
	fullContext = strings.ToLower(fullContext)

	var confidenceImpact float64 = 0

	// Check for positive keywords (increase confidence)
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact += 7 // +7% for keywords in the same line
			} else {
				confidenceImpact += 3 // +3% for keywords in surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact -= 15 // -15% for negative keywords in the same line
			} else {
				confidenceImpact -= 7 // -7% for negative keywords in surrounding context
			}
		}
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 25 {
		confidenceImpact = 25 // Maximum +25% boost
	} else if confidenceImpact < -50 {
		confidenceImpact = -50 // Maximum -50% reduction
	}

	return confidenceImpact
}

// findKeywords returns a list of keywords found in the context
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
	fullContext = strings.ToLower(fullContext)

	var found []string
	for _, keyword := range keywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			found = append(found, keyword)
		}
	}

	return found
}

// CalculateConfidence calculates the confidence score for a potential match
// This is where you implement your validation logic
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Define validation checks
	checks := map[string]bool{
		"format":           true,
		"length":           true,
		"valid_characters": true,
		"not_test_data":    true,
		// Add more checks as needed
	}

	confidence := 100.0

	// Implement your validation logic here
	// Example:

	// Check length (adjust weight as needed)
	if len(match) < 8 {
		confidence -= 20
		checks["length"] = false
	}

	// Check format (adjust weight as needed)
	if !regexp.MustCompile(`your-validation-regex`).MatchString(match) {
		confidence -= 30
		checks["format"] = false
	}

	// Check for valid characters (adjust weight as needed)
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(match) {
		confidence -= 15
		checks["valid_characters"] = false
	}

	// Check for placeholder data (adjust weight as needed)
	if strings.Contains(strings.ToLower(match), "test") ||
		strings.Contains(strings.ToLower(match), "example") {
		confidence -= 25
		checks["not_test_data"] = false
	}

	// Ensure confidence is within bounds
	if confidence < 0 {
		confidence = 0
	}

	return confidence, checks
}
