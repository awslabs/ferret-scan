// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package strategies

import (
	"regexp"
	"strings"

	"ferret-scan/internal/redactors"
)

// SimpleRedactionStrategy implements simple redaction with fixed replacement text
type SimpleRedactionStrategy struct {
	// name is the name of this strategy
	name string

	// supportedDataTypes lists the data types this strategy can handle
	supportedDataTypes []string

	// replacementTemplates maps data types to their replacement templates
	replacementTemplates map[string]string
}

// NewSimpleRedactionStrategy creates a new simple redaction strategy
func NewSimpleRedactionStrategy() *SimpleRedactionStrategy {
	strategy := &SimpleRedactionStrategy{
		name:               "simple_redaction_strategy",
		supportedDataTypes: []string{"*"}, // Supports all data types
		replacementTemplates: map[string]string{
			"CREDIT_CARD": "[CREDIT-CARD-REDACTED]",
			"SSN":         "[SSN-REDACTED]",
			"EMAIL":       "[EMAIL-REDACTED]",
			"PHONE":       "[PHONE-REDACTED]",
			"PERSON_NAME": "[PERSON-NAME-REDACTED]",
			"ADDRESS":     "[ADDRESS-REDACTED]",
			"DATE":        "[DATE-REDACTED]",
			"IP_ADDRESS":  "[IP-ADDRESS-REDACTED]",
			"URL":         "[URL-REDACTED]",
			"PASSWORD":    "[PASSWORD-HIDDEN]",
			"API_KEY":     "[API-KEY-HIDDEN]",
			"DEFAULT":     "[HIDDEN]",
		},
	}

	return strategy
}

// GetStrategyType returns the redaction strategy type
func (srs *SimpleRedactionStrategy) GetStrategyType() redactors.RedactionStrategy {
	return redactors.RedactionSimple
}

// GetStrategyName returns the name of the strategy implementation
func (srs *SimpleRedactionStrategy) GetStrategyName() string {
	return srs.name
}

// GetSupportedDataTypes returns the data types this strategy can handle
func (srs *SimpleRedactionStrategy) GetSupportedDataTypes() []string {
	return srs.supportedDataTypes
}

// RedactText redacts text using simple replacement
func (srs *SimpleRedactionStrategy) RedactText(originalText, dataType string, context RedactionContext) (*RedactionResult, error) {
	// Get replacement text for the data type
	replacement, exists := srs.replacementTemplates[dataType]
	if !exists {
		replacement = srs.replacementTemplates["DEFAULT"]
	}

	// Apply length preservation if requested
	if context.PreserveLength {
		replacement = srs.adjustReplacementLength(replacement, len(originalText))
	}

	// Apply format preservation if requested (limited for simple strategy)
	if context.PreserveFormat {
		replacement = srs.applyBasicFormatPreservation(originalText, replacement)
	}

	result := &RedactionResult{
		RedactedText:    replacement,
		Strategy:        redactors.RedactionSimple,
		DataType:        dataType,
		Confidence:      1.0, // Always confident for simple replacement
		PreservedFormat: context.PreserveFormat,
		PreservedLength: context.PreserveLength && len(replacement) == len(originalText),
		SecurityLevel:   5, // Highest security - no original data remains
		Metadata: map[string]interface{}{
			"replacement_template": replacement,
			"original_length":      len(originalText),
			"redacted_length":      len(replacement),
		},
	}

	return result, nil
}

// ValidateRedaction validates simple redaction
func (srs *SimpleRedactionStrategy) ValidateRedaction(original, redacted, dataType string) (*ValidationResult, error) {
	issues := []ValidationIssue{}

	// Check if original data leaked into redacted text
	if strings.Contains(redacted, original) && len(original) > 2 {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityCritical,
			Type:        IssueTypeSecurity,
			Description: "Original data found in hidden text",
			Suggestion:  "Ensure complete replacement of sensitive data",
		})
	}

	// Check if redacted text looks like a redaction placeholder
	if !srs.looksLikeRedactionPlaceholder(redacted) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypePattern,
			Description: "Redacted text doesn't look like a standard redaction placeholder",
			Suggestion:  "Use standard redaction placeholder format like TYPE-HIDDEN",
		})
	}

	// Calculate security score
	securityScore := 1.0
	if len(issues) > 0 && issues[0].Severity == SeverityCritical {
		securityScore = 0.0
	}

	return &ValidationResult{
		Valid:         securityScore > 0.0,
		Issues:        issues,
		SecurityScore: securityScore,
		FormatScore:   srs.calculateFormatScore(original, redacted),
		Confidence:    0.95,
	}, nil
}

// adjustReplacementLength adjusts replacement text to match original length
func (srs *SimpleRedactionStrategy) adjustReplacementLength(replacement string, targetLength int) string {
	if len(replacement) == targetLength {
		return replacement
	}

	if len(replacement) > targetLength {
		// Truncate
		if targetLength > 3 {
			return replacement[:targetLength-3] + "..."
		}
		return replacement[:targetLength]
	}

	// Pad with spaces or repeat pattern
	padding := targetLength - len(replacement)
	if strings.HasPrefix(replacement, "[") && strings.HasSuffix(replacement, "]") {
		// For bracketed replacements, pad with spaces inside brackets
		inner := replacement[1 : len(replacement)-1]
		paddedInner := inner + strings.Repeat(" ", padding)
		return "[" + paddedInner + "]"
	}

	// Default padding with spaces
	return replacement + strings.Repeat(" ", padding)
}

// applyBasicFormatPreservation applies basic format preservation for simple strategy
func (srs *SimpleRedactionStrategy) applyBasicFormatPreservation(original, replacement string) string {
	// For simple strategy, format preservation is limited
	// We can preserve some basic patterns like maintaining brackets, parentheses, etc.

	if len(original) == 0 {
		return replacement
	}

	// If original has specific formatting, try to maintain it
	if strings.Contains(original, "(") && strings.Contains(original, ")") {
		// Wrap in parentheses if original had them
		return "(" + strings.Trim(replacement, "[]") + ")"
	}

	if strings.Contains(original, "-") && len(original) > 5 {
		// Add dashes for structured data like SSN, credit cards
		return strings.ReplaceAll(replacement, " ", "-")
	}

	return replacement
}

// looksLikeRedactionPlaceholder checks if text looks like a redaction placeholder
func (srs *SimpleRedactionStrategy) looksLikeRedactionPlaceholder(text string) bool {
	// Check for common redaction patterns
	redactionPatterns := []string{
		"[HIDDEN]",
		"[.*-HIDDEN]",
		"\\*\\*\\*+",
		"XXX+",
		"####+",
	}

	for _, pattern := range redactionPatterns {
		if matched, _ := regexp.MatchString(pattern, text); matched {
			return true
		}
	}

	return false
}

// calculateFormatScore calculates basic format preservation score
func (srs *SimpleRedactionStrategy) calculateFormatScore(original, redacted string) float64 {
	// Simple strategy has limited format preservation
	// Score based on whether basic structure is maintained

	if len(original) == 0 {
		return 1.0
	}

	score := 0.0

	// Check if length is similar (within reasonable range)
	lengthRatio := float64(len(redacted)) / float64(len(original))
	if lengthRatio >= 0.5 && lengthRatio <= 2.0 {
		score += 0.3
	}

	// Check if basic punctuation patterns are preserved
	originalHasDashes := strings.Contains(original, "-")
	redactedHasDashes := strings.Contains(redacted, "-")
	if originalHasDashes == redactedHasDashes {
		score += 0.2
	}

	originalHasParens := strings.Contains(original, "(") || strings.Contains(original, ")")
	redactedHasParens := strings.Contains(redacted, "(") || strings.Contains(redacted, ")")
	if originalHasParens == redactedHasParens {
		score += 0.2
	}

	originalHasDots := strings.Contains(original, ".")
	redactedHasDots := strings.Contains(redacted, ".")
	if originalHasDots == redactedHasDots {
		score += 0.2
	}

	// Base score for being a proper redaction
	if srs.looksLikeRedactionPlaceholder(redacted) {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}
