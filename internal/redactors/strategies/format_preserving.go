// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package strategies

import (
	"fmt"
	"regexp"
	"strings"

	"ferret-scan/internal/redactors"
)

// FormatPreservingStrategy implements format-preserving redaction
type FormatPreservingStrategy struct {
	// name is the name of this strategy
	name string

	// supportedDataTypes lists the data types this strategy can handle
	supportedDataTypes []string

	// syntheticStrategy is used for generating synthetic data when needed
	syntheticStrategy *SyntheticDataStrategy
}

// NewFormatPreservingStrategy creates a new format-preserving strategy
func NewFormatPreservingStrategy() *FormatPreservingStrategy {
	return &FormatPreservingStrategy{
		name: "format_preserving_strategy",
		supportedDataTypes: []string{
			"CREDIT_CARD", "SSN", "EMAIL", "PHONE", "PERSON_NAME",
			"ADDRESS", "DATE", "IP_ADDRESS", "URL", "*", // Supports all types
		},
		syntheticStrategy: NewSyntheticDataStrategy(),
	}
}

// GetStrategyType returns the redaction strategy type
func (fps *FormatPreservingStrategy) GetStrategyType() redactors.RedactionStrategy {
	return redactors.RedactionFormatPreserving
}

// GetStrategyName returns the name of the strategy implementation
func (fps *FormatPreservingStrategy) GetStrategyName() string {
	return fps.name
}

// GetSupportedDataTypes returns the data types this strategy can handle
func (fps *FormatPreservingStrategy) GetSupportedDataTypes() []string {
	return fps.supportedDataTypes
}

// RedactText redacts text while preserving format and structure
func (fps *FormatPreservingStrategy) RedactText(originalText, dataType string, context RedactionContext) (*RedactionResult, error) {
	// Force format and length preservation for this strategy
	context.PreserveFormat = true
	context.PreserveLength = true

	var redactedText string
	var err error

	// Use data type-specific format preservation
	switch dataType {
	case "CREDIT_CARD":
		redactedText, err = fps.redactCreditCardFormatPreserving(originalText, context)
	case "SSN":
		redactedText, err = fps.redactSSNFormatPreserving(originalText, context)
	case "EMAIL":
		redactedText, err = fps.redactEmailFormatPreserving(originalText, context)
	case "PHONE":
		redactedText, err = fps.redactPhoneFormatPreserving(originalText, context)
	case "PERSON_NAME":
		redactedText, err = fps.redactPersonNameFormatPreserving(originalText, context)
	default:
		// Generic format-preserving redaction
		redactedText, err = fps.redactGenericFormatPreserving(originalText, context)
	}

	if err != nil {
		return nil, fmt.Errorf("format-preserving redaction failed: %w", err)
	}

	result := &RedactionResult{
		RedactedText:    redactedText,
		Strategy:        redactors.RedactionFormatPreserving,
		DataType:        dataType,
		Confidence:      0.9,
		PreservedFormat: true,
		PreservedLength: len(redactedText) == len(originalText),
		SecurityLevel:   context.SecurityLevel,
		Metadata: map[string]interface{}{
			"preservation_method": "format_preserving",
			"original_length":     len(originalText),
			"redacted_length":     len(redactedText),
		},
	}

	return result, nil
}

// ValidateRedaction validates format-preserving redaction
func (fps *FormatPreservingStrategy) ValidateRedaction(original, redacted, dataType string) (*ValidationResult, error) {
	issues := []ValidationIssue{}

	// Check length preservation
	if len(original) != len(redacted) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypeLength,
			Description: "Length was not preserved in format-preserving redaction",
			Suggestion:  "Ensure hidden text maintains original length",
		})
	}

	// Check format preservation
	formatScore := fps.calculateFormatPreservationScore(original, redacted)
	if formatScore < 0.8 {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypeFormat,
			Description: "Format preservation could be improved",
			Suggestion:  "Better preserve character types and structure",
		})
	}

	// Check for potential data leakage
	if fps.hasDataLeakage(original, redacted) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityCritical,
			Type:        IssueTypeSecurity,
			Description: "Potential data leakage detected in hidden text",
			Suggestion:  "Ensure no original sensitive data remains in hidden text",
		})
	}

	return &ValidationResult{
		Valid:         len(issues) == 0 || issues[0].Severity != SeverityCritical,
		Issues:        issues,
		SecurityScore: fps.calculateSecurityScore(original, redacted),
		FormatScore:   formatScore,
		Confidence:    0.85,
	}, nil
}

// redactCreditCardFormatPreserving redacts credit card while preserving format
func (fps *FormatPreservingStrategy) redactCreditCardFormatPreserving(original string, context RedactionContext) (string, error) {
	// Generate synthetic credit card
	synthetic, err := fps.syntheticStrategy.generateCreditCard(original, context)
	if err != nil {
		// Fallback to pattern-based redaction
		return fps.redactWithPattern(original, `\d`, "X"), nil
	}

	// Preserve exact format from original
	return fps.preserveExactFormat(original, synthetic), nil
}

// redactSSNFormatPreserving redacts SSN while preserving format
func (fps *FormatPreservingStrategy) redactSSNFormatPreserving(original string, context RedactionContext) (string, error) {
	// Generate synthetic SSN
	synthetic, err := fps.syntheticStrategy.generateSSN(original, context)
	if err != nil {
		// Fallback to pattern-based redaction
		return fps.redactWithPattern(original, `\d`, "X"), nil
	}

	return fps.preserveExactFormat(original, synthetic), nil
}

// redactEmailFormatPreserving redacts email while preserving format
func (fps *FormatPreservingStrategy) redactEmailFormatPreserving(original string, context RedactionContext) (string, error) {
	// Split email into parts
	parts := strings.Split(original, "@")
	if len(parts) != 2 {
		return fps.redactGenericFormatPreserving(original, context)
	}

	username := parts[0]
	domain := parts[1]

	// Redact username while preserving structure
	redactedUsername := fps.redactUsernamePreservingFormat(username)

	// Keep domain or redact based on security level
	var redactedDomain string
	if context.SecurityLevel >= 4 {
		redactedDomain = fps.redactDomainPreservingFormat(domain)
	} else {
		redactedDomain = domain // Keep domain for format preservation
	}

	return redactedUsername + "@" + redactedDomain, nil
}

// redactPhoneFormatPreserving redacts phone while preserving format
func (fps *FormatPreservingStrategy) redactPhoneFormatPreserving(original string, context RedactionContext) (string, error) {
	// Generate synthetic phone
	synthetic, err := fps.syntheticStrategy.generatePhone(original, context)
	if err != nil {
		// Fallback to pattern-based redaction
		return fps.redactWithPattern(original, `\d`, "X"), nil
	}

	return fps.preserveExactFormat(original, synthetic), nil
}

// redactPersonNameFormatPreserving redacts person name while preserving format
func (fps *FormatPreservingStrategy) redactPersonNameFormatPreserving(original string, context RedactionContext) (string, error) {
	// Split name into parts
	parts := strings.Fields(original)
	redactedParts := make([]string, len(parts))

	for i, part := range parts {
		// Preserve capitalization pattern
		redactedParts[i] = fps.redactNamePartPreservingFormat(part)
	}

	return strings.Join(redactedParts, " "), nil
}

// redactGenericFormatPreserving provides generic format-preserving redaction
func (fps *FormatPreservingStrategy) redactGenericFormatPreserving(original string, context RedactionContext) (string, error) {
	result := make([]rune, len(original))

	for i, char := range original {
		switch {
		case char >= '0' && char <= '9':
			// Replace digits with random digits
			if randomDigit, err := generateSecureRandom(0, 10); err == nil {
				result[i] = rune('0' + randomDigit)
			} else {
				result[i] = 'X'
			}
		case char >= 'A' && char <= 'Z':
			// Replace uppercase letters with random uppercase letters
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('A' + randomLetter)
			} else {
				result[i] = 'X'
			}
		case char >= 'a' && char <= 'z':
			// Replace lowercase letters with random lowercase letters
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('a' + randomLetter)
			} else {
				result[i] = 'x'
			}
		default:
			// Preserve special characters, spaces, punctuation
			result[i] = char
		}
	}

	return string(result), nil
}

// Helper methods

// preserveExactFormat preserves the exact format from original in synthetic data
func (fps *FormatPreservingStrategy) preserveExactFormat(original, synthetic string) string {
	if len(original) == 0 {
		return synthetic
	}

	result := make([]rune, 0, len(original))
	syntheticRunes := []rune(regexp.MustCompile(`\W`).ReplaceAllString(synthetic, ""))
	syntheticIndex := 0

	for _, char := range original {
		if fps.isAlphaNumeric(char) {
			if syntheticIndex < len(syntheticRunes) {
				result = append(result, syntheticRunes[syntheticIndex])
				syntheticIndex++
			} else {
				result = append(result, 'X') // Fallback
			}
		} else {
			result = append(result, char) // Preserve formatting characters
		}
	}

	return string(result)
}

// redactWithPattern redacts text using a regex pattern
func (fps *FormatPreservingStrategy) redactWithPattern(text, pattern, replacement string) string {
	regex := regexp.MustCompile(pattern)
	return regex.ReplaceAllString(text, replacement)
}

// redactUsernamePreservingFormat redacts email username while preserving format
func (fps *FormatPreservingStrategy) redactUsernamePreservingFormat(username string) string {
	if len(username) == 0 {
		return username
	}

	result := make([]rune, len(username))
	for i, char := range username {
		switch {
		case char >= 'a' && char <= 'z':
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('a' + randomLetter)
			} else {
				result[i] = 'x'
			}
		case char >= 'A' && char <= 'Z':
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('A' + randomLetter)
			} else {
				result[i] = 'X'
			}
		case char >= '0' && char <= '9':
			if randomDigit, err := generateSecureRandom(0, 10); err == nil {
				result[i] = rune('0' + randomDigit)
			} else {
				result[i] = '0'
			}
		default:
			result[i] = char // Preserve dots, underscores, etc.
		}
	}

	return string(result)
}

// redactDomainPreservingFormat redacts email domain while preserving format
func (fps *FormatPreservingStrategy) redactDomainPreservingFormat(domain string) string {
	parts := strings.Split(domain, ".")
	redactedParts := make([]string, len(parts))

	for i, part := range parts {
		if i == len(parts)-1 {
			// Keep TLD for format preservation
			redactedParts[i] = part
		} else {
			redactedParts[i] = fps.redactDomainPartPreservingFormat(part)
		}
	}

	return strings.Join(redactedParts, ".")
}

// redactDomainPartPreservingFormat redacts a domain part while preserving format
func (fps *FormatPreservingStrategy) redactDomainPartPreservingFormat(part string) string {
	result := make([]rune, len(part))
	for i, char := range part {
		if char >= 'a' && char <= 'z' {
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('a' + randomLetter)
			} else {
				result[i] = 'x'
			}
		} else {
			result[i] = char
		}
	}
	return string(result)
}

// redactNamePartPreservingFormat redacts a name part while preserving capitalization
func (fps *FormatPreservingStrategy) redactNamePartPreservingFormat(namePart string) string {
	if len(namePart) == 0 {
		return namePart
	}

	result := make([]rune, len(namePart))
	for i, char := range namePart {
		switch {
		case char >= 'A' && char <= 'Z':
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('A' + randomLetter)
			} else {
				result[i] = 'X'
			}
		case char >= 'a' && char <= 'z':
			if randomLetter, err := generateSecureRandom(0, 26); err == nil {
				result[i] = rune('a' + randomLetter)
			} else {
				result[i] = 'x'
			}
		default:
			result[i] = char // Preserve apostrophes, hyphens, etc.
		}
	}

	return string(result)
}

// Validation helper methods

// calculateFormatPreservationScore calculates how well format was preserved
func (fps *FormatPreservingStrategy) calculateFormatPreservationScore(original, redacted string) float64 {
	if len(original) != len(redacted) {
		return 0.0
	}

	if len(original) == 0 {
		return 1.0
	}

	matches := 0
	for i, origChar := range original {
		if i < len(redacted) {
			redactedChar := rune(redacted[i])
			if fps.getCharacterType(origChar) == fps.getCharacterType(redactedChar) {
				matches++
			}
		}
	}

	return float64(matches) / float64(len(original))
}

// hasDataLeakage checks if original data leaked into redacted text
func (fps *FormatPreservingStrategy) hasDataLeakage(original, redacted string) bool {
	// Check for exact substrings (3+ characters) that might indicate leakage
	if len(original) < 3 {
		return false
	}

	for i := 0; i <= len(original)-3; i++ {
		substring := original[i : i+3]
		if strings.Contains(redacted, substring) {
			// Check if it's just formatting characters
			if regexp.MustCompile(`^[\s\-\.\(\)]+$`).MatchString(substring) {
				continue
			}
			return true
		}
	}

	return false
}

// calculateSecurityScore calculates the security score of the redaction
func (fps *FormatPreservingStrategy) calculateSecurityScore(original, redacted string) float64 {
	if fps.hasDataLeakage(original, redacted) {
		return 0.0
	}

	// Base security score for format-preserving redaction
	baseScore := 0.8

	// Reduce score if too much similarity
	similarity := fps.calculateSimilarity(original, redacted)
	if similarity > 0.5 {
		baseScore -= (similarity - 0.5) * 0.4
	}

	if baseScore < 0.1 {
		baseScore = 0.1
	}

	return baseScore
}

// calculateSimilarity calculates similarity between original and redacted text
func (fps *FormatPreservingStrategy) calculateSimilarity(original, redacted string) float64 {
	if len(original) == 0 || len(redacted) == 0 {
		return 0.0
	}

	matches := 0
	minLen := len(original)
	if len(redacted) < minLen {
		minLen = len(redacted)
	}

	for i := 0; i < minLen; i++ {
		if original[i] == redacted[i] {
			matches++
		}
	}

	return float64(matches) / float64(len(original))
}

// getCharacterType returns the type of a character for format comparison
func (fps *FormatPreservingStrategy) getCharacterType(char rune) string {
	switch {
	case char >= '0' && char <= '9':
		return "digit"
	case char >= 'A' && char <= 'Z':
		return "uppercase"
	case char >= 'a' && char <= 'z':
		return "lowercase"
	case char == ' ':
		return "space"
	case char == '-' || char == '_':
		return "separator"
	case char == '.' || char == ',':
		return "punctuation"
	case char == '(' || char == ')':
		return "parenthesis"
	default:
		return "other"
	}
}

// isAlphaNumeric checks if a character is alphanumeric
func (fps *FormatPreservingStrategy) isAlphaNumeric(char rune) bool {
	return (char >= '0' && char <= '9') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z')
}
