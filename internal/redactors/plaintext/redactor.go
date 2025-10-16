// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/redactors"
	"ferret-scan/internal/redactors/position"
)

// PlainTextRedactor implements redaction for plain text files
type PlainTextRedactor struct {
	// observer handles observability and metrics
	observer *observability.StandardObserver

	// outputManager handles file system operations
	outputManager *redactors.OutputStructureManager

	// positionCorrelator handles position correlation between extracted and original text
	positionCorrelator position.PositionCorrelator

	// enablePositionCorrelation controls whether to use position correlation
	enablePositionCorrelation bool

	// confidenceThreshold is the minimum confidence required for position-based redaction
	confidenceThreshold float64

	// fallbackToSimple controls whether to fall back to simple text replacement on correlation failure
	fallbackToSimple bool
}

// NewPlainTextRedactor creates a new PlainTextRedactor
func NewPlainTextRedactor(outputManager *redactors.OutputStructureManager, observer *observability.StandardObserver) *PlainTextRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	return &PlainTextRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        position.NewDefaultPositionCorrelator(),
		enablePositionCorrelation: true,
		confidenceThreshold:       0.8,
		fallbackToSimple:          true,
	}
}

// NewPlainTextRedactorWithPositionCorrelation creates a new PlainTextRedactor with custom position correlation settings
func NewPlainTextRedactorWithPositionCorrelation(outputManager *redactors.OutputStructureManager, observer *observability.StandardObserver, correlator position.PositionCorrelator, confidenceThreshold float64) *PlainTextRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	if correlator == nil {
		correlator = position.NewDefaultPositionCorrelator()
	}

	return &PlainTextRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        correlator,
		enablePositionCorrelation: true,
		confidenceThreshold:       confidenceThreshold,
		fallbackToSimple:          true,
	}
}

// SetPositionCorrelationEnabled enables or disables position correlation
func (ptr *PlainTextRedactor) SetPositionCorrelationEnabled(enabled bool) {
	ptr.enablePositionCorrelation = enabled
}

// SetConfidenceThreshold sets the minimum confidence threshold for position-based redaction
func (ptr *PlainTextRedactor) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		ptr.confidenceThreshold = threshold
	}
}

// SetFallbackToSimple controls whether to fall back to simple text replacement on correlation failure
func (ptr *PlainTextRedactor) SetFallbackToSimple(fallback bool) {
	ptr.fallbackToSimple = fallback
}

// GetName returns the name of the redactor
func (ptr *PlainTextRedactor) GetName() string {
	return "plaintext_redactor"
}

// GetSupportedTypes returns the file types this redactor can handle
func (ptr *PlainTextRedactor) GetSupportedTypes() []string {
	return []string{"text", ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".md", ".conf", ".ini"}
}

// GetSupportedStrategies returns the redaction strategies this redactor supports
func (ptr *PlainTextRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument creates a redacted copy of the document at outputPath
func (ptr *PlainTextRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if ptr.observer != nil {
		finishTiming = ptr.observer.StartTiming("plaintext_redactor", "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Read the original file
	content, err := os.ReadFile(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read original file: %w", err)
	}

	// Convert to string for processing
	originalText := string(content)

	// Perform redaction
	redactedText, redactionMap, err := ptr.redactText(originalText, matches, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to redact text: %w", err)
	}

	// Ensure output directory exists
	if ptr.outputManager != nil {
		err = ptr.outputManager.EnsureDirectoryExists(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	// Write redacted content to output file with secure permissions
	err = os.WriteFile(outputPath, []byte(redactedText), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write redacted file: %w", err)
	}

	// Preserve file attributes (but not content) if output manager is available
	if ptr.outputManager != nil {
		// Get original file info for attribute preservation
		originalInfo, err := os.Stat(originalPath)
		if err == nil {
			// Preserve permissions
			os.Chmod(outputPath, originalInfo.Mode())
			// Preserve timestamps
			os.Chtimes(outputPath, originalInfo.ModTime(), originalInfo.ModTime())
		}
	}

	processingTime := time.Since(startTime)
	confidence := ptr.calculateOverallConfidence(redactionMap)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// redactText performs the actual text redaction based on matches and strategy
func (ptr *PlainTextRedactor) redactText(originalText string, matches []detector.Match, strategy redactors.RedactionStrategy) (string, []redactors.RedactionMapping, error) {
	if len(matches) == 0 {
		return originalText, []redactors.RedactionMapping{}, nil
	}

	// Sort matches by position (descending) to avoid position shifts during replacement
	sortedMatches := ptr.sortMatchesByPosition(matches)

	redactedText := originalText
	var redactionMap []redactors.RedactionMapping

	// Process matches in reverse order to maintain position accuracy
	for _, match := range sortedMatches {
		replacement, err := ptr.generateReplacement(match.Text, match.Type, strategy)
		if err != nil {
			return "", nil, fmt.Errorf("failed to generate replacement for %s: %w", match.Type, err)
		}

		var startPos, endPos int
		var confidence float64
		var correlationUsed bool

		// Try position correlation if enabled
		if ptr.enablePositionCorrelation && ptr.positionCorrelator != nil {
			correlatedPos, correlationErr := ptr.correlateMatchPosition(match, originalText)
			if correlationErr == nil && correlatedPos.ConfidenceScore >= ptr.confidenceThreshold {
				// Use position correlation result
				startPos = correlatedPos.OriginalPosition.CharOffset
				endPos = startPos + len(match.Text)
				confidence = correlatedPos.ConfidenceScore
				correlationUsed = true

				ptr.logEvent("position_correlation_success", true, map[string]interface{}{
					"match_text":         match.Text,
					"match_type":         match.Type,
					"confidence":         confidence,
					"correlation_method": correlatedPos.Method.String(),
					"start_pos":          startPos,
					"end_pos":            endPos,
				})
			} else {
				// Log correlation failure
				logData := map[string]interface{}{
					"match_text":       match.Text,
					"match_type":       match.Type,
					"error":            correlationErr,
					"threshold":        ptr.confidenceThreshold,
					"fallback_enabled": ptr.fallbackToSimple,
				}

				// Only add confidence if correlatedPos is not nil
				if correlatedPos != nil {
					logData["confidence"] = correlatedPos.ConfidenceScore
				}

				ptr.logEvent("position_correlation_failed", false, logData)

				// Fall back to simple text search if enabled
				if ptr.fallbackToSimple {
					simpleStartPos, simpleEndPos, simpleErr := ptr.findMatchPosition(redactedText, match)
					if simpleErr == nil {
						startPos = simpleStartPos
						endPos = simpleEndPos
						confidence = (match.Confidence / 100.0) * 0.5 // Normalize to 0-1 and reduce for fallback
						correlationUsed = false
					} else {
						// Skip this match if both correlation and fallback fail
						ptr.logEvent("match_skip", false, map[string]interface{}{
							"match_type":        match.Type,
							"match_line":        match.LineNumber,
							"correlation_error": correlationErr,
							"fallback_error":    simpleErr,
						})
						continue
					}
				} else {
					// Skip this match if correlation fails and fallback is disabled
					continue
				}
			}
		} else {
			// Use simple text search when position correlation is disabled
			simpleStartPos, simpleEndPos, err := ptr.findMatchPosition(redactedText, match)
			if err != nil {
				// Log warning but continue with other matches
				ptr.logEvent("position_warning", false, map[string]interface{}{
					"warning":    err.Error(),
					"match_text": match.Text,
					"match_type": match.Type,
				})
				continue
			}
			startPos = simpleStartPos
			endPos = simpleEndPos
			confidence = match.Confidence
			correlationUsed = false
		}

		// Validate positions
		if startPos < 0 || endPos > len(redactedText) || startPos >= endPos {
			ptr.logEvent("invalid_position_warning", false, map[string]interface{}{
				"warning":          "invalid position calculated",
				"start_pos":        startPos,
				"end_pos":          endPos,
				"text_length":      len(redactedText),
				"correlation_used": correlationUsed,
			})
			continue
		}

		// Verify the text at the calculated position matches what we expect
		actualText := redactedText[startPos:endPos]
		if actualText != match.Text {
			ptr.logEvent("text_mismatch_warning", false, map[string]interface{}{
				"match_type":       match.Type,
				"match_line":       match.LineNumber,
				"start_pos":        startPos,
				"end_pos":          endPos,
				"correlation_used": correlationUsed,
			})

			// Try to find the correct position if there's a mismatch
			if correctedStart, correctedEnd, correctionErr := ptr.findMatchPosition(redactedText, match); correctionErr == nil {
				startPos = correctedStart
				endPos = correctedEnd
				confidence *= 0.7 // Reduce confidence for corrected positions

				ptr.logEvent("position_corrected", true, map[string]interface{}{
					"original_start":        startPos,
					"corrected_start":       correctedStart,
					"confidence_adjustment": 0.7,
				})
			} else {
				// Skip this match if we can't find the correct position
				continue
			}
		}

		// Replace the text
		redactedText = redactedText[:startPos] + replacement + redactedText[endPos:]

		// Create redaction mapping with enhanced metadata
		mapping := redactors.RedactionMapping{
			RedactedText: replacement,
			Position: redactors.TextPosition{
				Line:      match.LineNumber,
				StartChar: startPos,
				EndChar:   endPos,
			},
			DataType:   match.Type,
			Strategy:   strategy,
			Confidence: confidence,

			Metadata: map[string]interface{}{
				"correlation_used":    correlationUsed,
				"original_confidence": match.Confidence,
				"position_method":     ptr.getPositionMethodString(correlationUsed),
			},
		}

		redactionMap = append(redactionMap, mapping)

		// Log successful redaction
		ptr.logEvent("redaction_applied", true, map[string]interface{}{
			"match_type":         match.Type,
			"replacement_length": len(replacement),
			"confidence":         confidence,
			"correlation_used":   correlationUsed,
		})
	}

	return redactedText, redactionMap, nil
}

// generateReplacement generates a replacement string based on the redaction strategy
func (ptr *PlainTextRedactor) generateReplacement(originalText, dataType string, strategy redactors.RedactionStrategy) (string, error) {
	switch strategy {
	case redactors.RedactionSimple:
		return ptr.generateSimpleReplacement(dataType), nil

	case redactors.RedactionFormatPreserving:
		return ptr.generateFormatPreservingReplacement(originalText, dataType), nil

	case redactors.RedactionSynthetic:
		return ptr.generateSyntheticReplacement(originalText, dataType)

	default:
		return ptr.generateSimpleReplacement(dataType), nil
	}
}

// generateSimpleReplacement creates a simple placeholder replacement
func (ptr *PlainTextRedactor) generateSimpleReplacement(dataType string) string {
	switch dataType {
	case "CREDIT_CARD":
		return "[CREDIT-CARD-REDACTED]"
	case "SSN":
		return "[SSN-REDACTED]"
	case "EMAIL":
		return "[EMAIL-REDACTED]"
	case "PHONE":
		return "[PHONE-REDACTED]"
	case "SECRETS":
		return "[SECRET-REDACTED]"
	case "IP_ADDRESS":
		return "[IP-ADDRESS-REDACTED]"
	case "PASSPORT":
		return "[PASSPORT-REDACTED]"
	default:
		return "[" + dataType + "-REDACTED]"
	}
}

// generateFormatPreservingReplacement creates a replacement that preserves the original format
func (ptr *PlainTextRedactor) generateFormatPreservingReplacement(originalText, dataType string) string {
	switch dataType {
	case "CREDIT_CARD":
		return ptr.preserveCreditCardFormat(originalText)
	case "SSN":
		return ptr.preserveSSNFormat(originalText)
	case "EMAIL":
		return ptr.preserveEmailFormat(originalText)
	case "PHONE":
		return ptr.preservePhoneFormat(originalText)
	case "IP_ADDRESS":
		return ptr.preserveIPFormat(originalText)
	default:
		// For unknown types, replace with asterisks of same length
		return strings.Repeat("*", len(originalText))
	}
}

// generateSyntheticReplacement creates realistic but fake data
func (ptr *PlainTextRedactor) generateSyntheticReplacement(originalText, dataType string) (string, error) {
	switch dataType {
	case "CREDIT_CARD":
		return ptr.generateSyntheticCreditCard(originalText)
	case "SSN":
		return ptr.generateSyntheticSSN(originalText)
	case "EMAIL":
		return ptr.generateSyntheticEmail(originalText)
	case "PHONE":
		return ptr.generateSyntheticPhone(originalText)
	case "IP_ADDRESS":
		return ptr.generateSyntheticIP(originalText)
	default:
		// For unknown types, generate random alphanumeric string of same length
		return ptr.generateRandomString(len(originalText))
	}
}

// Credit card format preservation
func (ptr *PlainTextRedactor) preserveCreditCardFormat(original string) string {
	// Preserve first 4 and last 4 digits, mask the middle
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")
	if len(cleaned) < 8 {
		return strings.Repeat("*", len(original))
	}

	first4 := cleaned[:4]
	last4 := cleaned[len(cleaned)-4:]
	middle := strings.Repeat("*", len(cleaned)-8)

	// Preserve original formatting
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digits := first4 + middle + last4
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(digits) {
			replacement := string(digits[digitIndex])
			digitIndex++
			return replacement
		}
		return "*"
	})

	return result
}

// SSN format preservation
func (ptr *PlainTextRedactor) preserveSSNFormat(original string) string {
	// Pattern: ***-**-1234 (preserve last 4 digits)
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")
	if len(cleaned) < 4 {
		return strings.Repeat("*", len(original))
	}

	last4 := cleaned[len(cleaned)-4:]

	// Replace digits with pattern, preserving last 4
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(cleaned)-4 {
			digitIndex++
			return "*"
		}
		if digitIndex < len(cleaned) {
			replacement := string(last4[digitIndex-(len(cleaned)-4)])
			digitIndex++
			return replacement
		}
		return "*"
	})

	return result
}

// Email format preservation
func (ptr *PlainTextRedactor) preserveEmailFormat(original string) string {
	// Pattern: u***@example.com (preserve first char and domain)
	parts := strings.Split(original, "@")
	if len(parts) != 2 {
		return strings.Repeat("*", len(original))
	}

	username := parts[0]
	domain := parts[1]

	if len(username) == 0 {
		return "*@" + domain
	}

	if len(username) == 1 {
		return username + "@" + domain
	}

	maskedUsername := string(username[0]) + strings.Repeat("*", len(username)-1)
	return maskedUsername + "@" + domain
}

// Phone format preservation
func (ptr *PlainTextRedactor) preservePhoneFormat(original string) string {
	// Preserve format but mask middle digits
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")
	if len(cleaned) < 6 {
		return strings.Repeat("*", len(original))
	}

	// Keep first 3 and last 4, mask middle
	first3 := cleaned[:3]
	last4 := cleaned[len(cleaned)-4:]
	middle := strings.Repeat("*", len(cleaned)-7)

	maskedDigits := first3 + middle + last4

	// Apply to original format
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(maskedDigits) {
			replacement := string(maskedDigits[digitIndex])
			digitIndex++
			return replacement
		}
		return "*"
	})

	return result
}

// IP format preservation
func (ptr *PlainTextRedactor) preserveIPFormat(original string) string {
	// Pattern: 192.168.*.*
	parts := strings.Split(original, ".")
	if len(parts) != 4 {
		return strings.Repeat("*", len(original))
	}

	// Keep first two octets, mask last two
	return parts[0] + "." + parts[1] + ".*.*"
}

// Synthetic data generation methods
func (ptr *PlainTextRedactor) generateSyntheticCreditCard(original string) (string, error) {
	// Generate a valid Luhn number that looks real but isn't
	// Use test card prefixes that are known to be invalid
	testPrefixes := []string{"4000", "4111", "5555", "3782"}

	prefix := testPrefixes[ptr.secureRandom(len(testPrefixes))]

	// Generate remaining digits
	var digits []int
	for _, char := range prefix {
		if char >= '0' && char <= '9' {
			digits = append(digits, int(char-'0'))
		}
	}

	// Add random digits to make 15 digits total (16th will be check digit)
	for len(digits) < 15 {
		digits = append(digits, ptr.secureRandom(10))
	}

	// Calculate Luhn check digit
	checkDigit := ptr.calculateLuhnCheckDigit(digits)
	digits = append(digits, checkDigit)

	// Convert to string with original formatting
	result := ""
	digitIndex := 0
	for _, char := range original {
		if char >= '0' && char <= '9' {
			if digitIndex < len(digits) {
				result += fmt.Sprintf("%d", digits[digitIndex])
				digitIndex++
			} else {
				result += "0"
			}
		} else {
			result += string(char)
		}
	}

	return result, nil
}

func (ptr *PlainTextRedactor) generateSyntheticSSN(original string) (string, error) {
	// Generate a synthetic SSN that follows format but is invalid
	// Use area numbers that are known to be invalid (000, 666, 900-999)
	invalidAreas := []string{"000", "666", "900", "999"}
	area := invalidAreas[ptr.secureRandom(len(invalidAreas))]

	group := fmt.Sprintf("%02d", ptr.secureRandom(100))
	serial := fmt.Sprintf("%04d", ptr.secureRandom(10000))

	syntheticSSN := area + group + serial

	// Apply original formatting
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(syntheticSSN) {
			replacement := string(syntheticSSN[digitIndex])
			digitIndex++
			return replacement
		}
		return "0"
	})

	return result, nil
}

func (ptr *PlainTextRedactor) generateSyntheticEmail(original string) (string, error) {
	// Generate a synthetic email with example.com domain
	parts := strings.Split(original, "@")
	if len(parts) != 2 {
		return "user@example.com", nil
	}

	// Generate random username
	username, err := ptr.generateRandomString(len(parts[0]))
	if err != nil {
		return "", err
	}

	return strings.ToLower(username) + "@example.com", nil
}

func (ptr *PlainTextRedactor) generateSyntheticPhone(original string) (string, error) {
	// Generate synthetic phone with 555 area code (reserved for fiction)
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")

	syntheticDigits := "555"
	for len(syntheticDigits) < len(cleaned) {
		syntheticDigits += fmt.Sprintf("%d", ptr.secureRandom(10))
	}

	// Apply to original format
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(syntheticDigits) {
			replacement := string(syntheticDigits[digitIndex])
			digitIndex++
			return replacement
		}
		return "0"
	})

	return result, nil
}

func (ptr *PlainTextRedactor) generateSyntheticIP(original string) (string, error) {
	// Generate IP in private range (192.168.x.x)
	return fmt.Sprintf("192.168.%d.%d",
		ptr.secureRandom(256),
		ptr.secureRandom(256)), nil
}

// Helper methods

// sortMatchesByPosition sorts matches by their position in descending order
func (ptr *PlainTextRedactor) sortMatchesByPosition(matches []detector.Match) []detector.Match {
	// Create a copy to avoid modifying the original slice
	sorted := make([]detector.Match, len(matches))
	copy(sorted, matches)

	// Simple bubble sort by line number and position (descending)
	for i := 0; i < len(sorted)-1; i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			if sorted[j].LineNumber < sorted[j+1].LineNumber {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	return sorted
}

// findMatchPosition finds the start and end position of a match in the text
func (ptr *PlainTextRedactor) findMatchPosition(text string, match detector.Match) (int, int, error) {
	// Simple approach: find the first occurrence of the match text
	// In a more sophisticated implementation, we would use the line number and character position
	startPos := strings.Index(text, match.Text)
	if startPos == -1 {
		return 0, 0, fmt.Errorf("match text not found in document")
	}

	endPos := startPos + len(match.Text)
	return startPos, endPos, nil
}

// generateVerificationHash creates a hash of surrounding context for verification
func (ptr *PlainTextRedactor) generateVerificationHash(text string, startPos, endPos int) string {
	// Validate input parameters
	if startPos < 0 || endPos > len(text) || startPos >= endPos {
		return redactors.GenerateContextHash("invalid_position")
	}

	// Extract context around the match
	contextStart := startPos - 20
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := endPos + 20
	if contextEnd > len(text) {
		contextEnd = len(text)
	}

	// Additional safety check
	if contextStart > len(text) || contextEnd < 0 || contextStart >= contextEnd {
		return redactors.GenerateContextHash("invalid_context")
	}

	context := text[contextStart:startPos] + "[REDACTED]" + text[endPos:contextEnd]
	return redactors.GenerateContextHash(context)
}

// calculateOverallConfidence calculates the overall confidence for the redaction
func (ptr *PlainTextRedactor) calculateOverallConfidence(redactionMap []redactors.RedactionMapping) float64 {
	if len(redactionMap) == 0 {
		return 1.0
	}

	totalConfidence := 0.0
	for _, mapping := range redactionMap {
		totalConfidence += mapping.Confidence
	}

	return totalConfidence / float64(len(redactionMap))
}

// secureRandom generates a cryptographically secure random number
func (ptr *PlainTextRedactor) secureRandom(max int) int {
	if max <= 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Fallback to a simple approach if crypto/rand fails
		return int(time.Now().UnixNano()) % max
	}

	return int(n.Int64())
}

// generateRandomString generates a random alphanumeric string of specified length
func (ptr *PlainTextRedactor) generateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[ptr.secureRandom(len(charset))]
	}

	return string(result), nil
}

// calculateLuhnCheckDigit calculates the Luhn check digit for a credit card number
func (ptr *PlainTextRedactor) calculateLuhnCheckDigit(digits []int) int {
	sum := 0
	alternate := true

	// Process digits from right to left
	for i := len(digits) - 1; i >= 0; i-- {
		digit := digits[i]

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}

		sum += digit
		alternate = !alternate
	}

	return (10 - (sum % 10)) % 10
}

// GetComponentName returns the component name for observability
func (ptr *PlainTextRedactor) GetComponentName() string {
	return "plaintext_redactor"
}

// RedactContent implements ContentRedactor interface for efficient content-based redaction
func (ptr *PlainTextRedactor) RedactContent(content *preprocessors.ProcessedContent, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if ptr.observer != nil {
		finishTiming = ptr.observer.StartTiming("plaintext_redactor", "redact_content", content.OriginalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Use the already-extracted text instead of re-reading the file
	originalText := content.Text

	// Perform redaction using the same logic as RedactDocument
	redactedText, redactionMap, err := ptr.redactText(originalText, matches, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to redact text: %w", err)
	}

	// Ensure output directory exists
	if ptr.outputManager != nil {
		err = ptr.outputManager.EnsureDirectoryExists(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	// Write redacted content to output file with secure permissions
	err = os.WriteFile(outputPath, []byte(redactedText), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write redacted file: %w", err)
	}

	// Preserve file attributes if output manager is available
	if ptr.outputManager != nil {
		// Get original file info for attribute preservation
		originalInfo, err := os.Stat(content.OriginalPath)
		if err == nil {
			// Preserve permissions
			os.Chmod(outputPath, originalInfo.Mode())
			// Preserve timestamps
			os.Chtimes(outputPath, originalInfo.ModTime(), originalInfo.ModTime())
		}
	}

	processingTime := time.Since(startTime)
	confidence := ptr.calculateOverallConfidence(redactionMap)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// logEvent logs an event if observer is available
func (ptr *PlainTextRedactor) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if ptr.observer != nil {
		ptr.observer.StartTiming("plaintext_redactor", operation, "")(success, metadata)
	}
}

// correlateMatchPosition correlates a detector match position with the original document
func (ptr *PlainTextRedactor) correlateMatchPosition(match detector.Match, originalText string) (*position.PositionCorrelation, error) {
	// Calculate character positions from line number and text
	startChar, endChar, err := ptr.calculateCharacterPositions(match, originalText)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate character positions: %w", err)
	}

	// Convert detector match to text position
	textPos := redactors.TextPosition{
		Line:      match.LineNumber,
		StartChar: startChar,
		EndChar:   endChar,
	}

	// Use the original text as both extracted and original content for plain text
	// In more complex scenarios, these would be different (e.g., extracted from PDF)
	correlation, err := ptr.positionCorrelator.CorrelatePosition(
		textPos,
		originalText,         // extracted text (same as original for plain text)
		[]byte(originalText), // original content
		"text",               // document type
	)

	if err != nil {
		return nil, fmt.Errorf("position correlation failed: %w", err)
	}

	// Validate the correlation result
	if err := ptr.positionCorrelator.ValidateCorrelation(correlation); err != nil {
		return nil, fmt.Errorf("correlation validation failed: %w", err)
	}

	return correlation, nil
}

// calculateCharacterPositions calculates start and end character positions from a match
func (ptr *PlainTextRedactor) calculateCharacterPositions(match detector.Match, text string) (int, int, error) {
	lines := strings.Split(text, "\n")

	if match.LineNumber < 1 || match.LineNumber > len(lines) {
		return 0, 0, fmt.Errorf("line number %d is out of range (1-%d)", match.LineNumber, len(lines))
	}

	line := lines[match.LineNumber-1] // Convert to 0-based indexing

	// Find the match text in the line
	startChar := strings.Index(line, match.Text)
	if startChar == -1 {
		return 0, 0, fmt.Errorf("match text %q not found in line %d", match.Text, match.LineNumber)
	}

	endChar := startChar + len(match.Text)

	return startChar, endChar, nil
}

// getPositionMethodString returns a string representation of the position method used
func (ptr *PlainTextRedactor) getPositionMethodString(correlationUsed bool) string {
	if correlationUsed {
		return "position_correlation"
	}
	return "simple_text_search"
}

// validatePositionCorrelationResult validates the result of position correlation
func (ptr *PlainTextRedactor) validatePositionCorrelationResult(correlation *position.PositionCorrelation, match detector.Match, originalText string) error {
	if correlation == nil {
		return fmt.Errorf("correlation result is nil")
	}

	if correlation.OriginalPosition == nil {
		return fmt.Errorf("original position is nil")
	}

	// Check if the position is within bounds
	if correlation.OriginalPosition.CharOffset < 0 || correlation.OriginalPosition.CharOffset >= len(originalText) {
		return fmt.Errorf("character offset %d is out of bounds (0-%d)",
			correlation.OriginalPosition.CharOffset, len(originalText)-1)
	}

	// Check if we can extract the expected text at the correlated position
	startPos := correlation.OriginalPosition.CharOffset
	endPos := startPos + len(match.Text)

	if endPos > len(originalText) {
		return fmt.Errorf("end position %d exceeds text length %d", endPos, len(originalText))
	}

	actualText := originalText[startPos:endPos]
	if actualText != match.Text {
		// Allow some flexibility for fuzzy matches
		if correlation.Method == position.CorrelationFuzzy {
			// Calculate similarity and allow if above threshold
			similarity := ptr.calculateTextSimilarity(actualText, match.Text)
			if similarity < 0.8 {
				return fmt.Errorf("text mismatch: expected %q, got %q (similarity: %.2f)",
					match.Text, actualText, similarity)
			}
		} else {
			return fmt.Errorf("text mismatch: expected %q, got %q", match.Text, actualText)
		}
	}

	return nil
}

// calculateTextSimilarity calculates similarity between two text strings
func (ptr *PlainTextRedactor) calculateTextSimilarity(text1, text2 string) float64 {
	if text1 == text2 {
		return 1.0
	}

	if len(text1) == 0 || len(text2) == 0 {
		return 0.0
	}

	// Simple similarity calculation based on common characters
	// This is a simplified version - in production, you might want to use
	// more sophisticated algorithms like Levenshtein distance

	shorter, longer := text1, text2
	if len(text1) > len(text2) {
		shorter, longer = text2, text1
	}

	commonChars := 0
	for i, char := range shorter {
		if i < len(longer) && longer[i] == byte(char) {
			commonChars++
		}
	}

	return float64(commonChars) / float64(len(longer))
}

// logPositionCorrelationMetrics logs detailed metrics about position correlation
func (ptr *PlainTextRedactor) logPositionCorrelationMetrics(correlations []*position.PositionCorrelation) {
	if len(correlations) == 0 {
		return
	}

	// Calculate metrics
	totalCorrelations := len(correlations)
	successfulCorrelations := 0
	averageConfidence := 0.0
	methodCounts := make(map[string]int)

	for _, correlation := range correlations {
		if correlation.ConfidenceScore >= ptr.confidenceThreshold {
			successfulCorrelations++
		}
		averageConfidence += correlation.ConfidenceScore
		methodCounts[correlation.Method.String()]++
	}

	averageConfidence /= float64(totalCorrelations)
	successRate := float64(successfulCorrelations) / float64(totalCorrelations)

	// Log comprehensive metrics
	ptr.logEvent("position_correlation_metrics", true, map[string]interface{}{
		"total_correlations":      totalCorrelations,
		"successful_correlations": successfulCorrelations,
		"success_rate":            successRate,
		"average_confidence":      averageConfidence,
		"confidence_threshold":    ptr.confidenceThreshold,
		"method_counts":           methodCounts,
		"correlation_enabled":     ptr.enablePositionCorrelation,
		"fallback_enabled":        ptr.fallbackToSimple,
	})
}

// GetPositionCorrelationStats returns statistics about position correlation performance
func (ptr *PlainTextRedactor) GetPositionCorrelationStats() map[string]interface{} {
	return map[string]interface{}{
		"correlation_enabled":  ptr.enablePositionCorrelation,
		"confidence_threshold": ptr.confidenceThreshold,
		"fallback_enabled":     ptr.fallbackToSimple,
		"correlator_type":      fmt.Sprintf("%T", ptr.positionCorrelator),
	}
}
