// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Validator implements the detector.Validator interface for detecting
// credit card numbers using optimized regex patterns, contextual analysis, and validation algorithms.
// This is the main validator with improved boundary detection, performance, and reduced false positives.
type Validator struct {
	// Improved regex pattern that handles boundaries better
	pattern string
	regex   *regexp.Regexp

	//  BIN ranges using range checks instead of massive maps
	binRanges []BINRange

	// Pre-compiled test patterns for fast rejection
	testPatterns []*regexp.Regexp

	// Keywords for context analysis
	positiveKeywords []string
	negativeKeywords []string

	// Observability
	observer *observability.StandardObserver
}

// BINRange represents a range of valid BIN numbers for efficient lookup
type BINRange struct {
	Start  int
	End    int
	Vendor string
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns, keywords, and validation rules for detecting credit card numbers.
func NewValidator() *Validator {
	v := &Validator{
		// Enhanced regex pattern with multiple format support:
		// 1. More specific boundary detection for tabular data
		// 2. Handles various separator patterns (dashes, spaces, none)
		// 3. Prevents detection within larger numbers
		// 4. Supports 15-digit (Amex) and 14-digit (Diners) cards
		// 5. Fixed boundary issue that was causing false matches across columns
		// 6. Added support for space-only separators and no separators
		// 7. Improved quoted string handling
		pattern: `(?:^|[\s\t,;|"'(){}[\]<>])(\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}|\d{4}[\s\-]\d{6}[\s\-]\d{5}|\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{3}|\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{2}|\d{4}\s\d{4}\s\d{4}\s\d{4}|\d{4}\s\d{6}\s\d{5}|\d{4}\s\d{4}\s\d{4}\s\d{3}|\d{4}\s\d{4}\s\d{4}\s\d{2}|\d{16}|\d{15}|\d{14})(?:[\s\t,;|"'(){}[\]<>]|$)`,

		binRanges: initBINRanges(),

		positiveKeywords: []string{
			"credit", "card", "visa", "mastercard", "amex", "american express",
			"discover", "jcb", "diners", "cardholder", "payment", "transaction",
			"purchase", "expiration", "expiry", "exp", "cvv", "cvc", "ccv",
			"billing", "checkout", "pay", "paid", "pci", "merchant",
		},

		negativeKeywords: []string{
			"account", "id", "identifier", "serial", "tracking", "reference",
			"order", "invoice", "timestamp", "unix", "epoch", "phone", "tel",
			"md5", "sha", "hash", "uuid", "guid", "crc", "checksum",
			"version", "build", "test", "example", "fake", "mock", "sample",
		},
	}

	// Compile regex once
	v.regex = regexp.MustCompile(v.pattern)

	// Pre-compile test patterns for fast rejection
	v.testPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^1234567890123456$`),
		regexp.MustCompile(`^0{14,16}$|^1{14,16}$|^2{14,16}$|^3{14,16}$|^4{14,16}$|^5{14,16}$|^6{14,16}$|^7{14,16}$|^8{14,16}$|^9{14,16}$`), // All same digit
		regexp.MustCompile(`^1111222233334444$`),
		regexp.MustCompile(`^1212121212121212$`), // Simple alternating pattern
		regexp.MustCompile(`^4111111111111111$`), // Common test Visa
		regexp.MustCompile(`^5555555555554444$`), // Common test MasterCard
		regexp.MustCompile(`^4444444444444448$`), // Obvious test pattern
		regexp.MustCompile(`^4000000000000002$`), // Common test Visa
		regexp.MustCompile(`^5100000000000008$`), // Common test MasterCard
		regexp.MustCompile(`^340000000000009$`),  // Common test Amex
	}

	return v
}

// initBINRanges creates BIN ranges using efficient range checks instead of massive maps
func initBINRanges() []BINRange {
	return []BINRange{
		// Visa: 4xxxxx
		{400000, 499999, "Visa"},

		// MasterCard: 51xxxx-55xxxx, 222100-272099
		{510000, 559999, "MasterCard"},
		{222100, 272099, "MasterCard"},

		// American Express: 34xxxx, 37xxxx
		{340000, 349999, "American Express"},
		{370000, 379999, "American Express"},

		// Discover: 6011xx, 644xxx-649xxx, 65xxxx
		{601100, 601199, "Discover"},
		{644000, 649999, "Discover"},
		{650000, 659999, "Discover"},

		// JCB: 35xxxx
		{350000, 359999, "JCB"},

		// Diners Club: 30xxxx, 36xxxx, 38xxxx
		{300000, 309999, "Diners Club"},
		{360000, 369999, "Diners Club"},
		{380000, 389999, "Diners Club"},

		// UnionPay: 62xxxx
		{620000, 629999, "UnionPay"},

		// Maestro: 50xxxx, 56xxxx-58xxxx
		{500000, 509999, "Maestro"},
		{560000, 589999, "Maestro"},
	}
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	// Credit card validator should not process files directly
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content with optimized performance
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("creditcard_validator_optimized", "validate_content", originalPath)
	}

	var matches []detector.Match
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Find potential matches using improved regex
		regexMatches := v.regex.FindAllStringSubmatch(line, -1)

		for _, regexMatch := range regexMatches {
			if len(regexMatch) < 2 {
				continue
			}

			match := regexMatch[1] // Extract the captured group (the actual number)
			cleanMatch := v.cleanCreditCardNumber(match)

			// OPTIMIZATION 1: Early rejection for obvious non-credit cards
			if !v.isValidLength(cleanMatch) {
				continue
			}

			// OPTIMIZATION 2: Note test patterns but don't reject them
			// They should be detected with very low confidence
			isTestPattern := v.isKnownTestPattern(cleanMatch)

			// OPTIMIZATION 3: Luhn check early (before expensive operations)
			if !v.luhnCheck(cleanMatch) {
				v.logLuhnFailure(match, cleanMatch, lineNum+1, originalPath)
				continue
			}

			// OPTIMIZATION 4: BIN validation using efficient range lookup
			vendor := v.detectCardVendor(cleanMatch)
			// Note: Don't skip unknown vendors for CalculateConfidence compatibility

			// Now do more expensive operations only for valid candidates
			confidence, checks := v.calculateConfidence(match, cleanMatch)

			// Override test pattern detection from calculateConfidence
			if isTestPattern {
				checks["not_test"] = false
			}

			// Context analysis (expensive, so do it last)
			contextInfo := v.buildContextInfo(line, match)
			contextImpact := v.analyzeContext(match, contextInfo)
			confidence += contextImpact

			// Check for tabular data and boost confidence
			if v.isTabularData(contextInfo.FullLine, match) {
				confidence += 10 // Boost for tabular data
			}

			// Apply bounds
			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			// CRITICAL: Ensure test patterns and suspicious numbers maintain minimum confidence
			// This must happen AFTER context analysis to prevent filtering
			if !checks["not_test"] || !checks["not_repeating"] {
				if confidence > 15.0 {
					confidence = 15.0 // Hard cap for test patterns
				}
				if confidence < 1.0 {
					confidence = 1.0 // Minimum confidence to ensure detection
				}
			}

			// Skip only matches with 0 confidence
			if confidence <= 0 {
				continue
			}

			cardType := v.getCreditCardType(cleanMatch)
			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1,
				Type:       cardType,
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "creditcard",
				Context:    contextInfo,
				Metadata: map[string]any{
					"card_type":         cardType,
					"vendor":            vendor,
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(lines),
			"content_length":  len(content),
		})
	}

	return matches, nil
}

// isValidLength checks if the number has a valid credit card length
func (v *Validator) isValidLength(number string) bool {
	length := len(number)
	return length == 14 || length == 15 || length == 16 // Support Diners (14), Amex (15), and standard (16)
}

// isKnownTestPattern uses pre-compiled regexes for fast test pattern detection
func (v *Validator) isKnownTestPattern(number string) bool {
	for _, pattern := range v.testPatterns {
		if pattern.MatchString(number) {
			return true
		}
	}
	return false
}

// detectCardVendor uses efficient range lookup instead of regex
func (v *Validator) detectCardVendor(cardNumber string) string {
	if len(cardNumber) < 6 {
		return "Unknown"
	}

	// Extract first 6 digits for BIN lookup
	bin, err := strconv.Atoi(cardNumber[:6])
	if err != nil {
		return "Unknown"
	}

	// Efficient range lookup
	for _, binRange := range v.binRanges {
		if bin >= binRange.Start && bin <= binRange.End {
			return binRange.Vendor
		}
	}

	return "Unknown"
}

// calculateConfidence provides faster confidence calculation
func (v *Validator) calculateConfidence(match, cleanMatch string) (float64, map[string]bool) {
	checks := map[string]bool{
		"length":        true, // Already checked
		"digits":        true, // Regex ensures this
		"luhn":          true, // Already checked
		"vendor":        false,
		"not_test":      true, // Will be checked below
		"entropy":       false,
		"not_repeating": false,
	}

	// Start with moderate confidence - we need to prove this is a real card
	confidence := 60.0

	// Check vendor (major confidence factor)
	vendor := v.detectCardVendor(cleanMatch)
	if vendor == "Unknown" {
		confidence -= 20 // Significant penalty for unknown vendors
	} else {
		checks["vendor"] = true
		confidence += 15 // Boost for known vendor
	}

	// Check for test patterns (CRITICAL - these should have very low confidence)
	if v.isKnownTestPattern(cleanMatch) {
		confidence = 5.0 // Force very low confidence for test patterns
		checks["not_test"] = false
		// Don't return early - let other checks run, but cap the final confidence
	} else {
		checks["not_test"] = true
	}

	// Check for repeating patterns (major red flag)
	if v.hasRepeatingPatterns(cleanMatch) {
		confidence -= 35 // Heavy penalty for suspicious patterns
		checks["not_repeating"] = false
	} else {
		checks["not_repeating"] = true
		confidence += 10 // Boost for non-repeating patterns
	}

	// Entropy check (indicator of randomness)
	entropy := v.calculateEntropy(cleanMatch)
	if entropy < 2.5 {
		confidence -= 20 // Heavy penalty for very low entropy
		checks["entropy"] = false
	} else if entropy >= 3.5 {
		confidence += 10 // Boost for good entropy
		checks["entropy"] = true
	} else {
		checks["entropy"] = false
	}

	// Ensure reasonable bounds
	if confidence > 100 {
		confidence = 100
	} else if confidence < 0 {
		confidence = 0
	}

	// CRITICAL: Cap confidence for test patterns and suspicious numbers
	// No amount of context should make obvious test patterns high confidence
	if !checks["not_test"] || !checks["not_repeating"] {
		if confidence > 15.0 {
			confidence = 15.0 // Hard cap for test patterns and repeating numbers
		}
		// Ensure test patterns have at least minimal confidence for detection
		if confidence < 5.0 {
			confidence = 5.0
		}
	}

	return confidence, checks
}

// hasRepeatingPatterns provides faster repeating pattern detection
func (v *Validator) hasRepeatingPatterns(number string) bool {
	// This should catch patterns that are unlikely to be real credit cards

	// Check for excessive consecutive identical digits (8+ consecutive)
	// Real cards can have some repetition, but 8+ consecutive is suspicious
	consecutiveCount := 1
	for i := 1; i < len(number); i++ {
		if number[i] == number[i-1] {
			consecutiveCount++
			if consecutiveCount >= 8 {
				return true
			}
		} else {
			consecutiveCount = 1
		}
	}

	// Check for all same digit (like 0000000000000000)
	allSame := true
	for i := 1; i < len(number); i++ {
		if number[i] != number[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Check for simple alternating patterns (like 1212121212121212)
	if len(number) >= 8 {
		alternating := true
		for i := 2; i < len(number); i++ {
			if number[i] != number[i-2] {
				alternating = false
				break
			}
		}
		if alternating && number[0] != number[1] {
			return true
		}
	}

	// Check for sequential patterns (like 1234567890123456)
	sequential := true
	for i := 1; i < len(number); i++ {
		expected := (int(number[i-1]-'0') + 1) % 10
		actual := int(number[i] - '0')
		if actual != expected {
			sequential = false
			break
		}
	}
	if sequential {
		return true
	}

	return false
}

// calculateEntropy provides faster entropy calculation
func (v *Validator) calculateEntropy(number string) float64 {
	// Quick entropy approximation using digit distribution
	digitCount := make([]int, 10)
	for _, digit := range number {
		if digit >= '0' && digit <= '9' {
			digitCount[digit-'0']++
		}
	}

	// Count unique digits (simpler than full entropy calculation)
	uniqueDigits := 0
	for _, count := range digitCount {
		if count > 0 {
			uniqueDigits++
		}
	}

	// Approximate entropy based on unique digits
	return float64(uniqueDigits) * 0.5 // Rough approximation
}

// analyzeContext provides faster context analysis with better false positive detection
func (v *Validator) analyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := strings.ToLower(context.FullLine)

	// Quick negative keyword check (more important for false positive reduction)
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, keyword) {
			return -100 // Very strong negative impact to ensure rejection
		}
	}

	// Quick positive keyword check
	confidenceImpact := 0.0
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, keyword) {
			confidenceImpact += 15 // Increased boost for positive context
			break                  // Only count one positive keyword to avoid over-boosting
		}
	}

	return confidenceImpact
}

// buildContextInfo efficiently builds context information
func (v *Validator) buildContextInfo(line, match string) detector.ContextInfo {
	matchIndex := strings.Index(line, match)
	contextInfo := detector.ContextInfo{
		FullLine: line,
	}

	if matchIndex >= 0 {
		start := matchIndex - 30 // Smaller context window for performance
		if start < 0 {
			start = 0
		}
		end := matchIndex + len(match) + 30
		if end > len(line) {
			end = len(line)
		}

		contextInfo.BeforeText = line[start:matchIndex]
		contextInfo.AfterText = line[matchIndex+len(match) : end]
	}

	return contextInfo
}

// getCreditCardType provides faster card type detection
func (v *Validator) getCreditCardType(cardNumber string) string {
	if len(cardNumber) < 1 {
		return "CREDIT_CARD"
	}

	// Fast first-digit check
	switch cardNumber[0] {
	case '4':
		return "VISA"
	case '5':
		if len(cardNumber) >= 2 && cardNumber[1] >= '1' && cardNumber[1] <= '5' {
			return "MASTERCARD"
		}
		return "MAESTRO"
	case '3':
		if len(cardNumber) >= 2 {
			second := cardNumber[1]
			if second == '4' || second == '7' {
				return "AMERICAN_EXPRESS"
			}
			if second == '5' {
				return "JCB"
			}
			if second == '0' || second == '6' || second == '8' {
				return "DINERS_CLUB"
			}
		}
		return "CREDIT_CARD"
	case '6':
		if len(cardNumber) >= 2 && cardNumber[1] == '2' {
			return "UNIONPAY"
		}
		return "DISCOVER"
	case '2':
		if len(cardNumber) >= 6 && cardNumber[:6] >= "222100" && cardNumber[:6] <= "272099" {
			return "MASTERCARD"
		}
		return "CREDIT_CARD"
	default:
		return "CREDIT_CARD"
	}
}

// Helper methods (optimized versions of existing methods)
func (v *Validator) cleanCreditCardNumber(number string) string {
	return strings.ReplaceAll(strings.ReplaceAll(number, " ", ""), "-", "")
}

func (v *Validator) luhnCheck(number string) bool {
	sum := 0
	isDouble := false

	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')

		if isDouble {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		isDouble = !isDouble
	}

	return sum%10 == 0
}

func (v *Validator) logLuhnFailure(originalMatch, cleanMatch string, lineNum int, filePath string) {
	if !v.isDebugEnabled() {
		return
	}

	fmt.Fprintf(os.Stderr, "[DEBUG]  Credit Card Validator: Luhn test failed\n")
	fmt.Fprintf(os.Stderr, "[DEBUG]   - File: %s, Line: %d\n", filePath, lineNum)
	fmt.Fprintf(os.Stderr, "[DEBUG]   - Match: %s -> %s\n", originalMatch, cleanMatch)
}

func (v *Validator) isDebugEnabled() bool {
	return os.Getenv("FERRET_DEBUG") != ""
}

// isTabularData checks if the credit card appears to be in a tabular format
func (v *Validator) isTabularData(line, match string) bool {
	// Check for common tabular delimiters
	tabCount := strings.Count(line, "\t")
	commaCount := strings.Count(line, ",")
	semicolonCount := strings.Count(line, ";")
	pipeCount := strings.Count(line, "|")

	// If line has common delimiters, likely tabular
	if tabCount > 0 || commaCount >= 2 || semicolonCount >= 2 || pipeCount >= 2 {
		return true
	}

	// Check for multiple consecutive spaces (common in fixed-width tabular data)
	multiSpacePattern := regexp.MustCompile(`\s{2,}`)
	if len(multiSpacePattern.FindAllString(line, -1)) >= 2 {
		return true
	}

	// Check for common financial data patterns (names/accounts followed by credit cards)
	financialPattern := regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+\d{4}[\s-]?\d{4}`)
	if financialPattern.MatchString(line) {
		return true
	}

	return false
}

// CalculateConfidence implements the detector.Validator interface
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	cleanMatch := v.cleanCreditCardNumber(match)
	return v.calculateConfidence(match, cleanMatch)
}

// DetectCardVendor implements the existing interface for compatibility
func (v *Validator) DetectCardVendor(cardNumber string) string {
	return v.detectCardVendor(cardNumber)
}

// Additional helper methods for compatibility with original validator

// AnalyzeContext analyzes the context around a match (compatibility method)
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	return v.analyzeContext(match, context)
}
