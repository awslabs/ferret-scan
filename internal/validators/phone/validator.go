// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Validator implements the detector.Validator interface for detecting
// phone numbers using regex patterns and contextual analysis.
type Validator struct {
	patterns []phonePattern

	// Keywords that suggest a phone context
	positiveKeywords []string

	// Keywords that suggest this is not a real phone
	negativeKeywords []string

	// Known test patterns that indicate test data
	knownTestPatterns []string

	// Common test phone numbers
	testPhoneNumbers []string

	// Country calling codes for validation
	countryCodeMap map[string]string

	// Optimized country code lookup (sorted by length, longest first)
	sortedCountryCodes []string

	// Observability
	observer *observability.StandardObserver
}

// phonePattern represents a phone number pattern with its format info
type phonePattern struct {
	name    string
	regex   *regexp.Regexp
	country string
	format  string
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns, keywords, and validation rules for detecting phone numbers.
func NewValidator() *Validator {
	v := &Validator{
		positiveKeywords: []string{
			"phone", "telephone", "tel", "call", "mobile", "cell", "cellular",
			"contact", "number", "fax", "voicemail", "extension", "ext",
			"dial", "ring", "caller", "emergency", "hotline", "helpline",
			"support", "service", "customer", "sales", "office", "home",
			"work", "business", "personal", "primary", "secondary",
			"toll-free", "tollfree", "free", "800", "888", "877", "866",
			"855", "844", "833", "directory", "assistance", "operator",
		},
		negativeKeywords: []string{
			"test", "example", "fake", "mock", "sample", "dummy", "placeholder",
			"demo", "template", "tutorial", "documentation", "readme",
			"lorem", "ipsum", "foo", "bar", "baz", "temp", "temporary",
			"invalid", "nonexistent", "blackhole", "devnull", "null",
			// SSN-specific keywords to avoid false positives
			"ssn", "social", "security", "social security", "tax", "identification",
			"taxpayer", "employee", "id", "number", "federal", "ein", "itin",
			// Credit card and financial data keywords
			"credit", "card", "visa", "mastercard", "amex", "american express",
			"discover", "account", "balance", "payment", "transaction", "amount",
			"first and last name", "last name", "first name", "name",
			// Timestamp and technical keywords
			"timestamp", "unix", "epoch", "milliseconds", "seconds", "time",
			"created", "modified", "updated", "generated", "build", "version",
			"revision", "commit", "hash", "checksum", "uuid", "guid",
		},
		knownTestPatterns: []string{
			"555-0", "555-1", "000-000", "111-111", "222-222", "333-333",
			"444-444", "555-555", "666-666", "777-777", "888-888", "999-999",
			"123-456", "987-654", "000-0000", "111-1111", "test", "example",
		},
		testPhoneNumbers: []string{
			"555-0100", "555-0199", "555-1212", "867-5309", "123-456-7890",
			"000-000-0000", "111-111-1111", "222-222-2222", "333-333-3333",
			"444-444-4444", "555-555-5555", "666-666-6666", "777-777-7777",
			"888-888-8888", "999-999-9999", "987-654-3210", "012-345-6789",
		},
		countryCodeMap: initCountryCodeMap(),
	}

	// Initialize sorted country codes for optimized lookup
	v.sortedCountryCodes = initSortedCountryCodes(v.countryCodeMap)

	// Initialize phone patterns
	v.patterns = []phonePattern{
		// US/Canada formats
		{
			name:    "US_Standard",
			regex:   regexp.MustCompile(`\b\(\d{3}\)\s?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "(XXX) XXX-XXXX",
		},
		{
			name:    "US_Dashed",
			regex:   regexp.MustCompile(`\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b`),
			country: "US/CA",
			format:  "XXX-XXX-XXXX",
		},
		{
			name:    "US_Plain",
			regex:   regexp.MustCompile(`\b\d{10}\b`),
			country: "US/CA",
			format:  "XXXXXXXXXX",
		},
		{
			name:    "US_International",
			regex:   regexp.MustCompile(`\b\+1[-.\s]?\(?(\d{3})\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "+1 (XXX) XXX-XXXX",
		},
		// International formats
		{
			name:    "International_Plus",
			regex:   regexp.MustCompile(`\b\+\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b`),
			country: "International",
			format:  "+XX XXXX XXXX XXXX",
		},
		{
			name:    "International_00",
			regex:   regexp.MustCompile(`\b00\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b`),
			country: "International",
			format:  "00XX XXXX XXXX XXXX",
		},
		// UK formats
		{
			name:    "UK_Standard",
			regex:   regexp.MustCompile(`\b0\d{2,4}[-.\s]?\d{3,8}\b`),
			country: "UK",
			format:  "0XXX XXXXXXXX",
		},
		{
			name:    "UK_International",
			regex:   regexp.MustCompile(`\b\+44[-.\s]?\d{1,4}[-.\s]?\d{3,8}\b`),
			country: "UK",
			format:  "+44 XXXX XXXXXXXX",
		},
		// European formats
		{
			name:    "European",
			regex:   regexp.MustCompile(`\b\+\d{2}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}\b`),
			country: "Europe",
			format:  "+XX XXXX XXXX XXXX",
		},
		// Mobile-specific patterns
		{
			name:    "Mobile_International",
			regex:   regexp.MustCompile(`\b\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b`),
			country: "Mobile",
			format:  "+XXX XXXX XXXX XXXX",
		},
		// Extension patterns
		{
			name:    "US_With_Extension",
			regex:   regexp.MustCompile(`\b\(?(\d{3})\)?[-.\s]?\d{3}[-.\s]?\d{4}[-.\s]?(?:ext\.?|extension|x)[-.\s]?\d{1,6}\b`),
			country: "US/CA",
			format:  "(XXX) XXX-XXXX ext XXXX",
		},
		{
			name:    "International_With_Extension",
			regex:   regexp.MustCompile(`\b\+\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}[-.\s]?(?:ext\.?|extension|x)[-.\s]?\d{1,6}\b`),
			country: "International",
			format:  "+XX XXXX XXXX ext XXXX",
		},
		// Toll-free patterns
		{
			name:    "US_TollFree",
			regex:   regexp.MustCompile(`\b(?:1[-.\s]?)?(?:800|833|844|855|866|877|888)[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "1-800-XXX-XXXX",
		},
		{
			name:    "US_TollFree_Parentheses",
			regex:   regexp.MustCompile(`\b(?:1[-.\s]?)?\((?:800|833|844|855|866|877|888)\)[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "1-(800) XXX-XXXX",
		},
		{
			name:    "US_TollFree_International",
			regex:   regexp.MustCompile(`\b\+1[-.\s]?(?:800|833|844|855|866|877|888)[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "+1-800-XXX-XXXX",
		},
	}

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("phone_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("phone_validator", "validate_file", filePath)
		}
	}

	// Phone validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Phone validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for phone numbers
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("phone_validator", "validate_content", originalPath)
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Process each pattern type
	for lineNum, line := range lines {
		for _, pattern := range v.patterns {
			foundMatches := pattern.regex.FindAllString(line, -1)

			for _, match := range foundMatches {
				// Skip if this match was already found by another pattern
				if v.isDuplicateMatch(matches, match, lineNum+1) {
					continue
				}

				// Skip if this phone number is embedded within an identifier or resource ID
				if v.isEmbeddedInIdentifier(match, line) {
					continue
				}

				// Calculate confidence
				confidence, checks := v.CalculateConfidence(match)

				// Analyze phone structure
				phoneInfo := v.AnalyzePhoneStructure(match, pattern)

				// For preprocessed content, create a context info
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract context around the match in the line
				matchIndex := strings.Index(line, match)
				if matchIndex >= 0 {
					start := matchIndex - 50
					if start < 0 {
						start = 0
					}
					end := matchIndex + len(match) + 50
					if end > len(line) {
						end = len(line)
					}

					contextInfo.BeforeText = line[start:matchIndex]
					contextInfo.AfterText = line[matchIndex+len(match) : end]
				}

				// Analyze context and adjust confidence
				contextImpact := v.AnalyzeContext(match, contextInfo)

				// Check for tabular data and boost confidence
				if v.isTabularData(contextInfo.FullLine, match) {
					contextImpact += 15 // Boost for tabular data
				}

				confidence += contextImpact

				// Ensure confidence stays within bounds
				if confidence > 100 {
					confidence = 100
				} else if confidence < 0 {
					confidence = 0
				}

				// Skip matches with 0% confidence - they are false positives
				if confidence <= 0 {
					continue
				}

				// Store keywords found in context
				contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
				contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
				contextInfo.ConfidenceImpact = contextImpact

				matches = append(matches, detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "PHONE",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "phone",
					Context:    contextInfo,
					Metadata: map[string]any{
						"country":           phoneInfo["country"],
						"format":            phoneInfo["format"],
						"pattern_name":      phoneInfo["pattern_name"],
						"clean_number":      phoneInfo["clean_number"],
						"validation_checks": checks,
						"context_impact":    contextInfo.ConfidenceImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
			}
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(strings.Split(content, "\n")),
			"content_length":  len(content),
		})
	}

	return matches, nil
}

// isDuplicateMatch checks if a match was already found (same number, same line)
func (v *Validator) isDuplicateMatch(existing []detector.Match, newMatch string, lineNum int) bool {
	cleanNew := v.cleanPhoneNumber(newMatch)

	for _, match := range existing {
		if match.LineNumber == lineNum {
			cleanExisting := v.cleanPhoneNumber(match.Text)
			if cleanExisting == cleanNew {
				return true
			}
		}
	}
	return false
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// CRITICAL: Check for structural indicators first (highest priority)
	// This uses what comes BEFORE/AFTER the match rather than keywords
	if !v.hasPhoneStructure(match, context.FullLine) {
		// This is NOT a phone number (resource ID, timestamp, etc.)
		return -100 // Zero out confidence completely
	}

	// Combine all context text for analysis
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var confidenceImpact float64 = 0
	var hasPositiveKeywords bool = false

	// Check for positive keywords (increase confidence)
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			hasPositiveKeywords = true
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact += 15 // +15% for keywords in the same line
			} else {
				confidenceImpact += 8 // +8% for keywords in surrounding context
			}
		}
	}

	// Apply moderate penalty if NO positive phone context keywords are found
	// Structural analysis handles most false positives, so this is less critical
	if !hasPositiveKeywords {
		confidenceImpact -= 20 // -20% penalty for no phone context (reduced from -70%)
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact -= 35 // -35% for negative keywords in the same line
			} else {
				confidenceImpact -= 18 // -18% for negative keywords in surrounding context
			}
		}
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 40 {
		confidenceImpact = 40 // Maximum +40% boost
	} else if confidenceImpact < -80 {
		confidenceImpact = -80 // Maximum -80% reduction
	}

	return confidenceImpact
}

// findKeywords returns a list of keywords found in the context
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var found []string
	for _, keyword := range keywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			found = append(found, keyword)
		}
	}

	return found
}

// CalculateConfidence calculates the confidence score for a potential phone number
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Find the best matching pattern for this phone number
	var bestPattern phonePattern
	found := false

	for _, pattern := range v.patterns {
		if pattern.regex.MatchString(match) {
			bestPattern = pattern
			found = true
			break
		}
	}

	// If no pattern matches, use a default pattern
	if !found {
		bestPattern = phonePattern{
			name:    "Unknown",
			country: "Unknown",
			format:  "Unknown",
		}
	}

	return v.calculateConfidenceWithPattern(match, bestPattern)
}

// calculateConfidenceWithPattern calculates confidence with a specific pattern
func (v *Validator) calculateConfidenceWithPattern(match string, pattern phonePattern) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_format":      true,
		"reasonable_length": true,
		"not_test_number":   true,
		"valid_digits":      true,
		"not_sequential":    true,
		"not_repeating":     true,
		"valid_country":     false,
		"not_ssn_pattern":   true,
		"not_timestamp":     true,
	}

	confidence := 100.0
	cleanMatch := v.cleanPhoneNumber(match)

	// CRITICAL: Check if this looks like an SSN pattern (XXX-XX-XXXX) vs phone (XXX-XXX-XXXX)
	if v.looksLikeSSN(match) {
		confidence -= 50 // Heavy penalty for SSN-like patterns
		checks["not_ssn_pattern"] = false
	}

	// Check if this looks like a timestamp
	if v.looksLikeTimestamp(match) {
		confidence -= 60 // Heavy penalty for timestamp patterns
		checks["not_timestamp"] = false
	} else {
		checks["not_timestamp"] = true
	}

	// Check if this looks like a credit card fragment
	if v.looksLikeCreditCard(match) {
		confidence -= 60 // Heavy penalty for credit card fragments
		checks["valid_format"] = false
	}

	// Check if this is obviously an invalid number pattern
	if v.looksLikeInvalidNumber(match) {
		confidence -= 70 // Very heavy penalty for invalid patterns
		checks["valid_format"] = false
	}

	// Check reasonable length (15%)
	if len(cleanMatch) < 7 || len(cleanMatch) > 15 {
		confidence -= 15
		checks["reasonable_length"] = false
	}

	// Check if it's a known test number (20%)
	if v.isTestPhoneNumber(match) {
		confidence -= 20
		checks["not_test_number"] = false
	}

	// Check for valid digits only (10%)
	if !regexp.MustCompile(`^[\d+\-.\s()]+$`).MatchString(match) {
		confidence -= 10
		checks["valid_digits"] = false
	}

	// Check for sequential patterns (15%)
	if v.isSequentialNumber(cleanMatch) {
		confidence -= 15
		checks["not_sequential"] = false
	}

	// Check for repeating patterns (15%)
	if v.isRepeatingNumber(cleanMatch) {
		confidence -= 15
		checks["not_repeating"] = false
	}

	// Check country/format validity (15%)
	if v.isValidCountryFormat(match, pattern) {
		checks["valid_country"] = true
		confidence += 5 // Small boost for valid country format
	} else {
		confidence -= 10
	}

	// Boost confidence for well-formatted international numbers
	if strings.HasPrefix(match, "+") && len(cleanMatch) >= 10 {
		confidence += 10
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// AnalyzePhoneStructure breaks down the phone number into components
func (v *Validator) AnalyzePhoneStructure(phone string, pattern phonePattern) map[string]string {
	cleanNumber := v.cleanPhoneNumber(phone)

	result := map[string]string{
		"pattern_name": pattern.name,
		"country":      pattern.country,
		"format":       pattern.format,
		"clean_number": cleanNumber,
		"original":     phone,
	}

	// Extract country code if present
	if strings.HasPrefix(phone, "+") {
		// Use optimized lookup with sorted codes (longest first)
		for _, code := range v.sortedCountryCodes {
			if strings.HasPrefix(cleanNumber[1:], code) { // Skip the '+' prefix
				result["country_code"] = code
				result["country_name"] = v.countryCodeMap[code]
				break
			}
		}
	}

	return result
}

// Helper methods
func (v *Validator) cleanPhoneNumber(phone string) string {
	// Remove all non-digit characters except +
	cleaned := regexp.MustCompile(`[^\d+]`).ReplaceAllString(phone, "")
	return cleaned
}

func (v *Validator) isTestPhoneNumber(phone string) bool {
	lowerPhone := strings.ToLower(phone)

	// Check against known test numbers
	for _, testNumber := range v.testPhoneNumbers {
		if strings.Contains(phone, testNumber) {
			return true
		}
	}

	// Check against test patterns
	for _, pattern := range v.knownTestPatterns {
		if strings.Contains(lowerPhone, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

func (v *Validator) isSequentialNumber(cleanNumber string) bool {
	if len(cleanNumber) < 7 {
		return false
	}

	// Remove country code if present
	digits := cleanNumber
	if strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}

	// Check for ascending sequence (123456...)
	sequential := 0
	for i := 1; i < len(digits); i++ {
		if digits[i] == digits[i-1]+1 {
			sequential++
		} else {
			sequential = 0
		}
		if sequential >= 4 { // 5 consecutive ascending digits
			return true
		}
	}

	// Check for descending sequence (987654...)
	sequential = 0
	for i := 1; i < len(digits); i++ {
		if digits[i] == digits[i-1]-1 {
			sequential++
		} else {
			sequential = 0
		}
		if sequential >= 4 { // 5 consecutive descending digits
			return true
		}
	}

	return false
}

func (v *Validator) isRepeatingNumber(cleanNumber string) bool {
	if len(cleanNumber) < 7 {
		return false
	}

	// Remove country code if present
	digits := cleanNumber
	if strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}

	// Check for 5+ consecutive identical digits
	for i := 0; i < len(digits)-4; i++ {
		allSame := true
		for j := 1; j < 5; j++ {
			if digits[i+j] != digits[i] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}

func (v *Validator) isValidCountryFormat(phone string, pattern phonePattern) bool {
	// Basic validation based on pattern country
	switch pattern.country {
	case "US/CA":
		// US/Canada numbers should be 10 digits (excluding country code)
		clean := v.cleanPhoneNumber(phone)
		if strings.HasPrefix(clean, "+1") {
			clean = clean[2:]
		}
		return len(clean) == 10
	case "UK":
		// UK numbers vary but should follow basic format
		if strings.HasPrefix(phone, "+44") || strings.HasPrefix(phone, "0") {
			return true
		}
	case "International", "Europe", "Mobile":
		// Basic international format validation
		return strings.HasPrefix(phone, "+") || strings.HasPrefix(phone, "00")
	}

	return true // Default to valid for unknown patterns
}

// initSortedCountryCodes creates a sorted slice of country codes (longest first) for optimized lookup
func initSortedCountryCodes(countryCodeMap map[string]string) []string {
	codes := make([]string, 0, len(countryCodeMap))
	for code := range countryCodeMap {
		codes = append(codes, code)
	}

	// Sort by length (longest first) to match longer codes before shorter ones
	// This prevents "1" from matching before "1242" (Bahamas)
	sort.Slice(codes, func(i, j int) bool {
		return len(codes[i]) > len(codes[j])
	})

	return codes
}

// Initialize country code map
func initCountryCodeMap() map[string]string {
	return map[string]string{
		"1":   "US/Canada",
		"44":  "United Kingdom",
		"33":  "France",
		"49":  "Germany",
		"39":  "Italy",
		"34":  "Spain",
		"31":  "Netherlands",
		"32":  "Belgium",
		"41":  "Switzerland",
		"43":  "Austria",
		"45":  "Denmark",
		"46":  "Sweden",
		"47":  "Norway",
		"358": "Finland",
		"7":   "Russia",
		"86":  "China",
		"81":  "Japan",
		"82":  "South Korea",
		"91":  "India",
		"61":  "Australia",
		"64":  "New Zealand",
		"55":  "Brazil",
		"52":  "Mexico",
		"54":  "Argentina",
		"56":  "Chile",
		"57":  "Colombia",
		"58":  "Venezuela",
		"51":  "Peru",
		"27":  "South Africa",
		"20":  "Egypt",
		"212": "Morocco",
		"213": "Algeria",
		"216": "Tunisia",
		"218": "Libya",
		"234": "Nigeria",
		"254": "Kenya",
	}
}

// looksLikeSSN checks if the pattern matches SSN format (XXX-XX-XXXX) instead of phone
func (v *Validator) looksLikeSSN(match string) bool {
	// SSN pattern: exactly 9 digits in XXX-XX-XXXX format
	ssnPattern := regexp.MustCompile(`^\d{3}[-.\s]\d{2}[-.\s]\d{4}$`)
	return ssnPattern.MatchString(match)
}

// looksLikeCreditCard checks if the pattern matches credit card fragments
func (v *Validator) looksLikeCreditCard(match string) bool {
	clean := v.cleanPhoneNumber(match)

	// Credit card fragments often have 4 digits
	if len(clean) == 4 {
		return true
	}

	// Patterns like XXXX-XXXX (8 digits) are often credit card fragments
	if len(clean) == 8 && strings.Contains(match, "-") {
		return true
	}

	// Look for patterns that start with common credit card prefixes in wrong context
	commonCCPrefixes := []string{"4", "5", "6", "3"}
	for _, prefix := range commonCCPrefixes {
		if strings.HasPrefix(clean, prefix) && len(clean) >= 4 && len(clean) <= 8 {
			return true
		}
	}

	return false
}

// looksLikeTimestamp checks if the pattern matches common timestamp formats
func (v *Validator) looksLikeTimestamp(match string) bool {
	clean := v.cleanPhoneNumber(match)

	// Unix timestamp patterns (10 digits starting with 1 or 2)
	if len(clean) == 10 && (strings.HasPrefix(clean, "1") || strings.HasPrefix(clean, "2")) {
		// Check if it's in a reasonable timestamp range
		// 1000000000 = Sep 2001, 2147483647 = Jan 2038 (32-bit limit)
		if timestamp, err := strconv.ParseInt(clean, 10, 64); err == nil {
			if timestamp >= 1000000000 && timestamp <= 2147483647 {
				return true
			}
		}
	}

	// Millisecond timestamp patterns (13 digits starting with 1)
	if len(clean) == 13 && strings.HasPrefix(clean, "1") {
		if timestamp, err := strconv.ParseInt(clean, 10, 64); err == nil {
			if timestamp >= 1000000000000 && timestamp <= 2147483647000 {
				return true
			}
		}
	}

	// Date-like patterns that could be confused with phones
	// YYYYMMDDHHMMSS (14 digits starting with 19 or 20)
	if len(clean) >= 8 && (strings.HasPrefix(clean, "19") || strings.HasPrefix(clean, "20")) {
		// Basic year validation (1900-2099)
		if len(clean) >= 4 {
			year := clean[:4]
			if year >= "1900" && year <= "2099" {
				return true
			}
		}
	}

	return false
}

// looksLikeInvalidNumber checks for obviously invalid phone patterns
func (v *Validator) looksLikeInvalidNumber(match string) bool {
	clean := v.cleanPhoneNumber(match)

	// Patterns like +0000, 0000, 060000 are clearly invalid
	if strings.HasPrefix(clean, "+0000") || strings.HasPrefix(clean, "0000") {
		return true
	}

	// Numbers that are too short to be valid phones (less than 7 digits)
	if len(clean) < 7 {
		return true
	}

	// Numbers starting with 0 that aren't international format
	if strings.HasPrefix(clean, "0") && !strings.HasPrefix(match, "+") && len(clean) < 10 {
		return true
	}

	// All zeros or mostly zeros
	zeroCount := strings.Count(clean, "0")
	if float64(zeroCount)/float64(len(clean)) > 0.8 {
		return true
	}

	return false
}

// isTabularData checks if the phone number appears to be in a tabular format
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

	// Check for common contact list patterns (names followed by phones)
	namePhonePattern := regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+\(?\d{3}\)?`)
	if namePhonePattern.MatchString(line) {
		return true
	}

	return false
}

// isEmbeddedInIdentifier checks if a phone number match is embedded within an identifier or resource ID
// This helps filter out false positives like "i-057034242931", "ami-050451375729", "vpc-1234567890"
func (v *Validator) isEmbeddedInIdentifier(match, line string) bool {
	matchIndex := strings.Index(line, match)
	if matchIndex == -1 {
		return false
	}

	// Check character before the match
	if matchIndex > 0 {
		charBefore := line[matchIndex-1]
		// If the character before is alphanumeric or common identifier separators, this phone is embedded
		if (charBefore >= 'a' && charBefore <= 'z') ||
			(charBefore >= 'A' && charBefore <= 'Z') ||
			(charBefore >= '0' && charBefore <= '9') ||
			charBefore == '-' || charBefore == '_' || charBefore == ':' {
			return true
		}

		// Check for patterns like "Timestamp: 1234567890" where there's a space before the number
		// But exclude phone-related labels like "Phone:", "Tel:", etc.
		if charBefore == ' ' && matchIndex >= 2 {
			charBeforeSpace := line[matchIndex-2]
			if charBeforeSpace == ':' {
				// Extract the word before the colon to check if it's a phone-related label
				wordStart := matchIndex - 3
				for wordStart >= 0 && line[wordStart] != ' ' && line[wordStart] != '\t' {
					wordStart--
				}
				wordStart++ // Move to start of word

				if wordStart < matchIndex-2 {
					wordBeforeColon := strings.ToLower(line[wordStart : matchIndex-2])

					// Don't filter if this is a phone-related label
					phoneLabels := []string{"phone", "tel", "telephone", "mobile", "cell", "fax", "contact", "call", "emergency", "support", "office", "home", "work"}
					for _, label := range phoneLabels {
						if wordBeforeColon == label || strings.HasSuffix(wordBeforeColon, label) {
							return false // Don't filter - this is likely a real phone
						}
					}

					// Filter out non-phone identifier patterns
					identifierLabels := []string{"timestamp", "build", "version", "revision", "id", "key", "hash", "uuid", "guid", "token", "session", "request", "response"}
					for _, label := range identifierLabels {
						if wordBeforeColon == label || strings.HasSuffix(wordBeforeColon, label) {
							return true // Filter - this is an identifier
						}
					}
				}
			}
		}
	}

	// Check character after the match
	matchEnd := matchIndex + len(match)
	if matchEnd < len(line) {
		charAfter := line[matchEnd]
		// If the character after is alphanumeric or common identifier separators, this phone is embedded
		if (charAfter >= 'a' && charAfter <= 'z') ||
			(charAfter >= 'A' && charAfter <= 'Z') ||
			(charAfter >= '0' && charAfter <= '9') ||
			charAfter == '-' || charAfter == '_' || charAfter == ':' {
			return true
		}
	}

	// Additional check: look for common AWS/cloud resource patterns
	// Check if the match is part of a resource identifier pattern
	beforeContext := ""
	if matchIndex >= 10 {
		beforeContext = line[matchIndex-10 : matchIndex]
	} else {
		beforeContext = line[0:matchIndex]
	}

	afterContext := ""
	if matchEnd+10 <= len(line) {
		afterContext = line[matchEnd : matchEnd+10]
	} else {
		afterContext = line[matchEnd:]
	}

	fullContext := strings.ToLower(beforeContext + match + afterContext)

	// Common patterns that indicate this is an identifier, not a phone number
	identifierPatterns := []string{
		"instance", "ami-", "vpc-", "subnet-", "sg-", "igw-", "rtb-", "acl-",
		"vol-", "snap-", "eni-", "eip-", "nat-", "tgw-", "vpce-", "pcx-",
		"build", "version", "revision", "timestamp", "id:", "key:", "hash",
		"uuid", "guid", "token", "session", "request", "response",
	}

	for _, pattern := range identifierPatterns {
		if strings.Contains(fullContext, pattern) {
			return true
		}
	}

	return false
}

// hasPhoneStructure checks if the match is actually a phone number, not something else
// This uses structural analysis (what comes BEFORE/AFTER the match) rather than
// keyword matching, making it future-proof and context-agnostic.
func (v *Validator) hasPhoneStructure(match string, line string) bool {
	matchIndex := strings.Index(line, match)
	if matchIndex < 0 {
		return false
	}

	// Get characters before and after the match
	var beforeMatch string
	if matchIndex >= 10 {
		beforeMatch = line[matchIndex-10 : matchIndex]
	} else if matchIndex > 0 {
		beforeMatch = line[0:matchIndex]
	}

	var afterMatch string
	matchEnd := matchIndex + len(match)
	if matchEnd+10 <= len(line) {
		afterMatch = line[matchEnd : matchEnd+10]
	} else if matchEnd < len(line) {
		afterMatch = line[matchEnd:]
	}

	// Check for NEGATIVE indicators (NOT a phone number)
	// These should be checked FIRST and return false immediately

	// 1. Resource ID patterns: prefix-digits or digits-suffix
	//    Examples: i-1234567890, ami-1234567890, vpc-1234567890
	if matchIndex > 0 {
		charBefore := line[matchIndex-1]

		// Check for resource ID patterns (letter-hyphen-digits)
		// But allow phone patterns like +1-555 or (555)
		if charBefore == '-' {
			// Check if there's a letter before the hyphen (resource ID pattern)
			if matchIndex >= 2 {
				charBeforeHyphen := line[matchIndex-2]
				if (charBeforeHyphen >= 'a' && charBeforeHyphen <= 'z') ||
					(charBeforeHyphen >= 'A' && charBeforeHyphen <= 'Z') {
					// This is likely a resource ID like ami-123456
					return false
				}
			}
			// If hyphen is preceded by digit or +, it's likely a phone number
			// Examples: +1-555, 1-800
		}

		// Underscore before digits indicates resource ID
		if charBefore == '_' {
			return false
		}

		// Letter immediately before (no space) indicates identifier
		// But allow closing parenthesis for phone formats like (555)
		if charBefore != ')' && charBefore != '+' {
			if (charBefore >= 'a' && charBefore <= 'z') || (charBefore >= 'A' && charBefore <= 'Z') {
				return false
			}
		}
	}

	// 2. Check what comes after the match
	if len(afterMatch) > 0 {
		firstChar := afterMatch[0]

		// Hyphen, underscore, or letter after indicates identifier/resource ID
		if firstChar == '-' || firstChar == '_' {
			return false
		}
		if (firstChar >= 'a' && firstChar <= 'z') || (firstChar >= 'A' && firstChar <= 'Z') {
			return false
		}

		// Colon after digits indicates ARN or timestamp
		//    Examples: arn:aws:iam::123456789012:role, timestamp:1234567890
		if firstChar == ':' {
			return false
		}
	}

	// 3. Check for ARN patterns in before context
	//    Examples: arn:aws:iam::, ::123456789012:
	if strings.Contains(beforeMatch, "::") || strings.Contains(beforeMatch, "arn:") {
		return false
	}

	// 4. Check for timestamp/build patterns in before context
	timestampIndicators := []string{"timestamp", "build", "created", "updated", "modified", "version"}
	beforeLower := strings.ToLower(beforeMatch)
	for _, indicator := range timestampIndicators {
		if strings.Contains(beforeLower, indicator) {
			// Check if this is a plain number (no separators) - likely timestamp
			cleanMatch := v.cleanPhoneNumber(match)
			if len(cleanMatch) == len(match) { // No separators removed = plain digits
				return false
			}
		}
	}

	// Check for POSITIVE indicators (IS a phone number)

	// 1. Phone terminators: space, comma, semicolon, period, closing punctuation
	if len(afterMatch) > 0 {
		firstChar := afterMatch[0]
		phoneTerminators := []byte{' ', '\t', ',', ';', '.', '!', '?', ')', ']', '}', '\n', '\r'}
		for _, terminator := range phoneTerminators {
			if firstChar == terminator {
				return true // Looks like a phone
			}
		}

		// Extension indicators
		if strings.HasPrefix(strings.ToLower(afterMatch), "ext") ||
			strings.HasPrefix(strings.ToLower(afterMatch), "x") {
			return true
		}
	}

	// 2. End of line
	if len(afterMatch) == 0 {
		return true
	}

	// 3. Phone has separators (dashes, spaces, parentheses)
	//    Plain digit sequences are more likely to be timestamps/IDs
	if strings.Contains(match, "-") || strings.Contains(match, " ") ||
		strings.Contains(match, "(") || strings.Contains(match, ")") {
		return true
	}

	// 4. Starts with + (international format)
	if strings.HasPrefix(match, "+") {
		return true
	}

	// Default: if ambiguous, assume it's a phone (favor false negatives over false positives)
	// But only if it has proper phone formatting
	cleanMatch := v.cleanPhoneNumber(match)
	hasFormatting := len(cleanMatch) < len(match) // Has separators

	return hasFormatting
}

// isDebugEnabled checks if debug mode is enabled
func (v *Validator) isDebugEnabled() bool {
	return os.Getenv("FERRET_DEBUG") != ""
}
