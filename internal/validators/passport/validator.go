// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"regexp"
	"strings"
	"unicode"

	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Validator implements the detector.Validator interface for detecting
// passport numbers from various countries using regex patterns and contextual analysis.
type Validator struct {
	patterns map[string]string

	// Keywords that suggest a passport context
	positiveKeywords []string

	// Keywords that suggest this is not a passport
	negativeKeywords []string

	// Valid country codes for passports
	validCountryCodes map[string]bool

	// Common English words that might be mistaken for passport numbers
	commonWords []string

	// Known test passport patterns
	knownTestPatterns []string

	// Enhanced context analysis
	contextAnalyzer *context.ContextAnalyzer

	// Travel-specific keywords for enhanced validation
	travelKeywords     []string
	governmentKeywords []string
	formKeywords       []string

	// Global test passport database
	globalTestPassports []string

	// Observability
	observer *observability.StandardObserver
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting passport numbers from various countries.
func NewValidator() *Validator {
	return &Validator{
		patterns: map[string]string{
			// Common passport formats by country - made more restrictive
			"US":     `\b[A-Z]\d{8}\b`,          // US: 1 letter followed by 8 digits
			"UK":     `\b\d{9}\b`,               // UK: 9 digits
			"Canada": `\b[A-Z]{2}\d{6}\b`,       // Canada: 2 letters followed by 6 digits
			"EU":     `\b[A-Z]{2}[A-Z0-9]{7}\b`, // EU: 2 letters followed by 7 alphanumeric chars
			// Removed overly broad Generic pattern - it was causing too many false positives
			"MRZ":     `\bP[A-Z]{1}[A-Z0-9<]{42,44}\b`,        // Machine Readable Zone format
			"MRZ_TD3": `\bP[A-Z]{3}[A-Z0-9<]{39}[0-9][0-9]\b`, // MRZ TD3 format
		},
		positiveKeywords: []string{
			// High-confidence passport-specific keywords
			"passport", "passport number", "passport no", "travel document",
			"travel document number", "document number", "document no",
			"mrz", "machine readable", "icao", "passport holder",

			// Medium-confidence travel-related keywords
			"visa", "immigration", "border control", "customs", "embassy", "consulate",
			"nationality", "citizenship", "issuing authority", "passport authority",

			// Lower-confidence general keywords
			"identification", "identity", "travel", "international", "foreign",
			"expiry", "expiration", "issue date", "valid until", "expires",
			"surname", "given name", "date of birth", "place of birth", "gender", "sex",
		},
		negativeKeywords: []string{
			// Test/fake data indicators
			"example", "test", "sample", "mock", "fake", "dummy", "placeholder",
			"template", "demo", "random", "generated", "simulation", "synthetic",

			// Technical identifiers
			"uuid", "guid", "serial", "serial number", "product code", "model",
			"version", "build", "revision", "commit", "hash", "checksum",

			// Business identifiers
			"tracking", "shipment", "order", "invoice", "receipt", "transaction",
			"customer", "account", "username", "login", "password", "pin",
			"reference", "confirmation", "booking", "reservation",

			// Database/system identifiers
			"primary key", "foreign key", "index", "database", "table", "record",
			"field", "column", "row", "entry", "item", "element",
		},
		validCountryCodes: initValidCountryCodes(),
		commonWords: []string{
			"positive", "negative", "passport", "document", "identity", "national",
			"personal", "official", "original", "certified", "verified", "approved",
			"accepted", "rejected", "expired", "renewed", "updated", "processed",
			"scanned", "uploaded", "downloaded", "attached", "included", "excluded",
		},
		knownTestPatterns: []string{
			"A00000000", "A11111111", "A12345678", "AA000000", "XX0000000",
			"000000000", "123456789", "AB123456", "AB000000", "XX0000000",
		},

		// Initialize context analyzer
		contextAnalyzer: context.NewContextAnalyzer(),

		// Travel-specific keywords for enhanced validation
		travelKeywords: []string{
			"airport", "flight", "airline", "boarding", "departure", "arrival",
			"terminal", "gate", "security", "checkpoint", "baggage", "luggage",
			"customs", "immigration", "visa", "entry", "exit", "transit",
			"vacation", "holiday", "business trip", "conference", "meeting",
		},

		// Government/official keywords
		governmentKeywords: []string{
			"government", "official", "authority", "department", "ministry",
			"embassy", "consulate", "foreign office", "state department",
			"homeland security", "border patrol", "immigration officer",
			"passport office", "visa office", "diplomatic", "consular",
		},

		// Form/document keywords
		formKeywords: []string{
			"application", "form", "document", "certificate", "record",
			"registration", "identification", "identity", "personal",
			"information", "details", "data", "field", "entry", "input",
		},

		// Global test passport database
		globalTestPassports: []string{
			"A00000000", "A11111111", "A12345678", "A99999999",
			"AA000000", "AB000000", "AB123456", "XX0000000", "XX123456",
			"000000000", "111111111", "123456789", "999999999",
			"GB000000000", "US000000000", "CA00000000", "FR00000000",
			"TEST123456", "SAMPLE123", "DEMO12345", "PLACEHOLDER",
			"EXAMPLE123", "FAKE123456", "MOCK123456", "DUMMY12345",
		},
	}
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Initialize valid country codes
func initValidCountryCodes() map[string]bool {
	codes := map[string]bool{
		// EU countries
		"AT": true, "BE": true, "BG": true, "HR": true, "CY": true,
		"CZ": true, "DK": true, "EE": true, "FI": true, "FR": true,
		"DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
		"LV": true, "LT": true, "LU": true, "MT": true, "NL": true,
		"PL": true, "PT": true, "RO": true, "SK": true, "SI": true,
		"ES": true, "SE": true,

		// Non-EU European countries
		"GB": true, "CH": true, "NO": true, "IS": true, "LI": true,

		// North America
		"US": true, "CA": true, "MX": true,

		// Major Asian countries
		"CN": true, "JP": true, "KR": true, "IN": true, "SG": true,

		// Major Oceania countries
		"AU": true, "NZ": true,

		// Major South American countries
		"BR": true, "AR": true, "CL": true,

		// Major African countries
		"ZA": true, "EG": true, "NG": true,
	}
	return codes
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("passport_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("passport_validator", "validate_file", filePath)
		}
	}

	// Passport validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Passport validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for passport numbers
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Check each pattern against the line
		for country, pattern := range v.patterns {
			re := regexp.MustCompile(pattern)
			foundMatches := re.FindAllString(line, -1)

			for _, match := range foundMatches {
				// Skip if it's a common word or test pattern
				if v.isCommonWord(match) || v.isTestPattern(match) {
					continue
				}

				// Double-check that this match actually belongs to a valid country format
				actualCountry := v.determineCountry(match)
				if actualCountry == "" {
					continue // Skip matches that don't fit any specific passport format
				}

				confidence, checks := v.CalculateConfidence(match + ":" + country)

				// Create context info for the line
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract some context around the match in the line
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

				contextInfo.ConfidenceImpact = contextImpact

				// Require strong context for passport matches
				hasStrongContext := v.hasStrongPassportContext(match, &contextInfo)

				// Skip matches with 0% confidence - they are false positives
				if confidence <= 0 {
					continue
				}

				// Only include matches with reasonable confidence AND strong context
				if confidence <= 60 || !hasStrongContext {
					continue
				}

				matches = append(matches, detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "PASSPORT",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "passport",
					Context:    contextInfo,
					Metadata: map[string]any{
						"country":           country,
						"validation_checks": checks,
						"context_impact":    contextImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
			}
		}
	}

	return matches, nil
}

// Check if two passport patterns are similar (likely part of a test sequence)
func (v *Validator) areSimilarPatterns(pat1, pat2 string) bool {
	// If they're identical except for the last character, they're likely sequential
	if len(pat1) == len(pat2) && len(pat1) >= 6 {
		samePrefix := true
		for i := 0; i < len(pat1)-1; i++ {
			if pat1[i] != pat2[i] {
				samePrefix = false
				break
			}
		}
		if samePrefix {
			return true
		}
	}

	// If they have the same pattern of letters and digits
	letterPattern1 := v.getLetterDigitPattern(pat1)
	letterPattern2 := v.getLetterDigitPattern(pat2)
	if letterPattern1 != "" && letterPattern1 == letterPattern2 {
		return true
	}

	return false
}

// Get the pattern of letters and digits (e.g., "AB123456" becomes "LL######")
func (v *Validator) getLetterDigitPattern(text string) string {
	if len(text) < 6 {
		return ""
	}

	var pattern strings.Builder
	for _, char := range text {
		if unicode.IsLetter(char) {
			pattern.WriteRune('L')
		} else if unicode.IsDigit(char) {
			pattern.WriteRune('#')
		} else {
			pattern.WriteRune(char)
		}
	}

	return pattern.String()
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Combine all context text for analysis
	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
	fullContext = strings.ToLower(fullContext)

	var confidenceImpact float64 = 0

	// Check proximity to "passport" specifically - this is the strongest indicator
	passportProximity := v.calculatePassportProximity(match, context)
	confidenceImpact += passportProximity

	// Check for positive keywords with weighted scoring
	for _, keyword := range v.positiveKeywords {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(fullContext, keywordLower) {
			// Weight keywords by their specificity to passports
			weight := v.getKeywordWeight(keyword)

			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, keywordLower) {
				confidenceImpact += weight * 1.5 // Boost for same-line keywords
			} else {
				confidenceImpact += weight // Base weight for surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(fullContext, keywordLower) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, keywordLower) {
				confidenceImpact -= 20 // Strong penalty for negative keywords in same line
			} else {
				confidenceImpact -= 10 // Moderate penalty for negative keywords in context
			}
		}
	}

	// Check for form-like structure (labels followed by values)
	if v.isInFormContext(match, context) {
		confidenceImpact += 15 // Boost for form-like contexts
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 40 {
		confidenceImpact = 40 // Maximum +40% boost
	} else if confidenceImpact < -60 {
		confidenceImpact = -60 // Maximum -60% reduction
	}

	return confidenceImpact
}

// calculatePassportProximity calculates confidence boost based on proximity to "passport" keyword
func (v *Validator) calculatePassportProximity(match string, context detector.ContextInfo) float64 {
	fullLine := strings.ToLower(context.FullLine)
	beforeText := strings.ToLower(context.BeforeText)
	afterText := strings.ToLower(context.AfterText)

	// Check for "passport" in various forms
	passportVariants := []string{"passport", "passport number", "passport no", "passport #"}

	for _, variant := range passportVariants {
		// Same line - highest boost
		if strings.Contains(fullLine, variant) {
			// Check if it's very close (within 20 characters)
			matchIndex := strings.Index(fullLine, match)
			variantIndex := strings.Index(fullLine, variant)

			if matchIndex >= 0 && variantIndex >= 0 {
				distance := matchIndex - variantIndex
				if distance < 0 {
					distance = -distance
				}

				if distance <= 20 {
					return 25 // Very close to "passport" - high confidence
				} else if distance <= 50 {
					return 15 // Moderately close
				} else {
					return 8 // Same line but far apart
				}
			}
		}

		// In surrounding context - moderate boost
		if strings.Contains(beforeText, variant) || strings.Contains(afterText, variant) {
			return 5
		}
	}

	return 0
}

// getKeywordWeight returns the weight for a specific keyword based on its relevance to passports
func (v *Validator) getKeywordWeight(keyword string) float64 {
	highConfidenceKeywords := map[string]float64{
		"passport": 15, "passport number": 15, "passport no": 15, "travel document": 12,
		"travel document number": 12, "document number": 10, "document no": 10,
		"mrz": 12, "machine readable": 10, "icao": 8, "passport holder": 10,
	}

	mediumConfidenceKeywords := map[string]float64{
		"visa": 6, "immigration": 6, "border control": 6, "customs": 5,
		"embassy": 5, "consulate": 5, "nationality": 4, "citizenship": 4,
		"issuing authority": 6, "passport authority": 8,
	}

	lowConfidenceKeywords := map[string]float64{
		"identification": 3, "identity": 3, "travel": 2, "international": 2,
		"foreign": 2, "expiry": 3, "expiration": 3, "issue date": 3,
		"valid until": 3, "expires": 3, "surname": 2, "given name": 2,
		"date of birth": 2, "place of birth": 2, "gender": 1, "sex": 1,
	}

	keywordLower := strings.ToLower(keyword)

	if weight, exists := highConfidenceKeywords[keywordLower]; exists {
		return weight
	}
	if weight, exists := mediumConfidenceKeywords[keywordLower]; exists {
		return weight
	}
	if weight, exists := lowConfidenceKeywords[keywordLower]; exists {
		return weight
	}

	return 2 // Default weight for unlisted keywords
}

// isInFormContext checks if the match appears to be in a form-like context
func (v *Validator) isInFormContext(match string, context detector.ContextInfo) bool {
	line := strings.ToLower(context.FullLine)

	// Look for form-like patterns: "label: value" or "label = value" or "label value"
	formPatterns := []string{
		"passport.*:", "passport.*=", "passport.*number.*:", "passport.*no.*:",
		"document.*:", "document.*number.*:", "travel.*document.*:",
		"number.*:", "no.*:", "#.*:",
	}

	for _, pattern := range formPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return true
		}
	}

	// Check for table-like structure (multiple values separated by tabs or multiple spaces)
	if strings.Count(line, "\t") >= 2 || regexp.MustCompile(`\s{3,}`).MatchString(line) {
		return true
	}

	return false
}

// hasStrongPassportContext checks if there's strong contextual evidence this is actually a passport
func (v *Validator) hasStrongPassportContext(match string, context *detector.ContextInfo) bool {
	if context == nil {
		return false
	}

	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)

	// Strong indicators - any of these is sufficient
	strongIndicators := []string{
		"passport", "passport number", "passport no", "passport #",
		"travel document", "travel document number", "document number",
		"mrz", "machine readable zone",
	}

	for _, indicator := range strongIndicators {
		if strings.Contains(fullContext, indicator) {
			return true
		}
	}

	// Medium indicators - need at least 2 of these
	mediumIndicators := []string{
		"visa", "immigration", "border", "customs", "embassy", "consulate",
		"nationality", "citizenship", "travel", "international", "foreign",
		"expiry", "expiration", "expires", "valid until", "issue date",
	}

	mediumCount := 0
	for _, indicator := range mediumIndicators {
		if strings.Contains(fullContext, indicator) {
			mediumCount++
			if mediumCount >= 2 {
				return true
			}
		}
	}

	// Form context can also be strong evidence if combined with any travel-related keyword
	if v.isInFormContext(match, *context) {
		travelKeywords := []string{"travel", "document", "identification", "identity", "international"}
		for _, keyword := range travelKeywords {
			if strings.Contains(fullContext, keyword) {
				return true
			}
		}
	}

	return false
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

// CalculateConfidence calculates the confidence score for a potential passport number
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Extract country from the match (added in Validate method)
	parts := strings.Split(match, ":")
	cleanMatch := parts[0]
	country := ""
	if len(parts) > 1 {
		country = parts[1]
	} else {
		country = v.determineCountry(cleanMatch)
	}

	checks := map[string]bool{
		"format":             true,
		"length":             true,
		"valid_country_code": false,
		"not_test_number":    true,
		"not_sequential":     true,
		"valid_characters":   true,
		"not_common_word":    true,
	}

	// Start with lower base confidence - require context to boost it
	confidence := 60.0

	// Clean the match (remove spaces, etc.)
	cleanMatch = strings.ReplaceAll(cleanMatch, " ", "")

	// Check if it's a known test pattern
	if v.isKnownTestPattern(cleanMatch) {
		confidence -= 30
		checks["not_test_number"] = false
	}

	// Check if it's a common English word
	if v.isLikelyWord(cleanMatch) {
		confidence -= 40
		checks["not_common_word"] = false
	}

	// Check format-specific validations
	switch country {
	case "US":
		// US passport: 1 letter followed by 8 digits
		if !regexp.MustCompile(`^[A-Z]\d{8}$`).MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 9 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for test numbers
		if cleanMatch == "A00000000" || cleanMatch == "A11111111" || cleanMatch == "A12345678" {
			confidence -= 15
			checks["not_test_number"] = false
		}

	case "UK":
		// UK passport: 9 digits
		if !regexp.MustCompile(`^\d{9}$`).MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 9 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for test numbers
		if cleanMatch == "000000000" || cleanMatch == "111111111" || cleanMatch == "123456789" {
			confidence -= 15
			checks["not_test_number"] = false
		}

	case "Canada":
		// Canadian passport: 2 letters followed by 6 digits
		if !regexp.MustCompile(`^[A-Z]{2}\d{6}$`).MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 8 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for valid country code
		if !v.validCountryCodes[cleanMatch[0:2]] {
			confidence -= 15
		} else {
			checks["valid_country_code"] = true
		}

		// Check for test numbers
		if cleanMatch == "AB000000" || cleanMatch == "AB123456" || cleanMatch == "AA000000" {
			confidence -= 15
			checks["not_test_number"] = false
		}

	case "EU":
		// EU passport: 2 letters followed by 7 alphanumeric chars
		if !regexp.MustCompile(`^[A-Z]{2}[A-Z0-9]{7}$`).MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 9 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for valid country code
		if !v.validCountryCodes[cleanMatch[0:2]] {
			confidence -= 15
		} else {
			checks["valid_country_code"] = true
		}

		// Check for invalid country codes like XX
		if cleanMatch[0:2] == "XX" || cleanMatch[0:2] == "ZZ" || cleanMatch[0:2] == "YY" {
			confidence -= 20
			checks["valid_country_code"] = false
		}

	case "MRZ", "MRZ_TD3":
		// Machine Readable Zone checks
		// These are more complex and would need specific validation
		// For now, just check basic format
		if !strings.HasPrefix(cleanMatch, "P") {
			confidence -= 20
			checks["format"] = false
		}

		// Check for valid characters in MRZ (letters, numbers, and <)
		if !regexp.MustCompile(`^[A-Z0-9<]+$`).MatchString(cleanMatch) {
			confidence -= 15
			checks["valid_characters"] = false
		}

	case "Generic":
		// Generic passport: 6-10 alphanumeric chars
		// This is a catch-all with lower confidence
		confidence -= 30 // Start with lower confidence for generic matches

		// Check for valid characters
		if !regexp.MustCompile(`^[A-Z0-9]+$`).MatchString(cleanMatch) {
			confidence -= 15
			checks["valid_characters"] = false
		}

		// Check for sequential or repeated characters
		if v.isSequentialOrRepeated(cleanMatch) {
			confidence -= 10
			checks["not_sequential"] = false
		}
	}

	// Check for common patterns that might be false positives
	if v.isPossibleFalsePositive(cleanMatch) {
		confidence -= 25
	}

	// Ensure confidence is within bounds
	if confidence < 0 {
		confidence = 0
	}

	return confidence, checks
}

// isKnownTestPattern checks if the pattern matches a known test pattern
func (v *Validator) isKnownTestPattern(text string) bool {
	for _, pattern := range v.knownTestPatterns {
		if text == pattern {
			return true
		}
	}
	return false
}

// isLikelyWord checks if the text is likely an English word
func (v *Validator) isLikelyWord(text string) bool {
	// Check against common words list
	for _, word := range v.commonWords {
		if strings.EqualFold(text, word) {
			return true
		}
	}

	// Simple heuristic: English words typically have vowels
	// and a reasonable vowel-to-consonant ratio
	if len(text) >= 5 {
		vowels := 0
		for _, char := range strings.ToUpper(text) {
			if strings.ContainsRune("AEIOU", char) {
				vowels++
			}
		}

		// If it has vowels and the ratio of vowels to length is reasonable for English
		vowelRatio := float64(vowels) / float64(len(text))
		return vowels >= 1 && vowelRatio >= 0.2 && vowelRatio <= 0.6
	}

	return false
}

// determineCountry tries to identify the country format based on the match pattern
func (v *Validator) determineCountry(match string) string {
	cleanMatch := strings.ReplaceAll(match, " ", "")

	// Try to match against each country pattern
	if regexp.MustCompile(`^[A-Z]\d{8}$`).MatchString(cleanMatch) {
		return "US"
	} else if regexp.MustCompile(`^\d{9}$`).MatchString(cleanMatch) {
		return "UK"
	} else if regexp.MustCompile(`^[A-Z]{2}\d{6}$`).MatchString(cleanMatch) {
		return "Canada"
	} else if regexp.MustCompile(`^[A-Z]{2}[A-Z0-9]{7}$`).MatchString(cleanMatch) {
		return "EU"
	} else if strings.HasPrefix(cleanMatch, "P") && len(cleanMatch) > 40 {
		if len(cleanMatch) == 44 {
			return "MRZ_TD3"
		}
		return "MRZ"
	}

	// No generic fallback - only match specific passport formats
	return ""
}

// Helper methods
func (v *Validator) isSequentialOrRepeated(text string) bool {
	// Check for repeated characters (e.g., "AAAAAA")
	for i := 0; i < len(text)-3; i++ {
		if text[i] == text[i+1] && text[i] == text[i+2] && text[i] == text[i+3] {
			return true
		}
	}

	// Check for sequential characters (e.g., "ABCDEF" or "123456")
	// For digits
	digitSequence := true
	for i := 0; i < len(text)-3; i++ {
		if unicode.IsDigit(rune(text[i])) && unicode.IsDigit(rune(text[i+1])) &&
			unicode.IsDigit(rune(text[i+2])) && unicode.IsDigit(rune(text[i+3])) {
			if text[i+1] != text[i]+1 || text[i+2] != text[i]+2 || text[i+3] != text[i]+3 {
				digitSequence = false
				break
			}
		} else {
			digitSequence = false
			break
		}
	}

	// For letters
	letterSequence := true
	for i := 0; i < len(text)-3; i++ {
		if unicode.IsLetter(rune(text[i])) && unicode.IsLetter(rune(text[i+1])) &&
			unicode.IsLetter(rune(text[i+2])) && unicode.IsLetter(rune(text[i+3])) {
			if text[i+1] != text[i]+1 || text[i+2] != text[i]+2 || text[i+3] != text[i]+3 {
				letterSequence = false
				break
			}
		} else {
			letterSequence = false
			break
		}
	}

	return digitSequence || letterSequence
}

func (v *Validator) isPossibleFalsePositive(text string) bool {
	// Check for common false positives like product codes, serial numbers, etc.
	falsePositivePatterns := []string{
		`^[A-Z]{2}\d{4}$`,    // Common product code format
		`^(SKU|UPC|EAN)\d+$`, // Product identifiers
		`^[A-Z]{3}-\d{4}$`,   // Part numbers
	}

	for _, pattern := range falsePositivePatterns {
		if regexp.MustCompile(pattern).MatchString(text) {
			return true
		}
	}

	// Check if it's a common English word
	if v.isLikelyWord(text) {
		return true
	}

	return false
}

func (v *Validator) getFormatDescription(country string) string {
	descriptions := map[string]string{
		"US":      "US passport (1 letter followed by 8 digits)",
		"UK":      "UK passport (9 digits)",
		"Canada":  "Canadian passport (2 letters followed by 6 digits)",
		"EU":      "EU passport (2 letters followed by 7 alphanumeric characters)",
		"Generic": "Generic passport format (6-10 alphanumeric characters)",
		"MRZ":     "Machine Readable Zone format",
		"MRZ_TD3": "Machine Readable Zone TD3 format",
	}

	if desc, ok := descriptions[country]; ok {
		return desc
	}

	return "Unknown passport format"
}

// isCommonWord checks if the match is a common English word that might be mistaken for a passport
func (v *Validator) isCommonWord(match string) bool {
	// Convert to lowercase for comparison
	lower := strings.ToLower(match)

	// Check against common words that might match passport patterns
	commonWords := []string{
		"password", "passport", "document", "number", "code", "test", "example",
		"sample", "demo", "placeholder", "template", "default", "unknown",
	}

	for _, word := range commonWords {
		if lower == word {
			return true
		}
	}

	return false
}

// isTabularData checks if the passport appears to be in a tabular format
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

	// Check for common travel document patterns (names followed by passport numbers)
	travelPattern := regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z0-9]{6,10}`)
	if travelPattern.MatchString(line) {
		return true
	}

	return false
}

// isTestPattern checks if the match is a known test passport pattern
func (v *Validator) isTestPattern(match string) bool {
	// Check against known test patterns
	testPatterns := []string{
		"A12345678", "123456789", "AB123456", "TEST1234", "SAMPLE01",
		"DEMO1234", "EXAMPLE1", "PASSPORT1", "DOCUMENT1",
	}

	upper := strings.ToUpper(match)
	for _, pattern := range testPatterns {
		if upper == pattern {
			return true
		}
	}

	// Check for obvious test patterns (all same digits, sequential, etc.)
	if len(match) >= 6 {
		// All same character
		allSame := true
		for i := 1; i < len(match); i++ {
			if match[i] != match[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}

		// Sequential numbers
		if regexp.MustCompile(`^[0-9]+$`).MatchString(match) {
			sequential := true
			for i := 1; i < len(match); i++ {
				if match[i] != match[i-1]+1 {
					sequential = false
					break
				}
			}
			if sequential {
				return true
			}
		}
	}

	return false
}
