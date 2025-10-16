// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"regexp"
	"strconv"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Validator implements the detector.Validator interface for detecting
// Social Security Numbers using regex patterns and contextual analysis.
type Validator struct {
	pattern string
	regex   *regexp.Regexp

	// Keywords that suggest an SSN context
	positiveKeywords []string

	// Keywords that suggest this is not an SSN
	negativeKeywords []string

	// Known invalid SSN patterns
	invalidPatterns []string

	// Enhanced domain-specific keywords for better context analysis
	hrKeywords         []string
	taxKeywords        []string
	healthcareKeywords []string

	// Global test patterns for enhanced false positive detection
	globalTestPatterns []string

	// Observability
	observer *observability.StandardObserver
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting Social Security Numbers.
func NewValidator() *Validator {
	v := &Validator{
		// SSN patterns: XXX-XX-XXXX, XXX XX XXXX, XXXXXXXXX only
		pattern: `\b(?:\d{3}-\d{2}-\d{4}|\d{3}\s\d{2}\s\d{4}|\d{9})\b`,
		positiveKeywords: []string{
			"ssn", "social security", "social security number", "social", "ein",
			"tax id", "taxpayer id", "identification number", "employee id",
			"federal id", "government id", "national id", "personal id",
			"identity", "benefits", "medicare", "medicaid", "irs", "w2", "w-2",
			"1099", "tax return", "tax form", "employment", "payroll",
			"hr", "human resources", "personnel", "employee record",
		},
		negativeKeywords: []string{
			"phone", "telephone", "fax", "zip", "postal", "area code",
			"extension", "ext", "routing", "account", "credit card", "card",
			"test", "example", "sample", "dummy", "fake", "mock", "demo",
			"template", "placeholder", "000-00-0000", "123-45-6789",
			"111-11-1111", "222-22-2222", "333-33-3333", "444-44-4444",
			"555-55-5555", "666-66-6666", "777-77-7777", "888-88-8888",
			"999-99-9999", "serial", "model", "version", "build",
			"encoded", "numeric", "code", "hash", "uuid", "guid",
		},
		invalidPatterns: []string{
			"000", "666", "900", "901", "902", "903", "904", "905", "906", "907", "908", "909",
		},
		hrKeywords: []string{
			"payroll", "hr", "human resources", "employee", "personnel", "staff",
			"employment", "hire", "onboarding", "benefits", "compensation",
			"employee record", "employee file", "personnel file", "hr system",
		},
		taxKeywords: []string{
			"tax", "w2", "w-2", "1099", "irs", "tax return", "tax form", "tax document",
			"tax filing", "tax preparation", "tax year", "tax id", "taxpayer",
			"federal tax", "state tax", "income tax", "tax liability",
		},
		healthcareKeywords: []string{
			"medical", "medicare", "medicaid", "insurance", "patient", "healthcare",
			"health record", "medical record", "patient record", "health plan",
			"medical insurance", "health insurance", "patient id", "medical id",
		},
		globalTestPatterns: []string{
			"test", "example", "sample", "demo", "placeholder", "mock", "fake",
			"tutorial", "documentation", "readme", "template", "default",
			"lorem ipsum", "john doe", "jane smith", "foo bar", "qwerty",
			"111111111", "222222222", "333333333", "444444444", "555555555",
			"777777777", "888888888", "999999999", "123456789", "987654321",
		},
	}

	// Compile the regex pattern once at initialization
	v.regex = regexp.MustCompile(v.pattern)

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
		finishTiming = v.observer.StartTiming("ssn_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("ssn_validator", "validate_file", filePath)
		}
	}

	// SSN validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "SSN validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for SSNs
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		foundMatches := v.regex.FindAllString(line, -1)

		// For preprocessed content, also look for SSN patterns in concatenated number sequences
		if len(foundMatches) == 0 && strings.Contains(originalPath, ".docx") {
			// This handles cases where text extraction concatenates SSNs with other data
			foundMatches = v.findSSNsInConcatenatedNumbers(line)
		}

		for _, match := range foundMatches {
			// Clean the SSN for validation
			cleanMatch := v.cleanSSN(match)

			// Validate the SSN format and content
			if !v.isValidSSN(cleanMatch) {
				continue
			}

			// Calculate confidence
			confidence, checks := v.CalculateConfidence(match)

			// Skip if this looks like encoded data or numeric sequences
			if v.isEncodedData(line, match) {
				continue
			}

			// For preprocessed content, create a simpler context info
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
			confidence += contextImpact

			// Store keywords found in context
			contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
			contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
			contextInfo.ConfidenceImpact = contextImpact

			// Check if this is tabular data first - this is more reliable than keyword detection
			isTabular := v.isTabularData(contextInfo.FullLine, match)

			// Adjust confidence based on context, prioritizing tabular data detection
			if isTabular {
				// For tabular data, don't cap confidence regardless of keywords
				// Only apply mild penalty for negative keywords
				if len(contextInfo.NegativeKeywords) > 0 {
					confidence -= 10 // Very mild penalty for negative context in tabular data
				}
				// Don't cap confidence for tabular data - let the base confidence stand
			} else if len(contextInfo.PositiveKeywords) == 0 {
				// For non-tabular data without positive keywords, be more restrictive
				if len(contextInfo.NegativeKeywords) > 0 {
					confidence -= 25 // Stronger penalty for negative context in non-tabular data
				} else if confidence > 50 {
					confidence = 50 // Cap at medium confidence without context for non-tabular data
				}
			}

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

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1, // 1-based line numbering
				Type:       "SSN",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "ssn",
				Context:    contextInfo,
				Metadata: map[string]any{
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}
	}

	return matches, nil
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Combine all context text for analysis
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var confidenceImpact float64 = 0

	// Enhanced domain-specific analysis
	domainBoost := v.validateSSNByDomain(match, fullContext)
	confidenceImpact += domainBoost

	// Check for positive keywords (increase confidence)
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact += 25 // +25% for keywords in the same line
			} else {
				confidenceImpact += 10 // +10% for keywords in surrounding context
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
				confidenceImpact -= 8 // -8% for negative keywords in surrounding context
			}
		}
	}

	// Enhanced tabular data detection
	if v.isEnhancedTabularData(context.FullLine, match) {
		confidenceImpact += 25 // Higher boost for enhanced tabular detection
	} else if v.isTabularData(context.FullLine, match) {
		confidenceImpact += 15 // Standard boost for basic tabular detection
	}

	// Check for global test patterns
	if v.isEnhancedTestPattern(match, fullContext) {
		confidenceImpact -= 40 // Strong penalty for test patterns
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 50 {
		confidenceImpact = 50 // Maximum +50% boost
	} else if confidenceImpact < -50 {
		confidenceImpact = -50 // Maximum -50% reduction
	}

	return confidenceImpact
}

// validateSSNByDomain provides domain-specific confidence boosts
func (v *Validator) validateSSNByDomain(ssn, context string) float64 {
	boost := 0.0

	// HR/Payroll context
	for _, keyword := range v.hrKeywords {
		if strings.Contains(context, keyword) {
			boost += 20
			break // Only apply once per domain
		}
	}

	// Tax document context
	for _, keyword := range v.taxKeywords {
		if strings.Contains(context, keyword) {
			boost += 25
			break // Only apply once per domain
		}
	}

	// Healthcare context
	for _, keyword := range v.healthcareKeywords {
		if strings.Contains(context, keyword) {
			boost += 18
			break // Only apply once per domain
		}
	}

	return boost
}

// isEnhancedTabularData provides enhanced detection of tabular data structures
func (v *Validator) isEnhancedTabularData(line, value string) bool {
	// Count structured elements in the line
	structuredCount := 0

	// Email patterns
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	structuredCount += len(emailPattern.FindAllString(line, -1))

	// Phone patterns
	phonePattern := regexp.MustCompile(`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	structuredCount += len(phonePattern.FindAllString(line, -1))

	// Date patterns
	datePattern := regexp.MustCompile(`\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}`)
	structuredCount += len(datePattern.FindAllString(line, -1))

	// SSN patterns
	ssnPattern := regexp.MustCompile(`\d{3}[-\s]?\d{2}[-\s]?\d{4}`)
	structuredCount += len(ssnPattern.FindAllString(line, -1))

	// Name patterns (Title Case words)
	namePattern := regexp.MustCompile(`\b[A-Z][a-z]+\s+[A-Z][a-z]+\b`)
	structuredCount += len(namePattern.FindAllString(line, -1))

	// If we have 3+ structured elements, it's likely tabular
	if structuredCount >= 3 {
		return true
	}

	// Check for common delimiters
	tabCount := strings.Count(line, "\t")
	commaCount := strings.Count(line, ",")
	pipeCount := strings.Count(line, "|")

	if tabCount >= 2 || commaCount >= 3 || pipeCount >= 2 {
		return true
	}

	// Check for multiple consecutive spaces (fixed-width tables)
	multiSpacePattern := regexp.MustCompile(`\s{3,}`)
	if len(multiSpacePattern.FindAllString(line, -1)) >= 2 {
		return true
	}

	return false
}

// isEnhancedTestPattern checks for enhanced test patterns
func (v *Validator) isEnhancedTestPattern(value, context string) bool {
	lowerValue := strings.ToLower(value)
	lowerContext := strings.ToLower(context)

	// Check global test patterns
	for _, pattern := range v.globalTestPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerContext, pattern) {
			return true
		}
	}

	// Check for obvious test sequences
	cleanValue := v.cleanSSN(value)
	if v.isObviousTestSequence(cleanValue) {
		return true
	}

	return false
}

// isObviousTestSequence checks for obvious test number sequences
func (v *Validator) isObviousTestSequence(value string) bool {
	if len(value) != 9 {
		return false
	}

	// Check for repeating digits (e.g., 111111111)
	for i := 0; i < len(value)-3; i++ {
		if value[i] == value[i+1] && value[i] == value[i+2] && value[i] == value[i+3] {
			return true
		}
	}

	// Check for ascending/descending sequences
	if len(value) >= 6 {
		ascending := true
		descending := true

		for i := 0; i < len(value)-1; i++ {
			curr := int(value[i] - '0')
			next := int(value[i+1] - '0')

			if next != (curr+1)%10 {
				ascending = false
			}
			if next != (curr+9)%10 {
				descending = false
			}
		}

		if ascending || descending {
			return true
		}
	}

	return false
}

// findKeywords returns a list of keywords found in the context
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	// Only check the current line to avoid cross-line contamination
	fullContext := strings.ToLower(context.FullLine)

	var found []string
	for _, keyword := range keywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			found = append(found, keyword)
		}
	}

	return found
}

// CalculateConfidence calculates the confidence score for a potential SSN
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":             true,
		"digits":             true,
		"valid_area":         false,
		"not_test_number":    true,
		"not_sequential":     true,
		"not_repeating":      true,
		"not_common_pattern": true,
	}

	cleanMatch := v.cleanSSN(match)
	confidence := 70.0 // Start with higher base confidence for properly formatted SSNs

	// Check format (already validated in isValidSSN)
	if len(cleanMatch) != 9 {
		confidence -= 20
		checks["format"] = false
	}

	// Check if all digits
	if !regexp.MustCompile(`^\d+$`).MatchString(cleanMatch) {
		confidence -= 20
		checks["digits"] = false
		return confidence, checks
	}

	// Check area number (first 3 digits)
	if len(cleanMatch) >= 3 {
		area := cleanMatch[0:3]
		if v.isValidAreaNumber(area) {
			checks["valid_area"] = true
			confidence += 15 // Increased boost for valid area numbers
		} else {
			confidence -= 15
		}
	}

	// Boost confidence for properly formatted SSNs (XXX-XX-XXXX pattern)
	if strings.Contains(match, "-") && len(strings.Split(match, "-")) == 3 {
		parts := strings.Split(match, "-")
		if len(parts[0]) == 3 && len(parts[1]) == 2 && len(parts[2]) == 4 {
			confidence += 10 // Boost for proper formatting
		}
	}

	// Check for test numbers
	if v.isTestSSN(cleanMatch) {
		confidence -= 25
		checks["not_test_number"] = false
	}

	// Check for sequential numbers
	if v.isSequential(cleanMatch) {
		confidence -= 15
		checks["not_sequential"] = false
	}

	// Check for repeating patterns
	if v.hasRepeatingPatterns(cleanMatch) {
		confidence -= 15
		checks["not_repeating"] = false
	}

	// Check for common invalid patterns
	if v.matchesCommonPattern(cleanMatch) {
		confidence -= 20
		checks["not_common_pattern"] = false
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// Helper methods
func (v *Validator) cleanSSN(ssn string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ssn, "-", ""), " ", "")
}

func (v *Validator) isValidSSN(ssn string) bool {
	if len(ssn) != 9 {
		return false
	}

	// Check for all zeros
	if ssn == "000000000" {
		return false
	}

	// Check area number (first 3 digits)
	area := ssn[0:3]
	if area == "000" || area == "666" {
		return false
	}

	// Check for 900-999 area numbers (invalid)
	if areaNum, err := strconv.Atoi(area); err == nil {
		if areaNum >= 900 {
			return false
		}
	}

	// Check group number (middle 2 digits)
	group := ssn[3:5]
	if group == "00" {
		return false
	}

	// Check serial number (last 4 digits)
	serial := ssn[5:9]
	if serial == "0000" {
		return false
	}

	return true
}

func (v *Validator) isValidAreaNumber(area string) bool {
	areaNum, err := strconv.Atoi(area)
	if err != nil {
		return false
	}

	// Valid area numbers are 001-665, 667-899
	return (areaNum >= 1 && areaNum <= 665) || (areaNum >= 667 && areaNum <= 899)
}

func (v *Validator) isTestSSN(ssn string) bool {
	testSSNs := map[string]bool{
		"123456789": true,
		"111111111": true,
		"222222222": true,
		"333333333": true,
		"444444444": true,
		"555555555": true,
		"777777777": true,
		"888888888": true,
		"999999999": true,
		"987654321": true,
		"123454321": true,
	}
	return testSSNs[ssn]
}

func (v *Validator) isSequential(ssn string) bool {
	// Check for ascending sequence
	ascending := true
	for i := 0; i < len(ssn)-1; i++ {
		curr, _ := strconv.Atoi(string(ssn[i]))
		next, _ := strconv.Atoi(string(ssn[i+1]))
		if next != (curr+1)%10 {
			ascending = false
			break
		}
	}

	// Check for descending sequence
	descending := true
	for i := 0; i < len(ssn)-1; i++ {
		curr, _ := strconv.Atoi(string(ssn[i]))
		next, _ := strconv.Atoi(string(ssn[i+1]))
		if next != (curr+9)%10 {
			descending = false
			break
		}
	}

	return ascending || descending
}

func (v *Validator) hasRepeatingPatterns(ssn string) bool {
	// Check for 3+ consecutive identical digits
	for i := 0; i < len(ssn)-2; i++ {
		if ssn[i] == ssn[i+1] && ssn[i] == ssn[i+2] {
			return true
		}
	}

	// Check for repeating blocks
	if len(ssn) == 9 {
		// Check for XXX-XX-XXXX where all parts are the same
		area := ssn[0:3]
		group := ssn[3:5]
		serial := ssn[5:9]

		if area == group+group[0:1] || area == serial[0:3] {
			return true
		}
	}

	return false
}

func (v *Validator) matchesCommonPattern(ssn string) bool {
	// Check for patterns like 123-45-6789
	if ssn == "123456789" {
		return true
	}

	// Check for all same digits
	firstDigit := ssn[0]
	allSame := true
	for i := 1; i < len(ssn); i++ {
		if ssn[i] != firstDigit {
			allSame = false
			break
		}
	}

	return allSame
}

// isEncodedData checks if the match appears to be part of encoded data or numeric sequences
func (v *Validator) isEncodedData(line, match string) bool {
	// First check if this looks like tabular data - if so, don't reject it
	if v.isTabularData(line, match) {
		return false
	}

	// Count total numbers in the line
	numberPattern := regexp.MustCompile(`\d+`)
	numbers := numberPattern.FindAllString(line, -1)

	// For non-tabular data, if line has many numbers (>15), it's likely encoded data
	if len(numbers) > 15 {
		// But check if the numbers are structured (like SSNs, credit cards, phone numbers)
		structuredNumbers := 0

		// Count SSN patterns
		ssnPattern := regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
		structuredNumbers += len(ssnPattern.FindAllString(line, -1))

		// Count credit card patterns
		ccPattern := regexp.MustCompile(`\d{4}-\d{4}-\d{4}-\d{4}`)
		structuredNumbers += len(ccPattern.FindAllString(line, -1))

		// Count phone patterns
		phonePattern := regexp.MustCompile(`\d{3}-\d{3}-\d{4}`)
		structuredNumbers += len(phonePattern.FindAllString(line, -1))

		// If we have structured numbers, it's likely legitimate data
		if structuredNumbers >= 2 {
			return false
		}

		return true
	}

	// Check if the line contains mostly numbers and spaces (but not tabs - tabs suggest tabular data)
	numericChars := 0
	spaceChars := 0
	tabChars := 0
	totalChars := len(line)

	for _, char := range line {
		if char >= '0' && char <= '9' {
			numericChars++
		} else if char == ' ' {
			spaceChars++
		} else if char == '\t' {
			tabChars++
		}
	}

	// If line has tabs, it's likely tabular data, so don't reject
	if tabChars > 0 {
		return false
	}

	// If more than 85% of the line is numbers and spaces (and no tabs), it's likely encoded
	if totalChars > 0 && float64(numericChars+spaceChars)/float64(totalChars) > 0.85 {
		return true
	}

	return false
}

// isTabularData checks if the SSN appears to be in a tabular format
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
	multiSpaceMatches := multiSpacePattern.FindAllString(line, -1)
	if len(multiSpaceMatches) >= 2 {
		return true
	}

	// Check for common tabular patterns (names followed by SSNs)
	namePattern := regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+\d{3}-\d{2}-\d{4}`)
	if namePattern.MatchString(line) {
		return true
	}

	// Check for CSV-style patterns (comma-separated values with quotes)
	csvPattern := regexp.MustCompile(`"[^"]*",\s*"[^"]*"`)
	if csvPattern.MatchString(line) {
		return true
	}

	// Check if line contains multiple structured data elements
	structuredElements := 0

	// Count SSN-like patterns
	ssnPattern := regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
	structuredElements += len(ssnPattern.FindAllString(line, -1))

	// Count credit card-like patterns
	ccPattern := regexp.MustCompile(`\d{4}-\d{4}-\d{4}-\d{4}`)
	structuredElements += len(ccPattern.FindAllString(line, -1))

	// Count phone-like patterns
	phonePattern := regexp.MustCompile(`\d{3}-\d{3}-\d{4}`)
	structuredElements += len(phonePattern.FindAllString(line, -1))

	// Count email-like patterns
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	structuredElements += len(emailPattern.FindAllString(line, -1))

	// Count date-like patterns (MM/DD/YYYY, YYYY-MM-DD, etc.)
	datePattern := regexp.MustCompile(`\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}`)
	structuredElements += len(datePattern.FindAllString(line, -1))

	// If multiple structured elements, likely tabular data
	return structuredElements >= 2
}

// findSSNsInConcatenatedNumbers looks for SSN patterns in concatenated number sequences
// This is specifically for preprocessed content where text extraction may concatenate numbers
func (v *Validator) findSSNsInConcatenatedNumbers(line string) []string {
	var matches []string

	// Look for sequences of exactly 18 digits (two 9-digit numbers concatenated)
	// This is much more restrictive than looking for any 9+ digit sequence
	digitSequences := regexp.MustCompile(`\b\d{18}\b`).FindAllString(line, -1)

	for _, seq := range digitSequences {
		// Split into two 9-digit candidates
		candidate1 := seq[0:9]
		candidate2 := seq[9:18]

		// Only accept if both halves could be valid SSNs
		if v.couldBeSSN(candidate1) && v.couldBeSSN(candidate2) {
			matches = append(matches, candidate1, candidate2)
		}
	}

	return matches
}

// couldBeSSN performs basic checks to see if a 9-digit string could be an SSN
func (v *Validator) couldBeSSN(candidate string) bool {
	if len(candidate) != 9 {
		return false
	}

	// Check area number (first 3 digits)
	area := candidate[0:3]
	if area == "000" || area == "666" {
		return false
	}

	// Check for 900-999 area numbers (invalid)
	if areaNum, err := strconv.Atoi(area); err == nil {
		if areaNum >= 900 {
			return false
		}
	}

	// Check group number (middle 2 digits)
	group := candidate[3:5]
	if group == "00" {
		return false
	}

	// Check serial number (last 4 digits)
	serial := candidate[5:9]
	if serial == "0000" {
		return false
	}

	return true
}
