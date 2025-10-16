// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"regexp"
	"slices"
	"strings"
	"sync"

	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Package-level variables for business suffixes and technical phrases to avoid repeated allocations
var (
	businessSuffixes = []string{"inc", "llc", "ltd", "corp", "corporation", "company", "enterprises", "industries"}
	technicalPhrases = []string{
		// Form field labels and similar patterns
		"first name", "last name", "full name", "user name", "customer name", "contact name",
		"credit card", "card number", "account number", "phone number", "social security",
		"date of birth", "birth date", "email address", "mailing address", "billing address",
		"zip code", "postal code", "state province", "country region",
		"number first", "number last", "card first", "card last", "security number",
	}
)

// Validator implements the detector.Validator interface for detecting
// person names using pattern matching combined with name database lookups.
type Validator struct {
	// Pattern manager for name detection
	patternManager *PatternManager

	// Name databases (loaded once, O(1) lookup)
	firstNames map[string]bool // ~5K entries
	lastNames  map[string]bool // ~2K entries

	// Context analysis keywords
	positiveKeywords []string
	negativeKeywords []string

	// Performance monitoring
	observer *observability.StandardObserver

	// Thread safety for lazy loading
	once sync.Once
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting person names.
func NewValidator() *Validator {
	v := &Validator{
		patternManager: NewPatternManager(),
		positiveKeywords: []string{
			"name", "employee", "customer", "contact", "person", "patient",
			"client", "user", "member", "staff", "author", "owner", "student",
			"teacher", "doctor", "nurse", "manager", "director", "supervisor",
			"resident", "participant", "attendee", "speaker", "presenter",
			"candidate", "applicant", "volunteer", "witness", "signatory",
			"developer", "analyst", "consultant", "engineer", "designer",
			"coordinator", "specialist", "administrator", "assistant",
		},
		negativeKeywords: []string{
			"company", "organization", "business", "product", "service",
			"brand", "system", "application", "software", "corporation",
			"enterprise", "platform", "solution", "technology", "framework",
			"vendor", "supplier", "manufacturer", "publisher",
			"agency", "firm", "studio", "lab", "laboratory", "institute",
			"inc", "llc", "ltd", "corp", "enterprises", "industries", "manufacturing",
			"consulting", "group", "associates", "partners", "holdings",
			"catalog", "collection", "series", "line", "model", "version",
			"city", "county", "state", "country", "mountain", "lake", "river",
			"creek", "valley", "park", "street", "avenue", "road", "drive",
			"algorithm", "method", "protocol", "function", "pattern", "transform",
		},
		observer: observability.NewStandardObserver(observability.ObservabilityMetrics, nil),
	}

	return v
}

// Validate implements the detector.Validator interface for direct file processing
// Returns empty results as this validator only works with preprocessed content
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	// Log operation for observability
	v.observer.LogOperation(observability.StandardObservabilityData{
		Component: "personname",
		Operation: "validate_file",
		FilePath:  filePath,
		Success:   true,
		Metadata: map[string]interface{}{
			"message": "Direct file validation not supported, use preprocessed content",
		},
	})
	return []detector.Match{}, nil
}

// ValidateContent implements the detector.Validator interface for preprocessed content
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Ensure name databases are loaded
	v.ensureNamesLoaded()

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		lineMatches := v.findNamesInLine(line, lineNum+1, originalPath)
		matches = append(matches, lineMatches...)
	}

	// Deduplicate overlapping matches (prefer longer, more specific matches)
	matches = v.deduplicateMatches(matches)

	return matches, nil
}

// ValidateWithContext implements the EnhancedValidator interface for context-aware validation
func (v *Validator) ValidateWithContext(content string, filePath string, contextInsights context.ContextInsights) ([]detector.Match, error) {
	var matches []detector.Match

	// Ensure name databases are loaded
	v.ensureNamesLoaded()

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		lineMatches := v.findNamesInLineWithContext(line, lineNum+1, filePath, contextInsights)
		matches = append(matches, lineMatches...)
	}

	// Deduplicate overlapping matches (prefer longer, more specific matches)
	matches = v.deduplicateMatches(matches)

	return matches, nil
}

// SetLanguage implements the EnhancedValidator interface for multi-language support
func (v *Validator) SetLanguage(lang string) error {
	// Person name detection is primarily pattern-based and works across languages
	// Future enhancement could load language-specific name databases
	return nil
}

// GetSupportedLanguages implements the EnhancedValidator interface
func (v *Validator) GetSupportedLanguages() []string {
	// Currently supports Western name patterns, can be extended for other languages
	return []string{"en", "es", "fr", "de", "it"}
}

// findNamesInLine finds person names in a single line of text
func (v *Validator) findNamesInLine(line string, lineNum int, filePath string) []detector.Match {
	var matches []detector.Match

	// Use pattern manager to find matches
	patternMatches := v.patternManager.FindMatches(line)

	for _, patternMatch := range patternMatches {
		nameText := patternMatch.Text
		nameComponents := ParseNameComponents(nameText, patternMatch.Pattern)

		confidence, validationChecks := v.CalculateConfidenceWithComponents(nameText, nameComponents)

		// Apply basic context analysis
		contextInfo := detector.ContextInfo{
			FullLine: line,
		}
		contextImpact := v.AnalyzeContext(nameText, contextInfo)
		confidence += contextImpact

		// Ensure final confidence is within bounds
		if confidence > 100.0 {
			confidence = 100.0
		}
		if confidence < 0.0 {
			confidence = 0.0
		}

		// Only include matches with reasonable confidence
		if confidence >= 50.0 {
			detectorMatch := detector.Match{
				Text:       nameText,
				Confidence: confidence,
				LineNumber: lineNum,
				Filename:   filePath,
				Validator:  "PERSON_NAME",
				Type:       "PERSON_NAME",
				Metadata: map[string]interface{}{
					"pattern":           patternMatch.Pattern.Name,
					"pattern_priority":  patternMatch.Pattern.Priority,
					"cultural_context":  patternMatch.Pattern.Cultural,
					"validation_checks": validationChecks,
					"context_keywords":  v.analyzeContext(line),
					"context_impact":    contextImpact,
					"name_components":   nameComponents,
				},
			}
			matches = append(matches, detectorMatch)
		}
	}

	return matches
}

// findNamesInLineWithContext finds person names with enhanced context analysis
func (v *Validator) findNamesInLineWithContext(line string, lineNum int, filePath string, contextInsights context.ContextInsights) []detector.Match {
	var matches []detector.Match

	// Use pattern manager to find matches
	patternMatches := v.patternManager.FindMatches(line)

	for _, patternMatch := range patternMatches {
		nameText := patternMatch.Text
		nameComponents := ParseNameComponents(nameText, patternMatch.Pattern)

		confidence, validationChecks := v.CalculateConfidenceWithComponents(nameText, nameComponents)

		// Apply basic context analysis
		contextInfo := detector.ContextInfo{
			FullLine: line,
		}
		contextImpact := v.AnalyzeContext(nameText, contextInfo)
		confidence += contextImpact

		// Apply enhanced context insights
		enhancedImpact := v.applyContextInsights(nameText, contextInsights)
		confidence += enhancedImpact

		// Apply cross-validator signals
		crossValidatorImpact := v.applyCrossValidatorSignals(nameText, contextInsights.CrossValidatorSignals)
		confidence += crossValidatorImpact

		// Ensure confidence bounds
		if confidence > 100 {
			confidence = 100
		}
		if confidence < 0 {
			confidence = 0
		}

		// Only include matches with reasonable confidence
		if confidence >= 50.0 {
			detectorMatch := detector.Match{
				Text:       nameText,
				Confidence: confidence,
				LineNumber: lineNum,
				Filename:   filePath,
				Validator:  "PERSON_NAME",
				Type:       "PERSON_NAME",
				Metadata: map[string]interface{}{
					"pattern":                 patternMatch.Pattern.Name,
					"pattern_priority":        patternMatch.Pattern.Priority,
					"cultural_context":        patternMatch.Pattern.Cultural,
					"validation_checks":       validationChecks,
					"context_keywords":        v.analyzeContext(line),
					"context_impact":          contextImpact,
					"enhanced_context_impact": enhancedImpact,
					"cross_validator_impact":  crossValidatorImpact,
					"document_type":           contextInsights.DocumentType,
					"domain":                  contextInsights.Domain,
					"name_components":         nameComponents,
				},
			}
			matches = append(matches, detectorMatch)
		}
	}

	return matches
}

// CalculateConfidence calculates confidence score for a detected name (legacy method)
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Ensure name databases are loaded
	v.ensureNamesLoaded()

	// Parse name components using basic parsing
	parts := v.parseNameParts(match)

	// Convert to NameComponents for consistency
	components := NameComponents{
		FullName:  match,
		FirstName: parts.FirstName,
		LastName:  parts.LastName,
		Pattern:   "legacy_parsing",
	}

	return v.CalculateConfidenceWithComponents(match, components)
}

// CalculateConfidenceWithComponents calculates confidence score using parsed name components
func (v *Validator) CalculateConfidenceWithComponents(match string, components NameComponents) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_pattern":      true,
		"known_first_name":   false,
		"known_last_name":    false,
		"proper_case":        true,
		"reasonable_length":  true,
		"not_test_data":      true,
		"not_business_name":  true,
		"not_technical_term": true,
		"has_title":          len(components.Title) > 0,
		"has_suffix":         len(components.Suffix) > 0,
		"has_middle_name":    len(components.MiddleName) > 0,
	}

	// EFFICIENCY FIRST: Check database matches before any expensive operations
	// This is the authoritative source - no matches = early exit
	if v.firstNames != nil && len(components.FirstName) > 0 {
		// Try both the original name and normalized version (without accents)
		firstName := strings.ToLower(components.FirstName)
		normalizedFirstName := v.normalizeAccents(firstName)

		if v.firstNames[firstName] || v.firstNames[normalizedFirstName] {
			checks["known_first_name"] = true
		}
	}

	if v.lastNames != nil && len(components.LastName) > 0 {
		// Try both the original name and normalized version (without accents)
		lastName := strings.ToLower(components.LastName)
		normalizedLastName := v.normalizeAccents(lastName)

		if v.lastNames[lastName] || v.lastNames[normalizedLastName] {
			checks["known_last_name"] = true
		}
	}

	// EARLY EXIT: If no database matches, reject immediately
	if !checks["known_first_name"] && !checks["known_last_name"] {
		// Database is authoritative source - no matches = no person name
		checks["has_known_name_component"] = false
		checks["both_names_known"] = false
		return 0.0, checks // Early exit - avoid all expensive calculations
	}

	// Only proceed with expensive calculations if we have database matches
	baseConfidence := 55.0
	checks["has_known_name_component"] = true

	// Apply pattern-specific confidence adjustments
	baseConfidence += v.getPatternConfidenceBoost(components.Pattern)

	// Apply database match bonuses
	if checks["known_first_name"] {
		baseConfidence += 12.5
	}
	if checks["known_last_name"] {
		baseConfidence += 12.5
	}

	// SENSITIVE DATA FOCUSED: Determine confidence based on database matches
	// At this point we know we have at least one database match
	if checks["known_first_name"] && checks["known_last_name"] {
		// Both names in database - but check for technical context first
		checks["has_known_name_component"] = true
		checks["both_names_known"] = true

		if v.isTechnicalContext(match, components) {
			// Technical context: reduce to MEDIUM confidence even with both names
			baseConfidence = 65.0
		} else {
			// True person name: HIGH confidence for sensitive data detection
			baseConfidence = 90.0

			// Additional boost for formal patterns that indicate complete person names
			if v.isFormalNamePattern(components.Pattern) {
				baseConfidence += 5.0 // Up to 95-100% for formal patterns
			}
		}
	} else {
		// Only one name in database - MEDIUM confidence
		baseConfidence = 65.0 // Start at MEDIUM confidence threshold
		checks["has_known_name_component"] = true
		checks["both_names_known"] = false

		// Apply technical context penalty to reduce false positives to LOW
		if v.isTechnicalContext(match, components) {
			baseConfidence -= 20.0 // Reduce to ~45% (LOW confidence)
		}
	}

	// Apply validation checks (we know we have database matches at this point)
	baseConfidence += v.applyValidationChecks(match, checks)

	// Apply technical term filtering
	if v.isTechnicalTerm(match) {
		// Technical terms should be completely rejected regardless of database matches
		baseConfidence = 0.0 // Zero out confidence for technical terms
		checks["not_technical_term"] = false
		checks["not_business_name"] = false // Business names are technical terms
	} else {
		checks["not_technical_term"] = true
		checks["not_business_name"] = true
	}

	// Apply component-specific adjustments (we know we have database matches at this point)
	baseConfidence += v.applyComponentAdjustments(components, checks)

	// Ensure confidence is within bounds
	if baseConfidence > 100 {
		baseConfidence = 100
	}
	if baseConfidence < 0 {
		baseConfidence = 0
	}

	return baseConfidence, checks
}

// getPatternConfidenceBoost returns confidence boost based on pattern type
func (v *Validator) getPatternConfidenceBoost(patternName string) float64 {
	switch patternName {
	case "name_with_title", "name_with_multiple_titles":
		return 10.0 // Titles indicate formal names
	case "name_with_suffix":
		return 8.0 // Suffixes are strong indicators
	case "name_with_middle_initial":
		return 5.0 // Middle initials are common in formal contexts
	case "hyphenated_last_name", "name_with_apostrophe":
		return 3.0 // Cultural variations are valid but less common
	default:
		return 0.0
	}
}

// applyComponentAdjustments applies adjustments based on name components
func (v *Validator) applyComponentAdjustments(components NameComponents, checks map[string]bool) float64 {
	adjustment := 0.0

	// Boost for titles
	if len(components.Title) > 0 {
		adjustment += 5.0
		checks["has_title"] = true
	}

	// Boost for suffixes
	if len(components.Suffix) > 0 {
		adjustment += 3.0
		checks["has_suffix"] = true
	}

	// Boost for middle names/initials
	if len(components.MiddleName) > 0 {
		adjustment += 2.0
		checks["has_middle_name"] = true
	}

	// Cultural context adjustments
	for _, cultural := range components.Cultural {
		switch cultural {
		case "formal", "academic":
			adjustment += 2.0
		case "western", "english":
			adjustment += 1.0
		}
	}

	return adjustment
}

// NameParts represents the components of a parsed name (legacy structure)
type NameParts struct {
	FirstName  string
	LastName   string
	MiddleName string
	Title      string
	Suffix     string
}

// parseNameParts parses a name string into its components (legacy method)
func (v *Validator) parseNameParts(name string) NameParts {
	parts := NameParts{}
	tokens := strings.Fields(name)

	if len(tokens) == 0 {
		return parts
	}

	// Handle titles
	if len(tokens) > 0 && v.isTitle(tokens[0]) {
		parts.Title = tokens[0]
		tokens = tokens[1:]
	}

	// Handle suffixes
	if len(tokens) > 0 && v.isSuffix(tokens[len(tokens)-1]) {
		parts.Suffix = tokens[len(tokens)-1]
		tokens = tokens[:len(tokens)-1]
	}

	// Parse remaining tokens
	if len(tokens) >= 2 {
		parts.FirstName = tokens[0]
		parts.LastName = tokens[len(tokens)-1]
		if len(tokens) > 2 {
			parts.MiddleName = strings.Join(tokens[1:len(tokens)-1], " ")
		}
	} else if len(tokens) == 1 {
		parts.FirstName = tokens[0]
	}

	return parts
}

// isTitle checks if a token is a title
func (v *Validator) isTitle(token string) bool {
	titles := []string{"Mr.", "Ms.", "Mrs.", "Dr.", "Prof."}
	return slices.Contains(titles, token)
}

// isSuffix checks if a token is a suffix
func (v *Validator) isSuffix(token string) bool {
	suffixes := []string{"Jr.", "Sr.", "III", "IV", "Jr", "Sr"}
	return slices.Contains(suffixes, token)
}

// applyValidationChecks applies various validation checks and adjusts confidence
func (v *Validator) applyValidationChecks(match string, checks map[string]bool) float64 {
	adjustment := 0.0

	// Only check for obvious test data patterns - database validation handles most false positives
	testPatterns := []string{
		"john doe", "jane doe", "foo bar", "test user", "sample name",
		"example name", "lorem ipsum", "first last", "firstname lastname",
		"your name", "user name", "full name",
	}

	lowerMatch := strings.ToLower(match)
	for _, pattern := range testPatterns {
		if strings.Contains(lowerMatch, pattern) {
			adjustment -= 50 // Strong penalty for obvious test data
			checks["not_test_data"] = false
			break
		}
	}

	// Check proper capitalization
	if !v.isProperlyCapitalized(match) {
		adjustment -= 15
		checks["proper_case"] = false
	}

	// Check reasonable length (names should be between 4-60 characters)
	if len(match) < 4 {
		// Cross-reference short names against known name databases
		if v.isKnownShortName(match) {
			adjustment -= 5 // Light penalty for known short names
		} else {
			adjustment -= 20 // Stronger penalty for unknown short names
		}
		checks["reasonable_length"] = false
	} else if len(match) > 60 {
		adjustment -= 15
		checks["reasonable_length"] = false
	}

	// Check for suspicious patterns
	if v.hasSuspiciousPatterns(match) {
		adjustment -= 10
	}

	// Check for repeated characters (like "aaaa bbbb")
	if v.hasRepeatedCharacters(match) {
		adjustment -= 20
	}

	return adjustment
}

// hasSuspiciousPatterns checks for patterns that are unlikely in real names
func (v *Validator) hasSuspiciousPatterns(name string) bool {
	suspiciousPatterns := []string{
		"123", "456", "789", "000", "111", "222", "333", "444", "555",
		"666", "777", "888", "999", "abc", "xyz", "qwerty", "asdf",
	}

	lowerName := strings.ToLower(name)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}
	return false
}

// hasRepeatedCharacters checks for suspicious repeated character patterns
func (v *Validator) hasRepeatedCharacters(name string) bool {
	words := strings.Fields(name)
	for _, word := range words {
		if len(word) >= 3 {
			// Check for 3+ consecutive identical characters
			for i := 0; i < len(word)-2; i++ {
				if word[i] == word[i+1] && word[i+1] == word[i+2] {
					return true
				}
			}
		}
	}
	return false
}

// isProperlyCapitalized checks if the name has proper capitalization
func (v *Validator) isProperlyCapitalized(name string) bool {
	words := strings.Fields(name)
	for _, word := range words {
		if len(word) > 0 && !strings.Contains("Mr.Ms.Mrs.Dr.Prof.Jr.Sr.III.IV.", word) {
			if word[0] < 'A' || word[0] > 'Z' {
				return false
			}
		}
	}
	return true
}

// isVeryCommonName checks if a name is extremely common and might cause false positives
func (v *Validator) isVeryCommonName(name string) bool {
	if name == "" {
		return false
	}

	lowerName := strings.ToLower(name)
	return veryCommonNamesMap[lowerName]
}

// isKnownShortName checks if a short name (< 4 chars) is in the known name databases
func (v *Validator) isKnownShortName(name string) bool {
	if name == "" || len(name) >= 4 {
		return false
	}

	lowerName := strings.ToLower(name)
	normalizedName := v.normalizeAccents(lowerName)

	// Check both first and last name databases
	if v.firstNames != nil && (v.firstNames[lowerName] || v.firstNames[normalizedName]) {
		return true
	}
	if v.lastNames != nil && (v.lastNames[lowerName] || v.lastNames[normalizedName]) {
		return true
	}

	return false
}

// isFormalNamePattern checks if the pattern indicates a formal/complete person name
func (v *Validator) isFormalNamePattern(patternName string) bool {
	formalPatterns := []string{
		"name_with_title",
		"name_with_multiple_titles",
		"name_with_suffix",
		"name_with_professional_suffix",
		"last_comma_first",
		"last_comma_first_middle",
		"last_comma_first_initial",
	}

	for _, formal := range formalPatterns {
		if patternName == formal {
			return true
		}
	}
	return false
}

// isTechnicalContext checks if the name appears in a technical context
func (v *Validator) isTechnicalContext(match string, components NameComponents) bool {
	// Check if first name is a technical term
	technicalFirstNames := []string{
		"user", "admin", "system", "manual", "auto", "automatic", "primary",
		"secondary", "backup", "test", "production", "staging", "development",
		"local", "remote", "public", "private", "internal", "external",
		"global", "regional", "cross", "multi", "single", "dual", "max", "min",
		"bulk", "batch", "creating", "building", "configuring", "setting",
		"managing", "monitoring", "processing", "handling", "validating",
	}

	firstName := strings.ToLower(components.FirstName)
	for _, tech := range technicalFirstNames {
		if firstName == tech {
			return true
		}
	}

	// Check if last name is a technical term (but still a valid surname)
	technicalLastNames := []string{
		"pool", "gateway", "service", "manager", "handler", "processor",
		"validator", "monitor", "controller", "executor", "scheduler",
		"builder", "factory", "registry", "repository", "store", "cache",
		"user", "admin", "system", "execution", "deployment", "configuration",
	}

	lastName := strings.ToLower(components.LastName)
	for _, tech := range technicalLastNames {
		if lastName == tech {
			return true
		}
	}

	return false
}

// isTechnicalTerm checks if the matched text is likely a technical term rather than a person name
func (v *Validator) isTechnicalTerm(match string) bool {
	lowerMatch := strings.ToLower(match)

	// Check for exact matches of technical terms (O(1) lookup)
	if technicalTermsMap[lowerMatch] {
		return true
	}

	// Check for business suffixes (company names) using package-level variable
	for _, suffix := range businessSuffixes {
		if strings.HasSuffix(lowerMatch, " "+suffix) || strings.HasSuffix(lowerMatch, suffix) {
			return true
		}
	}

	// Check for technical phrase patterns using package-level variable
	for _, phrase := range technicalPhrases {
		if strings.Contains(lowerMatch, phrase) {
			return true
		}
	}

	// Check for technical patterns in two-word combinations
	words := strings.Fields(lowerMatch)
	if len(words) == 2 {
		firstWord := words[0]
		secondWord := words[1]

		// O(1) lookups for technical adjective + noun combinations
		if technicalAdjectivesMap[firstWord] && technicalNounsMap[secondWord] {
			return true
		}
	}

	return false
}

// AnalyzeContext implements the detector.Validator interface for contextual analysis
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	adjustment := 0.0

	// Analyze the context line for keywords
	if context.FullLine != "" {
		lowerLine := strings.ToLower(context.FullLine)

		// Count positive and negative keyword matches
		positiveMatches := 0
		negativeMatches := 0

		// Check for positive keywords (boost confidence)
		for _, keyword := range v.positiveKeywords {
			if strings.Contains(lowerLine, keyword) {
				positiveMatches++
			}
		}

		// Check for negative keywords (reduce confidence)
		// Name database validation handles most false positives, so keep this simple
		for _, keyword := range v.negativeKeywords {
			if strings.Contains(lowerLine, keyword) {
				negativeMatches++
			}
		}

		// Apply adjustments based on keyword matches
		if positiveMatches > 0 {
			// Boost confidence, with diminishing returns for multiple matches
			adjustment += float64(positiveMatches) * 12.0
			if positiveMatches > 2 {
				adjustment = 25.0 // Cap at +25% for multiple positive keywords
			}
		}

		if negativeMatches > 0 {
			// Only apply business context penalty if the negative keywords are close to the name
			// This prevents penalizing names in employee directories or business contexts
			closeNegativeMatches := 0

			for _, keyword := range v.negativeKeywords {
				if strings.Contains(lowerLine, keyword) {
					// Skip keywords that appear in email addresses or URLs
					keywordIndex := strings.Index(lowerLine, keyword)
					if keywordIndex >= 0 {
						// Check if keyword is part of an email address (has @ nearby)
						beforeKeyword := ""
						afterKeyword := ""
						if keywordIndex > 10 {
							beforeKeyword = lowerLine[keywordIndex-10 : keywordIndex]
						}
						if keywordIndex+len(keyword)+10 < len(lowerLine) {
							afterKeyword = lowerLine[keywordIndex+len(keyword) : keywordIndex+len(keyword)+10]
						}

						// Skip if keyword is in email address or URL
						if strings.Contains(beforeKeyword, "@") || strings.Contains(afterKeyword, "@") ||
							strings.Contains(beforeKeyword, "http") || strings.Contains(afterKeyword, ".com") {
							continue
						}
					}

					// Check if the keyword is within close proximity to the name
					nameIndex := strings.Index(lowerLine, strings.ToLower(match))

					if keywordIndex >= 0 && nameIndex >= 0 {
						distance := keywordIndex - nameIndex
						if distance < 0 {
							distance = -distance
						}

						// If keyword is very close to the name (within 15 characters), apply penalty
						if distance < 15 {
							closeNegativeMatches++
						}
					}
				}
			}

			if closeNegativeMatches > 0 {
				// Reduce confidence only for close business context matches
				adjustment -= float64(closeNegativeMatches) * 15.0
				if closeNegativeMatches > 1 {
					adjustment = -25.0 // Moderate penalty for multiple close negative keywords
				}
			}
		}

		// Check for specific contextual patterns
		adjustment += v.analyzeSpecificPatterns(lowerLine, match)
	}

	// Analyze surrounding context if available
	if context.BeforeText != "" || context.AfterText != "" {
		surroundingContext := strings.ToLower(context.BeforeText + " " + context.AfterText)
		adjustment += v.analyzeSurroundingContext(surroundingContext, match)
	}

	// Ensure adjustment is within reasonable bounds
	if adjustment > 25.0 {
		adjustment = 25.0
	}
	if adjustment < -50.0 {
		adjustment = -50.0
	}

	return adjustment
}

// getSortedEmailPatterns returns sorted email patterns for deterministic iteration
func (v *Validator) getSortedEmailPatterns() []string {
	patterns := make([]string, 0, len(emailPatternsMap))
	for pattern := range emailPatternsMap {
		patterns = append(patterns, pattern)
	}
	slices.Sort(patterns)
	return patterns
}

// getSortedBusinessPatterns returns sorted business patterns for deterministic iteration
func (v *Validator) getSortedBusinessPatterns() []string {
	patterns := make([]string, 0, len(businessPatternsMap))
	for pattern := range businessPatternsMap {
		patterns = append(patterns, pattern)
	}
	slices.Sort(patterns)
	return patterns
}

// getSortedProductPatterns returns sorted product patterns for deterministic iteration
func (v *Validator) getSortedProductPatterns() []string {
	patterns := make([]string, 0, len(productPatternsMap))
	for pattern := range productPatternsMap {
		patterns = append(patterns, pattern)
	}
	slices.Sort(patterns)
	return patterns
}

// analyzeSpecificPatterns looks for specific contextual patterns
func (v *Validator) analyzeSpecificPatterns(contextLine, match string) float64 {
	adjustment := 0.0

	// Check for email signature patterns (positive indicators)
	for _, pattern := range v.getSortedEmailPatterns() {
		if strings.Contains(contextLine, pattern) {
			adjustment += 12.0 // Strong boost for email contexts
			break
		}
	}

	// Check for business context patterns (strong negative indicators)
	for _, pattern := range v.getSortedBusinessPatterns() {
		if strings.Contains(contextLine, pattern) {
			adjustment -= 20.0 // Moderate penalty for technical/business contexts
			break
		}
	}

	// Check for product-specific patterns (very strong negative indicators)
	for _, pattern := range v.getSortedProductPatterns() {
		if strings.Contains(contextLine, pattern) {
			adjustment -= 8.0 // Light penalty for product contexts
			break
		}
	}

	// Check for geographic patterns (negative indicators)
	for pattern := range geoPatternsMap {
		if strings.Contains(contextLine, pattern) {
			adjustment -= 35.0 // Strong penalty for geographic contexts
			break
		}
	}

	// Check if this appears to be a standalone name (common in email signatures)
	trimmedLine := strings.TrimSpace(contextLine)
	trimmedMatch := strings.TrimSpace(match)
	if len(trimmedLine) == len(trimmedMatch) {
		// This is likely a signature line - boost confidence more for email signatures
		adjustment += 13.0
	}

	// Most pattern-based filtering is now handled by name database validation
	// Keep only essential context detection

	// Look for email addresses in the same line (strong positive signal)
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emailPattern.MatchString(contextLine) {
		adjustment += 8.0
	}

	// Look for phone numbers in the same line (positive signal)
	phonePattern := regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
	if phonePattern.MatchString(contextLine) {
		adjustment += 5.0
	}

	return adjustment
}

// These complex pattern matching methods are no longer needed
// since name database validation handles most false positives

// analyzeSurroundingContext analyzes the broader context around the match
func (v *Validator) analyzeSurroundingContext(surroundingText, match string) float64 {
	adjustment := 0.0

	// Look for email addresses near names (strong positive signal)
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emailPattern.MatchString(surroundingText) {
		adjustment += 8.0
	}

	// Look for phone numbers near names (positive signal)
	phonePattern := regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
	if phonePattern.MatchString(surroundingText) {
		adjustment += 5.0
	}

	// Look for addresses (positive signal for person names)
	addressPatterns := []string{"street", "avenue", "road", "drive", "lane", "blvd", "apt", "suite"}
	for _, pattern := range addressPatterns {
		if strings.Contains(surroundingText, pattern) {
			adjustment += 3.0
			break
		}
	}

	return adjustment
}

// analyzeContext analyzes the surrounding context for keywords (internal helper)
func (v *Validator) analyzeContext(line string) []string {
	var foundKeywords []string
	lowerLine := strings.ToLower(line)

	// Check for positive keywords
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(lowerLine, keyword) {
			foundKeywords = append(foundKeywords, "+"+keyword)
		}
	}

	// Check for negative keywords
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(lowerLine, keyword) {
			foundKeywords = append(foundKeywords, "-"+keyword)
		}
	}

	return foundKeywords
}

// applyContextInsights applies enhanced context insights to adjust confidence
func (v *Validator) applyContextInsights(match string, insights context.ContextInsights) float64 {
	adjustment := 0.0

	// Document type adjustments
	switch insights.DocumentType {
	case "employee_directory", "contact_list", "customer_database":
		adjustment += 15.0 // High likelihood of person names
	case "product_catalog", "technical_documentation":
		adjustment -= 10.0 // Lower likelihood of person names
	case "legal_document", "contract":
		adjustment += 5.0 // Moderate likelihood (signatories, parties)
	}

	// Domain adjustments
	switch insights.Domain {
	case "hr", "healthcare", "education":
		adjustment += 10.0 // High likelihood of person names
	case "technology", "manufacturing":
		adjustment -= 5.0 // Lower likelihood
	case "finance", "legal":
		adjustment += 5.0 // Moderate likelihood
	}

	// Apply semantic context adjustments
	if personContext, exists := insights.SemanticContext["person"]; exists {
		adjustment += personContext * 20.0 // Scale semantic confidence
	}
	if businessContext, exists := insights.SemanticContext["business"]; exists {
		adjustment -= businessContext * 15.0 // Reduce for business context
	}

	// Apply confidence adjustments from context analysis
	if nameAdjustment, exists := insights.ConfidenceAdjustments["PERSON_NAME"]; exists {
		adjustment += nameAdjustment
	}

	// Ensure adjustment is within reasonable bounds
	if adjustment > 30.0 {
		adjustment = 30.0
	}
	if adjustment < -40.0 {
		adjustment = -40.0
	}

	return adjustment
}

// applyCrossValidatorSignals applies cross-validator signals to boost confidence
func (v *Validator) applyCrossValidatorSignals(match string, signals []context.CrossValidatorSignal) float64 {
	adjustment := 0.0

	for _, signal := range signals {
		switch signal.ValidatorType {
		case "EMAIL":
			// If email addresses are found nearby, person names are more likely
			if signal.SignalType == "person_context" && signal.Confidence > 0.7 {
				adjustment += 10.0
			}
		case "PHONE":
			// If phone numbers are found nearby, person names are more likely
			if signal.SignalType == "contact_context" && signal.Confidence > 0.7 {
				adjustment += 8.0
			}
		case "METADATA":
			// If metadata indicates person-related content
			if signal.SignalType == "author_field" && signal.Confidence > 0.8 {
				adjustment += 15.0
			}
		}
	}

	// Ensure adjustment is within reasonable bounds
	if adjustment > 25.0 {
		adjustment = 25.0
	}

	return adjustment
}

// ensureNamesLoaded ensures name databases are loaded using the existing data.go functionality
func (v *Validator) ensureNamesLoaded() {
	v.once.Do(func() {
		// Use the existing LoadNameDatabases function from data.go
		databases, err := LoadNameDatabases()
		if err != nil {
			// Fallback to empty maps if loading fails
			v.firstNames = make(map[string]bool)
			v.lastNames = make(map[string]bool)

			v.observer.LogOperation(observability.StandardObservabilityData{
				Component: "personname",
				Operation: "load_name_databases",
				Success:   false,
				Metadata: map[string]interface{}{
					"error": err.Error(),
				},
			})
		} else {
			// Successfully loaded databases
			v.firstNames = databases.FirstNames
			v.lastNames = databases.LastNames

			v.observer.LogOperation(observability.StandardObservabilityData{
				Component: "personname",
				Operation: "load_name_databases",
				Success:   true,
				Metadata: map[string]interface{}{
					"first_names_count": len(v.firstNames),
					"last_names_count":  len(v.lastNames),
				},
			})
		}
	})
}

// deduplicateMatches removes duplicate and overlapping matches, preferring longer/more specific ones
func (v *Validator) deduplicateMatches(matches []detector.Match) []detector.Match {
	if len(matches) <= 1 {
		return matches
	}

	var deduplicated []detector.Match

	for _, match := range matches {
		shouldKeep := true

		// Check if this match should be replaced by a better one
		for _, other := range matches {
			if match.LineNumber == other.LineNumber && match.Text != other.Text {
				// If the other match contains this match and is longer, skip this one
				if strings.Contains(other.Text, match.Text) && len(other.Text) > len(match.Text) {
					shouldKeep = false
					break
				}
			}
		}

		if shouldKeep {
			// Check if we already have this exact match (same text, same line)
			duplicate := false
			for i, existing := range deduplicated {
				if existing.LineNumber == match.LineNumber && existing.Text == match.Text {
					// Keep the one with higher confidence
					if match.Confidence > existing.Confidence {
						deduplicated[i] = match
					}
					duplicate = true
					break
				}
			}

			if !duplicate {
				deduplicated = append(deduplicated, match)
			}
		}
	}

	return deduplicated
}

// Removed complex pattern priority methods - simple deduplication is sufficient

// normalizeAccents removes accents from characters for name database lookups
func (v *Validator) normalizeAccents(name string) string {
	// Common accent mappings for name matching
	replacements := map[rune]rune{
		'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a', 'ã': 'a', 'å': 'a',
		'é': 'e', 'è': 'e', 'ë': 'e', 'ê': 'e',
		'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i',
		'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o', 'õ': 'o',
		'ú': 'u', 'ù': 'u', 'ü': 'u', 'û': 'u',
		'ñ': 'n',
		'ç': 'c',
		'ý': 'y', 'ÿ': 'y',
		// Add uppercase versions
		'Á': 'A', 'À': 'A', 'Ä': 'A', 'Â': 'A', 'Ã': 'A', 'Å': 'A',
		'É': 'E', 'È': 'E', 'Ë': 'E', 'Ê': 'E',
		'Í': 'I', 'Ì': 'I', 'Ï': 'I', 'Î': 'I',
		'Ó': 'O', 'Ò': 'O', 'Ö': 'O', 'Ô': 'O', 'Õ': 'O',
		'Ú': 'U', 'Ù': 'U', 'Ü': 'U', 'Û': 'U',
		'Ñ': 'N',
		'Ç': 'C',
		'Ý': 'Y', 'Ÿ': 'Y',
	}

	var result strings.Builder
	for _, r := range name {
		if replacement, exists := replacements[r]; exists {
			result.WriteRune(replacement)
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}
