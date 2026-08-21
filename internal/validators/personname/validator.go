// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	stdctx "context"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
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

	// Pre-compiled regex patterns to avoid repeated compilation in hot paths.
	pnEmailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	pnPhonePattern = regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
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
	observer observability.Observer

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
			// "park" intentionally omitted here too (it was removed from
			// geoPatternsMap): it is a common surname, so it must not carry a
			// geographic/negative penalty. Real addresses are caught by the
			// accompanying geo word (street/avenue/road/drive).
			"city", "county", "state", "country", "mountain", "lake", "river",
			"creek", "valley", "street", "avenue", "road", "drive",
			"algorithm", "method", "protocol", "function", "pattern", "transform",
		},
		observer: observability.NewStandardObserver(observability.ObservabilityMetrics, nil),
	}

	return v
}

// ValidateContent implements the detector.Validator interface for preprocessed content
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: the context-aware
// form of ValidateContent, polling ctx once per line so a runaway multi-line scan
// is reclaimed promptly (v2 Phase 3). On cancellation it returns the (pre-dedup)
// matches gathered so far plus ctx.Err().
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Ensure name databases are loaded
	v.ensureNamesLoaded()

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}
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

	// Per-line context work (lowercasing the line, keyword scans, pattern/regex
	// scans, context-keyword list) is identical for every match on this line, so
	// compute it once instead of recomputing the O(line) work per match.
	lineCache := v.newLineContextCache(line)
	var contextKeywords []string
	keywordsComputed := false

	for _, patternMatch := range patternMatches {
		nameText := patternMatch.Text
		nameComponents := ParseNameComponents(nameText, patternMatch.Pattern)

		confidence, validationChecks := v.CalculateConfidenceWithComponents(nameText, nameComponents)

		// Apply basic context analysis (cached per-line; identical to AnalyzeContext
		// for ContextInfo{FullLine: line}). The match's known byte offset is passed
		// so the proximity check is a bounded window lookup rather than a full-line
		// strings.Index per match (which is O(matches x lineLen) on a single very
		// long line, e.g. minified JSON).
		contextImpact := v.analyzeContextCached(nameText, patternMatch.StartIndex, lineCache)
		confidence += contextImpact

		// Ensure final confidence is within bounds
		if confidence > 100.0 {
			confidence = 100.0
		}
		if confidence < 0.0 {
			confidence = 0.0
		}

		// Unverified-surname ceiling, applied AFTER context so context cannot lift it.
		// See hasExplicitNameMarker: this match was admitted on a title or suffix rather
		// than on database confirmation, so it must never present as HIGH.
		if validationChecks["known_last_name_unverified"] && confidence > unverifiedSurnameCeiling {
			confidence = unverifiedSurnameCeiling
		}

		// Only include matches with reasonable confidence
		if confidence >= 50.0 {
			if !keywordsComputed {
				contextKeywords = v.analyzeContext(line)
				keywordsComputed = true
			}
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
					"context_keywords":  contextKeywords,
					"context_impact":    contextImpact,
					"name_components":   nameComponents,
				},
				// analyzeContextCached already scored against this line; recording
				// it changes no confidence, it just stops the finding reaching a
				// caller without the context used to judge it.
				Context: detector.LineContext(line, patternMatch.StartIndex, patternMatch.StartIndex+len(nameText)),
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

	// Per-line context work (lowercasing the line, keyword scans, pattern/regex
	// scans, context-keyword list) is identical for every match on this line, so
	// compute it once instead of recomputing the O(line) work per match.
	lineCache := v.newLineContextCache(line)
	var contextKeywords []string
	keywordsComputed := false

	for _, patternMatch := range patternMatches {
		nameText := patternMatch.Text
		nameComponents := ParseNameComponents(nameText, patternMatch.Pattern)

		confidence, validationChecks := v.CalculateConfidenceWithComponents(nameText, nameComponents)

		// Apply basic context analysis (cached per-line; identical to AnalyzeContext
		// for ContextInfo{FullLine: line}). Pass the match offset so proximity is a
		// bounded window lookup (avoids O(matches x lineLen) on a single long line).
		contextImpact := v.analyzeContextCached(nameText, patternMatch.StartIndex, lineCache)
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

		// Unverified-surname ceiling, applied AFTER context so context cannot lift it.
		// See hasExplicitNameMarker: this match was admitted on a title or suffix rather
		// than on database confirmation, so it must never present as HIGH.
		if validationChecks["known_last_name_unverified"] && confidence > unverifiedSurnameCeiling {
			confidence = unverifiedSurnameCeiling
		}

		// Only include matches with reasonable confidence
		if confidence >= 50.0 {
			if !keywordsComputed {
				contextKeywords = v.analyzeContext(line)
				keywordsComputed = true
			}
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
					"context_keywords":        contextKeywords,
					"context_impact":          contextImpact,
					"enhanced_context_impact": enhancedImpact,
					"cross_validator_impact":  crossValidatorImpact,
					"document_type":           contextInsights.DocumentType,
					"domain":                  contextInsights.Domain,
					"name_components":         nameComponents,
				},
				// See the sibling emitter in findNamesInLine: the line has already
				// been scored against, so this is a record of it, not an input.
				Context: detector.LineContext(line, patternMatch.StartIndex, patternMatch.StartIndex+len(nameText)),
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
	// hyphenPartKnown handles compound given/family names (Soo-Jin, Jean-Luc,
	// Mary-Kate): the full hyphenated token is rarely in the ~5K dictionary,
	// but its parts usually are. A single part matching is enough to treat the
	// compound as a known name component — the dictionary is the authoritative
	// gate and these are real names it would otherwise reject outright
	// (recall gap surfaced by the reranker-benchmark corpus generator).
	// Requires the part be 2+ chars so a stray "A-Team" style initial can't
	// qualify on a one-letter fragment.
	hyphenPartKnown := func(name string, dict map[string]bool) bool {
		if !strings.Contains(name, "-") {
			return false
		}
		for _, part := range strings.Split(name, "-") {
			if len(part) < 2 {
				continue
			}
			if dict[part] || dict[v.normalizeAccents(part)] {
				return true
			}
		}
		return false
	}

	if v.firstNames != nil && len(components.FirstName) > 0 {
		// Try both the original name and normalized version (without accents)
		firstName := strings.ToLower(components.FirstName)
		normalizedFirstName := v.normalizeAccents(firstName)

		if v.firstNames[firstName] || v.firstNames[normalizedFirstName] ||
			hyphenPartKnown(firstName, v.firstNames) {
			checks["known_first_name"] = true
		}
	}

	if v.lastNames != nil && len(components.LastName) > 0 {
		// Try both the original name and normalized version (without accents)
		lastName := strings.ToLower(components.LastName)
		normalizedLastName := v.normalizeAccents(lastName)

		if v.lastNames[lastName] || v.lastNames[normalizedLastName] ||
			hyphenPartKnown(lastName, v.lastNames) {
			checks["known_last_name"] = true
		}
	}

	// EARLY EXIT: the SURNAME must be known.
	//
	// This used to accept a hit in EITHER list, and that asymmetry was the source of
	// the validator's false positives. English has many words that are given names
	// and rarely surnames — mark, bill, grace, may, art, chase, rich, sunny, summer —
	// so one given-name hit was enough to report an ordinary noun phrase as a person.
	// Measured on shipped code:
	//
	//	"Please review the Rich Text format."      -> Rich Text (67)
	//	"The Grace Period expires Friday."         -> "The Grace" (67)
	//	"Frank Discussion about the Art Director." -> two findings at 79
	//
	// 43 such findings in 200 lines of ordinary business prose, all false, all at
	// MEDIUM — on the default review surface and blocking a pre-commit hook.
	//
	// Requiring the SURNAME specifically is strictly better than requiring BOTH,
	// measured over 73 real names across 14 locales and 20 non-name phrases:
	//
	//	rule            recall   FP     precision
	//	OR (before)      84.9%   14/20    0.816
	//	both known       45.2%    0/20    1.000
	//	surname only     75.3%    0/20    1.000   <- same precision, +30pt recall
	//
	// The remaining recall cost is entirely MISSING SURNAMES (vries, sato, yilmaz,
	// nkosi, ...), which is a data gap the surname list closes — not something this
	// rule can fix, and not something the OR rule fixed either: it recovered those
	// names only by also accepting every noun phrase above.
	if !checks["known_last_name"] {
		// An explicit human-name MARKER is evidence the database cannot supply.
		//
		// The surname list will always be incomplete — it holds ~2.3K entries against
		// an unbounded population — and a name it does not carry is unreportable at
		// every confidence level, so it is never redacted. That is the leak this arm
		// bounds: a title or a generational suffix says "the following tokens are a
		// person's name" regardless of whether the surname is on any list.
		//
		// Measured before this, with a surname absent from the list:
		//
		//	Dr. Elena Brightwater reviewed the chart.   not reported
		//	Ms. Priya Thorncastle filed the report.     not reported
		//	Thomas Vellamore Jr. signed today.         not reported
		//
		// TITLES AND SUFFIXES ONLY, and the exclusion is measured rather than assumed.
		// isFormalNamePattern also covers the comma forms (last_comma_first and
		// friends), and those are a bare punctuation shape that document structure
		// imitates: "Overview, Introduction" and "Appendix, Summary" both match it, and
		// both are rejected today only because "overview" and "appendix" are not
		// surnames. Admitting comma forms here would report them. The five fp__ decoy
		// cases contain no comma-form line, so the corpus could not have caught that —
		// negatives were added for it.
		//
		// Capped, not merely scored down. A ceiling context cannot lift is the same
		// shape used for reserved values in PR #365: any fixed penalty is out-voted by
		// enough positive context, so an unverified surname must not be able to present
		// as HIGH. The cap sits in MEDIUM so the finding reaches the default review
		// surface and the redactor, while a database-confirmed name still outranks it.
		if !v.hasExplicitNameMarker(components.Pattern) {
			// A known given name alone is not evidence of a person: it is evidence of a
			// word that is also a name.
			checks["has_known_name_component"] = false
			checks["both_names_known"] = false
			return 0.0, checks // Early exit - avoid all expensive calculations
		}
		checks["known_last_name_unverified"] = true
	}

	// The GIVEN half must not be an English function word.
	//
	// The surname gate above cannot catch this class, because the surname here is
	// GENUINE: "grace", "morgan" and "young" are all real surnames. What fails is
	// that the patterns match Title-Case SHAPE, so an article or preposition sitting
	// in front of a real surname satisfies "two capitalised tokens" and is reported
	// as a person — "The Grace", "Their Morgan", "Via Morgan". Measured: 49 of 49
	// leading function words produced a finding, and 156 of 5,888 PERSON_NAME
	// findings on a 1,388-file real corpus (2.6%) are of this shape.
	//
	// isFunctionWordGiven defers to the name databases, so Will/May/An survive.
	if v.isFunctionWordGiven(components.FirstName) {
		checks["proper_case"] = false
		checks["has_known_name_component"] = false
		checks["both_names_known"] = false
		return 0.0, checks
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
		} else if v.isCommonWordBigram(components) && !v.isFormalNamePattern(components.Pattern) {
			// Both tokens are ordinary English words that also happen to be in the
			// name databases ("Will Read", "Grace Hill"). Without a formal pattern
			// (title/suffix/comma/initial) this is far more likely prose than a
			// person name, so hold it at MEDIUM rather than jumping to HIGH. A name
			// with even one distinctive token, or any formal pattern, is unaffected
			// and still reaches HIGH below.
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

// titleAndSuffixTokens are honorifics/suffixes exempt from the leading-capital
// check in isProperlyCapitalized (they may be lowercased or all-caps).
var titleAndSuffixTokens = map[string]bool{
	"mr.": true, "ms.": true, "mrs.": true, "dr.": true, "prof.": true,
	"mr": true, "ms": true, "mrs": true, "dr": true, "prof": true,
	"jr.": true, "sr.": true, "jr": true, "sr": true,
	"ii": true, "iii": true, "iv": true, "v": true,
}

// isProperlyCapitalized checks if each name word starts with an uppercase letter.
//
// Two bugs were fixed here (M20):
//   - The previous code did strings.Contains("Mr.Ms.Mrs.Dr.Prof.Jr.Sr.III.IV.",
//     word) — arguments reversed — so any word that was a SUBSTRING of that
//     concatenation ("M", "I", "V", "Pro", "Sr") skipped the capitalization
//     check. We now compare against a proper token set.
//   - It indexed word[0] (a byte), so an accented capital like 'Á' (first byte
//     0xC3 > 'Z') was wrongly treated as not-capitalized. We now decode the
//     first rune and use unicode.IsUpper.
func (v *Validator) isProperlyCapitalized(name string) bool {
	for _, word := range strings.Fields(name) {
		if word == "" {
			continue
		}
		if titleAndSuffixTokens[strings.ToLower(word)] {
			continue
		}
		r, _ := utf8.DecodeRuneInString(word)
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// isCommonWordBigram reports whether BOTH the first and last name tokens are
// ordinary English words that merely happen to also be in the name databases
// (e.g. "Will Read", "Grace Hill"). Such a bigram is usually prose or a heading,
// not a person name, so it should not reach HIGH confidence on the strength of a
// bare two-word database match alone.
func (v *Validator) isCommonWordBigram(components NameComponents) bool {
	first := strings.ToLower(components.FirstName)
	last := strings.ToLower(components.LastName)
	if first == "" || last == "" {
		return false
	}
	return commonWordNamesMap[first] && commonWordNamesMap[last]
}

// isFunctionWordGiven reports whether the GIVEN-name half is an English function
// word that the name databases do not know. See functionWordsMap.
//
// The database check comes FIRST and wins. "will", "may" and "an" appear in both
// the function-word vocabulary and the shipped name data, and they belong to real
// people — Will Smith, May Chen, An Nguyen — so the data is authoritative and the
// word list only rejects what the data has no opinion about. Without that ordering
// this precision fix would delete real names, and an unreported name is never
// handed to the redactor: it stays in cleartext in the output.
func (v *Validator) isFunctionWordGiven(first string) bool {
	first = strings.ToLower(strings.TrimSpace(first))
	if first == "" || !functionWordsMap[first] {
		return false
	}
	// The name databases are authoritative; defer to them.
	normalized := v.normalizeAccents(first)
	if v.firstNames != nil && (v.firstNames[first] || v.firstNames[normalized]) {
		return false
	}
	if v.lastNames != nil && (v.lastNames[first] || v.lastNames[normalized]) {
		return false
	}
	return true
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
// unverifiedSurnameCeiling bounds a name admitted on an explicit marker rather than on
// database confirmation.
//
// 65 sits inside MEDIUM: high enough that the finding reaches the default review
// surface and the redactor, low enough that it can never present as HIGH and can never
// outrank a name whose surname the database actually carries. A ceiling rather than a
// penalty, because a fixed penalty is out-voted by enough positive context — the same
// reasoning as the reserved-value ceilings in PR #365.
const unverifiedSurnameCeiling = 65.0

// hasExplicitNameMarker reports whether the pattern carries a token that states the
// match is a person's name — a title or a generational/professional suffix.
//
// A strict subset of isFormalNamePattern, which also includes the comma forms. Those
// are excluded deliberately: "Surname, Given" is a bare punctuation shape that document
// structure imitates ("Overview, Introduction", "Appendix, Summary"), so it carries no
// evidence of personhood on its own. A title or suffix does.
func (v *Validator) hasExplicitNameMarker(patternName string) bool {
	switch patternName {
	case "name_with_title", "name_with_multiple_titles",
		"name_with_suffix", "name_with_professional_suffix":
		return true
	}
	return false
}

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

	// Consult veryCommonNamesMap for either token. These are very common
	// software/operations words (default, root, update, cancel, warning, debug,
	// system, ...) that appear beside a known surname in logs and UI text
	// ("Default Johnson", "Update User") and scored MEDIUM as false names. None
	// of these tokens is present in the first/last-name databases (verified), so
	// treating them as technical context cannot demote a real person name — it
	// only suppresses the technical-word-plus-surname false positive. This is the
	// intended consumer of veryCommonNamesMap, which was previously dead code.
	if veryCommonNamesMap[firstName] || veryCommonNamesMap[lastName] {
		return true
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

// containsWordKeyword reports whether text contains keyword as a whole word/
// phrase (case-insensitive, text already lowercased by callers). The previous
// substring matching let short context keywords fire inside unrelated words
// ("park" in "parking" -> -35, "inc" in "incident" -> -20, "name" in
// "username" -> +12), nudging confidence in both directions (L25).
//
// ModeAlnum preserves this validator's historical boundary semantics: a word
// byte is [a-z0-9], so '_' acts as a word boundary here. ContainsLower (rather
// than Contains) keeps the existing contract that callers pass lowercased text.
func containsWordKeyword(text, keyword string) bool {
	return kwmatch.ContainsLower(text, keyword)
}

// firstWordKeywordIndex returns the byte offset of the first whole-word occurrence
// of keyword in lowerText, or -1. It is the index-returning counterpart of
// containsWordKeyword: same word model (kwmatch's alphanumeric boundaries), so a
// keyword found by one is found at the reported offset by the other.
//
// The offset is what lets a penalty be applied by DISTANCE from the match instead
// of line-globally. A plain strings.Index would not do: it reports substring hits
// ("state" inside "estate", "drive" inside "driven") that containsWordKeyword
// rejects, so the two would disagree about whether a pattern is present.
func firstWordKeywordIndex(lowerText, keyword string) int {
	idx := -1
	kwmatch.ContainsFunc(lowerText, keyword, func(start, _ int) bool {
		idx = start
		return true // stop at the first whole-word hit
	})
	return idx
}

// lineContextCache holds the per-line work shared by every name match found on a
// single line. The original AnalyzeContext recomputed all of this (lowercasing the
// line, scanning every positive/negative keyword, running the email/business/
// product/geo pattern scans and the email/phone regexes) once *per match*, which
// is O(line) per match and quadratic on a line packed with matches. We compute it
// once per line in newLineContextCache and reuse it via analyzeContextCached, which
// reproduces AnalyzeContext's arithmetic exactly. Only the two genuinely
// match-specific signals (the negative-keyword proximity penalty and the
// "line is just the name" signature boost) are recomputed per match.
type lineContextCache struct {
	lowerLine string

	// emptyLine mirrors the original `context.FullLine != ""` guard: when the raw
	// line is empty, AnalyzeContext skips all line processing and returns 0.
	emptyLine bool
	// positiveAdjustment is the fully line-global positive-keyword contribution.
	positiveAdjustment float64
	// hasNegativeKeyword is true when at least one negative keyword matched the
	// line (whole-word), gating the per-match proximity penalty exactly as before.
	hasNegativeKeyword bool
	// negativeKeywordIndices holds the first-occurrence byte offset of each
	// negative keyword present on the line that ALSO passes the email/URL guard.
	// This is line-global (independent of the match), so it is computed once here
	// instead of re-scanning the whole line per match — the source of the
	// O(matches x lineLen) blowup on a single very long line (minified JSON/JS).
	negativeKeywordIndices []int
	// specificLineAdjustment is the line-global portion of analyzeSpecificPatterns
	// that is genuinely line-global: the email/phone-on-this-line boosts. The three
	// PENALTY families are proximity-gated per match instead, via the index slices
	// below — see analyzeSpecificPatternsLineGlobal.
	specificLineAdjustment float64
	// businessIndices, productIndices and geoIndices hold the first-occurrence byte
	// offset of each business / product / geographic pattern present on the line.
	// Like negativeKeywordIndices these are line-global to COMPUTE but are applied
	// per match by distance, so a street address at the far end of a long line no
	// longer penalizes a name at the near end.
	businessIndices []int
	productIndices  []int
	geoIndices      []int
}

// newLineContextCache precomputes the line-global context signals for line.
func (v *Validator) newLineContextCache(line string) *lineContextCache {
	c := &lineContextCache{lowerLine: strings.ToLower(line), emptyLine: line == ""}
	if c.emptyLine {
		return c
	}
	lowerLine := c.lowerLine

	positiveMatches := 0
	negativeMatches := 0
	for _, keyword := range v.positiveKeywords {
		if containsWordKeyword(lowerLine, keyword) {
			positiveMatches++
		}
	}
	for _, keyword := range v.negativeKeywords {
		if containsWordKeyword(lowerLine, keyword) {
			negativeMatches++
		}
	}

	if positiveMatches > 0 {
		c.positiveAdjustment += float64(positiveMatches) * 12.0
		if positiveMatches > 2 {
			c.positiveAdjustment = 25.0 // Cap at +25% for multiple positive keywords
		}
	}
	c.hasNegativeKeyword = negativeMatches > 0

	// Precompute, once per line, the first-occurrence offset of each negative
	// keyword that survives the email/URL guard. The original code recomputed
	// this (strings.Index + the ±10-char guard) for every match; it is
	// match-independent, so hoisting it makes the per-match proximity check O(1)
	// per keyword instead of O(lineLen). Preserves behavior: same keywords, same
	// first-occurrence index, same guard.
	if c.hasNegativeKeyword {
		for _, keyword := range v.negativeKeywords {
			keywordIndex := strings.Index(lowerLine, keyword)
			if keywordIndex < 0 {
				continue
			}
			beforeKeyword := ""
			afterKeyword := ""
			if keywordIndex > 10 {
				beforeKeyword = lowerLine[keywordIndex-10 : keywordIndex]
			}
			if keywordIndex+len(keyword)+10 < len(lowerLine) {
				afterKeyword = lowerLine[keywordIndex+len(keyword) : keywordIndex+len(keyword)+10]
			}
			if strings.Contains(beforeKeyword, "@") || strings.Contains(afterKeyword, "@") ||
				strings.Contains(beforeKeyword, "http") || strings.Contains(afterKeyword, ".com") {
				continue
			}
			c.negativeKeywordIndices = append(c.negativeKeywordIndices, keywordIndex)
		}
	}

	c.specificLineAdjustment = v.analyzeSpecificPatternsLineGlobal(lowerLine)
	c.businessIndices, c.productIndices, c.geoIndices = v.specificPatternIndices(lowerLine)
	return c
}

// AnalyzeContext implements the detector.Validator interface for contextual analysis.
//
// This is the public, directly-tested entry point. For the hot scanning path
// (findNamesInLine / findNamesInLineWithContext) we instead use
// newLineContextCache + analyzeContextCached, which produce identical results while
// hoisting the line-global work out of the per-match loop.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	adjustment := 0.0

	// Analyze the context line for keywords
	if context.FullLine != "" {
		cache := v.newLineContextCache(context.FullLine)
		// Public single-match path: locate the match once (the hot scanning path
		// passes the known offset instead). -1 is fine — analyzeLineContextForMatch
		// falls back to a full-line scan when the offset is unknown.
		matchStart := strings.Index(cache.lowerLine, strings.ToLower(match))
		adjustment += v.analyzeLineContextForMatch(match, matchStart, cache)
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

// analyzeContextCached returns the same value AnalyzeContext returns for
// ContextInfo{FullLine: line} (the only shape the scanning path uses), reusing the
// precomputed per-line cache. The hot loop calls this once per match.
func (v *Validator) analyzeContextCached(match string, matchStart int, cache *lineContextCache) float64 {
	adjustment := v.analyzeLineContextForMatch(match, matchStart, cache)

	// Ensure adjustment is within reasonable bounds (matches AnalyzeContext).
	if adjustment > 25.0 {
		adjustment = 25.0
	}
	if adjustment < -50.0 {
		adjustment = -50.0
	}
	return adjustment
}

// analyzeLineContextForMatch combines the cached line-global signals with the two
// match-specific signals (negative-keyword proximity penalty, signature boost) to
// reproduce the pre-clamp adjustment computed by the original AnalyzeContext body.
// matchStart is the byte offset of the match within cache.lowerLine (as found by
// the pattern engine). Pass -1 if unknown, in which case the name position is
// located with a single strings.Index (the directly-tested public AnalyzeContext
// path). The hot scanning path always passes the real offset, so the per-match
// full-line scans are eliminated.
// specificPatternProximity is how close (in bytes) a business / product /
// geographic pattern must sit to a name before it counts as context FOR that name.
//
// 25 was measured, not guessed. Sweeping the window against a corpus of 10 real
// names carrying addresses and 24 place/org/address decoys:
//
//	window   real names found   decoys reported
//	    15         10/10              8/24
//	    22         10/10              6/24
//	 23-25         10/10              5/24   <- plateau
//	    26          9/10              5/24
//	    30          8/10              5/24
//	line-global     4/10              5/24   (the old behavior)
//
// 5/24 is exactly what the line-global code reported, on the same five lines, so
// this window recovers every real name while introducing NO new false positive.
// 25 sits at the top of the plateau, one byte before recall starts dropping.
//
// The remaining five decoys ("Phoenix Arizona", "Menlo Park", ...) are a separate
// pre-existing issue: those place words are themselves entries in the FIRST-NAME
// database, so they score on their own merits and the geographic penalty was only
// masking them incidentally — at the cost of deleting real names. Fixing that means
// curating the name database, not widening this window; no window value separates
// the two classes, because the geographic word sits OUTSIDE the matched span in
// both (20-21 bytes away in the decoys, 29-31 in the real names).
//
// Note this is wider than the negative-keyword penalty's 15, even though many
// words appear in both lists (13 of 19 geographic patterns and 17 business
// patterns are also negativeKeywords).
//
// This comment used to end "That is intentional: the two penalties stack, so the
// keyword path still contributes at its own tighter distance." The window being
// wider is still intentional and unchanged. The STACKING was not measured, and it
// cost real names: one "Street" beside a name paid -35 here and -15 there, and
// 100 - 58 landed at 42, under the 50 emit floor — so five of eight mailing-label
// forms reported nothing at all and were never redacted (#387). A word outside the
// name is now charged once, at the higher of the two rates; a word INSIDE the
// candidate span still stacks, because there the geography and the "name" are the
// same evidence. See analyzeLineContextForMatch.
const specificPatternProximity = 25

// matchIndex resolves the byte offset of the match within lowerLine, preferring
// the offset the pattern engine already knows. Mirrors the nameIndex fallback used
// by the negative-keyword penalty: -1 means "not supplied", in which case a single
// lookup finds it (the directly-tested public AnalyzeContext path). Returns -1 if
// the match cannot be located, in which case no proximity penalty is applied —
// failing OPEN, because a name is reported rather than silently dropped.
// negativeKeywordProximity and negativeKeywordPenalty are the window and cost of the
// negative-keyword penalty, named because specificPatternPenalties has to compare against the cost
// to decide whether a word has already been charged more heavily elsewhere.
const (
	negativeKeywordProximity = 15
	negativeKeywordPenalty   = 15.0
)

// specificPatternPenalties returns the total business/product/geographic penalty for a name at
// nameIndex, and the byte offset of every pattern that contributed, mapped to the largest penalty
// charged at that offset.
//
// The offsets are what let the caller avoid charging one word under two penalty families. They are
// directly comparable with cache.negativeKeywordIndices: both are first-occurrence byte offsets
// into the same lowered line.
//
// A family charges once even when several of its patterns are in range — that is the pre-existing
// behaviour of the bool-returning check this replaces, and widening it would be a separate
// (precision-reducing) decision.
func (v *Validator) specificPatternPenalties(cache *lineContextCache, nameIndex int) (float64, map[int]float64) {
	if nameIndex < 0 {
		return 0, nil
	}

	var total float64
	var charged map[int]float64

	families := []struct {
		indices []int
		penalty float64
	}{
		{cache.businessIndices, 20.0}, // business/technical context
		{cache.productIndices, 8.0},   // product context
		{cache.geoIndices, 35.0},      // geographic context
	}

	for _, f := range families {
		if !nearestWithin(f.indices, nameIndex, specificPatternProximity) {
			continue
		}
		total += f.penalty
		for _, idx := range f.indices {
			distance := idx - nameIndex
			if distance < 0 {
				distance = -distance
			}
			if distance >= specificPatternProximity {
				continue
			}
			if charged == nil {
				charged = make(map[int]float64, len(families))
			}
			if charged[idx] < f.penalty {
				charged[idx] = f.penalty
			}
		}
	}
	return total, charged
}

func matchIndex(matchStart int, lowerLine, match string) int {
	if matchStart >= 0 {
		return matchStart
	}
	return strings.Index(lowerLine, strings.ToLower(match))
}

// nearestWithin reports whether any offset in indices is within window bytes of
// nameIndex. indices holds at most one entry per pattern family today, but the
// slice shape keeps it aligned with negativeKeywordIndices and costs nothing.
func nearestWithin(indices []int, nameIndex, window int) bool {
	for _, idx := range indices {
		distance := idx - nameIndex
		if distance < 0 {
			distance = -distance
		}
		if distance < window {
			return true
		}
	}
	return false
}

func (v *Validator) analyzeLineContextForMatch(match string, matchStart int, cache *lineContextCache) float64 {
	// Mirror AnalyzeContext's `if context.FullLine != ""` guard: an empty line
	// contributes nothing (no signature boost either).
	if cache.emptyLine {
		return 0.0
	}

	lowerLine := cache.lowerLine
	adjustment := cache.positiveAdjustment

	// Work out which specific-pattern families penalise THIS name, and at which byte offsets,
	// before the negative-keyword count below — because the two lists overlap and a word must not
	// be charged twice for being one word.
	//
	// 13 of 19 geographic patterns and 17 business patterns are also negativeKeywords, so a single
	// "Street" used to pay -35 as geography AND -15 as a negative keyword. The penalties are
	// applied in the original order further down; only the COUNT below changes.
	nameIdx := matchIndex(matchStart, lowerLine, match)
	specificPenalty, chargedOffsets := v.specificPatternPenalties(cache, nameIdx)

	if cache.hasNegativeKeyword {
		// Apply the business-context penalty only when guard-passing negative
		// keywords sit close (<15 chars) to the name. The keyword positions and
		// their email/URL guard are line-global and precomputed once in the cache;
		// here we just compare each against the name's offset. nameIndex uses the
		// known matchStart (or a single fallback lookup) instead of re-scanning the
		// whole line per match.
		nameIndex := nameIdx

		closeNegativeMatches := 0
		if nameIndex >= 0 {
			for _, keywordIndex := range cache.negativeKeywordIndices {
				distance := keywordIndex - nameIndex
				if distance < 0 {
					distance = -distance
				}
				if distance >= negativeKeywordProximity {
					continue
				}
				// One word OUTSIDE the name, one charge. If a specific-pattern family already
				// penalised the word at this offset by at least as much, charging it again here
				// is charging the same evidence twice.
				//
				// Measured: "1247 Oakmont Street, Marcus Whitfield" paid -35 (geographic) -15
				// (negative keyword) -8 (product) = -58, taking a list-surname name from 100 to
				// 42 — under the hardcoded 50 emit floor, so the finding did not exist at any
				// --confidence setting and no redacted file was written at all. Five of eight
				// realistic mailing-label forms behaved that way (#387).
				//
				// The span test is what keeps this from re-admitting place names, and it is the
				// real distinction between the two classes. In "Jordan Lake State Recreation
				// Area" the geographic word IS the second token of the candidate — the "name" is
				// the place — so both charges are evidence about the same thing and the stack is
				// correct. In a mailing label the street suffix sits outside the name entirely and
				// says nothing more about it than the geographic penalty already did. Measured:
				// without this test, that line returned as a LOW 57 false positive.
				insideName := nameIndex >= 0 && keywordIndex >= nameIndex && keywordIndex < nameIndex+len(match)
				if !insideName {
					if charged, ok := chargedOffsets[keywordIndex]; ok && charged >= negativeKeywordPenalty {
						continue
					}
				}
				closeNegativeMatches++
			}
		}

		if closeNegativeMatches > 0 {
			adjustment -= float64(closeNegativeMatches) * negativeKeywordPenalty
			if closeNegativeMatches > 1 {
				adjustment = -25.0 // Moderate penalty for multiple close negative keywords
			}
		}
	}

	// Line-global specific patterns (the BOOSTS only) plus the match-specific
	// signature boost.
	adjustment += cache.specificLineAdjustment

	// The business / product / geographic PENALTIES are applied by distance, like
	// the negative-keyword penalty above, rather than to the whole line. Locating
	// them stays hoisted per line (see specificPatternIndices); only this cheap
	// offset comparison is per match, so the validator stays linear.
	//
	// Same window as the negative-keyword penalty: a pattern has to sit within
	// specificPatternProximity of the name to say anything about THAT name. A
	// street address at the other end of a CSV row does not.
	// Computed above, before the negative-keyword count, so that count can tell which words have
	// already been charged. The arithmetic and its position here are unchanged.
	adjustment -= specificPenalty

	trimmedLine := strings.TrimSpace(lowerLine)
	trimmedMatch := strings.TrimSpace(match)
	if len(trimmedLine) == len(trimmedMatch) {
		// This is likely a signature line - boost confidence for email signatures.
		adjustment += 13.0
	}

	return adjustment
}

// Sorted pattern slices are derived solely from the package-level maps, so they
// are constant for the lifetime of the process. The originals rebuilt and sorted
// them on every call (once per match); we now build them lazily exactly once and
// reuse the cached slices. Iteration order and contents are unchanged.
var (
	sortedEmailPatterns    []string
	sortedBusinessPatterns []string
	sortedProductPatterns  []string
	sortedGeoPatterns      []string
	sortedPatternsOnce     sync.Once
)

func initSortedPatterns() {
	sortedEmailPatterns = make([]string, 0, len(emailPatternsMap))
	for pattern := range emailPatternsMap {
		sortedEmailPatterns = append(sortedEmailPatterns, pattern)
	}
	slices.Sort(sortedEmailPatterns)

	sortedBusinessPatterns = make([]string, 0, len(businessPatternsMap))
	for pattern := range businessPatternsMap {
		sortedBusinessPatterns = append(sortedBusinessPatterns, pattern)
	}
	slices.Sort(sortedBusinessPatterns)

	sortedProductPatterns = make([]string, 0, len(productPatternsMap))
	for pattern := range productPatternsMap {
		sortedProductPatterns = append(sortedProductPatterns, pattern)
	}
	slices.Sort(sortedProductPatterns)

	sortedGeoPatterns = make([]string, 0, len(geoPatternsMap))
	for pattern := range geoPatternsMap {
		sortedGeoPatterns = append(sortedGeoPatterns, pattern)
	}
	slices.Sort(sortedGeoPatterns)
}

// getSortedEmailPatterns returns sorted email patterns for deterministic iteration
func (v *Validator) getSortedEmailPatterns() []string {
	sortedPatternsOnce.Do(initSortedPatterns)
	return sortedEmailPatterns
}

// getSortedBusinessPatterns returns sorted business patterns for deterministic iteration
func (v *Validator) getSortedBusinessPatterns() []string {
	sortedPatternsOnce.Do(initSortedPatterns)
	return sortedBusinessPatterns
}

// getSortedProductPatterns returns sorted product patterns for deterministic iteration
func (v *Validator) getSortedProductPatterns() []string {
	sortedPatternsOnce.Do(initSortedPatterns)
	return sortedProductPatterns
}

// getSortedGeoPatterns returns sorted geographic patterns for deterministic
// iteration. The geo scan previously ranged geoPatternsMap directly and broke on
// the first hit, so which pattern won was decided by map order.
func (v *Validator) getSortedGeoPatterns() []string {
	sortedPatternsOnce.Do(initSortedPatterns)
	return sortedGeoPatterns
}

// analyzeSpecificPatternsLineGlobal computes the line-global portion of the
// original analyzeSpecificPatterns: everything except the match-specific
// "line is just the name" signature boost, which is applied per match in
// analyzeLineContextForMatch. contextLine is the already-lowercased line.
// analyzeSpecificPatternsLineGlobal returns the part of the specific-pattern
// analysis that is genuinely line-global: the boosts. A signature/email/phone
// signal anywhere on the line says something about the line as a whole, and
// boosting cannot hide a finding.
//
// The three PENALTY families (business, product, geographic) are deliberately NOT
// scored here. They are located instead — see specificPatternIndices — and applied
// per match by distance in analyzeLineContextForMatch, because line-global
// penalties were deleting real names:
//
//	"Sarah Brooks,Acme Inc,1425 Oak Drive,Springfield,IL"  -> 0 findings
//	"Patient Sarah Brooks, 42 River Road, admitted Monday" -> 0 findings
//
// business (-20, "inc") + geographic (-35, "drive"/"road") clamps to -50 in
// analyzeContextCached, which takes a solid two-token name from 92 to 42 and below
// the >= 50 emit threshold. The name is then absent from the report and so from
// redaction, leaving it cleartext in the output. The same names score 92 with the
// address removed, and 100 with the address on its own line.
//
// The asymmetry is the tell: the negative-KEYWORD penalty in
// analyzeLineContextForMatch has always been proximity-gated (< 15 chars from the
// match). These three families were the only context signals applied to the whole
// line regardless of distance.
func (v *Validator) analyzeSpecificPatternsLineGlobal(contextLine string) float64 {
	adjustment := 0.0

	// Check for email signature patterns (positive indicators)
	for _, pattern := range v.getSortedEmailPatterns() {
		if strings.Contains(contextLine, pattern) {
			adjustment += 12.0 // Strong boost for email contexts
			break
		}
	}

	// Most pattern-based filtering is now handled by name database validation
	// Keep only essential context detection

	// Look for email addresses in the same line (strong positive signal)
	if pnEmailPattern.MatchString(contextLine) {
		adjustment += 8.0
	}

	// Look for phone numbers in the same line (positive signal)
	if pnPhonePattern.MatchString(contextLine) {
		adjustment += 5.0
	}

	return adjustment
}

// specificPatternIndices locates EVERY pattern of each penalty family present on
// the line. Locating is line-global (identical for every match on the line, so it
// stays hoisted out of the per-match loop and the validator stays linear);
// APPLYING the penalty is per match, by distance.
//
// Every offset, not just the first, because under proximity gating the recorded
// offsets decide whether a name is penalized — so keeping only one per family lets
// a distant match mask an adjacent one. With `break` after the first hit:
//
//	"oak drive sarah brooks"                    -> geo=[4],  penalty FIRES
//	"avenue" + 60 dots + " oak drive sarah brooks" -> geo=[0],  penalty SILENT
//
// Identical adjacent "oak drive", but prepending the alphabetically-earlier
// "avenue" far away suppressed the penalty entirely (-50 became -15, and the
// finding rose from 57 to 69 through the CLI). That is attacker-controllable, and
// it is the same class of hazard as the map-order issue below: what changed was
// never the score for a given pattern, but WHICH offset got recorded.
//
// The penalty itself is still awarded at most once per family (see
// analyzeLineContextForMatch), so collecting more offsets cannot double-penalize;
// it only stops one from hiding another.
//
// The geographic loop also stops ranging over geoPatternsMap directly. Ranging a
// Go map picks an arbitrary winner among several present patterns; the score was
// the same either way, so this was invisible, but the recorded offset is not
// order-independent. Iterating a sorted slice makes it deterministic.
func (v *Validator) specificPatternIndices(lowerLine string) (business, product, geo []int) {
	collect := func(patterns []string) []int {
		var out []int
		for _, pattern := range patterns {
			if i := firstWordKeywordIndex(lowerLine, pattern); i >= 0 {
				out = append(out, i)
			}
		}
		return out
	}
	return collect(v.getSortedBusinessPatterns()),
		collect(v.getSortedProductPatterns()),
		collect(v.getSortedGeoPatterns())
}

// These complex pattern matching methods are no longer needed
// since name database validation handles most false positives

// analyzeSurroundingContext analyzes the broader context around the match
func (v *Validator) analyzeSurroundingContext(surroundingText, match string) float64 {
	adjustment := 0.0

	// Look for email addresses near names (strong positive signal)
	if pnEmailPattern.MatchString(surroundingText) {
		adjustment += 8.0
	}

	// Look for phone numbers near names (positive signal)
	if pnPhonePattern.MatchString(surroundingText) {
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

// dedupKey identifies an exact match by line and text for O(1) duplicate lookup.
type dedupKey struct {
	line int
	text string
}

// deduplicateMatches removes duplicate and overlapping matches, preferring longer/more specific ones.
//
// The original implementation was O(M^2) over the full match list: for every match it
// rescanned every other match for a containing/longer one, then rescanned the growing
// output for an exact duplicate. On a single long line packed with many (often identical)
// matches this is a quadratic DoS. This version preserves the exact same behavior while
// avoiding the quadratic blow-ups:
//
//   - Exact duplicates (same line + same text) are collapsed first via a map. Because the
//     containment check only ever compares matches with *different* text on the same line,
//     identical duplicates never influence anyone's keep/drop decision, so collapsing them
//     up front is behavior-preserving. The map keeps the highest-confidence copy and the
//     first-seen position, exactly as the old in-place overwrite did.
//   - The "is there a longer same-line match that contains me" check is then evaluated only
//     against the distinct texts present on the *same line* (grouped via a per-line index),
//     instead of every match in the whole file. This removes the cross-line comparisons that
//     made the many-line case quadratic, and shrinks the single-line case from O(k^2) over
//     all raw matches to O(u^2) over the far smaller set of distinct texts on that line.
//
// Output ordering matches the original: kept matches are emitted in order of first appearance.
func (v *Validator) deduplicateMatches(matches []detector.Match) []detector.Match {
	if len(matches) <= 1 {
		return matches
	}

	// Collapse exact duplicates (same line + same text), keeping the highest-confidence
	// copy and the first-seen position. unique holds one representative per distinct
	// (line, text) in first-appearance order.
	indexByKey := make(map[dedupKey]int, len(matches))
	unique := make([]detector.Match, 0, len(matches))
	for _, match := range matches {
		key := dedupKey{line: match.LineNumber, text: match.Text}
		if i, ok := indexByKey[key]; ok {
			if match.Confidence > unique[i].Confidence {
				unique[i] = match
			}
			continue
		}
		indexByKey[key] = len(unique)
		unique = append(unique, match)
	}

	// Group the distinct texts by line so the containment check only compares within a line.
	textsByLine := make(map[int][]string, len(unique))
	for _, m := range unique {
		textsByLine[m.LineNumber] = append(textsByLine[m.LineNumber], m.Text)
	}

	deduplicated := make([]detector.Match, 0, len(unique))
	for _, match := range unique {
		shouldKeep := true
		// Drop this match if another distinct match on the same line is strictly
		// longer and contains it (same semantics as the original inner loop).
		for _, otherText := range textsByLine[match.LineNumber] {
			if otherText != match.Text &&
				len(otherText) > len(match.Text) &&
				strings.Contains(otherText, match.Text) {
				shouldKeep = false
				break
			}
		}

		if shouldKeep {
			deduplicated = append(deduplicated, match)
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
