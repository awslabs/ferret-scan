// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"ferret-scan/internal/config"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Validator implements the detector.Validator interface for detecting
// intellectual property identifiers and references using regex patterns and contextual analysis.
// Internal URL detection is configuration-driven and requires explicit pattern configuration.
type Validator struct {
	// Regex patterns for different types of intellectual property identifiers
	patternPatent      string
	patternTrademark   string
	patternCopyright   string
	patternTradeSecret string

	// Compiled regex patterns
	regexPatent      *regexp.Regexp
	regexTrademark   *regexp.Regexp
	regexCopyright   *regexp.Regexp
	regexTradeSecret *regexp.Regexp

	// Keywords that suggest an intellectual property context
	positiveKeywords []string

	// Keywords that suggest this is not intellectual property
	negativeKeywords []string

	// Internal URL patterns to detect
	internalURLPatterns []string
	regexInternalURLs   []*regexp.Regexp

	// Track if internal URL patterns were configured
	internalURLPatternsConfigured bool

	// Legal notice reconstruction configuration
	legalNoticeConfig LegalNoticeConfig

	// Observability
	observer *observability.StandardObserver
}

// LegalNoticeAnalysis contains the results of analyzing whether multiple IP patterns
// form a coherent legal notice that should be reconstructed into a single finding
type LegalNoticeAnalysis struct {
	// IsLegalNotice indicates if the patterns appear to form a coherent legal notice
	IsLegalNotice bool

	// NoticeType classifies the type of legal notice detected
	NoticeType string // "copyright_notice", "confidentiality_statement", "mixed_notice", "trademark_notice"

	// Confidence represents how confident we are that this is a legal notice (0.0 to 1.0)
	Confidence float64

	// ProximityScore measures how close the patterns are to each other (0.0 to 1.0)
	ProximityScore float64

	// SemanticGrouping lists the types of IP patterns that were found together
	SemanticGrouping []string

	// ShouldReconstruct indicates the final decision on whether to reconstruct
	ShouldReconstruct bool

	// ReconstructionReason explains why the decision was made
	ReconstructionReason string
}

// LegalNoticeConfig contains configuration for legal notice reconstruction behavior
type LegalNoticeConfig struct {
	// Enabled controls whether legal notice reconstruction is active
	Enabled bool

	// ProximityThreshold is the maximum character distance for patterns to be considered related
	ProximityThreshold int

	// ConfidenceBoosts define confidence increases for different reconstruction scenarios
	ConfidenceBoosts map[string]float64

	// MaxConfidence caps the maximum confidence for reconstructed legal notices
	MaxConfidence float64

	// MinConfidenceThreshold filters out findings below this confidence level
	MinConfidenceThreshold float64

	// LegalNoticePatterns defines which pattern combinations indicate legal notices
	LegalNoticePatterns []string
}

// Internal configuration constants for legal notice reconstruction
// These are sensible defaults based on real-world legal notice patterns
// and can be adjusted based on user feedback without exposing configuration complexity
const (
	// Default proximity threshold in characters - patterns within this distance
	// are considered potentially related for legal notice reconstruction
	DefaultProximityThreshold = 100

	// Maximum confidence cap to maintain some uncertainty in reconstructed findings
	DefaultMaxConfidence = 98.0

	// Minimum confidence threshold - findings below this are filtered out
	DefaultMinConfidenceThreshold = 10.0

	// Confidence boost amounts for different legal notice patterns
	DefaultLegalNoticeBoost     = 8.0 // General legal notice reconstruction boost
	DefaultRepeatedMarkerBoost  = 5.0 // Boost for repeated same markers (e.g., multiple "Confidential")
	DefaultCopyrightNoticeBoost = 6.0 // Boost for copyright + other markers
	DefaultMixedNoticeBoost     = 7.0 // Boost for complex legal notices with multiple IP types
	DefaultTrademarkNoticeBoost = 5.5 // Boost for trademark + confidential combinations
	DefaultFullNoticeBoost      = 9.0 // Boost for comprehensive legal notices (copyright + confidential + trademark)

	// Proximity score thresholds for decision making
	ProximityCloseThreshold  = 0.8 // Very close - likely same legal notice
	ProximityMediumThreshold = 0.4 // Medium distance - analyze semantic relationship
	ProximityFarThreshold    = 0.1 // Far apart - likely distinct items

	// Confidence thresholds for reconstruction decisions
	ReconstructionMinConfidence      = 30.0 // Minimum confidence to consider reconstruction
	ReconstructionGoodConfidence     = 60.0 // Good confidence threshold
	ReconstructionMediumConfidence   = 45.0 // Medium confidence threshold
	ReconstructionMinProximity       = 0.2  // Minimum proximity score for reconstruction
	ReconstructionGoodProximity      = 0.6  // Good proximity threshold
	ReconstructionExcellentProximity = 0.8  // Excellent proximity threshold

	// Same-line analysis thresholds
	SameLineProximityThreshold = 80.0 // Character span threshold within a line
	SameLineMinimumScore       = 0.6  // Minimum proximity score for same-line matches

	// Semantic analysis boosts
	SemanticFullLegalNoticeBoost       = 35.0  // Boost for full legal notice patterns
	SemanticCopyrightPatternBoost      = 25.0  // Boost for copyright + other patterns
	SemanticAllRightsReservedBoost     = 30.0  // Boost for "all rights reserved" phrases
	SemanticTrademarkPatternBoost      = 20.0  // Boost for trademark patterns
	SemanticRepeatedConfidentialBoost  = 15.0  // Boost for repeated confidential markers
	SemanticCorporateConfidentialBoost = 18.0  // Boost for corporate confidentiality
	SemanticLegalDisclaimerBoost       = 22.0  // Boost for legal disclaimer language
	SemanticPatentConfidentialBoost    = 10.0  // Boost for patent + confidential (weaker)
	SemanticDistinctItemsPenalty       = -20.0 // Penalty for explicitly distinct items

	// Multi-IP type bonuses
	MultiIPTypeThreeOrMoreBonus = 15.0 // Bonus for 3+ IP types in legal notice
	MultiIPTypeTwoBonus         = 8.0  // Bonus for 2 IP types in legal notice
	SameLineBonus               = 10.0 // Bonus for same-line matches

	// Proximity-based confidence adjustments
	MaxProximityBonus    = 5.0 // Maximum boost from proximity score (5% for perfect proximity)
	PoorProximityPenalty = 0.5 // Multiply confidence by this for poor proximity
)

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting intellectual property references.
// Internal URL patterns start empty and must be configured via the Configure method.
func NewValidator() *Validator {
	v := &Validator{
		// Patent pattern: US patent numbers (e.g., US9123456, US 9,123,456) - case insensitive
		patternPatent: `(?i)\b(US|EP|JP|CN|WO)[ -]?(\d{1,3}[,.]?\d{3}[,.]?\d{3}|\d{1,3}[,.]?\d{3}[,.]?\d{2}[A-Z]\d?)\b`,

		// Trademark pattern: ™, ®, or phrases like "TM" or "Registered Trademark" - case insensitive
		patternTrademark: `(?i)\b(\w+\s*[™®]|\w+\s*\(TM\)|\w+\s*\(R\)|\w+\s+Trademark|\w+\s+Registered\s+Trademark)\b`,

		// Copyright pattern: © or (c) followed by year and name - case insensitive
		patternCopyright: `(?i)(©|\(c\)|\(C\)|Copyright|\bCopyright\b)\s*\d{4}[-,]?(\d{4})?\s+[A-Za-z0-9\s\.,]+`,

		// Trade secret pattern: confidential markings and classifications - case insensitive
		patternTradeSecret: `(?i)\b(Confidential|Trade\s+Secret|Proprietary|Company\s+Confidential|Internal\s+Use\s+Only|Restricted|Classified)\b`, // pragma: allowlist secret

		positiveKeywords: []string{
			"patent", "trademark", "copyright", "intellectual property", "IP rights",
			"proprietary", "confidential", "trade secret", "invention", "inventor",
			"assignee", "priority date", "filing date", "granted", "registered",
			"USPTO", "EPO", "WIPO", "infringement", "license", "royalty",
			"exclusive rights", "protected", "patented", "copyrighted", "all rights reserved",
			"unauthorized use", "proprietary technology", "proprietary algorithm",
			"proprietary process", "proprietary method", "proprietary formula",
			"confidentiality agreement", "NDA", "non-disclosure", "trade dress",
			"service mark", "industrial design", "mask work", "sui generis",
		},
		negativeKeywords: []string{
			"example", "sample", "test", "dummy", "placeholder", "template",
			"demo", "mock", "fake", "random", "tutorial", "learning",
			"public domain", "open source", "creative commons", "MIT license",
			"GPL", "Apache license", "BSD license", "free to use", "royalty-free",
			"no warranty", "as-is", "disclaimer", "not protected",
		},
		// Initialize internal URL patterns as empty - will be configured later
		internalURLPatterns:           []string{},
		internalURLPatternsConfigured: false,

		// Initialize legal notice reconstruction with sensible defaults using internal constants
		legalNoticeConfig: LegalNoticeConfig{
			Enabled:                true,
			ProximityThreshold:     DefaultProximityThreshold,
			MaxConfidence:          DefaultMaxConfidence,
			MinConfidenceThreshold: DefaultMinConfidenceThreshold,
			ConfidenceBoosts: map[string]float64{
				"legal_notice":     DefaultLegalNoticeBoost,
				"repeated_marker":  DefaultRepeatedMarkerBoost,
				"copyright_notice": DefaultCopyrightNoticeBoost,
				"mixed_notice":     DefaultMixedNoticeBoost,
				"trademark_notice": DefaultTrademarkNoticeBoost,
				"full_notice":      DefaultFullNoticeBoost,
			},
			LegalNoticePatterns: []string{
				"copyright_with_confidential", // © + confidential markers
				"copyright_with_trademark",    // © + trademark markers
				"full_legal_notice",           // © + rights reserved + confidential + trademark
				"repeated_confidential",       // multiple confidential markers
				"trademark_with_confidential", // trademark + confidential
				"all_rights_reserved",         // "all rights reserved" phrases
				"standard_copyright_notice",   // standard copyright notice structure
				"corporate_confidential",      // corporate confidentiality statements
				"legal_disclaimer",            // legal disclaimer language
			},
		},
	}

	// Compile the regex patterns once at initialization
	v.regexPatent = regexp.MustCompile(v.patternPatent)
	v.regexTrademark = regexp.MustCompile(v.patternTrademark)
	v.regexCopyright = regexp.MustCompile(v.patternCopyright)
	v.regexTradeSecret = regexp.MustCompile(v.patternTradeSecret)

	// Internal URL patterns will be compiled when configured
	v.regexInternalURLs = []*regexp.Regexp{}

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Configure configures the validator with custom settings from the configuration
func (v *Validator) Configure(cfg *config.Config) {
	// Check if we have validator-specific configuration
	if cfg == nil || cfg.Validators == nil {
		// No configuration available - log that no patterns are configured
		v.logNoInternalURLPatterns("no configuration available")
		return
	}

	// Get intellectual property validator config if it exists
	ipConfig, ok := cfg.Validators["intellectual_property"]
	if !ok {
		// No intellectual property configuration section - log that no patterns are configured
		v.logNoInternalURLPatterns("no intellectual_property configuration section")
		return
	}

	// Update internal URL patterns if provided
	if urls, ok := ipConfig["internal_urls"].([]any); ok {
		// Set configuration flag to true when internal_urls section is present
		v.internalURLPatternsConfigured = true

		// Handle empty internal_urls array - log informational message
		if len(urls) == 0 {
			v.internalURLPatterns = []string{}
			v.logNoInternalURLPatterns("empty internal_urls array configured")
			v.compileInternalURLPatterns()
			return
		}

		validPatterns := []string{}
		invalidCount := 0

		// Validate each pattern before storing
		for _, url := range urls {
			if urlStr, ok := url.(string); ok {
				// Add case-insensitive flag if not already present
				processedPattern := v.ensureCaseInsensitive(urlStr)

				// Validate regex pattern using regexp.Compile()
				if _, err := regexp.Compile(processedPattern); err != nil {
					// Log warning for invalid pattern but continue with valid ones
					if v.observer != nil && v.observer.DebugObserver != nil {
						v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Invalid internal URL pattern '%s': %v", urlStr, err))
						// Log specific invalid patterns with error details in debug mode
						v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Skipping invalid regex pattern: '%s' - Error: %v", urlStr, err))
					}

					// Also log to stderr in debug mode for comprehensive logging
					if os.Getenv("FERRET_DEBUG") == "1" {
						fmt.Fprintf(os.Stderr, "[DEBUG] Intellectual Property Validator: Invalid internal URL pattern\n")
						fmt.Fprintf(os.Stderr, "[DEBUG]   Pattern: %s\n", urlStr)
						fmt.Fprintf(os.Stderr, "[DEBUG]   Error: %v\n", err)
						fmt.Fprintf(os.Stderr, "[DEBUG]   Action: Skipping pattern and continuing with valid patterns\n")
					}
					invalidCount++
					continue
				}
				validPatterns = append(validPatterns, processedPattern)
			}
		}

		// Store only valid patterns
		v.internalURLPatterns = validPatterns

		// Log number of successfully loaded patterns in debug mode (requirement 7.2)
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Internal URL pattern validation: %d valid, %d invalid patterns", len(validPatterns), invalidCount))
			if len(validPatterns) > 0 {
				// Requirement 7.2: Log the number of active patterns
				v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Successfully loaded %d internal URL patterns", len(validPatterns)))
				// Requirement 7.1: Log the loaded internal URL patterns at startup
				for i, pattern := range validPatterns {
					v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("  Active pattern %d: %s", i+1, pattern))
				}
			}
			// Requirement 7.3: Log any skipped invalid patterns
			if invalidCount > 0 {
				v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Skipped %d invalid internal URL patterns during configuration", invalidCount))
			}
		}

		// Also log to stderr in debug mode for comprehensive logging
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[DEBUG] Intellectual Property Validator: Loaded %d valid internal URL patterns (%d invalid patterns skipped)\n", len(validPatterns), invalidCount)
			if len(validPatterns) > 0 {
				fmt.Fprintf(os.Stderr, "[DEBUG] Active internal URL patterns:\n")
				for i, pattern := range validPatterns {
					fmt.Fprintf(os.Stderr, "[DEBUG]   %d: %s\n", i+1, pattern)
				}
			}
		}

		// Handle case where all configured patterns are invalid - log warning
		if len(validPatterns) == 0 && len(urls) > 0 {
			v.logNoInternalURLPatterns("all configured internal URL patterns are invalid")
		}

		// Recompile patterns (only valid ones now)
		v.compileInternalURLPatterns()
	} else {
		// No internal_urls configuration provided - detect when no patterns are configured
		// Set configuration flag appropriately based on config presence
		if !v.internalURLPatternsConfigured {
			v.logNoInternalURLPatterns("no internal URL patterns configured")

			// Log to stderr in debug mode for comprehensive audit trail
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[INFO] Intellectual Property Validator: No internal URL patterns configured\n")
				fmt.Fprintf(os.Stderr, "[INFO] Internal URL detection is disabled. Configure 'validators.intellectual_property.internal_urls' to enable.\n")
			}
		}
	}

	// Update IP patterns if provided
	if patterns, ok := ipConfig["intellectual_property_patterns"].(map[string]any); ok {
		// Update patent pattern if provided
		if pattern, ok := patterns["patent"].(string); ok && pattern != "" {
			v.patternPatent = v.ensureCaseInsensitive(pattern)
			v.regexPatent = regexp.MustCompile(v.patternPatent)
		}

		// Update trademark pattern if provided
		if pattern, ok := patterns["trademark"].(string); ok && pattern != "" {
			v.patternTrademark = v.ensureCaseInsensitive(pattern)
			v.regexTrademark = regexp.MustCompile(v.patternTrademark)
		}

		// Update copyright pattern if provided
		if pattern, ok := patterns["copyright"].(string); ok && pattern != "" {
			v.patternCopyright = v.ensureCaseInsensitive(pattern)
			v.regexCopyright = regexp.MustCompile(v.patternCopyright)
		}

		// Update trade secret pattern if provided
		//  pragma: allowlist nextline secret
		if pattern, ok := patterns["trade_secret"].(string); ok && pattern != "" {
			//  pragma: allowlist nextline secret
			v.patternTradeSecret = v.ensureCaseInsensitive(pattern)
			//  pragma: allowlist nextline secret
			v.regexTradeSecret = regexp.MustCompile(v.patternTradeSecret)
		}
	}
}

// ensureCaseInsensitive adds the case-insensitive flag (?i) to a regex pattern
// if it doesn't already have case sensitivity flags
func (v *Validator) ensureCaseInsensitive(pattern string) string {
	// Check if pattern already has case sensitivity flags
	// Look for (?i), (?-i), (?s), (?m), etc. at the beginning
	if len(pattern) >= 4 && pattern[0] == '(' && pattern[1] == '?' {
		// Pattern already has flags, don't modify
		return pattern
	}

	// Add case-insensitive flag
	return "(?i)" + pattern
}

// logNoInternalURLPatterns logs informational messages when no internal URL patterns are active
// Implements requirements 6.1, 6.2, 6.3, 6.4, 6.5 for configuration status tracking and logging
func (v *Validator) logNoInternalURLPatterns(reason string) {
	message := "Internal URL detection disabled: " + reason + ". Configure 'validators.intellectual_property.internal_urls' to enable internal URL detection."

	// Log to debug observer for detailed logging
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("intellectualproperty", message)

		// Include configuration guidance in verbose mode warnings (requirement 6.4)
		guidance := "Example configuration:\n" +
			"validators:\n" +
			"  intellectual_property:\n" +
			"    internal_urls:\n" +
			"      - \"http[s]?:\\\\/\\\\/.*\\\\.internal\\\\..*\"    # Corporate internal domains\n" +
			"      - \"http[s]?:\\\\/\\\\/.*\\\\.corp\\\\..*\"       # Corporate domains\n" +
			"      - \"http[s]?:\\\\/\\\\/s3\\\\.amazonaws\\\\.com\" # AWS S3 buckets\n" +
			"      - \"http[s]?:\\\\/\\\\/.*\\\\.s3\\\\..*\"         # S3-style URLs\n" +
			"      - \"http[s]?:\\\\/\\\\/intranet\\\\..*\"         # Intranet sites\n" +
			"Common patterns by environment:\n" +
			"  AWS: \"http[s]?:\\\\/\\\\/.*\\\\.amazonaws\\\\.com\", \"http[s]?:\\\\/\\\\/.*\\\\.s3\\\\..*\"\n" +
			"  Azure: \"http[s]?:\\\\/\\\\/.*\\\\.azurewebsites\\\\.net\", \"http[s]?:\\\\/\\\\/.*\\\\.blob\\\\.core\\\\.windows\\\\.net\"\n" +
			"  GCP: \"http[s]?:\\\\/\\\\/.*\\\\.googleapis\\\\.com\", \"http[s]?:\\\\/\\\\/.*\\\\.appspot\\\\.com\""
		v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Configuration guidance for internal URL patterns:\n%s", guidance))

		// Also log configuration guidance to stderr in verbose/debug mode
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] Configuration guidance for internal URL patterns:\n")
			fmt.Fprintf(os.Stderr, "%s\n", guidance)
		}
	}

	// Handle different logging scenarios based on reason
	switch reason {
	case "all configured internal URL patterns are invalid":
		// Requirement 6.3: Warning logging when all configured patterns are invalid
		// Requirement 6.5: Warnings appear even in quiet mode as it's important configuration information
		fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
		// Also include configuration guidance in the warning for quiet mode
		fmt.Fprintf(os.Stderr, "Configure valid regex patterns in 'validators.intellectual_property.internal_urls' to enable internal URL detection.\n")

	case "empty internal_urls array configured":
		// Requirement 6.2: Informational logging when patterns array is empty
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] %s\n", message)
		}

	case "no internal URL patterns configured":
		// Requirement 6.1: Informational logging when no internal URL patterns are configured
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] %s\n", message)
		}

	case "all internal URL patterns failed to compile during regex compilation":
		// Additional case for compilation failures - treat as warning
		fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
		fmt.Fprintf(os.Stderr, "Check regex syntax in 'validators.intellectual_property.internal_urls' configuration.\n")

	default:
		// Default case - log as informational in debug mode
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] %s\n", message)
		}
	}
}

// compileInternalURLPatterns compiles the internal URL patterns into regex objects
// with defensive validation and error handling
func (v *Validator) compileInternalURLPatterns() {
	// Handle empty pattern arrays gracefully (len() for nil slices is defined as zero)
	if len(v.internalURLPatterns) == 0 {
		v.regexInternalURLs = []*regexp.Regexp{}
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("intellectualproperty", "No internal URL patterns to compile - empty pattern array")
		}
		return
	}

	// Pre-allocate slice with exact capacity for better memory efficiency
	v.regexInternalURLs = make([]*regexp.Regexp, 0, len(v.internalURLPatterns))
	compiledCount := 0
	failedCount := 0

	for i, pattern := range v.internalURLPatterns {
		// Skip empty patterns gracefully
		if pattern == "" {
			failedCount++
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Skipping empty internal URL pattern at index %d", i+1))
			}
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[WARNING] Intellectual Property Validator: Empty internal URL pattern at index %d - skipping\n", i+1)
			}
			continue
		}

		// Add error handling for pattern compilation failures
		regex, err := regexp.Compile(pattern)
		if err != nil {
			// Skip patterns that fail to compile rather than crashing
			failedCount++

			// Log compilation errors for debugging with enhanced context
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Failed to compile internal URL pattern %d: '%s' - Error: %v", i+1, pattern, err))
				// Provide additional context about the error type
				if strings.Contains(err.Error(), "invalid") {
					v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Pattern %d contains invalid regex syntax - check for unescaped special characters", i+1))
				}
			}

			// Also log to stderr in debug mode for comprehensive error tracking
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[ERROR] Intellectual Property Validator: Failed to compile internal URL pattern\n")
				fmt.Fprintf(os.Stderr, "[ERROR]   Pattern %d: %s\n", i+1, pattern)
				fmt.Fprintf(os.Stderr, "[ERROR]   Error: %v\n", err)
				fmt.Fprintf(os.Stderr, "[ERROR]   Action: Skipping pattern and continuing with remaining patterns\n")
				// Provide helpful context for common regex errors
				if strings.Contains(err.Error(), "missing closing") {
					fmt.Fprintf(os.Stderr, "[ERROR]   Hint: Check for unmatched brackets or parentheses in the pattern\n")
				} else if strings.Contains(err.Error(), "invalid") {
					fmt.Fprintf(os.Stderr, "[ERROR]   Hint: Check for unescaped special regex characters\n")
				}
			}
			continue
		}

		// Successfully compiled pattern
		v.regexInternalURLs = append(v.regexInternalURLs, regex)
		compiledCount++
	}

	// Log compilation summary in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Internal URL pattern compilation complete: %d successful, %d failed", compiledCount, failedCount))
		if compiledCount > 0 {
			v.observer.DebugObserver.LogDetail("intellectualproperty", fmt.Sprintf("Successfully compiled %d internal URL regex patterns", compiledCount))
		}
	}

	// Also log to stderr in debug mode for comprehensive audit trail
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Intellectual Property Validator: Pattern compilation summary\n")
		fmt.Fprintf(os.Stderr, "[DEBUG]   Total patterns: %d\n", len(v.internalURLPatterns))
		fmt.Fprintf(os.Stderr, "[DEBUG]   Successfully compiled: %d\n", compiledCount)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Failed to compile: %d\n", failedCount)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Active regex patterns: %d\n", len(v.regexInternalURLs))
	}

	// If all patterns failed to compile, log a warning
	if compiledCount == 0 && len(v.internalURLPatterns) > 0 {
		v.logNoInternalURLPatterns("all internal URL patterns failed to compile during regex compilation")
	}
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]any)
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("ip_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("ip_validator", "validate_file", filePath)
		}
	}

	// Intellectual property validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]any{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Intellectual property validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for intellectual property references
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Use line-based grouping for legal notice reconstruction
	lineMatches := v.detectPatternsByLine(content, originalPath)

	// Process line matches with legal notice reconstruction logic
	processedMatches := v.processLineMatches(lineMatches)

	return processedMatches, nil
}

// processLineMatches orchestrates the legal notice reconstruction logic
// Implements the decision tree: single match → pass through, multiple matches → analyze and reconstruct or keep separate
func (v *Validator) processLineMatches(lineMatches map[int][]detector.Match) []detector.Match {
	var finalMatches []detector.Match

	// Process each line's matches
	for lineNum, matches := range lineMatches {
		if len(matches) == 0 {
			// No matches on this line, skip
			continue
		} else if len(matches) == 1 {
			// Single match - pass through without modification
			finalMatches = append(finalMatches, matches[0])
		} else {
			// Multiple matches - analyze for legal notice reconstruction
			analysis := v.analyzeLegalNoticeContext(matches)

			if analysis.ShouldReconstruct {
				// Reconstruct fragmented legal notice into single finding with graceful degradation
				reconstructed, reconstructionError := v.reconstructLegalNoticeWithFallback(matches)

				if reconstructionError == nil && reconstructed.Confidence > 0 && reconstructed.Text != "" {
					// Successful reconstruction
					finalMatches = append(finalMatches, reconstructed)

					// Log reconstruction decision in debug mode
					if v.observer != nil && v.observer.DebugObserver != nil {
						v.observer.DebugObserver.LogDetail("intellectualproperty",
							fmt.Sprintf("Line %d: Reconstructed %d matches into single legal notice (confidence: %.1f%%)",
								lineNum+1, len(matches), reconstructed.Confidence))

						// Log the reconstruction success with details
						if reconstructed.Metadata != nil {
							if boost, ok := reconstructed.Metadata["confidence_boost"].(float64); ok {
								v.observer.DebugObserver.LogDetail("intellectualproperty",
									fmt.Sprintf("  Confidence boost: +%.1f%%, Reconstruction type: %s",
										boost, reconstructed.Metadata["reconstruction_type"]))
							}
						}
					}
				} else {
					// Graceful degradation: if reconstruction failed, keep original matches
					finalMatches = append(finalMatches, matches...)

					if v.observer != nil && v.observer.DebugObserver != nil {
						errorMsg := "unknown error"
						if reconstructionError != nil {
							errorMsg = reconstructionError.Error()
						} else if reconstructed.Confidence <= 0 {
							errorMsg = "zero confidence"
						} else if reconstructed.Text == "" {
							errorMsg = "empty text"
						}

						v.observer.DebugObserver.LogDetail("intellectualproperty",
							fmt.Sprintf("Line %d: Reconstruction failed (%s), keeping %d separate matches",
								lineNum+1, errorMsg, len(matches)))
						v.observer.DebugObserver.LogDetail("intellectualproperty",
							fmt.Sprintf("  Graceful degradation applied: Falling back to original matches"))
					}
				}
			} else {
				// Keep as separate findings (distinct IP items)
				finalMatches = append(finalMatches, matches...)

				// Log decision to keep separate in debug mode
				if v.observer != nil && v.observer.DebugObserver != nil {
					v.observer.DebugObserver.LogDetail("intellectualproperty",
						fmt.Sprintf("Line %d: Keeping %d matches separate - %s",
							lineNum+1, len(matches), analysis.ReconstructionReason))

					// Log additional context for the decision
					v.observer.DebugObserver.LogDetail("intellectualproperty",
						fmt.Sprintf("  Analysis: proximity=%.2f, confidence=%.1f%%, legal_notice=%v",
							analysis.ProximityScore, analysis.Confidence, analysis.IsLegalNotice))
				}
			}
		}
	}

	// Log final processing summary with detailed statistics
	if v.observer != nil && v.observer.DebugObserver != nil {
		totalOriginalMatches := 0
		linesWithMultipleMatches := 0
		reconstructedCount := 0

		for _, matches := range lineMatches {
			totalOriginalMatches += len(matches)
			if len(matches) > 1 {
				linesWithMultipleMatches++
			}
		}

		// Count reconstructed matches by checking metadata
		for _, match := range finalMatches {
			if match.Metadata != nil {
				if source, ok := match.Metadata["source"].(string); ok && source == "legal_notice_reconstruction" {
					reconstructedCount++
				}
			}
		}

		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("Legal notice processing complete: %d original matches → %d final matches",
				totalOriginalMatches, len(finalMatches)))

		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("  Lines with multiple matches: %d", linesWithMultipleMatches))

		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("  Reconstructed legal notices: %d", reconstructedCount))

		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("  Matches kept separate: %d", len(finalMatches)-reconstructedCount))

		// Calculate reduction percentage
		if totalOriginalMatches > 0 {
			reductionPercent := float64(totalOriginalMatches-len(finalMatches)) / float64(totalOriginalMatches) * 100
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("  Match reduction: %.1f%% (%d fewer matches)", reductionPercent, totalOriginalMatches-len(finalMatches)))
		}

		// Also log summary to stderr in debug mode
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[DEBUG] Legal Notice Processing Summary:\n")
			fmt.Fprintf(os.Stderr, "[DEBUG]   %d original matches → %d final matches\n", totalOriginalMatches, len(finalMatches))
			fmt.Fprintf(os.Stderr, "[DEBUG]   %d legal notices reconstructed, %d matches kept separate\n",
				reconstructedCount, len(finalMatches)-reconstructedCount)
		}
	}

	return finalMatches
}

// detectPatternsByLine detects IP patterns and groups matches by line number
func (v *Validator) detectPatternsByLine(content string, originalPath string) map[int][]detector.Match {
	lineMatches := make(map[int][]detector.Match)

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Check for internal URLs using pre-compiled regex patterns
		for _, regex := range v.regexInternalURLs {
			foundMatches := regex.FindAllString(line, -1)

			for _, match := range foundMatches {
				confidence, checks := v.CalculateConfidence(match)

				// Create context info for the line
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract some context around the match in the line
				matchIndex := strings.Index(line, match)
				if matchIndex >= 0 {
					start := max(0, matchIndex-50)
					end := min(len(line), matchIndex+len(match)+50)

					contextInfo.BeforeText = line[start:matchIndex]
					contextInfo.AfterText = line[matchIndex+len(match) : end]
				}

				// Analyze context and adjust confidence
				contextImpact := v.AnalyzeContext(match, contextInfo)
				confidence += contextImpact

				// Ensure confidence stays within bounds
				if confidence > 100 {
					confidence = 100
				} else if confidence < 0 {
					confidence = 0
				}

				contextInfo.ConfidenceImpact = contextImpact

				// Skip matches with 0% confidence - they are false positives
				if confidence <= 0 {
					continue
				}

				lineMatches[lineNum] = append(lineMatches[lineNum], detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "INTELLECTUAL_PROPERTY",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "INTELLECTUAL_PROPERTY",
					Context:    contextInfo,
					Metadata: map[string]any{
						"ip_type":           "internal_url",
						"validation_checks": checks,
						"context_impact":    contextImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
			}
		}

		// Check for IP patterns using individual regex patterns
		ipPatterns := map[string]*regexp.Regexp{
			"patent":       v.regexPatent,
			"trademark":    v.regexTrademark,
			"copyright":    v.regexCopyright,
			"trade_secret": v.regexTradeSecret,
		}

		for ipType, regex := range ipPatterns {
			if regex == nil {
				continue
			}
			foundMatches := regex.FindAllString(line, -1)

			for _, match := range foundMatches {

				confidence, checks := v.CalculateConfidence(match)

				// Create context info for the line
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract some context around the match in the line
				matchIndex := strings.Index(line, match)
				if matchIndex >= 0 {
					start := max(0, matchIndex-50)
					end := min(len(line), matchIndex+len(match)+50)

					contextInfo.BeforeText = line[start:matchIndex]
					contextInfo.AfterText = line[matchIndex+len(match) : end]
				}

				// Analyze context and adjust confidence
				contextImpact := v.AnalyzeContext(match, contextInfo)
				confidence += contextImpact

				// Ensure confidence stays within bounds
				if confidence > 100 {
					confidence = 100
				} else if confidence < 0 {
					confidence = 0
				}

				contextInfo.ConfidenceImpact = contextImpact

				lineMatches[lineNum] = append(lineMatches[lineNum], detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "INTELLECTUAL_PROPERTY",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "INTELLECTUAL_PROPERTY",
					Context:    contextInfo,
					Metadata: map[string]any{
						"ip_type":           ipType,
						"validation_checks": checks,
						"context_impact":    contextImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
			}
		}
	}

	return lineMatches
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

// CalculateConfidence calculates the confidence score for a potential intellectual property reference
// This method satisfies the detector.Validator interface but delegates to calculateConfidenceWithType
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Determine the type of IP from the match
	matchType := v.determineIPType(match)
	return v.calculateConfidenceWithType(match, matchType)
}

// determineIPType determines the type of intellectual property from the match
func (v *Validator) determineIPType(match string) string {
	if v.regexPatent.MatchString(match) {
		return "PATENT"
	} else if v.regexTrademark.MatchString(match) {
		return "TRADEMARK"
	} else if v.regexCopyright.MatchString(match) {
		return "COPYRIGHT"
	} else if v.regexTradeSecret.MatchString(match) {
		return "TRADE_SECRET"
	}
	return "UNKNOWN"
}

// calculateConfidenceWithType calculates confidence with a known IP type
func (v *Validator) calculateConfidenceWithType(match string, matchType string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":             true,
		"context_relevant":   false,
		"not_common_pattern": true,
		"not_example":        true,
	}

	confidence := 80.0 // Start with a base confidence

	// Specific checks based on IP type
	switch matchType {
	case "PATENT":
		return v.calculatePatentConfidence(match, checks)
	case "TRADEMARK":
		return v.calculateTrademarkConfidence(match, checks)
	case "COPYRIGHT":
		return v.calculateCopyrightConfidence(match, checks)
	case "TRADE_SECRET":
		return v.calculateTradeSecretConfidence(match, checks)
	default:
		return confidence, checks
	}
}

// calculatePatentConfidence calculates confidence for patent matches
func (v *Validator) calculatePatentConfidence(match string, checks map[string]bool) (float64, map[string]bool) {
	confidence := 80.0

	// Check for common example patent numbers
	examplePatents := map[string]bool{
		"US1234567":    true,
		"US 1,234,567": true,
		"EP1234567":    true,
		"EP 1,234,567": true,
		"WO1234567":    true,
		"WO 1,234,567": true,
	}

	// Clean the match for comparison
	cleanMatch := strings.ReplaceAll(strings.ReplaceAll(match, " ", ""), ",", "")

	if examplePatents[match] || examplePatents[cleanMatch] {
		confidence -= 30
		checks["not_example"] = false
	}

	// Check for valid patent office prefix
	validPrefix := false
	prefixes := []string{"US", "EP", "JP", "CN", "WO"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(cleanMatch, prefix) {
			validPrefix = true
			break
		}
	}

	if !validPrefix {
		confidence -= 20
		checks["format"] = false
	}

	return confidence, checks
}

// calculateTrademarkConfidence calculates confidence for trademark matches
func (v *Validator) calculateTrademarkConfidence(match string, checks map[string]bool) (float64, map[string]bool) {
	confidence := 80.0

	// Check for common symbols
	if strings.Contains(match, "™") || strings.Contains(match, "®") {
		confidence += 10
	}

	// Check for example/placeholder trademarks
	exampleTrademarks := []string{"ExampleTM", "SampleTM", "TestTM", "DemoTM"}
	for _, example := range exampleTrademarks {
		if strings.Contains(match, example) {
			confidence -= 30
			checks["not_example"] = false
			break
		}
	}

	return confidence, checks
}

// calculateCopyrightConfidence calculates confidence for copyright matches
func (v *Validator) calculateCopyrightConfidence(match string, checks map[string]bool) (float64, map[string]bool) {
	confidence := 80.0

	// Check for common symbols
	if strings.Contains(match, "©") {
		confidence += 10
	}

	// Check for valid year format
	yearPattern := regexp.MustCompile(`\d{4}(-\d{4})?`)
	if !yearPattern.MatchString(match) {
		confidence -= 20
		checks["format"] = false
	}

	// Check for example/placeholder copyrights
	exampleCopyrights := []string{"Example Company", "Sample Company", "Test Company", "Demo Company"}
	for _, example := range exampleCopyrights {
		if strings.Contains(match, example) {
			confidence -= 30
			checks["not_example"] = false
			break
		}
	}

	return confidence, checks
}

// calculateTradeSecretConfidence calculates confidence for trade secret matches
func (v *Validator) calculateTradeSecretConfidence(match string, checks map[string]bool) (float64, map[string]bool) {
	confidence := 70.0 // Start slightly lower for trade secrets as they're more context-dependent

	// Check for strong confidentiality markers
	strongMarkers := []string{"Confidential", "Trade Secret", "Proprietary", "Company Confidential", "Privileged"}
	for _, marker := range strongMarkers {
		if strings.Contains(match, marker) {
			confidence += 10
			break
		}
	}

	// Check for example/placeholder confidentiality
	exampleMarkers := []string{"Example Confidential", "Sample Confidential", "Test Confidential"}
	for _, example := range exampleMarkers {
		if strings.Contains(match, example) {
			confidence -= 30
			checks["not_example"] = false
			break
		}
	}

	return confidence, checks
}

// calculateProximityScore measures the distance between IP patterns to determine
// if they are close enough to be part of the same legal notice
// Returns a score from 0.0 (far apart) to 1.0 (very close)
// Optimized for performance with bounds checking and error handling
func (v *Validator) calculateProximityScore(matches []detector.Match) float64 {
	// Bounds checking for edge cases
	if len(matches) == 0 {
		return 0.0 // No matches have no proximity
	}

	if len(matches) == 1 {
		return 1.0 // Single match has perfect proximity
	}

	// Performance optimization: pre-allocate slices with known capacity
	positions := make([]int, 0, len(matches))

	// Special case: if all matches are on the same line, they're likely part of the same legal notice
	allSameLine := true
	firstLineNum := matches[0].LineNumber

	// Single pass to check same line and collect positions
	for _, match := range matches {
		if match.LineNumber != firstLineNum {
			allSameLine = false
		}

		// Calculate position with error handling
		pos := v.calculateCharacterPositionSafe(match)
		positions = append(positions, pos)
	}

	if allSameLine {
		// Performance optimization: check for overlapping matches first (fastest check)
		for i, match1 := range matches {
			for j := i + 1; j < len(matches); j++ { // Avoid duplicate comparisons
				match2 := matches[j]
				if strings.Contains(match1.Text, match2.Text) || strings.Contains(match2.Text, match1.Text) {
					// One match contains another - they're definitely related
					return 0.9 // High proximity for overlapping matches
				}
			}
		}

		// Calculate positions within the line with bounds checking
		if len(positions) == 0 {
			return SameLineMinimumScore // Fallback for edge case
		}

		// Optimized min/max calculation in single pass
		minPos := positions[0]
		maxPos := positions[0]
		for i := 1; i < len(positions); i++ {
			pos := positions[i] % 100 // Get position within line
			if pos < minPos {
				minPos = pos
			}
			if pos > maxPos {
				maxPos = pos
			}
		}

		span := maxPos - minPos

		// Bounds checking for edge cases
		if span < 0 {
			span = 0 // Handle potential negative spans
		}

		if span == 0 {
			return 1.0
		}

		if float64(span) >= SameLineProximityThreshold {
			return SameLineMinimumScore // Still give some proximity for same-line matches
		}

		// Linear decay but with higher minimum score for same-line matches
		proximityScore := 1.0 - (float64(span) / SameLineProximityThreshold)

		// Bounds checking to ensure score stays within valid range
		if proximityScore < SameLineMinimumScore {
			proximityScore = SameLineMinimumScore // Minimum score for same-line matches
		} else if proximityScore > 1.0 {
			proximityScore = 1.0 // Cap at maximum
		}

		return proximityScore
	}

	// For multi-line matches, use optimized calculation
	if len(positions) == 0 {
		return 0.0 // Fallback for edge case
	}

	// Optimized min/max calculation in single pass
	minPos := positions[0]
	maxPos := positions[0]
	for i := 1; i < len(positions); i++ {
		pos := positions[i]
		if pos < minPos {
			minPos = pos
		}
		if pos > maxPos {
			maxPos = pos
		}
	}

	// Calculate the span (distance between furthest matches)
	span := maxPos - minPos

	// Bounds checking for edge cases
	if span < 0 {
		span = 0 // Handle potential negative spans
	}

	// Convert span to proximity score using configured threshold with bounds checking
	threshold := float64(v.legalNoticeConfig.ProximityThreshold)
	if threshold <= 0 {
		threshold = float64(DefaultProximityThreshold) // Fallback to default if invalid config
	}

	if span == 0 {
		return 1.0 // All matches at same position
	}

	if float64(span) >= threshold {
		return 0.0 // Beyond threshold, considered far apart
	}

	// Linear decay from 1.0 to 0.0 as span approaches threshold
	proximityScore := 1.0 - (float64(span) / threshold)

	// Bounds checking to ensure score stays within valid range
	if proximityScore < 0.0 {
		proximityScore = 0.0
	} else if proximityScore > 1.0 {
		proximityScore = 1.0
	}

	return proximityScore
}

// calculateCharacterPosition estimates the character position of a match within its line
// This is used for proximity analysis between matches
func (v *Validator) calculateCharacterPosition(match detector.Match) int {
	return v.calculateCharacterPositionSafe(match)
}

// calculateCharacterPositionSafe estimates the character position with bounds checking and error handling
// This is used for proximity analysis between matches with graceful degradation
func (v *Validator) calculateCharacterPositionSafe(match detector.Match) int {
	// Bounds checking for line number
	lineNumber := match.LineNumber
	if lineNumber < 1 {
		lineNumber = 1 // Ensure positive line number
	}

	// Get the full line from context if available
	if match.Context.FullLine != "" && match.Text != "" {
		// Find the position of the match text within the full line
		matchIndex := strings.Index(match.Context.FullLine, match.Text)
		if matchIndex >= 0 {
			// Bounds checking for position calculation
			lineOffset := (lineNumber - 1) * 100
			if lineOffset < 0 {
				lineOffset = 0 // Ensure non-negative offset
			}

			position := lineOffset + matchIndex

			// Bounds checking for final position
			if position < 0 {
				position = 0
			}

			return position
		}
	}

	// Fallback: use line number as rough position estimate with bounds checking
	fallbackPosition := (lineNumber - 1) * 100
	if fallbackPosition < 0 {
		fallbackPosition = 0 // Ensure non-negative position
	}

	return fallbackPosition
}

// determineProximityRelationship analyzes the proximity between matches and determines
// if they are close enough to be part of the same legal notice
func (v *Validator) determineProximityRelationship(matches []detector.Match) (bool, string) {
	if len(matches) <= 1 {
		return false, "single_match" // Single matches don't need proximity analysis
	}

	proximityScore := v.calculateProximityScore(matches)

	// Use internal configuration constants for proximity thresholds
	if proximityScore >= ProximityCloseThreshold {
		return true, "close_proximity"
	} else if proximityScore >= ProximityMediumThreshold {
		return true, "medium_proximity" // Still consider for reconstruction based on semantics
	} else if proximityScore >= ProximityFarThreshold {
		return false, "far_proximity"
	} else {
		return false, "very_far_proximity"
	}
}

// identifySemanticGroups analyzes matches to recognize common legal notice combinations
// and patterns that indicate they should be reconstructed into a single finding
// Optimized with bounds checking and error handling
func (v *Validator) identifySemanticGroups(matches []detector.Match) []string {
	// Bounds checking for edge cases
	if len(matches) == 0 {
		return []string{} // No matches, no semantic groups
	}

	if len(matches) == 1 {
		return []string{} // Single matches don't form semantic groups
	}

	// Pre-allocate with reasonable capacity for performance
	semanticGroups := make([]string, 0, 5)
	ipTypes := make(map[string]bool, 4) // Expect at most 4 IP types

	// Build combined context with bounds checking and performance optimization
	var contextBuilder strings.Builder
	contextBuilder.Grow(len(matches) * 50) // Pre-allocate reasonable capacity

	// Extract IP types and build combined context with error handling
	for _, match := range matches {
		// Safely extract IP type with bounds checking
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok && ipType != "" {
				ipTypes[ipType] = true
			}
		}

		// Safely combine context with bounds checking
		if match.Context.FullLine != "" {
			contextBuilder.WriteString(strings.ToLower(match.Context.FullLine))
			contextBuilder.WriteString(" ")
		}
	}

	fullContext := contextBuilder.String()

	// Pattern 1: Copyright + Confidential + Trademark (full legal notice)
	if ipTypes["copyright"] && ipTypes["trade_secret"] && ipTypes["trademark"] {
		semanticGroups = append(semanticGroups, "full_legal_notice")
	}

	// Pattern 2: Copyright + Confidential (copyright notice with confidentiality)
	if ipTypes["copyright"] && ipTypes["trade_secret"] {
		semanticGroups = append(semanticGroups, "copyright_with_confidential")
	}

	// Pattern 3: Copyright + Trademark (copyright notice with trademark)
	if ipTypes["copyright"] && ipTypes["trademark"] {
		semanticGroups = append(semanticGroups, "copyright_with_trademark")
	}

	// Pattern 4: Trademark + Confidential (trademark with confidentiality)
	if ipTypes["trademark"] && ipTypes["trade_secret"] {
		semanticGroups = append(semanticGroups, "trademark_with_confidential")
	}

	// Pattern 5: Multiple confidential markers (repeated confidentiality)
	confidentialCount := 0
	for _, match := range matches {
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok && ipType == "trade_secret" {
				confidentialCount++
			}
		}
	}
	if confidentialCount > 1 {
		semanticGroups = append(semanticGroups, "repeated_confidential")
	}

	// Pattern 6: "All rights reserved" phrase detection
	allRightsReservedPatterns := []string{
		"all rights reserved",
		"all rights are reserved",
		"tous droits réservés",          // French
		"todos los derechos reservados", // Spanish
		"alle rechte vorbehalten",       // German
	}

	for _, pattern := range allRightsReservedPatterns {
		if strings.Contains(fullContext, pattern) {
			semanticGroups = append(semanticGroups, "all_rights_reserved")
			break
		}
	}

	// Pattern 7: Standard copyright notice structure
	copyrightNoticePatterns := []string{
		"copyright.*all rights reserved",
		"©.*all rights reserved",
		"copyright.*confidential",
		"©.*confidential",
		"copyright.*proprietary",
		"©.*proprietary",
	}

	for _, pattern := range copyrightNoticePatterns {
		if matched, _ := regexp.MatchString(pattern, fullContext); matched {
			semanticGroups = append(semanticGroups, "standard_copyright_notice")
			break
		}
	}

	// Pattern 8: Corporate confidentiality statement
	corporateConfidentialPatterns := []string{
		"company confidential",
		"internal use only",
		"proprietary and confidential",
		"confidential and proprietary",
		"strictly confidential",
		"highly confidential",
	}

	for _, pattern := range corporateConfidentialPatterns {
		if strings.Contains(fullContext, pattern) {
			semanticGroups = append(semanticGroups, "corporate_confidential")
			break
		}
	}

	// Pattern 9: Legal disclaimer patterns
	legalDisclaimerPatterns := []string{
		"unauthorized use",
		"unauthorized reproduction",
		"without permission",
		"strictly prohibited",
		"violation of law",
		"legal action",
	}

	for _, pattern := range legalDisclaimerPatterns {
		if strings.Contains(fullContext, pattern) {
			semanticGroups = append(semanticGroups, "legal_disclaimer")
			break
		}
	}

	// Pattern 10: Patent with confidentiality (distinct items, not legal notice)
	if ipTypes["patent"] && ipTypes["trade_secret"] {
		// Check if they appear to be related or distinct
		patentContext := ""
		confidentialContext := ""

		for _, match := range matches {
			if match.Metadata != nil {
				if ipType, ok := match.Metadata["ip_type"].(string); ok {
					if ipType == "patent" {
						patentContext = strings.ToLower(match.Context.FullLine)
					} else if ipType == "trade_secret" {
						confidentialContext = strings.ToLower(match.Context.FullLine)
					}
				}
			}
		}

		// If patent and confidential appear in different contexts, they're likely distinct
		// Also check for clear separation indicators in the full context
		if patentContext != confidentialContext && patentContext != "" && confidentialContext != "" {
			// Check for clear separation indicators
			if (strings.Contains(fullContext, "contact") && strings.Contains(fullContext, "patent")) ||
				(strings.Contains(fullContext, "this document") && strings.Contains(fullContext, "confidential")) {
				semanticGroups = append(semanticGroups, "distinct_patent_confidential")
			} else {
				semanticGroups = append(semanticGroups, "patent_with_confidential")
			}
		} else {
			semanticGroups = append(semanticGroups, "patent_with_confidential")
		}
	}

	// Pattern 11: Patent with trademark in contact context (distinct items, not legal notice)
	if ipTypes["patent"] && ipTypes["trademark"] {
		// Check for contact/inquiry context which suggests distinct items
		contactIndicators := []string{
			"contact",
			"call",
			"email",
			"reach out",
			"get in touch",
			"inquire",
			"inquiry",
			"questions",
			"issues",
			"problems",
			"help",
			"support",
		}

		for _, indicator := range contactIndicators {
			if strings.Contains(fullContext, indicator) {
				semanticGroups = append(semanticGroups, "distinct_patent_trademark")
				break
			}
		}

		// If not identified as distinct, treat as potential legal notice
		if !contains(semanticGroups, "distinct_patent_trademark") {
			semanticGroups = append(semanticGroups, "patent_with_trademark")
		}
	}

	return semanticGroups
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// analyzeLegalNoticeContext combines proximity and semantic analysis to determine
// if multiple matches should be reconstructed into a single legal notice finding
// Enhanced with bounds checking and error handling for robustness
func (v *Validator) analyzeLegalNoticeContext(matches []detector.Match) LegalNoticeAnalysis {
	// Initialize analysis result with safe defaults
	analysis := LegalNoticeAnalysis{
		IsLegalNotice:        false,
		NoticeType:           "unknown",
		Confidence:           0.0,
		ProximityScore:       0.0,
		SemanticGrouping:     []string{},
		ShouldReconstruct:    false,
		ReconstructionReason: "no_analysis_performed",
	}

	// Bounds checking for edge cases
	if len(matches) == 0 {
		analysis.ReconstructionReason = "no_matches"
		return analysis
	}

	if len(matches) == 1 {
		analysis.ReconstructionReason = "single_match"
		return analysis
	}

	// Add error handling for analysis steps
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery and provide safe fallback
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("intellectualproperty",
					fmt.Sprintf("Recovered from panic during legal notice analysis: %v", r))
			}

			// Reset to safe defaults
			analysis.IsLegalNotice = false
			analysis.ShouldReconstruct = false
			analysis.ReconstructionReason = "analysis_error_fallback"
		}
	}()

	// Step 1: Calculate proximity score
	analysis.ProximityScore = v.calculateProximityScore(matches)

	// Step 2: Identify semantic groupings
	analysis.SemanticGrouping = v.identifySemanticGroups(matches)

	// Step 3: Determine if this appears to be a legal notice
	analysis.IsLegalNotice = v.isLegalNoticePattern(matches, analysis.SemanticGrouping, analysis.ProximityScore)

	// Step 4: Classify the notice type
	analysis.NoticeType = v.classifyNoticeType(matches, analysis.SemanticGrouping)

	// Step 5: Calculate confidence for the legal notice analysis
	analysis.Confidence = v.calculateLegalNoticeConfidence(matches, analysis.SemanticGrouping, analysis.ProximityScore)

	// Step 6: Make final reconstruction decision
	analysis.ShouldReconstruct, analysis.ReconstructionReason = v.makeReconstructionDecision(analysis)

	// Log the analysis decision in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.logLegalNoticeAnalysis(matches, analysis)
	}

	return analysis
}

// isLegalNoticePattern determines if the matches and semantic groups indicate a legal notice
func (v *Validator) isLegalNoticePattern(matches []detector.Match, semanticGroups []string, proximityScore float64) bool {
	// Check for patterns that indicate distinct items (not legal notices) first
	distinctIndicators := []string{
		"distinct_patent_confidential",
		"distinct_patent_trademark",
	}

	for _, indicator := range distinctIndicators {
		for _, group := range semanticGroups {
			if group == indicator {
				return false // Explicitly not a legal notice
			}
		}
	}

	// If proximity is very poor, even strong indicators might not be legal notices
	if proximityScore < 0.1 {
		return false // Very poor proximity suggests distinct items
	}

	// Check for very strong legal notice indicators
	// Even these respect very strict proximity thresholds
	veryStrongIndicators := []string{
		"full_legal_notice",
		"all_rights_reserved",
		"standard_copyright_notice",
	}

	// For very strict thresholds, even strong indicators need reasonable proximity
	minProximityForVeryStrong := 0.1 // very lenient default
	if v.legalNoticeConfig.ProximityThreshold < 50 {
		minProximityForVeryStrong = 0.8 // require very high proximity for strict thresholds
	}

	if proximityScore >= minProximityForVeryStrong {
		for _, indicator := range veryStrongIndicators {
			for _, group := range semanticGroups {
				if group == indicator {
					return true
				}
			}
		}
	}

	// Check for strong indicators with reasonable proximity
	// Use a dynamic threshold based on configuration
	strongIndicators := []string{
		"copyright_with_confidential",
		"copyright_with_trademark",
	}

	// Calculate minimum proximity needed based on configuration
	// If threshold is very strict (< 50), require higher proximity
	minProximityForStrong := 0.3 // default
	if v.legalNoticeConfig.ProximityThreshold < 50 {
		minProximityForStrong = 0.7 // require higher proximity for strict thresholds
	}

	if proximityScore >= minProximityForStrong {
		for _, indicator := range strongIndicators {
			for _, group := range semanticGroups {
				if group == indicator {
					return true
				}
			}
		}
	}

	// Check for medium indicators with good proximity
	mediumIndicators := []string{
		"trademark_with_confidential",
		"repeated_confidential",
		"corporate_confidential",
		"legal_disclaimer",
	}

	if proximityScore >= 0.6 { // Good proximity threshold
		for _, indicator := range mediumIndicators {
			for _, group := range semanticGroups {
				if group == indicator {
					return true
				}
			}
		}
	}

	// Check if all matches are on the same line with reasonable proximity
	if len(matches) > 1 && proximityScore >= 0.7 {
		// Same line with good proximity suggests legal notice
		allSameLine := true
		firstLineNum := matches[0].LineNumber
		for _, match := range matches {
			if match.LineNumber != firstLineNum {
				allSameLine = false
				break
			}
		}
		if allSameLine {
			return true
		}
	}

	return false
}

// classifyNoticeType determines the specific type of legal notice
func (v *Validator) classifyNoticeType(matches []detector.Match, semanticGroups []string) string {
	// Check semantic groups for specific notice types
	for _, group := range semanticGroups {
		switch group {
		case "full_legal_notice":
			return "mixed_notice"
		case "copyright_with_confidential", "copyright_with_trademark", "standard_copyright_notice", "all_rights_reserved":
			return "copyright_notice"
		case "trademark_with_confidential":
			return "trademark_notice"
		case "repeated_confidential", "corporate_confidential":
			return "confidentiality_statement"
		case "legal_disclaimer":
			return "legal_disclaimer"
		case "distinct_patent_confidential":
			return "mixed_notice" // Distinct items should be classified as mixed
		}
	}

	// Fallback: analyze IP types in matches
	ipTypes := make(map[string]bool)
	for _, match := range matches {
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				ipTypes[ipType] = true
			}
		}
	}

	// Determine type based on IP types present
	if ipTypes["copyright"] && (ipTypes["trade_secret"] || ipTypes["trademark"]) {
		return "copyright_notice"
	} else if ipTypes["trademark"] && ipTypes["trade_secret"] {
		return "trademark_notice"
	} else if ipTypes["patent"] && ipTypes["trade_secret"] {
		return "mixed_notice" // Patent + confidential is mixed, not just confidential
	} else if ipTypes["trade_secret"] {
		return "confidentiality_statement"
	} else if ipTypes["copyright"] {
		return "copyright_notice"
	} else if ipTypes["trademark"] {
		return "trademark_notice"
	}

	return "mixed_notice"
}

// calculateLegalNoticeConfidence calculates confidence for legal notice reconstruction
func (v *Validator) calculateLegalNoticeConfidence(matches []detector.Match, semanticGroups []string, proximityScore float64) float64 {
	if len(matches) <= 1 {
		return 0.0
	}

	// Start with base confidence from proximity
	confidence := proximityScore * 50.0 // Convert 0-1 to 0-50 base score

	// If proximity is very poor, heavily penalize confidence
	if proximityScore < 0.1 {
		confidence = 0.0 // Reset to zero for very poor proximity
	}

	// Add confidence based on semantic groupings using internal constants
	for _, group := range semanticGroups {
		switch group {
		case "full_legal_notice":
			confidence += SemanticFullLegalNoticeBoost
		case "copyright_with_confidential", "copyright_with_trademark":
			// Reduce bonus if proximity is poor
			if proximityScore >= 0.3 {
				confidence += SemanticCopyrightPatternBoost
			} else {
				confidence += SemanticPatentConfidentialBoost // Reduced bonus for poor proximity
			}
		case "all_rights_reserved", "standard_copyright_notice":
			confidence += SemanticAllRightsReservedBoost
		case "trademark_with_confidential":
			confidence += SemanticTrademarkPatternBoost
		case "repeated_confidential":
			confidence += SemanticRepeatedConfidentialBoost
		case "corporate_confidential":
			confidence += SemanticCorporateConfidentialBoost
		case "legal_disclaimer":
			confidence += SemanticLegalDisclaimerBoost
		case "patent_with_confidential":
			confidence += SemanticPatentConfidentialBoost
		case "distinct_patent_confidential":
			confidence += SemanticDistinctItemsPenalty // Negative indicator
		}
	}

	// Bonus for same-line matches using internal constants
	if len(matches) > 1 {
		allSameLine := true
		firstLineNum := matches[0].LineNumber
		for _, match := range matches {
			if match.LineNumber != firstLineNum {
				allSameLine = false
				break
			}
		}
		if allSameLine {
			confidence += SameLineBonus
		}
	}

	// Bonus for multiple IP types (indicates comprehensive legal notice) using internal constants
	ipTypes := make(map[string]bool)
	for _, match := range matches {
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				ipTypes[ipType] = true
			}
		}
	}

	if len(ipTypes) >= 3 {
		confidence += MultiIPTypeThreeOrMoreBonus
	} else if len(ipTypes) >= 2 {
		confidence += MultiIPTypeTwoBonus
	}

	// Apply proximity penalty for poor proximity using internal constants
	if proximityScore < 0.3 {
		confidence *= PoorProximityPenalty // Reduce confidence for poor proximity
	}

	// Ensure confidence stays within reasonable bounds
	if confidence > 95.0 {
		confidence = 95.0 // Cap at 95% to maintain some uncertainty
	} else if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

// makeReconstructionDecision makes the final decision on whether to reconstruct
func (v *Validator) makeReconstructionDecision(analysis LegalNoticeAnalysis) (bool, string) {
	// Don't reconstruct if legal notice reconstruction is disabled
	if !v.legalNoticeConfig.Enabled {
		return false, "legal_notice_reconstruction_disabled"
	}

	// Don't reconstruct if not identified as a legal notice
	if !analysis.IsLegalNotice {
		return false, "not_identified_as_legal_notice"
	}

	// Don't reconstruct if confidence is too low using internal constants
	if analysis.Confidence < ReconstructionMinConfidence {
		return false, "confidence_too_low"
	}

	// Don't reconstruct if proximity is too poor using internal constants
	if analysis.ProximityScore < ReconstructionMinProximity {
		return false, "proximity_too_poor"
	}

	// Check for explicit distinct patterns
	for _, group := range analysis.SemanticGrouping {
		if group == "distinct_patent_confidential" {
			return false, "distinct_items_detected"
		}
	}

	// Reconstruct if we have strong indicators
	strongIndicators := []string{
		"full_legal_notice",
		"copyright_with_confidential",
		"copyright_with_trademark",
		"all_rights_reserved",
		"standard_copyright_notice",
	}

	for _, indicator := range strongIndicators {
		for _, group := range analysis.SemanticGrouping {
			if group == indicator {
				return true, "strong_legal_notice_pattern"
			}
		}
	}

	// Reconstruct if we have good confidence and proximity using internal constants
	if analysis.Confidence >= ReconstructionGoodConfidence && analysis.ProximityScore >= ReconstructionGoodProximity {
		return true, "good_confidence_and_proximity"
	}

	// Reconstruct if we have medium confidence with very good proximity using internal constants
	if analysis.Confidence >= ReconstructionMediumConfidence && analysis.ProximityScore >= ReconstructionExcellentProximity {
		return true, "medium_confidence_excellent_proximity"
	}

	// Default: don't reconstruct
	return false, "insufficient_evidence"
}

// reconstructLegalNoticeWithFallback combines fragmented matches with graceful degradation
// Returns the reconstructed match and any error that occurred during reconstruction
func (v *Validator) reconstructLegalNoticeWithFallback(matches []detector.Match) (detector.Match, error) {
	// Bounds checking for edge cases
	if len(matches) == 0 {
		return detector.Match{}, fmt.Errorf("no matches provided for reconstruction")
	}

	// Try reconstruction with error handling
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery in debug mode
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("intellectualproperty",
					fmt.Sprintf("Recovered from panic during legal notice reconstruction: %v", r))
			}
		}
	}()

	reconstructed := v.reconstructLegalNotice(matches)

	// Validate reconstructed match
	if err := v.validateReconstructedMatch(reconstructed, matches); err != nil {
		return detector.Match{}, fmt.Errorf("reconstruction validation failed: %w", err)
	}

	return reconstructed, nil
}

// validateReconstructedMatch validates that a reconstructed match is valid
func (v *Validator) validateReconstructedMatch(reconstructed detector.Match, originalMatches []detector.Match) error {
	// Check basic fields
	if reconstructed.Text == "" {
		return fmt.Errorf("reconstructed match has empty text")
	}

	if reconstructed.Confidence <= 0 || reconstructed.Confidence > 100 {
		return fmt.Errorf("reconstructed match has invalid confidence: %.1f", reconstructed.Confidence)
	}

	if reconstructed.LineNumber <= 0 {
		return fmt.Errorf("reconstructed match has invalid line number: %d", reconstructed.LineNumber)
	}

	if reconstructed.Validator == "" {
		return fmt.Errorf("reconstructed match missing validator")
	}

	if reconstructed.Type == "" {
		return fmt.Errorf("reconstructed match missing type")
	}

	// Check metadata
	if reconstructed.Metadata == nil {
		return fmt.Errorf("reconstructed match missing metadata")
	}

	// Validate required metadata fields
	requiredFields := []string{"ip_types", "original_match_count", "confidence_boost", "reconstruction_type"}
	for _, field := range requiredFields {
		if _, ok := reconstructed.Metadata[field]; !ok {
			return fmt.Errorf("reconstructed match missing required metadata field: %s", field)
		}
	}

	// Validate original match count consistency
	if originalCount, ok := reconstructed.Metadata["original_match_count"].(int); ok {
		if originalCount != len(originalMatches) {
			return fmt.Errorf("metadata original_match_count (%d) doesn't match actual count (%d)", originalCount, len(originalMatches))
		}
	}

	return nil
}

// reconstructLegalNotice combines fragmented matches into a single comprehensive finding
// This method creates a consolidated match with full line context as match text
func (v *Validator) reconstructLegalNotice(matches []detector.Match) detector.Match {
	if len(matches) == 0 {
		// Return empty match if no matches provided
		return detector.Match{}
	}

	if len(matches) == 1 {
		// Single match doesn't need reconstruction, but we still enhance metadata for consistency
		match := matches[0]

		// Create enhanced metadata even for single matches
		enhancedMetadata := make(map[string]any)

		// Copy existing metadata
		if match.Metadata != nil {
			for k, v := range match.Metadata {
				enhancedMetadata[k] = v
			}
		}

		// Add enhanced metadata fields for single matches
		enhancedMetadata["original_match_count"] = 1
		enhancedMetadata["consolidated_count"] = 1 // backward compatibility
		enhancedMetadata["original_confidences"] = []float64{match.Confidence}
		enhancedMetadata["confidence_boost"] = 0.0
		enhancedMetadata["confidence_boost_percentage"] = 0.0

		// Classify single match
		analysis := v.analyzeLegalNoticeContext(matches)
		legalNoticeType := v.classifyLegalNoticeType(matches, analysis)
		enhancedMetadata["legal_notice_type"] = legalNoticeType
		enhancedMetadata["reconstruction_type"] = analysis.NoticeType
		enhancedMetadata["notice_classification"] = v.getNoticeClassificationDetails(legalNoticeType, analysis)

		// Single match preservation
		enhancedMetadata["original_match_texts"] = []string{match.Text}
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				enhancedMetadata["original_match_types"] = []string{ipType}
			} else {
				enhancedMetadata["original_match_types"] = []string{""}
			}
			if checks, ok := match.Metadata["validation_checks"].(map[string]bool); ok {
				enhancedMetadata["original_validation_checks"] = []map[string]bool{checks}
			} else {
				enhancedMetadata["original_validation_checks"] = []map[string]bool{}
			}
			if impact, ok := match.Metadata["context_impact"].(float64); ok {
				enhancedMetadata["original_context_impacts"] = []float64{impact}
			} else {
				enhancedMetadata["original_context_impacts"] = []float64{0.0}
			}
		} else {
			enhancedMetadata["original_match_types"] = []string{""}
			enhancedMetadata["original_validation_checks"] = []map[string]bool{}
			enhancedMetadata["original_context_impacts"] = []float64{0.0}
		}

		enhancedMetadata["primary_match_index"] = 0
		enhancedMetadata["semantic_groups"] = analysis.SemanticGrouping
		enhancedMetadata["proximity_score"] = analysis.ProximityScore
		enhancedMetadata["reconstruction_reason"] = "single_match_no_reconstruction_needed"
		enhancedMetadata["analysis_confidence"] = analysis.Confidence
		enhancedMetadata["source"] = "single_match_enhanced"
		enhancedMetadata["reconstruction_algorithm"] = "proximity_semantic_analysis"
		enhancedMetadata["reconstruction_version"] = "1.1"
		enhancedMetadata["original_file"] = match.Filename
		enhancedMetadata["reconstruction_timestamp"] = v.getCurrentTimestamp()

		// Return match with enhanced metadata
		match.Metadata = enhancedMetadata
		return match
	}

	// Analyze the matches to get reconstruction context
	analysis := v.analyzeLegalNoticeContext(matches)

	// Find the primary match (usually the one with highest confidence or most comprehensive text)
	primaryMatch := v.findPrimaryMatch(matches)

	// Calculate reconstructed confidence
	reconstructedConfidence := v.calculateReconstructedConfidence(matches, analysis)

	// Build consolidated match text using full line context
	consolidatedText := v.buildConsolidatedMatchText(matches)

	// Collect all IP types from the original matches
	ipTypes := v.collectIPTypes(matches)

	// Collect original confidences and enhanced metadata for reconstruction
	originalConfidences := make([]float64, len(matches))
	originalMatchTexts := make([]string, len(matches))
	originalMatchTypes := make([]string, len(matches))
	originalValidationChecks := make([]map[string]bool, len(matches))
	originalContextImpacts := make([]float64, len(matches))

	for i, match := range matches {
		originalConfidences[i] = match.Confidence
		originalMatchTexts[i] = match.Text

		// Extract IP type from original match metadata
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				originalMatchTypes[i] = ipType
			}
			// Preserve validation checks from original matches
			if checks, ok := match.Metadata["validation_checks"].(map[string]bool); ok {
				originalValidationChecks[i] = checks
			}
			// Preserve context impact scores
			if impact, ok := match.Metadata["context_impact"].(float64); ok {
				originalContextImpacts[i] = impact
			}
		}
	}

	// Calculate confidence boost details
	confidenceBoost := reconstructedConfidence - primaryMatch.Confidence

	// Determine enhanced legal notice type classification
	legalNoticeType := v.classifyLegalNoticeType(matches, analysis)

	// Create enhanced consolidated metadata with reconstruction information
	consolidatedMetadata := map[string]any{
		// Core reconstruction metadata
		"ip_types":                    ipTypes,
		"original_match_count":        len(matches),
		"consolidated_count":          len(matches), // Keep for backward compatibility
		"original_confidences":        originalConfidences,
		"confidence_boost":            confidenceBoost,
		"confidence_boost_percentage": (confidenceBoost / primaryMatch.Confidence) * 100,

		// Enhanced legal notice classification
		"legal_notice_type":     legalNoticeType,
		"reconstruction_type":   analysis.NoticeType, // Keep for backward compatibility
		"notice_classification": v.getNoticeClassificationDetails(legalNoticeType, analysis),

		// Semantic and proximity analysis
		"semantic_groups":       analysis.SemanticGrouping,
		"proximity_score":       analysis.ProximityScore,
		"reconstruction_reason": analysis.ReconstructionReason,
		"analysis_confidence":   analysis.Confidence,

		// Original match preservation
		"original_match_texts":       originalMatchTexts,
		"original_match_types":       originalMatchTypes,
		"original_validation_checks": originalValidationChecks,
		"original_context_impacts":   originalContextImpacts,
		"primary_match_index":        v.findPrimaryMatchIndex(matches, primaryMatch),

		// Reconstruction metadata
		"source":                   "legal_notice_reconstruction",
		"reconstruction_algorithm": "proximity_semantic_analysis",
		"reconstruction_version":   "1.1", // Version for tracking algorithm changes
		"original_file":            primaryMatch.Filename,
		"reconstruction_timestamp": v.getCurrentTimestamp(),
	}

	// Create the reconstructed match
	reconstructedMatch := detector.Match{
		Text:       consolidatedText,
		LineNumber: primaryMatch.LineNumber, // Use primary match line number
		Type:       "INTELLECTUAL_PROPERTY",
		Confidence: reconstructedConfidence,
		Filename:   primaryMatch.Filename,
		Validator:  "INTELLECTUAL_PROPERTY",
		Context:    primaryMatch.Context, // Use primary match context but update FullLine if needed
		Metadata:   consolidatedMetadata,
	}

	// Log reconstruction details in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.logReconstructionDetails(matches, reconstructedMatch, analysis)
	}

	return reconstructedMatch
}

// classifyLegalNoticeType provides enhanced classification of legal notice types
// based on the IP patterns found and their semantic relationships
func (v *Validator) classifyLegalNoticeType(matches []detector.Match, analysis LegalNoticeAnalysis) string {
	ipTypeCounts := make(map[string]int)

	// Count IP types in the matches
	for _, match := range matches {
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				ipTypeCounts[ipType]++
			}
		}
	}

	hasCopyright := ipTypeCounts["copyright"] > 0
	hasTradeSecret := ipTypeCounts["trade_secret"] > 0
	hasTrademark := ipTypeCounts["trademark"] > 0
	hasPatent := ipTypeCounts["patent"] > 0

	// Enhanced classification logic
	switch {
	case hasCopyright && hasTradeSecret && hasTrademark:
		return "comprehensive_legal_notice"
	case hasCopyright && hasTradeSecret:
		return "copyright_confidentiality_notice"
	case hasCopyright && hasTrademark:
		return "copyright_trademark_notice"
	case hasTradeSecret && hasTrademark:
		return "confidentiality_trademark_notice"
	case hasCopyright && len(ipTypeCounts) == 1:
		if ipTypeCounts["copyright"] > 1 {
			return "multiple_copyright_notice"
		}
		return "copyright_notice"
	case hasTradeSecret && len(ipTypeCounts) == 1:
		if ipTypeCounts["trade_secret"] > 1 {
			return "repeated_confidentiality_statement"
		}
		return "confidentiality_statement"
	case hasTrademark && len(ipTypeCounts) == 1:
		if ipTypeCounts["trademark"] > 1 {
			return "multiple_trademark_notice"
		}
		return "trademark_notice"
	case hasPatent:
		if len(ipTypeCounts) > 1 {
			return "patent_mixed_notice"
		}
		return "patent_notice"
	default:
		return "mixed_notice"
	}
}

// getNoticeClassificationDetails provides detailed information about the notice classification
func (v *Validator) getNoticeClassificationDetails(legalNoticeType string, analysis LegalNoticeAnalysis) map[string]any {
	return map[string]any{
		"primary_type":       legalNoticeType,
		"semantic_strength":  analysis.Confidence,
		"pattern_complexity": len(analysis.SemanticGrouping),
		"is_comprehensive":   strings.Contains(legalNoticeType, "comprehensive"),
		"is_mixed":           strings.Contains(legalNoticeType, "mixed"),
		"has_repetition":     strings.Contains(legalNoticeType, "multiple") || strings.Contains(legalNoticeType, "repeated"),
	}
}

// findPrimaryMatchIndex returns the index of the primary match in the original matches slice
func (v *Validator) findPrimaryMatchIndex(matches []detector.Match, primaryMatch detector.Match) int {
	for i, match := range matches {
		if match.Text == primaryMatch.Text &&
			match.LineNumber == primaryMatch.LineNumber &&
			match.Confidence == primaryMatch.Confidence {
			return i
		}
	}
	return 0 // Default to first match if not found
}

// getCurrentTimestamp returns current timestamp for reconstruction tracking
func (v *Validator) getCurrentTimestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

// findPrimaryMatch identifies the most comprehensive or highest confidence match
// to use as the base for reconstruction
func (v *Validator) findPrimaryMatch(matches []detector.Match) detector.Match {
	if len(matches) == 0 {
		return detector.Match{}
	}

	primaryMatch := matches[0]
	maxScore := 0.0

	for _, match := range matches {
		// Calculate a score based on confidence and text length
		score := match.Confidence + float64(len(match.Text))*0.1

		// Prefer copyright matches as they're often the most comprehensive
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok && ipType == "copyright" {
				score += 10.0 // Bonus for copyright matches
			}
		}

		if score > maxScore {
			maxScore = score
			primaryMatch = match
		}
	}

	return primaryMatch
}

// buildConsolidatedMatchText creates the match text for the reconstructed finding
// Uses the full line context to show the complete legal notice
func (v *Validator) buildConsolidatedMatchText(matches []detector.Match) string {
	if len(matches) == 0 {
		return ""
	}

	// Check if all matches are on the same line
	allSameLine := true
	firstLineNum := matches[0].LineNumber
	var fullLine string

	for _, match := range matches {
		if match.LineNumber != firstLineNum {
			allSameLine = false
			break
		}
		if match.Context.FullLine != "" {
			fullLine = match.Context.FullLine
		}
	}

	if allSameLine && fullLine != "" {
		// All matches on same line - use the full line as consolidated text
		return strings.TrimSpace(fullLine)
	}

	// Multi-line matches - combine the individual match texts
	var textParts []string
	seenTexts := make(map[string]bool)

	for _, match := range matches {
		// Avoid duplicate text parts
		if !seenTexts[match.Text] {
			textParts = append(textParts, match.Text)
			seenTexts[match.Text] = true
		}
	}

	// Join with appropriate separator
	if len(textParts) <= 2 {
		return strings.Join(textParts, " ")
	}
	return strings.Join(textParts, "; ")
}

// collectIPTypes gathers all IP types from the original matches
func (v *Validator) collectIPTypes(matches []detector.Match) []string {
	ipTypeSet := make(map[string]bool)
	var ipTypes []string

	for _, match := range matches {
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				if !ipTypeSet[ipType] {
					ipTypes = append(ipTypes, ipType)
					ipTypeSet[ipType] = true
				}
			}
		}
	}

	return ipTypes
}

// calculateReconstructedConfidence calculates confidence for reconstructed legal notices
// with appropriate confidence boosts based on the legal notice analysis
func (v *Validator) calculateReconstructedConfidence(matches []detector.Match, analysis LegalNoticeAnalysis) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	if len(matches) == 1 {
		return matches[0].Confidence // Single match keeps original confidence
	}

	// Find the highest individual confidence as base
	baseConfidence := 0.0
	for _, match := range matches {
		if match.Confidence > baseConfidence {
			baseConfidence = match.Confidence
		}
	}

	// Start with base confidence
	reconstructedConfidence := baseConfidence

	// Apply confidence boosts based on legal notice patterns
	boostApplied := 0.0

	// Apply boosts based on notice type
	switch analysis.NoticeType {
	case "copyright_notice":
		if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["copyright_notice"]; ok {
			boostApplied += boost
		}
	case "mixed_notice":
		if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["mixed_notice"]; ok {
			boostApplied += boost
		}
	case "confidentiality_statement":
		if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["repeated_marker"]; ok {
			boostApplied += boost
		}
	}

	// Apply general legal notice boost
	if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["legal_notice"]; ok {
		boostApplied += boost
	}

	// Apply proximity-based boost using internal constants
	proximityBoost := analysis.ProximityScore * MaxProximityBonus // Up to MaxProximityBonus% boost for perfect proximity
	boostApplied += proximityBoost

	// Apply semantic grouping boosts using internal constants
	for _, group := range analysis.SemanticGrouping {
		switch group {
		case "full_legal_notice":
			boostApplied += 3.0 // Additional boost for comprehensive legal notices
		case "all_rights_reserved":
			boostApplied += 2.0 // Boost for "all rights reserved" phrases
		case "standard_copyright_notice":
			boostApplied += 2.5 // Boost for standard copyright structure
		}
	}

	// Apply boost for multiple IP types (indicates comprehensive legal notice) using internal constants
	ipTypes := v.collectIPTypes(matches)
	if len(ipTypes) >= 3 {
		boostApplied += 4.0 // Significant boost for 3+ IP types
	} else if len(ipTypes) >= 2 {
		boostApplied += 2.0 // Moderate boost for 2 IP types
	}

	// Apply the total boost
	reconstructedConfidence += boostApplied

	// Apply maximum confidence cap
	if reconstructedConfidence > v.legalNoticeConfig.MaxConfidence {
		reconstructedConfidence = v.legalNoticeConfig.MaxConfidence
	}

	// Ensure confidence doesn't go below minimum threshold
	if reconstructedConfidence < v.legalNoticeConfig.MinConfidenceThreshold {
		reconstructedConfidence = v.legalNoticeConfig.MinConfidenceThreshold
	}

	// Ensure confidence stays within valid bounds
	if reconstructedConfidence > 100.0 {
		reconstructedConfidence = 100.0
	} else if reconstructedConfidence < 0.0 {
		reconstructedConfidence = 0.0
	}

	// Log detailed confidence boost calculation in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.logConfidenceBoostCalculation(matches, analysis, baseConfidence, reconstructedConfidence)
	}

	return reconstructedConfidence
}

// logProximityCalculationDetails logs detailed proximity calculation information
func (v *Validator) logProximityCalculationDetails(matches []detector.Match, proximityScore float64) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Proximity Analysis:"))

	if len(matches) <= 1 {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Single match - proximity score: %.2f (perfect)", proximityScore))
		return
	}

	// Check if all matches are on same line
	allSameLine := true
	firstLineNum := matches[0].LineNumber
	for _, match := range matches {
		if match.LineNumber != firstLineNum {
			allSameLine = false
			break
		}
	}

	if allSameLine {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Same-line matches detected (line %d)", firstLineNum))

		// Calculate positions within the line for same-line matches
		positions := make([]int, len(matches))
		for i, match := range matches {
			positions[i] = v.calculateCharacterPosition(match) % 100
		}

		minPos := positions[0]
		maxPos := positions[0]
		for _, pos := range positions {
			if pos < minPos {
				minPos = pos
			}
			if pos > maxPos {
				maxPos = pos
			}
		}

		span := maxPos - minPos
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Character span within line: %d (threshold: %.0f)", span, SameLineProximityThreshold))
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Same-line proximity score: %.2f", proximityScore))
	} else {
		// Multi-line proximity calculation
		positions := make([]int, len(matches))
		for i, match := range matches {
			positions[i] = v.calculateCharacterPosition(match)
		}

		minPos := positions[0]
		maxPos := positions[0]
		for _, pos := range positions {
			if pos < minPos {
				minPos = pos
			}
			if pos > maxPos {
				maxPos = pos
			}
		}

		span := maxPos - minPos
		threshold := float64(v.legalNoticeConfig.ProximityThreshold)

		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Multi-line matches: lines %d-%d",
				matches[0].LineNumber, matches[len(matches)-1].LineNumber))
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Character span: %d (threshold: %.0f)", span, threshold))
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Multi-line proximity score: %.2f", proximityScore))
	}

	// Classify proximity level
	var proximityLevel string
	if proximityScore >= ProximityCloseThreshold {
		proximityLevel = "CLOSE"
	} else if proximityScore >= ProximityMediumThreshold {
		proximityLevel = "MEDIUM"
	} else if proximityScore >= ProximityFarThreshold {
		proximityLevel = "FAR"
	} else {
		proximityLevel = "VERY_FAR"
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Proximity classification: %s (score: %.2f)", proximityLevel, proximityScore))
}

// logSemanticGroupingDetails logs detailed semantic grouping analysis
func (v *Validator) logSemanticGroupingDetails(matches []detector.Match, semanticGroups []string) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Semantic Analysis:"))

	if len(semanticGroups) == 0 {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    No semantic patterns detected"))
		return
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Detected patterns: %v", semanticGroups))

	// Log what each semantic group means
	for _, group := range semanticGroups {
		var description string
		switch group {
		case "full_legal_notice":
			description = "Complete legal notice (copyright + confidential + trademark)"
		case "copyright_with_confidential":
			description = "Copyright notice with confidentiality markers"
		case "copyright_with_trademark":
			description = "Copyright notice with trademark indicators"
		case "trademark_with_confidential":
			description = "Trademark with confidentiality markers"
		case "repeated_confidential":
			description = "Multiple confidentiality markers"
		case "all_rights_reserved":
			description = "Contains 'all rights reserved' phrase"
		case "standard_copyright_notice":
			description = "Standard copyright notice structure"
		case "corporate_confidential":
			description = "Corporate confidentiality statement"
		case "legal_disclaimer":
			description = "Legal disclaimer language"
		case "patent_with_confidential":
			description = "Patent reference with confidentiality"
		case "distinct_patent_confidential":
			description = "Patent and confidential appear as distinct items"
		case "distinct_patent_trademark":
			description = "Patent and trademark appear as distinct items"
		default:
			description = "Unknown pattern"
		}

		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("      %s: %s", group, description))
	}

	// Log IP type distribution
	ipTypes := make(map[string]int)
	for _, match := range matches {
		if match.Metadata != nil {
			if ipType, ok := match.Metadata["ip_type"].(string); ok {
				ipTypes[ipType]++
			}
		}
	}

	if len(ipTypes) > 0 {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    IP type distribution: %v", ipTypes))
	}
}

// logDecisionTreeReasoning logs the decision-making process for reconstruction
func (v *Validator) logDecisionTreeReasoning(analysis LegalNoticeAnalysis) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Decision Tree Analysis:"))

	// Log configuration status
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Legal notice reconstruction enabled: %v", v.legalNoticeConfig.Enabled))

	if !v.legalNoticeConfig.Enabled {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    → Reconstruction disabled by configuration"))
		return
	}

	// Log threshold checks
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Confidence threshold check: %.1f%% >= %.1f%% = %v",
			analysis.Confidence, ReconstructionMinConfidence,
			analysis.Confidence >= ReconstructionMinConfidence))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Proximity threshold check: %.2f >= %.2f = %v",
			analysis.ProximityScore, ReconstructionMinProximity,
			analysis.ProximityScore >= ReconstructionMinProximity))

	// Log legal notice pattern check
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Legal notice pattern detected: %v", analysis.IsLegalNotice))

	// Log specific decision factors
	strongIndicators := []string{
		"full_legal_notice", "copyright_with_confidential", "copyright_with_trademark",
		"all_rights_reserved", "standard_copyright_notice",
	}

	hasStrongIndicator := false
	for _, indicator := range strongIndicators {
		for _, group := range analysis.SemanticGrouping {
			if group == indicator {
				hasStrongIndicator = true
				v.observer.DebugObserver.LogDetail("intellectualproperty",
					fmt.Sprintf("    Strong indicator found: %s", indicator))
				break
			}
		}
		if hasStrongIndicator {
			break
		}
	}

	// Log final decision reasoning
	if analysis.ShouldReconstruct {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    → DECISION: RECONSTRUCT (%s)", analysis.ReconstructionReason))
	} else {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    → DECISION: KEEP SEPARATE (%s)", analysis.ReconstructionReason))
	}
}

// logConfidenceBoostCalculation logs detailed confidence boost calculations
func (v *Validator) logConfidenceBoostCalculation(matches []detector.Match, analysis LegalNoticeAnalysis, baseConfidence float64, finalConfidence float64) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Confidence Boost Calculation:"))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Base confidence (highest individual): %.1f%%", baseConfidence))

	totalBoost := 0.0

	// Log notice type boost
	var noticeTypeBoost float64
	switch analysis.NoticeType {
	case "copyright_notice":
		if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["copyright_notice"]; ok {
			noticeTypeBoost = boost
		}
	case "mixed_notice":
		if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["mixed_notice"]; ok {
			noticeTypeBoost = boost
		}
	case "confidentiality_statement":
		if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["repeated_marker"]; ok {
			noticeTypeBoost = boost
		}
	}

	if noticeTypeBoost > 0 {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Notice type boost (%s): +%.1f%%", analysis.NoticeType, noticeTypeBoost))
		totalBoost += noticeTypeBoost
	}

	// Log general legal notice boost
	if boost, ok := v.legalNoticeConfig.ConfidenceBoosts["legal_notice"]; ok {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    General legal notice boost: +%.1f%%", boost))
		totalBoost += boost
	}

	// Log proximity boost
	proximityBoost := analysis.ProximityScore * MaxProximityBonus
	if proximityBoost > 0 {
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Proximity boost (%.2f × %.1f%%): +%.1f%%",
				analysis.ProximityScore, MaxProximityBonus, proximityBoost))
		totalBoost += proximityBoost
	}

	// Log semantic grouping boosts
	semanticBoost := 0.0
	for _, group := range analysis.SemanticGrouping {
		var groupBoost float64
		switch group {
		case "full_legal_notice":
			groupBoost = 3.0
		case "all_rights_reserved":
			groupBoost = 2.0
		case "standard_copyright_notice":
			groupBoost = 2.5
		}
		if groupBoost > 0 {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("    Semantic boost (%s): +%.1f%%", group, groupBoost))
			semanticBoost += groupBoost
		}
	}
	totalBoost += semanticBoost

	// Log IP type diversity boost
	ipTypes := v.collectIPTypes(matches)
	var ipTypeBoost float64
	if len(ipTypes) >= 3 {
		ipTypeBoost = 4.0
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    IP type diversity boost (3+ types): +%.1f%%", ipTypeBoost))
	} else if len(ipTypes) >= 2 {
		ipTypeBoost = 2.0
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    IP type diversity boost (2 types): +%.1f%%", ipTypeBoost))
	}
	totalBoost += ipTypeBoost

	// Log total calculation
	calculatedConfidence := baseConfidence + totalBoost
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Total boost applied: +%.1f%%", totalBoost))
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Calculated confidence: %.1f%% + %.1f%% = %.1f%%",
			baseConfidence, totalBoost, calculatedConfidence))

	// Log capping if applied
	if calculatedConfidence != finalConfidence {
		if finalConfidence == v.legalNoticeConfig.MaxConfidence {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("    Capped at maximum: %.1f%% → %.1f%%", calculatedConfidence, finalConfidence))
		} else if finalConfidence == v.legalNoticeConfig.MinConfidenceThreshold {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("    Raised to minimum: %.1f%% → %.1f%%", calculatedConfidence, finalConfidence))
		}
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("    Final confidence: %.1f%%", finalConfidence))
}

// logReconstructionDetails logs detailed information about the reconstruction process
func (v *Validator) logReconstructionDetails(originalMatches []detector.Match, reconstructedMatch detector.Match, analysis LegalNoticeAnalysis) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("Legal notice reconstruction completed:"))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Original matches: %d", len(originalMatches)))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Reconstructed text: '%s'", reconstructedMatch.Text))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Final confidence: %.1f%%", reconstructedMatch.Confidence))

	// Log detailed confidence boost calculation
	if reconstructedMatch.Metadata != nil {
		if boost, ok := reconstructedMatch.Metadata["confidence_boost"].(float64); ok {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("  Confidence boost applied: +%.1f%%", boost))

			// Find base confidence for detailed logging
			baseConfidence := 0.0
			for _, match := range originalMatches {
				if match.Confidence > baseConfidence {
					baseConfidence = match.Confidence
				}
			}
			v.logConfidenceBoostCalculation(originalMatches, analysis, baseConfidence, reconstructedMatch.Confidence)
		}

		if ipTypes, ok := reconstructedMatch.Metadata["ip_types"].([]string); ok {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("  IP types combined: %v", ipTypes))
		}

		if reconstructionType, ok := reconstructedMatch.Metadata["reconstruction_type"].(string); ok {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("  Reconstruction type: %s", reconstructionType))
		}

		if proximityScore, ok := reconstructedMatch.Metadata["proximity_score"].(float64); ok {
			v.observer.DebugObserver.LogDetail("intellectualproperty",
				fmt.Sprintf("  Proximity score: %.2f", proximityScore))
		}
	}

	// Log original match details with enhanced information
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Original match breakdown:"))
	for i, match := range originalMatches {
		ipType := "unknown"
		if match.Metadata != nil {
			if t, ok := match.Metadata["ip_type"].(string); ok {
				ipType = t
			}
		}
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("    Match %d: '%s' (type: %s, confidence: %.1f%%, line: %d)",
				i+1, match.Text, ipType, match.Confidence, match.LineNumber))
	}

	// Also log to stderr in debug mode for comprehensive audit trail
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Legal Notice Reconstruction: %d matches → 1 reconstructed match\n", len(originalMatches))
		fmt.Fprintf(os.Stderr, "[DEBUG]   Text: '%s'\n", reconstructedMatch.Text)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Confidence: %.1f%%", reconstructedMatch.Confidence)
		if reconstructedMatch.Metadata != nil {
			if boost, ok := reconstructedMatch.Metadata["confidence_boost"].(float64); ok {
				fmt.Fprintf(os.Stderr, " (boost: +%.1f%%)", boost)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}
}

// logLegalNoticeAnalysis logs the analysis decision for debugging
func (v *Validator) logLegalNoticeAnalysis(matches []detector.Match, analysis LegalNoticeAnalysis) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	// Log basic analysis info
	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("Legal notice analysis for %d matches:", len(matches)))

	// Log detailed proximity calculation
	v.logProximityCalculationDetails(matches, analysis.ProximityScore)

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Is Legal Notice: %v", analysis.IsLegalNotice))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Notice Type: %s", analysis.NoticeType))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Analysis Confidence: %.1f%%", analysis.Confidence))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Should Reconstruct: %v", analysis.ShouldReconstruct))

	v.observer.DebugObserver.LogDetail("intellectualproperty",
		fmt.Sprintf("  Reconstruction Reason: %s", analysis.ReconstructionReason))

	// Log detailed semantic grouping analysis
	v.logSemanticGroupingDetails(matches, analysis.SemanticGrouping)

	// Log match details with enhanced information
	for i, match := range matches {
		ipType := "unknown"
		if match.Metadata != nil {
			if t, ok := match.Metadata["ip_type"].(string); ok {
				ipType = t
			}
		}
		v.observer.DebugObserver.LogDetail("intellectualproperty",
			fmt.Sprintf("  Match %d: '%s' (type: %s, line: %d, confidence: %.1f%%, position: %d)",
				i+1, match.Text, ipType, match.LineNumber, match.Confidence, v.calculateCharacterPosition(match)))
	}

	// Log decision tree reasoning
	v.logDecisionTreeReasoning(analysis)

	// Also log to stderr in debug mode for comprehensive audit trail
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Legal Notice Analysis: %d matches → reconstruct: %v (reason: %s)\n",
			len(matches), analysis.ShouldReconstruct, analysis.ReconstructionReason)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Proximity: %.2f, Confidence: %.1f%%, Type: %s\n",
			analysis.ProximityScore, analysis.Confidence, analysis.NoticeType)
		if len(analysis.SemanticGrouping) > 0 {
			fmt.Fprintf(os.Stderr, "[DEBUG]   Semantic Groups: %v\n", analysis.SemanticGrouping)
		}
	}
}
