// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"ferret-scan/internal/config"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Helper functions for min/max operations
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Validator implements the detector.Validator interface for detecting
// social media profiles, usernames, and handles across major platforms.
// Detection is configuration-driven and supports platform-specific patterns.
type Validator struct {
	// Platform-specific pattern groups
	platformPatterns map[string][]string
	compiledPatterns map[string][]*regexp.Regexp

	// Contextual analysis keywords
	positiveKeywords []string
	negativeKeywords []string

	// Platform-specific keywords for enhanced context
	platformKeywords map[string][]string

	// False positive prevention
	whitelistPatterns         []string
	compiledWhitelistPatterns []*regexp.Regexp

	// Configuration tracking
	patternsConfigured bool

	// Social media profile clustering configuration
	clusteringConfig SocialMediaClusteringConfig

	// Observability
	observer *observability.StandardObserver
}

// SocialMediaClusteringAnalysis contains the results of analyzing whether multiple social media matches
// form a coherent profile cluster that should be reconstructed into a single finding
type SocialMediaClusteringAnalysis struct {
	// IsProfileCluster indicates if the patterns appear to form a coherent profile cluster
	IsProfileCluster bool

	// ClusterType classifies the type of profile cluster detected
	ClusterType string // "same_user_multi_platform", "related_profiles", "fragmented_references", "mixed_cluster"

	// Confidence represents how confident we are that this is a profile cluster (0.0 to 1.0)
	Confidence float64

	// ProximityScore measures how close the patterns are to each other (0.0 to 1.0)
	ProximityScore float64

	// PlatformGrouping lists the platforms that were found together
	PlatformGrouping []string

	// ShouldReconstruct indicates the final decision on whether to reconstruct
	ShouldReconstruct bool

	// ReconstructionReason explains why the decision was made
	ReconstructionReason string

	// UserIdentifiers contains extracted usernames/identifiers that suggest same user
	UserIdentifiers []string

	// ClusteringFactors contains factors that contributed to clustering decision
	ClusteringFactors map[string]float64
}

// SocialMediaClusteringConfig contains configuration for social media profile clustering behavior
type SocialMediaClusteringConfig struct {
	// Enabled controls whether profile clustering is active
	Enabled bool

	// ProximityThreshold is the maximum character distance for patterns to be considered related
	ProximityThreshold int

	// ConfidenceBoosts define confidence increases for different clustering scenarios
	ConfidenceBoosts map[string]float64

	// MaxConfidence caps the maximum confidence for reconstructed profile clusters
	MaxConfidence float64

	// MinConfidenceThreshold filters out findings below this confidence level
	MinConfidenceThreshold float64

	// SameUserIndicators defines patterns that suggest the same user across platforms
	SameUserIndicators []string
}

// Internal configuration constants for social media profile clustering
// These are sensible defaults based on real-world social media patterns
const (
	// Default proximity threshold for social media clustering (characters)
	DefaultSocialMediaProximityThreshold = 500

	// Default confidence boosts for different clustering scenarios
	DefaultSameUserBoost        = 25.0
	DefaultRelatedProfilesBoost = 15.0
	DefaultFragmentedRefsBoost  = 10.0
	DefaultMultiPlatformBoost   = 20.0

	// Default confidence bounds
	DefaultSocialMediaMaxConfidence          = 95.0
	DefaultSocialMediaMinConfidenceThreshold = 30.0
)

// NewValidator creates and returns a new Validator instance
// with default patterns and keywords for detecting social media references.
func NewValidator() *Validator {
	v := &Validator{
		// Initialize platform patterns as empty - will be configured later
		platformPatterns: make(map[string][]string),
		compiledPatterns: make(map[string][]*regexp.Regexp),

		// Default positive keywords that suggest social media context
		positiveKeywords: []string{
			"profile", "social media", "follow me", "connect with me", "find me on",
			"social", "handle", "username", "account", "page", "channel",
			"follow", "connect", "link", "contact", "reach me", "social network",
		},

		// Default negative keywords that suggest this is not social media
		negativeKeywords: []string{
			"example", "test", "placeholder", "demo", "sample", "template",
			"mock", "fake", "dummy", "tutorial", "documentation", "guide",
			"not real", "fictional", "made up", "for testing",
		},

		// Platform-specific keywords for enhanced context analysis
		platformKeywords: map[string][]string{
			"linkedin": {
				"professional", "career", "network", "business", "work",
				"employment", "job", "resume", "cv", "experience",
			},
			"twitter": {
				"tweet", "follow", "retweet", "hashtag", "mention",
				"timeline", "trending", "viral", "thread",
			},
			"github": {
				"repository", "code", "project", "commit", "pull request",
				"fork", "star", "issue", "developer", "programming",
			},
			"facebook": {
				"post", "share", "like", "comment", "friend",
				"page", "group", "event", "photo", "status",
			},
			"instagram": {
				"photo", "image", "story", "reel", "hashtag",
				"filter", "post", "share", "follow", "like",
			},
			"youtube": {
				"video", "channel", "subscribe", "playlist", "watch",
				"upload", "stream", "content", "creator", "vlog",
			},
			"tiktok": {
				"video", "viral", "trend", "dance", "challenge",
				"creator", "content", "short", "clip", "sound",
			},
		},

		// Initialize false positive prevention
		whitelistPatterns:         []string{},
		compiledWhitelistPatterns: []*regexp.Regexp{},

		// Track configuration status
		patternsConfigured: false,

		// Initialize clustering configuration with defaults
		clusteringConfig: SocialMediaClusteringConfig{
			Enabled:            true, // Enable clustering by default
			ProximityThreshold: DefaultSocialMediaProximityThreshold,
			ConfidenceBoosts: map[string]float64{
				"same_user_multi_platform": DefaultSameUserBoost,
				"related_profiles":         DefaultRelatedProfilesBoost,
				"fragmented_references":    DefaultFragmentedRefsBoost,
				"multi_platform_presence":  DefaultMultiPlatformBoost,
			},
			MaxConfidence:          DefaultSocialMediaMaxConfidence,
			MinConfidenceThreshold: DefaultSocialMediaMinConfidenceThreshold,
			SameUserIndicators: []string{
				"same_username", "similar_username", "name_match", "bio_match",
				"cross_reference", "linked_profiles", "consistent_branding",
			},
		},
	}

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Configure configures the validator with custom settings from the configuration
func (v *Validator) Configure(cfg *config.Config) {
	// Enhanced error handling for configuration loading failures
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[ERROR] Social Media Validator: Configuration panic: %v\n", r)
			}
			// Ensure validator is in a safe state after panic
			v.patternsConfigured = false
			v.platformPatterns = make(map[string][]string)
			v.compiledPatterns = make(map[string][]*regexp.Regexp)
		}
	}()

	// Check if we have validator-specific configuration
	if cfg == nil {
		// No configuration available - log that no patterns are configured
		v.logConfigurationError("configuration object is nil", "no configuration available")
		return
	}

	if cfg.Validators == nil {
		// No validators configuration section - log that no patterns are configured
		v.logConfigurationError("validators configuration section is nil", "no validators configuration section")
		return
	}

	// Get social media validator config if it exists
	smConfig, ok := cfg.Validators["social_media"]
	if !ok {
		// No social media configuration section - log that no patterns are configured
		v.logNoSocialMediaPatterns("no social_media configuration section")
		return
	}

	// Update platform patterns if provided
	if patterns, ok := smConfig["platform_patterns"].(map[string]any); ok {
		// Set configuration flag to true when platform_patterns section is present
		v.patternsConfigured = true

		// Handle empty platform_patterns map - log informational message
		if len(patterns) == 0 {
			v.platformPatterns = make(map[string][]string)
			v.logNoSocialMediaPatterns("empty platform_patterns map configured")
			v.compilePlatformPatterns()
			return
		}

		validPlatforms := make(map[string][]string)
		totalPatterns := 0
		totalInvalid := 0

		// Process each platform's patterns
		for platform, platformPatternsAny := range patterns {
			if platformPatternsList, ok := platformPatternsAny.([]any); ok {
				validPatterns := []string{}
				invalidCount := 0

				// Validate each pattern for this platform
				for _, patternAny := range platformPatternsList {
					if patternStr, ok := patternAny.(string); ok {
						// Add case-insensitive flag if not already present
						processedPattern := v.ensureCaseInsensitive(patternStr)

						// Validate regex pattern using regexp.Compile()
						if _, err := regexp.Compile(processedPattern); err != nil {
							// Log warning for invalid pattern but continue with valid ones
							if v.observer != nil && v.observer.DebugObserver != nil {
								v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Invalid %s pattern '%s': %v", platform, patternStr, err))
								v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Skipping invalid regex pattern for %s: '%s' - Error: %v", platform, patternStr, err))
							}

							// Log invalid pattern in debug mode
							if os.Getenv("FERRET_DEBUG") == "1" {
								fmt.Fprintf(os.Stderr, "[DEBUG] Social Media: Invalid %s pattern: %v\n", platform, err)
							}
							invalidCount++
							totalInvalid++
							continue
						}
						validPatterns = append(validPatterns, processedPattern)
						totalPatterns++
					}
				}

				// Store only valid patterns for this platform
				if len(validPatterns) > 0 {
					validPlatforms[platform] = validPatterns
				}

				// Log platform-specific pattern validation results
				if v.observer != nil && v.observer.DebugObserver != nil {
					v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Platform %s pattern validation: %d valid, %d invalid patterns", platform, len(validPatterns), invalidCount))
					if len(validPatterns) > 0 {
						v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Successfully loaded %d patterns for platform %s", len(validPatterns), platform))
						for i, pattern := range validPatterns {
							v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  %s pattern %d: %s", platform, i+1, pattern))
						}
					}
					if invalidCount > 0 {
						v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Skipped %d invalid patterns for platform %s", invalidCount, platform))
					}
				}

				// Log platform patterns in debug mode
				if os.Getenv("FERRET_DEBUG") == "1" && len(validPatterns) > 0 {
					fmt.Fprintf(os.Stderr, "[DEBUG] Social Media: %s loaded %d patterns\n", platform, len(validPatterns))
				}
			}
		}

		// Store only valid platform patterns
		v.platformPatterns = validPlatforms

		// Log overall pattern validation summary
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Social media pattern validation: %d total valid patterns across %d platforms, %d invalid patterns", totalPatterns, len(validPlatforms), totalInvalid))
			if len(validPlatforms) > 0 {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Successfully loaded patterns for platforms: %v", v.getPlatformNames(validPlatforms)))
			}
			if totalInvalid > 0 {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Skipped %d invalid social media patterns during configuration", totalInvalid))
			}
		}

		// Log total patterns in debug mode
		if os.Getenv("FERRET_DEBUG") == "1" && len(validPlatforms) > 0 {
			fmt.Fprintf(os.Stderr, "[DEBUG] Social Media: Loaded %d patterns across %d platforms\n", totalPatterns, len(validPlatforms))
		}

		// Handle case where all configured patterns are invalid - log warning
		if len(validPlatforms) == 0 && len(patterns) > 0 {
			v.logNoSocialMediaPatterns("all configured social media patterns are invalid")
		}

		// Recompile patterns (only valid ones now)
		v.compilePlatformPatterns()
	} else {
		// No platform_patterns configuration provided
		if !v.patternsConfigured {
			v.logNoSocialMediaPatterns("no social media patterns configured")

			// Log no patterns in debug mode
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[INFO] Social Media: No patterns configured - detection disabled\n")
			}
		}
	}

	// Update positive keywords if provided
	if keywords, ok := smConfig["positive_keywords"].([]any); ok {
		customKeywords := []string{}
		for _, keyword := range keywords {
			if keywordStr, ok := keyword.(string); ok {
				customKeywords = append(customKeywords, keywordStr)
			}
		}
		if len(customKeywords) > 0 {
			v.positiveKeywords = customKeywords
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Loaded %d custom positive keywords", len(customKeywords)))
			}
		}
	}

	// Update negative keywords if provided
	if keywords, ok := smConfig["negative_keywords"].([]any); ok {
		customKeywords := []string{}
		for _, keyword := range keywords {
			if keywordStr, ok := keyword.(string); ok {
				customKeywords = append(customKeywords, keywordStr)
			}
		}
		if len(customKeywords) > 0 {
			v.negativeKeywords = customKeywords
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Loaded %d custom negative keywords", len(customKeywords)))
			}
		}
	}

	// Update platform-specific keywords if provided
	if platformKeywords, ok := smConfig["platform_keywords"].(map[string]any); ok {
		customPlatformKeywords := make(map[string][]string)
		for platform, keywordsAny := range platformKeywords {
			if keywordsList, ok := keywordsAny.([]any); ok {
				keywords := []string{}
				for _, keyword := range keywordsList {
					if keywordStr, ok := keyword.(string); ok {
						keywords = append(keywords, keywordStr)
					}
				}
				if len(keywords) > 0 {
					customPlatformKeywords[platform] = keywords
				}
			}
		}
		if len(customPlatformKeywords) > 0 {
			v.platformKeywords = customPlatformKeywords
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Loaded custom platform keywords for %d platforms", len(customPlatformKeywords)))
			}
		}
	}

	// Update whitelist patterns if provided
	if whitelistPatterns, ok := smConfig["whitelist_patterns"].([]any); ok {
		customWhitelistPatterns := []string{}
		validWhitelistPatterns := []string{}
		invalidCount := 0

		for _, patternAny := range whitelistPatterns {
			if patternStr, ok := patternAny.(string); ok {
				// Add case-insensitive flag if not already present
				processedPattern := v.ensureCaseInsensitive(patternStr)

				// Validate regex pattern
				if _, err := regexp.Compile(processedPattern); err != nil {
					// Log warning for invalid whitelist pattern but continue with valid ones
					if v.observer != nil && v.observer.DebugObserver != nil {
						v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Invalid whitelist pattern '%s': %v", patternStr, err))
					}

					// Log invalid whitelist pattern in debug mode
					if os.Getenv("FERRET_DEBUG") == "1" {
						fmt.Fprintf(os.Stderr, "[DEBUG] Social Media: Invalid whitelist pattern: %v\n", err)
					}
					invalidCount++
					continue
				}
				customWhitelistPatterns = append(customWhitelistPatterns, patternStr)
				validWhitelistPatterns = append(validWhitelistPatterns, processedPattern)
			}
		}

		if len(validWhitelistPatterns) > 0 {
			v.whitelistPatterns = customWhitelistPatterns
			v.compileWhitelistPatterns()
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Loaded %d valid whitelist patterns (%d invalid patterns skipped)", len(validWhitelistPatterns), invalidCount))
				for i, pattern := range customWhitelistPatterns {
					v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Whitelist pattern %d: %s", i+1, pattern))
				}
			}

			// Log whitelist patterns in debug mode
			if os.Getenv("FERRET_DEBUG") == "1" && len(validWhitelistPatterns) > 0 {
				fmt.Fprintf(os.Stderr, "[DEBUG] Social Media: Loaded %d whitelist patterns\n", len(validWhitelistPatterns))
			}
		} else if invalidCount > 0 {
			// All whitelist patterns were invalid
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("All %d configured whitelist patterns are invalid", invalidCount))
			}
		}
	}
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	// Social media validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	var finishTiming func(bool, map[string]any)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("social_media_validator", "validate_file", filePath)
	}

	if finishTiming != nil {
		finishTiming(true, map[string]any{"match_count": 0, "direct_file_processing": false})
	}

	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for social media references
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]any)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("social_media_validator", "validate_content", originalPath)
	}

	// Enhanced error handling and memory management for large files
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery for debugging
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Recovered from panic in ValidateContent for %s: %v", originalPath, r))
			}
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[ERROR] Social Media: ValidateContent panic: %v\n", r)
			}
		}
	}()

	// Memory management and monitoring for large files
	contentLength := len(content)
	if contentLength > 50*1024*1024 { // 50MB threshold
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Processing large file %s (%d MB) - enabling memory optimization", originalPath, contentLength/(1024*1024)))
		}
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] Social Media: Processing large file %d MB\n", contentLength/(1024*1024))
		}

		// Monitor memory usage for very large files
		v.monitorMemoryUsage("large_file_processing", map[string]any{
			"file_size_mb": contentLength / (1024 * 1024),
			"file_path":    originalPath,
		})
	}

	// Check if patterns are configured before processing
	if !v.patternsConfigured || len(v.compiledPatterns) == 0 {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("No social media patterns configured for %s - returning empty results", originalPath))
		}
		if finishTiming != nil {
			finishTiming(true, map[string]any{"match_count": 0, "content_length": contentLength, "patterns_configured": false})
		}
		return []detector.Match{}, nil
	}

	// Use line-based processing for social media pattern detection with error handling
	lineMatches, err := v.detectPatternsByLineWithErrorHandling(content, originalPath)
	if err != nil {
		// Log error but continue with empty results for graceful degradation
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Pattern detection failed for %s: %v", originalPath, err))
		}
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[ERROR] Social Media: Pattern detection failed: %v\n", err)
		}
		if finishTiming != nil {
			finishTiming(false, map[string]any{"match_count": 0, "content_length": contentLength, "error": err.Error()})
		}
		return []detector.Match{}, nil
	}

	// Process line matches for social media profile clustering with error handling
	processedMatches, err := v.processLineMatchesWithClusteringAndErrorHandling(lineMatches, originalPath)
	if err != nil {
		// Log error but return individual matches for graceful degradation
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Clustering failed for %s, using individual matches: %v", originalPath, err))
		}
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[WARN] Social Media: Clustering failed: %v\n", err)
		}
		// Fallback to flattened individual matches
		var allMatches []detector.Match
		for _, matches := range lineMatches {
			allMatches = append(allMatches, matches...)
		}
		processedMatches = allMatches
	}

	// Performance monitoring and memory cleanup
	if finishTiming != nil {
		finishTiming(true, map[string]any{
			"match_count":        len(processedMatches),
			"content_length":     contentLength,
			"patterns_used":      len(v.compiledPatterns),
			"clustering_enabled": v.clusteringConfig.Enabled,
		})
	}

	// Memory cleanup for large files
	if contentLength > 50*1024*1024 {
		// Force garbage collection for large files to free memory
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Completed processing large file %s - memory cleanup initiated", originalPath))
		}
	}

	return processedMatches, nil
}

// detectPatternsByLineWithErrorHandling wraps detectPatternsByLine with comprehensive error handling
func (v *Validator) detectPatternsByLineWithErrorHandling(content string, originalPath string) (map[int][]detector.Match, error) {
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery for debugging
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Recovered from panic in detectPatternsByLine for %s: %v", originalPath, r))
			}
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[ERROR] Social Media: Pattern detection panic: %v\n", r)
			}
		}
	}()

	// Check for empty content
	if len(content) == 0 {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Empty content for %s - returning empty results", originalPath))
		}
		return make(map[int][]detector.Match), nil
	}

	// Check if patterns are available
	if len(v.compiledPatterns) == 0 {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("No compiled patterns available for %s", originalPath))
		}
		return make(map[int][]detector.Match), nil
	}

	// Call the original method with error handling
	lineMatches := v.detectPatternsByLine(content, originalPath)
	return lineMatches, nil
}

// processLineMatchesWithClusteringAndErrorHandling wraps clustering with comprehensive error handling
func (v *Validator) processLineMatchesWithClusteringAndErrorHandling(lineMatches map[int][]detector.Match, originalPath string) ([]detector.Match, error) {
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery for debugging
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Recovered from panic in clustering for %s: %v", originalPath, r))
			}
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[ERROR] Social Media: Clustering panic: %v\n", r)
			}
		}
	}()

	// Check for empty line matches
	if len(lineMatches) == 0 {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("No line matches for clustering in %s", originalPath))
		}
		return []detector.Match{}, nil
	}

	// Call the original method with error handling
	processedMatches := v.processLineMatchesWithClustering(lineMatches, originalPath)
	return processedMatches, nil
}

// processLineMatchesWithClustering processes line-based matches and applies social media profile clustering
// This method groups related social media matches and reconstructs fragmented profile references
func (v *Validator) processLineMatchesWithClustering(lineMatches map[int][]detector.Match, originalPath string) []detector.Match {
	var allMatches []detector.Match

	// Flatten line matches into a single slice for clustering analysis
	for _, matches := range lineMatches {
		allMatches = append(allMatches, matches...)
	}

	// If clustering is disabled or we have no matches, return flattened matches
	if !v.clusteringConfig.Enabled || len(allMatches) == 0 {
		return allMatches
	}

	// If we only have one match, no clustering needed
	if len(allMatches) == 1 {
		return allMatches
	}

	// Group matches by potential clusters
	clusterGroups := v.identifyProfileClusters(allMatches)

	var processedMatches []detector.Match

	// Process each cluster group
	for _, clusterGroup := range clusterGroups {
		if len(clusterGroup) == 1 {
			// Single match - no clustering needed
			processedMatches = append(processedMatches, clusterGroup[0])
		} else {
			// Multiple matches - analyze for clustering
			analysis := v.analyzeSocialMediaClusteringContext(clusterGroup)

			if analysis.ShouldReconstruct {
				// Reconstruct the cluster into a single match
				reconstructedMatch, err := v.reconstructSocialMediaClusterWithFallback(clusterGroup)
				if err != nil {
					// Fallback: add individual matches if reconstruction fails
					if v.observer != nil && v.observer.DebugObserver != nil {
						v.observer.DebugObserver.LogDetail("socialmedia",
							fmt.Sprintf("Social media cluster reconstruction failed, using individual matches: %v", err))
					}
					processedMatches = append(processedMatches, clusterGroup...)
				} else {
					// Add the reconstructed cluster match
					processedMatches = append(processedMatches, reconstructedMatch)
				}
			} else {
				// Don't reconstruct - add individual matches
				processedMatches = append(processedMatches, clusterGroup...)
			}
		}
	}

	return processedMatches
}

// CalculateConfidence implements the detector.Validator interface
// with multi-factor validation and platform-specific confidence scoring
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := make(map[string]bool)
	var confidence float64 = 0

	// Enhanced error handling for confidence calculation
	defer func() {
		if r := recover(); r != nil {
			// Log panic recovery for debugging
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Recovered from panic in CalculateConfidence for match '%s': %v", match, r))
			}
			if v.isDebugEnabled() {
				fmt.Fprintf(os.Stderr, "[ERROR] Social Media Validator: Panic in confidence calculation\n")
				fmt.Fprintf(os.Stderr, "[ERROR]   Match: %s\n", match)
				fmt.Fprintf(os.Stderr, "[ERROR]   Panic: %v\n", r)
				fmt.Fprintf(os.Stderr, "[ERROR]   Action: Returning low confidence for safety\n")
			}
		}
	}()

	// Input validation
	if match == "" {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", "Empty match provided to CalculateConfidence")
		}
		checks["valid_input"] = false
		return 0.0, checks
	}
	checks["valid_input"] = true

	// Determine which platform this match belongs to
	platform := v.identifyPlatform(match)
	if platform == "" {
		// Unknown platform - assign low confidence with enhanced logging
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Unknown platform for match: %s", match))
		}
		if v.isDebugEnabled() {
			fmt.Fprintf(os.Stderr, "[DEBUG] Social Media Validator: Unknown platform for match: %s\n", match)
		}
		checks["platform_identified"] = false
		return 10.0, checks
	}
	checks["platform_identified"] = true

	// Base confidence adjustment based on platform type
	platformBonus := v.getPlatformConfidenceBonus(platform)
	confidence += platformBonus

	// Validate URL format if it's a URL
	if strings.HasPrefix(strings.ToLower(match), "http://") || strings.HasPrefix(strings.ToLower(match), "https://") {
		checks["valid_url_format"] = v.validateURLFormat(match, platform)
		if checks["valid_url_format"] {
			confidence += 30.0
		} else {
			confidence -= 10.0 // Penalty for invalid URL format
		}
	} else {
		// Non-URL patterns (handles, etc.)
		checks["valid_url_format"] = false
		confidence += 15.0 // Lower base confidence for non-URL patterns
	}

	// Validate username format
	username := v.extractUsername(match, platform)
	if username != "" {
		checks["valid_username_format"] = v.validateUsernameFormat(username, platform)
		if checks["valid_username_format"] {
			confidence += 25.0
		} else {
			confidence -= 15.0 // Penalty for invalid username format
		}
	} else {
		checks["valid_username_format"] = false
		confidence -= 5.0 // Small penalty for no extractable username
	}

	// Platform-specific validation with enhanced checks
	checks["platform_specific_validation"] = v.validatePlatformSpecific(match, platform)
	if checks["platform_specific_validation"] {
		confidence += 20.0
	} else {
		confidence -= 10.0 // Penalty for failing platform-specific validation
	}

	// Pattern specificity check with false positive prevention
	checks["pattern_specificity"] = v.validatePatternSpecificity(match, platform)
	if checks["pattern_specificity"] {
		confidence += 15.0
	} else {
		confidence -= 20.0 // Strong penalty for non-specific patterns
	}

	// Length and character validation
	checks["reasonable_length"] = v.validateReasonableLength(match, platform)
	if checks["reasonable_length"] {
		confidence += 10.0
	} else {
		confidence -= 15.0 // Penalty for unreasonable length
	}

	// Additional validation checks for enhanced accuracy
	checks["domain_validation"] = v.validateDomain(match, platform)
	if checks["domain_validation"] {
		confidence += 12.0
	} else {
		confidence -= 8.0 // Penalty for invalid domain
	}

	// Character set validation
	checks["valid_character_set"] = v.validateCharacterSet(match, platform)
	if checks["valid_character_set"] {
		confidence += 8.0
	} else {
		confidence -= 12.0 // Penalty for invalid characters
	}

	// Path structure validation for URLs
	checks["valid_path_structure"] = v.validatePathStructure(match, platform)
	if checks["valid_path_structure"] {
		confidence += 10.0
	} else {
		confidence -= 8.0 // Penalty for invalid path structure
	}

	// False positive detection
	checks["not_false_positive"] = v.validateNotFalsePositive(match, platform)
	if !checks["not_false_positive"] {
		confidence -= 30.0 // Strong penalty for likely false positives
	}

	// Ensure confidence stays within reasonable bounds
	if confidence > 100 {
		confidence = 100
	} else if confidence < 0 {
		confidence = 0
	}

	return confidence, checks
}

// identifyPlatform determines which platform a match belongs to
func (v *Validator) identifyPlatform(match string) string {
	matchLower := strings.ToLower(match)

	// Check each platform's patterns to identify the match
	for platform, patterns := range v.compiledPatterns {
		for _, regex := range patterns {
			if regex.MatchString(match) {
				return platform
			}
		}
	}

	// Fallback: identify by domain/content
	if strings.Contains(matchLower, "linkedin.com") {
		return "linkedin"
	}
	if strings.Contains(matchLower, "twitter.com") || strings.Contains(matchLower, "x.com") {
		return "twitter"
	}
	// Handle Twitter handles that start with @
	if strings.HasPrefix(match, "@") && len(match) >= 2 && len(match) <= 16 {
		return "twitter"
	}
	if strings.Contains(matchLower, "github.com") || strings.Contains(matchLower, "github.io") {
		return "github"
	}
	if strings.Contains(matchLower, "facebook.com") || strings.Contains(matchLower, "fb.com") {
		return "facebook"
	}
	if strings.Contains(matchLower, "instagram.com") || strings.Contains(matchLower, "instagr.am") {
		return "instagram"
	}
	if strings.Contains(matchLower, "youtube.com") {
		return "youtube"
	}
	if strings.Contains(matchLower, "tiktok.com") {
		return "tiktok"
	}
	if strings.Contains(matchLower, "discord.gg") || strings.Contains(matchLower, "discord.com") {
		return "discord"
	}
	if strings.Contains(matchLower, "reddit.com") {
		return "reddit"
	}

	return ""
}

// validateURLFormat validates the URL format for the specific platform
func (v *Validator) validateURLFormat(match string, platform string) bool {
	matchLower := strings.ToLower(match)

	// Basic URL format validation
	if !strings.HasPrefix(matchLower, "http://") && !strings.HasPrefix(matchLower, "https://") {
		return false
	}

	// Platform-specific URL validation
	switch platform {
	case "linkedin", "linkedin_patterns":
		return strings.Contains(matchLower, "linkedin.com") &&
			(strings.Contains(matchLower, "/in/") || strings.Contains(matchLower, "/company/") || strings.Contains(matchLower, "/pub/"))

	case "twitter", "twitter_patterns":
		return (strings.Contains(matchLower, "twitter.com") || strings.Contains(matchLower, "x.com")) &&
			!strings.Contains(matchLower, "/status/") // Exclude tweet URLs

	case "github", "github_patterns":
		return strings.Contains(matchLower, "github.com") || strings.Contains(matchLower, "github.io")

	case "facebook", "facebook_patterns":
		return (strings.Contains(matchLower, "facebook.com") || strings.Contains(matchLower, "fb.com")) &&
			!strings.Contains(matchLower, "/posts/") // Exclude post URLs

	case "instagram", "instagram_patterns":
		return (strings.Contains(matchLower, "instagram.com") || strings.Contains(matchLower, "instagr.am")) &&
			!strings.Contains(matchLower, "/p/") // Exclude post URLs

	case "youtube", "youtube_patterns":
		return strings.Contains(matchLower, "youtube.com") &&
			(strings.Contains(matchLower, "/user/") || strings.Contains(matchLower, "/c/") ||
				strings.Contains(matchLower, "/channel/") || strings.Contains(matchLower, "/@"))

	case "tiktok", "tiktok_patterns":
		return strings.Contains(matchLower, "tiktok.com")

	default:
		return true // Generic validation for other platforms
	}
}

// validateUsernameFormat validates the username format for the specific platform
func (v *Validator) validateUsernameFormat(username string, platform string) bool {
	if username == "" {
		return false
	}

	// Platform-specific username validation
	switch platform {
	case "linkedin", "linkedin_patterns":
		// LinkedIn usernames: alphanumeric, hyphens, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) && len(username) >= 3 && len(username) <= 100

	case "twitter", "twitter_patterns":
		// Twitter usernames: alphanumeric, underscores, 1-15 characters
		return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) && len(username) >= 1 && len(username) <= 15

	case "github", "github_patterns":
		// GitHub usernames: alphanumeric, hyphens, cannot start/end with hyphen
		return regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`).MatchString(username) && len(username) >= 1 && len(username) <= 39

	case "facebook", "facebook_patterns":
		// Facebook usernames: alphanumeric, dots, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9._]+$`).MatchString(username) && len(username) >= 5 && len(username) <= 50

	case "instagram", "instagram_patterns":
		// Instagram usernames: alphanumeric, dots, underscores, 1-30 characters
		return regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(username) && len(username) >= 1 && len(username) <= 30

	case "youtube", "youtube_patterns":
		// YouTube usernames: alphanumeric, hyphens, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) && len(username) >= 1 && len(username) <= 100

	case "tiktok", "tiktok_patterns":
		// TikTok usernames: alphanumeric, dots, underscores, 2-24 characters
		return regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(username) && len(username) >= 2 && len(username) <= 24

	default:
		// Generic username validation
		return regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(username) && len(username) >= 1 && len(username) <= 100
	}
}

// validatePlatformSpecific performs comprehensive platform-specific validation checks
func (v *Validator) validatePlatformSpecific(match string, platform string) bool {
	matchLower := strings.ToLower(match)

	switch platform {
	case "linkedin", "linkedin_patterns":
		return v.validateLinkedInSpecific(match, matchLower)

	case "twitter", "twitter_patterns":
		return v.validateTwitterSpecific(match, matchLower)

	case "github", "github_patterns":
		return v.validateGitHubSpecific(match, matchLower)

	case "facebook", "facebook_patterns":
		return v.validateFacebookSpecific(match, matchLower)

	case "instagram", "instagram_patterns":
		return v.validateInstagramSpecific(match, matchLower)

	case "youtube", "youtube_patterns":
		return v.validateYouTubeSpecific(match, matchLower)

	case "tiktok", "tiktok_patterns":
		return v.validateTikTokSpecific(match, matchLower)

	case "discord", "discord_patterns":
		return v.validateDiscordSpecific(match, matchLower)

	case "reddit", "reddit_patterns":
		return v.validateRedditSpecific(match, matchLower)

	default:
		return true // Generic validation passes
	}
}

// validateLinkedInSpecific performs comprehensive LinkedIn URL and handle validation
func (v *Validator) validateLinkedInSpecific(match string, matchLower string) bool {
	// Personal profile URLs: linkedin.com/in/username
	if strings.Contains(matchLower, "/in/") {
		// No double slashes
		if strings.Contains(matchLower, "/in//") {
			return false
		}
		// Extract and validate username
		parts := strings.Split(matchLower, "/in/")
		if len(parts) > 1 {
			username := strings.Split(parts[1], "/")[0]
			if username == "" || len(username) < 3 || len(username) > 100 {
				return false
			}
			// LinkedIn usernames: alphanumeric, hyphens, underscores
			return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username)
		}
		return false
	}

	// Company page URLs: linkedin.com/company/companyname
	if strings.Contains(matchLower, "/company/") {
		// No double slashes
		if strings.Contains(matchLower, "/company//") {
			return false
		}
		// Extract and validate company name
		parts := strings.Split(matchLower, "/company/")
		if len(parts) > 1 {
			companyName := strings.Split(parts[1], "/")[0]
			if companyName == "" || len(companyName) < 2 || len(companyName) > 100 {
				return false
			}
			// Company names: alphanumeric, hyphens, underscores
			return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(companyName)
		}
		return false
	}

	// Public profile URLs: linkedin.com/pub/name/...
	if strings.Contains(matchLower, "/pub/") {
		// No double slashes
		if strings.Contains(matchLower, "/pub//") {
			return false
		}
		// Extract and validate pub path
		parts := strings.Split(matchLower, "/pub/")
		if len(parts) > 1 {
			pubPath := strings.Split(parts[1], "?")[0] // Remove query parameters
			if pubPath == "" || len(pubPath) < 3 {
				return false
			}
			// Pub paths can contain slashes and alphanumeric characters
			return regexp.MustCompile(`^[a-zA-Z0-9_/-]+$`).MatchString(pubPath)
		}
		return false
	}

	// School pages: linkedin.com/school/schoolname
	if strings.Contains(matchLower, "/school/") {
		// No double slashes
		if strings.Contains(matchLower, "/school//") {
			return false
		}
		// Extract and validate school name
		parts := strings.Split(matchLower, "/school/")
		if len(parts) > 1 {
			schoolName := strings.Split(parts[1], "/")[0]
			if schoolName == "" || len(schoolName) < 2 || len(schoolName) > 100 {
				return false
			}
			// School names: alphanumeric, hyphens, underscores
			return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(schoolName)
		}
		return false
	}

	return true
}

// validateTwitterSpecific performs comprehensive Twitter/X handle and URL validation
func (v *Validator) validateTwitterSpecific(match string, matchLower string) bool {
	// Handle format: @username
	if strings.HasPrefix(match, "@") {
		username := match[1:]
		// Twitter handles: 1-15 characters, alphanumeric and underscores only
		if len(username) < 1 || len(username) > 15 {
			return false
		}
		// Must start with letter or number, can contain underscores
		return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) &&
			!strings.HasPrefix(username, "_") && !strings.HasSuffix(username, "_")
	}

	// Profile URLs: twitter.com/username or x.com/username
	if strings.Contains(matchLower, "twitter.com/") || strings.Contains(matchLower, "x.com/") {
		// Extract username from URL
		parts := strings.Split(matchLower, "/")
		if len(parts) < 4 {
			return false
		}
		username := parts[3]

		// Skip tweet URLs and other non-profile paths
		if strings.Contains(matchLower, "/status/") || strings.Contains(matchLower, "/i/") ||
			strings.Contains(matchLower, "/search") || strings.Contains(matchLower, "/hashtag/") {
			return false
		}

		// Validate username format
		if len(username) < 1 || len(username) > 15 {
			return false
		}
		return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) &&
			!strings.HasPrefix(username, "_") && !strings.HasSuffix(username, "_")
	}

	return true
}

// validateGitHubSpecific performs comprehensive GitHub username and repository URL validation
func (v *Validator) validateGitHubSpecific(match string, matchLower string) bool {
	// GitHub repository URLs: github.com/username or github.com/username/repository
	if strings.Contains(matchLower, "github.com/") {
		parts := strings.Split(matchLower, "github.com/")
		if len(parts) < 2 {
			return false
		}

		pathParts := strings.Split(parts[1], "/")
		if len(pathParts) < 1 || pathParts[0] == "" {
			return false
		}

		username := pathParts[0]

		// GitHub usernames: 1-39 characters, alphanumeric and hyphens, cannot start/end with hyphen
		if len(username) < 1 || len(username) > 39 {
			return false
		}
		if strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
			return false
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(username) {
			return false
		}

		// If repository name is present, validate it too
		if len(pathParts) > 1 && pathParts[1] != "" {
			repoName := pathParts[1]
			// Repository names: alphanumeric, hyphens, underscores, dots
			if len(repoName) > 100 {
				return false
			}
			if !regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(repoName) {
				return false
			}
		}

		return true
	}

	// GitHub Pages: username.github.io
	if strings.Contains(matchLower, ".github.io") {
		// Extract username from subdomain
		parts := strings.Split(matchLower, ".")
		if len(parts) < 3 {
			return false
		}

		// Find the part before .github.io
		for i, part := range parts {
			if part == "github" && i+1 < len(parts) && parts[i+1] == "io" {
				if i == 0 {
					return false // No username
				}
				username := parts[i-1]
				// Remove protocol if present
				if strings.Contains(username, "//") {
					username = strings.Split(username, "//")[1]
				}

				// Validate GitHub username format
				if len(username) < 1 || len(username) > 39 {
					return false
				}
				if strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
					return false
				}
				return regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(username)
			}
		}
		return false
	}

	return true
}

// validateFacebookSpecific performs comprehensive Facebook profile URL and ID validation
func (v *Validator) validateFacebookSpecific(match string, matchLower string) bool {
	// Numeric ID format: facebook.com/profile.php?id=123456789
	if strings.Contains(matchLower, "profile.php?id=") {
		// Extract and validate numeric ID
		idMatch := regexp.MustCompile(`profile\.php\?id=(\d+)`).FindStringSubmatch(matchLower)
		if len(idMatch) < 2 {
			return false
		}
		id := idMatch[1]
		// Facebook numeric IDs are typically 15-17 digits
		return len(id) >= 10 && len(id) <= 20
	}

	// Username format: facebook.com/username or fb.com/username
	if strings.Contains(matchLower, "facebook.com/") || strings.Contains(matchLower, "fb.com/") {
		// Extract username from URL
		parts := strings.Split(matchLower, "/")
		if len(parts) < 4 {
			return false
		}
		username := parts[3]

		// Skip post URLs and other non-profile paths
		if strings.Contains(matchLower, "/posts/") || strings.Contains(matchLower, "/photos/") ||
			strings.Contains(matchLower, "/videos/") || username == "profile.php" {
			return false
		}

		// Facebook usernames: 5-50 characters, alphanumeric, dots, underscores
		if len(username) < 5 || len(username) > 50 {
			return false
		}
		return regexp.MustCompile(`^[a-zA-Z0-9._]+$`).MatchString(username) &&
			!strings.HasPrefix(username, ".") && !strings.HasSuffix(username, ".")
	}

	return true
}

// validateInstagramSpecific performs comprehensive Instagram username and URL validation
func (v *Validator) validateInstagramSpecific(match string, matchLower string) bool {
	// Instagram URLs: instagram.com/username/ or instagr.am/username/
	if strings.Contains(matchLower, "instagram.com/") || strings.Contains(matchLower, "instagr.am/") {
		// No double slashes
		if strings.Contains(matchLower, "//") && !strings.Contains(matchLower, "://") {
			return false
		}

		// Extract username
		var username string
		if strings.Contains(matchLower, "instagram.com/") {
			parts := strings.Split(matchLower, "instagram.com/")
			if len(parts) > 1 {
				username = strings.Split(parts[1], "/")[0]
			}
		} else if strings.Contains(matchLower, "instagr.am/") {
			parts := strings.Split(matchLower, "instagr.am/")
			if len(parts) > 1 {
				username = strings.Split(parts[1], "/")[0]
			}
		}

		if username == "" {
			return false
		}

		// Skip post URLs and other non-profile paths
		if strings.Contains(matchLower, "/p/") || strings.Contains(matchLower, "/reel/") ||
			strings.Contains(matchLower, "/tv/") || strings.Contains(matchLower, "/stories/") {
			return false
		}

		// Instagram usernames: 1-30 characters, alphanumeric, dots, underscores
		if len(username) < 1 || len(username) > 30 {
			return false
		}
		return regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(username) &&
			!strings.HasPrefix(username, ".") && !strings.HasSuffix(username, ".") &&
			!strings.Contains(username, "..")
	}

	return true
}

// validateYouTubeSpecific performs comprehensive YouTube channel URL and handle validation
func (v *Validator) validateYouTubeSpecific(match string, matchLower string) bool {
	// Channel URLs: youtube.com/user/name, youtube.com/c/name, youtube.com/channel/id
	if strings.Contains(matchLower, "youtube.com/") {
		// User channels: youtube.com/user/username
		if strings.Contains(matchLower, "/user/") {
			parts := strings.Split(matchLower, "/user/")
			if len(parts) > 1 {
				username := strings.Split(parts[1], "/")[0]
				if len(username) < 1 || len(username) > 100 {
					return false
				}
				return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username)
			}
			return false
		}

		// Custom channels: youtube.com/c/channelname
		if strings.Contains(matchLower, "/c/") {
			parts := strings.Split(matchLower, "/c/")
			if len(parts) > 1 {
				channelName := strings.Split(parts[1], "/")[0]
				if len(channelName) < 1 || len(channelName) > 100 {
					return false
				}
				return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(channelName)
			}
			return false
		}

		// Channel IDs: youtube.com/channel/UCxxxxxxxxxxxxxxxxxxxxx
		if strings.Contains(matchLower, "/channel/") {
			parts := strings.Split(matchLower, "/channel/")
			if len(parts) > 1 {
				channelID := strings.Split(parts[1], "/")[0]
				// YouTube channel IDs are typically 24 characters starting with UC
				if len(channelID) != 24 || !strings.HasPrefix(channelID, "UC") {
					return false
				}
				return regexp.MustCompile(`^UC[a-zA-Z0-9_-]{22}$`).MatchString(channelID)
			}
			return false
		}

		// Handle format: youtube.com/@username
		if strings.Contains(matchLower, "/@") {
			parts := strings.Split(matchLower, "/@")
			if len(parts) > 1 {
				handle := strings.Split(parts[1], "/")[0]
				if len(handle) < 3 || len(handle) > 30 {
					return false
				}
				return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(handle)
			}
			return false
		}
	}

	return true
}

// validateTikTokSpecific performs comprehensive TikTok handle and URL validation
func (v *Validator) validateTikTokSpecific(match string, matchLower string) bool {
	// Handle format: tiktok.com/@username
	if strings.Contains(matchLower, "/@") {
		// No double slashes
		if strings.Contains(matchLower, "//@") {
			return false
		}

		parts := strings.Split(matchLower, "/@")
		if len(parts) > 1 {
			username := strings.Split(parts[1], "/")[0]
			// TikTok usernames: 2-24 characters, alphanumeric, dots, underscores
			if len(username) < 2 || len(username) > 24 {
				return false
			}
			return regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(username) &&
				!strings.HasPrefix(username, ".") && !strings.HasSuffix(username, ".") &&
				!strings.Contains(username, "..")
		}
		return false
	}

	// Short URLs: tiktok.com/t/shortcode
	if strings.Contains(matchLower, "/t/") {
		parts := strings.Split(matchLower, "/t/")
		if len(parts) > 1 {
			shortCode := strings.Split(parts[1], "/")[0]
			// TikTok short codes are typically 9-10 alphanumeric characters
			if len(shortCode) < 8 || len(shortCode) > 12 {
				return false
			}
			return regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(shortCode)
		}
		return false
	}

	return true
}

// validateDiscordSpecific performs comprehensive Discord server and user validation
func (v *Validator) validateDiscordSpecific(match string, matchLower string) bool {
	// Discord server invites: discord.gg/invitecode
	if strings.Contains(matchLower, "discord.gg/") {
		parts := strings.Split(matchLower, "discord.gg/")
		if len(parts) > 1 {
			inviteCode := strings.Split(parts[1], "/")[0]
			// Discord invite codes are typically 6-10 alphanumeric characters
			if len(inviteCode) < 6 || len(inviteCode) > 10 {
				return false
			}
			return regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(inviteCode)
		}
		return false
	}

	// Discord user profiles: discord.com/users/userid
	if strings.Contains(matchLower, "discord.com/users/") {
		parts := strings.Split(matchLower, "/users/")
		if len(parts) > 1 {
			userID := strings.Split(parts[1], "/")[0]
			// Discord user IDs are 17-19 digit numbers (snowflakes)
			if len(userID) < 17 || len(userID) > 19 {
				return false
			}
			return regexp.MustCompile(`^\d+$`).MatchString(userID)
		}
		return false
	}

	return true
}

// validateRedditSpecific performs comprehensive Reddit user and subreddit validation
func (v *Validator) validateRedditSpecific(match string, matchLower string) bool {
	// Reddit user profiles: reddit.com/u/username or reddit.com/user/username
	if strings.Contains(matchLower, "/u/") || strings.Contains(matchLower, "/user/") {
		var username string
		if strings.Contains(matchLower, "/u/") {
			parts := strings.Split(matchLower, "/u/")
			if len(parts) > 1 {
				username = strings.Split(parts[1], "/")[0]
			}
		} else {
			parts := strings.Split(matchLower, "/user/")
			if len(parts) > 1 {
				username = strings.Split(parts[1], "/")[0]
			}
		}

		if username == "" {
			return false
		}

		// Reddit usernames: 3-20 characters, alphanumeric, hyphens, underscores
		if len(username) < 3 || len(username) > 20 {
			return false
		}
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) &&
			!strings.HasPrefix(username, "-") && !strings.HasSuffix(username, "-")
	}

	// Reddit subreddits: reddit.com/r/subredditname
	if strings.Contains(matchLower, "/r/") {
		parts := strings.Split(matchLower, "/r/")
		if len(parts) > 1 {
			subreddit := strings.Split(parts[1], "/")[0]
			// Subreddit names: 2-21 characters, alphanumeric, underscores
			if len(subreddit) < 2 || len(subreddit) > 21 {
				return false
			}
			return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(subreddit)
		}
		return false
	}

	return true
}

// validatePatternSpecificity checks if the pattern is specific enough to avoid false positives
func (v *Validator) validatePatternSpecificity(match string, platform string) bool {
	matchLower := strings.ToLower(match)

	// Check for overly generic patterns
	if len(match) < 10 && !strings.HasPrefix(match, "@") {
		return false // Too short to be specific
	}

	// Platform-specific specificity checks
	switch platform {
	case "linkedin", "linkedin_patterns":
		return strings.Contains(matchLower, "linkedin.com") &&
			(strings.Contains(matchLower, "/in/") || strings.Contains(matchLower, "/company/"))

	case "twitter", "twitter_patterns":
		if strings.HasPrefix(match, "@") {
			return len(match) > 2 // @x is too short
		}
		return strings.Contains(matchLower, "twitter.com") || strings.Contains(matchLower, "x.com")

	case "github", "github_patterns":
		return strings.Contains(matchLower, "github.com") || strings.Contains(matchLower, "github.io")

	default:
		return true // Generic specificity check passes
	}
}

// validateReasonableLength checks if the match has a reasonable length
func (v *Validator) validateReasonableLength(match string, platform string) bool {
	// Platform-specific length validation
	switch platform {
	case "linkedin", "linkedin_patterns":
		// LinkedIn URLs can be longer due to profile paths
		return len(match) >= 10 && len(match) <= 300
	case "twitter", "twitter_patterns":
		if strings.HasPrefix(match, "@") {
			// Twitter handles: 1-15 characters plus @
			return len(match) >= 2 && len(match) <= 16
		}
		// Twitter URLs
		return len(match) >= 15 && len(match) <= 150
	case "github", "github_patterns":
		// GitHub URLs can include repository paths
		return len(match) >= 10 && len(match) <= 250
	case "facebook", "facebook_patterns":
		// Facebook URLs vary in length
		return len(match) >= 10 && len(match) <= 200
	case "instagram", "instagram_patterns":
		// Instagram URLs are typically shorter
		return len(match) >= 10 && len(match) <= 150
	case "youtube", "youtube_patterns":
		// YouTube URLs can be long with channel IDs
		return len(match) >= 15 && len(match) <= 300
	case "tiktok", "tiktok_patterns":
		// TikTok URLs are typically shorter
		return len(match) >= 10 && len(match) <= 150
	default:
		// General length bounds
		return len(match) >= 5 && len(match) <= 200
	}
}

// getPlatformConfidenceBonus returns a platform-specific confidence bonus
func (v *Validator) getPlatformConfidenceBonus(platform string) float64 {
	// Different platforms have different reliability indicators
	switch platform {
	case "linkedin", "linkedin_patterns":
		return 5.0 // LinkedIn URLs are typically more structured
	case "github", "github_patterns":
		return 5.0 // GitHub URLs are well-structured
	case "twitter", "twitter_patterns":
		return 3.0 // Twitter handles can be ambiguous
	case "facebook", "facebook_patterns":
		return 4.0 // Facebook URLs are fairly structured
	case "instagram", "instagram_patterns":
		return 4.0 // Instagram URLs are structured
	case "youtube", "youtube_patterns":
		return 4.0 // YouTube URLs are structured
	case "tiktok", "tiktok_patterns":
		return 3.0 // TikTok URLs can vary
	default:
		return 2.0 // Generic platform bonus
	}
}

// validateDomain validates the domain portion of URLs for the specific platform
func (v *Validator) validateDomain(match string, platform string) bool {
	if !strings.Contains(match, "://") {
		// Not a URL, skip domain validation
		return true
	}

	matchLower := strings.ToLower(match)

	switch platform {
	case "linkedin", "linkedin_patterns":
		return strings.Contains(matchLower, "linkedin.com")
	case "twitter", "twitter_patterns":
		return strings.Contains(matchLower, "twitter.com") || strings.Contains(matchLower, "x.com")
	case "github", "github_patterns":
		return strings.Contains(matchLower, "github.com") || strings.Contains(matchLower, "github.io")
	case "facebook", "facebook_patterns":
		return strings.Contains(matchLower, "facebook.com") || strings.Contains(matchLower, "fb.com")
	case "instagram", "instagram_patterns":
		return strings.Contains(matchLower, "instagram.com") || strings.Contains(matchLower, "instagr.am")
	case "youtube", "youtube_patterns":
		return strings.Contains(matchLower, "youtube.com") || strings.Contains(matchLower, "youtu.be")
	case "tiktok", "tiktok_patterns":
		return strings.Contains(matchLower, "tiktok.com")
	case "discord", "discord_patterns":
		return strings.Contains(matchLower, "discord.gg") || strings.Contains(matchLower, "discord.com")
	case "reddit", "reddit_patterns":
		return strings.Contains(matchLower, "reddit.com")
	default:
		return true // Generic validation passes
	}
}

// validateCharacterSet validates that the match contains only valid characters for the platform
func (v *Validator) validateCharacterSet(match string, platform string) bool {
	// Extract the relevant part for character validation
	username := v.extractUsername(match, platform)
	if username == "" {
		// If we can't extract username, validate the whole match
		username = match
	}

	switch platform {
	case "linkedin", "linkedin_patterns":
		// LinkedIn: alphanumeric, hyphens, underscores, dots
		return regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(username) ||
			strings.Contains(match, "://") // URLs get different validation
	case "twitter", "twitter_patterns":
		if strings.HasPrefix(match, "@") {
			// Twitter handles: alphanumeric and underscores only
			return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username)
		}
		return true // URLs get different validation
	case "github", "github_patterns":
		// GitHub: alphanumeric and hyphens, cannot start/end with hyphen
		if strings.Contains(match, "://") {
			return true // URLs get different validation
		}
		return regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`).MatchString(username)
	case "facebook", "facebook_patterns":
		// Facebook: alphanumeric, dots, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9._]+$`).MatchString(username) ||
			strings.Contains(match, "://") // URLs get different validation
	case "instagram", "instagram_patterns":
		// Instagram: alphanumeric, dots, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(username) ||
			strings.Contains(match, "://") // URLs get different validation
	case "youtube", "youtube_patterns":
		// YouTube: alphanumeric, hyphens, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) ||
			strings.Contains(match, "://") // URLs get different validation
	case "tiktok", "tiktok_patterns":
		// TikTok: alphanumeric, dots, underscores
		return regexp.MustCompile(`^[a-zA-Z0-9_.]+$`).MatchString(username) ||
			strings.Contains(match, "://") // URLs get different validation
	default:
		// Generic character validation
		return regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(username) ||
			strings.Contains(match, "://") // URLs get different validation
	}
}

// validatePathStructure validates the URL path structure for the specific platform
func (v *Validator) validatePathStructure(match string, platform string) bool {
	if !strings.Contains(match, "://") {
		// Not a URL, skip path validation
		return true
	}

	matchLower := strings.ToLower(match)

	switch platform {
	case "linkedin", "linkedin_patterns":
		// LinkedIn requires specific path structures
		return strings.Contains(matchLower, "/in/") ||
			strings.Contains(matchLower, "/company/") ||
			strings.Contains(matchLower, "/pub/") ||
			strings.Contains(matchLower, "/school/")
	case "twitter", "twitter_patterns":
		// Twitter URLs should have username after domain
		parts := strings.Split(matchLower, "/")
		return len(parts) >= 4 && parts[3] != "" // domain/username
	case "github", "github_patterns":
		// GitHub URLs should have username (and optionally repo)
		if strings.Contains(matchLower, "github.com/") {
			parts := strings.Split(matchLower, "github.com/")
			if len(parts) > 1 {
				pathParts := strings.Split(parts[1], "/")
				return len(pathParts) >= 1 && pathParts[0] != ""
			}
		}
		return strings.Contains(matchLower, "github.io") // GitHub Pages
	case "facebook", "facebook_patterns":
		// Facebook URLs should have username or profile ID
		return !strings.HasSuffix(matchLower, "facebook.com/") &&
			!strings.HasSuffix(matchLower, "fb.com/")
	case "instagram", "instagram_patterns":
		// Instagram URLs should have username
		return !strings.HasSuffix(matchLower, "instagram.com/") &&
			!strings.HasSuffix(matchLower, "instagr.am/")
	case "youtube", "youtube_patterns":
		// YouTube URLs should have proper channel structure
		return strings.Contains(matchLower, "/user/") ||
			strings.Contains(matchLower, "/c/") ||
			strings.Contains(matchLower, "/channel/") ||
			strings.Contains(matchLower, "/@")
	case "tiktok", "tiktok_patterns":
		// TikTok URLs should have username or short URL
		return strings.Contains(matchLower, "/@") ||
			strings.Contains(matchLower, "/t/")
	default:
		return true // Generic validation passes
	}
}

// validateNotFalsePositive checks for common false positive patterns
// Implements comprehensive false positive prevention including:
// - Negative keyword filtering for test data and examples
// - Placeholder URL detection and exclusion
// - Context-based false positive detection (code comments, documentation)
// - Pattern specificity checks to avoid overly broad matches
// - Whitelist pattern support for excluding known false positives
func (v *Validator) validateNotFalsePositive(match string, platform string) bool {
	// 1. Check whitelist patterns first - if match is whitelisted, exclude it
	if v.isWhitelistedMatch(match) {
		return false
	}

	// 2. Negative keyword filtering to exclude test data and examples
	if v.containsNegativeKeywords(match) {
		return false
	}

	// 3. Detect and exclude placeholder URLs
	if v.isPlaceholderURL(match) {
		return false
	}

	// 4. Context-based false positive detection (code comments, documentation)
	if v.isCodeOrDocumentationContext(match) {
		return false
	}

	// 5. Pattern specificity checks to avoid overly broad matches
	if v.isOverlyBroadMatch(match, platform) {
		return false
	}

	return true
}

// isWhitelistedMatch checks if the match should be excluded based on whitelist patterns
func (v *Validator) isWhitelistedMatch(match string) bool {
	for _, pattern := range v.compiledWhitelistPatterns {
		if pattern.MatchString(match) {
			return true
		}
	}
	return false
}

// containsNegativeKeywords checks for negative keywords that indicate test data or examples
func (v *Validator) containsNegativeKeywords(match string) bool {
	matchLower := strings.ToLower(match)

	// Enhanced test/example patterns - using more precise matching
	// Check for exact matches or word boundaries for generic terms
	genericNegativeWords := []string{
		"test", "testing", "example", "demo", "sample", "mock", "fake", "dummy",
		"placeholder", "template", "boilerplate", "skeleton", "stub",
		"dev", "development", "staging", "localhost", "sandbox", "beta", "alpha", "preview", "canary",
		"docs", "documentation", "readme", "guide", "tutorial", "howto",
		"manual", "reference", "spec", "specification", "code", "source",
	}

	// Check for generic negative words with word boundaries
	for _, word := range genericNegativeWords {
		// Use word boundary matching to avoid false positives
		// Match if the word appears as a standalone word or at word boundaries
		if matchLower == word ||
			strings.HasPrefix(matchLower, word+"_") || strings.HasPrefix(matchLower, word+"-") ||
			strings.HasSuffix(matchLower, "_"+word) || strings.HasSuffix(matchLower, "-"+word) ||
			strings.Contains(matchLower, "_"+word+"_") || strings.Contains(matchLower, "-"+word+"-") ||
			strings.Contains(matchLower, "/"+word+"/") || strings.Contains(matchLower, "/"+word) ||
			strings.HasSuffix(matchLower, "/"+word) {
			return true
		}
	}

	// Check for specific problematic patterns that should always be excluded
	alwaysNegativePatterns := []string{
		// IP addresses and localhost
		"127.0.0.1", "0.0.0.0", "localhost.com", "127-0-0-1.com",
		// Generic domains
		"example.com", "example.org", "example.net", "test.com", "demo.com",
		"sample.com", "placeholder.com", "dummy.com", "fake.com",
		// Specific example patterns
		"github.com/example", "gitlab.com/example", "bitbucket.org/example", "git.example.com",
		// Generic usernames that are clearly placeholders
		"username", "your-username", "your_username", "yourusername",
	}

	for _, pattern := range alwaysNegativePatterns {
		if strings.Contains(matchLower, pattern) {
			return true
		}
	}

	// Check for exact placeholder usernames (to avoid false positives like "realuser123")
	exactPlaceholderUsernames := []string{
		"user123", "testuser", "sampleuser", "demouser", "exampleuser",
		"user", "test", "example", "demo", "sample",
	}

	// Extract potential username from the match for exact comparison
	username := v.extractUsername(matchLower, "generic")
	if username != "" {
		for _, placeholder := range exactPlaceholderUsernames {
			if username == placeholder {
				return true
			}
		}
	}

	// Check configured negative keywords
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(matchLower, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// isPlaceholderURL detects and excludes placeholder URLs
func (v *Validator) isPlaceholderURL(match string) bool {
	matchLower := strings.ToLower(match)

	// Placeholder URL patterns
	placeholderPatterns := []string{
		// Generic placeholder formats
		"https://example.com/", "http://example.com/",
		"https://www.example.com/", "http://www.example.com/",
		"https://your-domain.com/", "http://your-domain.com/",
		"https://yourdomain.com/", "http://yourdomain.com/",
		// Platform-specific placeholder patterns
		"https://facebook.com/your-profile", "https://twitter.com/your-handle",
		"https://instagram.com/your-username", "https://linkedin.com/in/your-name",
		"https://github.com/your-username", "https://youtube.com/your-channel",
		// Bracketed placeholders
		"[username]", "[your-username]", "[profile-name]", "[handle]",
		"{username}", "{your-username}", "{profile-name}", "{handle}",
		"<username>", "<your-username>", "<profile-name>", "<handle>",
		// Variable-style placeholders
		"$username", "$user", "${username}", "${user}",
		"{{username}}", "{{user}}", "{{profile}}",
		// Documentation-style placeholders
		"username_here", "your_username_here", "insert_username",
		"replace_with_username", "add_your_username",
	}

	for _, pattern := range placeholderPatterns {
		if strings.Contains(matchLower, pattern) {
			return true
		}
	}

	// Check for generic placeholder patterns with regex-like detection
	placeholderRegexPatterns := []string{
		`\[.*\]`, `\{.*\}`, `<.*>`, `\$\{.*\}`, `\{\{.*\}\}`,
	}
	for _, pattern := range placeholderRegexPatterns {
		if matched, _ := regexp.MatchString(pattern, match); matched {
			return true
		}
	}

	return false
}

// isCodeOrDocumentationContext detects matches in code comments or documentation
func (v *Validator) isCodeOrDocumentationContext(match string) bool {
	matchLower := strings.ToLower(match)

	// Code comment indicators - be more specific to avoid false positives
	commentPatterns := []string{
		// Single-line comments (must be at start or after space)
		"// ", "# ", "-- ", "rem ", "; ", "% ",
		// Multi-line comments
		"/*", "*/", "<!--", "-->", "\"\"\"", "'''",
		// Documentation formats
		"@param", "@return", "@example", "@see", "@link",
		"@author", "@since", "@version", "@deprecated",
		// Markdown/documentation
		"```", "~~~", "**", "__", "##", "###",
		"[link]", "](http",
	}

	for _, pattern := range commentPatterns {
		if strings.Contains(matchLower, pattern) {
			return true
		}
	}

	// Check for code file extensions, but be more specific
	// Only flag if the extension appears at the end or followed by non-alphanumeric
	codeExtensions := []string{
		".js", ".ts", ".py", ".go", ".java", ".cpp", ".c", ".h",
		".php", ".rb", ".rs", ".swift", ".kt", ".scala",
		".yml", ".yaml", ".json", ".xml", ".ini", ".cfg", ".conf",
		".toml", ".properties", ".env",
	}

	for _, ext := range codeExtensions {
		// Only match if the extension is at the end or followed by non-alphanumeric
		if strings.HasSuffix(matchLower, ext) ||
			strings.Contains(matchLower, ext+" ") ||
			strings.Contains(matchLower, ext+":") ||
			strings.Contains(matchLower, ext+"\t") ||
			strings.Contains(matchLower, ext+"\n") {
			return true
		}
	}

	// Special handling for single backticks - only flag if they appear to be code formatting
	if strings.Contains(match, "`") && (strings.Count(match, "`") >= 2 ||
		strings.Contains(matchLower, "`http") || strings.Contains(matchLower, "http`")) {
		return true
	}

	// Check for documentation-specific patterns
	docIndicators := []string{
		"readme", "changelog", "license", "contributing", "code_of_conduct",
		"documentation", "docs/", "doc/", "manual", "guide", "tutorial",
		"api-reference", "reference", "specification", "spec",
	}
	for _, indicator := range docIndicators {
		if strings.Contains(matchLower, indicator) {
			return true
		}
	}

	return false
}

// isOverlyBroadMatch implements pattern specificity checks to avoid overly broad matches
func (v *Validator) isOverlyBroadMatch(match string, platform string) bool {
	matchLower := strings.ToLower(match)

	// Check for overly generic patterns that are too broad
	genericPatterns := []string{
		// Too short to be meaningful
		"a", "an", "the", "is", "at", "in", "on", "to", "of", "for",
		"and", "or", "but", "not", "with", "by", "from", "as",
		// Single characters or very short strings
		"x", "y", "z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
		// Common words that might appear in URLs but aren't social media handles
		"www", "http", "https", "com", "org", "net", "edu", "gov",
		"index", "home", "main", "page", "site", "web", "blog",
		// Generic social media terms without specificity
		"profile", "user", "account", "page", "channel", "handle",
		"social", "media", "network", "connect", "follow", "share",
	}

	for _, pattern := range genericPatterns {
		if matchLower == pattern {
			return true
		}
	}

	// Check for matches that are too short to be meaningful social media handles
	if len(strings.TrimSpace(match)) < 3 {
		return true
	}

	// Platform-specific overly broad pattern checks
	switch strings.ToLower(platform) {
	case "twitter", "x":
		// Twitter handles should not be just numbers or single characters
		if matched, _ := regexp.MatchString(`^[0-9]+$`, match); matched {
			return true
		}
		if matched, _ := regexp.MatchString(`^[a-zA-Z]$`, match); matched {
			return true
		}
	case "instagram":
		// Instagram usernames should not be just underscores or dots
		if matched, _ := regexp.MatchString(`^[_.]+$`, match); matched {
			return true
		}
	case "linkedin":
		// LinkedIn profiles should not be just numbers
		if matched, _ := regexp.MatchString(`^[0-9]+$`, match); matched {
			return true
		}
	case "github":
		// GitHub usernames should not be reserved words
		reservedGitHubNames := []string{
			"admin", "api", "blog", "help", "support", "security",
			"about", "contact", "legal", "privacy", "terms",
		}
		for _, reserved := range reservedGitHubNames {
			if matchLower == reserved {
				return true
			}
		}
	}

	// Check for matches that contain only special characters
	if matched, _ := regexp.MatchString(`^[^a-zA-Z0-9]+$`, match); matched {
		return true
	}

	// Check for matches that are likely file paths or technical identifiers
	// Note: We exclude "/" from this check since it's common in URLs
	technicalPatterns := []string{
		"\\", ";", "|", "&", "=", "?", "%", "+",
		"../", "./", "~/", "c:", "d:", "usr/", "var/", "tmp/",
	}
	for _, pattern := range technicalPatterns {
		if strings.Contains(matchLower, pattern) {
			return true
		}
	}

	// Special check for file paths (but not URLs)
	// Only flag as technical if it looks like a file path and not a URL
	if strings.Contains(matchLower, "/") && !strings.Contains(matchLower, "http") && !strings.Contains(matchLower, "://") {
		// Check if it looks like a file path
		if strings.Contains(matchLower, "../") || strings.Contains(matchLower, "./") ||
			strings.HasPrefix(matchLower, "/") || strings.Contains(matchLower, "usr/") ||
			strings.Contains(matchLower, "var/") || strings.Contains(matchLower, "tmp/") {
			return true
		}
	}

	return false
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

// logConfigurationError logs configuration loading errors with comprehensive context
func (v *Validator) logConfigurationError(errorType string, reason string) {
	// Log through observability system if available
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Configuration error: %s - %s", errorType, reason))
		v.observer.DebugObserver.LogDetail("socialmedia", "Social media detection is disabled due to configuration error")
	}

	// Also log to stderr in debug mode for comprehensive error tracking
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[ERROR] Social Media Validator: Configuration loading failed\n")
		fmt.Fprintf(os.Stderr, "[ERROR]   Error Type: %s\n", errorType)
		fmt.Fprintf(os.Stderr, "[ERROR]   Reason: %s\n", reason)
		fmt.Fprintf(os.Stderr, "[ERROR]   Action: Social media detection disabled\n")
		fmt.Fprintf(os.Stderr, "[ERROR]   Solution: Check configuration file format and structure\n")
	}

	// Set safe defaults
	v.patternsConfigured = false
	v.logNoSocialMediaPatterns(reason)
}

// logNoSocialMediaPatterns logs informational messages when no social media patterns are active
// Implements configuration status tracking and logging similar to intellectual property validator
func (v *Validator) logNoSocialMediaPatterns(reason string) {
	message := "Social media detection disabled: " + reason + ". Configure 'validators.social_media.platform_patterns' to enable social media detection."

	// Log to debug observer for detailed logging
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", message)
	}

	// Also log to stderr in debug mode for comprehensive audit trail
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[INFO] Social Media Validator: No patterns configured\n")
		fmt.Fprintf(os.Stderr, "[INFO]   Reason: %s\n", reason)
		fmt.Fprintf(os.Stderr, "[INFO]   Status: Social media detection disabled\n")
		fmt.Fprintf(os.Stderr, "[INFO]   Solution: Configure 'validators.social_media.platform_patterns' to enable detection\n")
	}

	// Continue with existing detailed guidance logging
	if v.observer != nil && v.observer.DebugObserver != nil {

		// Include configuration guidance in verbose mode warnings
		guidance := "Example configuration:\n" +
			"validators:\n" +
			"  social_media:\n" +
			"    platform_patterns:\n" +
			"      linkedin_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?linkedin\\\\.com/in/[a-zA-Z0-9_-]+\"\n" +
			"        - \"(?i)https?://(?:www\\\\.)?linkedin\\\\.com/company/[a-zA-Z0-9_-]+\"\n" +
			"      twitter_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?(twitter|x)\\\\.com/[a-zA-Z0-9_]+\"\n" +
			"        - \"(?i)@[a-zA-Z0-9_]{1,15}\\\\b\"\n" +
			"      github_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?github\\\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?\"\n" +
			"      facebook_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?(facebook|fb)\\\\.com/[a-zA-Z0-9._-]+\"\n" +
			"      instagram_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?instagram\\\\.com/[a-zA-Z0-9_.]+/\"\n" +
			"      youtube_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?youtube\\\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+\"\n" +
			"      tiktok_patterns:\n" +
			"        - \"(?i)https?://(?:www\\\\.)?tiktok\\\\.com/@[a-zA-Z0-9_.]+/\"\n" +
			"    positive_keywords:\n" +
			"      - \"profile\"\n" +
			"      - \"social media\"\n" +
			"      - \"follow me\"\n" +
			"    negative_keywords:\n" +
			"      - \"example\"\n" +
			"      - \"test\"\n" +
			"      - \"placeholder\""
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Configuration guidance for social media patterns:\n%s", guidance))

		// Also log configuration guidance to stderr in verbose/debug mode
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] Configuration guidance for social media patterns:\n")
			fmt.Fprintf(os.Stderr, "%s\n", guidance)
		}
	}

	// Handle different logging scenarios based on reason
	switch reason {
	case "all configured social media patterns are invalid":
		// Warning logging when all configured patterns are invalid
		fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
		// Also include configuration guidance in the warning for quiet mode
		fmt.Fprintf(os.Stderr, "Configure valid regex patterns in 'validators.social_media.platform_patterns' to enable social media detection.\n")

	case "empty platform_patterns map configured":
		// Informational logging when patterns map is empty
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] %s\n", message)
		}

	case "no social media patterns configured":
		// Informational logging when no social media patterns are configured
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] %s\n", message)
		}

	case "all social media patterns failed to compile during regex compilation":
		// Additional case for compilation failures - treat as warning
		fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
		fmt.Fprintf(os.Stderr, "Check regex syntax in 'validators.social_media.platform_patterns' configuration.\n")

	default:
		// Default case - log as informational in debug mode
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[INFO] %s\n", message)
		}
	}
}

// Pattern compilation cache for performance optimization
var (
	patternCache = make(map[string]*regexp.Regexp)
	cacheMutex   sync.RWMutex
)

// compilePlatformPatterns compiles the platform-specific patterns into regex objects
// with defensive validation, error handling, and performance optimizations
func (v *Validator) compilePlatformPatterns() {
	// Handle empty pattern maps gracefully
	if len(v.platformPatterns) == 0 {
		v.compiledPatterns = make(map[string][]*regexp.Regexp)
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", "No social media patterns to compile - empty pattern map")
		}
		return
	}

	// Initialize compiled patterns map with pre-allocated capacity
	v.compiledPatterns = make(map[string][]*regexp.Regexp, len(v.platformPatterns))
	totalCompiled := 0
	totalFailed := 0
	cacheHits := 0

	// Process each platform's patterns with optimized compilation
	for platform, patterns := range v.platformPatterns {
		if len(patterns) == 0 {
			// Skip platforms with no patterns
			continue
		}

		// Pre-allocate slice with exact capacity for better memory efficiency
		compiledPlatformPatterns := make([]*regexp.Regexp, 0, len(patterns))
		compiledCount := 0
		failedCount := 0

		// Batch process patterns for better performance
		for i, pattern := range patterns {
			// Skip empty patterns gracefully
			if pattern == "" {
				failedCount++
				totalFailed++
				if v.observer != nil && v.observer.DebugObserver != nil {
					v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Skipping empty %s pattern at index %d", platform, i+1))
				}
				continue
			}

			// Check pattern cache first for performance optimization
			cacheMutex.RLock()
			if cachedRegex, exists := patternCache[pattern]; exists {
				compiledPlatformPatterns = append(compiledPlatformPatterns, cachedRegex)
				compiledCount++
				totalCompiled++
				cacheHits++
				cacheMutex.RUnlock()
				continue
			}
			cacheMutex.RUnlock()

			// Compile pattern with optimizations
			regex, err := v.compileOptimizedPattern(pattern)
			if err != nil {
				// Skip patterns that fail to compile rather than crashing
				failedCount++
				totalFailed++

				// Log compilation errors for debugging with enhanced context
				if v.observer != nil && v.observer.DebugObserver != nil {
					v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Failed to compile %s pattern %d: '%s' - Error: %v", platform, i+1, pattern, err))
					// Provide additional context about the error type
					if strings.Contains(err.Error(), "invalid") {
						v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("%s pattern %d contains invalid regex syntax - check for unescaped special characters", platform, i+1))
					}
				}

				// Also log to stderr in debug mode for comprehensive error tracking
				if os.Getenv("FERRET_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "[ERROR] Social Media Validator: Failed to compile %s pattern\n", platform)
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

			// Successfully compiled pattern - cache it for future use
			cacheMutex.Lock()
			patternCache[pattern] = regex
			cacheMutex.Unlock()

			compiledPlatformPatterns = append(compiledPlatformPatterns, regex)
			compiledCount++
			totalCompiled++
		}

		// Store compiled patterns for this platform if any were successful
		if len(compiledPlatformPatterns) > 0 {
			v.compiledPatterns[platform] = compiledPlatformPatterns
		}

		// Log platform-specific compilation summary in debug mode
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Platform %s pattern compilation: %d successful, %d failed", platform, compiledCount, failedCount))
			if compiledCount > 0 {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Successfully compiled %d regex patterns for platform %s", compiledCount, platform))
			}
		}

		// Also log to stderr in debug mode for comprehensive audit trail
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[DEBUG] Social Media Validator: Platform %s compilation summary\n", platform)
			fmt.Fprintf(os.Stderr, "[DEBUG]   Total patterns: %d\n", len(patterns))
			fmt.Fprintf(os.Stderr, "[DEBUG]   Successfully compiled: %d\n", compiledCount)
			fmt.Fprintf(os.Stderr, "[DEBUG]   Failed to compile: %d\n", failedCount)
		}
	}

	// Log overall compilation summary in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Social media pattern compilation complete: %d total successful, %d total failed across %d platforms", totalCompiled, totalFailed, len(v.compiledPatterns)))
		if totalCompiled > 0 {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Successfully compiled patterns for platforms: %v", v.getPlatformNames(v.compiledPatterns)))
		}
	}

	// Also log to stderr in debug mode for comprehensive audit trail
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Social Media Validator: Overall compilation summary\n")
		fmt.Fprintf(os.Stderr, "[DEBUG]   Total platforms: %d\n", len(v.platformPatterns))
		fmt.Fprintf(os.Stderr, "[DEBUG]   Successfully compiled: %d patterns\n", totalCompiled)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Failed to compile: %d patterns\n", totalFailed)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Active platforms: %d\n", len(v.compiledPatterns))
		if len(v.compiledPatterns) > 0 {
			fmt.Fprintf(os.Stderr, "[DEBUG]   Platforms with compiled patterns: %v\n", v.getPlatformNames(v.compiledPatterns))
		}
	}

	// Log performance metrics for pattern compilation
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Pattern compilation performance: %d cache hits, %d new compilations", cacheHits, totalCompiled-cacheHits))
	}

	// If all patterns failed to compile, log a warning
	if totalCompiled == 0 && len(v.platformPatterns) > 0 {
		v.logNoSocialMediaPatterns("all social media patterns failed to compile during regex compilation")
	}
}

// compileOptimizedPattern compiles a regex pattern with performance optimizations
func (v *Validator) compileOptimizedPattern(pattern string) (*regexp.Regexp, error) {
	// Pre-validate pattern for common issues to fail fast
	if strings.Contains(pattern, "(?P<") {
		// Named capture groups can be slower - warn but allow
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Pattern contains named capture group which may impact performance: %s", pattern))
		}
	}

	// Check for potentially expensive patterns
	if strings.Contains(pattern, ".*.*") || strings.Contains(pattern, ".+.+") {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Pattern contains potentially expensive nested quantifiers: %s", pattern))
		}
	}

	// Compile with standard Go regex engine
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Optimize by pre-compiling common prefixes if possible
	// This is a placeholder for future optimizations
	return regex, nil
}

// monitorMemoryUsage monitors memory usage during processing
func (v *Validator) monitorMemoryUsage(operation string, metadata map[string]any) {
	// This is a placeholder for memory monitoring
	// In a production environment, this could integrate with runtime.MemStats
	// or other memory profiling tools

	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Memory monitoring: %s", operation))

		// Log metadata if provided
		for key, value := range metadata {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  %s: %v", key, value))
		}
	}
}

// compileWhitelistPatterns compiles the whitelist patterns into regex objects
// for false positive prevention
func (v *Validator) compileWhitelistPatterns() {
	// Handle empty whitelist patterns gracefully
	if len(v.whitelistPatterns) == 0 {
		v.compiledWhitelistPatterns = []*regexp.Regexp{}
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", "No whitelist patterns to compile - empty pattern list")
		}
		return
	}

	// Pre-allocate slice with exact capacity for better memory efficiency
	v.compiledWhitelistPatterns = make([]*regexp.Regexp, 0, len(v.whitelistPatterns))
	compiledCount := 0
	failedCount := 0

	for i, pattern := range v.whitelistPatterns {
		// Skip empty patterns gracefully
		if pattern == "" {
			failedCount++
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Skipping empty whitelist pattern at index %d", i+1))
			}
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[WARNING] Social Media Validator: Empty whitelist pattern at index %d - skipping\n", i+1)
			}
			continue
		}

		// Add case-insensitive flag if not already present
		processedPattern := v.ensureCaseInsensitive(pattern)

		// Add error handling for pattern compilation failures
		regex, err := regexp.Compile(processedPattern)
		if err != nil {
			// Skip patterns that fail to compile rather than crashing
			failedCount++

			// Log compilation errors for debugging
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Failed to compile whitelist pattern %d: '%s' - Error: %v", i+1, pattern, err))
			}

			// Also log to stderr in debug mode
			if os.Getenv("FERRET_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[ERROR] Social Media Validator: Failed to compile whitelist pattern\n")
				fmt.Fprintf(os.Stderr, "[ERROR]   Pattern %d: %s\n", i+1, pattern)
				fmt.Fprintf(os.Stderr, "[ERROR]   Error: %v\n", err)
				fmt.Fprintf(os.Stderr, "[ERROR]   Action: Skipping pattern and continuing with remaining patterns\n")
			}
			continue
		}

		// Successfully compiled pattern
		v.compiledWhitelistPatterns = append(v.compiledWhitelistPatterns, regex)
		compiledCount++
	}

	// Log compilation summary
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Whitelist pattern compilation: %d successful, %d failed", compiledCount, failedCount))
		if compiledCount > 0 {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Successfully compiled %d whitelist regex patterns", compiledCount))
		}
	}

	// Also log to stderr in debug mode
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Social Media Validator: Whitelist compilation summary\n")
		fmt.Fprintf(os.Stderr, "[DEBUG]   Total patterns: %d\n", len(v.whitelistPatterns))
		fmt.Fprintf(os.Stderr, "[DEBUG]   Successfully compiled: %d\n", compiledCount)
		fmt.Fprintf(os.Stderr, "[DEBUG]   Failed to compile: %d\n", failedCount)
	}
}

// detectPatternsByLine detects social media patterns and groups matches by line number
// with platform categorization, metadata tagging, and batch processing optimizations
func (v *Validator) detectPatternsByLine(content string, originalPath string) map[int][]detector.Match {
	lineMatches := make(map[int][]detector.Match)

	// If no patterns are configured, return empty results
	if len(v.compiledPatterns) == 0 {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", "No compiled patterns available for social media detection")
		}
		return lineMatches
	}

	// Optimize for large files by using batch processing
	contentLength := len(content)
	useBatchProcessing := contentLength > 1024*1024 // 1MB threshold

	if useBatchProcessing {
		return v.detectPatternsByLineBatch(content, originalPath)
	}

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Pre-allocate context extractor for reuse
	contextExtractor := detector.NewContextExtractor()

	// Process each line for social media patterns with optimizations
	for lineNum, line := range lines {
		// Skip empty lines early
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Batch process all patterns for this line to reduce overhead
		lineMatches[lineNum] = v.processLineForAllPatterns(line, lineNum, originalPath, contextExtractor)
	}

	return lineMatches
}

// detectPatternsByLineBatch processes large files using batch processing for better performance
func (v *Validator) detectPatternsByLineBatch(content string, originalPath string) map[int][]detector.Match {
	lineMatches := make(map[int][]detector.Match)

	// Split content into lines
	lines := strings.Split(content, "\n")

	// Process in batches to reduce memory pressure
	batchSize := 1000 // Process 1000 lines at a time
	contextExtractor := detector.NewContextExtractor()

	for i := 0; i < len(lines); i += batchSize {
		end := min(i+batchSize, len(lines))

		// Process batch
		for lineNum := i; lineNum < end; lineNum++ {
			line := lines[lineNum]

			// Skip empty lines early
			if len(strings.TrimSpace(line)) == 0 {
				continue
			}

			// Process line with all patterns
			matches := v.processLineForAllPatterns(line, lineNum, originalPath, contextExtractor)
			if len(matches) > 0 {
				lineMatches[lineNum] = matches
			}
		}

		// Log progress for very large files
		if v.observer != nil && v.observer.DebugObserver != nil && len(lines) > 10000 {
			progress := float64(end) / float64(len(lines)) * 100
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Batch processing progress: %.1f%% (%d/%d lines)", progress, end, len(lines)))
		}
	}

	return lineMatches
}

// processLineForAllPatterns efficiently processes a single line against all patterns
func (v *Validator) processLineForAllPatterns(line string, lineNum int, originalPath string, contextExtractor *detector.ContextExtractor) []detector.Match {
	var matches []detector.Match

	// Check each platform's patterns
	for platform, patterns := range v.compiledPatterns {
		for patternIndex, regex := range patterns {
			// Find all matches for this pattern on this line
			foundMatches := regex.FindAllString(line, -1)

			for _, match := range foundMatches {
				// Skip empty matches
				if len(strings.TrimSpace(match)) == 0 {
					continue
				}

				// Process match with optimized confidence calculation
				processedMatch := v.processMatchOptimized(match, platform, patternIndex, line, lineNum, originalPath, contextExtractor)
				if processedMatch != nil {
					matches = append(matches, *processedMatch)
				}
			}
		}
	}

	return matches
}

// processMatchOptimized processes a single match with performance optimizations
func (v *Validator) processMatchOptimized(match, platform string, patternIndex int, line string, lineNum int, originalPath string, contextExtractor *detector.ContextExtractor) *detector.Match {
	// Filter out false positives from email addresses
	if v.isPartOfEmailAddress(match, line) {
		return nil
	}

	// Filter out other common false positive patterns
	if v.isFalsePositiveHandle(match, line) {
		return nil
	}

	// Calculate confidence for this match
	confidence, checks := v.CalculateConfidence(match)

	// Extract context around the match for enhanced analysis
	contextInfo, err := contextExtractor.ExtractContext(originalPath, lineNum, match)
	if err != nil {
		// Fallback to basic context info if extraction fails
		contextInfo = detector.ContextInfo{
			FullLine: line,
		}

		// Log context extraction failure for debugging (only in debug mode to reduce overhead)
		if os.Getenv("FERRET_DEBUG") == "1" && v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Context extraction failed for match '%s' at line %d: %v", match, lineNum+1, err))
		}
	}

	// Extract context around the match in the line with optimized string operations
	matchIndex := strings.Index(line, match)
	if matchIndex >= 0 {
		start := max(0, matchIndex-50)
		end := min(len(line), matchIndex+len(match)+50)

		contextInfo.BeforeText = line[start:matchIndex]
		contextInfo.AfterText = line[matchIndex+len(match) : end]
	}

	// Analyze context and adjust confidence with platform-specific analysis
	contextImpact := v.analyzeContextWithPlatform(match, platform, contextInfo)
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
		return nil
	}

	// Extract username/handle from the match if possible
	username := v.extractUsername(match, platform)

	// Determine pattern type based on the match content
	patternType := v.determinePatternType(match, platform)

	// Create the match with enhanced platform-specific metadata
	confidenceFactors := v.getConfidenceFactors(match, platform, checks, contextImpact)

	// Convert platform name to display format
	displayType := v.getPlatformDisplayName(platform)

	socialMediaMatch := detector.Match{
		Text:       match,
		LineNumber: lineNum + 1, // 1-based line numbering
		Type:       displayType,
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "SOCIAL_MEDIA",
		Context:    contextInfo,
		Metadata: map[string]any{
			"platform":           platform,
			"pattern_type":       patternType,
			"username":           username,
			"validation_checks":  checks,
			"context_impact":     contextImpact,
			"source":             "preprocessed_content",
			"original_file":      originalPath,
			"pattern_index":      patternIndex,
			"confidence_factors": confidenceFactors,
			"validation_details": v.getValidationDetails(match, platform, checks),
		},
	}

	// Perform enhanced context window analysis (only if needed for performance)
	if confidence > 50 { // Only do expensive analysis for higher confidence matches
		contextAnalysis := v.analyzeContextWindow(contextInfo, platform)

		// Add detailed context analysis to metadata
		socialMediaMatch.Metadata["context_analysis"] = contextAnalysis

		// Add individual keyword arrays for backward compatibility and easy access
		if positiveKeywords, ok := contextAnalysis["positive_keywords"].([]string); ok && len(positiveKeywords) > 0 {
			socialMediaMatch.Metadata["positive_keywords"] = positiveKeywords
		}
		if negativeKeywords, ok := contextAnalysis["negative_keywords"].([]string); ok && len(negativeKeywords) > 0 {
			socialMediaMatch.Metadata["negative_keywords"] = negativeKeywords
		}
		if platformKeywords, ok := contextAnalysis["platform_keywords"].([]string); ok && len(platformKeywords) > 0 {
			socialMediaMatch.Metadata["platform_keywords"] = platformKeywords
		}
	}

	// Log match details in debug mode (only for high-confidence matches to reduce overhead)
	if os.Getenv("FERRET_DEBUG") == "1" && confidence > 70 && v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Found %s match: '%s' (confidence: %.1f%%, type: %s, username: %s)", platform, match, confidence, patternType, username))
	}

	return &socialMediaMatch
}

// analyzeContextWithPlatform analyzes the context around a match with platform-specific analysis
// and returns a confidence adjustment following the intellectual property validator's pattern
func (v *Validator) analyzeContextWithPlatform(match string, platform string, context detector.ContextInfo) float64 {
	// Combine all context text for analysis following IP validator pattern
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var confidenceImpact float64 = 0

	// Track found keywords for detailed analysis
	var foundPositiveKeywords []string
	var foundNegativeKeywords []string
	var foundPlatformKeywords []string

	// Check for general positive keywords (increase confidence)
	// Following IP validator's pattern with similar confidence adjustments
	for _, keyword := range v.positiveKeywords {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(fullContext, keywordLower) {
			foundPositiveKeywords = append(foundPositiveKeywords, keyword)

			// Give more weight to keywords that are closer to the match
			// Following IP validator's weighting: 7% same line, 3% surrounding
			if strings.Contains(strings.ToLower(context.FullLine), keywordLower) {
				confidenceImpact += 7 // +7% for keywords in the same line
			} else {
				confidenceImpact += 3 // +3% for keywords in surrounding context
			}
		}
	}

	// Check for platform-specific keywords (higher weight than general keywords)
	// This provides enhanced context analysis specific to each social media platform
	if platformKeywords, exists := v.platformKeywords[platform]; exists {
		for _, keyword := range platformKeywords {
			keywordLower := strings.ToLower(keyword)
			if strings.Contains(fullContext, keywordLower) {
				foundPlatformKeywords = append(foundPlatformKeywords, keyword)

				// Platform-specific keywords get higher weight than general keywords
				// This helps distinguish between different social media contexts
				if strings.Contains(strings.ToLower(context.FullLine), keywordLower) {
					confidenceImpact += 10 // +10% for platform keywords in the same line
				} else {
					confidenceImpact += 5 // +5% for platform keywords in surrounding context
				}
			}
		}
	}

	// Check for general negative keywords (decrease confidence)
	// Following IP validator's pattern with strong negative impact
	for _, keyword := range v.negativeKeywords {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(fullContext, keywordLower) {
			foundNegativeKeywords = append(foundNegativeKeywords, keyword)

			// Give more weight to keywords that are closer to the match
			// Following IP validator's pattern: -15% same line, -7% surrounding
			if strings.Contains(strings.ToLower(context.FullLine), keywordLower) {
				confidenceImpact -= 15 // -15% for negative keywords in the same line
			} else {
				confidenceImpact -= 7 // -7% for negative keywords in surrounding context
			}
		}
	}

	// Additional context analysis for social media specific patterns
	// Check for URL context indicators
	if strings.Contains(fullContext, "http://") || strings.Contains(fullContext, "https://") {
		confidenceImpact += 2 // Small boost for URL context
	}

	// Check for @ symbol context (handle indicators)
	if strings.Contains(fullContext, "@") && platform == "twitter" {
		confidenceImpact += 3 // Boost for Twitter handle context
	}

	// Check for common false positive indicators
	falsePositiveIndicators := []string{
		"example.com", "test.com", "placeholder", "lorem ipsum",
		"sample data", "dummy", "fake", "not real", "for demonstration",
	}
	for _, indicator := range falsePositiveIndicators {
		if strings.Contains(fullContext, indicator) {
			confidenceImpact -= 20 // Strong penalty for false positive indicators
			break                  // Only apply penalty once
		}
	}

	// Cap the impact to reasonable bounds following IP validator pattern
	// IP validator uses +25% max boost, -50% max reduction
	if confidenceImpact > 25 {
		confidenceImpact = 25 // Maximum +25% boost
	} else if confidenceImpact < -50 {
		confidenceImpact = -50 // Maximum -50% reduction
	}

	// Log detailed context analysis in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Context analysis for %s match '%s': impact=%.1f", platform, match, confidenceImpact))
		if len(foundPositiveKeywords) > 0 {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Positive keywords found: %v", foundPositiveKeywords))
		}
		if len(foundPlatformKeywords) > 0 {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Platform keywords found: %v", foundPlatformKeywords))
		}
		if len(foundNegativeKeywords) > 0 {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Negative keywords found: %v", foundNegativeKeywords))
		}
	}

	return confidenceImpact
}

// AnalyzeContext implements the detector.Validator interface
// This is a wrapper that calls the platform-specific analysis
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Identify the platform for this match
	platform := v.identifyPlatform(match)
	if platform == "" {
		platform = "unknown"
	}

	// Use the platform-specific analysis
	return v.analyzeContextWithPlatform(match, platform, context)
}

// detectKeywordsInContext performs detailed keyword detection in the context window
// Returns lists of found keywords for enhanced metadata and analysis
func (v *Validator) detectKeywordsInContext(context detector.ContextInfo, platform string) ([]string, []string, []string) {
	// Combine all context text for comprehensive keyword analysis
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var foundPositiveKeywords []string
	var foundNegativeKeywords []string
	var foundPlatformKeywords []string

	// Detect general positive keywords
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			foundPositiveKeywords = append(foundPositiveKeywords, keyword)
		}
	}

	// Detect general negative keywords
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			foundNegativeKeywords = append(foundNegativeKeywords, keyword)
		}
	}

	// Detect platform-specific keywords
	if platformKeywords, exists := v.platformKeywords[platform]; exists {
		for _, keyword := range platformKeywords {
			if strings.Contains(fullContext, strings.ToLower(keyword)) {
				foundPlatformKeywords = append(foundPlatformKeywords, keyword)
			}
		}
	}

	return foundPositiveKeywords, foundNegativeKeywords, foundPlatformKeywords
}

// analyzeContextWindow performs detailed analysis of the context window
// Returns structured information about the context for enhanced confidence scoring
func (v *Validator) analyzeContextWindow(context detector.ContextInfo, platform string) map[string]any {
	analysis := make(map[string]any)

	// Get keyword detection results
	positiveKeywords, negativeKeywords, platformKeywords := v.detectKeywordsInContext(context, platform)

	// Store keyword analysis results
	analysis["positive_keywords"] = positiveKeywords
	analysis["negative_keywords"] = negativeKeywords
	analysis["platform_keywords"] = platformKeywords

	// Analyze context window characteristics
	beforeTextLength := len(context.BeforeText)
	afterTextLength := len(context.AfterText)
	fullLineLength := len(context.FullLine)

	analysis["context_window_size"] = beforeTextLength + afterTextLength + fullLineLength
	analysis["before_text_length"] = beforeTextLength
	analysis["after_text_length"] = afterTextLength
	analysis["full_line_length"] = fullLineLength

	// Check for URL indicators in context
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)
	analysis["has_url_indicators"] = strings.Contains(fullContext, "http://") || strings.Contains(fullContext, "https://")
	analysis["has_at_symbol"] = strings.Contains(fullContext, "@")

	// Check for common false positive patterns
	falsePositiveIndicators := []string{
		"example.com", "test.com", "placeholder", "lorem ipsum",
		"sample data", "dummy", "fake", "not real", "for demonstration",
	}

	var foundFalsePositiveIndicators []string
	for _, indicator := range falsePositiveIndicators {
		if strings.Contains(fullContext, indicator) {
			foundFalsePositiveIndicators = append(foundFalsePositiveIndicators, indicator)
		}
	}
	analysis["false_positive_indicators"] = foundFalsePositiveIndicators
	analysis["has_false_positive_indicators"] = len(foundFalsePositiveIndicators) > 0

	return analysis
}

// extractUsername extracts the username/handle from a social media match
func (v *Validator) extractUsername(match string, platform string) string {
	// Handle different platform URL formats
	switch platform {
	case "linkedin", "linkedin_patterns":
		// Extract from LinkedIn URLs: linkedin.com/in/username, linkedin.com/company/name
		if strings.Contains(match, "/in/") {
			parts := strings.Split(match, "/in/")
			if len(parts) > 1 {
				username := strings.Split(parts[1], "/")[0]
				return strings.TrimSpace(username)
			}
		}
		if strings.Contains(match, "/company/") {
			parts := strings.Split(match, "/company/")
			if len(parts) > 1 {
				username := strings.Split(parts[1], "/")[0]
				return strings.TrimSpace(username)
			}
		}
		if strings.Contains(match, "/pub/") {
			parts := strings.Split(match, "/pub/")
			if len(parts) > 1 {
				username := strings.Split(parts[1], "/")[0]
				return strings.TrimSpace(username)
			}
		}

	case "twitter", "twitter_patterns":
		// Extract from Twitter URLs: twitter.com/username, x.com/username
		if strings.Contains(match, "twitter.com/") || strings.Contains(match, "x.com/") {
			parts := strings.Split(match, "/")
			if len(parts) > 0 {
				username := parts[len(parts)-1]
				return strings.TrimSpace(username)
			}
		}
		// Extract from @handles
		if strings.HasPrefix(match, "@") {
			return strings.TrimSpace(match[1:])
		}

	case "github", "github_patterns":
		// Extract from GitHub URLs: github.com/username or github.com/username/repo
		if strings.Contains(match, "github.com/") {
			parts := strings.Split(match, "github.com/")
			if len(parts) > 1 {
				pathParts := strings.Split(parts[1], "/")
				if len(pathParts) > 0 {
					username := pathParts[0]
					return strings.TrimSpace(username)
				}
			}
		}
		// Extract from GitHub Pages: username.github.io
		if strings.Contains(match, ".github.io") {
			parts := strings.Split(match, ".")
			if len(parts) > 0 {
				username := strings.Split(parts[0], "//")[len(strings.Split(parts[0], "//"))-1]
				return strings.TrimSpace(username)
			}
		}

	case "facebook", "facebook_patterns":
		// Extract from Facebook URLs: facebook.com/username, fb.com/username
		if strings.Contains(match, "facebook.com/") || strings.Contains(match, "fb.com/") {
			parts := strings.Split(match, "/")
			if len(parts) > 0 {
				username := parts[len(parts)-1]
				// Skip profile.php URLs
				if username != "profile.php" {
					return strings.TrimSpace(username)
				}
			}
		}

	case "instagram", "instagram_patterns":
		// Extract from Instagram URLs: instagram.com/username/
		if strings.Contains(match, "instagram.com/") || strings.Contains(match, "instagr.am/") {
			parts := strings.Split(match, "/")
			for i, part := range parts {
				if (part == "instagram.com" || part == "instagr.am") && i+1 < len(parts) {
					username := parts[i+1]
					return strings.TrimSpace(username)
				}
			}
		}

	case "youtube", "youtube_patterns":
		// Extract from YouTube URLs: youtube.com/user/name, youtube.com/c/name, youtube.com/@name
		if strings.Contains(match, "youtube.com/") {
			if strings.Contains(match, "/user/") || strings.Contains(match, "/c/") || strings.Contains(match, "/channel/") {
				parts := strings.Split(match, "/")
				if len(parts) > 0 {
					username := parts[len(parts)-1]
					return strings.TrimSpace(username)
				}
			}
			if strings.Contains(match, "/@") {
				parts := strings.Split(match, "/@")
				if len(parts) > 1 {
					username := strings.Split(parts[1], "/")[0]
					return strings.TrimSpace(username)
				}
			}
		}

	case "tiktok", "tiktok_patterns":
		// Extract from TikTok URLs: tiktok.com/@username/
		if strings.Contains(match, "tiktok.com/@") {
			parts := strings.Split(match, "/@")
			if len(parts) > 1 {
				username := strings.Split(parts[1], "/")[0]
				return strings.TrimSpace(username)
			}
		}

	default:
		// Generic extraction for other platforms
		parts := strings.Split(match, "/")
		if len(parts) > 0 {
			username := parts[len(parts)-1]
			return strings.TrimSpace(username)
		}
	}

	return ""
}

// determinePatternType determines the type of social media pattern (URL, handle, etc.)
func (v *Validator) determinePatternType(match string, platform string) string {
	matchLower := strings.ToLower(match)

	// Check for handle patterns first
	if strings.HasPrefix(match, "@") {
		return "handle"
	}

	// Check for domain patterns
	if strings.Contains(matchLower, ".github.io") {
		return "github_pages"
	}

	// Check for URL patterns
	if strings.HasPrefix(matchLower, "http://") || strings.HasPrefix(matchLower, "https://") {
		// Determine specific URL type based on content
		if strings.Contains(matchLower, "/profile") || strings.Contains(matchLower, "/in/") {
			return "profile_url"
		}
		if strings.Contains(matchLower, "/company") || strings.Contains(matchLower, "/c/") {
			return "company_url"
		}
		if strings.Contains(matchLower, "/channel/") || strings.Contains(matchLower, "/user/") {
			return "channel_url"
		}
		// GitHub specific check
		if strings.Contains(matchLower, "github.com") {
			return "profile_url"
		}
		return "profile_url" // Default for URLs
	}

	// Default pattern type
	return "reference"
}

// getConfidenceFactors returns a detailed breakdown of confidence factors for debugging and metadata
func (v *Validator) getConfidenceFactors(match string, platform string, checks map[string]bool, contextImpact float64) map[string]float64 {
	factors := make(map[string]float64)

	// Platform-specific bonus
	platformBonus := v.getPlatformConfidenceBonus(platform)
	factors["platform_bonus"] = platformBonus

	// Individual validation check contributions
	if checks["platform_identified"] {
		factors["platform_identification"] = 5.0
	} else {
		factors["platform_identification"] = -90.0 // Major penalty for unknown platform
	}

	if checks["valid_url_format"] {
		factors["url_format_validation"] = 30.0
	} else if strings.Contains(match, "://") {
		factors["url_format_validation"] = -10.0 // Penalty for invalid URL format
	} else {
		factors["url_format_validation"] = 15.0 // Non-URL patterns get base score
	}

	if checks["valid_username_format"] {
		factors["username_format_validation"] = 25.0
	} else if v.extractUsername(match, platform) != "" {
		factors["username_format_validation"] = -15.0 // Penalty for invalid username
	} else {
		factors["username_format_validation"] = -5.0 // Small penalty for no username
	}

	if checks["platform_specific_validation"] {
		factors["platform_specific_checks"] = 20.0
	} else {
		factors["platform_specific_checks"] = -10.0 // Penalty for failing platform checks
	}

	if checks["pattern_specificity"] {
		factors["pattern_specificity"] = 15.0
	} else {
		factors["pattern_specificity"] = -20.0 // Strong penalty for non-specific patterns
	}

	if checks["reasonable_length"] {
		factors["length_validation"] = 10.0
	} else {
		factors["length_validation"] = -15.0 // Penalty for unreasonable length
	}

	if checks["domain_validation"] {
		factors["domain_validation"] = 12.0
	} else if strings.Contains(match, "://") {
		factors["domain_validation"] = -8.0 // Penalty for invalid domain in URLs
	} else {
		factors["domain_validation"] = 0.0 // No domain to validate
	}

	if checks["valid_character_set"] {
		factors["character_set_validation"] = 8.0
	} else {
		factors["character_set_validation"] = -12.0 // Penalty for invalid characters
	}

	if checks["valid_path_structure"] {
		factors["path_structure_validation"] = 10.0
	} else if strings.Contains(match, "://") {
		factors["path_structure_validation"] = -8.0 // Penalty for invalid path in URLs
	} else {
		factors["path_structure_validation"] = 0.0 // No path to validate
	}

	if checks["not_false_positive"] {
		factors["false_positive_prevention"] = 0.0 // No bonus, just avoiding penalty
	} else {
		factors["false_positive_prevention"] = -30.0 // Strong penalty for likely false positives
	}

	// Context analysis impact
	factors["context_impact"] = contextImpact

	// Calculate total confidence for verification
	totalConfidence := 0.0
	for _, value := range factors {
		totalConfidence += value
	}
	factors["calculated_total"] = totalConfidence

	return factors
}

// getValidationDetails returns detailed information about each validation check
func (v *Validator) getValidationDetails(match string, platform string, checks map[string]bool) map[string]any {
	details := make(map[string]any)

	// Platform identification details
	details["platform_identification"] = map[string]any{
		"identified_platform":   platform,
		"platform_confidence":   v.getPlatformConfidenceBonus(platform),
		"identification_method": v.getIdentificationMethod(match, platform),
	}

	// URL format validation details
	if strings.Contains(match, "://") {
		details["url_format"] = map[string]any{
			"is_url":       true,
			"valid_format": checks["valid_url_format"],
			"protocol":     v.extractProtocol(match),
			"domain":       v.extractDomain(match),
			"path":         v.extractPath(match),
		}
	} else {
		details["url_format"] = map[string]any{
			"is_url":       false,
			"pattern_type": v.determinePatternType(match, platform),
		}
	}

	// Username extraction and validation details
	username := v.extractUsername(match, platform)
	details["username_validation"] = map[string]any{
		"extracted_username":    username,
		"username_length":       len(username),
		"valid_format":          checks["valid_username_format"],
		"platform_requirements": v.getUsernameRequirements(platform),
	}

	// Platform-specific validation details
	details["platform_specific"] = map[string]any{
		"validation_passed": checks["platform_specific_validation"],
		"platform_rules":    v.getPlatformRules(platform),
		"specific_checks":   v.getSpecificCheckResults(match, platform),
	}

	// Pattern specificity details
	details["pattern_specificity"] = map[string]any{
		"is_specific":         checks["pattern_specificity"],
		"specificity_score":   v.calculateSpecificityScore(match, platform),
		"specificity_factors": v.getSpecificityFactors(match, platform),
	}

	// Length validation details
	details["length_validation"] = map[string]any{
		"match_length":          len(match),
		"reasonable_length":     checks["reasonable_length"],
		"platform_length_range": v.getPlatformLengthRange(platform),
	}

	// Domain validation details (for URLs)
	if strings.Contains(match, "://") {
		details["domain_validation"] = map[string]any{
			"valid_domain":     checks["domain_validation"],
			"expected_domains": v.getExpectedDomains(platform),
			"actual_domain":    v.extractDomain(match),
		}
	}

	// Character set validation details
	details["character_set"] = map[string]any{
		"valid_characters":   checks["valid_character_set"],
		"allowed_characters": v.getAllowedCharacters(platform),
		"invalid_characters": v.findInvalidCharacters(match, platform),
	}

	// Path structure validation details (for URLs)
	if strings.Contains(match, "://") {
		details["path_structure"] = map[string]any{
			"valid_structure":   checks["valid_path_structure"],
			"expected_patterns": v.getExpectedPathPatterns(platform),
			"actual_path":       v.extractPath(match),
		}
	}

	// False positive prevention details
	details["false_positive_prevention"] = map[string]any{
		"not_false_positive":        checks["not_false_positive"],
		"false_positive_indicators": v.findFalsePositiveIndicators(match),
		"confidence_impact":         v.getFalsePositiveImpact(match),
	}

	return details
}

// Helper methods for validation details

func (v *Validator) getIdentificationMethod(match string, platform string) string {
	if strings.Contains(strings.ToLower(match), platform) {
		return "domain_based"
	}
	if strings.HasPrefix(match, "@") && platform == "twitter" {
		return "handle_pattern"
	}
	return "pattern_matching"
}

func (v *Validator) extractProtocol(match string) string {
	if strings.HasPrefix(strings.ToLower(match), "https://") {
		return "https"
	}
	if strings.HasPrefix(strings.ToLower(match), "http://") {
		return "http"
	}
	return ""
}

func (v *Validator) extractDomain(match string) string {
	if !strings.Contains(match, "://") {
		return ""
	}
	parts := strings.Split(match, "://")
	if len(parts) < 2 {
		return ""
	}
	domainPart := strings.Split(parts[1], "/")[0]
	return domainPart
}

func (v *Validator) extractPath(match string) string {
	if !strings.Contains(match, "://") {
		return ""
	}
	parts := strings.Split(match, "://")
	if len(parts) < 2 {
		return ""
	}
	pathParts := strings.Split(parts[1], "/")
	if len(pathParts) <= 1 {
		return "/"
	}
	return "/" + strings.Join(pathParts[1:], "/")
}

func (v *Validator) getUsernameRequirements(platform string) map[string]any {
	switch platform {
	case "linkedin", "linkedin_patterns":
		return map[string]any{
			"min_length":    3,
			"max_length":    100,
			"allowed_chars": "alphanumeric, hyphens, underscores",
		}
	case "twitter", "twitter_patterns":
		return map[string]any{
			"min_length":    1,
			"max_length":    15,
			"allowed_chars": "alphanumeric, underscores",
		}
	case "github", "github_patterns":
		return map[string]any{
			"min_length":    1,
			"max_length":    39,
			"allowed_chars": "alphanumeric, hyphens (not at start/end)",
		}
	default:
		return map[string]any{
			"min_length":    1,
			"max_length":    100,
			"allowed_chars": "platform-specific",
		}
	}
}

func (v *Validator) getPlatformRules(platform string) []string {
	switch platform {
	case "linkedin", "linkedin_patterns":
		return []string{"must contain /in/, /company/, or /pub/", "no double slashes"}
	case "twitter", "twitter_patterns":
		return []string{"handles must be 1-15 chars", "URLs must not be tweet links"}
	case "github", "github_patterns":
		return []string{"must have username", "can include repository name"}
	default:
		return []string{"platform-specific validation"}
	}
}

func (v *Validator) getSpecificCheckResults(match string, platform string) map[string]bool {
	results := make(map[string]bool)
	matchLower := strings.ToLower(match)

	switch platform {
	case "linkedin", "linkedin_patterns":
		results["has_profile_path"] = strings.Contains(matchLower, "/in/")
		results["has_company_path"] = strings.Contains(matchLower, "/company/")
		results["no_double_slashes"] = !strings.Contains(matchLower, "//")
	case "twitter", "twitter_patterns":
		results["valid_handle_length"] = len(match) >= 2 && len(match) <= 16
		results["not_tweet_url"] = !strings.Contains(matchLower, "/status/")
	case "github", "github_patterns":
		results["has_username"] = v.extractUsername(match, platform) != ""
		results["valid_structure"] = strings.Contains(matchLower, "github.com") || strings.Contains(matchLower, "github.io")
	}

	return results
}

func (v *Validator) calculateSpecificityScore(match string, platform string) float64 {
	score := 0.0

	// Length contributes to specificity
	if len(match) > 10 {
		score += 20.0
	}

	// Platform domain presence
	if strings.Contains(strings.ToLower(match), platform) {
		score += 30.0
	}

	// Path specificity for URLs
	if strings.Contains(match, "://") && strings.Count(match, "/") > 2 {
		score += 25.0
	}

	// Username extractability
	if v.extractUsername(match, platform) != "" {
		score += 25.0
	}

	return score
}

func (v *Validator) getSpecificityFactors(match string, platform string) []string {
	factors := []string{}

	if len(match) > 10 {
		factors = append(factors, "sufficient_length")
	}
	if strings.Contains(strings.ToLower(match), platform) {
		factors = append(factors, "platform_domain_present")
	}
	if strings.Contains(match, "://") {
		factors = append(factors, "full_url_format")
	}
	if v.extractUsername(match, platform) != "" {
		factors = append(factors, "extractable_username")
	}

	return factors
}

func (v *Validator) getPlatformLengthRange(platform string) map[string]int {
	switch platform {
	case "twitter", "twitter_patterns":
		if strings.HasPrefix("@", "@") { // Handle case
			return map[string]int{"min": 2, "max": 16}
		}
		return map[string]int{"min": 15, "max": 150}
	case "linkedin", "linkedin_patterns":
		return map[string]int{"min": 10, "max": 300}
	case "github", "github_patterns":
		return map[string]int{"min": 10, "max": 250}
	default:
		return map[string]int{"min": 5, "max": 200}
	}
}

func (v *Validator) getExpectedDomains(platform string) []string {
	switch platform {
	case "linkedin", "linkedin_patterns":
		return []string{"linkedin.com"}
	case "twitter", "twitter_patterns":
		return []string{"twitter.com", "x.com"}
	case "github", "github_patterns":
		return []string{"github.com", "github.io"}
	case "facebook", "facebook_patterns":
		return []string{"facebook.com", "fb.com"}
	case "instagram", "instagram_patterns":
		return []string{"instagram.com", "instagr.am"}
	case "youtube", "youtube_patterns":
		return []string{"youtube.com", "youtu.be"}
	case "tiktok", "tiktok_patterns":
		return []string{"tiktok.com"}
	default:
		return []string{"platform-specific"}
	}
}

func (v *Validator) getAllowedCharacters(platform string) string {
	switch platform {
	case "linkedin", "linkedin_patterns":
		return "a-zA-Z0-9._-"
	case "twitter", "twitter_patterns":
		return "a-zA-Z0-9_"
	case "github", "github_patterns":
		return "a-zA-Z0-9- (not at start/end)"
	case "facebook", "facebook_patterns":
		return "a-zA-Z0-9._"
	case "instagram", "instagram_patterns":
		return "a-zA-Z0-9_."
	default:
		return "platform-specific"
	}
}

func (v *Validator) findInvalidCharacters(match string, platform string) []string {
	username := v.extractUsername(match, platform)
	if username == "" {
		return []string{}
	}

	var allowedPattern *regexp.Regexp
	switch platform {
	case "linkedin", "linkedin_patterns":
		allowedPattern = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	case "twitter", "twitter_patterns":
		allowedPattern = regexp.MustCompile(`[^a-zA-Z0-9_]`)
	case "github", "github_patterns":
		allowedPattern = regexp.MustCompile(`[^a-zA-Z0-9-]`)
	default:
		allowedPattern = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	}

	invalidChars := allowedPattern.FindAllString(username, -1)
	return invalidChars
}

func (v *Validator) getExpectedPathPatterns(platform string) []string {
	switch platform {
	case "linkedin", "linkedin_patterns":
		return []string{"/in/username", "/company/name", "/pub/name"}
	case "twitter", "twitter_patterns":
		return []string{"/username"}
	case "github", "github_patterns":
		return []string{"/username", "/username/repo"}
	case "youtube", "youtube_patterns":
		return []string{"/user/name", "/c/name", "/channel/id", "/@name"}
	default:
		return []string{"platform-specific"}
	}
}

func (v *Validator) findFalsePositiveIndicators(match string) []string {
	indicators := []string{}
	matchLower := strings.ToLower(match)

	falsePositivePatterns := []string{
		"example", "test", "placeholder", "demo", "sample",
		"dummy", "fake", "template", "mock", "tutorial",
	}

	for _, pattern := range falsePositivePatterns {
		if strings.Contains(matchLower, pattern) {
			indicators = append(indicators, pattern)
		}
	}

	return indicators
}

func (v *Validator) getFalsePositiveImpact(match string) float64 {
	indicators := v.findFalsePositiveIndicators(match)
	if len(indicators) > 0 {
		return -30.0 // Strong negative impact
	}
	return 0.0
}

// getPlatformNames returns a slice of platform names from a map
// Helper function for logging platform names
func (v *Validator) getPlatformNames(platformMap any) []string {
	var names []string

	switch pm := platformMap.(type) {
	case map[string][]string:
		for platform := range pm {
			names = append(names, platform)
		}
	case map[string][]*regexp.Regexp:
		for platform := range pm {
			names = append(names, platform)
		}
	}

	return names
}

// identifyProfileClusters groups matches into potential profile clusters
// This method identifies matches that might belong to the same user or related profiles
func (v *Validator) identifyProfileClusters(matches []detector.Match) [][]detector.Match {
	if len(matches) <= 1 {
		// Single or no matches - return as individual clusters
		var clusters [][]detector.Match
		for _, match := range matches {
			clusters = append(clusters, []detector.Match{match})
		}
		return clusters
	}

	// Group matches by proximity and similarity
	var clusters [][]detector.Match
	processed := make(map[int]bool)

	for i, match := range matches {
		if processed[i] {
			continue
		}

		// Start a new cluster with this match
		cluster := []detector.Match{match}
		processed[i] = true

		// Find related matches within proximity threshold
		for j, otherMatch := range matches {
			if processed[j] || i == j {
				continue
			}

			// Check if matches are related (same user, similar usernames, etc.)
			if v.areMatchesRelated(match, otherMatch) {
				cluster = append(cluster, otherMatch)
				processed[j] = true
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}

// areMatchesRelated determines if two social media matches are related
// This checks for same user indicators, similar usernames, or platform cross-references
func (v *Validator) areMatchesRelated(match1, match2 detector.Match) bool {
	// Check proximity - matches should be reasonably close to each other
	if !v.areMatchesInProximity(match1, match2) {
		return false
	}

	// Extract usernames and platforms for comparison
	username1 := v.extractUsernameFromMatch(match1)
	username2 := v.extractUsernameFromMatch(match2)
	platform1 := v.extractPlatformFromMatch(match1)
	platform2 := v.extractPlatformFromMatch(match2)

	// Same username on different platforms suggests same user
	if username1 != "" && username2 != "" && strings.EqualFold(username1, username2) && platform1 != platform2 {
		return true
	}

	// Similar usernames (with minor variations) might be the same user
	if username1 != "" && username2 != "" && v.areSimilarUsernames(username1, username2) {
		return true
	}

	// Check for cross-platform references in context
	if v.hasContextualCrossReference(match1, match2) {
		return true
	}

	// Check for consistent branding or naming patterns
	if v.hasConsistentBranding(match1, match2) {
		return true
	}

	return false
}

// areMatchesInProximity checks if two matches are within the proximity threshold
func (v *Validator) areMatchesInProximity(match1, match2 detector.Match) bool {
	// Calculate character distance between matches
	distance := v.calculateMatchDistance(match1, match2)
	return distance <= v.clusteringConfig.ProximityThreshold
}

// calculateMatchDistance calculates the character distance between two matches
func (v *Validator) calculateMatchDistance(match1, match2 detector.Match) int {
	// Use line number information if available
	if match1.LineNumber != 0 && match2.LineNumber != 0 {
		lineDiff := match1.LineNumber - match2.LineNumber
		if lineDiff < 0 {
			lineDiff = -lineDiff
		}

		// Approximate character distance based on line difference
		// Assume average line length of 80 characters
		return lineDiff * 80
	}

	// Default: assume they're close if we can't calculate distance
	return 100
}

// extractUsernameFromMatch extracts the username from a social media match
func (v *Validator) extractUsernameFromMatch(match detector.Match) string {
	// Try to get platform from metadata first
	var platform string
	if match.Metadata != nil {
		if p, ok := match.Metadata["platform"].(string); ok {
			platform = p
		}
	}

	// If no platform in metadata, identify it from the match text
	if platform == "" {
		platform = v.identifyPlatform(match.Text)
	}

	return v.extractUsername(match.Text, platform)
}

// extractPlatformFromMatch extracts the platform from a social media match
func (v *Validator) extractPlatformFromMatch(match detector.Match) string {
	// Try to get platform from metadata first
	if match.Metadata != nil {
		if platform, ok := match.Metadata["platform"].(string); ok {
			return platform
		}
	}

	// Fallback: identify platform from match text
	return v.identifyPlatform(match.Text)
}

// areSimilarUsernames checks if two usernames are similar (same user with minor variations)
func (v *Validator) areSimilarUsernames(username1, username2 string) bool {
	// Exact match (case insensitive)
	if strings.EqualFold(username1, username2) {
		return true
	}

	// Remove common variations (dots, underscores, numbers)
	clean1 := v.cleanUsernameForComparison(username1)
	clean2 := v.cleanUsernameForComparison(username2)

	if strings.EqualFold(clean1, clean2) {
		return true
	}

	// Check if one is a substring of the other (with reasonable length)
	if len(username1) >= 4 && len(username2) >= 4 {
		if strings.Contains(strings.ToLower(username1), strings.ToLower(username2)) ||
			strings.Contains(strings.ToLower(username2), strings.ToLower(username1)) {
			return true
		}
	}

	return false
}

// cleanUsernameForComparison removes common variations from usernames for comparison
func (v *Validator) cleanUsernameForComparison(username string) string {
	// Remove dots, underscores, and trailing numbers
	cleaned := strings.ReplaceAll(username, ".", "")
	cleaned = strings.ReplaceAll(cleaned, "_", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	// Remove trailing numbers (common variation)
	for len(cleaned) > 0 && cleaned[len(cleaned)-1] >= '0' && cleaned[len(cleaned)-1] <= '9' {
		cleaned = cleaned[:len(cleaned)-1]
	}

	return cleaned
}

// hasContextualCrossReference checks if matches have contextual cross-references
func (v *Validator) hasContextualCrossReference(match1, match2 detector.Match) bool {
	// Check if the context around one match mentions the other platform
	platform1 := v.extractPlatformFromMatch(match1)
	platform2 := v.extractPlatformFromMatch(match2)

	// Look for platform keywords in the context of each match
	if platform2 != "" {
		contextText := strings.ToLower(match1.Context.BeforeText + " " + match1.Context.AfterText)
		if strings.Contains(contextText, platform2) {
			return true
		}
	}

	if platform1 != "" {
		contextText := strings.ToLower(match2.Context.BeforeText + " " + match2.Context.AfterText)
		if strings.Contains(contextText, platform1) {
			return true
		}
	}

	return false
}

// hasConsistentBranding checks if matches show consistent branding or naming patterns
func (v *Validator) hasConsistentBranding(match1, match2 detector.Match) bool {
	// Extract potential brand/name elements from usernames
	username1 := v.extractUsernameFromMatch(match1)
	username2 := v.extractUsernameFromMatch(match2)

	if username1 == "" || username2 == "" {
		return false
	}

	// Look for common brand elements (first part of username, etc.)
	parts1 := v.extractBrandElements(username1)
	parts2 := v.extractBrandElements(username2)

	// Check for overlap in brand elements
	for _, part1 := range parts1 {
		for _, part2 := range parts2 {
			if len(part1) >= 3 && len(part2) >= 3 && strings.EqualFold(part1, part2) {
				return true
			}
		}
	}

	return false
}

// extractBrandElements extracts potential brand elements from a username
func (v *Validator) extractBrandElements(username string) []string {
	var elements []string

	// Split by common separators
	separators := []string{"_", ".", "-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	parts := []string{username}

	for _, sep := range separators {
		var newParts []string
		for _, part := range parts {
			newParts = append(newParts, strings.Split(part, sep)...)
		}
		parts = newParts
	}

	// Filter out short parts and numbers
	for _, part := range parts {
		if len(part) >= 3 && !v.isNumeric(part) {
			elements = append(elements, part)
		}
	}

	return elements
}

// isNumeric checks if a string is purely numeric
func (v *Validator) isNumeric(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(s) > 0
}

// analyzeSocialMediaClusteringContext analyzes whether multiple social media matches
// form a coherent profile cluster that should be reconstructed into a single finding
func (v *Validator) analyzeSocialMediaClusteringContext(matches []detector.Match) SocialMediaClusteringAnalysis {
	// Initialize analysis result with safe defaults
	analysis := SocialMediaClusteringAnalysis{
		IsProfileCluster:     false,
		ClusterType:          "unknown",
		Confidence:           0.0,
		ProximityScore:       0.0,
		PlatformGrouping:     []string{},
		ShouldReconstruct:    false,
		ReconstructionReason: "no_analysis_performed",
		UserIdentifiers:      []string{},
		ClusteringFactors:    make(map[string]float64),
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
				v.observer.DebugObserver.LogDetail("socialmedia",
					fmt.Sprintf("Recovered from panic during social media clustering analysis: %v", r))
			}

			// Reset to safe defaults
			analysis.IsProfileCluster = false
			analysis.ShouldReconstruct = false
			analysis.ReconstructionReason = "analysis_error_fallback"
		}
	}()

	// Step 1: Calculate proximity score
	analysis.ProximityScore = v.calculateClusterProximityScore(matches)

	// Step 2: Identify platform groupings
	analysis.PlatformGrouping = v.identifyPlatformGroupings(matches)

	// Step 3: Extract user identifiers
	analysis.UserIdentifiers = v.extractUserIdentifiers(matches)

	// Step 4: Calculate clustering factors
	analysis.ClusteringFactors = v.calculateClusteringFactors(matches, analysis)

	// Step 5: Determine if this appears to be a profile cluster
	analysis.IsProfileCluster = v.isProfileClusterPattern(matches, analysis)

	// Step 6: Classify the cluster type
	analysis.ClusterType = v.classifyClusterType(matches, analysis)

	// Step 7: Calculate confidence for the clustering analysis
	analysis.Confidence = v.calculateClusteringConfidence(matches, analysis)

	// Step 8: Make final reconstruction decision
	analysis.ShouldReconstruct, analysis.ReconstructionReason = v.makeClusteringDecision(analysis)

	// Log the analysis decision in debug mode
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.logClusteringAnalysis(matches, analysis)
	}

	return analysis
}

// calculateClusterProximityScore calculates how close the matches are to each other
func (v *Validator) calculateClusterProximityScore(matches []detector.Match) float64 {
	if len(matches) <= 1 {
		return 0.0
	}

	totalDistance := 0
	pairCount := 0

	// Calculate average distance between all pairs
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			distance := v.calculateMatchDistance(matches[i], matches[j])
			totalDistance += distance
			pairCount++
		}
	}

	if pairCount == 0 {
		return 0.0
	}

	avgDistance := float64(totalDistance) / float64(pairCount)

	// Convert distance to proximity score (0.0 to 1.0)
	// Closer matches get higher scores
	maxDistance := float64(v.clusteringConfig.ProximityThreshold)
	if avgDistance >= maxDistance {
		return 0.0
	}

	return (maxDistance - avgDistance) / maxDistance
}

// identifyPlatformGroupings identifies which platforms are represented in the cluster
func (v *Validator) identifyPlatformGroupings(matches []detector.Match) []string {
	platformSet := make(map[string]bool)

	for _, match := range matches {
		platform := v.extractPlatformFromMatch(match)
		if platform != "" {
			platformSet[platform] = true
		}
	}

	var platforms []string
	for platform := range platformSet {
		platforms = append(platforms, platform)
	}

	return platforms
}

// extractUserIdentifiers extracts potential user identifiers from the matches
func (v *Validator) extractUserIdentifiers(matches []detector.Match) []string {
	identifierSet := make(map[string]bool)

	for _, match := range matches {
		username := v.extractUsernameFromMatch(match)
		if username != "" {
			identifierSet[username] = true

			// Also add cleaned version for comparison
			cleaned := v.cleanUsernameForComparison(username)
			if cleaned != "" && cleaned != username {
				identifierSet[cleaned] = true
			}
		}
	}

	var identifiers []string
	for identifier := range identifierSet {
		identifiers = append(identifiers, identifier)
	}

	return identifiers
}

// calculateClusteringFactors calculates various factors that contribute to clustering decision
func (v *Validator) calculateClusteringFactors(matches []detector.Match, analysis SocialMediaClusteringAnalysis) map[string]float64 {
	factors := make(map[string]float64)

	// Factor 1: Platform diversity (more platforms = higher clustering potential)
	factors["platform_diversity"] = float64(len(analysis.PlatformGrouping)) * 5.0

	// Factor 2: Username similarity
	factors["username_similarity"] = v.calculateUsernameSimilarityFactor(analysis.UserIdentifiers)

	// Factor 3: Proximity bonus
	factors["proximity_bonus"] = analysis.ProximityScore * 10.0

	// Factor 4: Cross-reference indicators
	factors["cross_reference"] = v.calculateCrossReferenceFactor(matches)

	// Factor 5: Consistent branding
	factors["consistent_branding"] = v.calculateBrandingConsistencyFactor(matches)

	return factors
}

// calculateUsernameSimilarityFactor calculates how similar the usernames are
func (v *Validator) calculateUsernameSimilarityFactor(identifiers []string) float64 {
	if len(identifiers) <= 1 {
		return 0.0
	}

	similarityScore := 0.0
	pairCount := 0

	// Compare all pairs of identifiers
	for i := 0; i < len(identifiers); i++ {
		for j := i + 1; j < len(identifiers); j++ {
			if v.areSimilarUsernames(identifiers[i], identifiers[j]) {
				similarityScore += 15.0
			}
			pairCount++
		}
	}

	if pairCount == 0 {
		return 0.0
	}

	return similarityScore / float64(pairCount)
}

// calculateCrossReferenceFactor calculates the cross-reference factor
func (v *Validator) calculateCrossReferenceFactor(matches []detector.Match) float64 {
	crossRefScore := 0.0

	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if v.hasContextualCrossReference(matches[i], matches[j]) {
				crossRefScore += 10.0
			}
		}
	}

	return crossRefScore
}

// calculateBrandingConsistencyFactor calculates the branding consistency factor
func (v *Validator) calculateBrandingConsistencyFactor(matches []detector.Match) float64 {
	brandingScore := 0.0

	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if v.hasConsistentBranding(matches[i], matches[j]) {
				brandingScore += 8.0
			}
		}
	}

	return brandingScore
}

// isProfileClusterPattern determines if the matches form a profile cluster
func (v *Validator) isProfileClusterPattern(matches []detector.Match, analysis SocialMediaClusteringAnalysis) bool {
	// Must have multiple platforms for a meaningful cluster
	if len(analysis.PlatformGrouping) < 2 {
		return false
	}

	// Must have reasonable proximity
	if analysis.ProximityScore < 0.3 {
		return false
	}

	// Must have some similarity indicators
	totalFactorScore := 0.0
	for _, score := range analysis.ClusteringFactors {
		totalFactorScore += score
	}

	return totalFactorScore >= 20.0 // Minimum threshold for clustering
}

// classifyClusterType determines the specific type of profile cluster
func (v *Validator) classifyClusterType(matches []detector.Match, analysis SocialMediaClusteringAnalysis) string {
	// Check for same user across multiple platforms
	if len(analysis.PlatformGrouping) >= 2 && analysis.ClusteringFactors["username_similarity"] >= 10.0 {
		return "same_user_multi_platform"
	}

	// Check for related profiles (similar but not identical)
	if analysis.ClusteringFactors["consistent_branding"] >= 5.0 {
		return "related_profiles"
	}

	// Check for fragmented references
	if analysis.ProximityScore >= 0.7 && len(matches) >= 3 {
		return "fragmented_references"
	}

	// Default to mixed cluster
	return "mixed_cluster"
}

// calculateClusteringConfidence calculates confidence for profile clustering
func (v *Validator) calculateClusteringConfidence(matches []detector.Match, analysis SocialMediaClusteringAnalysis) float64 {
	if len(matches) <= 1 {
		return 0.0
	}

	baseConfidence := 30.0 // Base confidence for multiple matches

	// Add factor-based confidence
	for factor, score := range analysis.ClusteringFactors {
		switch factor {
		case "username_similarity":
			baseConfidence += score * 0.8
		case "platform_diversity":
			baseConfidence += score * 0.6
		case "cross_reference":
			baseConfidence += score * 0.9
		case "consistent_branding":
			baseConfidence += score * 0.7
		case "proximity_bonus":
			baseConfidence += score * 0.5
		}
	}

	// Apply cluster type bonus
	switch analysis.ClusterType {
	case "same_user_multi_platform":
		baseConfidence += v.clusteringConfig.ConfidenceBoosts["same_user_multi_platform"]
	case "related_profiles":
		baseConfidence += v.clusteringConfig.ConfidenceBoosts["related_profiles"]
	case "fragmented_references":
		baseConfidence += v.clusteringConfig.ConfidenceBoosts["fragmented_references"]
	}

	// Cap at maximum confidence
	if baseConfidence > v.clusteringConfig.MaxConfidence {
		baseConfidence = v.clusteringConfig.MaxConfidence
	}

	return baseConfidence
}

// makeClusteringDecision makes the final decision on whether to reconstruct
func (v *Validator) makeClusteringDecision(analysis SocialMediaClusteringAnalysis) (bool, string) {
	// Don't reconstruct if clustering is disabled
	if !v.clusteringConfig.Enabled {
		return false, "clustering_disabled"
	}

	// Don't reconstruct if not identified as a profile cluster
	if !analysis.IsProfileCluster {
		return false, "not_profile_cluster"
	}

	// Don't reconstruct if confidence is too low
	if analysis.Confidence < v.clusteringConfig.MinConfidenceThreshold {
		return false, fmt.Sprintf("confidence_too_low_%.1f", analysis.Confidence)
	}

	// Reconstruct if all conditions are met
	return true, fmt.Sprintf("profile_cluster_detected_%.1f_confidence", analysis.Confidence)
}

// reconstructSocialMediaClusterWithFallback combines related matches with graceful degradation
func (v *Validator) reconstructSocialMediaClusterWithFallback(matches []detector.Match) (detector.Match, error) {
	// Bounds checking for edge cases
	if len(matches) == 0 {
		return detector.Match{}, fmt.Errorf("no matches provided for reconstruction")
	}

	if len(matches) == 1 {
		// Single match doesn't need reconstruction
		return matches[0], nil
	}

	// Attempt reconstruction with error handling
	reconstructed, err := v.reconstructSocialMediaCluster(matches)
	if err != nil {
		// Log the error and return it for fallback handling
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia",
				fmt.Sprintf("Social media cluster reconstruction failed: %v", err))
		}
		return detector.Match{}, err
	}

	// Validate the reconstructed match
	if err := v.validateReconstructedCluster(reconstructed, matches); err != nil {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia",
				fmt.Sprintf("Reconstructed cluster validation failed: %v", err))
		}
		return detector.Match{}, err
	}

	return reconstructed, nil
}

// reconstructSocialMediaCluster combines related matches into a single comprehensive finding
func (v *Validator) reconstructSocialMediaCluster(matches []detector.Match) (detector.Match, error) {
	if len(matches) == 0 {
		return detector.Match{}, fmt.Errorf("no matches to reconstruct")
	}

	// Analyze the matches to get clustering context
	analysis := v.analyzeSocialMediaClusteringContext(matches)

	// Find the primary match (usually the one with highest confidence)
	primaryMatch := v.findPrimaryClusterMatch(matches)

	// Calculate reconstructed confidence
	reconstructedConfidence := v.calculateReconstructedClusterConfidence(matches, analysis)

	// Build consolidated match text
	consolidatedText := v.buildConsolidatedClusterText(matches)

	// Collect platforms and usernames from the original matches
	platforms := analysis.PlatformGrouping
	usernames := analysis.UserIdentifiers

	// Collect original match metadata
	originalConfidences := make([]float64, len(matches))
	originalMatchTexts := make([]string, len(matches))
	originalPlatforms := make([]string, len(matches))

	for i, match := range matches {
		originalConfidences[i] = match.Confidence
		originalMatchTexts[i] = match.Text
		originalPlatforms[i] = v.extractPlatformFromMatch(match)
	}

	// Calculate confidence boost
	confidenceBoost := reconstructedConfidence - primaryMatch.Confidence

	// Create consolidated metadata
	consolidatedMetadata := map[string]any{
		// Core clustering metadata
		"platforms":                   platforms,
		"usernames":                   usernames,
		"original_match_count":        len(matches),
		"original_confidences":        originalConfidences,
		"confidence_boost":            confidenceBoost,
		"confidence_boost_percentage": (confidenceBoost / primaryMatch.Confidence) * 100,

		// Clustering analysis results
		"cluster_type":          analysis.ClusterType,
		"clustering_confidence": analysis.Confidence,
		"proximity_score":       analysis.ProximityScore,
		"clustering_factors":    analysis.ClusteringFactors,
		"user_identifiers":      analysis.UserIdentifiers,

		// Original match preservation
		"original_match_texts": originalMatchTexts,
		"original_platforms":   originalPlatforms,
		"primary_match_index":  v.findPrimaryClusterMatchIndex(matches, primaryMatch),

		// Reconstruction metadata
		"source":                   "social_media_clustering",
		"reconstruction_algorithm": "profile_clustering_analysis",
		"reconstruction_version":   "1.0",
		"original_file":            primaryMatch.Filename,
		"reconstruction_reason":    analysis.ReconstructionReason,
	}

	// Create the reconstructed match
	reconstructedMatch := detector.Match{
		Text:       consolidatedText,
		Filename:   primaryMatch.Filename,
		LineNumber: primaryMatch.LineNumber, // Use primary match line number
		Type:       "SOCIAL_MEDIA_CLUSTER",
		Confidence: reconstructedConfidence,
		Context:    v.buildClusterContext(matches),
		Metadata:   consolidatedMetadata,
		Validator:  "SOCIAL_MEDIA",
	}

	return reconstructedMatch, nil
}

// findPrimaryClusterMatch finds the match with the highest confidence to use as primary
func (v *Validator) findPrimaryClusterMatch(matches []detector.Match) detector.Match {
	if len(matches) == 0 {
		return detector.Match{}
	}

	primaryMatch := matches[0]
	for _, match := range matches[1:] {
		if match.Confidence > primaryMatch.Confidence {
			primaryMatch = match
		}
	}

	return primaryMatch
}

// findPrimaryClusterMatchIndex finds the index of the primary match
func (v *Validator) findPrimaryClusterMatchIndex(matches []detector.Match, primaryMatch detector.Match) int {
	for i, match := range matches {
		if match.Text == primaryMatch.Text && match.LineNumber == primaryMatch.LineNumber {
			return i
		}
	}
	return 0
}

// calculateReconstructedClusterConfidence calculates confidence for reconstructed clusters
func (v *Validator) calculateReconstructedClusterConfidence(matches []detector.Match, analysis SocialMediaClusteringAnalysis) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	// Start with the highest individual confidence
	maxConfidence := 0.0
	for _, match := range matches {
		if match.Confidence > maxConfidence {
			maxConfidence = match.Confidence
		}
	}

	// Apply clustering confidence boost
	clusteringBoost := analysis.Confidence * 0.3 // 30% of clustering confidence

	// Apply cluster type specific boost
	var typeBoost float64
	if boost, exists := v.clusteringConfig.ConfidenceBoosts[analysis.ClusterType]; exists {
		typeBoost = boost
	}

	finalConfidence := maxConfidence + clusteringBoost + typeBoost

	// Cap at maximum confidence
	if finalConfidence > v.clusteringConfig.MaxConfidence {
		finalConfidence = v.clusteringConfig.MaxConfidence
	}

	return finalConfidence
}

// buildConsolidatedClusterText builds consolidated text for the cluster
func (v *Validator) buildConsolidatedClusterText(matches []detector.Match) string {
	if len(matches) == 0 {
		return ""
	}

	if len(matches) == 1 {
		return matches[0].Text
	}

	// Build a summary of the cluster
	platforms := make(map[string][]string)

	for _, match := range matches {
		platform := v.extractPlatformFromMatch(match)
		username := v.extractUsernameFromMatch(match)

		if platform != "" {
			if username != "" {
				platforms[platform] = append(platforms[platform], username)
			} else {
				platforms[platform] = append(platforms[platform], match.Text)
			}
		}
	}

	// Build consolidated text
	var parts []string
	for platform, items := range platforms {
		if len(items) == 1 {
			parts = append(parts, fmt.Sprintf("%s: %s", platform, items[0]))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", platform, strings.Join(items, ", ")))
		}
	}

	return strings.Join(parts, " | ")
}

// buildClusterContext builds context information for the cluster
func (v *Validator) buildClusterContext(matches []detector.Match) detector.ContextInfo {
	if len(matches) == 0 {
		return detector.ContextInfo{}
	}

	// Use the primary match's context as base
	primaryMatch := v.findPrimaryClusterMatch(matches)

	// Return the primary match's context
	// Could be enhanced to combine contexts from all matches
	return primaryMatch.Context
}

// validateReconstructedCluster validates that a reconstructed cluster is valid
func (v *Validator) validateReconstructedCluster(reconstructed detector.Match, originalMatches []detector.Match) error {
	// Check basic fields
	if reconstructed.Text == "" {
		return fmt.Errorf("reconstructed cluster has empty text")
	}

	if reconstructed.Confidence <= 0 {
		return fmt.Errorf("reconstructed cluster has invalid confidence: %.2f", reconstructed.Confidence)
	}

	// Check metadata
	if reconstructed.Metadata == nil {
		return fmt.Errorf("reconstructed cluster missing metadata")
	}

	// Validate required metadata fields
	requiredFields := []string{"platforms", "cluster_type", "original_match_count"}
	for _, field := range requiredFields {
		if _, exists := reconstructed.Metadata[field]; !exists {
			return fmt.Errorf("reconstructed cluster missing required metadata field: %s", field)
		}
	}

	return nil
}

// logClusteringAnalysis logs detailed clustering analysis information
func (v *Validator) logClusteringAnalysis(matches []detector.Match, analysis SocialMediaClusteringAnalysis) {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}

	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("Social media clustering analysis for %d matches:", len(matches)))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Cluster Type: %s", analysis.ClusterType))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Is Profile Cluster: %t", analysis.IsProfileCluster))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Confidence: %.2f", analysis.Confidence))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Proximity Score: %.2f", analysis.ProximityScore))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Platforms: %v", analysis.PlatformGrouping))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  User Identifiers: %v", analysis.UserIdentifiers))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Should Reconstruct: %t", analysis.ShouldReconstruct))
	v.observer.DebugObserver.LogDetail("socialmedia",
		fmt.Sprintf("  Reconstruction Reason: %s", analysis.ReconstructionReason))

	// Log clustering factors
	v.observer.DebugObserver.LogDetail("socialmedia", "  Clustering Factors:")
	for factor, score := range analysis.ClusteringFactors {
		v.observer.DebugObserver.LogDetail("socialmedia",
			fmt.Sprintf("    %s: %.2f", factor, score))
	}
}

// logPerformanceMetrics logs performance metrics for monitoring and optimization
func (v *Validator) logPerformanceMetrics(operation string, duration int64, metadata map[string]any) {
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Performance: %s completed in %dms", operation, duration))

		// Log additional performance context
		if contentLength, ok := metadata["content_length"].(int); ok {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Content length: %d bytes", contentLength))
			if contentLength > 0 {
				throughput := float64(contentLength) / float64(duration) * 1000 // bytes per second
				v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Throughput: %.2f bytes/sec", throughput))
			}
		}

		if matchCount, ok := metadata["match_count"].(int); ok {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Matches found: %d", matchCount))
		}

		if patternsUsed, ok := metadata["patterns_used"].(int); ok {
			v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("  Patterns used: %d", patternsUsed))
		}
	}

	// Also log to stderr in debug mode for comprehensive performance tracking
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[PERF] Social Media Validator: %s completed in %dms\n", operation, duration)
		if contentLength, ok := metadata["content_length"].(int); ok && contentLength > 1024*1024 {
			fmt.Fprintf(os.Stderr, "[PERF]   Large file processed: %d MB\n", contentLength/(1024*1024))
		}
		if matchCount, ok := metadata["match_count"].(int); ok {
			fmt.Fprintf(os.Stderr, "[PERF]   Matches: %d\n", matchCount)
		}
	}
}

// logMemoryUsage logs memory usage information for large file processing
func (v *Validator) logMemoryUsage(operation string, filePath string, beforeMB, afterMB int64) {
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Memory usage for %s on %s: %d MB -> %d MB (delta: %+d MB)",
			operation, filePath, beforeMB, afterMB, afterMB-beforeMB))
	}

	// Log memory warnings for large usage
	if afterMB > 500 { // 500MB threshold
		if os.Getenv("FERRET_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "[MEMORY] Social Media Validator: High memory usage detected\n")
			fmt.Fprintf(os.Stderr, "[MEMORY]   Operation: %s\n", operation)
			fmt.Fprintf(os.Stderr, "[MEMORY]   File: %s\n", filePath)
			fmt.Fprintf(os.Stderr, "[MEMORY]   Memory usage: %d MB\n", afterMB)
			fmt.Fprintf(os.Stderr, "[MEMORY]   Recommendation: Consider processing file in chunks\n")
		}
	}
}

// logErrorRecovery logs error recovery information for debugging
func (v *Validator) logErrorRecovery(operation string, filePath string, err error, recoveryAction string) {
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Error recovery in %s for %s: %v", operation, filePath, err))
		v.observer.DebugObserver.LogDetail("socialmedia", fmt.Sprintf("Recovery action: %s", recoveryAction))
	}

	// Also log to stderr in debug mode for comprehensive error tracking
	if os.Getenv("FERRET_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "[RECOVERY] Social Media Validator: Error recovery\n")
		fmt.Fprintf(os.Stderr, "[RECOVERY]   Operation: %s\n", operation)
		fmt.Fprintf(os.Stderr, "[RECOVERY]   File: %s\n", filePath)
		fmt.Fprintf(os.Stderr, "[RECOVERY]   Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "[RECOVERY]   Action: %s\n", recoveryAction)
	}
}

// isDebugEnabled checks if debug mode is enabled following the pattern from other validators
func (v *Validator) isDebugEnabled() bool {
	return os.Getenv("FERRET_DEBUG") != ""
}

// getPlatformDisplayName converts platform pattern names to user-friendly display names
func (v *Validator) getPlatformDisplayName(platform string) string {
	// Map platform pattern names to display names
	displayNames := map[string]string{
		"linkedin":               "LINKEDIN",
		"linkedin_patterns":      "LINKEDIN",
		"twitter":                "TWITTER",
		"twitter_patterns":       "TWITTER",
		"github":                 "GITHUB",
		"github_patterns":        "GITHUB",
		"facebook":               "FACEBOOK",
		"facebook_patterns":      "FACEBOOK",
		"instagram":              "INSTAGRAM",
		"instagram_patterns":     "INSTAGRAM",
		"youtube":                "YOUTUBE",
		"youtube_patterns":       "YOUTUBE",
		"tiktok":                 "TIKTOK",
		"tiktok_patterns":        "TIKTOK",
		"discord":                "DISCORD",
		"discord_patterns":       "DISCORD",
		"reddit":                 "REDDIT",
		"reddit_patterns":        "REDDIT",
		"snapchat":               "SNAPCHAT",
		"snapchat_patterns":      "SNAPCHAT",
		"pinterest":              "PINTEREST",
		"pinterest_patterns":     "PINTEREST",
		"twitch":                 "TWITCH",
		"twitch_patterns":        "TWITCH",
		"medium":                 "MEDIUM",
		"medium_patterns":        "MEDIUM",
		"stackoverflow":          "STACKOVERFLOW",
		"stackoverflow_patterns": "STACKOVERFLOW",
		"mastodon":               "MASTODON",
		"mastodon_patterns":      "MASTODON",
		"telegram":               "TELEGRAM",
		"telegram_patterns":      "TELEGRAM",
		"whatsapp":               "WHATSAPP",
		"whatsapp_patterns":      "WHATSAPP",
		"skype":                  "SKYPE",
		"skype_patterns":         "SKYPE",
		"clubhouse":              "CLUBHOUSE",
		"clubhouse_patterns":     "CLUBHOUSE",
	}

	if displayName, exists := displayNames[platform]; exists {
		return displayName
	}

	// Fallback: convert to uppercase and remove _patterns suffix
	displayName := strings.ToUpper(platform)
	displayName = strings.ReplaceAll(displayName, "_PATTERNS", "")
	return displayName
}

// isPartOfEmailAddress checks if a social media match is actually part of an email address
// This prevents false positives where email domain parts are detected as social media handles
func (v *Validator) isPartOfEmailAddress(match, line string) bool {
	// This is specifically designed to catch cases where Twitter handle patterns (@username)
	// match the domain part of email addresses (e.g., @amazon from user@amazon.com)

	// Only check for @ handles that could be confused with email domains
	if !strings.HasPrefix(match, "@") {
		return false
	}

	// Extract the domain part (without @)
	domainPart := match[1:]

	// Look for email patterns in the line that contain this domain part
	// Pattern: word characters + @ + our domain part + . + domain extension
	emailPattern := `\b[A-Za-z0-9._%+-]+@` + regexp.QuoteMeta(domainPart) + `\.[A-Za-z]{2,}\b`
	emailRegex := regexp.MustCompile(emailPattern)

	// If we find a complete email address that contains our match, it's a false positive
	if emailRegex.MatchString(line) {
		// Log the filtering for debugging
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia",
				fmt.Sprintf("Filtered social media false positive: '%s' is part of email address in line: %s",
					match, line))
		}
		return true
	}

	return false
}

// isFalsePositiveHandle checks for common false positive patterns that shouldn't be detected as social media
func (v *Validator) isFalsePositiveHandle(match, line string) bool {
	if !strings.HasPrefix(match, "@") {
		return false
	}

	username := match[1:]
	lineLower := strings.ToLower(line)

	// Documentation and code annotation patterns
	docPatterns := []string{
		"param", "return", "author", "since", "version", "deprecated", "override",
		"todo", "fixme", "hack", "note", "see", "link", "throws", "exception",
		"example", "code", "pre", "post", "invariant", "requires", "ensures",
		"suppress", "nullable", "nonnull", "inject", "autowired", "component",
		"service", "repository", "controller", "entity", "table", "column",
	}

	usernameLower := strings.ToLower(username)
	for _, pattern := range docPatterns {
		if usernameLower == pattern {
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia",
					fmt.Sprintf("Filtered documentation annotation: '%s' in line: %s", match, line))
			}
			return true
		}
	}

	// Code comment context (// @something or /* @something)
	if strings.Contains(lineLower, "//") || strings.Contains(lineLower, "/*") || strings.Contains(lineLower, "*/") {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia",
				fmt.Sprintf("Filtered code comment annotation: '%s' in line: %s", match, line))
		}
		return true
	}

	// Invalid Twitter handle patterns
	// Twitter handles cannot start with numbers, underscores, or be too short
	if len(username) < 2 || strings.HasPrefix(username, "_") || regexp.MustCompile(`^\d`).MatchString(username) {
		if v.observer != nil && v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("socialmedia",
				fmt.Sprintf("Filtered invalid handle format: '%s' in line: %s", match, line))
		}
		return true
	}

	// Partial domain matches (e.g., @my from contact@my-company.com)
	// Look for patterns where the handle is immediately followed by a hyphen or dot
	matchIndex := strings.Index(line, match)
	if matchIndex >= 0 && matchIndex+len(match) < len(line) {
		nextChar := line[matchIndex+len(match)]
		if nextChar == '-' || nextChar == '.' {
			if v.observer != nil && v.observer.DebugObserver != nil {
				v.observer.DebugObserver.LogDetail("socialmedia",
					fmt.Sprintf("Filtered partial domain match: '%s' in line: %s", match, line))
			}
			return true
		}
	}

	return false
}
