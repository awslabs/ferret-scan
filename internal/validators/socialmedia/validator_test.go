// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"

	"ferret-scan/internal/detector"
)

// --- Helper to create a configured validator with platform patterns ---

func newConfiguredValidator() *Validator {
	v := NewValidator()
	// Manually set up platform patterns and compile them so tests can run
	// without needing a full config file.
	v.platformPatterns = map[string][]string{
		"twitter": {
			`(?i)https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}`,
			`(?i)https?://(?:www\.)?x\.com/[a-zA-Z0-9_]{1,15}`,
			`(?i)@[a-zA-Z0-9_]{1,15}\b`,
		},
		"linkedin": {
			`(?i)https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_-]+`,
			`(?i)https?://(?:www\.)?linkedin\.com/company/[a-zA-Z0-9_-]+`,
		},
		"github": {
			`(?i)https?://(?:www\.)?github\.com/[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(?:/[a-zA-Z0-9._-]+)?`,
		},
		"facebook": {
			`(?i)https?://(?:www\.)?facebook\.com/[a-zA-Z0-9._]{5,50}`,
		},
		"instagram": {
			`(?i)https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.]{1,30}`,
		},
		"youtube": {
			`(?i)https?://(?:www\.)?youtube\.com/(?:user|c|channel|@)[/]?[a-zA-Z0-9_-]+`,
		},
	}
	v.patternsConfigured = true
	v.compilePlatformPatterns()
	return v
}

// --- Valid URL Tests ---

func TestSocialMediaValidator_ValidURLs(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Twitter profile URL",
			content:     "Follow me at https://twitter.com/johndoe for updates",
			expectMatch: true,
			description: "Standard Twitter profile URL should be detected",
		},
		{
			name:        "LinkedIn profile URL",
			content:     "Connect on https://linkedin.com/in/john-doe-123",
			expectMatch: true,
			description: "Standard LinkedIn profile URL should be detected",
		},
		{
			name:        "GitHub user URL",
			content:     "Check out https://github.com/johndoe for my projects",
			expectMatch: true,
			description: "Standard GitHub user URL should be detected",
		},
		{
			name:        "Facebook page URL",
			content:     "Like us at https://facebook.com/johndoe.page",
			expectMatch: true,
			description: "Standard Facebook page URL should be detected",
		},
		{
			name:        "Instagram profile URL",
			content:     "Follow https://instagram.com/john_doe for photos",
			expectMatch: true,
			description: "Standard Instagram profile URL should be detected",
		},
		{
			name:        "X.com URL (Twitter rebrand)",
			content:     "Find me at https://x.com/johndoe",
			expectMatch: true,
			description: "X.com profile URL should be detected",
		},
		{
			name:        "LinkedIn company URL",
			content:     "Visit https://linkedin.com/company/acme-corp for info",
			expectMatch: true,
			description: "LinkedIn company URL should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

// --- Handle Tests ---

func TestSocialMediaValidator_Handles(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Twitter handle with social context",
			content:     "Follow me on social media @johndoe",
			expectMatch: true,
			description: "@handle in social media context should be detected",
		},
		{
			name:        "Twitter handle with profile context",
			content:     "My profile handle is @janedoe",
			expectMatch: true,
			description: "@handle with profile context should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

// --- False Positive Tests ---

func TestSocialMediaValidator_FalsePositives(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Git SSH URL should not match",
			content:     "git clone git@github.com:user/repo.git",
			expectMatch: false,
			description: "Git SSH URLs (git@github.com:user/repo.git) should be filtered",
		},
		{
			name:        "No patterns without configuration",
			content:     "Some random text with no social media",
			expectMatch: false,
			description: "Content without social media references should not match",
		},
		{
			name:        "Empty content",
			content:     "",
			expectMatch: false,
			description: "Empty content should produce no matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

// --- Unconfigured Validator Tests ---

func TestSocialMediaValidator_UnconfiguredReturnsEmpty(t *testing.T) {
	v := NewValidator()

	matches, err := v.ValidateContent("https://twitter.com/johndoe", "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("Unconfigured validator should return no matches, got %d", len(matches))
	}
}

func TestSocialMediaValidator_Validate_ReturnsEmpty(t *testing.T) {
	v := NewValidator()

	matches, err := v.Validate("somefile.txt")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate should return empty (direct file processing not supported), got %d", len(matches))
	}
}

// --- CalculateConfidence Tests ---

func TestSocialMediaValidator_CalculateConfidence(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name           string
		match          string
		expectPlatform bool
		description    string
	}{
		{
			name:           "Twitter URL gets confidence",
			match:          "https://twitter.com/johndoe",
			expectPlatform: true,
			description:    "Twitter URL should be identified and scored",
		},
		{
			name:           "LinkedIn URL gets confidence",
			match:          "https://linkedin.com/in/john-doe",
			expectPlatform: true,
			description:    "LinkedIn URL should be identified and scored",
		},
		{
			name:           "GitHub URL gets confidence",
			match:          "https://github.com/johndoe",
			expectPlatform: true,
			description:    "GitHub URL should be identified and scored",
		},
		{
			name:           "Empty match gets zero",
			match:          "",
			expectPlatform: false,
			description:    "Empty match should return 0 confidence",
		},
		{
			name:           "Unknown platform gets low confidence",
			match:          "https://unknownsite.com/user",
			expectPlatform: false,
			description:    "Unknown platform should get low confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := v.CalculateConfidence(tt.match)

			if tt.match == "" {
				if confidence != 0 {
					t.Errorf("Expected 0 confidence for empty match, got %f", confidence)
				}
				return
			}

			if tt.expectPlatform {
				if !checks["platform_identified"] {
					t.Errorf("Expected platform to be identified for %q: %s", tt.match, tt.description)
				}
				if confidence <= 0 {
					t.Errorf("Expected positive confidence for %q, got %f: %s", tt.match, confidence, tt.description)
				}
			}
		})
	}
}

// --- Context Analysis Tests ---

func TestSocialMediaValidator_AnalyzeContext(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name           string
		match          string
		contextLine    string
		expectPositive bool
		description    string
	}{
		{
			name:           "Social media keyword boost",
			match:          "https://twitter.com/johndoe",
			contextLine:    "Follow me on social media https://twitter.com/johndoe",
			expectPositive: true,
			description:    "Social media keywords should boost confidence",
		},
		{
			name:           "Profile keyword boost",
			match:          "https://linkedin.com/in/johndoe",
			contextLine:    "My profile: https://linkedin.com/in/johndoe",
			expectPositive: true,
			description:    "Profile keyword should boost confidence",
		},
		{
			name:           "Test/example context reduces",
			match:          "https://twitter.com/testuser",
			contextLine:    "Example: https://twitter.com/testuser for demo",
			expectPositive: false,
			description:    "Test/example context should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextInfo := detector.ContextInfo{
				FullLine: tt.contextLine,
			}
			impact := v.AnalyzeContext(tt.match, contextInfo)
			if tt.expectPositive && impact < 0 {
				t.Errorf("Expected non-negative context impact, got %f: %s", impact, tt.description)
			}
			if !tt.expectPositive && impact > 0 {
				t.Errorf("Expected non-positive context impact, got %f: %s", impact, tt.description)
			}
		})
	}
}

// --- Platform Identification Tests ---

func TestSocialMediaValidator_IdentifyPlatform(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name             string
		match            string
		expectedPlatform string
	}{
		{name: "Twitter URL", match: "https://twitter.com/user", expectedPlatform: "twitter"},
		{name: "X.com URL", match: "https://x.com/user", expectedPlatform: "twitter"},
		{name: "LinkedIn URL", match: "https://linkedin.com/in/user", expectedPlatform: "linkedin"},
		{name: "GitHub URL", match: "https://github.com/user", expectedPlatform: "github"},
		{name: "Facebook URL", match: "https://facebook.com/userpage", expectedPlatform: "facebook"},
		{name: "Instagram URL", match: "https://instagram.com/user", expectedPlatform: "instagram"},
		{name: "YouTube URL", match: "https://youtube.com/user/channel", expectedPlatform: "youtube"},
		{name: "Unknown URL", match: "https://unknownsite.com/user", expectedPlatform: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform := v.identifyPlatform(tt.match)
			if platform != tt.expectedPlatform {
				t.Errorf("identifyPlatform(%q) = %q, want %q", tt.match, platform, tt.expectedPlatform)
			}
		})
	}
}

// --- URL Format Validation Tests ---

func TestSocialMediaValidator_ValidateURLFormat(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name     string
		match    string
		platform string
		isValid  bool
	}{
		{name: "Valid LinkedIn /in/ URL", match: "https://linkedin.com/in/johndoe", platform: "linkedin", isValid: true},
		{name: "Valid LinkedIn /company/ URL", match: "https://linkedin.com/company/acme", platform: "linkedin", isValid: true},
		{name: "Invalid LinkedIn - no path", match: "https://linkedin.com/", platform: "linkedin", isValid: false},
		{name: "Valid Twitter URL", match: "https://twitter.com/johndoe", platform: "twitter", isValid: true},
		{name: "Valid GitHub URL", match: "https://github.com/johndoe", platform: "github", isValid: true},
		{name: "Non-URL string", match: "@johndoe", platform: "twitter", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateURLFormat(tt.match, tt.platform)
			if result != tt.isValid {
				t.Errorf("validateURLFormat(%q, %q) = %v, want %v", tt.match, tt.platform, result, tt.isValid)
			}
		})
	}
}

// --- Username Format Validation Tests ---

func TestSocialMediaValidator_ValidateUsernameFormat(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name     string
		username string
		platform string
		isValid  bool
	}{
		{name: "Valid Twitter username", username: "johndoe", platform: "twitter", isValid: true},
		{name: "Twitter username too long", username: "abcdefghijklmnop", platform: "twitter", isValid: false},
		{name: "Valid GitHub username", username: "johndoe", platform: "github", isValid: true},
		{name: "GitHub username with hyphen", username: "john-doe", platform: "github", isValid: true},
		{name: "GitHub username starts with hyphen", username: "-johndoe", platform: "github", isValid: false},
		{name: "Valid LinkedIn username", username: "john-doe-123", platform: "linkedin", isValid: true},
		{name: "Empty username", username: "", platform: "twitter", isValid: false},
		{name: "Valid Instagram username", username: "john_doe.photos", platform: "instagram", isValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateUsernameFormat(tt.username, tt.platform)
			if result != tt.isValid {
				t.Errorf("validateUsernameFormat(%q, %q) = %v, want %v", tt.username, tt.platform, result, tt.isValid)
			}
		})
	}
}

// --- Platform-Specific Validation Tests ---

func TestSocialMediaValidator_ValidateLinkedInSpecific(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name    string
		match   string
		isValid bool
	}{
		{name: "Valid /in/ URL", match: "https://linkedin.com/in/johndoe", isValid: true},
		{name: "Valid /company/ URL", match: "https://linkedin.com/company/acme-corp", isValid: true},
		{name: "Double slash in /in/", match: "https://linkedin.com/in//", isValid: false},
		{name: "Empty username in /in/", match: "https://linkedin.com/in/", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateLinkedInSpecific(tt.match, strings.ToLower(tt.match))
			if result != tt.isValid {
				t.Errorf("validateLinkedInSpecific(%q) = %v, want %v", tt.match, result, tt.isValid)
			}
		})
	}
}

func TestSocialMediaValidator_ValidateTwitterSpecific(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name    string
		match   string
		isValid bool
	}{
		{name: "Valid handle", match: "@johndoe", isValid: true},
		{name: "Handle too long", match: "@abcdefghijklmnop", isValid: false},
		{name: "Handle starts with underscore", match: "@_johndoe", isValid: false},
		{name: "Valid URL", match: "https://twitter.com/johndoe", isValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateTwitterSpecific(tt.match, strings.ToLower(tt.match))
			if result != tt.isValid {
				t.Errorf("validateTwitterSpecific(%q) = %v, want %v", tt.match, result, tt.isValid)
			}
		})
	}
}

func TestSocialMediaValidator_ValidateGitHubSpecific(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name    string
		match   string
		isValid bool
	}{
		{name: "Valid user URL", match: "https://github.com/johndoe", isValid: true},
		{name: "Valid user/repo URL", match: "https://github.com/johndoe/myrepo", isValid: true},
		{name: "Username starts with hyphen", match: "https://github.com/-johndoe", isValid: false},
		{name: "Empty username", match: "https://github.com/", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateGitHubSpecific(tt.match, strings.ToLower(tt.match))
			if result != tt.isValid {
				t.Errorf("validateGitHubSpecific(%q) = %v, want %v", tt.match, result, tt.isValid)
			}
		})
	}
}

// --- Edge Cases ---

func TestSocialMediaValidator_EdgeCases(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Multiple social media URLs on one line",
			content:     "Connect: https://twitter.com/johndoe https://linkedin.com/in/johndoe",
			expectMatch: true,
			description: "Multiple URLs on one line should each be detected",
		},
		{
			name:        "URL with www prefix",
			content:     "Visit https://www.twitter.com/johndoe",
			expectMatch: true,
			description: "URLs with www prefix should be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

// --- Reasonable Length Validation Tests ---

func TestSocialMediaValidator_ValidateReasonableLength(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name     string
		match    string
		platform string
		isValid  bool
	}{
		{name: "Twitter handle valid length", match: "@johndoe", platform: "twitter", isValid: true},
		{name: "Twitter handle too short", match: "@", platform: "twitter", isValid: false},
		{name: "LinkedIn URL valid length", match: "https://linkedin.com/in/johndoe", platform: "linkedin", isValid: true},
		{name: "Generic short match", match: "abc", platform: "other", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateReasonableLength(tt.match, tt.platform)
			if result != tt.isValid {
				t.Errorf("validateReasonableLength(%q, %q) = %v, want %v", tt.match, tt.platform, result, tt.isValid)
			}
		})
	}
}

// --- Platform Confidence Bonus Tests ---

func TestSocialMediaValidator_GetPlatformConfidenceBonus(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name     string
		platform string
		minBonus float64
	}{
		{name: "LinkedIn bonus", platform: "linkedin", minBonus: 5.0},
		{name: "GitHub bonus", platform: "github", minBonus: 5.0},
		{name: "Twitter bonus", platform: "twitter", minBonus: 3.0},
		{name: "Facebook bonus", platform: "facebook", minBonus: 4.0},
		{name: "Instagram bonus", platform: "instagram", minBonus: 4.0},
		{name: "Unknown platform bonus", platform: "unknown", minBonus: 2.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bonus := v.getPlatformConfidenceBonus(tt.platform)
			if bonus < tt.minBonus {
				t.Errorf("getPlatformConfidenceBonus(%q) = %f, want >= %f", tt.platform, bonus, tt.minBonus)
			}
		})
	}
}

// --- Domain Validation Tests ---

func TestSocialMediaValidator_ValidateDomain(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name     string
		match    string
		platform string
		isValid  bool
	}{
		{name: "LinkedIn correct domain", match: "https://linkedin.com/in/user", platform: "linkedin", isValid: true},
		{name: "Twitter correct domain", match: "https://twitter.com/user", platform: "twitter", isValid: true},
		{name: "X.com correct domain", match: "https://x.com/user", platform: "twitter", isValid: true},
		{name: "Non-URL skips domain validation", match: "@johndoe", platform: "twitter", isValid: true},
		{name: "Wrong domain for platform", match: "https://fakebook.org/in/user", platform: "linkedin", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.validateDomain(tt.match, tt.platform)
			if result != tt.isValid {
				t.Errorf("validateDomain(%q, %q) = %v, want %v", tt.match, tt.platform, result, tt.isValid)
			}
		})
	}
}

// --- Whitelist Pattern Tests ---

func TestSocialMediaValidator_IsWhitelistedMatch(t *testing.T) {
	v := newConfiguredValidator()

	// With no whitelist patterns, nothing should be whitelisted
	t.Run("empty whitelist", func(t *testing.T) {
		result := v.isWhitelistedMatch("https://twitter.com/user")
		if result {
			t.Error("Expected no whitelist match with empty whitelist")
		}
	})
}

// --- Compile Platform Patterns Tests ---

func TestSocialMediaValidator_CompilePlatformPatterns(t *testing.T) {
	t.Run("compiles valid patterns", func(t *testing.T) {
		v := NewValidator()
		v.platformPatterns = map[string][]string{
			"twitter": {`(?i)https?://twitter\.com/[a-zA-Z0-9_]+`},
		}
		v.compilePlatformPatterns()

		if len(v.compiledPatterns) == 0 {
			t.Error("Expected compiled patterns after compilation")
		}
		if _, ok := v.compiledPatterns["twitter"]; !ok {
			t.Error("Expected twitter patterns to be compiled")
		}
	})

	t.Run("handles empty patterns gracefully", func(t *testing.T) {
		v := NewValidator()
		v.platformPatterns = map[string][]string{}
		v.compilePlatformPatterns()

		if len(v.compiledPatterns) != 0 {
			t.Errorf("Expected 0 compiled patterns for empty input, got %d", len(v.compiledPatterns))
		}
	})

	t.Run("skips invalid regex patterns", func(t *testing.T) {
		v := NewValidator()
		v.platformPatterns = map[string][]string{
			"twitter": {`(?i)https?://twitter\.com/[a-zA-Z0-9_]+`, `[invalid`},
		}
		v.compilePlatformPatterns()

		if patterns, ok := v.compiledPatterns["twitter"]; ok {
			if len(patterns) != 1 {
				t.Errorf("Expected 1 valid compiled pattern (invalid should be skipped), got %d", len(patterns))
			}
		}
	})
}

// --- Extract Username Tests ---

func TestSocialMediaValidator_ExtractUsername(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name             string
		match            string
		platform         string
		expectedUsername string
	}{
		{name: "LinkedIn /in/ URL", match: "https://linkedin.com/in/johndoe", platform: "linkedin", expectedUsername: "johndoe"},
		{name: "Twitter handle", match: "@johndoe", platform: "twitter", expectedUsername: "johndoe"},
		{name: "GitHub URL", match: "https://github.com/johndoe", platform: "github", expectedUsername: "johndoe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username := v.extractUsername(tt.match, tt.platform)
			if username != tt.expectedUsername {
				t.Errorf("extractUsername(%q, %q) = %q, want %q", tt.match, tt.platform, username, tt.expectedUsername)
			}
		})
	}
}

// --- Negative Keywords Detection Tests ---

func TestSocialMediaValidator_ContainsNegativeKeywords(t *testing.T) {
	v := newConfiguredValidator()

	tests := []struct {
		name        string
		match       string
		hasNegative bool
	}{
		{name: "Test URL", match: "https://twitter.com/test", hasNegative: true},
		{name: "Example URL", match: "https://twitter.com/example", hasNegative: true},
		{name: "Normal URL", match: "https://twitter.com/johndoe", hasNegative: false},
		{name: "Demo URL", match: "https://github.com/demo", hasNegative: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.containsNegativeKeywords(tt.match)
			if result != tt.hasNegative {
				t.Errorf("containsNegativeKeywords(%q) = %v, want %v", tt.match, result, tt.hasNegative)
			}
		})
	}
}

// --- NewValidator Tests ---

func TestSocialMediaValidator_NewValidator(t *testing.T) {
	v := NewValidator()

	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}
	if v.platformPatterns == nil {
		t.Error("platformPatterns should be initialized")
	}
	if v.compiledPatterns == nil {
		t.Error("compiledPatterns should be initialized")
	}
	if len(v.positiveKeywords) == 0 {
		t.Error("positiveKeywords should have default values")
	}
	if len(v.negativeKeywords) == 0 {
		t.Error("negativeKeywords should have default values")
	}
	if !v.clusteringConfig.Enabled {
		t.Error("clustering should be enabled by default")
	}
	if v.patternsConfigured {
		t.Error("patterns should not be configured initially")
	}
}
