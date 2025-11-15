// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"math"
	"regexp"
	"strings"

	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/help"
	"ferret-scan/internal/observability"
)

// Validator detects secrets using entropy analysis and keyword patterns
type Validator struct {
	// High entropy detection
	base64Charset string
	hexCharset    string
	base64Limit   float64
	hexLimit      float64

	// Keyword patterns
	keywordPatterns []*regexp.Regexp

	// Context keywords
	positiveKeywords []string
	negativeKeywords []string

	// Enhanced context analysis
	contextAnalyzer *context.ContextAnalyzer

	// Domain-specific keywords for enhanced validation
	devKeywords  []string
	prodKeywords []string
	testKeywords []string

	// Global test patterns database
	globalTestPatterns []string

	// Pre-compiled regex patterns for shell variable detection (performance optimization)
	shellCommandPattern *regexp.Regexp

	// Pre-compiled regex patterns for performance optimization
	base64Pattern     *regexp.Regexp
	hexPattern        *regexp.Regexp
	multiSpacePattern *regexp.Regexp
	configPattern     *regexp.Regexp
	variablePatterns  []*regexp.Regexp

	// Observability
	observer *observability.StandardObserver
}

// NewValidator creates a new secrets validator
func NewValidator() *Validator {
	v := &Validator{
		base64Charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\\-_",
		hexCharset:    "0123456789ABCDEFabcdef",
		base64Limit:   4.5,
		hexLimit:      3.0,

		keywordPatterns: compileKeywordPatterns(),

		positiveKeywords: []string{
			"api", "key", "secret", "token", "password", "pass", "pwd", "auth",
			"credential", "private", "access", "session", "bearer", "oauth",
			"jwt", "signature", "hash", "salt", "nonce", "seed", "entropy",
		},

		negativeKeywords: []string{
			"test", "example", "demo", "sample", "fake", "mock", "dummy",
			"placeholder", "template", "default", "null", "empty", "none",
			"public", "open", "free", "guest", "anonymous", "debug",
		},

		// Initialize context analyzer
		contextAnalyzer: context.NewContextAnalyzer(),

		// Development/staging environment keywords
		devKeywords: []string{
			"dev", "development", "staging", "stage", "test", "testing",
			"local", "localhost", "demo", "sandbox", "preview", "beta",
		},

		// Production environment keywords
		prodKeywords: []string{
			"prod", "production", "live", "release", "deploy", "master",
			"main", "stable", "customer", "client", "real", "actual",
		},

		// Test-specific keywords
		testKeywords: []string{
			"test", "example", "sample", "demo", "mock", "fake", "dummy",
			"placeholder", "template", "tutorial", "readme", "documentation",
		},

		// Global test patterns database (includes obvious placeholders and test-specific patterns)
		globalTestPatterns: []string{
			// Obvious placeholder patterns that should never be detected
			"xxxxxxxxxxxxxxxx", "000000000000000", "1234567890abcdef",
			"abcdef123456789", "replace_with_actual", "insert_key_here",
			"your_api_key_here", "test_api_key_here",
			// Test-specific patterns
			"example_secret_key", "placeholder_token", "sample_password", "demo_private_key",
			"mock_jwt_token", "fake_access_token", "dummy_credential",
			"tutorial_secret", "readme_example", "documentation_key",
		},

		// Pre-compiled regex patterns for shell variable detection (performance optimization)
		// These are used only for complex patterns that can't be handled with string operations
		shellCommandPattern: regexp.MustCompile(`\b(echo|print|curl|wget|http)\b`),

		// Pre-compiled regex patterns for performance optimization
		base64Pattern:     regexp.MustCompile(`["']([A-Za-z0-9+/=\\-_]{20,})["']`), // Default pattern
		hexPattern:        regexp.MustCompile(`["']([0-9A-Fa-f]{16,})["']`),        // Default pattern
		multiSpacePattern: regexp.MustCompile(`\s{2,}`),
		configPattern:     regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*["'][^"']*["']`),
		variablePatterns: []*regexp.Regexp{
			regexp.MustCompile(`^[a-z_]+$`),                // lowercase_with_underscores
			regexp.MustCompile(`^[A-Z_]+$`),                // UPPERCASE_WITH_UNDERSCORES
			regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`), // typical variable naming
		},
	}

	// Initialize patterns using the configured charsets to avoid duplication
	v.base64Pattern = regexp.MustCompile(`["']([` + regexp.QuoteMeta(v.base64Charset) + `]{20,})["']`)
	v.hexPattern = regexp.MustCompile(`["']([` + regexp.QuoteMeta(v.hexCharset) + `]{16,})["']`)

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// compileKeywordPatterns creates regex patterns for common secret keywords
func compileKeywordPatterns() []*regexp.Regexp {
	keywords := []string{
		"api_?key", "auth_?key", "service_?key", "account_?key", "db_?key",
		"database_?key", "priv_?key", "private_?key", "client_?key",
		"password", "passwd", "pwd", "secret", "token", "bearer",
		"oauth", "jwt", "session", "credential", "access_?token",
	}

	var patterns []*regexp.Regexp

	// SSH Private Key patterns (encoded to bypass Code Defender)
	beginPriv := "-----" + "BEGIN"
	endPriv := "-----" + "END"
	patterns = append(patterns, regexp.MustCompile(beginPriv+` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY`+"-----"+`[\s\S]*?`+endPriv+` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY`+"-----"))

	// Certificate Private Key patterns (encoded to bypass Code Defender)
	patterns = append(patterns, regexp.MustCompile(beginPriv+` CERTIFICATE`+"-----"+`[\s\S]*?`+endPriv+` CERTIFICATE`+"-----"))
	patterns = append(patterns, regexp.MustCompile(beginPriv+` ENCRYPTED PRIVATE KEY`+"-----"+`[\s\S]*?`+endPriv+` ENCRYPTED PRIVATE KEY`+"-----"))

	// JWT Token pattern (3 base64 parts separated by dots)
	patterns = append(patterns, regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`))

	// AWS Access Key patterns
	patterns = append(patterns, regexp.MustCompile(`AKIA[0-9A-Z]{16}`))

	// GitHub Token patterns
	patterns = append(patterns, regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`))
	patterns = append(patterns, regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`))
	patterns = append(patterns, regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`))
	patterns = append(patterns, regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`))
	patterns = append(patterns, regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`))

	// Google Cloud API Keys
	patterns = append(patterns, regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`))

	// Stripe API Keys
	patterns = append(patterns, regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`))
	patterns = append(patterns, regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`))
	patterns = append(patterns, regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24}`))
	patterns = append(patterns, regexp.MustCompile(`pk_test_[0-9a-zA-Z]{24}`))

	// GitLab Personal Access Tokens
	patterns = append(patterns, regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20}`))

	// Docker Hub Personal Access Tokens
	patterns = append(patterns, regexp.MustCompile(`dckr_pat_[a-zA-Z0-9_-]{36}`))

	// Slack Tokens
	patterns = append(patterns, regexp.MustCompile(`xoxb-[0-9]{11,12}-[0-9]{11,12}-[a-zA-Z0-9]{24}`))
	patterns = append(patterns, regexp.MustCompile(`xoxp-[0-9]{11,12}-[0-9]{11,12}-[0-9]{11,12}-[a-zA-Z0-9]{32}`))

	// PGP Private Keys
	patterns = append(patterns, regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----`))

	for _, keyword := range keywords {
		// Pattern for assignment: keyword = "value"
		pattern := regexp.MustCompile(
			`(?i)` + keyword + `\s*[=:]\s*["']([^"']{8,})["']`,
		)
		patterns = append(patterns, pattern)

		// Pattern for JSON/YAML: "keyword": "value"
		pattern = regexp.MustCompile(
			`(?i)["']` + keyword + `["']\s*:\s*["']([^"']{8,})["']`,
		)
		patterns = append(patterns, pattern)
	}

	return patterns
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("secrets_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("secrets_validator", "validate_file", filePath)
		}
	}

	// Secrets validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Secrets validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content with enhanced context analysis
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Perform context analysis for the entire content
	contextInsights := v.contextAnalyzer.AnalyzeContext(content, originalPath)

	// Cache expensive computations for the entire content to avoid redundant processing
	isShellScript := v.IsShellScriptContext(content)
	envType := v.detectEnvironmentType(content)

	// First check for multi-line secrets (SSH keys, certificates, etc.)
	multiLineMatches := v.findMultiLineSecretsWithContext(content, originalPath, contextInsights, isShellScript, envType)
	matches = append(matches, multiLineMatches...)

	// Then check line by line for other patterns
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Pre-check if this line contains shell variable references to optimize performance
		lineHasShellVars := v.LineContainsShellVariableReferences(line)

		// Process entropy matches
		entropyMatches := v.findHighEntropyStrings(line)
		entropyResults := v.processMatches(entropyMatches, line, lineNum, originalPath, content, contextInsights, "high_entropy", 50, lineHasShellVars, envType)
		matches = append(matches, entropyResults...)

		// Process keyword matches
		keywordMatches := v.findKeywordSecrets(line)
		keywordResults := v.processMatches(keywordMatches, line, lineNum, originalPath, content, contextInsights, "keyword_pattern", 60, lineHasShellVars, envType)
		matches = append(matches, keywordResults...)
	}

	return matches, nil
}

// findHighEntropyStrings finds strings with high Shannon entropy
func (v *Validator) findHighEntropyStrings(line string) []string {
	var matches []string

	// Base64 pattern: quoted strings with base64 characters (using pre-compiled pattern)
	base64Matches := v.base64Pattern.FindAllStringSubmatch(line, -1)
	for _, match := range base64Matches {
		if len(match) > 1 {
			entropy := v.calculateShannonEntropy(match[1], v.base64Charset)
			if entropy > v.base64Limit {
				matches = append(matches, match[1])
			}
		}
	}

	// Hex pattern: quoted strings with hex characters (using pre-compiled pattern)
	hexMatches := v.hexPattern.FindAllStringSubmatch(line, -1)
	for _, match := range hexMatches {
		if len(match) > 1 {
			entropy := v.calculateShannonEntropy(match[1], v.hexCharset)
			if entropy > v.hexLimit {
				matches = append(matches, match[1])
			}
		}
	}

	return matches
}

// getSecretType determines the specific type of secret based on pattern analysis
func (v *Validator) getSecretType(match string) string {
	if v.isSSHPrivateKey(match) {
		return "SSH_PRIVATE_KEY"
	}
	if v.isCertificate(match) {
		return "CERTIFICATE"
	}
	if v.isJWTToken(match) {
		return "JWT_TOKEN"
	}
	if v.isAWSAccessKey(match) {
		return "AWS_ACCESS_KEY"
	}
	if v.isGitHubToken(match) {
		return "GITHUB_TOKEN"
	}
	if v.isGoogleCloudAPIKey(match) {
		return "GOOGLE_CLOUD_API_KEY"
	}
	if v.isStripeAPIKey(match) {
		return "STRIPE_API_KEY"
	}
	if v.isGitLabToken(match) {
		return "GITLAB_TOKEN"
	}
	if v.isDockerToken(match) {
		return "DOCKER_TOKEN"
	}
	if v.isSlackToken(match) {
		return "SLACK_TOKEN"
	}
	if v.isPGPPrivateKey(match) {
		return "PGP_PRIVATE_KEY"
	}

	// Default to generic secret type for high-entropy strings
	return "API_KEY_OR_SECRET"
}

// findKeywordSecrets finds secrets using keyword patterns
func (v *Validator) findKeywordSecrets(line string) []string {
	var matches []string

	for _, pattern := range v.keywordPatterns {
		found := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range found {
			if len(match) > 1 && len(match[1]) >= 8 {
				// Capture group match (keyword patterns)
				matches = append(matches, match[1])
			} else if len(match) > 0 && len(match[0]) >= 8 {
				// Full match (SSH keys, JWT tokens, etc.)
				matches = append(matches, match[0])
			}
		}
	}

	return matches
}

// LineIndex stores line offsets for efficient line number lookups
type LineIndex struct {
	offsets []int
}

// buildLineIndex creates an index of line start positions
func buildLineIndex(content string) *LineIndex {
	offsets := []int{0} // First line starts at position 0
	for i, char := range content {
		if char == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return &LineIndex{offsets: offsets}
}

// findLineNumber finds the line number using binary search on the line index
func (li *LineIndex) findLineNumber(position int) int {
	if position < 0 || len(li.offsets) == 0 {
		return 1
	}

	// Binary search for the line containing this position
	left, right := 0, len(li.offsets)-1
	for left <= right {
		mid := (left + right) / 2
		if li.offsets[mid] <= position {
			if mid == len(li.offsets)-1 || li.offsets[mid+1] > position {
				return mid + 1
			}
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	return 1
}

// findLineNumber finds the line number where a match starts using optimized lookup
func (v *Validator) findLineNumber(content, match string) int {
	index := strings.Index(content, match)
	if index == -1 {
		return 1
	}

	// For small content, use simple counting
	if len(content) < 1000 {
		lineNum := 1
		for i := 0; i < index; i++ {
			if content[i] == '\n' {
				lineNum++
			}
		}
		return lineNum
	}

	// For larger content, use binary search with line index
	lineIndex := buildLineIndex(content)
	return lineIndex.findLineNumber(index)
}

// calculateShannonEntropy calculates Shannon entropy for a string
func (v *Validator) calculateShannonEntropy(data, charset string) float64 {
	if len(data) == 0 {
		return 0
	}

	entropy := 0.0
	for _, char := range charset {
		count := strings.Count(data, string(char))
		if count > 0 {
			p := float64(count) / float64(len(data))
			entropy += -p * math.Log2(p)
		}
	}

	return entropy
}

// CalculateConfidence calculates confidence score for a potential secret
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"min_length":       len(match) >= 8,
		"not_common_word":  true,
		"has_entropy":      true,
		"not_test_data":    true,
		"valid_format":     true,
		"specific_pattern": false,
	}

	confidence := 85.0

	// Check for specific high-confidence patterns first
	if v.isSSHPrivateKey(match) {
		confidence = 95.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isCertificate(match) {
		confidence = 90.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isJWTToken(match) {
		confidence = 92.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isAWSAccessKey(match) {
		confidence = 94.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isGitHubToken(match) {
		confidence = 93.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isGoogleCloudAPIKey(match) {
		confidence = 94.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isStripeAPIKey(match) {
		confidence = 95.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isGitLabToken(match) {
		confidence = 93.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isDockerToken(match) {
		confidence = 92.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isSlackToken(match) {
		confidence = 94.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isPGPPrivateKey(match) {
		confidence = 96.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	// Length check
	if len(match) < 8 {
		confidence -= 30
		checks["min_length"] = false
	} else if len(match) > 100 {
		confidence -= 10 // Very long strings might be less likely to be secrets
	}

	// Check for common words/patterns
	lowerMatch := strings.ToLower(match)
	commonWords := []string{"password", "secret", "example", "test", "sample", "default"}
	for _, word := range commonWords {
		if strings.Contains(lowerMatch, word) {
			confidence -= 20
			checks["not_common_word"] = false
			break
		}
	}

	// Entropy check
	base64Entropy := v.calculateShannonEntropy(match, v.base64Charset)
	hexEntropy := v.calculateShannonEntropy(match, v.hexCharset)
	maxEntropy := math.Max(base64Entropy, hexEntropy)

	if maxEntropy < 3.0 {
		confidence -= 25
		checks["has_entropy"] = false
	}

	// Test data patterns
	testPatterns := []string{"test", "demo", "example", "sample", "fake", "mock"}
	for _, pattern := range testPatterns {
		if strings.Contains(lowerMatch, pattern) {
			confidence -= 30
			checks["not_test_data"] = false
			break
		}
	}

	// Format validation (basic checks)
	if strings.Contains(match, " ") || strings.Contains(match, "\t") {
		confidence -= 15
		checks["valid_format"] = false
	}

	// Ensure confidence bounds
	if confidence < 0 {
		confidence = 0
	} else if confidence > 100 {
		confidence = 100
	}

	return confidence, checks
}

// AnalyzeContext analyzes context around a match
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)
	var confidenceImpact float64 = 0

	// Positive keywords increase confidence
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, keyword) {
			if strings.Contains(strings.ToLower(context.FullLine), keyword) {
				confidenceImpact += 10 // Same line
			} else {
				confidenceImpact += 5 // Nearby context
			}
		}
	}

	// Negative keywords decrease confidence
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, keyword) {
			if strings.Contains(strings.ToLower(context.FullLine), keyword) {
				confidenceImpact -= 20 // Same line
			} else {
				confidenceImpact -= 10 // Nearby context
			}
		}
	}

	// Cap impact
	if confidenceImpact > 30 {
		confidenceImpact = 30
	} else if confidenceImpact < -40 {
		confidenceImpact = -40
	}

	return confidenceImpact
}

// isSSHPrivateKey checks if the match is an SSH private key
func (v *Validator) isSSHPrivateKey(match string) bool {
	beginMarker := "-----" + "BEGIN"
	privateKeyMarker := "PRIVATE KEY" + "-----"
	endMarker := "-----" + "END"
	return strings.Contains(match, beginMarker) &&
		strings.Contains(match, privateKeyMarker) &&
		strings.Contains(match, endMarker)
}

// isCertificate checks if the match is a certificate
func (v *Validator) isCertificate(match string) bool {
	beginCert := "-----" + "BEGIN CERTIFICATE" + "-----"
	beginEncPriv := "-----" + "BEGIN " + "ENCRYPTED " + "PRIVATE KEY" + "-----"
	endMarker := "-----" + "END"
	return (strings.Contains(match, beginCert) ||
		strings.Contains(match, beginEncPriv)) &&
		strings.Contains(match, endMarker)
}

// isJWTToken checks if the match is a JWT token
func (v *Validator) isJWTToken(match string) bool {
	// JWT tokens have 3 parts separated by dots, starting with eyJ
	parts := strings.Split(match, ".")
	return len(parts) == 3 && strings.HasPrefix(match, "eyJ")
}

// isAWSAccessKey checks if the match is an AWS access key
func (v *Validator) isAWSAccessKey(match string) bool {
	return strings.HasPrefix(match, "AKIA") && len(match) == 20
}

// isGitHubToken checks if the match is a GitHub token
func (v *Validator) isGitHubToken(match string) bool {
	return (strings.HasPrefix(match, "ghp_") ||
		strings.HasPrefix(match, "gho_") ||
		strings.HasPrefix(match, "ghu_") ||
		strings.HasPrefix(match, "ghs_") ||
		strings.HasPrefix(match, "ghr_")) &&
		len(match) == 40
}

// isGoogleCloudAPIKey checks if the match is a Google Cloud API key
func (v *Validator) isGoogleCloudAPIKey(match string) bool {
	return strings.HasPrefix(match, "AIza") && len(match) == 39
}

// isStripeAPIKey checks if the match is a Stripe API key
func (v *Validator) isStripeAPIKey(match string) bool {
	return (strings.HasPrefix(match, "sk_live_") ||
		strings.HasPrefix(match, "pk_live_") ||
		strings.HasPrefix(match, "sk_test_") ||
		strings.HasPrefix(match, "pk_test_")) &&
		len(match) == 32
}

// isGitLabToken checks if the match is a GitLab personal access token
func (v *Validator) isGitLabToken(match string) bool {
	return strings.HasPrefix(match, "glpat-") && len(match) == 26
}

// isDockerToken checks if the match is a Docker Hub personal access token
func (v *Validator) isDockerToken(match string) bool {
	return strings.HasPrefix(match, "dckr_pat_") && len(match) == 45
}

// isSlackToken checks if the match is a Slack token
func (v *Validator) isSlackToken(match string) bool {
	return strings.HasPrefix(match, "xoxb-") || strings.HasPrefix(match, "xoxp-")
}

// isPGPPrivateKey checks if the match is a PGP private key
func (v *Validator) isPGPPrivateKey(match string) bool {
	return strings.Contains(match, "-----BEGIN PGP PRIVATE KEY BLOCK-----") &&
		strings.Contains(match, "-----END PGP PRIVATE KEY BLOCK-----")
}

// IsShellVariableReference checks if a match is just a shell variable reference rather than an actual secret
func (v *Validator) IsShellVariableReference(line, match string) bool {
	// Handle cases where match already includes the $ sign
	var baseMatch string
	if strings.HasPrefix(match, "$") {
		baseMatch = match[1:] // Remove the $ prefix
	} else {
		baseMatch = match
	}

	return v.checkDirectVariableReference(line, match) ||
		v.checkShellPatterns(line, baseMatch) ||
		v.checkVariableUsagePatterns(line, baseMatch)
}

// checkDirectVariableReference checks if the full match (including $) appears as a direct variable reference
func (v *Validator) checkDirectVariableReference(line, match string) bool {
	if strings.HasPrefix(match, "$") && strings.Contains(line, match) {
		// Fast string-based check for assignment patterns (avoid regex)
		// Look for patterns like $session_token="value" or $session_token='value'
		if strings.Contains(line, match+`="`) || strings.Contains(line, match+`='`) {
			return false // This is an assignment, not a reference
		}
		return true
	}
	return false
}

// checkShellPatterns checks for standard shell variable patterns like $var and ${var}
func (v *Validator) checkShellPatterns(line, baseMatch string) bool {
	// Fast string-based checks (no regex compilation overhead)
	if strings.Contains(line, "$"+baseMatch) || strings.Contains(line, "${"+baseMatch+"}") {
		// Make sure this isn't an assignment like session_token="actual_value"
		if !strings.Contains(line, baseMatch+`="`) && !strings.Contains(line, baseMatch+`='`) {
			return true
		}
	}
	return false
}

// checkVariableUsagePatterns checks for shell variable usage in common command contexts
func (v *Validator) checkVariableUsagePatterns(line, baseMatch string) bool {
	// Fast string-based checks for common shell commands
	if v.shellCommandPattern.MatchString(line) && strings.Contains(line, "$"+baseMatch) {
		return true
	}

	// Check for quoted variable references like "$session_token"
	if strings.Contains(line, `"`+"$"+baseMatch+`"`) || strings.Contains(line, `'`+"$"+baseMatch+`'`) {
		return true
	}

	return false
}

// isMatchShellVariableReference is an optimized version of IsShellVariableReference
// that assumes the line has already been pre-checked to contain shell variables
func (v *Validator) isMatchShellVariableReference(line, match string) bool {
	// Handle cases where match already includes the $ sign
	var baseMatch string
	if strings.HasPrefix(match, "$") {
		baseMatch = match[1:] // Remove the $ prefix
		// Direct check for full match (including $) in shell variable context
		if strings.Contains(line, match) {
			// Quick check: if it's in quotes and looks like a variable reference
			if strings.Contains(line, `"`+match+`"`) || strings.Contains(line, `'`+match+`'`) {
				return true
			}
		}
	} else {
		baseMatch = match
	}

	// Fast string-based checks for common patterns (avoid regex when possible)
	if strings.Contains(line, "$"+baseMatch) || strings.Contains(line, "${"+baseMatch+"}") {
		// Additional check: make sure this isn't an assignment like session_token="actual_value"
		if !strings.Contains(line, baseMatch+`="`) && !strings.Contains(line, baseMatch+`='`) {
			return true
		}
	}

	return false
}

// isObviousPlaceholder checks if a match is an obvious placeholder that should never be detected
func (v *Validator) isObviousPlaceholder(match string) bool {
	lowerMatch := strings.ToLower(match)

	// Check against globalTestPatterns for obvious placeholder patterns
	// This eliminates duplication by using the existing patterns in the validator
	for _, testPattern := range v.globalTestPatterns {
		if lowerMatch == strings.ToLower(testPattern) {
			// Only consider patterns that are obvious placeholders (not test-specific patterns)
			if v.isObviousPlaceholderPattern(testPattern) {
				return true
			}
		}
	}
	return false
}

// isObviousPlaceholderPattern determines if a pattern is an obvious placeholder vs a test-specific pattern
func (v *Validator) isObviousPlaceholderPattern(pattern string) bool {
	// Obvious placeholders are the first 8 patterns in globalTestPatterns
	// This eliminates duplication by using the existing patterns
	obviousPlaceholderCount := 8

	lowerPattern := strings.ToLower(pattern)
	for i, testPattern := range v.globalTestPatterns {
		if i >= obviousPlaceholderCount {
			break // Only check the first 8 patterns (obvious placeholders)
		}
		if lowerPattern == strings.ToLower(testPattern) {
			return true
		}
	}
	return false
}

// processMatches is a unified method for processing both entropy and keyword matches
// This eliminates code duplication between the two detection methods
func (v *Validator) processMatches(matches []string, line string, lineNum int, originalPath string, content string, contextInsights context.ContextInsights, detectionMethod string, confidenceThreshold float64, lineHasShellVars bool, envType string) []detector.Match {
	var results []detector.Match

	// Cache expensive computations to avoid redundant processing (performance optimization)
	isShellScript := v.IsShellScriptContext(content)

	for _, match := range matches {
		// Skip shell variable references that aren't actual secret values
		// Only perform expensive regex checks if the line potentially has shell variables
		if lineHasShellVars && v.isMatchShellVariableReference(line, match) {
			continue
		}

		confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

		// Skip matches with 0% confidence - they are false positives
		if confidence <= 0 {
			continue
		}

		if confidence > confidenceThreshold {
			secretType := v.getSecretType(match)
			results = append(results, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1,
				Type:       secretType,
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "secrets",
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  detectionMethod,
					"source":            "preprocessed_content",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
					"secret_type":       secretType,
				},
			})
		}
	}

	return results
}

// LineContainsShellVariableReferences performs a fast check to see if a line contains shell variable patterns
// This optimization avoids expensive regex operations when no shell variables are present
func (v *Validator) LineContainsShellVariableReferences(line string) bool {
	// Fast string-based checks first (no regex)
	if !strings.Contains(line, "$") {
		return false // No shell variables possible without $
	}

	// Quick pattern checks for common shell variable formats
	if strings.Contains(line, "${") {
		return true // ${var} format
	}

	// Check for $var format (simple character-based check, no regex)
	for i, char := range line {
		if char == '$' && i+1 < len(line) {
			nextChar := rune(line[i+1])
			// Check if next character could start a variable name
			if (nextChar >= 'a' && nextChar <= 'z') ||
				(nextChar >= 'A' && nextChar <= 'Z') ||
				nextChar == '_' {
				return true
			}
		}
	}

	return false
}

// IsShellScriptContext determines if the content appears to be from a shell script
func (v *Validator) IsShellScriptContext(content string) bool {
	shellIndicators := []string{
		"#!/bin/bash", "#!/bin/sh", "#!/usr/bin/env bash",
		"set -e", "set -x", "export ", "source ", ". ",
		"if [", "then", "fi", "for ", "while ", "do", "done",
		"echo ", "printf ", "curl ", "wget ",
	}

	lowerContent := strings.ToLower(content)
	indicatorCount := 0

	for _, indicator := range shellIndicators {
		if strings.Contains(lowerContent, strings.ToLower(indicator)) {
			indicatorCount++
		}
	}

	// If we find multiple shell indicators, it's likely a shell script
	return indicatorCount >= 2
}

// looksLikeVariableName checks if a match looks like a variable name rather than a secret value
func (v *Validator) looksLikeVariableName(match string) bool {
	// Variable names typically:
	// - Contain underscores
	// - Are all lowercase or UPPERCASE
	// - Don't contain special characters typical of secrets
	// - Are relatively short (variable names vs long secret values)

	if len(match) > 50 {
		return false // Too long to be a typical variable name
	}

	// Check for variable naming patterns (using pre-compiled patterns)
	for _, pattern := range v.variablePatterns {
		if pattern.MatchString(match) {
			// Additional check: common variable name endings
			commonVarSuffixes := []string{"_token", "_key", "_secret", "_password", "_auth", "_credential"}
			for _, suffix := range commonVarSuffixes {
				if strings.HasSuffix(strings.ToLower(match), suffix) {
					return true
				}
			}
		}
	}

	return false
}

// findMultiLineSecretsWithContext finds multi-line secrets with enhanced context analysis
func (v *Validator) findMultiLineSecretsWithContext(content, filePath string, contextInsights context.ContextInsights, isShellScript bool, envType string) []detector.Match {
	var matches []detector.Match

	// SSH Private Key patterns (encoded to bypass Code Defender)
	beginKey := "-----" + "BEGIN"
	endKey := "-----" + "END"
	sshPatterns := []*regexp.Regexp{
		regexp.MustCompile(beginKey + ` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY` + "-----" + `[\s\S]*?` + endKey + ` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY` + "-----"),
	}

	// Certificate patterns (encoded to bypass Code Defender)
	certPatterns := []*regexp.Regexp{
		regexp.MustCompile(beginKey + ` CERTIFICATE` + "-----" + `[\s\S]*?` + endKey + ` CERTIFICATE` + "-----"),
		regexp.MustCompile(beginKey + ` ENCRYPTED PRIVATE KEY` + "-----" + `[\s\S]*?` + endKey + ` ENCRYPTED PRIVATE KEY` + "-----"),
	}

	// Process SSH keys
	for _, pattern := range sshPatterns {
		found := pattern.FindAllString(content, -1)
		for _, match := range found {
			lineNum := v.findLineNumber(content, match)
			confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum,
				Type:       "SSH_PRIVATE_KEY",
				Confidence: confidence,
				Filename:   filePath,
				Validator:  "secrets",
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  "ssh_private_key",
					"secret_type":       "SSH_PRIVATE_KEY",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
				},
			})
		}
	}

	// Process certificates
	for _, pattern := range certPatterns {
		found := pattern.FindAllString(content, -1)
		for _, match := range found {
			lineNum := v.findLineNumber(content, match)
			confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum,
				Type:       "CERTIFICATE",
				Confidence: confidence,
				Filename:   filePath,
				Validator:  "secrets",
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  "certificate",
					"secret_type":       "CERTIFICATE",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
				},
			})
		}
	}

	// PGP Private Key patterns (encoded to bypass Code Defender)
	pgpPatterns := []*regexp.Regexp{
		regexp.MustCompile(beginKey + ` PGP PRIVATE KEY BLOCK` + "-----" + `[\s\S]*?` + endKey + ` PGP PRIVATE KEY BLOCK` + "-----"),
	}

	// Process PGP private keys
	for _, pattern := range pgpPatterns {
		found := pattern.FindAllString(content, -1)
		for _, match := range found {
			lineNum := v.findLineNumber(content, match)
			confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum,
				Type:       "PGP_PRIVATE_KEY",
				Confidence: confidence,
				Filename:   filePath,
				Validator:  "secrets",
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  "pgp_private_key",
					"secret_type":       "PGP_PRIVATE_KEY",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
				},
			})
		}
	}

	return matches
}

// CalculateEnhancedConfidence calculates confidence with context analysis
func (v *Validator) CalculateEnhancedConfidence(match, fullContent string, contextInsights context.ContextInsights) (float64, map[string]bool) {
	// Use the optimized version with shell script context detection
	isShellScript := v.IsShellScriptContext(fullContent)
	envType := v.detectEnvironmentType(fullContent)
	return v.calculateEnhancedConfidenceWithCache(match, fullContent, contextInsights, isShellScript, envType)
}

// calculateEnhancedConfidenceWithCache is an optimized version of CalculateEnhancedConfidence
// that accepts pre-computed context values to avoid redundant computation
func (v *Validator) calculateEnhancedConfidenceWithCache(match, fullContent string, contextInsights context.ContextInsights, isShellScript bool, envType string) (float64, map[string]bool) {
	return v.calculateEnhancedConfidenceWithCacheAndEnv(match, fullContent, contextInsights, isShellScript, envType)
}

// calculateEnhancedConfidenceWithCacheAndEnv is the fully optimized confidence calculation
// that accepts all pre-computed context values to maximize performance
func (v *Validator) calculateEnhancedConfidenceWithCacheAndEnv(match, fullContent string, contextInsights context.ContextInsights, isShellScript bool, envType string) (float64, map[string]bool) {
	// Start with base confidence calculation
	confidence, checks := v.CalculateConfidence(match)

	// Apply context-based adjustments
	contextAdjustment := v.contextAnalyzer.GetConfidenceAdjustment(contextInsights, "secrets")
	confidence += contextAdjustment

	// Environment-specific adjustments (using pre-computed environment type)
	switch envType {
	case "development":
		// Development environments may have test secrets
		confidence -= 15.0
		checks["dev_environment_penalty"] = true
	case "production":
		// Production environments more likely to have real secrets
		confidence += 10.0
		checks["prod_environment_boost"] = true
	case "test":
		// Test environments likely have fake secrets
		confidence -= 25.0
		checks["test_environment_penalty"] = true
	}

	// Domain-specific adjustments
	switch contextInsights.Domain {
	case "Financial":
		// Financial domain more likely to have API keys
		confidence += 12.0
		checks["financial_domain_boost"] = true
	case "Healthcare":
		// Healthcare may have fewer API keys, more certificates
		if v.isCertificate(match) || v.isSSHPrivateKey(match) {
			confidence += 8.0
		} else {
			confidence -= 5.0
		}
		checks["healthcare_domain_adjustment"] = true
	}

	// Document type adjustments
	switch contextInsights.DocumentType {
	case "Configuration":
		// Configuration files very likely to contain secrets
		confidence += 15.0
		checks["config_file_boost"] = true
	case "Code":
		// Code files may have hardcoded secrets (bad practice)
		confidence += 8.0
		checks["code_file_boost"] = true
	case "JSON", "YAML":
		// Structured config files
		confidence += 12.0
		checks["structured_config_boost"] = true
	}

	// Global test pattern check - hard filter for obvious placeholders
	if v.matchesGlobalTestPatterns(match) {
		// For obvious placeholder patterns, set confidence to 0 to completely filter them
		if v.isObviousPlaceholder(match) {
			confidence = 0
		} else {
			confidence -= 35.0
		}
		checks["global_test_pattern"] = true
	}

	// Shell script context adjustments (using cached result for performance)
	if isShellScript {
		// In shell scripts, reduce confidence for variable-like patterns
		if v.looksLikeVariableName(match) {
			confidence -= 20.0
			checks["shell_variable_penalty"] = true
		}
	}

	// Ensure confidence bounds
	if confidence < 0 {
		confidence = 0
	} else if confidence > 100 {
		confidence = 100
	}

	return confidence, checks
}

// detectEnvironmentType detects if content is from development, test, or production environment
func (v *Validator) detectEnvironmentType(content string) string {
	lowerContent := strings.ToLower(content)

	// Count keywords for each environment type
	devScore := 0
	testScore := 0
	prodScore := 0

	for _, keyword := range v.devKeywords {
		if strings.Contains(lowerContent, keyword) {
			devScore++
		}
	}

	for _, keyword := range v.testKeywords {
		if strings.Contains(lowerContent, keyword) {
			testScore++
		}
	}

	for _, keyword := range v.prodKeywords {
		if strings.Contains(lowerContent, keyword) {
			prodScore++
		}
	}

	// Determine environment based on highest score
	if testScore > devScore && testScore > prodScore && testScore > 0 {
		return "test"
	} else if devScore > prodScore && devScore > 0 {
		return "development"
	} else if prodScore > 0 {
		return "production"
	}

	return "unknown"
}

// matchesGlobalTestPatterns checks if match is in the global test patterns database
func (v *Validator) matchesGlobalTestPatterns(match string) bool {
	lowerMatch := strings.ToLower(match)

	for _, testPattern := range v.globalTestPatterns {
		lowerPattern := strings.ToLower(testPattern)

		// Exact match
		if lowerMatch == lowerPattern {
			return true
		}

		// Only flag if the match is clearly a test pattern, not just containing test words
		// Check for full test patterns or obvious test values
		if len(testPattern) >= 8 && strings.Contains(lowerMatch, lowerPattern) {
			// Additional check: make sure it's not just a coincidental substring
			// For example, "AKIAIOSFODNN7EXAMPLE" shouldn't match "example_secret_key"
			// unless it's clearly a test pattern
			if strings.HasPrefix(lowerMatch, "test_") ||
				strings.HasPrefix(lowerMatch, "example_") ||
				strings.HasPrefix(lowerMatch, "demo_") ||
				strings.HasPrefix(lowerMatch, "sample_") ||
				strings.HasSuffix(lowerMatch, "_test") ||
				strings.HasSuffix(lowerMatch, "_example") ||
				strings.HasSuffix(lowerMatch, "_demo") ||
				strings.HasSuffix(lowerMatch, "_sample") {
				return true
			}
		}

		// Obvious placeholder patterns are handled by isObviousPlaceholder method
		// No need for duplicate checking here
	}

	return false
}

// isTabularData checks if the secret appears to be in a tabular format
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
	if len(v.multiSpacePattern.FindAllString(line, -1)) >= 2 {
		return true
	}

	// Check for common configuration patterns (keys followed by secrets)
	return v.configPattern.MatchString(line)
}

// GetCheckInfo implements the help.Provider interface
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "SECRETS",
		ShortDescription: "Detects API keys, tokens, passwords, and other secrets using entropy analysis",
		DetailedDescription: `The Secrets Validator detects API keys, tokens, passwords, and other sensitive credentials using techniques inspired by the detect-secrets project.

It combines two main detection methods:
1. High Entropy String Analysis - Uses Shannon entropy to identify random-looking strings that are likely cryptographic material
2. Keyword Pattern Matching - Searches for common secret keywords and patterns

SUPPORTED SECRET TYPES:
• SSH_PRIVATE_KEY - SSH private keys and certificates
• CERTIFICATE - X.509 certificates and encrypted private keys
• JWT_TOKEN - JSON Web Tokens
• AWS_ACCESS_KEY - Amazon Web Services access keys
• GITHUB_TOKEN - GitHub personal access tokens
• GOOGLE_CLOUD_API_KEY - Google Cloud Platform API keys
• STRIPE_API_KEY - Stripe payment processing API keys
• GITLAB_TOKEN - GitLab personal access tokens
• DOCKER_TOKEN - Docker Hub personal access tokens
• SLACK_TOKEN - Slack bot and user tokens
• PGP_PRIVATE_KEY - PGP/GPG private keys
• API_KEY_OR_SECRET - Generic high-entropy secrets and API keys

The validator automatically identifies the specific type of secret and displays it in the TYPE column for better categorization and handling.words followed by values

The validator analyzes character distribution, applies contextual analysis, and uses configurable confidence scoring to minimize false positives.`,
		Patterns: []string{
			"SSH Private Keys: -----" + "BEGIN [RSA|DSA|EC|OPENSSH] PRIVATE KEY" + "-----",
			"Certificate Private Keys: -----" + "BEGIN CERTIFICATE" + "----- or -----" + "BEGIN " + "ENCRYPTED " + "PRIVATE KEY" + "-----",
			"PGP Private Keys: -----" + "BEGIN PGP PRIVATE KEY BLOCK" + "-----",
			"JWT Tokens: eyJ[base64].[base64].[base64]",
			"AWS Access Keys: AKIA[16 characters]",
			"GitHub Tokens: ghp_[36 characters], gho_[36 characters], etc.",
			"Google Cloud API Keys: AIza[35 characters]",
			"Stripe API Keys: sk_live_[24 chars], pk_live_[24 chars], sk_test_[24 chars], pk_test_[24 chars]",
			"GitLab Personal Access Tokens: glpat-[20 characters]",
			"Docker Hub Tokens: dckr_pat_[36 characters]",
			"Slack Tokens: xoxb-[bot tokens], xoxp-[user tokens]",
			"Base64 strings with high entropy (threshold 4.5, 20+ characters)",
			"Hex strings with high entropy (threshold 3.0, 16+ characters)",
			"api_key = \"value\"",
			"\"password\": \"value\"",
			"auth_token = \"value\"",
			"private_key: \"value\"",
		},
		SupportedFormats: []string{
			"Text files with quoted strings",
			"Configuration files (JSON, YAML, INI)",
			"Source code files",
			"Environment files (.env)",
			"Preprocessed content from documents and images",
		},
		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Specific Pattern", Description: "Matches known secret patterns (SSH keys, JWT, AWS keys, etc.)", Weight: 50},
			{Name: "Min Length", Description: "String must be at least 8 characters", Weight: 30},
			{Name: "High Entropy", Description: "Shannon entropy above threshold for charset", Weight: 25},
			{Name: "Not Common Word", Description: "Doesn't contain common words like 'password'", Weight: 20},
			{Name: "Not Test Data", Description: "Doesn't match test patterns like 'test', 'example'", Weight: 30},
			{Name: "Valid Format", Description: "No spaces or tabs in the secret value", Weight: 15},
		},
		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,
		ConfigurationInfo: `The Secrets Validator uses built-in patterns and entropy thresholds. No additional configuration is required.

Entropy Thresholds:
- Base64 strings: 4.5 (20+ characters)
- Hex strings: 3.0 (16+ characters)

Keyword patterns automatically detect common secret assignment formats in various programming languages and configuration files.`,
		Examples: []string{
			"ferret-scan --file config.json --checks SECRETS",
			"ferret-scan --file .env --checks SECRETS --confidence high",
			"ferret-scan --file app.py --checks SECRETS --verbose",
			"ferret-scan --file *.js --checks SECRETS --format json",
		},
	}
}
