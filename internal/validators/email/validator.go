// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"os"
	"regexp"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// Validator implements the detector.Validator interface for detecting
// email addresses using regex patterns and contextual analysis.
type Validator struct {
	pattern string
	regex   *regexp.Regexp

	// Keywords that suggest an email context
	positiveKeywords []string

	// Keywords that suggest this is not a real email
	negativeKeywords []string

	// Known test patterns that indicate test data
	knownTestPatterns []string

	// Common test domains and usernames
	testDomains   []string
	testUsernames []string

	// Common business email patterns
	businessPatterns []string

	// Observability
	observer *observability.StandardObserver
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns, keywords, and validation rules for detecting email addresses.
func NewValidator() *Validator {
	v := &Validator{
		pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
		positiveKeywords: []string{
			"email", "e-mail", "contact", "mailto", "address", "recipient", "sender",
			"from", "to", "cc", "bcc", "reply", "subscribe", "unsubscribe",
			"notification", "alert", "newsletter", "support", "info", "admin",
			"sales", "marketing", "customer", "service", "help", "noreply",
			"donotreply", "bounce", "postmaster", "webmaster",
		},
		negativeKeywords: []string{
			"test", "example", "fake", "mock", "sample", "dummy", "placeholder",
			"demo", "template", "tutorial", "documentation", "readme",
			"lorem", "ipsum", "foo", "bar", "baz", "temp", "temporary",
			"invalid", "nonexistent", "blackhole", "devnull",
		},
		knownTestPatterns: []string{
			"test@", "example@", "user@", "admin@", "noreply@",
			"@test", "@example", "@localhost", "@domain", "@company",
		},
		testDomains: []string{
			"example.com", "example.org", "example.net", "test.com", "test.org",
			"localhost", "domain.com", "company.com", "email.com", "mail.com",
			"foo.com", "bar.com", "baz.com", "temp.com", "dummy.com",
			"sample.com", "demo.com", "placeholder.com", "invalid.com",
		},
		testUsernames: []string{
			"test", "example", "user", "admin", "root", "demo", "sample",
			"dummy", "placeholder", "foo", "bar", "baz", "temp", "invalid",
			"john.doe", "jane.smith", "user123", "testuser", "demouser",
		},
		businessPatterns: []string{
			"firstname.lastname@", "first.last@", "f.lastname@", "flastname@",
			"lastname.firstname@", "last.first@", "l.firstname@", "lfirstname@",
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
		finishTiming = v.observer.StartTiming("email_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("email_validator", "validate_file", filePath)
		}
	}

	// Email validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Email validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for email addresses
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("email_validator", "validate_content", originalPath)
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Use the pre-compiled regex
	re := v.regex

	for lineNum, line := range lines {
		foundMatches := re.FindAllString(line, -1)

		for _, match := range foundMatches {
			// Calculate confidence
			confidence, checks := v.CalculateConfidence(match)

			// Analyze email structure
			emailParts := v.AnalyzeEmailStructure(match)

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

			emailType := v.getEmailProviderType(match)
			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1, // 1-based line numbering
				Type:       emailType,
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "email",
				Context:    contextInfo,
				Metadata: map[string]any{
					"domain":            emailParts["domain"],
					"username":          emailParts["username"],
					"tld":               emailParts["tld"],
					"email_provider":    emailType,
					"validation_checks": checks,
					"context_impact":    contextInfo.ConfidenceImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
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
				confidenceImpact += 8 // +8% for keywords in the same line
			} else {
				confidenceImpact += 4 // +4% for keywords in surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact -= 20 // -20% for negative keywords in the same line
			} else {
				confidenceImpact -= 10 // -10% for negative keywords in surrounding context
			}
		}
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 30 {
		confidenceImpact = 30 // Maximum +30% boost
	} else if confidenceImpact < -60 {
		confidenceImpact = -60 // Maximum -60% reduction
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

// CalculateConfidence calculates the confidence score for a potential email address
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_format":        true,
		"valid_domain":        true,
		"valid_tld":           true,
		"not_test_email":      true,
		"business_pattern":    false,
		"reasonable_length":   true,
		"no_consecutive_dots": true,
		"valid_username":      true,
	}

	confidence := 100.0
	lowerMatch := strings.ToLower(match)

	// Basic format validation (already passed regex, but check edge cases)
	if !v.isValidEmailFormat(match) {
		confidence -= 30
		checks["valid_format"] = false
	}

	// Check domain validity (20%)
	parts := strings.Split(match, "@")
	if len(parts) != 2 {
		confidence -= 20
		checks["valid_domain"] = false
	} else {
		domain := strings.ToLower(parts[1])

		// Check for test domains
		if v.isTestDomain(domain) {
			confidence -= 25
			checks["not_test_email"] = false
		}

		// Check TLD validity (15%)
		if !v.hasValidTLD(domain) {
			confidence -= 15
			checks["valid_tld"] = false
		}
	}

	// Check username validity (15%)
	if len(parts) == 2 {
		username := strings.ToLower(parts[0])

		// Check for test usernames
		if v.isTestUsername(username) {
			confidence -= 20
			checks["not_test_email"] = false
		}

		// Check for business patterns
		if v.matchesBusinessPattern(lowerMatch) {
			checks["business_pattern"] = true
			confidence += 5 // Small boost for business-like emails
		}
	}

	// Check reasonable length (10%)
	if len(match) > 254 || len(match) < 6 {
		confidence -= 10
		checks["reasonable_length"] = false
	}

	// Check for consecutive dots (10%)
	if strings.Contains(match, "..") {
		confidence -= 10
		checks["no_consecutive_dots"] = false
	}

	// Check for known test patterns (15%)
	for _, pattern := range v.knownTestPatterns {
		if strings.Contains(lowerMatch, pattern) {
			confidence -= 15
			checks["not_test_email"] = false
			break
		}
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// AnalyzeEmailStructure breaks down the email into components
func (v *Validator) AnalyzeEmailStructure(email string) map[string]string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return map[string]string{
			"username": email,
			"domain":   "",
			"tld":      "",
		}
	}

	username := parts[0]
	domain := parts[1]

	// Extract TLD
	domainParts := strings.Split(domain, ".")
	tld := ""
	if len(domainParts) > 0 {
		tld = domainParts[len(domainParts)-1]
	}

	return map[string]string{
		"username": username,
		"domain":   domain,
		"tld":      tld,
	}
}

// getEmailProviderType determines the specific email provider type based on domain analysis
func (v *Validator) getEmailProviderType(email string) string {
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return "EMAIL"
	}

	domain := parts[1]

	// Major email providers
	switch domain {
	// Google services
	case "gmail.com", "googlemail.com":
		return "GMAIL"
	case "google.com":
		return "GOOGLE_WORKSPACE"

	// Microsoft services
	case "outlook.com", "hotmail.com", "live.com", "msn.com":
		return "OUTLOOK"
	case "microsoft.com":
		return "MICROSOFT_365"

	// Yahoo services
	case "yahoo.com", "yahoo.co.uk", "yahoo.ca", "yahoo.au", "yahoo.de", "yahoo.fr", "yahoo.it", "yahoo.es", "yahoo.co.jp", "yahoo.co.in":
		return "YAHOO"

	// Apple services
	case "icloud.com", "me.com", "mac.com":
		return "ICLOUD"
	case "apple.com":
		return "APPLE_CORPORATE"

	// Other major providers
	case "aol.com":
		return "AOL"
	case "protonmail.com", "proton.me", "pm.me":
		return "PROTONMAIL"
	case "tutanota.com", "tutanota.de", "tutamail.com", "tuta.io":
		return "TUTANOTA"
	case "fastmail.com", "fastmail.fm":
		return "FASTMAIL"
	case "zoho.com", "zohomail.com":
		return "ZOHO"
	case "yandex.com", "yandex.ru":
		return "YANDEX"
	case "mail.ru", "inbox.ru", "list.ru", "bk.ru":
		return "MAIL_RU"

	// Business/Enterprise providers
	case "salesforce.com":
		return "SALESFORCE"
	case "slack.com":
		return "SLACK"
	case "atlassian.com":
		return "ATLASSIAN"
	case "github.com":
		return "GITHUB"
	case "gitlab.com":
		return "GITLAB"

	// Educational domains
	case "edu", "ac.uk", "edu.au", "edu.ca":
		return "EDUCATIONAL"
	}

	// Check for common educational patterns
	if strings.HasSuffix(domain, ".edu") || strings.HasSuffix(domain, ".ac.uk") ||
		strings.HasSuffix(domain, ".edu.au") || strings.HasSuffix(domain, ".edu.ca") ||
		strings.HasSuffix(domain, ".ac.in") || strings.HasSuffix(domain, ".edu.sg") {
		return "EDUCATIONAL"
	}

	// Check for government domains
	if strings.HasSuffix(domain, ".gov") || strings.HasSuffix(domain, ".gov.uk") ||
		strings.HasSuffix(domain, ".gov.au") || strings.HasSuffix(domain, ".gov.ca") ||
		strings.HasSuffix(domain, ".mil") {
		return "GOVERNMENT"
	}

	// Check for temporary/disposable email services (check this before business check)
	if v.isDisposableEmail(domain) {
		return "DISPOSABLE"
	}

	// Check for common business patterns
	if v.isBusinessDomain(domain) {
		return "BUSINESS"
	}

	// Default to generic email type
	return "EMAIL"
}

// isBusinessDomain checks if the domain appears to be a business domain
func (v *Validator) isBusinessDomain(domain string) bool {
	// Common business indicators
	businessIndicators := []string{
		"corp", "company", "inc", "ltd", "llc", "group", "enterprise",
		"solutions", "services", "consulting", "tech", "software",
		"systems", "digital", "online", "web", "net", "org",
	}

	domainLower := strings.ToLower(domain)

	// Check if domain contains business indicators
	for _, indicator := range businessIndicators {
		if strings.Contains(domainLower, indicator) {
			return true
		}
	}

	// Check for common business TLDs
	businessTLDs := []string{".biz", ".co", ".inc", ".corp", ".company"}
	for _, tld := range businessTLDs {
		if strings.HasSuffix(domainLower, tld) {
			return true
		}
	}

	// If it's not a well-known consumer provider and has a reasonable structure, likely business
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 && len(parts[0]) > 3 && !v.isConsumerProvider(domain) {
		return true
	}

	return false
}

// isConsumerProvider checks if the domain is a known consumer email provider
func (v *Validator) isConsumerProvider(domain string) bool {
	consumerProviders := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
		"icloud.com", "protonmail.com", "tutanota.com", "fastmail.com",
		"zoho.com", "yandex.com", "mail.ru", "live.com", "msn.com",
	}

	domainLower := strings.ToLower(domain)
	for _, provider := range consumerProviders {
		if domainLower == provider {
			return true
		}
	}
	return false
}

// isDisposableEmail checks if the domain is a known disposable/temporary email service
func (v *Validator) isDisposableEmail(domain string) bool {
	disposableProviders := []string{
		"10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.org",
		"temp-mail.org", "throwaway.email", "maildrop.cc", "sharklasers.com",
		"guerrillamailblock.com", "pokemail.net", "spam4.me", "tempail.com",
		"20minutemail.it", "emailondeck.com", "fakeinbox.com", "getnada.com",
		"harakirimail.com", "incognitomail.org", "jetable.org", "mailcatch.com",
		"mailnesia.com", "mytrashmail.com", "no-spam.ws", "nowmymail.com",
		"objectmail.com", "oneoffmail.com", "pookmail.com", "quickinbox.com",
		"rcpt.at", "rtrtr.com", "sendspamhere.com", "tempemail.com",
		"tempinbox.com", "tempmailo.com", "tempmailaddress.com", "trashmail.at",
		"trashmail.com", "trashmail.de", "trashmail.me", "trashmail.net",
		"wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org", "yopmail.com",
	}

	domainLower := strings.ToLower(domain)
	for _, provider := range disposableProviders {
		if domainLower == provider {
			return true
		}
	}
	return false
}

// Helper methods
func (v *Validator) isValidEmailFormat(email string) bool {
	// More strict validation than the initial regex
	if len(email) == 0 || len(email) > 254 {
		return false
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	username := parts[0]
	domain := parts[1]

	// Username checks
	if len(username) == 0 || len(username) > 64 {
		return false
	}

	// Domain checks
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters
	validChars := regexp.MustCompile(`^[A-Za-z0-9._%+-]+$`)
	if !validChars.MatchString(username) {
		return false
	}

	validDomainChars := regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	if !validDomainChars.MatchString(domain) {
		return false
	}

	return true
}

func (v *Validator) isTestDomain(domain string) bool {
	for _, testDomain := range v.testDomains {
		if domain == testDomain {
			return true
		}
	}
	return false
}

func (v *Validator) isTestUsername(username string) bool {
	for _, testUsername := range v.testUsernames {
		if username == testUsername {
			return true
		}
	}
	return false
}

func (v *Validator) hasValidTLD(domain string) bool {
	// Common valid TLDs
	validTLDs := map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true,
		"mil": true, "int": true, "co": true, "uk": true, "ca": true,
		"au": true, "de": true, "fr": true, "jp": true, "cn": true,
		"ru": true, "br": true, "in": true, "it": true, "es": true,
		"mx": true, "nl": true, "se": true, "no": true, "dk": true,
		"fi": true, "pl": true, "be": true, "ch": true, "at": true,
		"ie": true, "nz": true, "sg": true, "hk": true, "kr": true,
		"tw": true, "th": true, "my": true, "ph": true, "id": true,
		"vn": true, "za": true, "eg": true, "ma": true, "ng": true,
		"ke": true, "gh": true, "tz": true, "ug": true, "zm": true,
		"biz": true, "info": true, "name": true, "pro": true, "aero": true,
		"coop": true, "museum": true, "travel": true, "jobs": true, "mobi": true,
		"tel": true, "asia": true, "cat": true, "post": true, "xxx": true,
		"arpa": true, "local": true, "localhost": true, "test": true,
	}

	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false
	}

	tld := strings.ToLower(parts[len(parts)-1])

	// Check against known valid TLDs
	if validTLDs[tld] {
		return true
	}

	// Allow 2-4 character TLDs that we might not have in our list
	if len(tld) >= 2 && len(tld) <= 4 {
		// Basic validation - only letters
		validTLD := regexp.MustCompile(`^[a-z]+$`)
		return validTLD.MatchString(tld)
	}

	return false
}

func (v *Validator) matchesBusinessPattern(email string) bool {
	lowerEmail := strings.ToLower(email)

	for _, pattern := range v.businessPatterns {
		if strings.Contains(lowerEmail, pattern) {
			return true
		}
	}

	// Check for firstname.lastname pattern
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		username := parts[0]
		if strings.Contains(username, ".") && !strings.HasPrefix(username, ".") && !strings.HasSuffix(username, ".") {
			return true
		}
	}

	return false
}

// isTabularData checks if the email appears to be in a tabular format
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

	// Check for common email list patterns (names followed by emails)
	nameEmailPattern := regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Za-z0-9._%+-]+@`)
	if nameEmailPattern.MatchString(line) {
		return true
	}

	return false
}

// isDebugEnabled checks if debug mode is enabled
func (v *Validator) isDebugEnabled() bool {
	return os.Getenv("FERRET_DEBUG") != ""
}
