// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"fmt"
	"regexp"
	"strings"

	"ferret-scan/internal/detector"
)

// DataSanitizer handles sanitization of sensitive data for GitLab security reports
// It leverages the existing redaction system and provides context-aware descriptions
type DataSanitizer struct{}

// NewDataSanitizer creates a new DataSanitizer instance
func NewDataSanitizer() DataSanitizerInterface {
	return &DataSanitizer{}
}

// SanitizeMessage creates a safe message for GitLab vulnerability reports
// It respects the existing ShowMatch flag and provides useful context without exposing sensitive data
func (s *DataSanitizer) SanitizeMessage(match detector.Match) string {
	// Use secure defaults - never show actual sensitive data in GitLab reports
	// This ensures GitLab Security Dashboard doesn't expose sensitive information
	matchText := "[REDACTED]"

	// Create context-aware message based on check type
	checkTypeDescription := s.GetCheckTypeDescription(match.Type)

	// Build message with context
	message := fmt.Sprintf("%s detected: %s", checkTypeDescription, matchText)

	// Add confidence information
	confidenceLevel := s.GetConfidenceLevel(match.Confidence)
	message += fmt.Sprintf(" (confidence: %s)", confidenceLevel)

	return message
}

// SanitizeDescription creates a detailed but safe description for GitLab vulnerability reports
func (s *DataSanitizer) SanitizeDescription(match detector.Match) string {
	var description strings.Builder

	// Start with check type description
	checkTypeDescription := s.GetCheckTypeDescription(match.Type)
	description.WriteString(fmt.Sprintf("Ferret Scan detected %s in this file.\n\n", strings.ToLower(checkTypeDescription)))

	// Add location context
	description.WriteString(fmt.Sprintf("**Location:** %s (line %d)\n", match.Filename, match.LineNumber))

	// Add confidence information
	confidenceLevel := s.GetConfidenceLevel(match.Confidence)
	description.WriteString(fmt.Sprintf("**Confidence:** %s (%.1f%%)\n", confidenceLevel, match.Confidence))

	// Add validator information
	if match.Validator != "" {
		description.WriteString(fmt.Sprintf("**Detected by:** %s validator\n", match.Validator))
	}

	// Add context information if available and safe
	if match.Context.FullLine != "" {
		// Always sanitize the full line context
		sanitizedLine := s.EnsureNoSensitiveData(match.Context.FullLine)
		description.WriteString(fmt.Sprintf("\n**Context:**\n```\n%s\n```\n", sanitizedLine))
	}

	// Add metadata information if available
	if len(match.Metadata) > 0 {
		// First, collect safe metadata items
		var safeMetadata []string
		for key, value := range match.Metadata {
			// Only include safe metadata keys
			if s.IsSafeMetadataKey(key) {
				safeMetadata = append(safeMetadata, fmt.Sprintf("- %s: %v", key, value))
			}
		}

		// Only add the section if we have safe metadata to show
		if len(safeMetadata) > 0 {
			description.WriteString("\n**Additional Information:**\n")
			for _, item := range safeMetadata {
				description.WriteString(item + "\n")
			}
		}
	}

	// Add remediation guidance
	remediation := s.getRemediationGuidance(match.Type)
	if remediation != "" {
		description.WriteString(fmt.Sprintf("\n**Remediation:**\n%s", remediation))
	}

	return description.String()
}

// EnsureNoSensitiveData ensures that text doesn't contain actual sensitive data
// This is a safety net that replaces common sensitive patterns with placeholders
func (s *DataSanitizer) EnsureNoSensitiveData(text string) string {
	if text == "" {
		return text
	}

	// Replace common sensitive data patterns with safe placeholders
	sanitized := text

	// Credit card patterns (16 digits with optional separators)
	sanitized = s.replacePattern(sanitized, `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`, "[CREDIT-CARD]")

	// SSN patterns (XXX-XX-XXXX)
	sanitized = s.replacePattern(sanitized, `\b\d{3}-\d{2}-\d{4}\b`, "[SSN]")

	// Phone number patterns
	sanitized = s.replacePattern(sanitized, `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`, "[PHONE]")

	// Email patterns
	sanitized = s.replacePattern(sanitized, `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, "[EMAIL]")

	// AWS Access Key patterns (AKIA followed by 16 alphanumeric characters)
	sanitized = s.replacePattern(sanitized, `\bAKIA[A-Z0-9]{16}\b`, "[AWS-ACCESS-KEY]")

	// AWS Secret Key patterns (40 character base64-like strings)
	sanitized = s.replacePattern(sanitized, `\b[A-Za-z0-9/+=]{40}\b`, "[AWS-SECRET-KEY]")

	// API key patterns (long alphanumeric strings with underscores)
	sanitized = s.replacePattern(sanitized, `\b[A-Za-z0-9_]{32,}\b`, "[API-KEY]")

	// IP address patterns
	sanitized = s.replacePattern(sanitized, `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`, "[IP-ADDRESS]")

	return sanitized
}

// GetCheckTypeDescription returns a human-readable description for check types
// Made public for testing
func (s *DataSanitizer) GetCheckTypeDescription(checkType string) string {
	descriptions := map[string]string{
		"CREDIT_CARD":           "Credit card number",
		"VISA":                  "Visa credit card",
		"MASTERCARD":            "Mastercard credit card",
		"AMERICAN_EXPRESS":      "American Express credit card",
		"DISCOVER":              "Discover credit card",
		"JCB":                   "JCB credit card",
		"DINERS_CLUB":           "Diners Club credit card",
		"SSN":                   "Social Security Number",
		"PHONE":                 "Phone number",
		"EMAIL":                 "Email address",
		"IP_ADDRESS":            "IP address",
		"API_KEY":               "API key",
		"AWS_ACCESS_KEY":        "AWS access key",
		"GITHUB_TOKEN":          "GitHub token",
		"SLACK_TOKEN":           "Slack token",
		"GPS":                   "GPS coordinates",
		"INTELLECTUAL_PROPERTY": "Intellectual property",
		"SOCIAL_MEDIA_CLUSTER":  "Social media information",
		"PII_PERSON":            "Personal information",
		"PII_LOCATION":          "Location information",
		"PII_ORGANIZATION":      "Organization information",
		"METADATA":              "Sensitive metadata",
		"DOCUMENT_COMMENTS":     "Document comments",
		"AUTHOR_INFO":           "Author information",
		"COMPANY_INFO":          "Company information",
	}

	if description, exists := descriptions[checkType]; exists {
		return description
	}

	// Fallback: convert check type to readable format
	readable := strings.ReplaceAll(checkType, "_", " ")
	readable = strings.ToLower(readable)
	return fmt.Sprintf("Sensitive data (%s)", readable)
}

// GetConfidenceLevel returns a human-readable confidence level
// Made public for testing
func (s *DataSanitizer) GetConfidenceLevel(confidence float64) string {
	switch {
	case confidence >= 90:
		return "HIGH"
	case confidence >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// IsSafeMetadataKey determines if a metadata key is safe to include in reports
// Made public for testing
func (s *DataSanitizer) IsSafeMetadataKey(key string) bool {
	safeKeys := map[string]bool{
		"card_type":           true,
		"vendor":              true,
		"confidence_level":    true,
		"context_impact":      true,
		"source":              true,
		"validator_version":   true,
		"check_type":          true,
		"pattern_type":        true,
		"reconstruction_type": true,
		"consolidated_count":  true,
		"cluster_type":        true,
		"analysis_confidence": true,
	}

	// Exclude keys that might contain sensitive data
	unsafeKeys := map[string]bool{
		"original_text":  true,
		"raw_match":      true,
		"full_content":   true,
		"before_context": true,
		"after_context":  true,
		"line_content":   true,
	}

	if unsafeKeys[key] {
		return false
	}

	return safeKeys[key]
}

// getRemediationGuidance provides remediation guidance based on check type
func (s *DataSanitizer) getRemediationGuidance(checkType string) string {
	guidance := map[string]string{
		"CREDIT_CARD":           "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"VISA":                  "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"MASTERCARD":            "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"AMERICAN_EXPRESS":      "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"DISCOVER":              "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"JCB":                   "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"DINERS_CLUB":           "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs.",
		"SSN":                   "Remove Social Security Numbers from code and documentation. Use test data or anonymized identifiers instead.",
		"PHONE":                 "Remove phone numbers or replace with example numbers (e.g., 555-0123).",
		"EMAIL":                 "Remove email addresses or replace with example addresses (e.g., user@domain.example).",
		"IP_ADDRESS":            "Remove IP addresses or replace with example addresses (e.g., 192.0.2.1).",
		"API_KEY":               "Remove API keys and store them securely using environment variables or secret management systems.",
		"AWS_ACCESS_KEY":        "Remove AWS credentials immediately and rotate them. Use IAM roles or environment variables instead.",
		"GITHUB_TOKEN":          "Remove GitHub tokens and regenerate them. Use GitHub Actions secrets or environment variables instead.",
		"GPS":                   "Remove GPS coordinates or replace with approximate/example coordinates if location data is needed for testing.",
		"INTELLECTUAL_PROPERTY": "Review and remove proprietary information. Ensure compliance with intellectual property policies.",
		"PII_PERSON":            "Remove personal information or replace with anonymized test data.",
		"METADATA":              "Review and remove sensitive metadata from files before committing to version control.",
	}

	if remediation, exists := guidance[checkType]; exists {
		return remediation
	}

	return "Review the detected sensitive data and remove or replace it with appropriate test data or placeholders."
}

// replacePattern is a helper function to replace regex patterns with placeholders
func (s *DataSanitizer) replacePattern(text, pattern, replacement string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		// If regex compilation fails, return original text
		return text
	}
	return re.ReplaceAllString(text, replacement)
}
