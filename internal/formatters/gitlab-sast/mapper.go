// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"ferret-scan/internal/detector"
)

// VulnerabilityMapper handles mapping Ferret Scan matches to GitLab vulnerabilities
type VulnerabilityMapper struct {
	// Configuration for mapping behavior
	categoryMappings map[string]string
}

// NewVulnerabilityMapper creates a new vulnerability mapper with default configuration
func NewVulnerabilityMapper() *VulnerabilityMapper {
	return &VulnerabilityMapper{
		categoryMappings: map[string]string{
			// All Ferret Scan check types map to SAST category
			"CREDIT_CARD":           "sast",
			"SSN":                   "sast",
			"PASSPORT":              "sast",
			"EMAIL":                 "sast",
			"PHONE":                 "sast",
			"IP_ADDRESS":            "sast",
			"SECRETS":               "sast",
			"INTELLECTUAL_PROPERTY": "sast",
			"SOCIAL_MEDIA":          "sast",
			"METADATA":              "sast",
			"COMPREHEND":            "sast",
			// Default fallback
			"DEFAULT": "sast",
		},
	}
}

// MapToGitLabVulnerability converts a Ferret Scan match to GitLab vulnerability format
func (m *VulnerabilityMapper) MapToGitLabVulnerability(match detector.Match) (*GitLabVulnerability, error) {
	if match.Filename == "" {
		return nil, NewMappingError("match filename is required")
	}

	if match.LineNumber < 1 {
		return nil, NewMappingError("match line number must be >= 1")
	}

	if match.Type == "" {
		return nil, NewMappingError("match type is required")
	}

	// Generate deterministic vulnerability ID
	vulnID := m.GenerateVulnerabilityID(match)

	// Map confidence level to severity (use Ferret's confidence_level classification)
	confidenceLevel := m.GetConfidenceLevel(match.Confidence)
	severity := m.MapConfidenceLevelToSeverity(confidenceLevel)

	// Map check type to GitLab category
	category := m.mapCheckTypeToCategory(match.Type)

	// Generate vulnerability name based on check type
	name := m.generateVulnerabilityName(match.Type)

	// Create sanitized message (no actual sensitive data)
	message := m.generateSanitizedMessage(match)

	// Create enhanced description with context
	description := m.generateDescription(match)

	// Create location information
	location := GitLabLocation{
		File:      m.normalizeFilePath(match.Filename),
		StartLine: match.LineNumber,
		EndLine:   match.LineNumber, // Single line for now
	}

	// Create identifiers
	identifiers := m.generateIdentifiers(match)

	// Create the vulnerability
	vulnerability := NewGitLabVulnerability(
		vulnID,
		category,
		name,
		message,
		description,
		severity,
		m.mapConfidenceToGitLabConfidence(match.Confidence),
		location,
		identifiers,
	)

	return vulnerability, nil
}

// GenerateVulnerabilityID creates a deterministic ID using SHA256 hash
func (m *VulnerabilityMapper) GenerateVulnerabilityID(match detector.Match) string {
	// Create deterministic ID based on file, line, and check type
	// This ensures the same vulnerability gets the same ID across scans
	data := fmt.Sprintf("%s:%d:%s", match.Filename, match.LineNumber, match.Type)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("ferret-%x", hash[:8])
}

// GetConfidenceLevel returns the confidence level as a string (same logic as shared/structures.go)
func (m *VulnerabilityMapper) GetConfidenceLevel(confidence float64) string {
	switch {
	case confidence >= 90:
		return "HIGH"
	case confidence >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// MapConfidenceLevelToSeverity maps Ferret Scan confidence levels to GitLab severity levels
func (m *VulnerabilityMapper) MapConfidenceLevelToSeverity(confidenceLevel string) string {
	// Map Ferret's confidence levels (how bad the finding is) to GitLab severity
	switch confidenceLevel {
	case "HIGH":
		return "Critical" // High severity findings → Critical in GitLab
	case "MEDIUM":
		return "High" // Medium severity findings → High in GitLab
	case "LOW":
		return "Medium" // Low severity findings → Medium in GitLab
	default:
		return "Low" // Fallback for unknown levels
	}
}

// mapCheckTypeToCategory maps Ferret Scan check types to GitLab categories
func (m *VulnerabilityMapper) mapCheckTypeToCategory(checkType string) string {
	// Normalize check type to uppercase
	normalizedType := strings.ToUpper(checkType)

	if category, exists := m.categoryMappings[normalizedType]; exists {
		return category
	}

	// Default to SAST category for all Ferret Scan findings
	return m.categoryMappings["DEFAULT"]
}

// generateVulnerabilityName creates a human-readable name for the vulnerability
func (m *VulnerabilityMapper) generateVulnerabilityName(checkType string) string {
	// Convert check type to human-readable format
	nameMap := map[string]string{
		"CREDIT_CARD":           "Credit Card Number Detected",
		"SSN":                   "Social Security Number Detected",
		"PASSPORT":              "Passport Number Detected",
		"EMAIL":                 "Email Address Detected",
		"PHONE":                 "Phone Number Detected",
		"IP_ADDRESS":            "IP Address Detected",
		"SECRETS":               "Secret/API Key Detected",
		"INTELLECTUAL_PROPERTY": "Intellectual Property Detected",
		"SOCIAL_MEDIA":          "Social Media Handle Detected",
		"METADATA":              "Sensitive Metadata Detected",
		"COMPREHEND":            "AWS Comprehend PII Detected",
	}

	normalizedType := strings.ToUpper(checkType)
	if name, exists := nameMap[normalizedType]; exists {
		return name
	}

	// Fallback: convert underscores to spaces and title case
	return strings.Title(strings.ReplaceAll(strings.ToLower(checkType), "_", " ")) + " Detected"
}

// generateSanitizedMessage creates a safe message without exposing sensitive data
func (m *VulnerabilityMapper) generateSanitizedMessage(match detector.Match) string {
	checkType := strings.ToUpper(match.Type)

	messageMap := map[string]string{
		"CREDIT_CARD":           "Potential credit card number found in source code",
		"SSN":                   "Potential social security number found in source code",
		"PASSPORT":              "Potential passport number found in source code",
		"EMAIL":                 "Email address found in source code",
		"PHONE":                 "Phone number found in source code",
		"IP_ADDRESS":            "IP address found in source code",
		"SECRETS":               "Potential secret or API key found in source code",
		"INTELLECTUAL_PROPERTY": "Potential intellectual property content found",
		"SOCIAL_MEDIA":          "Social media handle found in source code",
		"METADATA":              "Sensitive metadata found in file",
		"COMPREHEND":            "AWS Comprehend detected potential PII",
	}

	if message, exists := messageMap[checkType]; exists {
		return message
	}

	return fmt.Sprintf("Potential sensitive data (%s) found in source code", strings.ToLower(match.Type))
}

// generateDescription creates an enhanced description with context
func (m *VulnerabilityMapper) generateDescription(match detector.Match) string {
	baseDescription := m.generateSanitizedMessage(match)

	// Add context information if available
	contextInfo := ""
	if match.Context.FullLine != "" {
		// Don't include the actual line content to avoid exposing sensitive data
		contextInfo = " Review the indicated line for potential sensitive data exposure."
	}

	// Add confidence information
	confidenceInfo := fmt.Sprintf(" Detection confidence: %.2f", match.Confidence)

	// Add validator information
	validatorInfo := ""
	if match.Validator != "" {
		validatorInfo = fmt.Sprintf(" Detected by: %s validator", match.Validator)
	}

	return baseDescription + contextInfo + confidenceInfo + validatorInfo
}

// generateIdentifiers creates GitLab identifiers for the vulnerability
func (m *VulnerabilityMapper) generateIdentifiers(match detector.Match) []GitLabIdentifier {
	identifiers := []GitLabIdentifier{
		{
			Type:  "ferret_scan_check_type",
			Name:  "Ferret Scan Check Type",
			Value: match.Type,
		},
	}

	// Add validator identifier if available
	if match.Validator != "" {
		identifiers = append(identifiers, GitLabIdentifier{
			Type:  "ferret_scan_validator",
			Name:  "Ferret Scan Validator",
			Value: match.Validator,
		})
	}

	return identifiers
}

// mapConfidenceToGitLabConfidence maps numeric confidence to GitLab confidence levels
func (m *VulnerabilityMapper) mapConfidenceToGitLabConfidence(confidence float64) string {
	// Normalize confidence to 0-1 range if it's in percentage format (0-100)
	normalizedConfidence := confidence
	if confidence > 1.0 {
		normalizedConfidence = confidence / 100.0
	}

	// GitLab uses High/Medium/Low confidence levels
	if normalizedConfidence >= 0.8 {
		return "High"
	} else if normalizedConfidence >= 0.5 {
		return "Medium"
	} else {
		return "Low"
	}
}

// normalizeFilePath normalizes file paths for consistent reporting
func (m *VulnerabilityMapper) normalizeFilePath(filePath string) string {
	// Clean the path and ensure it's relative
	cleaned := filepath.Clean(filePath)

	// Remove leading "./" if present
	if strings.HasPrefix(cleaned, "./") {
		cleaned = cleaned[2:]
	}

	// Handle parent directory references by removing leading "../"
	for strings.HasPrefix(cleaned, "../") {
		cleaned = cleaned[3:]
	}

	// Ensure we don't have absolute paths in reports
	if filepath.IsAbs(cleaned) {
		cleaned = filepath.Base(cleaned)
	}

	return cleaned
}

// ValidateMapping validates that a mapping operation can be performed
func (m *VulnerabilityMapper) ValidateMapping(match detector.Match) error {
	if match.Filename == "" {
		return NewMappingError("match filename is required for mapping")
	}

	if match.LineNumber < 1 {
		return NewMappingError("match line number must be >= 1 for mapping")
	}

	if match.Type == "" {
		return NewMappingError("match type is required for mapping")
	}

	// Accept both percentage (0-100) and decimal (0-1) confidence values
	if match.Confidence < 0 || match.Confidence > 100 {
		return NewMappingError("match confidence must be between 0 and 100 (percentage) or 0 and 1 (decimal)")
	}

	return nil
}

// AddCategoryMapping adds or updates a check type to category mapping
func (m *VulnerabilityMapper) AddCategoryMapping(checkType, category string) {
	m.categoryMappings[strings.ToUpper(checkType)] = category
}
