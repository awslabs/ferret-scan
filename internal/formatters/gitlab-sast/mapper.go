// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// VulnerabilityMapper handles mapping Ferret Scan matches to GitLab vulnerabilities
type VulnerabilityMapper struct{}

// NewVulnerabilityMapper creates a new vulnerability mapper.
func NewVulnerabilityMapper() *VulnerabilityMapper {
	return &VulnerabilityMapper{}
}

// MapToGitLabVulnerability converts a Ferret Scan match to GitLab vulnerability format
func (m *VulnerabilityMapper) MapToGitLabVulnerability(match detector.Match, sourceRoot string) (*GitLabVulnerability, error) {
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

	// Create location information. Virtual matches (stdin, in-memory) keep
	// their synthetic label as-is; only filesystem paths get normalized.
	locationFile := match.Filename
	if !match.IsVirtual() {
		locationFile = m.normalizeFilePath(match.Filename, sourceRoot)
	}
	location := GitLabLocation{
		File:      locationFile,
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
	//
	// Two findings of the same type on one line therefore hash alike. That WAS the
	// #328 collapse — GitLab deduplicates by id, so it kept one and silently dropped
	// the other (measured: 4 vulnerabilities emitted, 2 distinct ids, exit 0) — and
	// it is resolved by the emit-time collision guard in formatter.go, not here.
	//
	// The match's column is deliberately NOT mixed in. It would also separate the
	// two, but only for findings that HAVE a column, so the guard is needed anyway
	// for synthesised match texts that have none; and mixing it in changes the id of
	// every finding that already had one, which silently detaches an operator's
	// existing GitLab triage state (dismissals, issue links) from the findings it
	// belongs to. Verified by mutation: dropping the column here breaks nothing,
	// dropping the guard reintroduces the collision.
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
	// Every Ferret Scan finding is a SAST-category vulnerability in GitLab. The
	// former per-type categoryMappings map (and its DEFAULT) mapped every key to
	// "sast", so this is byte-identical and removes a redundant table (gap 3.3).
	return "sast"
}

// generateVulnerabilityName creates a human-readable name for the vulnerability
func (m *VulnerabilityMapper) generateVulnerabilityName(checkType string) string {
	// Display name from the central type-metadata registry (core.TypeMeta — gap
	// 3.3, name tier). Keyed by validator name (CREDIT_CARD, …); sub-types like
	// VISA have no GitLabName entry and hit the title-case fallback below,
	// byte-identical to the former local nameMap behavior.
	// DescribeType: see #662 — the registry is keyed by sub-type but was populated at validator level.
	if d := core.DescribeType(strings.ToUpper(checkType)); d.GitLabName != "" {
		return d.GitLabName
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
		"VIN":                   "Potential vehicle identification number found in source code",
		"METADATA":              "Sensitive metadata found in file",
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

// normalizeFilePath renders a scanned file's path as the repository-relative POSIX path GitLab
// expects in location.file.
//
// The CLI hands the formatter ABSOLUTE paths — cmd/main.go resolves every input with
// filepath.Abs before walking it — so this is the only place the report learns where the
// repository is. Before #705 an absolute path was replaced with filepath.Base, which put every
// finding at the repository root: two files named config.py in different directories were one
// location, and the Security Dashboard's link opened the wrong file or a 404.
//
// An absolute path INSIDE sourceRoot is made relative to it and keeps every segment below it.
// Anything else — no root known, a path on another volume, a path that would climb out of the
// root — keeps the basename behaviour every earlier release had. That is a lossy answer and it
// is chosen deliberately over refusing: this mapper's error return is consumed by a loop in
// formatter.go that `continue`s past the finding and logs it only under --verbose, and #562
// already measured what that produces — a report with "status": "success" and a real finding
// missing from it. A finding at the wrong path can still be found; a finding that is not in
// the report cannot.
func (m *VulnerabilityMapper) normalizeFilePath(filePath, sourceRoot string) string {
	cleaned := filepath.Clean(filePath)

	if filepath.IsAbs(cleaned) {
		cleaned = relativeToRootOrBase(cleaned, sourceRoot)
	}

	cleaned = strings.TrimPrefix(cleaned, "./")
	for strings.HasPrefix(cleaned, "../") {
		cleaned = cleaned[3:]
	}

	// GitLab wants forward slashes. filepath.ToSlash is the whole answer: it converts the host
	// separator and nothing else. On POSIX a backslash is an ordinary filename character, and
	// rewriting it would report `we\ird.txt` as a directory that does not exist — the class
	// #637 fixed in the redaction path.
	return filepath.ToSlash(cleaned)
}

// relativeToRootOrBase returns abs relative to root when abs lies inside root, and its basename
// otherwise.
//
// The lexical spellings are tried first, then both sides resolved with EvalSymlinks, as
// withinRoot in cmd does: on macOS /tmp is a link to /private/tmp, and a container volume mount
// routinely is one, so a root spelled one way and a path the walker resolved the other way look
// unrelated to Rel. Measured on the first revision of this change, CI_PROJECT_DIR=/tmp/sym/link
// against a scan of /tmp/sym/real: 2 vulnerabilities became 0.
//
// Lexical FIRST, not resolved-only, because resolution can succeed on one side and fail on the
// other — a root under /var resolves to /private/var while a file that has since been removed
// does not — and Rel between a resolved root and an unresolved path is exactly the mismatch
// being avoided.
func relativeToRootOrBase(abs, root string) string {
	if root == "" {
		return filepath.Base(abs)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.Base(abs)
	}
	if rel, ok := relInside(absRoot, abs); ok {
		return rel
	}
	resolvedRoot, errRoot := filepath.EvalSymlinks(absRoot)
	resolvedAbs, errAbs := filepath.EvalSymlinks(abs)
	if errRoot != nil || errAbs != nil {
		return filepath.Base(abs)
	}
	if rel, ok := relInside(resolvedRoot, resolvedAbs); ok {
		return rel
	}
	return filepath.Base(abs)
}

// relInside is filepath.Rel with "outside the root" folded into the ok result. Rel yields ".." or
// a "../" prefix exactly when target sits outside root.
func relInside(root, target string) (string, bool) {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
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
