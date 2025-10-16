// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"fmt"
	"time"
)

// GitLabSecurityReport represents the top-level GitLab Security Report structure
// following GitLab SAST report schema version 15.0.4
type GitLabSecurityReport struct {
	Version         string                `json:"version"`
	Vulnerabilities []GitLabVulnerability `json:"vulnerabilities"`
	Remediations    []GitLabRemediation   `json:"remediations"`
	Scan            GitLabScanInfo        `json:"scan"`
}

// GitLabVulnerability represents a single vulnerability in GitLab format
type GitLabVulnerability struct {
	ID          string             `json:"id"`
	Category    string             `json:"category"`
	Name        string             `json:"name"`
	Message     string             `json:"message"`
	Description string             `json:"description"`
	Severity    string             `json:"severity"`
	Confidence  string             `json:"confidence"`
	Location    GitLabLocation     `json:"location"`
	Identifiers []GitLabIdentifier `json:"identifiers"`
}

// GitLabLocation represents the location of a vulnerability
type GitLabLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// GitLabIdentifier represents vulnerability identifiers
type GitLabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// GitLabRemediation represents remediation information
type GitLabRemediation struct {
	Fixes   []GitLabFix `json:"fixes"`
	Summary string      `json:"summary"`
	Diff    string      `json:"diff"`
}

// GitLabFix represents a fix for a vulnerability
type GitLabFix struct {
	ID  string `json:"id"`
	CWE string `json:"cwe,omitempty"`
}

// GitLabScanInfo represents scan metadata
type GitLabScanInfo struct {
	Analyzer  GitLabAnalyzer `json:"analyzer"`
	Scanner   GitLabScanner  `json:"scanner"`
	Type      string         `json:"type"`
	StartTime string         `json:"start_time"`
	EndTime   string         `json:"end_time"`
	Status    string         `json:"status"`
}

// GitLabAnalyzer represents the analyzer information
type GitLabAnalyzer struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	URL     string       `json:"url"`
	Vendor  GitLabVendor `json:"vendor"`
	Version string       `json:"version"`
}

// GitLabScanner represents the scanner information
type GitLabScanner struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	URL     string       `json:"url"`
	Vendor  GitLabVendor `json:"vendor"`
	Version string       `json:"version"`
}

// GitLabVendor represents vendor information
type GitLabVendor struct {
	Name string `json:"name"`
}

// Validation methods for GitLabSecurityReport

// Validate checks if the GitLabSecurityReport is valid according to GitLab schema
func (r *GitLabSecurityReport) Validate() error {
	if r.Version == "" {
		return fmt.Errorf("version is required")
	}

	if r.Vulnerabilities == nil {
		return fmt.Errorf("vulnerabilities array is required (can be empty)")
	}

	if r.Remediations == nil {
		return fmt.Errorf("remediations array is required (can be empty)")
	}

	if err := r.Scan.Validate(); err != nil {
		return fmt.Errorf("scan validation failed: %w", err)
	}

	for i, vuln := range r.Vulnerabilities {
		if err := vuln.Validate(); err != nil {
			return fmt.Errorf("vulnerability %d validation failed: %w", i, err)
		}
	}

	return nil
}

// Validate checks if the GitLabVulnerability is valid
func (v *GitLabVulnerability) Validate() error {
	if v.ID == "" {
		return fmt.Errorf("vulnerability ID is required")
	}

	if v.Category == "" {
		return fmt.Errorf("vulnerability category is required")
	}

	if v.Name == "" {
		return fmt.Errorf("vulnerability name is required")
	}

	if v.Message == "" {
		return fmt.Errorf("vulnerability message is required")
	}

	if v.Severity == "" {
		return fmt.Errorf("vulnerability severity is required")
	}

	if err := v.Location.Validate(); err != nil {
		return fmt.Errorf("location validation failed: %w", err)
	}

	// Validate severity values
	validSeverities := map[string]bool{
		"Critical": true,
		"High":     true,
		"Medium":   true,
		"Low":      true,
		"Info":     true,
	}

	if !validSeverities[v.Severity] {
		return fmt.Errorf("invalid severity: %s", v.Severity)
	}

	return nil
}

// Validate checks if the GitLabLocation is valid
func (l *GitLabLocation) Validate() error {
	if l.File == "" {
		return fmt.Errorf("location file is required")
	}

	if l.StartLine < 1 {
		return fmt.Errorf("start_line must be >= 1")
	}

	if l.EndLine < l.StartLine {
		return fmt.Errorf("end_line must be >= start_line")
	}

	return nil
}

// Validate checks if the GitLabScanInfo is valid
func (s *GitLabScanInfo) Validate() error {
	if err := s.Analyzer.Validate(); err != nil {
		return fmt.Errorf("analyzer validation failed: %w", err)
	}

	if err := s.Scanner.Validate(); err != nil {
		return fmt.Errorf("scanner validation failed: %w", err)
	}

	if s.Type == "" {
		return fmt.Errorf("scan type is required")
	}

	if s.Status == "" {
		return fmt.Errorf("scan status is required")
	}

	// Validate scan type
	if s.Type != "sast" {
		return fmt.Errorf("scan type must be 'sast' for SAST reports")
	}

	// Validate status values
	validStatuses := map[string]bool{
		"success": true,
		"failure": true,
	}

	if !validStatuses[s.Status] {
		return fmt.Errorf("invalid scan status: %s", s.Status)
	}

	return nil
}

// Validate checks if the GitLabAnalyzer is valid
func (a *GitLabAnalyzer) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("analyzer ID is required")
	}

	if a.Name == "" {
		return fmt.Errorf("analyzer name is required")
	}

	if a.Version == "" {
		return fmt.Errorf("analyzer version is required")
	}

	if err := a.Vendor.Validate(); err != nil {
		return fmt.Errorf("vendor validation failed: %w", err)
	}

	return nil
}

// Validate checks if the GitLabScanner is valid
func (s *GitLabScanner) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("scanner ID is required")
	}

	if s.Name == "" {
		return fmt.Errorf("scanner name is required")
	}

	if s.Version == "" {
		return fmt.Errorf("scanner version is required")
	}

	if err := s.Vendor.Validate(); err != nil {
		return fmt.Errorf("vendor validation failed: %w", err)
	}

	return nil
}

// Validate checks if the GitLabVendor is valid
func (v *GitLabVendor) Validate() error {
	if v.Name == "" {
		return fmt.Errorf("vendor name is required")
	}

	return nil
}

// Immutability helper methods

// NewGitLabSecurityReport creates a new GitLabSecurityReport with immutable patterns
func NewGitLabSecurityReport(version string, vulnerabilities []GitLabVulnerability, remediations []GitLabRemediation, scan GitLabScanInfo) *GitLabSecurityReport {
	// Create defensive copies to ensure immutability
	vulnCopy := make([]GitLabVulnerability, len(vulnerabilities))
	copy(vulnCopy, vulnerabilities)

	remediationCopy := make([]GitLabRemediation, len(remediations))
	copy(remediationCopy, remediations)

	return &GitLabSecurityReport{
		Version:         version,
		Vulnerabilities: vulnCopy,
		Remediations:    remediationCopy,
		Scan:            scan,
	}
}

// NewGitLabVulnerability creates a new GitLabVulnerability with immutable patterns
func NewGitLabVulnerability(id, category, name, message, description, severity, confidence string, location GitLabLocation, identifiers []GitLabIdentifier) *GitLabVulnerability {
	// Create defensive copy of identifiers
	identifiersCopy := make([]GitLabIdentifier, len(identifiers))
	copy(identifiersCopy, identifiers)

	return &GitLabVulnerability{
		ID:          id,
		Category:    category,
		Name:        name,
		Message:     message,
		Description: description,
		Severity:    severity,
		Confidence:  confidence,
		Location:    location,
		Identifiers: identifiersCopy,
	}
}

// NewGitLabScanInfo creates a new GitLabScanInfo with current timestamps
func NewGitLabScanInfo(analyzer GitLabAnalyzer, scanner GitLabScanner, status string) *GitLabScanInfo {
	now := time.Now().Format("2006-01-02T15:04:05") // GitLab schema format

	return &GitLabScanInfo{
		Analyzer:  analyzer,
		Scanner:   scanner,
		Type:      "sast",
		StartTime: now,
		EndTime:   now,
		Status:    status,
	}
}

// NewGitLabAnalyzer creates a new GitLabAnalyzer
func NewGitLabAnalyzer(id, name, url, version string, vendor GitLabVendor) *GitLabAnalyzer {
	return &GitLabAnalyzer{
		ID:      id,
		Name:    name,
		URL:     url,
		Vendor:  vendor,
		Version: version,
	}
}

// NewGitLabScanner creates a new GitLabScanner
func NewGitLabScanner(id, name, url, version string, vendor GitLabVendor) *GitLabScanner {
	return &GitLabScanner{
		ID:      id,
		Name:    name,
		URL:     url,
		Vendor:  vendor,
		Version: version,
	}
}

// ToJSON converts the GitLabSecurityReport to JSON with proper formatting
func (r *GitLabSecurityReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Constants for GitLab SAST report schema
const (
	GitLabSASTSchemaVersion = "15.0.4"
	GitLabSASTScanType      = "sast"
	GitLabSASTCategory      = "sast"

	// Ferret Scan specific constants
	FerretAnalyzerID   = "ferret-scan"
	FerretAnalyzerName = "Ferret Scan"
	FerretAnalyzerURL  = "https://github.com/bank-vaults/ferret-scan"
	FerretVendorName   = "Bank Vaults"
)
