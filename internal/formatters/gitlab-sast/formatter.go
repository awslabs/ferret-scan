// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"log"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/version"
)

// Formatter implements the GitLab SAST security report formatter
type Formatter struct {
	mapper    VulnerabilityMapperInterface
	sanitizer DataSanitizerInterface
	validator SchemaValidatorInterface
}

// VulnerabilityMapperInterface defines the contract for vulnerability mapping
type VulnerabilityMapperInterface interface {
	MapToGitLabVulnerability(match detector.Match) (*GitLabVulnerability, error)
	GenerateVulnerabilityID(match detector.Match) string
	MapConfidenceLevelToSeverity(confidenceLevel string) string
	ValidateMapping(match detector.Match) error
}

// DataSanitizerInterface defines the contract for data sanitization
type DataSanitizerInterface interface {
	SanitizeMessage(match detector.Match) string
	SanitizeDescription(match detector.Match) string
	EnsureNoSensitiveData(text string) string
}

// SchemaValidatorInterface defines the contract for schema validation
type SchemaValidatorInterface interface {
	ValidateReport(report *GitLabSecurityReport) error
	ValidateVulnerability(vuln *GitLabVulnerability) error
	IsValidSeverity(severity string) bool
}

// NewFormatter creates a new GitLab SAST formatter with injected dependencies
func NewFormatter() *Formatter {
	return &Formatter{
		mapper:    NewVulnerabilityMapper(),
		sanitizer: NewDataSanitizer(),
		validator: NewSchemaValidator(),
	}
}

// Name returns the formatter name
func (f *Formatter) Name() string {
	return "gitlab-sast"
}

// Description returns the formatter description
func (f *Formatter) Description() string {
	return "GitLab Security Report format for integration with GitLab Security Dashboard"
}

// FileExtension returns the file extension for this format
func (f *Formatter) FileExtension() string {
	return "json"
}

// Format converts Ferret Scan results to GitLab SAST format
func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	startTime := time.Now()

	// Log debug information if needed
	if options.Verbose {
		log.Printf("GitLab SAST Formatter: Processing %d matches, %d suppressed matches", len(matches), len(suppressedMatches))
	}

	// Create the GitLab security report structure with proper metadata
	report := &GitLabSecurityReport{
		Version:         GitLabSASTSchemaVersion, // Use constant from models.go
		Vulnerabilities: make([]GitLabVulnerability, 0, len(matches)),
		Remediations:    []GitLabRemediation{}, // Always include empty array as required by schema
		Scan: GitLabScanInfo{
			Analyzer: GitLabAnalyzer{
				ID:      FerretAnalyzerID,
				Name:    FerretAnalyzerName,
				URL:     FerretAnalyzerURL,
				Vendor:  GitLabVendor{Name: FerretVendorName},
				Version: version.Short(), // Use actual version from version package
			},
			Scanner: GitLabScanner{
				ID:      FerretAnalyzerID,
				Name:    FerretAnalyzerName,
				URL:     FerretAnalyzerURL,
				Vendor:  GitLabVendor{Name: FerretVendorName},
				Version: version.Short(), // Use actual version from version package
			},
			Type:      GitLabSASTScanType,
			StartTime: startTime.Format("2006-01-02T15:04:05"),  // GitLab schema format
			EndTime:   time.Now().Format("2006-01-02T15:04:05"), // GitLab schema format
			Status:    "success",                                // Will be updated to "failure" if errors occur
		},
	}

	// Handle empty results - return valid empty GitLab report structure
	if len(matches) == 0 {
		if options.Verbose {
			log.Printf("GitLab SAST Formatter: No matches found, returning empty report")
		}

		// Update end time for empty report
		report.Scan.EndTime = time.Now().Format("2006-01-02T15:04:05") // GitLab schema format

		// Validate the empty report
		if err := f.validator.ValidateReport(report); err != nil {
			// If validation fails, set status to failure but still return the report
			report.Scan.Status = "failure"
			if options.Verbose {
				log.Printf("GitLab SAST Formatter: Empty report validation failed: %v", err)
			}
		}

		// Marshal empty report to JSON
		jsonBytes, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", NewFormatterError("failed to marshal empty report JSON", err)
		}

		return string(jsonBytes), nil
	}

	// Process each match with proper error handling
	processedCount := 0
	errorCount := 0

	for i, match := range matches {
		// Validate the match before processing
		if err := f.mapper.ValidateMapping(match); err != nil {
			errorCount++
			if options.Verbose {
				log.Printf("GitLab SAST Formatter: Skipping invalid match %d: %v", i, err)
			}
			continue
		}

		// Map to GitLab vulnerability format
		vuln, err := f.mapper.MapToGitLabVulnerability(match)
		if err != nil {
			errorCount++
			if options.Verbose {
				log.Printf("GitLab SAST Formatter: Failed to map match %d: %v", i, err)
			}
			continue
		}

		// Sanitize the vulnerability data to ensure no sensitive information is exposed
		vuln.Message = f.sanitizer.SanitizeMessage(match)
		vuln.Description = f.sanitizer.SanitizeDescription(match)

		// Validate the vulnerability before adding
		if err := f.validator.ValidateVulnerability(vuln); err != nil {
			errorCount++
			if options.Verbose {
				log.Printf("GitLab SAST Formatter: Vulnerability validation failed for match %d: %v", i, err)
			}
			continue
		}

		report.Vulnerabilities = append(report.Vulnerabilities, *vuln)
		processedCount++
	}

	// Update end time after processing
	report.Scan.EndTime = time.Now().Format("2006-01-02T15:04:05") // GitLab schema format

	// Log processing summary
	if options.Verbose {
		log.Printf("GitLab SAST Formatter: Successfully processed %d/%d matches", processedCount, len(matches))
		if errorCount > 0 {
			log.Printf("GitLab SAST Formatter: %d matches had errors and were skipped", errorCount)
		}
	}

	// Set scan status based on processing results
	if errorCount > 0 && processedCount == 0 {
		// All matches failed to process
		report.Scan.Status = "failure"
	} else if errorCount > 0 {
		// Some matches failed but some succeeded - still mark as success
		// GitLab will show the vulnerabilities that were successfully processed
		report.Scan.Status = "success"
	}

	// Validate the complete report
	if err := f.validator.ValidateReport(report); err != nil {
		// If final validation fails, set status to failure but still return the report
		report.Scan.Status = "failure"
		if options.Verbose {
			log.Printf("GitLab SAST Formatter: Final report validation failed: %v", err)
		}
		// Continue to return the report even if validation fails
		// This ensures GitLab gets some output rather than a complete failure
	}

	// Marshal to JSON with proper error handling
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", NewFormatterError("failed to marshal report JSON", err)
	}

	return string(jsonBytes), nil
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
