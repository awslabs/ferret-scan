// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/formatters/shared"
	"ferret-scan/internal/version"
	"fmt"
)

// Formatter implements the formatters.Formatter interface for SARIF output
type Formatter struct {
	mapper      *VulnerabilityMapper
	ruleManager *RuleManager
}

// NewFormatter creates a new SARIF formatter instance
func NewFormatter() *Formatter {
	ruleManager := NewRuleManager()
	return &Formatter{
		mapper:      NewVulnerabilityMapper(ruleManager),
		ruleManager: ruleManager,
	}
}

// Name returns the name of the formatter
func (f *Formatter) Name() string {
	return "sarif"
}

// Description returns a brief description of the formatter
func (f *Formatter) Description() string {
	return "SARIF 2.1.0 format for integration with GitHub Security, IDEs, and security platforms"
}

// FileExtension returns the recommended file extension for SARIF files
func (f *Formatter) FileExtension() string {
	return ".sarif"
}

// Format converts matches and suppressed matches to SARIF 2.1.0 format
func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	// Handle nil inputs gracefully
	if matches == nil {
		matches = []detector.Match{}
	}
	if suppressedMatches == nil {
		suppressedMatches = []detector.SuppressedMatch{}
	}

	// Apply confidence filtering before conversion
	filteredMatches := shared.FilterMatchesByConfidence(matches, options)

	// Build the SARIF report
	report := f.buildReport(filteredMatches, suppressedMatches, options)

	// Marshal to JSON with indentation for readability
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return string(jsonBytes), nil
}

// buildReport constructs the complete SARIF report structure
func (f *Formatter) buildReport(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) *SARIFReport {
	// Convert matches to SARIF results
	var results []SARIFResult

	// Process active matches
	for _, match := range matches {
		result, err := f.mapper.MapToSARIFResult(match, options)
		if err != nil {
			// Log error but continue processing other matches
			// In production, you might want to use a proper logger here
			continue
		}
		results = append(results, *result)
	}

	// Process suppressed matches
	for _, suppressed := range suppressedMatches {
		result, err := f.mapper.MapSuppressedMatch(suppressed, options)
		if err != nil {
			// Log error but continue processing other matches
			continue
		}
		results = append(results, *result)
	}

	// Build tool driver with metadata and rules
	driver := f.buildDriver()

	// Create the SARIF run with version control provenance
	run := SARIFRun{
		Tool: SARIFTool{
			Driver: driver,
		},
		Results:                  results,
		VersionControlProvenance: f.buildVersionControlProvenance(),
	}

	// Create the top-level SARIF report
	report := &SARIFReport{
		Schema:  SARIFSchemaURL,
		Version: SARIFVersion,
		Runs:    []SARIFRun{run},
	}

	return report
}

// buildDriver constructs the SARIF tool driver with metadata and rules
func (f *Formatter) buildDriver() SARIFDriver {
	// Get version information
	versionStr := version.Short()

	// Collect all rules that were encountered during processing
	rules := f.ruleManager.GetAllRules()

	driver := SARIFDriver{
		Name:            ToolName,
		Version:         versionStr,
		SemanticVersion: versionStr,
		InformationURI:  ToolInformationURI,
		Rules:           rules,
	}

	return driver
}

// buildVersionControlProvenance constructs version control information for the SARIF report
// This provides context about the repository being analyzed
func (f *Formatter) buildVersionControlProvenance() []SARIFVersionControl {
	// Return repository information for ferret-scan
	// In a real-world scenario, this could be enhanced to detect the actual
	// repository being scanned using git commands
	return []SARIFVersionControl{
		{
			RepositoryURI: ToolInformationURI,
			RevisionID:    version.Short(),
			MappedTo: &SARIFMappedTo{
				URIBaseID: "%SRCROOT%",
			},
		},
	}
}

// init registers the SARIF formatter with the global formatter registry
func init() {
	formatters.Register(NewFormatter())
}
