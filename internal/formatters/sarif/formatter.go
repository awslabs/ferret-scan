// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"fmt"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
	"github.com/awslabs/ferret-scan/v2/internal/version"
)

// Formatter implements the formatters.Formatter interface for SARIF output.
//
// It is intentionally stateless: the per-call rule set is built fresh inside
// each Format() call (see below). Earlier versions cached a RuleManager on the
// Formatter, which — because the formatter is registered as a process singleton
// in formatters.DefaultRegistry — accumulated rules across Format() calls, so a
// SARIF report's tool.driver.rules array depended on everything formatted
// earlier in the same process. Harmless for the CLI (one Format per process)
// but a real cross-invocation contamination bug for long-lived embedders (the
// web server formats repeatedly). Building the RuleManager per call makes each
// report depend only on its own matches and is concurrency-safe.
type Formatter struct{}

// NewFormatter creates a new SARIF formatter instance.
func NewFormatter() *Formatter {
	return &Formatter{}
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

	// Fresh per-call rule manager + mapper so the rules array derives only from
	// THIS call's matches (no cross-call accumulation).
	ruleManager := NewRuleManager()
	mapper := NewVulnerabilityMapper(ruleManager)

	// Build the SARIF report
	report := f.buildReport(mapper, ruleManager, filteredMatches, suppressedMatches, options)

	// Marshal to JSON with indentation for readability
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return string(jsonBytes), nil
}

// buildReport constructs the complete SARIF report structure. The mapper and
// ruleManager are per-call (constructed in Format) so the rules array reflects
// only this report's matches.
func (f *Formatter) buildReport(mapper *VulnerabilityMapper, ruleManager *RuleManager, matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) *SARIFReport {
	// Convert matches to SARIF results
	var results []SARIFResult

	// Process active matches
	for _, match := range matches {
		result, err := mapper.MapToSARIFResult(match, options)
		if err != nil {
			// Log error but continue processing other matches
			// In production, you might want to use a proper logger here
			continue
		}
		results = append(results, *result)
	}

	// Process suppressed matches
	for _, suppressed := range suppressedMatches {
		result, err := mapper.MapSuppressedMatch(suppressed, options)
		if err != nil {
			// Log error but continue processing other matches
			continue
		}
		results = append(results, *result)
	}

	// Build tool driver with metadata and rules
	driver := f.buildDriver(ruleManager)

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

// buildDriver constructs the SARIF tool driver with metadata and rules from the
// per-call ruleManager.
func (f *Formatter) buildDriver(ruleManager *RuleManager) SARIFDriver {
	// Get version information
	versionStr := version.Short()

	// Collect all rules that were encountered during processing
	rules := ruleManager.GetAllRules()

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
