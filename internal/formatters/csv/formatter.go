// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package csv

import (
	"encoding/json"
	"fmt"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/formatters/shared"
)

// Formatter implements CSV output formatting
type Formatter struct{}

// NewFormatter creates a new CSV formatter
func NewFormatter() *Formatter {
	return &Formatter{}
}

func (f *Formatter) Name() string {
	return "csv"
}

func (f *Formatter) Description() string {
	return "Comma-separated values for spreadsheet import"
}

func (f *Formatter) FileExtension() string {
	return ".csv"
}

func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	// Filter matches by confidence level using shared logic
	filteredMatches := shared.FilterMatchesByConfidence(matches, options)

	// In pre-commit mode, return empty string if no matches to reduce noise
	if options.PrecommitMode && len(filteredMatches) == 0 && len(suppressedMatches) == 0 {
		return "", nil
	}

	// Create CSV headers - simplified for pre-commit mode
	var headers []string
	if options.PrecommitMode {
		headers = []string{"File", "Issue", "Line", "Confidence"}
	} else {
		headers = []string{"Filename", "Type", "Confidence Level", "Confidence %", "Line Number", "Text"}
		if options.Verbose {
			headers = append(headers, "Metadata")
		}
	}

	// Start with header row
	csvRows := []string{strings.Join(headers, ",")}

	// Process regular matches
	for _, match := range filteredMatches {
		row := f.createCSVRow(match, options, false)
		csvRows = append(csvRows, row)
	}

	// Process suppressed matches if provided (skip in pre-commit mode for brevity)
	if !options.PrecommitMode {
		for _, suppressed := range suppressedMatches {
			row := f.createCSVRow(suppressed.Match, options, true)
			csvRows = append(csvRows, row)
		}
	}

	return strings.Join(csvRows, "\n"), nil
}

// createCSVRow creates a CSV row for a match
func (f *Formatter) createCSVRow(match detector.Match, options formatters.FormatterOptions, suppressed bool) string {
	// Get confidence level using shared logic
	confidenceLevel := shared.GetConfidenceLevel(match.Confidence)
	if suppressed {
		confidenceLevel = "SUPPRESSED"
	}

	var row []string

	if options.PrecommitMode {
		// Simplified format for pre-commit: File, Issue, Line, Confidence
		issueDesc := f.getPrecommitIssueDescription(match)
		row = []string{
			f.escapeCSVField(f.getSmartFilename(match.Filename)),
			f.escapeCSVField(issueDesc),
			fmt.Sprintf("%d", match.LineNumber),
			f.escapeCSVField(confidenceLevel),
		}
	} else {
		// Full format for normal mode
		// Determine display text based on ShowMatch option
		displayText := "[REDACTED]"
		if options.ShowMatch {
			displayText = match.Text
		}

		row = []string{
			f.escapeCSVField(match.Filename),
			f.escapeCSVField(match.Type),
			f.escapeCSVField(confidenceLevel),
			fmt.Sprintf("%.1f", match.Confidence),
			fmt.Sprintf("%d", match.LineNumber),
			f.escapeCSVField(displayText),
		}

		// Add metadata if verbose mode is enabled
		if options.Verbose && match.Metadata != nil {
			metadataJSON, err := json.Marshal(match.Metadata)
			if err != nil {
				row = append(row, f.escapeCSVField("Error serializing metadata"))
			} else {
				row = append(row, f.escapeCSVField(string(metadataJSON)))
			}
		}
	}

	return strings.Join(row, ",")
}

// getPrecommitIssueDescription returns a concise description for pre-commit CSV output
func (f *Formatter) getPrecommitIssueDescription(match detector.Match) string {
	switch match.Type {
	case "CREDIT_CARD":
		return "Credit card number"
	case "SSN":
		return "Social Security Number"
	case "PASSPORT":
		return "Passport number"
	case "EMAIL":
		return "Email address"
	case "PHONE":
		return "Phone number"
	case "IP_ADDRESS":
		return "IP address"
	case "SECRETS":
		return "API key/secret"
	case "INTELLECTUAL_PROPERTY":
		return "IP notice"
	case "SOCIAL_MEDIA":
		return "Social media handle"
	default:
		return strings.ReplaceAll(match.Type, "_", " ")
	}
}

// getSmartFilename returns a simplified filename for pre-commit output
func (f *Formatter) getSmartFilename(fullPath string) string {
	// Handle embedded media paths
	if strings.Contains(fullPath, " -> ") {
		return fullPath
	}

	if !strings.Contains(fullPath, "/") {
		return fullPath
	}

	parts := strings.Split(fullPath, "/")
	return parts[len(parts)-1] // Return just the basename
}

// escapeCSVField properly escapes a field for CSV format and prevents CSV injection
func (f *Formatter) escapeCSVField(field string) string {
	// Prevent CSV injection by sanitizing formula characters
	field = f.sanitizeFormulaInjection(field)

	// If field contains comma, quote, or newline, wrap in quotes and escape internal quotes
	if strings.Contains(field, ",") || strings.Contains(field, "\"") || strings.Contains(field, "\n") || strings.Contains(field, "\r") {
		// Escape internal quotes by doubling them
		escaped := strings.ReplaceAll(field, "\"", "\"\"")
		return fmt.Sprintf("\"%s\"", escaped)
	}
	return field
}

// sanitizeFormulaInjection prevents CSV injection attacks by sanitizing formula characters
func (f *Formatter) sanitizeFormulaInjection(field string) string {
	if len(field) == 0 {
		return field
	}

	// Check if field starts with formula characters that could be dangerous in spreadsheets
	// Using direct byte comparisons for optimal performance
	firstChar := field[0]
	if firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@' {
		// Prefix with single quote to prevent formula execution
		// This is a standard technique to neutralize CSV injection
		return "'" + field
	}

	return field
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
