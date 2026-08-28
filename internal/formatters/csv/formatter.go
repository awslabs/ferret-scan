// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package csv

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
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

	// Give the rows the shared total order. Safe to sort in place: the filter
	// above returned a fresh slice, so the caller's slice is untouched.
	shared.SortMatchesByPriority(filteredMatches)

	// Suppressed rows need the same total order as active ones; without it the
	// suppressed block's row order followed worker completion order and so
	// changed run to run on an unchanged scan.
	shared.SortSuppressedByPriority(suppressedMatches)

	// Honor --limit, after the sort so the rows kept are the highest-confidence
	// ones. Without this the CSV emitted every finding while the same scan's
	// text and JSON output stopped at the cap.
	filteredMatches, _, _ = shared.ApplyLimit(filteredMatches, options)

	// In pre-commit mode, return empty string if no matches to reduce noise
	if options.PrecommitMode && !options.OutputToFile &&
		len(filteredMatches) == 0 && len(suppressedMatches) == 0 {
		return "", nil
	}

	// Create CSV headers - simplified for pre-commit mode
	var headers []string
	if options.PrecommitMode {
		headers = []string{"File", "Issue", "Line", "Confidence"}
	} else {
		headers = []string{"Filename", "Type", "Confidence Level", "Confidence %", "Line Number", "Text"}
		// The redaction disclosure, per FINDING rather than per file.
		//
		// CSV's grain is one row per finding, and every unredacted value HAS a row by
		// construction — the disclosure counts reported values. So the per-row form is
		// COMPLETE here, unlike the not-examined disclosure, where a file with no
		// findings has no row to carry it and CSV therefore still says nothing. That
		// asymmetry is deliberate and documented rather than papered over with a
		// pseudo-row: a row that is not a finding breaks row counts and any grouping
		// by Type.
		//
		// Present only when redaction was REQUESTED, which is the same convention this
		// formatter already uses for --verbose adding Metadata: the header varies with
		// the invocation, not with the data. A consumer runs a fixed command, so its
		// header is stable; and a read-only scan is not made to carry two columns that
		// could only ever say "n/a".
		//
		// Placed BEFORE the optional Metadata column so these two are always at fixed
		// positions. Metadata is appended only when non-nil, so appending after it
		// would put these fields at a position that varies with the row's content.
		if options.RedactionRequested {
			headers = append(headers, "Redacted", "Not Redacted Reason")
		}
		if options.Verbose {
			headers = append(headers, "Metadata")
		}
	}

	// Built once rather than per row: the per-finding columns below need a path lookup,
	// and recomputing it inside the row builder would make the formatter quadratic in
	// (findings x unredacted files) on exactly the input where both are large.
	unredactedByPath := formatters.UnredactedPaths(options.Unredacted)

	// Start with header row
	csvRows := []string{strings.Join(headers, ",")}

	// Process regular matches
	for _, match := range filteredMatches {
		row := f.createCSVRow(match, options, unredactedByPath, false)
		csvRows = append(csvRows, row)
	}

	// Process suppressed matches if provided (skip in pre-commit mode for brevity)
	if !options.PrecommitMode {
		for _, suppressed := range suppressedMatches {
			row := f.createCSVRow(suppressed.Match, options, unredactedByPath, true)
			csvRows = append(csvRows, row)
		}
	}

	return strings.Join(csvRows, "\n"), nil
}

// createCSVRow creates a CSV row for a match
func (f *Formatter) createCSVRow(match detector.Match, options formatters.FormatterOptions, unredactedByPath map[string]formatters.UnredactedFile, suppressed bool) string {
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
		displayText := "[HIDDEN]"
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

		// Whether THIS finding's value was written out redacted. Emitted only when
		// redaction was requested, so the row width always matches the header.
		if options.RedactionRequested {
			redacted, reason := "true", ""
			if uf, ok := unredactedByPath[match.Filename]; ok {
				redacted = "false"
				reason = uf.Cause.String()
			}
			row = append(row, f.escapeCSVField(redacted), f.escapeCSVField(reason))
		}

		// Add metadata if verbose mode is enabled. Run it through the shared
		// sanitizer first: when ShowMatch is false this redacts any metadata
		// value that embeds the raw matched text (e.g. name_components,
		// full_field), so --verbose CSV can't leak what displayText hid.
		if options.Verbose {
			sanitized := shared.SanitizeMetadata(match.Metadata, match.Text, options.ShowMatch)
			if sanitized != nil {
				metadataJSON, err := json.Marshal(sanitized)
				if err != nil {
					row = append(row, f.escapeCSVField("Error serializing metadata"))
				} else {
					row = append(row, f.escapeCSVField(string(metadataJSON)))
				}
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
	case "VIN":
		return "Vehicle Identification Number"
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
	// Escape control bytes. A filename comes from the scanned tree, and RFC 4180 quoting
	// passes a control byte straight through — it sits happily inside the quotes — so a csv
	// report of a directory containing a name like "quarterly-report.txt\x1b[2K\r" loses
	// that row when the report is read in a terminal, which is at least as common as
	// opening it in a spreadsheet (#381).
	//
	// Placed before sanitizeFormulaInjection for readability only; the two are independent.
	// A mutation swapping them survived, and enumerating the cases confirms why: escaping
	// can only ever produce a field beginning with a backslash, which is not a formula
	// trigger, so it cannot create one. The orders differ on a tab/CR/LF-prefixed field,
	// where running the guard first adds a leading quote that is no longer needed once the
	// prefix is an escape sequence. Neither order is unsafe, so no ordering claim is made.
	field = shared.SanitizeDisplayText(field)

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

	// Check if field starts with formula characters that could be dangerous in spreadsheets.
	// Covers: standard formula triggers (=, +, -, @), tab-prefixed formulas (\t),
	// and Unicode direction overrides that can hide malicious content.
	firstChar := field[0]
	if firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@' || firstChar == '\t' || firstChar == '\r' || firstChar == '\n' {
		return "'" + field
	}

	// Block Unicode direction override characters (U+202A-U+202E, U+2066-U+2069)
	// that can be used to visually hide formula injection
	for _, r := range field {
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return "'" + field
		}
		break // only check first rune
	}

	return field
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
