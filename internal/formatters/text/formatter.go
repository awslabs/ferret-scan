// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"

	"github.com/fatih/color"
)

// Formatter implements text-based output formatting
type Formatter struct {
	colors map[string]*color.Color
}

// NewFormatter creates a new text formatter
func NewFormatter() *Formatter {
	return &Formatter{
		colors: map[string]*color.Color{
			"green":   color.New(color.FgGreen),
			"yellow":  color.New(color.FgYellow),
			"red":     color.New(color.FgRed),
			"cyan":    color.New(color.FgCyan),
			"magenta": color.New(color.FgMagenta),
			"blue":    color.New(color.FgBlue),
			"white":   color.New(color.FgWhite, color.Bold),
		},
	}
}

// displayMatchText returns the text to print for a match's value, honoring the
// ShowMatch redaction control. The raw matched value is revealed ONLY when
// --show-match is set; --verbose controls how much detail/structure is shown,
// not whether the secret is exposed. Every site that would otherwise print
// match.Text must go through this helper so verbose output cannot re-leak a
// value that ShowMatch is meant to hide.
func displayMatchText(match detector.Match, options formatters.FormatterOptions) string {
	if !options.ShowMatch {
		return "[HIDDEN]"
	}
	return match.Text
}

func (f *Formatter) Name() string {
	return "text"
}

func (f *Formatter) Description() string {
	return "Human-readable text output with colors and tables"
}

func (f *Formatter) FileExtension() string {
	return ".txt"
}

func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	// Disable colors if requested
	if options.NoColor {
		color.NoColor = true
	}

	// Check if we're in pre-commit mode for optimized output
	isPrecommitMode := f.isPrecommitMode(options)

	if len(matches) == 0 {
		if len(suppressedMatches) > 0 {
			if isPrecommitMode {
				return f.formatPrecommitOutput([]detector.Match{}, suppressedMatches, options), nil
			}
			return f.formatTextWithSuppressed([]detector.Match{}, suppressedMatches, options), nil
		}
		if isPrecommitMode {
			return "", nil // Silent success in pre-commit mode when no matches
		}
		return "No matches found.", nil
	}

	// Filter matches by confidence level
	filteredMatches := f.filterMatchesByConfidence(matches, options)
	if len(filteredMatches) == 0 {
		if len(suppressedMatches) > 0 {
			if isPrecommitMode {
				return f.formatPrecommitOutput([]detector.Match{}, suppressedMatches, options), nil
			}
			return f.formatTextWithSuppressed([]detector.Match{}, suppressedMatches, options), nil
		}
		if isPrecommitMode {
			return "", nil // Silent success in pre-commit mode when no matches at specified levels
		}
		return "No matches found at the specified confidence levels.", nil
	}

	// Sort by confidence descending, then type ascending for priority ordering
	f.sortMatchesByPriority(filteredMatches)

	if isPrecommitMode {
		return f.formatPrecommitOutput(filteredMatches, suppressedMatches, options), nil
	}

	// Determine output writer: stream directly if StreamWriter is set,
	// otherwise buffer into a strings.Builder.
	var w io.Writer
	if options.StreamWriter != nil {
		w = options.StreamWriter
	} else {
		w = &strings.Builder{}
	}

	f.writeFormattedOutput(w, filteredMatches, suppressedMatches, options)

	// If streaming, content was already written — return empty string.
	if options.StreamWriter != nil {
		return "", nil
	}
	return w.(*strings.Builder).String(), nil
}

// sortMatchesByPriority sorts matches by confidence descending, then type ascending.
func (f *Formatter) sortMatchesByPriority(matches []detector.Match) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].Type < matches[j].Type
	})
}

// writeFormattedOutput writes the formatted text output to the given writer,
// applying limit truncation and summary header/footer.
func (f *Formatter) writeFormattedOutput(w io.Writer, matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) {
	totalFindings := len(matches)

	// Apply limit: determine how many findings to show
	limit := options.Limit
	truncated := false
	displayMatches := matches
	if limit > 0 && totalFindings > limit {
		displayMatches = matches[:limit]
		truncated = true
	}

	// Add headers for non-verbose mode
	if !options.Verbose && (len(displayMatches) > 0 || len(suppressedMatches) > 0) {
		f.appendHeaders(w, displayMatches, options)
	}

	// Display findings
	for _, match := range displayMatches {
		confidenceLevel := f.getConfidenceLevel(match.Confidence)

		if !options.Verbose {
			f.appendSummaryLine(w, match, confidenceLevel, displayMatches, false, options)
			continue
		}

		f.appendDetailedMatch(w, match, confidenceLevel, options)
	}

	// Display suppressed findings if provided
	if len(suppressedMatches) > 0 {
		for _, suppressed := range suppressedMatches {
			match := suppressed.Match
			confidenceLevel := f.getConfidenceLevel(match.Confidence)

			if !options.Verbose {
				f.appendSummaryLine(w, match, confidenceLevel, displayMatches, true, options)
				continue
			}

			f.appendDetailedSuppressedMatch(w, suppressed, confidenceLevel, options)
		}
	}

	// Print truncation footer
	if truncated {
		remaining := totalFindings - limit
		footer := fmt.Sprintf("\n... and %d more findings (use --limit 0 to show all)\n", remaining)
		fmt.Fprint(w, footer)
	}

	// Print summary footer when stats are available
	if options.Stats != nil {
		f.writeSummaryHeader(w, options)
	}
}

// writeSummaryHeader writes the scan summary block to the writer.
func (f *Formatter) writeSummaryHeader(w io.Writer, options formatters.FormatterOptions) {
	stats := options.Stats
	topLine := "\n═══ Scan Summary ═══════════════════════════════════════════════════════════════\n"
	bottomLine := "════════════════════════════════════════════════════════════════════════════════\n"

	summaryLine := fmt.Sprintf("Files: %d processed, %d skipped | Findings: %d (%d high, %d medium, %d low)",
		stats.FilesProcessed, stats.FilesSkipped,
		stats.TotalFindings, stats.High, stats.Medium, stats.Low)
	if stats.Suppressed > 0 {
		summaryLine += fmt.Sprintf(" | %d suppressed", stats.Suppressed)
	}

	fmt.Fprint(w, topLine)
	fmt.Fprintln(w, summaryLine)
	fmt.Fprintln(w, bottomLine)
}

// filterMatchesByConfidence filters matches based on confidence level settings
func (f *Formatter) filterMatchesByConfidence(matches []detector.Match, options formatters.FormatterOptions) []detector.Match {
	var filtered []detector.Match
	for _, match := range matches {
		if (match.Confidence >= 90 && options.ConfidenceLevel["high"]) ||
			(match.Confidence >= 60 && match.Confidence < 90 && options.ConfidenceLevel["medium"]) ||
			(match.Confidence < 60 && options.ConfidenceLevel["low"]) {
			filtered = append(filtered, match)
		}
	}
	return filtered
}

// formatTextWithSuppressed formats matches and suppressed findings as text output
func (f *Formatter) formatTextWithSuppressed(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) string {
	var builder strings.Builder
	f.writeFormattedOutput(&builder, matches, suppressedMatches, options)
	return builder.String()
}

// appendHeaders adds column headers to the writer
func (f *Formatter) appendHeaders(w io.Writer, matches []detector.Match, options formatters.FormatterOptions) {
	matchWidth := f.calculateMatchColumnWidth(matches, options)
	headerStr := fmt.Sprintf("%-8s %-12s %-20s %-8s %-10s %-*s %s\n",
		"LEVEL", "VALIDATOR", "TYPE", "CONF%", "LINE", matchWidth, "MATCH", "FILE")
	if !options.NoColor {
		headerStr = f.colors["white"].Sprintf("%-8s %-12s %-20s %-8s %-10s %-*s %s\n",
			"LEVEL", "VALIDATOR", "TYPE", "CONF%", "LINE", matchWidth, "MATCH", "FILE")
	}
	io.WriteString(w, headerStr)

	// Add separator line with dynamic width
	totalWidth := 8 + 1 + 12 + 1 + 20 + 1 + 8 + 1 + 10 + 1 + matchWidth + 1 + 10 // approximate
	separator := strings.Repeat("-", totalWidth) + "\n"
	if !options.NoColor {
		separator = f.colors["white"].Sprint(strings.Repeat("-", totalWidth) + "\n")
	}
	io.WriteString(w, separator)
}

// calculateMatchColumnWidth calculates the optimal width for the match column
func (f *Formatter) calculateMatchColumnWidth(matches []detector.Match, options formatters.FormatterOptions) int {
	maxWidth := 10 // Minimum width for "[HIDDEN]"
	for _, match := range matches {
		if options.ShowMatch {
			matchText := strings.ReplaceAll(match.Text, "\n", " ")
			matchText = strings.ReplaceAll(matchText, "\t", " ")
			runeCount := len([]rune(matchText))
			if runeCount > maxWidth {
				maxWidth = runeCount
			}
		}
	}
	// Cap at 30 characters for readability
	if maxWidth > 30 {
		maxWidth = 30
	}
	return maxWidth
}

// appendSummaryLine adds a single line summary to the writer
func (f *Formatter) appendSummaryLine(w io.Writer, match detector.Match, confidenceLevel string, allMatches []detector.Match, suppressed bool, options formatters.FormatterOptions) {
	// Get the appropriate color for the confidence level
	var levelColor *color.Color
	if suppressed {
		// Use dimmed colors for suppressed findings
		levelColor = f.colors["white"] // Dimmed appearance
	} else {
		switch confidenceLevel {
		case "HIGH":
			levelColor = f.colors["red"]
		case "MEDIUM":
			levelColor = f.colors["yellow"]
		case "LOW":
			levelColor = f.colors["green"]
		}
	}

	// Format confidence level (fixed width)
	var levelStr string
	if suppressed {
		levelStr = fmt.Sprintf("[%-6s]", "SUPP")
		if !options.NoColor {
			levelStr = f.colors["white"].Sprintf("[%-6s]", "SUPP")
		}
	} else {
		levelStr = fmt.Sprintf("[%-6s]", confidenceLevel)
		if !options.NoColor {
			levelStr = levelColor.Sprintf("[%-6s]", confidenceLevel)
		}
	}

	// Format type (fixed width, with smart truncation)
	typeDisplay := match.Type
	// For INTELLECTUAL_PROPERTY, show the specific sub-type (copyright, patent, etc.)
	if match.Type == "INTELLECTUAL_PROPERTY" && match.Metadata != nil {
		if ipType, ok := match.Metadata["ip_type"].(string); ok && ipType != "" {
			typeDisplay = strings.ToUpper(ipType)
		} else if ipTypes, ok := match.Metadata["ip_types"].([]string); ok && len(ipTypes) > 0 {
			typeDisplay = strings.ToUpper(ipTypes[0])
			if len(ipTypes) > 1 {
				typeDisplay += fmt.Sprintf("+%d", len(ipTypes)-1)
			}
		}
	}
	if len(typeDisplay) > 20 {
		typeDisplay = typeDisplay[:17] + "..."
	}
	typeStr := fmt.Sprintf("%-20s", typeDisplay)
	if !options.NoColor {
		typeStr = f.colors["cyan"].Sprintf("%-20s", typeDisplay)
	}

	// Format confidence percentage (fixed width)
	confidenceStr := fmt.Sprintf("%7.2f%%", match.Confidence)
	if !options.NoColor {
		confidenceStr = f.colors["blue"].Sprintf("%7.2f%%", match.Confidence)
	}

	// Format line number (fixed width, right-aligned)
	lineStr := fmt.Sprintf("line %5d", match.LineNumber)
	if !options.NoColor {
		lineStr = f.colors["magenta"].Sprintf("line %5d", match.LineNumber)
	}

	// Format validator name (fixed width)
	validatorName := match.Validator
	if len(validatorName) > 12 {
		validatorName = validatorName[:9] + "..."
	}
	validatorStr := fmt.Sprintf("%-12s", validatorName)
	if !options.NoColor {
		validatorStr = f.colors["green"].Sprintf("%-12s", validatorName)
	}

	// Show match text (dynamic width for alignment). Revealed only when
	// ShowMatch is set; --verbose alone must not expose the value.
	targetWidth := f.calculateMatchColumnWidth(allMatches, options)
	matchText := displayMatchText(match, options)
	if options.ShowMatch {
		matchText = strings.ReplaceAll(matchText, "\n", " ")
		matchText = strings.ReplaceAll(matchText, "\t", " ")

		// For metadata fields, extract just the value part to avoid redundancy with TYPE column
		if match.Validator == "metadata" && strings.Contains(matchText, ":") {
			parts := strings.SplitN(matchText, ":", 2)
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				if value != "" {
					matchText = value
				}
			}
		}

		// Truncate if needed for consistent alignment using rune count
		runes := []rune(matchText)
		if len(runes) > targetWidth {
			matchText = string(runes[:targetWidth-3]) + "..."
		}
	}
	// Ensure exactly targetWidth visible characters by padding with spaces
	runeCount := len([]rune(matchText))
	padding := targetWidth - runeCount
	if padding > 0 {
		matchText += strings.Repeat(" ", padding)
	}
	matchStr := matchText

	// Format filename with smart path display
	filename := f.getSmartFilename(match.Filename, allMatches)
	filenameStr := filename
	if !options.NoColor {
		filenameStr = f.colors["white"].Sprint(filename)
	}

	// Output in columnar format with better spacing
	fmt.Fprintf(w, "%s %s %s %s %s %s %s\n",
		levelStr,
		validatorStr,
		typeStr,
		confidenceStr,
		lineStr,
		matchStr,
		filenameStr)
}

// appendDetailedMatch adds detailed match information to the writer
func (f *Formatter) appendDetailedMatch(w io.Writer, match detector.Match, confidenceLevel string, options formatters.FormatterOptions) {
	// Title with color
	if !options.NoColor {
		f.colors["white"].Fprintf(w, "=== Match Details ===\n")
	} else {
		fmt.Fprintf(w, "=== Match Details ===\n")
	}

	// Match text with filename and line number. The value is shown only when
	// ShowMatch is set; verbose detail must not expose a hidden secret.
	shownText := displayMatchText(match, options)
	if !options.NoColor {
		f.colors["cyan"].Fprintf(w, "Match found in ")
		f.colors["white"].Fprintf(w, "%s", match.Filename)
		f.colors["cyan"].Fprintf(w, " on ")
		f.colors["magenta"].Fprintf(w, "line %d", match.LineNumber)
		f.colors["cyan"].Fprintf(w, ": %s\n", shownText)
	} else {
		fmt.Fprintf(w, "Match found in %s on line %d: %s\n", match.Filename, match.LineNumber, shownText)
	}

	// Type
	if !options.NoColor {
		f.colors["cyan"].Fprintf(w, "Type: ")
		f.colors["white"].Fprintf(w, "%s\n", match.Type)
	} else {
		fmt.Fprintf(w, "Type: %s\n", match.Type)
	}

	// Vendor (if available)
	if vendor, ok := match.Metadata["vendor"].(string); ok {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Vendor: ")
			f.colors["white"].Fprintf(w, "%s\n", vendor)
		} else {
			fmt.Fprintf(w, "Vendor: %s\n", vendor)
		}
	}

	// Country (if available)
	if country, ok := match.Metadata["country"].(string); ok {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Country: ")
			f.colors["white"].Fprintf(w, "%s\n", country)
		} else {
			fmt.Fprintf(w, "Country: %s\n", country)
		}
	}

	// Format (if available)
	if format, ok := match.Metadata["format"].(string); ok {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Format: ")
			f.colors["white"].Fprintf(w, "%s\n", format)
		} else {
			fmt.Fprintf(w, "Format: %s\n", format)
		}
	}

	// Confidence level
	var levelColor *color.Color
	switch confidenceLevel {
	case "HIGH":
		levelColor = f.colors["red"]
	case "MEDIUM":
		levelColor = f.colors["yellow"]
	case "LOW":
		levelColor = f.colors["green"]
	}

	if !options.NoColor {
		f.colors["cyan"].Fprintf(w, "Confidence level: ")
		f.colors["white"].Fprintf(w, "%.2f%% ", match.Confidence)
		levelColor.Fprintf(w, "(%s)\n", confidenceLevel)
	} else {
		fmt.Fprintf(w, "Confidence level: %.2f%% (%s)\n", match.Confidence, confidenceLevel)
	}

	// Context impact (if available)
	if impact, ok := match.Metadata["context_impact"].(float64); ok {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Context impact: ")
			if impact > 0 {
				f.colors["green"].Fprintf(w, "+%.2f%%\n", impact)
			} else if impact < 0 {
				f.colors["red"].Fprintf(w, "%.2f%%\n", impact)
			} else {
				f.colors["white"].Fprintf(w, "0.00%%\n")
			}
		} else {
			if impact > 0 {
				fmt.Fprintf(w, "Context impact: +%.2f%%\n", impact)
			} else {
				fmt.Fprintf(w, "Context impact: %.2f%%\n", impact)
			}
		}
	}

	// Validation checks
	if checks, ok := match.Metadata["validation_checks"].(map[string]bool); ok {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Validation results:\n")
		} else {
			fmt.Fprintf(w, "Validation results:\n")
		}

		for check, result := range checks {
			checkName := f.formatCheckName(check)
			if !options.NoColor {
				fmt.Fprintf(w, "- %s: ", checkName)
				if result {
					f.colors["green"].Fprintf(w, "true\n")
				} else {
					f.colors["red"].Fprintf(w, "false\n")
				}
			} else {
				fmt.Fprintf(w, "- %s: %v\n", checkName, result)
			}
		}
	}

	// Context keywords
	if len(match.Context.PositiveKeywords) > 0 || len(match.Context.NegativeKeywords) > 0 {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Context analysis:\n")
		} else {
			fmt.Fprintf(w, "Context analysis:\n")
		}

		// Positive keywords
		if len(match.Context.PositiveKeywords) > 0 {
			if !options.NoColor {
				fmt.Fprintf(w, "- Supporting keywords: ")
				f.colors["green"].Fprintf(w, "%s\n", strings.Join(match.Context.PositiveKeywords, ", "))
			} else {
				fmt.Fprintf(w, "- Supporting keywords: %s\n", strings.Join(match.Context.PositiveKeywords, ", "))
			}
		}

		// Negative keywords
		if len(match.Context.NegativeKeywords) > 0 {
			if !options.NoColor {
				fmt.Fprintf(w, "- Contradicting keywords: ")
				f.colors["red"].Fprintf(w, "%s\n", strings.Join(match.Context.NegativeKeywords, ", "))
			} else {
				fmt.Fprintf(w, "- Contradicting keywords: %s\n", strings.Join(match.Context.NegativeKeywords, ", "))
			}
		}
	}

	// Show context snippet if available and verbose mode is on. Gated on
	// ShowMatch too: the snippet prints the raw before/[match]/after text, so
	// emitting it when ShowMatch is false would re-leak the secret that hiding
	// is meant to suppress (consistent with the JSON/YAML/SARIF/JUnit formatters).
	if options.Verbose && options.ShowMatch && (match.Context.BeforeText != "" || match.Context.AfterText != "") {
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Context snippet:\n")
			if match.Context.BeforeText != "" {
				fmt.Fprintf(w, "... %s", match.Context.BeforeText)
			}
			f.colors["yellow"].Fprintf(w, "[%s]", match.Text)
			if match.Context.AfterText != "" {
				fmt.Fprintf(w, "%s ...\n", match.Context.AfterText)
			} else {
				fmt.Fprintln(w)
			}
		} else {
			fmt.Fprintf(w, "Context snippet:\n")
			fmt.Fprintf(w, "... %s[%s]%s ...\n",
				match.Context.BeforeText,
				match.Text,
				match.Context.AfterText)
		}
	}

	// Advisory explanation (present only when scanned with --explain).
	f.appendExplanation(w, match, options)

	fmt.Fprintln(w)
}

// appendExplanation renders the advisory explanation attached by the
// --explain pass, if present. It is purely additive narrative — no payload
// bytes, no effect on confidence or suppression.
func (f *Formatter) appendExplanation(w io.Writer, match detector.Match, options formatters.FormatterOptions) {
	ex, ok := explain.FromMatch(match)
	if !ok {
		return
	}
	if !options.NoColor {
		f.colors["cyan"].Fprintf(w, "Explanation:\n")
		fmt.Fprintf(w, "- Why: %s\n", ex.Rationale)
		fmt.Fprintf(w, "- Verdict: ")
		switch ex.Verdict {
		case explain.VerdictLikelyReal:
			f.colors["red"].Fprintf(w, "%s\n", ex.Verdict)
		case explain.VerdictLikelyTest:
			f.colors["green"].Fprintf(w, "%s\n", ex.Verdict)
		default:
			f.colors["yellow"].Fprintf(w, "%s\n", ex.Verdict)
		}
		if ex.DraftSuppressReason != "" {
			fmt.Fprintf(w, "- Suggested suppression reason: %s\n", ex.DraftSuppressReason)
		}
	} else {
		fmt.Fprintf(w, "Explanation:\n")
		fmt.Fprintf(w, "- Why: %s\n", ex.Rationale)
		fmt.Fprintf(w, "- Verdict: %s\n", ex.Verdict)
		if ex.DraftSuppressReason != "" {
			fmt.Fprintf(w, "- Suggested suppression reason: %s\n", ex.DraftSuppressReason)
		}
	}
}

// appendDetailedSuppressedMatch adds detailed suppressed match information to the writer
func (f *Formatter) appendDetailedSuppressedMatch(w io.Writer, suppressed detector.SuppressedMatch, confidenceLevel string, options formatters.FormatterOptions) {
	match := suppressed.Match

	// Title with color
	if !options.NoColor {
		f.colors["white"].Fprintf(w, "=== Suppressed Match Details ===\n")
	} else {
		fmt.Fprintf(w, "=== Suppressed Match Details ===\n")
	}

	// Match text with filename and line number. Shown only when ShowMatch is set.
	shownText := displayMatchText(match, options)
	if !options.NoColor {
		f.colors["cyan"].Fprintf(w, "Suppressed match found in ")
		f.colors["white"].Fprintf(w, "%s", match.Filename)
		f.colors["cyan"].Fprintf(w, " on ")
		f.colors["magenta"].Fprintf(w, "line %d", match.LineNumber)
		f.colors["cyan"].Fprintf(w, ": %s\n", shownText)
	} else {
		fmt.Fprintf(w, "Suppressed match found in %s on line %d: %s\n", match.Filename, match.LineNumber, shownText)
	}

	// Suppression info
	if !options.NoColor {
		f.colors["cyan"].Fprintf(w, "Suppressed by: ")
		f.colors["white"].Fprintf(w, "%s\n", suppressed.SuppressedBy)
		f.colors["cyan"].Fprintf(w, "Reason: ")
		f.colors["white"].Fprintf(w, "%s\n", suppressed.RuleReason)
	} else {
		fmt.Fprintf(w, "Suppressed by: %s\n", suppressed.SuppressedBy)
		fmt.Fprintf(w, "Reason: %s\n", suppressed.RuleReason)
	}

	// Expiration info
	if suppressed.ExpiresAt != nil {
		expirationStatus := f.formatExpirationStatus(suppressed.ExpiresAt, suppressed.Expired)
		if !options.NoColor {
			f.colors["cyan"].Fprintf(w, "Expiration: ")
			if suppressed.Expired {
				f.colors["red"].Fprintf(w, "%s\n", expirationStatus)
			} else {
				f.colors["white"].Fprintf(w, "%s\n", expirationStatus)
			}
		} else {
			fmt.Fprintf(w, "Expiration: %s\n", expirationStatus)
		}
	}

	// Original match details (dimmed)
	f.appendDetailedMatch(w, match, confidenceLevel, options)
}

// formatCheckName formats a check name from snake_case to Title Case
func (f *Formatter) formatCheckName(check string) string {
	words := strings.Split(check, "_")
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

// sortMatches sorts matches by confidence level (HIGH, MEDIUM, LOW) and then by confidence score
func (f *Formatter) sortMatches(matches []detector.Match) {
	// Sort using a custom comparison function
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			// Get confidence levels
			level1 := f.getConfidenceLevel(matches[i].Confidence)
			level2 := f.getConfidenceLevel(matches[j].Confidence)

			// Define level priority (lower number = higher priority)
			levelPriority := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}

			// Compare by level first
			if levelPriority[level1] > levelPriority[level2] {
				// Swap if level1 has lower priority than level2
				matches[i], matches[j] = matches[j], matches[i]
			} else if levelPriority[level1] == levelPriority[level2] {
				// Same level, sort by confidence score (higher first)
				if matches[i].Confidence < matches[j].Confidence {
					matches[i], matches[j] = matches[j], matches[i]
				}
			}
		}
	}
}

// getSmartFilename returns a smart filename that avoids conflicts
func (f *Formatter) getSmartFilename(fullPath string, allMatches []detector.Match) string {
	// Handle embedded media paths (format: "originalfile.pptx -> image.png")
	if strings.Contains(fullPath, " -> ") {
		return fullPath // Return embedded media path as-is
	}

	if !strings.Contains(fullPath, "/") {
		return fullPath // No path separators, return as-is
	}

	parts := strings.Split(fullPath, "/")
	basename := parts[len(parts)-1]

	// Check if any other files have the same basename
	conflicts := false
	for _, match := range allMatches {
		if match.Filename != fullPath && strings.Contains(match.Filename, "/") {
			otherParts := strings.Split(match.Filename, "/")
			otherBasename := otherParts[len(otherParts)-1]
			if basename == otherBasename {
				conflicts = true
				break
			}
		}
	}

	// If no conflicts, return basename only
	if !conflicts {
		return basename
	}

	// If conflicts exist, return parent/basename
	if len(parts) >= 2 {
		parent := parts[len(parts)-2]
		return parent + "/" + basename
	}

	return basename
}

// getConfidenceLevel returns the confidence level as a string
func (f *Formatter) getConfidenceLevel(confidence float64) string {
	switch {
	case confidence >= 90:
		return "HIGH"
	case confidence >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// formatExpirationStatus returns a human-readable expiration status
func (f *Formatter) formatExpirationStatus(expiresAt *time.Time, expired bool) string {
	if expiresAt == nil {
		return "never expires"
	}

	if expired {
		daysAgo := int(time.Since(*expiresAt).Hours() / 24)
		if daysAgo == 0 {
			return "expired today"
		} else if daysAgo == 1 {
			return "expired 1 day ago"
		} else {
			return fmt.Sprintf("expired %d days ago", daysAgo)
		}
	}

	daysUntil := int(time.Until(*expiresAt).Hours() / 24)
	if daysUntil == 0 {
		return "expires today"
	} else if daysUntil == 1 {
		return "expires in 1 day"
	} else {
		return fmt.Sprintf("expires in %d days", daysUntil)
	}
}

// isPrecommitMode detects if we're running in pre-commit mode based on formatter options
func (f *Formatter) isPrecommitMode(options formatters.FormatterOptions) bool {
	return options.PrecommitMode
}

// formatPrecommitOutput formats output optimized for pre-commit workflows
func (f *Formatter) formatPrecommitOutput(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) string {
	if len(matches) == 0 && len(suppressedMatches) == 0 {
		return ""
	}

	var builder strings.Builder

	// Sort matches by confidence level for consistent output
	f.sortMatches(matches)

	// Group matches by file for cleaner pre-commit output
	fileMatches := f.groupMatchesByFile(matches)

	// Output format: FILE: ISSUE_COUNT issues found
	for filename, fileMatchList := range fileMatches {
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, match := range fileMatchList {
			switch f.getConfidenceLevel(match.Confidence) {
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}
		}

		// Format: filename: X high, Y medium, Z low confidence issues
		var issueParts []string
		if highCount > 0 {
			issueParts = append(issueParts, fmt.Sprintf("%d high", highCount))
		}
		if mediumCount > 0 {
			issueParts = append(issueParts, fmt.Sprintf("%d medium", mediumCount))
		}
		if lowCount > 0 {
			issueParts = append(issueParts, fmt.Sprintf("%d low", lowCount))
		}

		if len(issueParts) > 0 {
			fmt.Fprintf(&builder, "%s: %s confidence issues found\n",
				f.getSmartFilename(filename, matches),
				strings.Join(issueParts, ", "))

			// Add specific issue details for actionable guidance
			for _, match := range fileMatchList {
				confidenceLevel := f.getConfidenceLevel(match.Confidence)
				fmt.Fprintf(&builder, "  line %d: %s (%s confidence)\n",
					match.LineNumber,
					f.getPrecommitIssueDescription(match),
					strings.ToLower(confidenceLevel))

				// Honor --show-match here too, so the resolution hint below
				// ("Use --show-match flag to see exact matches") is truthful in
				// pre-commit mode. displayMatchText returns "[HIDDEN]" by default
				// and the raw value only when ShowMatch is set, so the default
				// pre-commit output still never prints the matched value.
				fmt.Fprintf(&builder, "    match: %s\n", displayMatchText(match, options))

				// Per-finding explanation when scanned with --explain: promote
				// the "why" and a verdict to the pre-commit gate, the highest-
				// friction moment, instead of leaving it in verbose-only output.
				if ex, ok := explain.FromMatch(match); ok {
					fmt.Fprintf(&builder, "    why: %s\n", ex.Rationale)
					fmt.Fprintf(&builder, "    verdict: %s\n", ex.Verdict)
					if ex.DraftSuppressReason != "" {
						fmt.Fprintf(&builder, "    suppression reason: %s\n", ex.DraftSuppressReason)
					}
				}
			}
		}
	}

	// Add resolution guidance if there are findings
	if len(matches) > 0 {
		builder.WriteString("\n")
		builder.WriteString(f.getPrecommitResolutionGuidance(matches, options))
	}

	return builder.String()
}

// groupMatchesByFile groups matches by filename for organized output
func (f *Formatter) groupMatchesByFile(matches []detector.Match) map[string][]detector.Match {
	fileMatches := make(map[string][]detector.Match)
	for _, match := range matches {
		fileMatches[match.Filename] = append(fileMatches[match.Filename], match)
	}
	return fileMatches
}

// getPrecommitIssueDescription returns a concise, actionable description for pre-commit
func (f *Formatter) getPrecommitIssueDescription(match detector.Match) string {
	switch match.Type {
	case "CREDIT_CARD":
		return "Credit card number detected"
	case "SSN":
		return "Social Security Number detected"
	case "PASSPORT":
		return "Passport number detected"
	case "EMAIL":
		return "Email address detected"
	case "PHONE":
		return "Phone number detected"
	case "IP_ADDRESS":
		return "IP address detected"
	case "SECRETS":
		return "API key or secret detected"
	case "INTELLECTUAL_PROPERTY":
		return "Intellectual property notice detected"
	case "SOCIAL_MEDIA":
		return "Social media handle detected"
	case "VIN":
		return "Vehicle Identification Number detected"
	default:
		// For metadata and other types, try to extract meaningful info
		if match.Validator == "metadata" && strings.Contains(match.Text, ":") {
			parts := strings.SplitN(match.Text, ":", 2)
			if len(parts) == 2 {
				return fmt.Sprintf("Metadata field '%s' detected", strings.TrimSpace(parts[0]))
			}
		}
		return fmt.Sprintf("%s detected", strings.ReplaceAll(match.Type, "_", " "))
	}
}

// getPrecommitResolutionGuidance provides actionable guidance for resolving issues
func (f *Formatter) getPrecommitResolutionGuidance(matches []detector.Match, options formatters.FormatterOptions) string {
	var guidance strings.Builder

	guidance.WriteString("Resolution options:\n")
	guidance.WriteString("1. Remove or redact the sensitive data\n")
	guidance.WriteString("2. Add suppression rules if data is intentional (run `ferret-scan --help` for the suppression flags, or see https://github.com/awslabs/ferret-scan)\n")
	// Only suggest --show-match when it is not already in effect: suggesting a
	// flag the operator has already passed is misleading. When ShowMatch is on,
	// the per-finding "match:" lines above already show the exact values.
	if !options.ShowMatch {
		guidance.WriteString("3. Use --show-match flag to see exact matches for review (otherwise shows [HIDDEN])\n")
	}

	// Check if there are high confidence findings that should block
	hasHighConfidence := false
	for _, match := range matches {
		if match.Confidence >= 90 {
			hasHighConfidence = true
			break
		}
	}

	if hasHighConfidence {
		guidance.WriteString("\nHigh confidence issues found - commit blocked for security.\n")
	}

	return guidance.String()
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
