// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// FormatterOptions defines configuration options for formatters
type FormatterOptions struct {
	ConfidenceLevel map[string]bool // Which confidence levels to display
	Verbose         bool            // Whether to display detailed information
	NoColor         bool            // Whether to disable colored output
	ShowMatch       bool            // Whether to display the actual matched text
	PrecommitMode   bool            // Whether to use pre-commit optimized output

	// Limit caps how many findings are included in the output. 0 = unlimited.
	// When the total exceeds Limit, a footer indicates how many were omitted.
	Limit int

	// Stats, when non-nil, is rendered as a summary block in the output
	// (position depends on format: header for text, top-level field for JSON).
	Stats *ScanStats

	// NotExaminedFooter, when non-empty, is appended INSIDE the text formatter's
	// summary block, between the summary's closing rule and a final single rule.
	//
	// It lives here rather than being printed by the caller so the whole footer is
	// one contiguous block on ONE stream. Printed separately to stderr it rendered
	// as a detached box after a blank line, and a piped stdout ended with a summary
	// whose frame was closed by content the pipe never received.
	//
	// Text format only: structured formats carry the same information as data via
	// NotExamined below, not as decorated prose.
	NotExaminedFooter string

	// NotExamined is the STRUCTURED form of the same disclosure, for machine
	// formats. Empty means every file was fully examined.
	//
	// Separate from NotExaminedFooter because that field is rendered prose — box
	// rules, column padding, a flag hint — which a JUnit or SARIF consumer cannot
	// use. A machine format needs the path and the cause as distinct fields.
	//
	// Deliberately NOT part of ScanStats: stats is marshalled directly into the
	// json/yaml output, and putting an int-backed enum there would put an ordinal on
	// the wire as a number, which would then be an output contract. The count that
	// belongs in stats is already there (ScanStats.FilesNotExamined).
	//
	// Formatters must guard on len(NotExamined) > 0 AND treat a nil Stats as
	// legitimate: the golden harness constructs FormatterOptions without either.
	NotExamined []NotExaminedFile

	// FailOnIncomplete mirrors --fail-on-incomplete, which makes incomplete coverage
	// a non-zero exit.
	//
	// Only the JUnit formatter reads it, and only to decide the VALENCE of the
	// not-examined entries: <skipped> by default, <error> when the flag is set. That
	// keeps one decision in one place — a JUnit widget's verdict then agrees with the
	// process exit code instead of contradicting it.
	//
	// Default-false matters: emitting <error> unconditionally would turn currently
	// green pipelines red on the first unreadable file, which is a behaviour change
	// nobody asked for, dressed up as a disclosure.
	FailOnIncomplete bool

	// StreamWriter, when non-nil, causes the text formatter to write output
	// directly to this writer instead of buffering into a returned string.
	// The Format call returns "" when streaming is active — the caller must
	// skip its own fmt.Println(result). Only the text formatter honors this;
	// structured formats (JSON, SARIF, etc.) ignore it because they require
	// structural integrity of the complete document.
	StreamWriter io.Writer
}

// ScanStats holds aggregate scan statistics rendered in the output summary.
// Every field carries a yaml tag as well as a json one, and they MUST agree.
//
// Without them gopkg.in/yaml.v3 falls back to the lower-cased Go field name, so the
// YAML artifact spelled these `totalfiles`, `filesprocessed` and — the costly one —
// `filesnotexamined`. A consumer written against the documented JSON schema therefore
// could not read the coverage disclosure out of the YAML report at all: it was looking
// for `files_not_examined`, which never appeared under that name. The missing tag also
// dropped `omitempty`, so YAML emitted `filesnotexamined: 0` where JSON omitted it.
//
// Two serializations of one struct that disagree about key names are worse than one
// format being absent, because the field LOOKS present and reads as zero.
type ScanStats struct {
	TotalFiles     int `json:"total_files" yaml:"total_files"`
	FilesProcessed int `json:"files_processed" yaml:"files_processed"`
	FilesSkipped   int `json:"files_skipped" yaml:"files_skipped"`

	// FilesNotExamined counts files the tool could not read, parse or extract text
	// from. They are NOT "skipped" (an unsupported type the user does not expect a
	// result for) and NOT "processed" (a scan that ran to completion) — they are
	// files whose contents were never seen, so nothing can be concluded about them.
	//
	// Before this existed the summary said "2 processed, 0 skipped" for a directory
	// of 7 files where 2 were unreadable and 4 failed to parse: five files vanished
	// from the accounting and one FAILURE was counted as "processed". A clean-looking
	// summary over unexamined files is the same class of harm as a missed detection.
	//
	// omitempty so a scan with nothing to report stays byte-identical in JSON/YAML.
	FilesNotExamined int     `json:"files_not_examined,omitempty" yaml:"files_not_examined,omitempty"`
	TotalFindings    int     `json:"total_findings" yaml:"total_findings"`
	High             int     `json:"high" yaml:"high"`
	Medium           int     `json:"medium" yaml:"medium"`
	Low              int     `json:"low" yaml:"low"`
	Suppressed       int     `json:"suppressed" yaml:"suppressed"`
	Duration         float64 `json:"duration_seconds" yaml:"duration_seconds"`
}

// Formatter interface defines methods that all output formatters must implement
type Formatter interface {
	// Format formats the matches according to the formatter's specific output format
	Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options FormatterOptions) (string, error)

	// Name returns the name of the formatter (e.g., "json", "text", "csv")
	Name() string

	// Description returns a brief description of what this formatter outputs
	Description() string

	// FileExtension returns the recommended file extension for this format (e.g., ".json", ".txt", ".csv")
	FileExtension() string
}

// Registry holds all registered formatters
type Registry struct {
	formatters map[string]Formatter
}

// NewRegistry creates a new formatter registry
func NewRegistry() *Registry {
	return &Registry{
		formatters: make(map[string]Formatter),
	}
}

// Register adds a formatter to the registry
func (r *Registry) Register(formatter Formatter) {
	r.formatters[formatter.Name()] = formatter
}

// Get retrieves a formatter by name
func (r *Registry) Get(name string) (Formatter, bool) {
	formatter, exists := r.formatters[name]
	return formatter, exists
}

// List returns all registered formatter names in ascending order. The order is
// user-visible: this backs the "Use one of: ..." hint on an unsupported --format
// and the equivalent web export error, both of which listed the formats in a
// different order on every invocation.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.formatters))
	for name := range r.formatters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// FormatInfo provides metadata about a formatter for web UI integration
type FormatInfo struct {
	Name         string
	Description  string
	Extension    string
	MimeType     string
	WebSupported bool
}

// DefaultRegistry is the global formatter registry
var DefaultRegistry = NewRegistry()

// Register is a convenience function to register a formatter with the default registry
func Register(formatter Formatter) {
	DefaultRegistry.Register(formatter)
}

// Get is a convenience function to get a formatter from the default registry
func Get(name string) (Formatter, bool) {
	return DefaultRegistry.Get(name)
}

// List is a convenience function to list all formatters in the default registry
func List() []string {
	return DefaultRegistry.List()
}

// Export is a service-level function that provides unified formatting for both CLI and Web UI
func Export(format string, matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options FormatterOptions) (string, error) {
	formatter, exists := Get(format)
	if !exists {
		availableFormats := List()
		return "", fmt.Errorf("unsupported format '%s'. Available formats: %s", format, strings.Join(availableFormats, ", "))
	}
	return formatter.Format(matches, suppressedMatches, options)
}

// ExportForWeb provides web-friendly export with proper MIME types and filenames
func ExportForWeb(format string, matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options FormatterOptions) (content string, mimeType string, filename string, err error) {
	// Get the formatted content
	content, err = Export(format, matches, suppressedMatches, options)
	if err != nil {
		return "", "", "", err
	}

	// Get format info
	info := GetFormatInfo(format)
	mimeType = info.MimeType
	filename = "ferret-scan-results" + info.Extension

	return content, mimeType, filename, nil
}

// GetFormatInfo returns metadata about a specific formatter
func GetFormatInfo(name string) FormatInfo {
	formatter, exists := Get(name)
	if !exists {
		return FormatInfo{}
	}

	// Get basic info from formatter
	info := FormatInfo{
		Name:         formatter.Name(),
		Description:  formatter.Description(),
		Extension:    formatter.FileExtension(),
		WebSupported: true, // Most formatters support web
	}

	// Set appropriate MIME types
	switch name {
	case "json":
		info.MimeType = "application/json"
	case "csv":
		info.MimeType = "text/csv"
	case "yaml":
		info.MimeType = "application/x-yaml"
	case "junit":
		info.MimeType = "application/xml"
	case "text":
		info.MimeType = "text/plain"
	case "sarif":
		info.MimeType = "application/sarif+json"
	default:
		info.MimeType = "application/octet-stream"
	}

	return info
}

// GetSupportedFormats returns information about all available formatters
func GetSupportedFormats() []FormatInfo {
	var formats []FormatInfo
	for _, name := range List() {
		formats = append(formats, GetFormatInfo(name))
	}
	return formats
}
