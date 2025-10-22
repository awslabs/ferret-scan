// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"ferret-scan/internal/detector"
	"fmt"
	"strings"
)

// FormatterOptions defines configuration options for formatters
type FormatterOptions struct {
	ConfidenceLevel map[string]bool // Which confidence levels to display
	Verbose         bool            // Whether to display detailed information
	NoColor         bool            // Whether to disable colored output
	ShowMatch       bool            // Whether to display the actual matched text
	PrecommitMode   bool            // Whether to use pre-commit optimized output
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

// List returns all registered formatter names
func (r *Registry) List() []string {
	var names []string
	for name := range r.formatters {
		names = append(names, name)
	}
	return names
}

// GetAll returns all registered formatters
func (r *Registry) GetAll() map[string]Formatter {
	result := make(map[string]Formatter)
	for name, formatter := range r.formatters {
		result[name] = formatter
	}
	return result
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
