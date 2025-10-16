// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package yaml

import (
	"fmt"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/formatters/shared"

	"gopkg.in/yaml.v3"
)

// Formatter implements YAML output formatting
type Formatter struct{}

// NewFormatter creates a new YAML formatter
func NewFormatter() *Formatter {
	return &Formatter{}
}

func (f *Formatter) Name() string {
	return "yaml"
}

func (f *Formatter) Description() string {
	return "YAML format output, 100% compatible with JSON structure"
}

func (f *Formatter) FileExtension() string {
	return ".yaml"
}

func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	if len(matches) == 0 {
		if len(suppressedMatches) > 0 {
			return f.formatYAMLWithSuppressed([]detector.Match{}, suppressedMatches, options), nil
		}
		// In pre-commit mode, return empty string for no matches to reduce noise
		if options.PrecommitMode {
			return "", nil
		}
		return "results: []\n", nil
	}

	// Filter matches by confidence level using shared logic
	filteredMatches := shared.FilterMatchesByConfidence(matches, options)
	if len(filteredMatches) == 0 {
		if len(suppressedMatches) > 0 {
			return f.formatYAMLWithSuppressed([]detector.Match{}, suppressedMatches, options), nil
		}
		// In pre-commit mode, return empty string for no matches at specified levels
		if options.PrecommitMode {
			return "", nil
		}
		return "results: []\n", nil
	}

	// Always use the new format when suppressedMatches are provided
	return f.formatYAMLWithSuppressed(filteredMatches, suppressedMatches, options), nil
}

// formatYAMLWithSuppressed formats matches and suppressed findings as YAML using shared structures
func (f *Formatter) formatYAMLWithSuppressed(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) string {
	// Use shared conversion logic - IDENTICAL to JSON formatter
	response := shared.ConvertMatchesToJSONFormat(matches, suppressedMatches, options)

	yamlData, err := yaml.Marshal(response)
	if err != nil {
		return fmt.Sprintf("Error formatting YAML: %v", err)
	}

	return string(yamlData)
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
