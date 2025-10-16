// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"encoding/json"
	"fmt"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/formatters/shared"
)

// Formatter implements JSON output formatting
type Formatter struct{}

// NewFormatter creates a new JSON formatter
func NewFormatter() *Formatter {
	return &Formatter{}
}

func (f *Formatter) Name() string {
	return "json"
}

func (f *Formatter) Description() string {
	return "Structured JSON output for programmatic consumption"
}

func (f *Formatter) FileExtension() string {
	return ".json"
}

func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	if len(matches) == 0 {
		if len(suppressedMatches) > 0 {
			return f.formatJSONWithSuppressed([]detector.Match{}, suppressedMatches, options), nil
		}
		// In pre-commit mode, return empty string for no matches to reduce noise
		if options.PrecommitMode {
			return "", nil
		}
		return "[]", nil
	}

	// Filter matches by confidence level using shared logic
	filteredMatches := shared.FilterMatchesByConfidence(matches, options)
	if len(filteredMatches) == 0 {
		if len(suppressedMatches) > 0 {
			return f.formatJSONWithSuppressed([]detector.Match{}, suppressedMatches, options), nil
		}
		// In pre-commit mode, return empty string for no matches at specified levels
		if options.PrecommitMode {
			return "", nil
		}
		return "[]", nil
	}

	// Always use the new format when suppressedMatches are provided
	return f.formatJSONWithSuppressed(filteredMatches, suppressedMatches, options), nil
}

// formatJSONWithSuppressed formats matches and suppressed findings as JSON using shared structures
func (f *Formatter) formatJSONWithSuppressed(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) string {
	// Use shared conversion logic
	response := shared.ConvertMatchesToJSONFormat(matches, suppressedMatches, options)

	var jsonData []byte
	var err error

	// In pre-commit mode, use compact JSON to reduce output size
	if options.PrecommitMode {
		jsonData, err = json.Marshal(response)
	} else {
		jsonData, err = json.MarshalIndent(response, "", "  ")
	}

	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}

	return string(jsonData)
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
