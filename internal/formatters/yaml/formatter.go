// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package yaml

import (
	"fmt"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"

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
	// Filter first, then take ONE path regardless of how many findings survive.
	//
	// Identical treatment to the JSON formatter, and for the same reason: two early
	// returns emitting a bare `results: []` bypassed
	// shared.ConvertMatchesToJSONFormat, the only place `stats` — and with it
	// files_not_examined — is attached. The coverage disclosure was therefore present
	// exactly when there were findings and absent exactly when the report read as a
	// clean bill of health. Measured on a directory of three unreadable files: text
	// printed "NOT FULLY EXAMINED: 3 of 3 files", yaml printed `results: []` (11 bytes)
	// at exit 0. See #296.
	filteredMatches := shared.FilterMatchesByConfidence(matches, options)

	// Pre-commit mode stays silent when there is genuinely nothing to say — deliberate
	// noise reduction on a developer's every commit, and it signals out of band via
	// exit code and stderr rather than through this artifact.
	if len(filteredMatches) == 0 && len(suppressedMatches) == 0 && options.PrecommitMode {
		return "", nil
	}

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
