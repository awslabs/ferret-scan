// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"encoding/json"
	"fmt"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
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
	// Filter first, then take ONE path regardless of how many findings survive.
	//
	// There used to be two early returns emitting a bare `[]`: one for "no matches at
	// all" and one for "none at the requested confidence". Both bypassed
	// shared.ConvertMatchesToJSONFormat, which is the only place `stats` — and with it
	// files_not_examined — is attached. So the coverage disclosure was present exactly
	// when there were findings and absent exactly when the report read as a clean bill
	// of health. Measured on a directory of three unreadable files: text printed
	// "NOT FULLY EXAMINED: 3 of 3 files", json printed `[]` (2 bytes) at exit 0.
	//
	// That is the case the field exists for. stats.files_not_examined was added (#277)
	// so a machine consumer could tell an unexamined file from a clean one, and #284
	// extended it to sarif/gitlab-sast/junit on the stated premise that json and yaml
	// already disclosed — they disclosed only on the path where findings existed. See
	// #296, and #257 whose json half was left unfixed.
	//
	// Dropping the early returns also stabilizes the top-level TYPE. It used to flip
	// between a list (`[]`, zero findings) and an object (`{"stats":…,"results":[…]}`,
	// with findings), so a typed consumer that worked on a dirty scan failed on a clean
	// one with "cannot unmarshal array into Go value of type struct". It is now always
	// an object.
	filteredMatches := shared.FilterMatchesByConfidence(matches, options)

	// Pre-commit mode stays silent when there is genuinely nothing to say, which is
	// deliberate noise reduction on a developer's every commit. It has its own
	// out-of-band signalling (exit code + stderr), so it is not relying on this
	// artifact for the disclosure.
	if len(filteredMatches) == 0 && len(suppressedMatches) == 0 && options.PrecommitMode &&
		!options.OutputToFile {
		return "", nil
	}

	return f.formatJSONWithSuppressed(filteredMatches, suppressedMatches, options)
}

// formatJSONWithSuppressed formats matches and suppressed findings as JSON using shared structures
func (f *Formatter) formatJSONWithSuppressed(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
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
		// RETURNED, not stringified into the output. This used to hand the error text back as
		// the document: stdout received `Error formatting JSON: ...` where the report should
		// have been, and the process exited 0. Measured, one non-finite metadata value turned
		// 57,786 findings across 1,009 files into 52 bytes with a green exit code, so a CI job
		// piping this to a file saw no findings and passed. The Formatter interface has always
		// returned an error and main.go has always exited 1 on it; only this function declined
		// to use the channel. See #520.
		return "", fmt.Errorf("formatting JSON: %w", err)
	}

	return string(jsonData), nil
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
