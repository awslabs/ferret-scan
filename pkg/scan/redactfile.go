// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"io"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// RedactFileOptions configures a file-level redaction.
type RedactFileOptions struct {
	// OutputDir is the base directory where the redacted copy is written. The
	// redactor mirrors the source path structure beneath this directory.
	OutputDir string

	// Strategy: StrategyFormatPreserving (default), StrategySimple, or StrategySynthetic.
	Strategy RedactStrategy

	// Checks selects validators. Empty = all.
	Checks []string

	// LogWriter receives payload-free progress output. Defaults to io.Discard.
	LogWriter io.Writer
}

// RedactFileResult reports the outcome of a file-level redaction.
type RedactFileResult struct {
	// RedactedFilePath is the path to the redacted output file (same type as input).
	RedactedFilePath string
	// RedactionCount is the number of sensitive values masked.
	RedactionCount int
	// Strategy is the strategy that was applied.
	Strategy string
}

// RedactFile scans a file and writes a redacted copy of the SAME file type
// (a redacted .docx stays a .docx, a .pdf stays a .pdf, images get EXIF/GPS
// stripped). Delegates to internal/core.RedactFile — no new logic.
//
// The output is a real file safe to share; the original is never modified.
// Clean files (no findings) are copied through so callers always get an output.
func RedactFile(path string, opts RedactFileOptions) (*RedactFileResult, error) {
	logWriter := opts.LogWriter
	if logWriter == nil {
		logWriter = io.Discard
	}

	strategy := "format_preserving"
	switch opts.Strategy {
	case StrategySimple:
		strategy = "simple"
	case StrategySynthetic:
		strategy = "synthetic"
	}

	result, err := core.RedactFile(core.RedactConfig{
		FilePath:  path,
		OutputDir: opts.OutputDir,
		Strategy:  strategy,
		Checks:    normalizeChecks(opts.Checks),
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: logWriter,
	})
	if err != nil {
		return nil, err
	}

	return &RedactFileResult{
		RedactedFilePath: result.RedactedFilePath,
		RedactionCount:   result.RedactionCount,
		Strategy:         result.Strategy,
	}, nil
}

// ParseStrategy converts a string to a RedactStrategy. Accepts "simple",
// "format_preserving" (default), and "synthetic". Unknown values default to
// format-preserving.
func ParseStrategy(s string) RedactStrategy {
	switch s {
	case "simple":
		return StrategySimple
	case "synthetic":
		return StrategySynthetic
	default:
		return StrategyFormatPreserving
	}
}

// String returns the engine-recognized name for the strategy.
func (s RedactStrategy) String() string {
	switch s {
	case StrategySimple:
		return "simple"
	case StrategySynthetic:
		return "synthetic"
	default:
		return "format_preserving"
	}
}

// CanProcessFile reports whether the engine can scan a given file path.
// Returns true + a reason string (e.g. "Text file", "Binary document").
// Returns false + the reason it was rejected (e.g. "Unsupported file type").
//
// This is the same gate the CLI and mobile apps use to classify files as
// scannable vs. skipped. Use this to pre-filter before calling ScanFile —
// ScanFile will also reject unsupported files, but CanProcessFile is cheaper
// (no validator construction).
func CanProcessFile(path string) (ok bool, reason string) {
	fr := router.NewFileRouter(false)
	return fr.CanProcessFile(path, true, false)
}
