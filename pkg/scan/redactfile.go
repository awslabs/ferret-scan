// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

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
	// ConfigPath pins the config file this redaction uses; empty keeps the historical
	// discovery behaviour. DisableConfigDiscovery ignores ambient config entirely and
	// uses built-in defaults. See TextOptions.ConfigPath — without one of the two, which
	// validators run depends on the calling process's working directory, and a config
	// beside the content can disable detection types. That matters more here than on the
	// scan path: only reported findings are redacted. #293.
	ConfigPath string

	// DisableConfigDiscovery uses built-in defaults only. Takes precedence over
	// ConfigPath.
	DisableConfigDiscovery bool
}

// RedactFileResult reports the outcome of a file-level redaction.
type RedactFileResult struct {
	// RedactedFilePath is the path to the redacted output file (same type as input). Empty when
	// no file was written: the file was not fully examined and nothing in it was masked.
	RedactedFilePath string
	// RedactionCount is the number of sensitive values masked.
	RedactionCount int
	// Strategy is the strategy that was applied.
	Strategy string

	// Coverage is nil when the file was fully examined, and otherwise says what was not, in the
	// names scan.Result uses (#770). Whenever it is non-nil RedactFile also returns an error
	// wrapping ErrIncomplete.
	//
	// A POINTER so RedactFileResult stays comparable: a caller using it as a map key or with ==
	// keeps compiling, which slice fields on this struct would break (the v2.4.5 scan.Finding
	// break). The pointer compares by identity, and it is only ever non-nil on a result that
	// came back with an error.
	Coverage *RedactCoverage
}

// RedactCoverage describes a file RedactFile did not fully examine. The fields mean what the
// fields of the same names on Result mean.
type RedactCoverage struct {
	Incomplete       bool
	IncompleteReason string
	NotExamined      []NotExaminedFile
}

// ErrIncomplete is wrapped by the error RedactFile and RedactFileContext return when the file was
// not fully examined: coverage was cut short (a validator size cap, the caller's deadline or
// cancellation), the bytes could not be parsed, or the body extracted to no text -- the three
// channels --fail-on-incomplete counts. The result is returned alongside, io.Reader style, with
// RedactFileResult.Coverage saying which and why.
//
// Before #770 each of these was a success: the passthrough copied the file to the output path as
// if it were clean. An unparseable .pdf came back byte-identical, and a log over the
// CLOUD_RESOURCES size cap came back with every ARN in clear, both at err == nil.
//
// What is on disk then: nothing, when the scan masked nothing -- no passthrough copy is made for a
// file that was not fully examined -- or, when it did mask something, the partially redacted copy,
// as --file leaves it. Either way it is not a redacted copy safe to share.
var ErrIncomplete = errors.New("scan: redaction incomplete")

// RedactFile scans a file and writes a redacted copy of the SAME file type
// (a redacted .docx stays a .docx, a .jpg stays a .jpg, images get EXIF/GPS
// stripped). Delegates to internal/core.RedactFile — no new logic.
//
// The output is a real file and the original is never modified. It is safe to
// share only when the error is nil: when the file was not fully examined the
// error wraps ErrIncomplete, see there for what is on disk. A clean file that
// WAS fully examined (no findings) is copied through, so a caller always gets an
// output on success.
//
// RedactFile runs with context.Background(); RedactFileContext takes a ctx.
func RedactFile(path string, opts RedactFileOptions) (*RedactFileResult, error) {
	return RedactFileContext(context.Background(), path, opts)
}

// RedactFileContext is RedactFile bounded by ctx (#770). A ctx that is done
// before the scan starts writes nothing; one that fires during the scan stops the
// validators, the values found before it fired are masked, and the file is
// reported not fully examined. Either way the error wraps both ErrIncomplete and
// ctx.Err(). Extraction cannot be interrupted: a cancellation that arrives while
// a PDF or a .docx is being turned into text is observed when that returns. A nil
// ctx is treated as context.Background().
func RedactFileContext(ctx context.Context, path string, opts RedactFileOptions) (*RedactFileResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	logWriter := opts.LogWriter
	if logWriter == nil {
		logWriter = io.Discard
	}

	// Reject an out-of-range strategy BEFORE any output file is created, like the
	// unknown-check case below and like pkg/redact.NewEngine already does. A
	// RedactStrategy is an int, so RedactStrategy(7) compiles; it used to be
	// mapped to format_preserving and written at exit 0 (#772).
	if !opts.Strategy.valid() {
		return nil, fmt.Errorf("scan: invalid RedactStrategy %d (use StrategySimple, StrategyFormatPreserving or StrategySynthetic)", int(opts.Strategy))
	}

	// Reject an unknown check BEFORE any output file is created. Failing after the
	// write would leave a file the API calls a redacted copy holding cleartext.
	checks, err := normalizeChecks(opts.Checks)
	if err != nil {
		return nil, err
	}

	cfg, err := resolveConfig(opts.ConfigPath, opts.DisableConfigDiscovery)
	if err != nil {
		return nil, err
	}

	result, err := core.RedactFileCtx(ctx, core.RedactConfig{
		FilePath:  path,
		OutputDir: opts.OutputDir,
		Strategy:  opts.Strategy.String(),
		Checks:    checks,
		Config:    cfg,
		LogWriter: logWriter,
	})
	if err != nil && (result == nil || !errors.Is(err, core.ErrRedactionIncomplete)) {
		return nil, err
	}

	res := &RedactFileResult{
		RedactedFilePath: result.RedactedFilePath,
		RedactionCount:   result.RedactionCount,
		Strategy:         result.Strategy,
	}
	if !result.Incomplete {
		return res, nil
	}
	res.Coverage = &RedactCoverage{
		Incomplete:       true,
		IncompleteReason: result.IncompleteReason,
		NotExamined:      mapNotExamined(result.NotExamined),
	}
	// The same message core builds, under this package's sentinel: the path, the taxonomy cause
	// and, when the caller's ctx cut the scan short, that error, so errors.Is reaches it.
	return res, core.IncompleteRedactionError(ctx, ErrIncomplete, result.NotExamined)
}

// ParseStrategyStrict converts a strategy name to a RedactStrategy. Exactly
// "simple", "format_preserving" or "synthetic"; any other value, including "",
// is an error naming the value and the valid names (and, for a case or
// whitespace variant of a valid name, the name it may have meant).
//
// Added in #772 beside ParseStrategy, whose fallback to format_preserving on an
// unknown value is the behaviour its callers were written against and is kept
// for them, deprecated. New code should use this one: a strategy name that came
// from a user is exactly the input a silent default must not swallow.
func ParseStrategyStrict(s string) (RedactStrategy, error) {
	switch s {
	case "simple":
		return StrategySimple, nil
	case "format_preserving":
		return StrategyFormatPreserving, nil
	case "synthetic":
		return StrategySynthetic, nil
	}
	hint := ""
	if folded := strings.ToLower(strings.TrimSpace(s)); folded != s {
		if _, err := ParseStrategyStrict(folded); err == nil {
			hint = fmt.Sprintf(" (did you mean %q?)", folded)
		}
	}
	return StrategyFormatPreserving, fmt.Errorf("scan: invalid redaction strategy %q: valid values are simple, format_preserving, synthetic%s", s, hint)
}

// valid reports whether s is one of the three defined strategies.
func (s RedactStrategy) valid() bool {
	return s >= StrategyFormatPreserving && s <= StrategySynthetic
}

// ParseStrategy converts a string to a RedactStrategy. Accepts "simple",
// "format_preserving" (default), and "synthetic". Unknown values default to
// format-preserving.
//
// Deprecated: the fallback hides a typo in a user-supplied name as a different
// strategy, written at exit 0 (#772). Use ParseStrategyStrict, which returns an
// error instead. This function is unchanged and stays for existing callers.
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
	return fr.CanProcessFile(path, true)
}
