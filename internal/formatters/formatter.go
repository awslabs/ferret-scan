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

	// PrecommitBlockMessage is the pre-commit verdict line to render, or "" to render none.
	//
	// The formatter RENDERS this; it does not decide it. It used to decide: it printed "High
	// confidence issues found - commit blocked for security." whenever any match had
	// Confidence >= 90, while the exit code was decided in internal/precommit from
	// FERRET_PRECOMMIT_EXIT_ON. With EXIT_ON=none the tool therefore printed "commit blocked"
	// and exited 0, so the commit proceeded — and `none` is exactly what a team sets while
	// adopting the tool. See precommit.Decision, which now returns the message and the exit
	// code from one evaluation of one policy.
	//
	// A string rather than a bool so this package needs no dependency on internal/precommit,
	// which keeps that dependency one-way and the policy in one place.
	PrecommitBlockMessage string

	// OutputToFile is true when the caller directed output to a path with --output.
	//
	// Pre-commit mode returns an EMPTY document when there is nothing to report, which is
	// deliberate noise reduction on a developer's every commit — it has its own out-of-band
	// signalling in the exit code and on stderr. That reasoning holds for a terminal and not
	// for a file the caller named: with --output the caller asked for a machine artifact and
	// received a 0-byte file that no parser accepts.
	//
	// Measured before this field existed, on a clean tree with --format json --output r.json:
	//
	//	ordinary run    237 bytes, valid JSON, results: []
	//	PRE_COMMIT=1      0 bytes, JSONDecodeError
	//
	// Same shape as the bug #351 fixed for --format: an explicit request silently discarded by
	// an inference the caller never opted into. Quiet mode governs console chatter, not whether
	// a requested artifact exists (#353).
	OutputToFile bool

	// SourceRoot is the directory a machine report's file locations are made relative to.
	//
	// GitLab resolves a SAST report's location.file against the repository root, so an
	// absolute scanner path has to keep every segment BELOW that root and lose everything
	// above it. The CLI sets this to the working directory — that is what GitLab CI's
	// checkout is, and what every documented gitlab-sast invocation scans (`--file .`). It
	// is set here, by the caller, rather than read from CI_PROJECT_DIR inside a formatter:
	// an environment variable steering a report's contents is the shape #704 is filing
	// against, and a formatter should produce the same bytes for the same matches wherever
	// it runs. Empty means no root is known, and an absolute path is then reported by its
	// basename, which is what every release before this field did (#705).
	SourceRoot string

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

	// UnredactedFooter is the text formatter's rendered block, appended inside the
	// summary exactly as NotExaminedFooter is, and for the same reason: printed
	// separately to stderr it rendered as a detached box, and a piped stdout ended
	// with a frame closed by content the pipe never received.
	//
	// Text format only; structured formats carry the same information as data via
	// Unredacted below.
	UnredactedFooter string

	// RedactionRequested records whether the run asked for redaction at all.
	//
	// Needed to distinguish three states a consumer must not conflate: redaction was
	// not requested, it was requested and succeeded, and it was requested and refused.
	// Without this a read-only scan and a fully redacted one look identical, so a
	// consumer filtering for exposures would be told a scan that never redacted
	// anything was clean.
	RedactionRequested bool

	// Unredacted is the STRUCTURED form of the redaction disclosure, for machine
	// formats. Empty means nothing was left in cleartext — which includes the common
	// case of a scan that never asked for redaction.
	//
	// Separate from ScanStats for the same reason NotExamined is: stats marshals
	// directly to json/yaml, and an int-backed enum there would put an ordinal on the
	// wire as a number and make it an output contract. The counts that belong in
	// stats are already there (FilesNotRedacted, ValuesNotRedacted).
	//
	// Formatters must guard on len(Unredacted) > 0 AND treat a nil Stats as
	// legitimate: the golden harness constructs FormatterOptions without either.
	Unredacted []UnredactedFile

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
	// SkippedTypes names WHICH types were skipped, because a count is not a disclosure: the
	// output is byte-identical whether the skipped files are build detritus or customer
	// documents. See SummarizeSkippedTypes.
	SkippedTypes map[string]int `json:"skipped_types,omitempty" yaml:"skipped_types,omitempty"`

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
	FilesNotExamined int `json:"files_not_examined,omitempty" yaml:"files_not_examined,omitempty"`

	// DisabledDetectionTypes names detection sub-types that CONFIG switched off for this run,
	// keyed by validator. It is a coverage disclosure, not a setting echo: with it absent, a scan
	// whose detection had been narrowed was byte-identical to one that ran in full.
	//
	// Measured on the parent commit, one copyright notice, --checks INTELLECTUAL_PROPERTY:
	//
	//	no project config                       1 finding
	//	.ferret-scan.yaml disabling copyright   0 findings, rc 0, 109 bytes of stderr naming the
	//	                                        config but not what it turned off
	//	--config <same file>                    0 findings, rc 0, ZERO bytes of stderr
	//
	// The third row is why this is not merely the provenance note's job. #603 deliberately keeps
	// the provenance note silent for an explicit --config, on the ground that the operator chose
	// the file — but a CI job consuming `"results": []` from that run did not choose it and has no
	// way to tell a clean scan from a narrowed one.
	//
	// Sourced from the CONFIGURED VALIDATOR, not from re-reading config: only the
	// intellectual-property validator honours `disabled_types`, so a config-derived disclosure
	// would announce reduced coverage for any validator whose section carried the key.
	//
	// Values are sorted, because they come from a map and an unsorted disclosure would differ
	// between runs of an unchanged scan. omitempty so a scan with nothing disabled stays
	// byte-identical in JSON and YAML.
	DisabledDetectionTypes map[string][]string `json:"disabled_detection_types,omitempty" yaml:"disabled_detection_types,omitempty"`

	// FilesNotRedacted counts files whose findings were REPORTED but whose values
	// were not redacted, so they remain in cleartext. Separate from
	// FilesNotExamined because they are different facts about different stages: a
	// file can be fully examined and unredacted, or partly examined and redacted
	// fine. Merging them would tell a consumer that something went wrong without
	// saying whether the remedy is to re-scan or to stop shipping the output.
	//
	// Only meaningful when redaction was requested; a scan without
	// --enable-redaction leaves it zero.
	//
	// omitempty so a scan with nothing to report stays byte-identical in JSON/YAML.
	FilesNotRedacted int `json:"files_not_redacted,omitempty" yaml:"files_not_redacted,omitempty"`

	// ValuesNotRedacted counts the individual reported findings left in cleartext
	// across those files. This is the number that sizes the exposure; the file count
	// alone understates one file holding forty values.
	ValuesNotRedacted int `json:"values_not_redacted,omitempty" yaml:"values_not_redacted,omitempty"`

	TotalFindings int     `json:"total_findings" yaml:"total_findings"`
	High          int     `json:"high" yaml:"high"`
	Medium        int     `json:"medium" yaml:"medium"`
	Low           int     `json:"low" yaml:"low"`
	Suppressed    int     `json:"suppressed" yaml:"suppressed"`
	Duration      float64 `json:"duration_seconds" yaml:"duration_seconds"`
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

// MayStaySilent reports whether a formatter is allowed to return an EMPTY document.
//
// Pre-commit mode returns nothing when there is genuinely nothing to say, which is deliberate noise
// reduction on a developer's every commit. The bug is the word "genuinely": four formatters — text,
// json, yaml and csv — each decided it from the FILTERED match set, while the exit code is decided
// from the UNFILTERED one. When a finding's confidence tier is inside the blocking policy but outside
// the display filter, those two sets disagree and the run rejects the commit having printed nothing.
//
// Reachable with one documented environment variable and no other flags, because pre-commit mode
// auto-applies the built-in `precommit` profile whose ConfidenceLevels is "high,medium". Measured:
//
//	FERRET_PRECOMMIT_EXIT_ON=none    rc 0   stdout 0 bytes   stderr 0 bytes
//	FERRET_PRECOMMIT_EXIT_ON=high    rc 0   stdout 0 bytes   stderr 0 bytes
//	FERRET_PRECOMMIT_EXIT_ON=medium  rc 0   stdout 0 bytes   stderr 0 bytes
//	FERRET_PRECOMMIT_EXIT_ON=low     rc 1   stdout 0 bytes   stderr 0 bytes   <- blocks, says nothing
//
// on a file holding two LOW findings. The blocking run is BYTE-IDENTICAL to a clean pass on both
// streams; only the exit code differs. junit, sarif and gitlab-sast are worse than silent — they emit
// an affirmatively clean envelope (`failures="0"`, `results: []`) while the commit is rejected.
//
// The json formatter's stated justification for its silence — that pre-commit mode "has its own
// out-of-band signalling (exit code + stderr)" — is false in exactly this case, because stderr is
// empty too.
//
// So the rule: silence is permitted only when the run does NOT block. PrecommitBlockMessage is
// non-empty exactly when precommit.Resolve decided to block, so one predicate covers every format and
// a formatter cannot reach the wrong answer on its own.
func (o FormatterOptions) MayStaySilent() bool {
	return o.PrecommitMode && !o.OutputToFile && o.PrecommitBlockMessage == ""
}

// MatchesToReport returns the matches a formatter must render.
//
// Normally the filtered set: the operator asked to see certain confidence levels. But when the run
// BLOCKS and the filter has emptied the report, the filtered set is the wrong answer — the exit policy
// judged the unfiltered set, so the report has to show what it judged, or the developer is told their
// commit was rejected and nothing else.
//
// Widening only in that case, rather than always reporting unfiltered matches, keeps --confidence
// meaning what it says on every run that does not block.
func MatchesToReport(filtered, all []detector.Match, o FormatterOptions) []detector.Match {
	if len(filtered) == 0 && o.PrecommitBlockMessage != "" {
		return all
	}
	return filtered
}
