// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scan is the public detection API for ferret-scan.
//
// It exposes the engine's detection capabilities (find sensitive data in text
// or files) without coupling callers to redaction. Detection and redaction are
// separate concerns:
//
//   - pkg/scan  — "what sensitive data is in this content?" (this package)
//   - pkg/redact — "mask/replace the sensitive data" (consumes scan results)
//
// Both delegate to the same internal detection pipeline (internal/core); this
// package is a thin, stable, public forwarding layer — no detection logic is
// duplicated.
//
// Third-party apps, the gomobile facade, and pkg/redact itself can all import
// this package to detect without depending on redaction internals.
package scan

import (
	"context"
	"fmt"
	"io"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
)

// TextOptions configures an in-memory text scan.
type TextOptions struct {
	// Checks selects which validators to run. Empty or ["all"] = every
	// validator. Use CheckNames() to discover valid IDs.
	Checks []string

	// Label is the synthetic filename attached to findings (e.g. "clipboard",
	// "contact-note"). Defaults to "<text>" if empty.
	Label string

	// Explain, when true, attaches a plain-language rationale + verdict to each
	// finding (the "why was this flagged" annotation).
	Explain bool

	// LogWriter receives payload-free progress output. Defaults to io.Discard
	// (silent). Never receives matched values or input bytes.
	LogWriter io.Writer
}

// FileOptions configures a file-path scan.
type FileOptions struct {
	// Checks selects which validators to run. Empty or ["all"] = every validator.
	Checks []string

	// Explain attaches rationale + verdict annotations to findings.
	Explain bool

	// LogWriter receives payload-free progress output. Defaults to io.Discard.
	LogWriter io.Writer

	// MaxLiveBytes caps the total bytes of extracted content held in memory at
	// once. Zero or negative means unlimited, which is the default and matches the
	// CLI without --max-live-bytes.
	//
	// This exists for the caller the engine cannot see: a memory-constrained host
	// such as a Lambda handler, where a single large container can extract to many
	// times its own size and there is a hard ceiling on the process. The CLI has
	// exposed --max-live-bytes since the limiter was added, and core.ScanConfig has
	// carried the field all along — this package simply never forwarded it, so the
	// one consumer that most needs a memory envelope was the only one that could
	// not set it.
	MaxLiveBytes int64
}

// Finding is one piece of sensitive data detected.
type Finding struct {
	Type       string  // validator-assigned classification (e.g. "SSN", "VISA", "EMAIL")
	Validator  string  // which validator produced it
	Confidence float64 // 0–100
	LineNumber int     // 1-based
	Text       string  // the matched substring (handle with care)
	Filename   string  // source file or label
	Rationale  string  // plain-language "why flagged" (empty unless Explain=true)
	Verdict    string  // "likely_real" | "likely_test" | "uncertain" (empty unless Explain)

	// SuppressedBy is always the empty string.
	//
	// Deprecated: this package applies no suppression, so nothing can ever set
	// this field — see the note on Result about suppression. It has read as ""
	// for every finding since the package was introduced, and the check it
	// invites, `if f.SuppressedBy != ""`, therefore answers "nothing was
	// suppressed" for a package that never asked the question. Do not branch on
	// it. It is kept only so existing callers keep compiling and will be removed
	// in the next major version.
	SuppressedBy string

	// ContextBefore and ContextAfter are the text on either side of the match,
	// excluding the match itself; FullLine is the whole line the match sits on.
	// They answer "how was this value used?", which is the signal that separates
	// a live value from a documentation example — the same signal the validators
	// already score against internally.
	//
	// What is and is not promised:
	//
	//   - Single line. These never span lines, even in multi-line documents:
	//     ContextBefore stops at the start of the match's own line.
	//   - The window width is the validator's own, chosen for its confidence
	//     scoring (currently 30–50 bytes per side depending on the validator).
	//     It is not part of this package's compatibility surface and will move
	//     as validators are tuned. Do not parse against a fixed width.
	//   - MAY BE EMPTY, field by field, and empty always means "not recorded" —
	//     never "the match had no surrounding text". Three shapes exist:
	//
	//       * all three populated, for a validator that found the value at a
	//         position inside a line it can point into. Most findings.
	//       * FullLine only, with ContextBefore and ContextAfter always empty:
	//         METADATA, which reports the document property it read
	//         ("Author: Some Name") rather than an offset within a line, so
	//         there is no before or after to give.
	//       * all three empty, for a match that spans lines and therefore has
	//         no single line to describe: the multi-line SECRETS types
	//         (SSH_PRIVATE_KEY, CERTIFICATE, PGP_PRIVATE_KEY).
	//
	//     So branch on the specific field you read, not on "does this finding
	//     have context", and do not read an empty ContextBefore as evidence
	//     that the value stood alone on its line.
	//   - Rune-aligned. Some validators cut their windows at byte offsets, which
	//     can slice a multi-byte rune in half; the fragment is trimmed here, so
	//     these fields can differ from the internal value by up to three bytes
	//     and are always valid UTF-8 when the underlying line is.
	//
	// Sensitivity: raw content copied out of the scanned input, exactly as
	// sensitive as Text and frequently more revealing, since a line of prose
	// around a value can identify the person the value belongs to. They carry
	// `json:"-"` so that adding them cannot silently widen an existing
	// serialization sink — a caller already marshaling Finding keeps its old
	// output and has to opt in explicitly to emit context.
	ContextBefore string `json:"-"`
	ContextAfter  string `json:"-"`
	FullLine      string `json:"-"`
}

// Result holds the output of a scan.
//
// Suppression is NOT applied. Findings is every match the selected validators
// produced; no suppression rule is consulted, and no finding is filtered or
// annotated as suppressed. This differs from the CLI, which does apply a
// suppressions file, so a caller that assumes this package honors the project's
// `.ferret-scan-suppressions.yaml` will see findings an operator has already
// reviewed and accepted. That is the safe direction for a detection API — it
// reports everything and lets the caller decide — but it is worth knowing before
// wiring this into a gate.
//
// Suppression in the engine is opt-in at the internal layer
// (core.ScanConfig.SuppressionManager), which this package deliberately does not
// set: filtering findings by default would let a stale rule silently hide a real
// value from a caller who never asked for it. Callers wanting rule-based
// suppression today can express it over the returned Findings, or use
// pkg/redact, whose Engine matches caller-supplied rules and reports what they
// suppressed.
type Result struct {
	Findings         []Finding
	Incomplete       bool // true if coverage was cut short (timeout, cancellation)
	IncompleteReason string
}

// ScanText detects sensitive data in an in-memory string. It delegates directly
// to the engine's existing in-memory detection pipeline (the same path the CLI's
// --stdin uses). No file I/O, no temp files, no disk.
//
// This is the detection-only counterpart to pkg/redact.Engine.Redact — use it
// when you want findings without redacting.
func ScanText(_ context.Context, text string, opts TextOptions) (*Result, error) {
	label := opts.Label
	if label == "" {
		label = "<text>"
	}
	logWriter := opts.LogWriter
	if logWriter == nil {
		logWriter = io.Discard
	}

	coreResult, err := core.ScanContent(text, core.ContentScanConfig{
		VirtualPath: label,
		Checks:      normalizeChecks(opts.Checks),
		Explain:     opts.Explain,
		Config:      config.LoadConfigOrDefault(""),
		LogWriter:   logWriter,
	})
	if err != nil {
		return nil, err
	}

	return mapResult(coreResult), nil
}

// ScanFile detects sensitive data in a file (PDF, DOCX, XLSX, images, text,
// etc.). It delegates directly to the engine's file-scan pipeline (preprocessors,
// worker pool, the "can this be scanned" gate — the same path the CLI's --file
// uses). No new logic; just a public entry point.
//
// Returns an error for unsupported file types. Use CanProcessFile to check
// cheaply before calling this.
func ScanFile(_ context.Context, path string, opts FileOptions) (*Result, error) {
	// Reject unsupported files early with a clear error (before constructing
	// the full validator pipeline).
	if ok, reason := CanProcessFile(path); !ok {
		return nil, fmt.Errorf("scan: unsupported file: %s (%s)", path, reason)
	}

	logWriter := opts.LogWriter
	if logWriter == nil {
		logWriter = io.Discard
	}

	coreResult, err := core.ScanFile(core.ScanConfig{
		FilePath:            path,
		Checks:              normalizeChecks(opts.Checks),
		EnablePreprocessors: true,
		Explain:             opts.Explain,
		Config:              config.LoadConfigOrDefault(""),
		LogWriter:           logWriter,
		MaxLiveBytes:        opts.MaxLiveBytes,
	})
	if err != nil {
		return nil, err
	}

	return mapResult(coreResult), nil
}

// CheckNames returns the canonical validator IDs the engine recognizes (e.g.
// "CREDIT_CARD", "SSN", "EMAIL"). Use these as values for Options.Checks.
func CheckNames() []string {
	return core.CheckNames()
}

// mapResult converts the internal ScanResult to the public Result, extracting
// findings into the public Finding type. This is the single mapping point —
// internal types never leak to callers.
func mapResult(r *core.ScanResult) *Result {
	findings := make([]Finding, 0, len(r.Matches))
	for _, m := range r.Matches {
		f := Finding{
			Type:       m.Type,
			Validator:  m.Validator,
			Confidence: m.Confidence,
			LineNumber: m.LineNumber,
			Text:       m.Text,
			Filename:   m.Filename,

			// Trim on the cut edge only: the window's outer boundary is the one
			// the validator sliced at a byte offset, while the inner boundary is
			// the match itself and is already rune-aligned.
			ContextBefore: detector.TrimLeadingRuneFragment(m.Context.BeforeText),
			ContextAfter:  detector.TrimTrailingRuneFragment(m.Context.AfterText),
			FullLine:      m.Context.FullLine,
		}
		if ex, ok := explain.FromMatch(m); ok {
			f.Rationale = ex.Rationale
			f.Verdict = string(ex.Verdict)
		}
		findings = append(findings, f)
	}
	return &Result{
		Findings:         findings,
		Incomplete:       r.Incomplete,
		IncompleteReason: r.IncompleteReason,
	}
}

func normalizeChecks(checks []string) []string {
	if len(checks) == 0 {
		return []string{"all"}
	}
	return checks
}
