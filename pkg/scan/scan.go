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
}

// Finding is one piece of sensitive data detected.
type Finding struct {
	Type         string  // validator-assigned classification (e.g. "SSN", "VISA", "EMAIL")
	Validator    string  // which validator produced it
	Confidence   float64 // 0–100
	LineNumber   int     // 1-based
	Text         string  // the matched substring (handle with care)
	Filename     string  // source file or label
	Rationale    string  // plain-language "why flagged" (empty unless Explain=true)
	Verdict      string  // "likely_real" | "likely_test" | "uncertain" (empty unless Explain)
	SuppressedBy string  // non-empty if this finding was suppressed
}

// Result holds the output of a scan.
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
