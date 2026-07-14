// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	plaintextredactor "github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// Engine is a reusable, thread-safe entry point for scanning and
// redacting text. Construct one with NewEngine, reuse it across calls,
// and Close it on shutdown. See the package doc for the thread-safety
// contract.
type Engine struct {
	// Immutable post-construction. No locks needed for these fields.
	defaultStrategy Strategy
	logWriter       io.Writer
	debug           bool

	// validators is the slice passed into parallel.RunValidators on
	// each Redact call. It contains exactly one entry — the Detector
	// facade that fans out to the registered validators. Reusing this
	// graph is the entire point of the Engine: constructing it costs
	// roughly an order of magnitude more than running it on a small
	// payload.
	validatorsList []detector.Validator

	// observer is the package-internal observer that EnhancedManager
	// shares for its lifetime. Callers can provide their own
	// LogWriter; observer respects that writer.
	observer *observability.StandardObserver

	// redactor is the in-memory plaintext redactor reused across
	// calls. It carries no per-request state (RedactString takes its
	// inputs by value).
	redactor *plaintextredactor.PlainTextRedactor

	// closed is set atomically when Close is called; subsequent
	// Redact calls return ErrEngineClosed.
	closed atomic.Bool
}

// NewEngine constructs a reusable Engine. The construction cost is
// dominated by validator instantiation and dual-path setup; once built,
// each Redact call adds no setup overhead.
//
// EngineOptions.Checks selects which validators to enable. Empty or
// ["all"] enables every default validator (METADATA is excluded — it
// requires filesystem access). Validator names not recognized are
// silently dropped, mirroring the CLI's tolerant parsing.
//
// LogWriter defaults to io.Discard when nil. Set to os.Stderr to mirror
// the CLI's progress output.
func NewEngine(opts EngineOptions) (*Engine, error) {
	if opts.LogWriter == nil {
		opts.LogWriter = io.Discard
	}
	if opts.Strategy < Simple || opts.Strategy > Synthetic {
		return nil, fmt.Errorf("redact: invalid Strategy %d", int(opts.Strategy))
	}

	// Build observer. The internal StandardObserver writes progress
	// markers (component name + duration) but never the matched
	// substrings or input bytes — wire it to opts.LogWriter so the
	// caller controls the destination.
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, opts.LogWriter)
	if opts.Debug {
		debugObs := observability.NewDebugObserver(opts.LogWriter)
		observer = debugObs.StandardObserver
		observer.DebugObserver = debugObs
	}

	// Build the validator set. core.ParseChecksToRun handles "all" and
	// individual names; an empty slice is equivalent to "all" by the
	// existing CLI convention.
	enabledChecks := core.ParseChecksToRun(opts.Checks)

	// Don't pass project config / profile here — the public API does not
	// expose those types. Validator-specific tuning is a v2 concern.
	standardValidators := core.BuildValidatorSet(enabledChecks, nil, nil)

	// METADATA needs filesystem access; the CLI deletes it from the set
	// on its in-memory path for the same reason. ValidCheckNames excludes
	// it for the same reason, via the same constant.
	delete(standardValidators, checkUnsupportedInMemory)

	if len(standardValidators) == 0 {
		return nil, fmt.Errorf("redact: no validators enabled (Checks=%v)", opts.Checks)
	}

	// Wire up the detection facade (dual-path bridge) so contextual
	// analysis behaves identically to ScanContent. Constructing this
	// once is the entire reason Engine exists — the CLI rebuilds it
	// every call.
	detectorFacade := validators.NewDetector(observer)
	if err := detectorFacade.SetupValidators(standardValidators); err != nil {
		return nil, fmt.Errorf("redact: failed to setup dual path validation: %w", err)
	}

	// nil output manager + nil observer is fine for in-memory redaction —
	// RedactString uses neither. Position correlation is unnecessary for
	// plaintext (1:1 mapping) and disabling avoids per-call latency.
	redactor := plaintextredactor.NewPlainTextRedactor(nil, nil)
	redactor.SetPositionCorrelationEnabled(false)

	strategy := opts.Strategy

	e := &Engine{
		defaultStrategy: strategy,
		logWriter:       opts.LogWriter,
		debug:           opts.Debug,
		validatorsList:  []detector.Validator{detectorFacade},
		observer:        observer,
		redactor:        redactor,
	}
	return e, nil
}

// checkUnsupportedInMemory names the one validator that exists in the core
// validator set but cannot run on this in-memory path because it requires
// filesystem access. NewEngine deletes it from the constructed set, and
// ValidCheckNames omits it, so the two stay consistent: a name advertised as
// valid is always a name that actually contributes a validator here.
const checkUnsupportedInMemory = "METADATA"

// ValidCheckNames returns the sorted set of canonical validator IDs accepted
// in EngineOptions.Checks (e.g. "CREDIT_CARD", "EMAIL", "SSN"). It does NOT
// include the "all" sentinel or the empty default, both of which select every
// validator, nor "METADATA" — that validator needs filesystem access and is a
// no-op on this in-memory path, so selecting only METADATA would error with
// "no validators enabled".
//
// NewEngine deliberately tolerates unrecognized names — it drops them and only
// errors when the resulting set is empty (see EngineOptions.Checks). That makes
// a mixed list like {"CREDIT_CARD", "emial"} fail OPEN: the typo'd validator is
// silently disabled while the engine still constructs. Callers that want
// fail-closed behavior should validate their Checks against this list before
// calling NewEngine and reject anything unrecognized. The names are
// case-sensitive and match the project's internal validator IDs.
func ValidCheckNames() []string {
	all := core.CheckNames()
	out := make([]string, 0, len(all))
	for _, n := range all {
		if n == checkUnsupportedInMemory {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Close releases resources held by the Engine. v1 implementations are
// no-ops; future versions may run background goroutines for metric
// flushing or signal aggregation, in which case Close becomes mandatory.
// Always call it via defer to remain forward-compatible.
//
// After Close, subsequent Redact calls return ErrEngineClosed.
func (e *Engine) Close() error {
	e.closed.Store(true)
	return nil
}

// Redact scans the request text and returns a Result with the redacted
// content, finding metadata, and an audit record. See the package doc
// for the thread-safety contract.
func (e *Engine) Redact(ctx context.Context, req Request) (*Result, error) {
	if e.closed.Load() {
		return nil, ErrEngineClosed
	}

	// Normalize the input the same way the CLI does for stdin: strip
	// BOM, reject NUL, coerce invalid UTF-8 to the replacement rune.
	// This keeps line numbers and offsets aligned with what the user
	// expects and gives the same output for "this string written to
	// stdin" vs "this string passed to the public API".
	text := req.Text
	if text == "" {
		return nil, ErrEmptyText
	}
	if len(text) > MaxInputBytes {
		return nil, ErrTextTooLarge
	}
	text = strings.TrimPrefix(text, "\uFEFF")
	if strings.IndexByte(text, 0) >= 0 {
		return nil, fmt.Errorf("redact: input contains NUL bytes (binary content not supported)")
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}

	label := req.Label
	if label == "" {
		label = "<request>"
	}

	strategy := e.defaultStrategy
	if req.OverrideStrategy {
		strategy = req.Strategy
	}
	if strategy < Simple || strategy > Synthetic {
		return nil, fmt.Errorf("redact: invalid request strategy %d", int(strategy))
	}

	// Synthesize the ProcessedContent the validator pipeline expects.
	// "plaintext" processor type ensures the metadata path is bypassed
	// and ProcessedContent.Filename flows through to Match.Filename.
	processed := &preprocessors.ProcessedContent{
		OriginalPath:            label,
		Filename:                label,
		Text:                    text,
		Format:                  "Plain Text",
		ProcessorType:           "plaintext",
		Success:                 true,
		PositionTrackingEnabled: false,
	}

	// Scope the validator run to the parent context but cap at 5
	// minutes — same ceiling the CLI uses for ScanContent. Callers
	// that need a tighter deadline should pass a derived context.
	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	startTime := time.Now()
	matches, runErr := parallel.RunValidators(scanCtx, e.validatorsList, processed, nil)
	if runErr != nil && e.debug {
		fmt.Fprintf(e.logWriter, "redact: validator error: %v\n", runErr)
	}

	// Stamp every match as virtual + label. ScanContent does this; we
	// repeat it here because we don't go through ScanContent — we call
	// the parallel runner directly to avoid its per-call construction.
	for i := range matches {
		matches[i].SourceKind = detector.SourceKindVirtual
		if matches[i].Filename == "" {
			matches[i].Filename = label
		}
	}

	// Apply per-request suppressions. Suppressed matches pass through
	// unredacted (the redactor is fed only the unsuppressed ones).
	unsuppressed, suppressed := applySuppressions(matches, req.AllowSuppressions, label)

	// Run redaction. Map our public Strategy onto the internal enum.
	internalStrategy := mapStrategy(strategy)
	redacted, _, err := e.redactor.RedactString(text, unsuppressed, internalStrategy)
	if err != nil {
		return nil, fmt.Errorf("redact: redaction failed: %w", err)
	}

	duration := time.Since(startTime)

	// Build findings + audit input maps in one pass.
	findings := make([]finding, 0, len(unsuppressed)+len(suppressed))
	findingsByT := make(map[string]int, 8)
	suppressedByT := make(map[string]int, 4)

	for _, m := range unsuppressed {
		findings = append(findings, finding{
			Type:       m.Type,
			LineNumber: m.LineNumber,
			Confidence: confidenceTier(m.Confidence),
			MatchText:  m.Text,
		})
		findingsByT[m.Type]++
	}
	for _, sm := range suppressed {
		findings = append(findings, finding{
			Type:         sm.Match.Type,
			LineNumber:   sm.Match.LineNumber,
			Confidence:   confidenceTier(sm.Match.Confidence),
			SuppressedBy: sm.SuppressedBy,
			MatchText:    sm.Match.Text,
		})
		suppressedByT[sm.Match.Type]++
	}

	// Clear sensitive data from the original match slice — defense in
	// depth so accidental retention doesn't leak the input bytes.
	for i := range matches {
		matches[i].Clear()
	}

	return &Result{
		Redacted: redacted,
		findings: findings,
		auditInputs: auditInputs{
			label:         label,
			findingsByT:   findingsByT,
			suppressedByT: suppressedByT,
			strategy:      strategy,
			inputBytes:    len(req.Text),
			redactedBytes: len(redacted),
			duration:      duration,
			timestamp:     time.Now().UTC(),
		},
	}, nil
}

// mapStrategy converts a public Strategy into the internal enum used by
// the redactor. The two enums must stay in sync.
func mapStrategy(s Strategy) redactors.RedactionStrategy {
	switch s {
	case Simple:
		return redactors.RedactionSimple
	case FormatPreserving:
		return redactors.RedactionFormatPreserving
	case Synthetic:
		return redactors.RedactionSynthetic
	default:
		return redactors.RedactionFormatPreserving
	}
}

// confidenceTier maps the internal numeric confidence (0–100) onto the
// public coarse Confidence tier. Threshold values mirror the CLI's
// highest-confidence-level computation in cmd/stdin.go.
func confidenceTier(c float64) Confidence {
	switch {
	case c >= 90:
		return ConfidenceHigh
	case c >= 60:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// applySuppressions partitions matches into (unsuppressed, suppressed)
// slices according to the per-request rules. A nil/empty rules list
// suppresses nothing — every match is unsuppressed.
//
// Matching semantics:
//   - Type must match exactly (case-sensitive).
//   - Scope, when non-empty, must equal the request label exactly.
//   - Expired rules (ExpiresAt before now) are dormant — they do not
//     suppress. This matches the CLI's behavior at cmd/stdin.go.
//
// The first matching rule wins.
func applySuppressions(matches []detector.Match, rules []Rule, label string) (
	unsuppressed []detector.Match,
	suppressed []detector.SuppressedMatch,
) {
	if len(rules) == 0 {
		return matches, nil
	}

	now := time.Now()
	for _, m := range matches {
		var matched *Rule
		for i := range rules {
			r := &rules[i]
			if r.Type != m.Type {
				continue
			}
			if r.Scope != "" && r.Scope != label {
				continue
			}
			if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
				continue
			}
			matched = r
			break
		}
		if matched != nil {
			suppressed = append(suppressed, detector.SuppressedMatch{
				Match:        m,
				SuppressedBy: matched.Reason,
				RuleReason:   matched.Reason,
				ExpiresAt:    matched.ExpiresAt,
				Expired:      false,
			})
		} else {
			unsuppressed = append(unsuppressed, m)
		}
	}
	return unsuppressed, suppressed
}
