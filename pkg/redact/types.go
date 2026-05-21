// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"io"
	"time"
)

// Strategy selects the redaction algorithm applied to matched substrings.
type Strategy int

const (
	// Simple replaces each match with a placeholder marker like
	// "[CREDIT-CARD-REDACTED]". Lossy but most legible.
	Simple Strategy = iota

	// FormatPreserving keeps the same length and structural format as the
	// original (e.g. "5500-****-****-0004"). Best for callers that need
	// the byte length and surrounding structure unchanged downstream.
	FormatPreserving

	// Synthetic replaces each match with realistic but fake data of the
	// same type (e.g. a different valid Visa number for a Visa match).
	// Best for building test datasets from real traffic.
	Synthetic
)

// String returns the canonical lowercase name of the strategy.
func (s Strategy) String() string {
	switch s {
	case Simple:
		return "simple"
	case FormatPreserving:
		return "format_preserving"
	case Synthetic:
		return "synthetic"
	default:
		return "unknown"
	}
}

// Confidence is a coarse classification of how confident the validator
// is that a finding is a real match. Numeric confidence (0–100) is folded
// into one of three tiers; the tier is what the public API exposes so
// callers don't depend on the exact thresholds (which are tuning
// parameters, not contract).
type Confidence string

const (
	ConfidenceLow    Confidence = "low"    // <60
	ConfidenceMedium Confidence = "medium" // 60–89
	ConfidenceHigh   Confidence = "high"   // >=90
)

// Rule is a project-supplied suppression rule. Public callers construct
// these directly; ferret-scan does not load them from disk on the public
// path. Each rule matches a finding by Type and (optionally) by location
// scope, and may carry an expiry — expired rules are dormant, not
// actively whitelisting.
//
// Field semantics:
//
//   - Type names a finding type. Match is exact and case-sensitive. Most
//     validators emit a single type ("EMAIL", "SSN", "PHONE"), but the
//     credit-card validator emits brand-specific types: "VISA",
//     "MASTERCARD", "AMERICAN_EXPRESS", "DISCOVER", "JCB",
//     "DINERS_CLUB", "UNKNOWN_CARD". To suppress all credit-card
//     findings you must enumerate the brands you want to allow.
//
//     TODO(future): a redact.ExpandTypeAliases([]string{"CREDIT_CARD"})
//     helper or an Aliases []string field would close the gap. Tracked
//     as a v1.x follow-up — for now, callers should consult
//     Result.AuditRecord().FindingsByType to enumerate the actual
//     emitted types and write rules against those.
//
//   - Scope optionally restricts the rule to findings whose Label (the
//     synthetic source label set in Request.Label) matches the given
//     string exactly. An empty Scope means "applies to all labels".
//
//   - ExpiresAt, when non-nil, marks the rule dormant after the
//     specified time. Expired rules do not suppress matches; expiry
//     means the rule is inactive, not that it actively whitelists. A
//     nil ExpiresAt means the rule never expires.
//
//   - Reason is a human-readable string explaining why the rule exists.
//     It is preserved on the finding record (in the SuppressedBy field)
//     for audit traceability.
type Rule struct {
	Type      string
	Scope     string
	ExpiresAt *time.Time
	Reason    string
}

// Request carries the per-call inputs to Engine.Redact.
//
// Only Text is required. Strategy defaults to the engine-level Strategy
// (set in EngineOptions) when zero; Label defaults to "<request>";
// AllowSuppressions is empty by default (no suppressions applied).
type Request struct {
	// Text is the input content to scan and redact.
	Text string

	// Label is a synthetic source identifier stamped on every finding
	// (e.g. a request ID, customer ID, or trace ID). Useful for log
	// correlation and per-tenant suppression scoping. Defaults to
	// "<request>" when empty.
	Label string

	// Strategy overrides the engine's default redaction strategy for
	// this request. Zero (Simple) is a valid value; if you want to
	// inherit the engine default, leave Strategy at the zero value AND
	// set OverrideStrategy=false. The OverrideStrategy bool exists
	// because Go can't distinguish "explicitly Simple" from "field not
	// set" on an int-backed enum.
	Strategy         Strategy
	OverrideStrategy bool

	// AllowSuppressions is the per-request set of suppression rules.
	// Findings matching any rule are suppressed; the redacted output
	// will contain the original (unmasked) substring for those matches.
	//
	// IMPORTANT: passing a non-empty AllowSuppressions in a
	// multi-tenant gateway is a footgun — a tenant with a permissive
	// rule could leak data through the redactor. Default to nil; only
	// pass rules you have built tenant isolation around.
	AllowSuppressions []Rule
}

// Finding is a single sensitive-data hit in the input text.
//
// The matched substring is deliberately NOT exposed on this struct.
// Callers who need the actual matched bytes use Result.FindingsWithMatchText,
// which returns a separate slice with the substrings included.
//
// Finding is safe to log directly: the fmt verbs %v / %+v will not leak
// the input payload because Match is not a field.
type Finding struct {
	// Type is the validator-assigned classification. For most checks
	// this is the parent name (e.g. "EMAIL", "SSN", "PHONE"). For
	// credit cards it is the brand-specific name emitted by the
	// validator: "VISA", "MASTERCARD", "AMERICAN_EXPRESS",
	// "DISCOVER", "JCB", "DINERS_CLUB", or "UNKNOWN_CARD". Suppression
	// rules match this exact string — see Rule.Type.
	//
	// To enumerate the actual type names produced by a given input,
	// inspect Result.AuditRecord().FindingsByType after a Redact call.
	Type string

	// LineNumber is 1-based and points at the start line of the match
	// in the input text. Multi-line matches report the line they begin on.
	LineNumber int

	// Confidence classifies how strong the match is.
	Confidence Confidence

	// SuppressedBy, when non-empty, names the rule that suppressed this
	// finding. Suppressed findings appear in the result for transparency
	// but their corresponding bytes pass through the redactor unchanged.
	SuppressedBy string
}

// FindingWithMatchText is Finding with the matched substring attached.
// Returned only by Result.FindingsWithMatchText. Callers that log this
// type are responsible for redacting MatchText before persisting it.
type FindingWithMatchText struct {
	Finding

	// MatchText is the literal substring from the input that was
	// detected. Logging or persisting this field defeats the purpose
	// of redaction — handle with care.
	MatchText string
}

// AuditRecord is a payload-free summary of a redaction operation. It
// is safe to log directly to CloudWatch, S3 with Object Lock, or any
// WORM-style audit sink; it contains no matched substrings, no offsets,
// and no input bytes.
//
// Schema is intentionally narrow: per-type counts are sufficient to
// answer "did the gateway see a CC at this point in time?" without
// telling the reader which CC. The struct shape enforces this by
// construction; no field carries payload bytes, offsets, or substrings.
type AuditRecord struct {
	// Label is the request's Label (or "<request>" if unset). Use this
	// to correlate the audit record with upstream request logs.
	Label string

	// FindingsByType maps finding type (e.g. "CREDIT_CARD") to the
	// number of unsuppressed findings of that type.
	FindingsByType map[string]int

	// SuppressedByType maps finding type to the number of suppressed
	// (passed-through) findings of that type.
	SuppressedByType map[string]int

	// Strategy is the redaction strategy that was applied.
	Strategy Strategy

	// InputBytes / RedactedBytes are byte-length counts; format-preserving
	// redaction emits identical lengths, simple emits longer text with
	// the placeholder, synthetic preserves length.
	InputBytes    int
	RedactedBytes int

	// Duration is the wall-clock duration of the Redact call. It rounds
	// to microseconds in the JSON marshaling but is stored at full
	// resolution.
	Duration time.Duration

	// Timestamp is the moment the Redact call returned (UTC). Use this
	// rather than your own clock to anchor the audit record to the
	// engine's view of when the redaction happened.
	Timestamp time.Time
}

// Result is the output of Engine.Redact.
type Result struct {
	// Redacted is the input text with each unsuppressed match replaced
	// according to the strategy. Suppressed findings (matching a rule
	// in AllowSuppressions) pass through unchanged.
	Redacted string

	// findings is unexported; callers reach it via Findings() and
	// FindingsWithMatchText() so we control what's reachable.
	findings []finding

	// auditRecord is computed lazily by AuditRecord() to keep the
	// hot path's allocation profile predictable; the Redact path
	// pre-fills the inputs it needs.
	auditInputs auditInputs
}

// auditInputs holds the data needed to construct an AuditRecord without
// retaining the full match list once the result has been returned.
type auditInputs struct {
	label         string
	findingsByT   map[string]int
	suppressedByT map[string]int
	strategy      Strategy
	inputBytes    int
	redactedBytes int
	duration      time.Duration
	timestamp     time.Time
}

// finding is the internal representation that retains the matched text,
// expiry rule reference, etc. It is converted to the public Finding /
// FindingWithMatchText types on demand.
type finding struct {
	Type         string
	LineNumber   int
	Confidence   Confidence
	SuppressedBy string
	MatchText    string
}

// Findings returns the public, payload-free finding list. Safe to log.
func (r *Result) Findings() []Finding {
	out := make([]Finding, len(r.findings))
	for i, f := range r.findings {
		out[i] = Finding{
			Type:         f.Type,
			LineNumber:   f.LineNumber,
			Confidence:   f.Confidence,
			SuppressedBy: f.SuppressedBy,
		}
	}
	return out
}

// FindingsWithMatchText returns the findings with the matched substrings
// attached. The returned slice contains the literal input bytes that
// matched — handle with care; do not log to any sink that isn't already
// designed for sensitive content.
func (r *Result) FindingsWithMatchText() []FindingWithMatchText {
	out := make([]FindingWithMatchText, len(r.findings))
	for i, f := range r.findings {
		out[i] = FindingWithMatchText{
			Finding: Finding{
				Type:         f.Type,
				LineNumber:   f.LineNumber,
				Confidence:   f.Confidence,
				SuppressedBy: f.SuppressedBy,
			},
			MatchText: f.MatchText,
		}
	}
	return out
}

// AuditRecord returns the audit summary for this Redact call.
func (r *Result) AuditRecord() AuditRecord {
	// Defensive copies so a caller can't mutate the engine's snapshot.
	findingsByT := make(map[string]int, len(r.auditInputs.findingsByT))
	for k, v := range r.auditInputs.findingsByT {
		findingsByT[k] = v
	}
	suppressedByT := make(map[string]int, len(r.auditInputs.suppressedByT))
	for k, v := range r.auditInputs.suppressedByT {
		suppressedByT[k] = v
	}
	return AuditRecord{
		Label:            r.auditInputs.label,
		FindingsByType:   findingsByT,
		SuppressedByType: suppressedByT,
		Strategy:         r.auditInputs.strategy,
		InputBytes:       r.auditInputs.inputBytes,
		RedactedBytes:    r.auditInputs.redactedBytes,
		Duration:         r.auditInputs.duration,
		Timestamp:        r.auditInputs.timestamp,
	}
}

// EngineOptions configures Engine construction. All fields are optional;
// the zero value yields an engine that runs every default validator with
// FormatPreserving redaction and no log output.
type EngineOptions struct {
	// Checks names the validators to enable. Empty (default) or
	// containing "all" enables every default validator. Case-sensitive;
	// names match the project's internal validator IDs (e.g.
	// "CREDIT_CARD", "EMAIL", "SSN", "PHONE", "PASSPORT", "VIN",
	// "SECRETS", "INTELLECTUAL_PROPERTY", "SOCIAL_MEDIA", "IP_ADDRESS",
	// "PERSON_NAME"). The METADATA validator requires filesystem access
	// and is not available on this in-memory path; passing it is a no-op.
	Checks []string

	// Strategy is the default redaction strategy for Redact calls that
	// don't override it via Request.Strategy. Defaults to FormatPreserving.
	Strategy Strategy

	// LogWriter receives observability output (progress lines, debug
	// messages from the underlying scanner). Defaults to io.Discard so
	// nothing is written. Pass os.Stderr in development to surface the
	// internal observer, or wire your structured logger's writer to
	// route through your own logging stack.
	//
	// Critically, the underlying scanner writes payload-free progress
	// strings only — it does NOT log matched substrings. Future-proofing:
	// even if a future change accidentally introduced payload logging,
	// LogWriter gives the caller a chokepoint to enforce no-payload-bytes
	// at the destination. The io.Discard default makes the no-leak
	// property enforceable rather than aspirational — even a regression
	// that started writing payload bytes to the observer would not
	// reach a log sink unless the caller explicitly wired LogWriter.
	LogWriter io.Writer

	// Debug toggles verbose internal logging. Implies LogWriter is set
	// (or stderr by default). Off by default.
	Debug bool
}

// Common errors returned by the package.
var (
	// ErrEmptyText is returned when Engine.Redact is called with an
	// empty Request.Text. The caller usually wants to fast-path that
	// case rather than scan an empty buffer.
	ErrEmptyText = errors.New("redact: request text is empty")

	// ErrTextTooLarge is returned when Request.Text exceeds MaxInputBytes.
	ErrTextTooLarge = errors.New("redact: request text exceeds 100 MB limit")

	// ErrEngineClosed is returned by Redact after Close has been called.
	ErrEngineClosed = errors.New("redact: engine is closed")
)

// MaxInputBytes is the hard cap on Request.Text size, mirroring the
// CLI's stdin limit. Larger inputs should be processed via streaming
// or by writing to a file and using the file-mode CLI.
const MaxInputBytes = 100 * 1024 * 1024
