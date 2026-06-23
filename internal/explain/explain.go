// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package explain turns a finding into a plain-language rationale, a verdict
// gloss on its existing confidence, and a drafted suppression justification.
//
// The default implementation (SignalSynthesizer) is pure Go with no external
// dependencies and makes no network calls: it only re-phrases signals the
// detection engine has ALREADY computed and stored on Match.Metadata (e.g.
// "validation_checks", "vendor", "context_impact"). This keeps the project's
// privacy / offline / tiny-static-binary guarantees intact by construction —
// see docs/proposals/AI_ENHANCEMENT_FERRET_EXPLAIN.md.
//
// Explanations are ADVISORY annotations only. The explainer never mutates a
// Match's Confidence and never auto-suppresses a finding. In particular the
// Verdict is a human-readable gloss on the confidence the engine already
// assigned, NOT an independent signal — a security tool must never talk a
// reviewer out of a real finding, so HIGH findings always surface regardless
// of verdict.
package explain

import "github.com/awslabs/ferret-scan/internal/detector"

// MetadataKey is the Match.Metadata key under which an Explanation is stashed
// by the pipeline once an Explainer has run. Formatters read it from here.
//
// IMPORTANT: detector.Match.Clear() must scrub this key — see
// detector.Match.Clear. The Explanation contains no payload bytes today, but
// keeping it on the same lifecycle as Text/Context avoids a future retention
// surface if a richer (e.g. LLM) backend ever echoes content.
const MetadataKey = "explanation"

// Verdict is a coarse, human-facing gloss on a finding's existing confidence.
// It is NOT an independent detection signal.
type Verdict string

const (
	// VerdictLikelyReal indicates the finding looks like real sensitive data.
	VerdictLikelyReal Verdict = "likely_real"
	// VerdictLikelyTest indicates the finding looks like test / placeholder /
	// example data (e.g. it matched a known test pattern or sits in a test file).
	VerdictLikelyTest Verdict = "likely_test"
	// VerdictUncertain indicates the available signals don't lean either way.
	VerdictUncertain Verdict = "uncertain"
)

// Explanation is the advisory annotation attached to a finding. It carries no
// payload bytes (no copy of Match.Text); it only references the finding's type
// and the signals the engine already computed.
type Explanation struct {
	// Rationale is a one or two sentence plain-language "why this was flagged".
	Rationale string `json:"rationale"`
	// Verdict is a gloss on the existing confidence (see Verdict docs).
	Verdict Verdict `json:"verdict"`
	// DraftSuppressReason is a human-readable justification suitable for the
	// `reason` field of a generated suppression rule. It is a suggestion for a
	// human to review, never an instruction to auto-suppress.
	DraftSuppressReason string `json:"draft_suppress_reason"`
}

// Explainer produces an Explanation for a finding. Implementations MUST be
// pure with respect to the Match: they read it and return an Explanation, and
// MUST NOT mutate the Match (in particular MUST NOT change Confidence).
type Explainer interface {
	Explain(m detector.Match) Explanation
}

// Annotate runs the explainer over each match and stashes the result on
// match.Metadata[MetadataKey]. It is the single helper the scan pipeline calls
// at the post-detection seam.
//
// Constraints enforced here:
//   - Confidence is never read-modified-written; we only add a metadata key.
//   - It is safe to call with a nil explainer (no-op) so callers can wire it
//     unconditionally and gate on a flag.
//   - It runs AFTER suppression-hash computation in the pipeline, so adding the
//     annotation cannot change a finding's suppression identity.
func Annotate(matches []detector.Match, e Explainer) {
	if e == nil {
		return
	}
	for i := range matches {
		ex := e.Explain(matches[i])
		if matches[i].Metadata == nil {
			matches[i].Metadata = make(map[string]any)
		}
		matches[i].Metadata[MetadataKey] = ex
	}
}

// FromMatch returns the Explanation previously attached to a match, if any.
// Formatters use this to enrich output without re-running the explainer.
func FromMatch(m detector.Match) (Explanation, bool) {
	if m.Metadata == nil {
		return Explanation{}, false
	}
	ex, ok := m.Metadata[MetadataKey].(Explanation)
	return ex, ok
}
