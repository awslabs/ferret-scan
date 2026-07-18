// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

// Confidence classifies a finding's detection strength into actionable bands.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"   // ≥90 — act on this
	ConfidenceMedium Confidence = "MEDIUM" // ≥60 — review
	ConfidenceLow    Confidence = "LOW"    // <60 — likely noise / test data
)

// ConfidenceOf classifies a numeric score (0–100) into a band.
// Mirrors the engine's internal banding (pkg/redact and internal/core).
// Clamps to [0, 100] defensively — the engine should never produce values
// outside this range, but a validator bug or NaN must not propagate as a
// nonsensical band.
func ConfidenceOf(score float64) Confidence {
	if score != score { // NaN check (NaN != NaN)
		return ConfidenceLow
	}
	switch {
	case score >= 90:
		return ConfidenceHigh
	case score >= 60:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// ClampScore defensively bounds a confidence score to [0, 100].
// Use this when casting float64 → int for JSON serialization to prevent
// overflow/NaN/Inf from producing nonsensical values in the API response.
func ClampScore(score float64) int {
	if score != score { // NaN
		return 0
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return int(score)
}

// Band returns the confidence band for this finding.
func (f Finding) Band() Confidence {
	return ConfidenceOf(f.Confidence)
}
