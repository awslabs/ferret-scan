// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"sort"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// redactionPlaceholder is the single token used everywhere a sensitive value is
// withheld, so output is consistent across formatters and fields.
const redactionPlaceholder = "[HIDDEN]"

// safeMetadataKeys is an ALLOWLIST of metadata keys that are known to carry only
// non-sensitive, analytical/structural data and are therefore safe to serialize
// when the matched value is hidden (ShowMatch=false).
//
// Redaction here is deny-by-default (fail-safe): the raw value must NEVER be in
// the output unless the operator explicitly opts in with --show-match. So rather
// than enumerate the keys that DO leak (a denylist that fails open the moment a
// validator adds a new value-bearing key), we enumerate the keys that are proven
// safe and withhold everything else. Anything not in this set — including any
// future key — is dropped when ShowMatch is false.
//
// Adding a key here is a deliberate security decision: it asserts the key's
// value can never contain matched content or other PII. Keys that echo the
// matched value or document content (e.g. name_components, full_field, clean_ip,
// clean_number, username, field_name, description, message) are intentionally
// absent and are withheld until --show-match.
var safeMetadataKeys = map[string]bool{
	// Classification / type labels
	"card_type":       true,
	"vendor":          true,
	"metadata_type":   true,
	"ip_type":         true,
	"pii_type":        true,
	"secret_type":     true,
	"pattern_type":    true,
	"platform":        true,
	"type":            true,
	"document_type":   true,
	"coordinate_type": true,
	"email_provider":  true,
	"language":        true,
	"format":          true,

	// Confidence / scoring / correlation (numeric or structured, no content)
	"confidence_adjustment":   true,
	"original_confidence":     true,
	"context_impact":          true,
	"enhanced_context_impact": true,
	"context_confidence":      true,
	"confidence_factors":      true,
	"correlation_boost":       true,
	"cross_path_correlation":  true,
	"cross_validator_signals": true,
	"cross_validator_impact":  true,
	"total_adjustment":        true,
	"preprocessor_adjustment": true,
	"semantic_context":        true,
	"analysis_confidence":     true,

	// Context classification (labels/scores, not raw text)
	"context_domain":   true,
	"context_doctype":  true,
	"context_doc_type": true,
	"context_keywords": true,
	"cultural_context": true,
	"environment_type": true,

	// Validation results / detection bookkeeping.
	// NOTE: validation_details is intentionally NOT allowlisted. Unlike
	// validation_checks (booleans) and validation_path (a "document"/"metadata"
	// label), some validators populate validation_details with value-derived
	// sub-fields — e.g. the social-media validator embeds the raw matched
	// LinkedIn URL/username (actual_path, extracted_username, domain). Echoing
	// it would re-leak the value the Text field redacts. Withheld until
	// --show-match. (Caught by scanning real documents, not synthetic fixtures.)
	"validation_checks": true,
	"validation_path":   true,
	"detection_method":  true,
	"detection_reason":  true,
	"is_private":        true,
	"is_reserved":       true,
	"not_test":          true,
	"first_names_count": true,
	"last_names_count":  true,

	// Pattern bookkeeping (names of internal patterns, not matched content)
	"pattern":             true,
	"pattern_name":        true,
	"pattern_priority":    true,
	"pattern_index":       true,
	"reconstruction_type": true,
	"consolidated_count":  true,
	"cluster_type":        true,

	// Risk classification (levels/factors, not content)
	"custom_prop_risk_level":   true,
	"custom_prop_risk_factors": true,
	"template_risk_level":      true,
	"template_risk_factors":    true,

	// Provenance — the scanned file path / preprocessor, already exposed via the
	// top-level filename field; not match content.
	"source":              true,
	"source_file":         true,
	"original_file":       true,
	"source_preprocessor": true,
	"preprocessor_name":   true,
	"preprocessor_type":   true,
	"validator_version":   true,
	"check_type":          true,
}

// SanitizeMetadata returns a copy of a finding's metadata that is safe to
// serialize given the ShowMatch setting. It is the single, canonical path shared
// by every formatter that emits the metadata map (JSON, YAML, SARIF, CSV), so
// the matched value can never reach output through metadata when it is hidden in
// the Text field.
//
//   - ShowMatch=true: all metadata is returned (only the explain key is dropped,
//     since it is surfaced separately as a first-class field).
//   - ShowMatch=false: ONLY allowlisted, known-safe keys are returned
//     (deny-by-default). Every other key — including any new/unknown one — is
//     withheld so raw values can never leak.
//
// Returns nil when nothing remains, so callers can omit an empty map.
func SanitizeMetadata(meta map[string]interface{}, matchText string, showMatch bool) map[string]interface{} {
	if len(meta) == 0 {
		return nil
	}

	out := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		// The explanation is surfaced as a first-class field; never dump it raw.
		if k == explain.MetadataKey {
			continue
		}
		// Deny-by-default: when the value is hidden, emit only proven-safe keys.
		if !showMatch && !safeMetadataKeys[k] {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SanitizeSuppressedMatches returns suppressed matches that are safe to
// serialize given the ShowMatch setting. The JSON/YAML formatters embed the
// raw detector.SuppressedMatch (its finding's Text, Metadata, and Context all
// carry the matched value and surrounding line), so without this the
// `suppressed` block re-leaks exactly what the active-results redaction hides —
// e.g. `--show-suppressed` without `--show-match` would dump raw cards/SSNs.
//
//   - ShowMatch=true: returned unchanged (the web UI relies on the real value
//     to power its client-side click-to-reveal of suppressed findings).
//   - ShowMatch=false: a copy is returned with the finding's value-bearing
//     fields redacted, while the structural/suppression fields (type, line,
//     confidence, filename, validator, suppressed_by, rule_reason, expiry) are
//     preserved so the entry is still useful.
func SanitizeSuppressedMatches(suppressed []detector.SuppressedMatch, showMatch bool) []detector.SuppressedMatch {
	if showMatch || len(suppressed) == 0 {
		return suppressed
	}
	out := make([]detector.SuppressedMatch, len(suppressed))
	for i, s := range suppressed {
		sanitized := s // copy the suppression envelope (SuppressedBy, RuleReason, ...)
		m := s.Match   // copy the finding so we don't mutate the caller's slice
		m.Metadata = SanitizeMetadata(m.Metadata, s.Match.Text, false)
		m.Text = redactionPlaceholder
		m.SecureText = nil
		// Context holds the raw surrounding line and before/after text.
		m.Context.FullLine = ""
		m.Context.BeforeText = ""
		m.Context.AfterText = ""
		sanitized.Match = m
		out[i] = sanitized
	}
	return out
}

// JSONResponse represents the top-level response structure for JSON/YAML output
type JSONResponse struct {
	Stats         *formatters.ScanStats      `json:"stats,omitempty" yaml:"stats,omitempty"`
	Results       []JSONMatch                `json:"results" yaml:"results"`
	Suppressed    []detector.SuppressedMatch `json:"suppressed,omitempty" yaml:"suppressed,omitempty"`
	Truncated     bool                       `json:"truncated,omitempty" yaml:"truncated,omitempty"`
	TotalFindings int                        `json:"total_findings,omitempty" yaml:"total_findings,omitempty"`
}

// JSONMatch represents a single match in JSON/YAML format
type JSONMatch struct {
	Text            string                 `json:"text" yaml:"text"`
	LineNumber      int                    `json:"line_number" yaml:"line_number"`
	Type            string                 `json:"type" yaml:"type"`
	Confidence      float64                `json:"confidence" yaml:"confidence"`
	ConfidenceLevel string                 `json:"confidence_level" yaml:"confidence_level"`
	Filename        string                 `json:"filename" yaml:"filename"`
	Validator       string                 `json:"validator,omitempty" yaml:"validator,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Explanation     *JSONExplanation       `json:"explanation,omitempty" yaml:"explanation,omitempty"`
	FullLine        string                 `json:"full_line,omitempty" yaml:"full_line,omitempty"`
	BeforeText      string                 `json:"before_text,omitempty" yaml:"before_text,omitempty"`
	AfterText       string                 `json:"after_text,omitempty" yaml:"after_text,omitempty"`
}

// JSONExplanation is the first-class, schema-stable rendering of an advisory
// explanation (present only when scanned with --explain). It is lifted out of
// the raw Metadata map so consumers get a defined field instead of a nested
// blob, and so the explanation has exactly one representation on the wire.
type JSONExplanation struct {
	Rationale           string `json:"rationale" yaml:"rationale"`
	Verdict             string `json:"verdict" yaml:"verdict"`
	DraftSuppressReason string `json:"draft_suppress_reason,omitempty" yaml:"draft_suppress_reason,omitempty"`
}

// FilterMatchesByConfidence filters matches based on confidence level settings
func FilterMatchesByConfidence(matches []detector.Match, options formatters.FormatterOptions) []detector.Match {
	var filtered []detector.Match
	for _, match := range matches {
		if (match.Confidence >= 90 && options.ConfidenceLevel["high"]) ||
			(match.Confidence >= 60 && match.Confidence < 90 && options.ConfidenceLevel["medium"]) ||
			(match.Confidence < 60 && options.ConfidenceLevel["low"]) {
			filtered = append(filtered, match)
		}
	}
	return filtered
}

// GetConfidenceLevel returns the confidence level as a string
func GetConfidenceLevel(confidence float64) string {
	switch {
	case confidence >= 90:
		return "HIGH"
	case confidence >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ConvertMatchesToJSONFormat converts detector matches to JSON/YAML format
func ConvertMatchesToJSONFormat(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) JSONResponse {
	totalFindings := len(matches)

	// Sort by confidence descending, then type ascending (same priority order as text)
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].Type < matches[j].Type
	})

	// Apply limit
	truncated := false
	if options.Limit > 0 && totalFindings > options.Limit {
		matches = matches[:options.Limit]
		truncated = true
	}

	var jsonMatches []JSONMatch
	for _, match := range matches {
		// Sanitize metadata through the single shared path so a value duplicated
		// inside metadata (e.g. name_components, full_field) cannot defeat the
		// Text-field redaction below.
		metadata := SanitizeMetadata(match.Metadata, match.Text, options.ShowMatch)

		confidenceLevel := GetConfidenceLevel(match.Confidence)

		// Determine display text based on ShowMatch option. When ShowMatch is
		// false, substitute "[HIDDEN]" so raw sensitive data is never serialized
		// into JSON/YAML output, matching the text, CSV, SARIF, and JUnit formatters.
		displayText := redactionPlaceholder
		if options.ShowMatch {
			displayText = match.Text
		}

		jsonMatch := JSONMatch{
			Text:            displayText,
			LineNumber:      match.LineNumber,
			Type:            match.Type,
			Confidence:      match.Confidence,
			ConfidenceLevel: confidenceLevel,
			Filename:        match.Filename,
			Validator:       match.Validator,
			Metadata:        metadata,
		}

		if ex, ok := explain.FromMatch(match); ok {
			jsonMatch.Explanation = &JSONExplanation{
				Rationale:           ex.Rationale,
				Verdict:             string(ex.Verdict),
				DraftSuppressReason: ex.DraftSuppressReason,
			}
		}

		// Verbose context fields (full line, surrounding text) contain the raw
		// matched value, so they must ALSO be gated on ShowMatch — otherwise
		// --verbose re-leaks the secret that ShowMatch=false just hid in Text
		// (e.g. full_line "apiKey := \"sk_live_...\""). Require both.
		if options.Verbose && options.ShowMatch {
			if match.Context.FullLine != "" {
				jsonMatch.FullLine = match.Context.FullLine
			}
			if match.Context.BeforeText != "" {
				jsonMatch.BeforeText = match.Context.BeforeText
			}
			if match.Context.AfterText != "" {
				jsonMatch.AfterText = match.Context.AfterText
			}
		}

		jsonMatches = append(jsonMatches, jsonMatch)
	}

	resp := JSONResponse{
		Results: jsonMatches,
		// Suppressed matches embed the raw finding, so route them through the
		// same deny-by-default redaction as active results: without --show-match
		// the value, metadata, and surrounding context are withheld.
		Suppressed: SanitizeSuppressedMatches(suppressedMatches, options.ShowMatch),
		Stats:      options.Stats,
	}
	if truncated {
		resp.Truncated = true
		resp.TotalFindings = totalFindings
	}
	return resp
}
