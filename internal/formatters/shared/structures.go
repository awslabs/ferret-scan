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
	"pattern":              true,
	"pattern_name":         true,
	"pattern_priority":     true,
	"pattern_index":        true,
	"reconstruction_type":  true,
	"consolidated_count":   true,
	"match_text_truncated": true, // boolean flag: display text was bounded
	"cluster_type":         true,

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
	Stats   *formatters.ScanStats `json:"stats,omitempty" yaml:"stats,omitempty"`
	Results []JSONMatch           `json:"results" yaml:"results"`

	// Unredacted lists files whose findings were reported but not redacted, so their
	// values remain in cleartext.
	//
	// A LIST rather than only the stats counters, because a count tells a consumer
	// that something is exposed without telling it what to do. The equivalent
	// not-examined disclosure carries only a count today, which means a consumer must
	// re-run in text format to learn which file — a worse contract that is not worth
	// copying. Retrofitting a list there is tracked separately.
	//
	// omitempty, so every scan that redacted cleanly — and every scan that never
	// asked for redaction — stays byte-identical.
	Unredacted []JSONUnredacted `json:"unredacted,omitempty" yaml:"unredacted,omitempty"`

	Suppressed    []detector.SuppressedMatch `json:"suppressed,omitempty" yaml:"suppressed,omitempty"`
	Truncated     bool                       `json:"truncated,omitempty" yaml:"truncated,omitempty"`
	TotalFindings int                        `json:"total_findings,omitempty" yaml:"total_findings,omitempty"`
}

// JSONUnredacted is one file whose reported values were left in cleartext.
//
// A distinct wire type rather than reusing formatters.UnredactedFile, whose Cause is
// an int-backed enum: marshalling that directly would put an ORDINAL on the wire and
// make the numbering an output contract, so inserting a cause later would silently
// change every consumer's meaning. Cause is emitted as its label instead.
type JSONUnredacted struct {
	Path string `json:"path" yaml:"path"`
	// Cause is the coarse, stable label ("no redactor for this file type").
	Cause string `json:"cause" yaml:"cause"`
	// Detail is the redactor's own explanation, useful for a human triaging.
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
	// ReportedValues is how many findings for this file remain in cleartext.
	ReportedValues int `json:"reported_values" yaml:"reported_values"`
}

// convertUnredacted maps the structured disclosure onto the wire type, capped the same
// way every machine format caps it.
//
// The cap is a denial-of-service bound on the CONSUMER, not on the disclosure: the
// totals stay in stats.files_not_redacted and stats.values_not_redacted, which are
// computed over the full set, so a truncated list can never make the report understate
// the exposure.
func convertUnredacted(files []formatters.UnredactedFile) []JSONUnredacted {
	shown, _ := formatters.CapUnredacted(files)
	if len(shown) == 0 {
		return nil
	}
	out := make([]JSONUnredacted, 0, len(shown))
	for _, f := range shown {
		out = append(out, JSONUnredacted{
			Path:           f.Path,
			Cause:          f.Cause.String(),
			Detail:         f.Detail,
			ReportedValues: f.ReportedValues,
		})
	}
	return out
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

// ApplyLimit truncates an already-filtered, already-sorted slice to
// options.Limit, reporting the pre-truncation total and whether anything was
// dropped. A Limit of 0 or less means unlimited.
//
// Order matters: callers must filter by confidence and sort by priority BEFORE
// truncating, or the surviving findings are an arbitrary subset rather than the
// highest-confidence ones the user asked to see.
func ApplyLimit(matches []detector.Match, options formatters.FormatterOptions) (display []detector.Match, total int, truncated bool) {
	total = len(matches)
	if options.Limit > 0 && total > options.Limit {
		return matches[:options.Limit], total, true
	}
	return matches, total, false
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

// LessByPriority is the total display order shared by every formatter: highest
// confidence first, then type, then line number, filename and text ascending.
// The last three make it a TOTAL order so the emitted sequence is identical run
// to run even when the caller's input order is not (map iteration upstream can
// permute same-(confidence,type) findings).
func LessByPriority(a, b detector.Match) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.LineNumber != b.LineNumber {
		return a.LineNumber < b.LineNumber
	}
	if a.Filename != b.Filename {
		return a.Filename < b.Filename
	}
	return a.Text < b.Text
}

// LessSuppressedByPriority is the total display order for suppressed findings.
// It defers to LessByPriority on the wrapped finding and then breaks any
// remaining tie on the suppressing rule, so two rules matching an identical
// finding still emit in a fixed sequence.
//
// Suppressed findings need their own comparator because nothing sorted them at
// all: every formatter gave `matches` a total order but walked
// `suppressedMatches` in arrival order, and arrival order is per-file worker
// completion order — so `--show-suppressed` reordered its [SUPP] rows on every
// run of the same scan, in text, JSON, YAML and CSV alike.
func LessSuppressedByPriority(a, b detector.SuppressedMatch) bool {
	if LessByPriority(a.Match, b.Match) {
		return true
	}
	if LessByPriority(b.Match, a.Match) {
		return false
	}
	if a.SuppressedBy != b.SuppressedBy {
		return a.SuppressedBy < b.SuppressedBy
	}
	return a.RuleReason < b.RuleReason
}

// SortSuppressedByPriority sorts suppressed findings into the shared total
// display order in place.
func SortSuppressedByPriority(suppressed []detector.SuppressedMatch) {
	sort.SliceStable(suppressed, func(i, j int) bool {
		return LessSuppressedByPriority(suppressed[i], suppressed[j])
	})
}

// SortMatchesByPriority sorts active findings into the shared total display
// order in place. Formatters that own their own copy of the slice (one returned
// by FilterMatchesByConfidence, say) can call this directly; those handed the
// caller's slice should copy first, as gitlab-sast does.
//
// The CSV, SARIF and JUnit formatters had no finding order at all: they walked
// the slice as the scanner handed it over, and that is per-file worker
// completion order, so every run of one unchanged scan emitted its rows,
// results and testcases in a different sequence.
func SortMatchesByPriority(matches []detector.Match) {
	sort.SliceStable(matches, func(i, j int) bool {
		return LessByPriority(matches[i], matches[j])
	})
}

// ConvertMatchesToJSONFormat converts detector matches to JSON/YAML format
func ConvertMatchesToJSONFormat(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) JSONResponse {
	// Sort by confidence descending, then type ascending (same priority order as
	// text), then line/filename/text ascending as a TOTAL order. The final
	// tiebreakers matter: confidence+type alone leaves same-(confidence,type)
	// findings in input order, and the input order can be nondeterministic (map
	// iteration upstream), so without them the serialized output — and any
	// consumer diffing it — flaps run to run on unchanged input.
	sort.SliceStable(matches, func(i, j int) bool {
		return LessByPriority(matches[i], matches[j])
	})

	// The `suppressed` block needs the same treatment, for the same reason: it
	// was serialized in arrival (worker-completion) order, so two JSON or YAML
	// reports of one unchanged scan differed inside that block.
	SortSuppressedByPriority(suppressedMatches)

	// Apply limit
	matches, totalFindings, truncated := ApplyLimit(matches, options)

	// Non-nil, so an empty result set serializes as `"results": []` and not
	// `"results": null`.
	//
	// Results carries no omitempty, so a nil slice reaches the encoder and becomes
	// null. That is not hypothetical: the SARIF formatter had exactly this shape and
	// emitted `"results": null` on every clean scan, which is schema-INVALID and made
	// GitHub reject the whole report (#283). json/yaml never showed it only because an
	// empty result list used to short-circuit before reaching here; now that the
	// zero-finding case routes through this function so it can carry `stats`, the nil
	// would become visible.
	jsonMatches := make([]JSONMatch, 0, len(matches))
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
		Results:    jsonMatches,
		Unredacted: convertUnredacted(options.Unredacted),
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
