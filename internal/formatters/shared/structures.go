// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/explain"
	"github.com/awslabs/ferret-scan/internal/formatters"
)

// JSONResponse represents the top-level response structure for JSON/YAML output
type JSONResponse struct {
	Results    []JSONMatch                `json:"results" yaml:"results"`
	Suppressed []detector.SuppressedMatch `json:"suppressed,omitempty" yaml:"suppressed,omitempty"`
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
	var jsonMatches []JSONMatch
	for _, match := range matches {
		metadata := make(map[string]interface{})
		for k, v := range match.Metadata {
			// The explanation is surfaced as a first-class field below; don't
			// also dump it as a raw blob in metadata (one representation only).
			if k == explain.MetadataKey {
				continue
			}
			metadata[k] = v
		}
		if len(metadata) == 0 {
			metadata = nil // keep `metadata` omitted rather than emitting {}
		}

		confidenceLevel := GetConfidenceLevel(match.Confidence)

		jsonMatch := JSONMatch{
			Text:            match.Text,
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

		if options.Verbose {
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

	return JSONResponse{
		Results:    jsonMatches,
		Suppressed: suppressedMatches,
	}
}
