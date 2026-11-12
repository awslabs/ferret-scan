// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nationalid detects national identification numbers that no other check covers: the
// Americas rows of #884 Part B, Brazil's CPF, Chile's RUT/RUN, Argentina's CUIL (with the personal
// CUIT prefixes), Canada's SIN and Mexico's CURP.
//
// Before it, a file holding only these numbers reported nothing and was never redacted: measured on
// main @ 3aa380e, the issue's §1 files gave 2 findings (both ITIN) and the redacted copy of its
// new-hire sink kept CPF, CURP, RUT, CUIL and SIN byte for byte.
//
// Every row is tier B (labels.go): a value is reported only beside its own label, and only when its
// check digit and structural rules pass (checks.go). A labelled value whose check digit fails is not
// reported, so a synthetic replacement that fails the check (internal/redactors/replacement) never
// re-detects in a redacted copy.
package nationalid

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// shape is one printed form of one identifier.
type shape struct {
	dataType string
	re       *regexp.Regexp
}

// shapes are the printed forms each type is matched in. Separators must be consistent within a value
// (a SIN is 3-3-3 with two dashes or two spaces); a bare digit run is allowed because the label is
// required anyway. A SIN never matches the SSN's 3-2-4 grouping.
var shapes = []shape{
	{TypeBRCPF, regexp.MustCompile(`\d{3}\.\d{3}\.\d{3}-\d{2}|\d{9}-\d{2}|\d{11}`)},
	{TypeCLRUT, regexp.MustCompile(`\d{1,2}\.\d{3}\.\d{3}-[0-9Kk]|\d{7,8}-[0-9Kk]`)},
	{TypeARCUIL, regexp.MustCompile(`(?:20|23|24|27)-\d{8}-\d|(?:20|23|24|27)\d{9}`)},
	{TypeCASIN, regexp.MustCompile(`\d{3}-\d{3}-\d{3}|\d{3} \d{3} \d{3}|\d{9}`)},
	{TypeMXCURP, regexp.MustCompile(`(?i)[A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{5}[0-9A-Z]\d`)},
}

// countryOf is each type's ISO 3166-1 alpha-2 country, carried in the finding's metadata.
var countryOf = map[string]string{
	TypeBRCPF: "BR", TypeCLRUT: "CL", TypeARCUIL: "AR", TypeCASIN: "CA", TypeMXCURP: "MX",
}

// Confidence. A labelled value whose check passes is HIGH; the label is the only context read.
const (
	// confidenceStrong: a long-form label, or an acronym with a colon/ordinal ("CPF nº", "SIN:").
	confidenceStrong = 95
	// confidenceAcronym: a capitalised acronym directly before the value ("RUN 12345678-5").
	confidenceAcronym = 90
)

// Validator detects the Americas national identifiers.
type Validator struct {
	observer observability.Observer
}

// NewValidator returns a national-ID validator.
func NewValidator() *Validator { return &Validator{} }

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) { v.observer = observer }

// CalculateConfidence scores a bare value with no context: a valid value of any row scores the
// acronym-label confidence, anything else 0. It satisfies detector.Validator; the scan path scores in
// ValidateContentCtx, where the label is known.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	for _, t := range Types {
		if Valid(t, match) {
			return confidenceAcronym, map[string]bool{"check_digit": true}
		}
	}
	return 0, map[string]bool{"check_digit": false}
}

// AnalyzeContext returns no adjustment: the label gate in ValidateContentCtx is the context rule.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 { return 0 }

// ValidateContent scans content for labelled national identifiers.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// isAlnum reports whether b is an ASCII letter or digit.
func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// standsAlone reports whether line[start:end] is a whole token: not glued to a letter or digit, and
// not one segment of a longer dotted or dashed number ("1.234.567.890-92-3", "v12.345.678-5").
func standsAlone(line string, start, end int) bool {
	if start > 0 {
		p := line[start-1]
		if isAlnum(p) || ((p == '.' || p == '-' || p == '/') && start > 1 && isAlnum(line[start-2])) {
			return false
		}
	}
	if end < len(line) {
		n := line[end]
		if isAlnum(n) || ((n == '.' || n == '-' || n == '/') && end+1 < len(line) && isAlnum(line[end+1])) {
			return false
		}
	}
	return true
}

// ValidateContentCtx implements execguard.ContextAwareValidator, polling ctx once per line.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("nationalid_validator", "validate_content", originalPath)
	}
	var matches []detector.Match
	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": len(matches)})
			}
			return matches, ctx.Err()
		}
		if !strings.ContainsAny(line, "0123456789") || !lineMayHaveLabel(fold(line)) {
			continue
		}
		for _, sh := range shapes {
			for _, loc := range sh.re.FindAllStringIndex(line, -1) {
				start, end := loc[0], loc[1]
				if !standsAlone(line, start, end) {
					continue
				}
				value := line[start:end]
				if !Valid(sh.dataType, value) {
					continue
				}
				l, gap, ok := labelBefore(line, start, sh.dataType)
				if !ok {
					continue
				}
				confidence := float64(confidenceStrong)
				if l.abbr && !strongSeparator(gap) {
					confidence = confidenceAcronym
				}
				matches = append(matches, detector.Match{
					Text:       value,
					LineNumber: lineNum + 1,
					Type:       sh.dataType,
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "nationalid",
					Context: detector.ContextInfo{
						FullLine:         line,
						PositiveKeywords: []string{l.text},
					},
					Metadata: map[string]any{
						"country":           countryOf[sh.dataType],
						"check_digit_valid": true,
						"source":            "preprocessed_content",
					},
				})
			}
		}
	}
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(lines),
			"content_length":  len(content),
		})
	}
	return matches, nil
}
