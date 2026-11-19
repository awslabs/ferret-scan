// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nationalid detects national identification numbers that no other check covers: the
// Americas rows of #884 Part B, Brazil's CPF, Chile's RUT/RUN, Argentina's CUIL (with the personal
// CUIT prefixes), Canada's SIN and Mexico's CURP and RFC.
//
// Before it, a file holding only these numbers reported nothing and was never redacted: measured on
// main @ 3aa380e, the issue's §1 files gave 2 findings (both ITIN) and the redacted copy of its
// new-hire sink kept CPF, CURP, RUT, CUIL and SIN byte for byte.
//
// Every row is tier B (labels.go): a value is reported only beside its own label, and only when its
// structural rules pass (checks.go). With the check digit passing it is HIGH; with the check digit
// failing it is LOW with checksum_valid=false. A synthetic replacement (internal/redactors/replacement)
// fails the structure or is skipped by isSyntheticShape, so it never re-detects in a redacted copy.
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
	{TypeCLRUT, regexp.MustCompile(`\d{1,2}\.\d{3}\.\d{3}-[0-9Kk]|\d{7,8}-[0-9Kk]|\d{7,8}[0-9Kk]`)},
	{TypeARCUIL, regexp.MustCompile(`(?:20|23|24|27)-\d{8}-\d|(?:20|23|24|27)\d{9}`)},
	{TypeCASIN, regexp.MustCompile(`\d{3}-\d{3}-\d{3}|\d{3} \d{3} \d{3}|\d{9}`)},
	{TypeMXCURP, regexp.MustCompile(`(?i)[A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{5}[0-9A-Z]\d`)},
	// shortcut: ASCII only, so an RFC whose name letters include Ñ is not read; add it with the SAT's
	// table value (38) when one is measured in a corpus.
	{TypeMXRFC, regexp.MustCompile(`(?i)[A-Z&]{3,4}\d{6}[0-9A-Z]{3}`)},
}

// countryOf is each type's ISO 3166-1 alpha-2 country, carried in the finding's metadata.
var countryOf = map[string]string{
	TypeBRCPF: "BR", TypeCLRUT: "CL", TypeARCUIL: "AR", TypeCASIN: "CA", TypeMXCURP: "MX", TypeMXRFC: "MX",
}

// Confidence. A labelled value whose check passes is HIGH; the label is the only context read.
const (
	// confidenceStrong: a long-form label, or an acronym with a colon/ordinal ("CPF nº", "SIN:").
	confidenceStrong = 95
	// confidenceAcronym: a capitalised acronym directly before the value (a RUN printed as "RUN" and the value).
	confidenceAcronym = 90
	// checkFailedConfidence: the value is shaped right and sits beside its own label, but its check
	// digit fails. A mistyped number is still a person's number, so it is reported (and redacted); the
	// check is the only value-intrinsic evidence, so without it the finding is LOW. It is published as
	// confidence_ceiling so a document-context boost cannot lift it.
	checkFailedConfidence = 40.0
	// genericRFCConfidence: the SAT's two generic RFCs (genericRFCs) name nobody. Held at the top of
	// LOW, the number creditcard gives a published test card and bankaccount a published example IBAN.
	genericRFCConfidence = 15.0
)

// confidenceCeilingKey is the metadata key the document bridge reads as a hard upper bound.
const confidenceCeilingKey = "confidence_ceiling"

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
// not one segment of a longer dotted or dashed number (a CPF with a third dashed group, a RUT glued to a "v").
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
				shapeOK, checkOK := assess(sh.dataType, value)
				if !shapeOK {
					continue
				}
				l, gap, ok := labelBefore(line, start, sh.dataType)
				if !ok {
					continue
				}
				m := detector.Match{
					Text:       value,
					LineNumber: lineNum + 1,
					Type:       sh.dataType,
					Filename:   originalPath,
					Validator:  "nationalid",
					Context: detector.ContextInfo{
						FullLine:         line,
						PositiveKeywords: []string{l.text},
					},
					Metadata: map[string]any{
						"country": countryOf[sh.dataType],
						"source":  "preprocessed_content",
					},
				}
				switch {
				case sh.dataType == TypeMXRFC && isGenericRFC(strings.ToUpper(value)):
					m.Confidence = genericRFCConfidence
					m.Metadata["checksum_valid"] = checkOK
					m.Metadata[confidenceCeilingKey] = genericRFCConfidence
				case checkOK:
					m.Confidence = confidenceStrong
					if l.abbr && !strongSeparator(gap) {
						m.Confidence = confidenceAcronym
					}
					m.Metadata["check_digit_valid"] = true
				case isSyntheticShape(sh.dataType, value):
					continue
				default:
					m.Confidence = checkFailedConfidence
					m.Metadata["checksum_valid"] = false
					m.Metadata[confidenceCeilingKey] = checkFailedConfidence
				}
				matches = append(matches, m)
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
