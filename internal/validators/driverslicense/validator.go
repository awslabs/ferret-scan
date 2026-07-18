// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns for US driver's license formats by state.
// Each pattern uses word boundaries to avoid matching substrings of longer tokens.
var (
	// California: 1 letter + 7 digits (e.g. D1234567)
	reCaliforniaDL = regexp.MustCompile(`\b[A-Za-z]\d{7}\b`)

	// Texas: 8 digits (also Pennsylvania)
	reTexasDL = regexp.MustCompile(`\b\d{8}\b`)

	// Florida: 1 letter + 12 digits (also Michigan)
	reFloridaDL = regexp.MustCompile(`\b[A-Za-z]\d{12}\b`)

	// New York: 9 digits (also Georgia)
	reNewYorkDL = regexp.MustCompile(`\b\d{9}\b`)

	// Illinois: 1 letter + 11 digits
	reIllinoisDL = regexp.MustCompile(`\b[A-Za-z]\d{11}\b`)

	// Ohio: 2 letters + 6 digits
	reOhioDL = regexp.MustCompile(`\b[A-Za-z]{2}\d{6}\b`)

	// Composite pattern that matches ANY of the above formats in a single pass.
	// Used by ValidateContentCtx for the initial line scan; hits are then
	// classified into the specific state format in classifyMatch.
	reAnyDL = regexp.MustCompile(
		`\b(?:` +
			`[A-Za-z]{2}\d{6}` + // Ohio (2 letters + 6 digits)
			`|[A-Za-z]\d{12}` + // Florida/Michigan (1 letter + 12 digits)
			`|[A-Za-z]\d{11}` + // Illinois (1 letter + 11 digits)
			`|[A-Za-z]\d{7}` + // California (1 letter + 7 digits)
			`|\d{9}` + // New York/Georgia (9 digits)
			`|\d{8}` + // Texas/Pennsylvania (8 digits)
			`)\b`)

	// State name patterns for context detection
	reStateName = regexp.MustCompile(`(?i)\b(?:california|texas|florida|new york|pennsylvania|illinois|ohio|georgia|north carolina|michigan|CA|TX|FL|NY|PA|IL|OH|GA|NC|MI)\b`)
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively. Implements word-boundary-aware matching to prevent false
// positives from substring matches (e.g. "dl" inside "handle").
func containsKeyword(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	lt := strings.ToLower(text)
	lk := strings.ToLower(keyword)
	for from := 0; from+len(lk) <= len(lt); {
		i := strings.Index(lt[from:], lk)
		if i < 0 {
			return false
		}
		i += from
		leftOK := i == 0 || !isWordByte(lt[i-1])
		right := i + len(lk)
		rightOK := right >= len(lt) || !isWordByte(lt[right])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
	return false
}

// isWordByte reports whether b is a word character for boundary detection.
func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// Validator implements the detector.Validator interface for detecting
// US driver's license numbers using state-specific regex patterns and
// keyword-dependent contextual analysis.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	stateKeywords    []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new Validator instance with predefined
// patterns and keywords for detecting US driver's license numbers.
func NewValidator() *Validator {
	v := &Validator{
		pattern: reAnyDL.String(),
		positiveKeywords: []string{
			"driver", "license", "licence", "dl", "dmv",
			"motor vehicle", "driving", "permit", "state id",
			"identification card", "operator", "driver's license",
			"drivers license", "driver license", "dl number",
			"license number", "licence number",
		},
		negativeKeywords: []string{
			"ssn", "social security", "phone", "account", "serial",
			"order", "invoice", "reference", "tracking", "confirmation",
			"test", "example", "sample", "placeholder", "fake", "mock", "demo",
			"ip", "address", "port", "version", "build", "hash",
			"uuid", "guid", "isbn", "sku", "model",
			// Non-DL license/permit contexts (common false positive sources)
			"software", "fishing", "hunting", "gun", "concealed",
			"business", "plate", "immigration", "construction", "key",
			"expires", "expiry", "renew", "mailed", "activation",
			"work permit",
		},
		stateKeywords: []string{
			"california", "texas", "florida", "new york", "pennsylvania",
			"illinois", "ohio", "georgia", "north carolina", "michigan",
		},
	}

	v.regex = reAnyDL

	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for driver's license numbers.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: it is the
// context-aware form of ValidateContent, polling ctx once per line so a
// runaway scan is reclaimed promptly.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		// Quick pre-check: does the line contain any DL-related keyword?
		// Because DL formats are extremely ambiguous (8 digits, 9 digits, etc.),
		// we ONLY scan lines that have at least one positive keyword present.
		if !v.lineHasPositiveKeyword(line) {
			continue
		}

		idxMatches := v.regex.FindAllStringIndex(line, -1)
		if len(idxMatches) == 0 {
			continue
		}

		for _, loc := range idxMatches {
			match := line[loc[0]:loc[1]]

			// Classify which state format this matches
			format := v.classifyMatch(match)
			if format == "" {
				continue
			}

			// Calculate base confidence from structural validation
			confidence, checks := v.CalculateConfidence(match)

			// Build context info
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}
			start := loc[0] - 50
			if start < 0 {
				start = 0
			}
			end := loc[1] + 50
			if end > len(line) {
				end = len(line)
			}
			contextInfo.BeforeText = line[start:loc[0]]
			contextInfo.AfterText = line[loc[1]:end]

			// Analyze context for keyword-based adjustment
			contextImpact := v.AnalyzeContext(match, contextInfo)
			confidence += contextImpact

			// Store keywords found
			contextInfo.PositiveKeywords = v.findKeywordsOnLine(line, v.positiveKeywords)
			contextInfo.NegativeKeywords = v.findKeywordsOnLine(line, v.negativeKeywords)
			contextInfo.ConfidenceImpact = contextImpact

			// Clamp confidence
			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			// Skip very low confidence matches
			if confidence <= 0 {
				continue
			}

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1,
				Type:       "DRIVERS_LICENSE",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "driverslicense",
				Context:    contextInfo,
				Metadata: map[string]any{
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"format":            format,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}
	}

	return matches, nil
}

// lineHasPositiveKeyword checks whether the line contains at least one
// DL-related keyword. This is the first gate: without a keyword, no format
// match is considered (because all DL formats overlap with generic numbers).
func (v *Validator) lineHasPositiveKeyword(line string) bool {
	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			return true
		}
	}
	// Also accept state name + a generic ID indicator
	if reStateName.MatchString(line) {
		// State name alone is not enough; require at least "id" or "number" nearby
		lower := strings.ToLower(line)
		if strings.Contains(lower, "id") || strings.Contains(lower, "number") || strings.Contains(lower, "no.") || strings.Contains(lower, "no:") {
			return true
		}
	}
	return false
}

// classifyMatch determines which state DL format the match corresponds to.
// Returns a human-readable format string or "" if no specific format is matched.
func (v *Validator) classifyMatch(match string) string {
	switch {
	case reFloridaDL.MatchString(match):
		// 1 letter + 12 digits: Florida or Michigan
		return "FL_MI_1L12D"
	case reIllinoisDL.MatchString(match):
		// 1 letter + 11 digits: Illinois
		return "IL_1L11D"
	case reCaliforniaDL.MatchString(match):
		// 1 letter + 7 digits: California
		return "CA_1L7D"
	case reOhioDL.MatchString(match):
		// 2 letters + 6 digits: Ohio
		return "OH_2L6D"
	case reNewYorkDL.MatchString(match):
		// 9 digits: New York or Georgia
		return "NY_GA_9D"
	case reTexasDL.MatchString(match):
		// 8 digits: Texas or Pennsylvania
		return "TX_PA_8D"
	default:
		return ""
	}
}

// CalculateConfidence calculates the base confidence score for a potential
// driver's license number based on structural properties alone.
// Because DL formats are so generic, the base confidence is intentionally very
// low (20) — keyword context is required to raise it to actionable levels.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format_match":   true,
		"not_all_zeros":  true,
		"not_sequential": true,
		"not_all_same":   true,
		"has_dl_context": false, // set by context analysis later
	}

	// Very conservative base: format match alone is insufficient evidence.
	confidence := 20.0

	// Check for obviously invalid patterns
	cleanDigits := extractDigits(match)

	// All zeros
	if allSameChar(cleanDigits, '0') {
		confidence -= 20
		checks["not_all_zeros"] = false
	}

	// All same digit (never a real DL number)
	if len(cleanDigits) > 0 && allSameChar(cleanDigits, cleanDigits[0]) {
		confidence -= 20
		checks["not_all_same"] = false
	}

	// Sequential digits (ascending or descending)
	if isSequentialDigits(cleanDigits) {
		confidence -= 15
		checks["not_sequential"] = false
	}

	if confidence < 0 {
		confidence = 0
	}

	return confidence, checks
}

// strongSuppressKeywords are negative keywords that indicate test/placeholder
// data or definitive non-DL identifiers and must always suppress regardless
// of how strong the positive signal is.
var strongSuppressKeywords = []string{
	"test", "example", "sample", "placeholder", "fake", "mock", "demo",
	"uuid", "guid",
}

// AnalyzeContext analyzes context around a match and returns a confidence adjustment.
// This is where the heavy lifting happens for DL detection: without keywords,
// the score stays at the low base of 20.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	line := context.FullLine
	var impact float64

	// Check for strong suppress keywords FIRST. These always cap the result to
	// produce a net-negative or near-zero outcome, ensuring test/example data
	// never surfaces as an actionable finding regardless of positive context.
	for _, kw := range strongSuppressKeywords {
		if containsKeyword(line, kw) {
			return -20 // hard suppression: base 20 + (-20) = 0
		}
	}

	// Check for explicit DL prefix patterns (strongest signal)
	lower := strings.ToLower(line)
	if strings.Contains(lower, "dl:") || strings.Contains(lower, "dl #") ||
		strings.Contains(lower, "dl#") || strings.Contains(lower, "d.l.") ||
		strings.Contains(lower, "driver's license:") || strings.Contains(lower, "drivers license:") ||
		strings.Contains(lower, "driver license:") || strings.Contains(lower, "license number:") ||
		strings.Contains(lower, "licence number:") || strings.Contains(lower, "license no:") ||
		strings.Contains(lower, "license no.") {
		impact += 75 // prefix pattern -> base 20 + 75 = 95
	} else {
		// Check for positive keywords (moderate signal)
		keywordCount := 0
		for _, kw := range v.positiveKeywords {
			if containsKeyword(line, kw) {
				keywordCount++
			}
		}

		if keywordCount > 0 {
			// First keyword: +45 (base 20 + 45 = 65)
			impact += 45
			// Additional keywords: +10 each, capped
			if keywordCount > 1 {
				extra := float64(keywordCount-1) * 10
				if extra > 20 {
					extra = 20
				}
				impact += extra
			}
		}

		// State name boost: +20 when a state name is also present
		if reStateName.MatchString(line) {
			impact += 20
		}
	}

	// Check for remaining negative keywords (non-strong-suppress; moderate penalty)
	for _, kw := range v.negativeKeywords {
		// Skip the strong-suppress keywords (already handled above)
		isStrong := false
		for _, sk := range strongSuppressKeywords {
			if kw == sk {
				isStrong = true
				break
			}
		}
		if isStrong {
			continue
		}
		if containsKeyword(line, kw) {
			impact -= 20
			break // one negative keyword is enough to suppress
		}
	}

	// Cap the impact
	if impact > 80 {
		impact = 80
	} else if impact < -30 {
		impact = -30
	}

	return impact
}

// findKeywordsOnLine returns which of the given keywords are present on the line.
func (v *Validator) findKeywordsOnLine(line string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsKeyword(line, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// --- Helper functions ---

// extractDigits returns only the digit characters from s.
func extractDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// allSameChar reports whether every byte in s equals ch.
func allSameChar(s string, ch byte) bool {
	if len(s) == 0 {
		return false
	}
	for i := range s {
		if s[i] != ch {
			return false
		}
	}
	return true
}

// isSequentialDigits reports whether the digit string is strictly ascending
// or descending (wrapping mod 10). Only flags sequences of 8+ digits to avoid
// over-penalizing shorter DL numbers where partial sequences are common.
func isSequentialDigits(s string) bool {
	if len(s) < 8 {
		return false
	}
	ascending := true
	descending := true
	for i := 0; i < len(s)-1; i++ {
		curr := int(s[i] - '0')
		next := int(s[i+1] - '0')
		if next != (curr+1)%10 {
			ascending = false
		}
		if next != (curr+9)%10 {
			descending = false
		}
	}
	return ascending || descending
}
