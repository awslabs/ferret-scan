// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	stdctx "context"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns for bank account detection.
var (
	// ABA routing number: 9 digits, word-boundary anchored.
	reABA = regexp.MustCompile(`\b\d{9}\b`)

	// IBAN: 2-letter country code + 2 check digits + up to 30 alphanumeric.
	// We require at least 15 characters total (shortest valid IBAN is Norway at 15).
	reIBAN = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)

	// IBAN in the standard display format: space-separated groups of 4
	// (e.g. "DE89 3704 0044 0532 0130 00" on invoices and statements).
	// Candidates are normalized (spaces stripped) and must pass the same
	// isValidIBAN gate (valid country, exact length, mod-97 checksum) as
	// contiguous IBANs, so the loose grouping here adds no FP surface.
	reIBANSpaced = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b`)

	// SWIFT/BIC: 4 bank + 2 country + 2 location + optional 3 branch (8 or 11 chars).
	reSWIFT = regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`)

	// US bank account number: 8-17 digits, word-boundary anchored.
	reUSAccount = regexp.MustCompile(`\b\d{8,17}\b`)

	// Helper patterns for false positive suppression.
	rePhoneLike   = regexp.MustCompile(`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	reDateLike    = regexp.MustCompile(`\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}`)
	reVersionLike = regexp.MustCompile(`\b[vV]?\d+\.\d+\.\d+`)
	// reVersionPrefix matches a "v"/"v." version prefix bound to a digit at a
	// word boundary (v.1, v2, V.10), so a version-labelled number is suppressed
	// without a bare "v." substring firing inside unrelated words.
	reVersionPrefix = regexp.MustCompile(`\b[vV]\.?\d`)

	// ISO 3166-1 alpha-2 country codes (subset used for IBAN validation).
	validIBANCountries = map[string]int{
		"AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16,
		"BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24,
		"DK": 18, "DO": 28, "TL": 23, "EE": 20, "FO": 18, "FI": 18, "FR": 27,
		"GE": 22, "DE": 22, "GI": 23, "GR": 27, "GL": 18, "GT": 28, "HU": 28,
		"IS": 26, "IQ": 23, "IE": 22, "IL": 23, "IT": 27, "JO": 30, "KZ": 20,
		"XK": 20, "KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20,
		"MK": 19, "MT": 31, "MR": 27, "MU": 30, "MC": 27, "MD": 24, "ME": 22,
		"NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25, "QA": 29,
		"RO": 24, "LC": 32, "SM": 27, "SA": 24, "RS": 22, "SC": 31, "SK": 24,
		"SI": 19, "ES": 24, "SE": 24, "CH": 21, "TN": 24, "TR": 26, "UA": 29,
		"AE": 23, "GB": 22, "VA": 22, "VG": 24,
	}

	// Known test ABA routing numbers that should NOT be flagged.
	testRoutingNumbers = map[string]bool{
		"011000015": true, // Federal Reserve Bank of Boston (commonly used in tests)
		"021000021": true, // JP Morgan Chase (commonly used in docs/examples)
		"000000000": true,
		"123456789": true,
		"111111111": true,
		"222222222": true,
		"333333333": true,
		"444444444": true,
		"555555555": true,
		"666666666": true,
		"777777777": true,
		"888888888": true,
		"999999999": true,
		"987654321": true,
	}
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively. Uses manual boundary checks for performance.
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
// bank account numbers, routing numbers, IBANs, and SWIFT/BIC codes.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new Validator instance for bank account detection.
func NewValidator() *Validator {
	v := &Validator{
		pattern: `\b\d{8,17}\b`, // base pattern for US account numbers
		positiveKeywords: []string{
			"routing", "aba", "account number", "bank account", "checking",
			"savings", "wire", "swift", "bic", "iban", "transit",
			"financial institution", "deposit", "ach", "direct deposit",
			"bank", "routing number", "account no", "acct",
		},
		negativeKeywords: []string{
			"phone", "zip", "postal", "serial", "model", "version",
			"test", "example", "sample", "ssn", "social security",
			"placeholder", "fake", "mock", "demo", "ip address",
			"order", "invoice", "tracking", "confirmation",
		},
	}
	v.regex = regexp.MustCompile(v.pattern)
	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates content for bank account information.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// lineContext holds per-line values that are invariant across every match on
// the line. AnalyzeContext, hasStrongNegativeContext and hasBankingKeywords all
// scan the whole line and ignore the match position, so their results are the
// same for every match — computing them once per line instead of once per match
// is what keeps scanning O(line length) instead of O(matches × line length).
// The latter is a CPU-exhaustion DoS on a single long line (a crafted 48KB line
// otherwise pins a core for seconds). See the timing regression test.
type lineContext struct {
	lower          string  // strings.ToLower(line), for near-match keyword probes
	keywordImpact  float64 // AnalyzeContext result (positive/negative keyword scan)
	strongNegative bool    // hasStrongNegativeContext(line)
	bankingKeyword bool    // hasBankingKeywords(line)
	phoneKeyword   bool    // any phone-context keyword on the line (looksLikePhone)
}

// buildLineContext computes the per-line invariants once. AnalyzeContext is
// invoked with an empty before/after window and the full line: because the
// function only tests keyword PRESENCE in BeforeText+FullLine+AfterText and
// FullLine already spans the whole line, this yields the identical keyword set
// (and therefore identical impact) as the original per-match calls.
func (v *Validator) buildLineContext(line string) lineContext {
	return lineContext{
		lower:          strings.ToLower(line),
		keywordImpact:  v.AnalyzeContext("", detector.ContextInfo{FullLine: line}),
		strongNegative: v.hasStrongNegativeContext(line),
		bankingKeyword: v.hasBankingKeywords(line),
		// Phone-context keywords are line-global (looksLikePhone asked the
		// same six whole-line questions for EVERY 10-digit match). Hoisting
		// them here turns the US-account scan from O(matches × line length)
		// back to O(line length) — this was the bankaccount O(n^2) the
		// expanded complexity guard caught.
		phoneKeyword: containsKeyword(line, "phone") || containsKeyword(line, "telephone") ||
			containsKeyword(line, "fax") || containsKeyword(line, "call us") ||
			containsKeyword(line, "mobile") || containsKeyword(line, "cell"),
	}
}

// ValidateContentCtx is the context-aware form of ValidateContent.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		lc := v.buildLineContext(line)
		lineMatches := v.scanLine(ctx, line, lineNum, originalPath, lc)
		matches = append(matches, lineMatches...)
	}

	return matches, nil
}

// scanLine scans a single line for all bank account related patterns. The
// precomputed lineContext is shared across the per-pattern scanners so none of
// them re-scan the whole line per match.
func (v *Validator) scanLine(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// Scan for IBAN (highest specificity first)
	matches = append(matches, v.scanIBAN(ctx, line, lineNum, originalPath, lc)...)

	// Scan for SWIFT/BIC
	matches = append(matches, v.scanSWIFT(ctx, line, lineNum, originalPath, lc)...)

	// Scan for ABA routing numbers
	matches = append(matches, v.scanABA(ctx, line, lineNum, originalPath, lc)...)

	// Scan for US bank account numbers (only if banking context present)
	matches = append(matches, v.scanUSAccount(ctx, line, lineNum, originalPath, lc)...)

	return matches
}

// scanIBAN detects and validates IBAN numbers.
func (v *Validator) scanIBAN(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// Try case-insensitive match by checking uppercase version
	upperLine := strings.ToUpper(line)
	idxMatches := reIBAN.FindAllStringIndex(upperLine, -1)

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := upperLine[loc[0]:loc[1]]

		// Validate IBAN structure
		if !v.isValidIBAN(candidate) {
			continue
		}

		// Check for negative context (per-line invariant)
		contextInfo := v.buildContextInfo(line, loc[0], loc[1]-loc[0])
		if lc.strongNegative {
			continue
		}

		confidence := 85.0 // IBAN with valid checksum is high confidence

		// Context adjustment (per-line invariant: keyword presence over the line)
		contextImpact := lc.keywordImpact
		confidence += contextImpact

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       line[loc[0]:loc[1]], // preserve original case
			LineNumber: lineNum + 1,
			Type:       "IBAN",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"country":        candidate[:2],
				"context_impact": contextImpact,
			},
		})
	}

	// Second pass: display-format (space-grouped) IBANs. Candidates are
	// normalized and must pass the identical isValidIBAN gate; the reported
	// span is the original spaced text so redaction masks the whole token.
	for i, loc := range reIBANSpaced.FindAllStringIndex(upperLine, -1) {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		normalized := strings.ReplaceAll(upperLine[loc[0]:loc[1]], " ", "")
		if !v.isValidIBAN(normalized) {
			continue
		}
		if lc.strongNegative {
			continue
		}

		confidence := clampConfidence(85.0 + lc.keywordImpact)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       line[loc[0]:loc[1]], // original case and spacing
			LineNumber: lineNum + 1,
			Type:       "IBAN",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    v.buildContextInfo(line, loc[0], loc[1]-loc[0]),
			Metadata: map[string]any{
				"country":        normalized[:2],
				"context_impact": lc.keywordImpact,
				"normalized":     normalized,
			},
		})
	}

	return matches
}

// scanSWIFT detects and validates SWIFT/BIC codes.
func (v *Validator) scanSWIFT(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	upperLine := strings.ToUpper(line)
	idxMatches := reSWIFT.FindAllStringIndex(upperLine, -1)

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := upperLine[loc[0]:loc[1]]

		// The original text must be uppercase -- real SWIFT codes are always uppercase.
		originalText := line[loc[0]:loc[1]]
		if originalText != candidate {
			continue
		}

		// Validate SWIFT structure
		if !v.isValidSWIFT(candidate) {
			continue
		}

		// SWIFT codes without banking context are often false positives (random 8-char strings)
		contextInfo := v.buildContextInfo(line, loc[0], loc[1]-loc[0])
		hasBankingContext := lc.bankingKeyword

		// All-letter candidates (no digits) are very likely English words unless
		// banking context is present. Real all-alpha SWIFT codes like DEUTDEFF
		// will only be surfaced when "swift", "bic", "bank", etc. appear nearby.
		if isCommonWord(candidate) && !hasBankingContext {
			continue
		}

		if lc.strongNegative {
			continue
		}

		confidence := 50.0 // Base is conservative for SWIFT without context
		if hasBankingContext {
			confidence = 75.0
		}

		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// SWIFT needs banking context to reach meaningful confidence
		if !hasBankingContext && confidence < 40 {
			continue
		}

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       originalText,
			LineNumber: lineNum + 1,
			Type:       "SWIFT_BIC",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"bank_code":      candidate[:4],
				"country_code":   candidate[4:6],
				"context_impact": contextImpact,
			},
		})
	}

	return matches
}

// isCommonWord checks if an uppercase string is likely a common English word
// rather than a real SWIFT/BIC code. Real SWIFT codes almost always contain at
// least one digit in positions 6-7 (location code) or are composed of unusual
// letter combinations. Words that are all letters and pronounceable are likely
// English words, not bank identifiers.
//
// Strategy: if the candidate is 8 all-letter characters (no digits anywhere),
// it is very likely a word, not a SWIFT code. Real 8-char SWIFT codes nearly
// always have digits in the location code (e.g. CHASUS33, BNPAFRPP is one
// exception but those are validated by banking context requirement). For 11-char
// codes, the branch suffix often has digits too.
func isCommonWord(s string) bool {
	// All-letter strings of length 8 or 11 with no digits are almost certainly
	// English words or identifiers, not SWIFT codes.
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return false // has a digit -- likely a real SWIFT code
		}
	}
	// All letters, no digits. Without banking context this is almost certainly
	// not a SWIFT code. We let the banking-context requirement in the caller
	// handle the remaining edge cases (like BNPAFRPP which is real but all-alpha).
	return true
}

// scanABA detects and validates US ABA routing numbers.
func (v *Validator) scanABA(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	idxMatches := reABA.FindAllStringIndex(line, -1)

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := line[loc[0]:loc[1]]

		// Must be exactly 9 digits
		if len(candidate) != 9 {
			continue
		}

		// Validate ABA routing number
		if !v.isValidABA(candidate) {
			continue
		}

		// Skip known test routing numbers
		if testRoutingNumbers[candidate] {
			continue
		}

		contextInfo := v.buildContextInfo(line, loc[0], 9)
		if lc.strongNegative {
			continue
		}

		// ABA routing numbers are only 9 digits -- lots of 9-digit numbers exist.
		// Without banking context, confidence is low.
		hasBankingContext := lc.bankingKeyword

		confidence := 40.0 // Conservative base for bare 9-digit number
		if hasBankingContext {
			confidence = 70.0
		}

		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// Without any banking keywords, bare 9-digit numbers should not surface.
		if !hasBankingContext && confidence < 50 {
			continue
		}

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       candidate,
			LineNumber: lineNum + 1,
			Type:       "ABA_ROUTING",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"federal_reserve_district": candidate[:2],
				"context_impact":           contextImpact,
			},
		})
	}

	return matches
}

// scanUSAccount detects US bank account numbers (8-17 digits) only when banking
// keywords are present nearby.
func (v *Validator) scanUSAccount(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// US account numbers are just digit sequences -- require banking context.
	if !lc.bankingKeyword {
		return nil
	}

	idxMatches := reUSAccount.FindAllStringIndex(line, -1)

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := line[loc[0]:loc[1]]
		length := len(candidate)

		// Skip anything exactly 9 digits (handled by ABA scanner)
		if length == 9 {
			continue
		}

		// Skip numbers that look like credit card numbers (Luhn valid, 13-19 digits).
		// Credit cards are a different validator's domain; flagging them as bank
		// account numbers is a cross-validator false positive.
		if looksLikeCreditCard(candidate) {
			continue
		}

		// Skip if this looks like a phone number
		if v.looksLikePhone(line, loc[0], loc[1], lc.phoneKeyword) {
			continue
		}

		// Skip if this looks like a date
		if v.looksLikeDate(line, loc[0], loc[1]) {
			continue
		}

		// Skip if preceded by version-like patterns
		if v.looksLikeVersion(line, loc[0]) {
			continue
		}

		contextInfo := v.buildContextInfo(line, loc[0], length)
		if lc.strongNegative {
			continue
		}

		confidence := 55.0 // Moderate base (requires banking context to even enter here)

		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// Account numbers very close to "account" keyword get a boost. Uses the
		// per-line lowercased copy (lc.lower) so we don't re-lower the whole line
		// per match; keywordNearMatch only inspects a ±30-char window by offset.
		if v.keywordNearMatch(lc.lower, loc[0], "account") ||
			v.keywordNearMatch(lc.lower, loc[0], "acct") {
			confidence += 15
		}

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       candidate,
			LineNumber: lineNum + 1,
			Type:       "US_BANK_ACCOUNT",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"length":         length,
				"context_impact": contextImpact,
			},
		})
	}

	return matches
}

// CalculateConfidence calculates the confidence score for a potential bank account match.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":        true,
		"valid_length":  false,
		"checksum":      false,
		"not_test":      true,
		"valid_country": false,
	}

	upper := strings.ToUpper(strings.TrimSpace(match))

	// Determine what type this is
	if len(upper) >= 15 && len(upper) <= 34 && len(upper) >= 2 && unicode.IsLetter(rune(upper[0])) && unicode.IsLetter(rune(upper[1])) {
		// Looks like IBAN
		checks["valid_length"] = true
		if v.isValidIBAN(upper) {
			checks["checksum"] = true
			checks["valid_country"] = true
			return 85.0, checks
		}
		return 30.0, checks
	}

	if (len(upper) == 8 || len(upper) == 11) && isAllAlphaOrDigit(upper) && hasMinLetters(upper, 6) {
		// Looks like SWIFT
		checks["valid_length"] = true
		if v.isValidSWIFT(upper) {
			checks["valid_country"] = true
			return 60.0, checks
		}
		return 25.0, checks
	}

	// Digit-only: ABA or account number
	clean := stripNonDigits(match)
	if len(clean) == 9 {
		checks["valid_length"] = true
		if testRoutingNumbers[clean] {
			checks["not_test"] = false
			return 20.0, checks
		}
		if v.isValidABA(clean) {
			checks["checksum"] = true
			return 65.0, checks
		}
		return 30.0, checks
	}

	if len(clean) >= 8 && len(clean) <= 17 {
		checks["valid_length"] = true
		return 50.0, checks
	}

	checks["format"] = false
	return 10.0, checks
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
	var impact float64

	for _, keyword := range v.positiveKeywords {
		if containsKeyword(fullContext, keyword) {
			impact += 15
		}
	}

	for _, keyword := range v.negativeKeywords {
		if containsKeyword(fullContext, keyword) {
			impact -= 20
		}
	}

	// Cap impact
	if impact > 40 {
		impact = 40
	} else if impact < -50 {
		impact = -50
	}

	return impact
}

// --- Validation helpers ---

// isValidABA validates a 9-digit ABA routing number using the checksum algorithm.
// The first two digits must be 01-32 (Federal Reserve routing symbol range).
// Checksum: 3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9) mod 10 == 0
func (v *Validator) isValidABA(s string) bool {
	if len(s) != 9 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}

	// First two digits must be 01-32 (or 61-72 for electronic, 80 for traveler's checks)
	prefix, _ := strconv.Atoi(s[:2])
	validPrefix := (prefix >= 1 && prefix <= 32) ||
		(prefix >= 61 && prefix <= 72) ||
		prefix == 80
	if !validPrefix {
		return false
	}

	// Checksum validation
	d := make([]int, 9)
	for i := 0; i < 9; i++ {
		d[i] = int(s[i] - '0')
	}
	checksum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return checksum%10 == 0
}

// isValidIBAN validates an IBAN using the mod-97 algorithm (ISO 13616).
func (v *Validator) isValidIBAN(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}

	// Country code must be valid
	country := s[:2]
	expectedLen, ok := validIBANCountries[country]
	if !ok {
		return false
	}

	// Length must match country expectation
	if len(s) != expectedLen {
		return false
	}

	// Check digits (positions 2-3) must be numeric
	if s[2] < '0' || s[2] > '9' || s[3] < '0' || s[3] > '9' {
		return false
	}

	// Check digits must not be "00" or "01" or "99"
	checkDigits := s[2:4]
	if checkDigits == "00" || checkDigits == "01" || checkDigits == "99" {
		return false
	}

	// Move first 4 chars to end and convert letters to numbers
	rearranged := s[4:] + s[:4]
	var numStr strings.Builder
	for _, c := range rearranged {
		if c >= '0' && c <= '9' {
			numStr.WriteRune(c)
		} else if c >= 'A' && c <= 'Z' {
			// A=10, B=11, ..., Z=35
			numStr.WriteString(strconv.Itoa(int(c-'A') + 10))
		} else {
			return false // invalid character
		}
	}

	// Compute mod 97
	return mod97(numStr.String()) == 1
}

// mod97 computes n mod 97 for a large number represented as a string.
func mod97(s string) int {
	remainder := 0
	for _, c := range s {
		digit := int(c - '0')
		remainder = (remainder*10 + digit) % 97
	}
	return remainder
}

// isValidSWIFT validates a SWIFT/BIC code structure.
func (v *Validator) isValidSWIFT(s string) bool {
	if len(s) != 8 && len(s) != 11 {
		return false
	}

	// First 4: bank code (letters only)
	for i := 0; i < 4; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}

	// Chars 4-5: country code (must be valid ISO 3166-1)
	countryCode := s[4:6]
	if !isValidCountryCode(countryCode) {
		return false
	}

	// Chars 6-7: location code (letters or digits)
	for i := 6; i < 8; i++ {
		if !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
			return false
		}
	}

	// Optional chars 8-10: branch code (letters or digits)
	if len(s) == 11 {
		for i := 8; i < 11; i++ {
			if !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
				return false
			}
		}
	}

	return true
}

// isValidCountryCode checks if a 2-letter code is a valid ISO 3166-1 country.
func isValidCountryCode(code string) bool {
	// Common SWIFT country codes (non-exhaustive but covers major financial centers)
	validCodes := map[string]bool{
		"AD": true, "AE": true, "AF": true, "AG": true, "AL": true, "AM": true,
		"AO": true, "AR": true, "AT": true, "AU": true, "AZ": true, "BA": true,
		"BB": true, "BD": true, "BE": true, "BF": true, "BG": true, "BH": true,
		"BI": true, "BJ": true, "BM": true, "BN": true, "BO": true, "BR": true,
		"BS": true, "BT": true, "BW": true, "BY": true, "BZ": true, "CA": true,
		"CD": true, "CF": true, "CG": true, "CH": true, "CI": true, "CL": true,
		"CM": true, "CN": true, "CO": true, "CR": true, "CU": true, "CV": true,
		"CY": true, "CZ": true, "DE": true, "DJ": true, "DK": true, "DM": true,
		"DO": true, "DZ": true, "EC": true, "EE": true, "EG": true, "ER": true,
		"ES": true, "ET": true, "FI": true, "FJ": true, "FK": true, "FM": true,
		"FO": true, "FR": true, "GA": true, "GB": true, "GD": true, "GE": true,
		"GH": true, "GI": true, "GL": true, "GM": true, "GN": true, "GQ": true,
		"GR": true, "GT": true, "GW": true, "GY": true, "HK": true, "HN": true,
		"HR": true, "HT": true, "HU": true, "ID": true, "IE": true, "IL": true,
		"IN": true, "IQ": true, "IR": true, "IS": true, "IT": true, "JM": true,
		"JO": true, "JP": true, "KE": true, "KG": true, "KH": true, "KI": true,
		"KM": true, "KN": true, "KP": true, "KR": true, "KW": true, "KY": true,
		"KZ": true, "LA": true, "LB": true, "LC": true, "LI": true, "LK": true,
		"LR": true, "LS": true, "LT": true, "LU": true, "LV": true, "LY": true,
		"MA": true, "MC": true, "MD": true, "ME": true, "MG": true, "MH": true,
		"MK": true, "ML": true, "MM": true, "MN": true, "MO": true, "MR": true,
		"MT": true, "MU": true, "MV": true, "MW": true, "MX": true, "MY": true,
		"MZ": true, "NA": true, "NE": true, "NG": true, "NI": true, "NL": true,
		"NO": true, "NP": true, "NR": true, "NZ": true, "OM": true, "PA": true,
		"PE": true, "PG": true, "PH": true, "PK": true, "PL": true, "PS": true,
		"PT": true, "PW": true, "PY": true, "QA": true, "RO": true, "RS": true,
		"RU": true, "RW": true, "SA": true, "SB": true, "SC": true, "SD": true,
		"SE": true, "SG": true, "SI": true, "SK": true, "SL": true, "SM": true,
		"SN": true, "SO": true, "SR": true, "SS": true, "ST": true, "SV": true,
		"SY": true, "SZ": true, "TD": true, "TG": true, "TH": true, "TJ": true,
		"TL": true, "TM": true, "TN": true, "TO": true, "TR": true, "TT": true,
		"TV": true, "TW": true, "TZ": true, "UA": true, "UG": true, "US": true,
		"UY": true, "UZ": true, "VA": true, "VC": true, "VE": true, "VG": true,
		"VN": true, "VU": true, "WS": true, "XK": true, "YE": true, "ZA": true,
		"ZM": true, "ZW": true,
	}
	return validCodes[code]
}

// --- Context helpers ---

// buildContextInfo constructs a ContextInfo from a line and match position.
func (v *Validator) buildContextInfo(line string, matchStart, matchLen int) detector.ContextInfo {
	ci := detector.ContextInfo{
		FullLine: line,
	}

	start := matchStart - 50
	if start < 0 {
		start = 0
	}
	end := matchStart + matchLen + 50
	if end > len(line) {
		end = len(line)
	}

	ci.BeforeText = line[start:matchStart]
	ci.AfterText = line[matchStart+matchLen : end]

	return ci
}

// hasBankingKeywords checks if the line contains any banking-related keywords.
func (v *Validator) hasBankingKeywords(line string) bool {
	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			return true
		}
	}
	return false
}

// hasStrongNegativeContext checks for negative keywords that strongly indicate
// this is not a bank account number. Returns true when negative evidence
// overwhelmingly outweighs positive evidence (e.g. "test example sample" with
// only one banking keyword nearby).
func (v *Validator) hasStrongNegativeContext(line string) bool {
	negCount := 0
	hasPostalNeg := false
	for _, kw := range v.negativeKeywords {
		if containsKeyword(line, kw) {
			negCount++
			if kw == "zip" || kw == "postal" {
				hasPostalNeg = true
			}
		}
	}
	if negCount == 0 {
		return false
	}

	posCount := 0
	hasOnlyRoutingPos := true
	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			posCount++
			if kw != "routing" && kw != "routing number" && kw != "transit" {
				hasOnlyRoutingPos = false
			}
		}
	}

	// Suppress when negatives strongly outnumber positives (3+ negatives with
	// at most 1 positive, or 2+ negatives with zero positives).
	if negCount >= 3 && posCount <= 1 {
		return true
	}
	if negCount >= 2 && posCount == 0 {
		return true
	}

	// Special case: "zip"/"postal" + only ambiguous keywords ("routing", "transit")
	// indicates postal/mail routing, not bank routing. Suppress this combination.
	if hasPostalNeg && posCount <= 1 && hasOnlyRoutingPos {
		return true
	}

	return false
}

// keywordNearMatch checks if a keyword appears within 30 chars of the match position.
func (v *Validator) keywordNearMatch(lowerLine string, matchStart int, keyword string) bool {
	start := matchStart - 30
	if start < 0 {
		start = 0
	}
	end := matchStart + 30
	if end > len(lowerLine) {
		end = len(lowerLine)
	}
	return strings.Contains(lowerLine[start:end], keyword)
}

// --- False positive suppression helpers ---

// rePhoneFormatted matches phone numbers with explicit separators/parens,
// distinguishing them from bare digit sequences.
var rePhoneFormatted = regexp.MustCompile(`\(\d{3}\)\s?\d{3}[-.]?\d{4}|\d{3}[-.\s]\d{3}[-.\s]\d{4}`)

// looksLikePhone checks if the digit sequence at the given position is part of a phone number.
// Only returns true if the match appears as a formatted phone (with separators/parens) or
// if phone-related keywords are present in the line. Bare 10-digit numbers in banking
// context are NOT suppressed as phones.
func (v *Validator) looksLikePhone(line string, start, end int, phoneKeyword bool) bool {
	matchLen := end - start
	// Phone numbers are exactly 10 digits. Longer sequences are not phones.
	if matchLen != 10 {
		return false
	}

	// Phone-context keywords on the line (precomputed once per line in
	// lineContext — see phoneKeyword). Scanning them per match was the O(n^2).
	if phoneKeyword {
		return true
	}

	// Check if the surrounding text has a formatted phone pattern (parens/dashes/dots)
	windowStart := start - 6
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 2
	if windowEnd > len(line) {
		windowEnd = len(line)
	}
	window := line[windowStart:windowEnd]
	return rePhoneFormatted.MatchString(window)
}

// looksLikeDate checks if the digit sequence is part of a date pattern.
func (v *Validator) looksLikeDate(line string, start, end int) bool {
	windowStart := start - 3
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 3
	if windowEnd > len(line) {
		windowEnd = len(line)
	}
	window := line[windowStart:windowEnd]
	return reDateLike.MatchString(window)
}

// looksLikeVersion checks if the digit sequence is preceded by a version indicator.
//
// The "version" word is matched on a WHOLE-WORD boundary (containsKeyword), not a
// raw substring: a bare strings.Contains matched "version" inside "conversion",
// "subversion" and "aversion", wrongly suppressing a real account number that
// happened to follow one of those words. The "v." prefix check is likewise
// anchored to a version token (reVersionPrefix: "v." or "v" immediately before a
// digit at a word boundary, e.g. "v.1"/"v2"), not any word merely ending in "v".
func (v *Validator) looksLikeVersion(line string, start int) bool {
	windowStart := start - 10
	if windowStart < 0 {
		windowStart = 0
	}
	window := line[windowStart:start]
	return reVersionLike.MatchString(window) ||
		containsKeyword(window, "version") ||
		reVersionPrefix.MatchString(window)
}

// --- Utility helpers ---

// looksLikeCreditCard checks if a digit string passes the Luhn algorithm,
// which is used for credit card number validation. Numbers of 13-19 digits
// that pass Luhn are almost certainly credit card numbers, not bank accounts.
func looksLikeCreditCard(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	// Luhn algorithm
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func clampConfidence(c float64) float64 {
	if c > 100 {
		return 100
	}
	if c < 0 {
		return 0
	}
	return c
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func isAllAlphaOrDigit(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func hasMinLetters(s string, n int) bool {
	count := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			count++
		}
	}
	return count >= n
}
