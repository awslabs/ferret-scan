// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// transliterationMap maps VIN characters to their numeric values for check digit calculation.
var transliterationMap = map[byte]int{
	'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
	'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
	'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
	'0': 0, '1': 1, '2': 2, '3': 3, '4': 4,
	'5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
}

// positionWeights are the weights for each of the 17 VIN positions.
var positionWeights = [17]int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}

// containsKeyword reports whether text contains keyword as a whole word,
// case-insensitively. The previous code used strings.Contains, so short context
// keywords matched inside unrelated words — positive "car"/"vin" inside
// "carbon"/"moving" fabricated a +50 boost on a random check-digit-passing
// token, and negative "sha"/"key"/"api" inside "shall"/"monkey"/"rapid" dropped
// real VINs. A plain string scan (word byte = [a-z0-9]) keeps this cheap.
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
		leftOK := i == 0 || !isVINWordByte(lt[i-1])
		right := i + len(lk)
		rightOK := right >= len(lt) || !isVINWordByte(lt[right])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
	return false
}

// isVINWordByte reports whether b is a word character ([a-z0-9]) for keyword
// boundary detection. text is already lowercased by the caller.
func isVINWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// knownWMIs maps common World Manufacturer Identifier prefixes to manufacturer names.
var knownWMIs = map[string]string{
	"1G1": "Chevrolet", "1G2": "Pontiac", "1GC": "Chevrolet Truck",
	"1GT": "GMC Truck", "1HG": "Honda", "1J4": "Jeep", "1FA": "Ford",
	"1FB": "Ford", "1FC": "Ford", "1FD": "Ford", "1FM": "Ford",
	"1FT": "Ford Truck", "1FU": "Freightliner", "1GY": "Cadillac",
	"1HD": "Harley-Davidson", "1HF": "Honda", "1LN": "Lincoln",
	"1ME": "Mercury", "1N4": "Nissan", "1NX": "Toyota",
	"2C3": "Chrysler", "2FA": "Ford Canada", "2G1": "Chevrolet Canada",
	"2HG": "Honda Canada", "2HM": "Hyundai Canada", "2T1": "Toyota Canada",
	"3FA": "Ford Mexico", "3G1": "Chevrolet Mexico", "3HG": "Honda Mexico",
	"3VW": "Volkswagen Mexico",
	"JHM": "Honda", "JN1": "Nissan", "JT2": "Toyota", "JTE": "Toyota",
	"JTD": "Toyota", "JTH": "Lexus",
	"KM8": "Hyundai", "KNA": "Kia", "KND": "Kia",
	"SAJ": "Jaguar", "SAL": "Land Rover", "SCA": "Rolls-Royce",
	"SCF": "Aston Martin",
	"WAU": "Audi", "WBA": "BMW", "WBS": "BMW M", "WDB": "Mercedes-Benz",
	"WDD": "Mercedes-Benz", "WF0": "Ford Germany", "WMW": "MINI",
	"WP0": "Porsche", "WUA": "Audi Sport", "WVW": "Volkswagen",
	"YV1": "Volvo",
	"ZAR": "Alfa Romeo", "ZFF": "Ferrari",
}

// Validator implements the detector.Validator interface for detecting
// Vehicle Identification Numbers using regex patterns, check digit validation,
// and contextual analysis.
type Validator struct {
	pattern string
	regex   *regexp.Regexp

	positiveKeywords []string
	negativeKeywords []string

	// maxKeywordLen is the length of the longest positive/negative keyword.
	// It bounds the line prefix/suffix a keyword can straddle at an injected
	// context boundary, letting analyzeContextHoisted scan only a small window
	// per match instead of the whole line.
	maxKeywordLen int

	testPatterns []string

	observer observability.Observer
}

// NewValidator creates and returns a new VIN Validator instance.
func NewValidator() *Validator {
	v := &Validator{
		// 17 alphanumeric characters excluding I, O, Q. Case-insensitive: VINs
		// are commonly stored lowercase or mixed-case in logs/JSON/CSV, and the
		// uppercase-only class never matched them (ValidateContent ToUppers the
		// match afterward, so the previous lowercasing was a detection no-op).
		// The lowercase exclusions (i, o, q) mirror the uppercase ones.
		pattern: `\b[A-HJ-NPR-Za-hj-npr-z0-9]{17}\b`,
		positiveKeywords: []string{
			"vin", "vehicle identification", "vehicle id", "chassis",
			"title", "registration", "dmv", "odometer", "mileage",
			"carfax", "autocheck", "recall", "nhtsa", "manufacturer",
			"make", "model", "year", "vehicle number", "frame number",
			"hull id", "vin:", "vin#", "automobile", "car", "truck",
			"motorcycle", "trailer", "fleet", "motor vehicle",
			"insurance claim", "accident report", "vehicle history",
			"dealer", "dealership", "automotive",
		},
		negativeKeywords: []string{
			"serial", "part number", "sku", "product code", "model number",
			"uuid", "hash", "token", "key", "password", "api",
			"mac address", "isbn", "test", "example", "sample", "dummy",
			"base64", "encoded", "hex", "checksum", "digest", "signature",
			"commit", "sha", "md5", "certificate", "license key",
			"activation", "registration key", "product key",
		},
		testPatterns: []string{
			"11111111111111111", "00000000000000000",
			"AAAAAAAAAAAAAAAAA", "12345678901234567",
			"ABCDEFGHJKLMNPRS",
		},
	}
	v.regex = regexp.MustCompile(v.pattern)
	for _, kw := range v.positiveKeywords {
		if len(kw) > v.maxKeywordLen {
			v.maxKeywordLen = len(kw)
		}
	}
	for _, kw := range v.negativeKeywords {
		if len(kw) > v.maxKeywordLen {
			v.maxKeywordLen = len(kw)
		}
	}
	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for VINs.
//
// Performance: a single very long line can carry thousands of candidate
// matches. The naive shape recomputed per-LINE-global work (strings.Index
// rescans for each match's offset, the hex-dump heuristics, and a ~60-keyword
// case-insensitive scan of the whole line for context, plus the same scan a
// second time for findKeywords) once PER MATCH, making the line O(M·L) —
// quadratic in line length. We now (1) get each match's byte offset from the
// regex (FindAllStringIndex) so no strings.Index rescan is needed (this also
// fixes the latent bug where strings.Index returned the FIRST occurrence of a
// duplicated token rather than the actual match), (2) hoist all per-line-global
// work out of the per-match loop — the lowercased line, the hex-dump verdict,
// and the per-keyword "present in line" verdict are each computed ONCE per
// line, and (3) restrict the per-match context scan to a bounded ±50-char
// window. Behavior is unchanged: the per-line keyword verdict plus the bounded
// boundary check reproduce the original fullContext/fullLine distinction
// exactly (see analyzeContextHoisted).
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: the context-aware
// form of ValidateContent, polling ctx once per line so a runaway multi-line scan
// is reclaimed promptly (v2 Phase 3). Returns partial matches + ctx.Err() on
// cancellation.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("vin_validator", "validate_content", originalPath)
	}

	var matches []detector.Match
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": len(matches)})
			}
			return matches, ctx.Err()
		}
		locs := v.regex.FindAllStringIndex(line, -1)
		if len(locs) == 0 {
			continue
		}

		// --- Per-LINE-global work, computed once and reused by every match on
		// this line (was previously recomputed per match -> O(M·L)). ---
		lineLower := strings.ToLower(line)
		lineIsHexDump := v.lineLooksEncoded(line)
		// Whether each keyword is present (as a whole word) anywhere in the
		// line. This is the dominant cost and is identical for all matches on
		// the line, so it is hoisted here.
		posInLine := keywordPresence(lineLower, v.positiveKeywords)
		negInLine := keywordPresence(lineLower, v.negativeKeywords)

		for _, loc := range locs {
			start, end := loc[0], loc[1]
			match := line[start:end]
			upper := strings.ToUpper(match)

			// --- Early rejection cascade ---

			if len(upper) != 17 {
				continue
			}

			if v.isAllRepeating(upper) {
				continue
			}

			if v.isTestPattern(upper) {
				continue
			}

			// Check-digit gate. The ISO 3779 position-9 check digit is mandatory
			// ONLY for North American VINs (WMI region 1-5); manufacturers in
			// the rest of the world are not required to encode it, so a huge
			// share of genuine EU/Asian VINs legitimately "fail" this checksum.
			// Hard-rejecting on failure therefore dropped most non-NA VINs —
			// including ones whose WMI is in our own knownWMIs table (WVW, WAU,
			// ZFF, ...). We now only hard-reject when the check digit is
			// REQUIRED (NA region). For non-NA VINs we keep the candidate but
			// require a recognized WMI as corroboration so we don't start
			// surfacing arbitrary 17-char alphanumeric tokens (hashes, base32);
			// the check-digit status is carried into confidence scoring below.
			checkDigitOK := v.checkDigitValid(upper)
			if !checkDigitOK {
				if v.isNorthAmericanVIN(upper) {
					continue // NA VIN with a bad check digit is genuinely invalid
				}
				if v.detectManufacturer(upper) == "" {
					continue // no check digit AND no known WMI -> not enough signal
				}
			}

			if v.isEncodedDataAt(line, start, end, lineIsHexDump) {
				continue
			}

			// --- Passed all gates: score confidence ---

			confidence, checks := v.calculateConfidence(upper, checkDigitOK)

			contextInfo := v.buildContextAt(line, start, end)
			contextImpact, posFound, negFound := v.analyzeContextHoisted(
				line, lineLower, start, end, posInLine, negInLine)
			confidence += contextImpact

			contextInfo.PositiveKeywords = posFound
			contextInfo.NegativeKeywords = negFound
			contextInfo.ConfidenceImpact = contextImpact

			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			if confidence <= 0 {
				continue
			}

			manufacturer := v.detectManufacturer(upper)
			metadata := map[string]any{
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			}
			if manufacturer != "" {
				metadata["manufacturer"] = manufacturer
			}

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1,
				Type:       "VIN",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "vin",
				Context:    contextInfo,
				Metadata:   metadata,
			})
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

// CalculateConfidence returns a base confidence and validation checks map.
// It satisfies the detector.Validator interface; the check-digit status is
// derived here so external callers get a correct score. The internal scan path
// uses calculateConfidence directly to avoid recomputing the check digit.
func (v *Validator) CalculateConfidence(vin string) (float64, map[string]bool) {
	return v.calculateConfidence(vin, v.checkDigitValid(vin))
}

// calculateConfidence scores a VIN given the already-computed check-digit
// result. A valid check digit is a strong signal (+20); an invalid one is only
// reached here for non-North-American VINs with a recognized WMI (the scan
// gate rejects NA VINs and unknown-WMI VINs that fail the check digit), so we
// neither add nor heavily penalize — the known WMI below carries the weight.
func (v *Validator) calculateConfidence(vin string, checkDigitOK bool) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":        true,
		"check_digit":   checkDigitOK,
		"known_wmi":     false,
		"valid_year":    false,
		"not_test":      true,
		"not_repeating": true,
	}

	confidence := 65.0

	if checkDigitOK {
		confidence += 20
	} else {
		// Non-NA VIN without the optional check digit: drop below the +20 a
		// valid checksum earns, so these surface lower than verified VINs but
		// remain detectable (a known WMI re-adds signal just below).
		confidence -= 10
	}

	// Known manufacturer
	if v.detectManufacturer(vin) != "" {
		checks["known_wmi"] = true
		confidence += 10
	}

	// Valid model year (position 10)
	if v.isValidModelYear(vin[9]) {
		checks["valid_year"] = true
		confidence += 5
	}

	return confidence, checks
}

// isNorthAmericanVIN reports whether the VIN's WMI region (first character)
// designates North America (1-5), where the ISO 3779 position-9 check digit is
// mandatory. For these VINs a failed check digit means the VIN is invalid; for
// all other regions the check digit is optional and a failure is not
// disqualifying on its own.
func (v *Validator) isNorthAmericanVIN(vin string) bool {
	if len(vin) == 0 {
		return false
	}
	return vin[0] >= '1' && vin[0] <= '5'
}

// AnalyzeContext adjusts confidence based on surrounding text.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)
	fullLine := strings.ToLower(context.FullLine)

	var impact float64

	for _, keyword := range v.positiveKeywords {
		if containsKeyword(fullContext, keyword) {
			if containsKeyword(fullLine, keyword) {
				impact += 25
			} else {
				impact += 10
			}
		}
	}

	for _, keyword := range v.negativeKeywords {
		if containsKeyword(fullContext, keyword) {
			if containsKeyword(fullLine, keyword) {
				impact -= 15
			} else {
				impact -= 8
			}
		}
	}

	if impact > 50 {
		impact = 50
	} else if impact < -50 {
		impact = -50
	}

	return impact
}

// findKeywords returns a list of keywords found in the context.
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)

	var found []string
	for _, keyword := range keywords {
		if containsKeyword(fullContext, keyword) {
			found = append(found, keyword)
		}
	}
	return found
}

// keywordPresence returns, parallel to keywords, whether each keyword occurs as
// a whole word in lineLower. lineLower MUST already be lowercased. This is the
// per-LINE-global keyword scan, computed once per line and reused by every
// match on the line (it is the dominant cost the per-match loop used to repeat).
func keywordPresence(lineLower string, keywords []string) []bool {
	present := make([]bool, len(keywords))
	for i, kw := range keywords {
		present[i] = containsKeyword(lineLower, kw)
	}
	return present
}

// analyzeContextHoisted reproduces AnalyzeContext + findKeywords for a match at
// byte offsets [start,end) on line, but without re-scanning the whole line per
// match. It is mathematically identical to calling, with the ContextInfo that
// buildContextAt(line, start, end) produces:
//
//	impact = AnalyzeContext(match, ctx)
//	posFound = findKeywords(ctx, positiveKeywords)
//	negFound = findKeywords(ctx, negativeKeywords)
//
// The original computes fullContext = lower(before + " " + line + " " + after)
// and asks, per keyword, "present in fullContext?" (drives findKeywords and the
// +/- impact) and "present in line?" (drives the in-line vs in-context weight).
// Because before/after are slices of line and fullContext ⊇ line, a keyword is
// in fullContext iff it is in the line (precomputed in posInLine/negInLine) OR
// it straddles one of the two injected " " boundaries. A straddling match uses
// at most maxKeywordLen chars on each side of a boundary, so it is fully
// captured by a bounded boundary string. The '\x00' separator below cannot
// appear in any keyword, so it never fabricates a cross-region match.
func (v *Validator) analyzeContextHoisted(
	line, lineLower string, start, end int,
	posInLine, negInLine []bool,
) (impact float64, posFound, negFound []string) {

	boundary := v.boundaryContext(lineLower, start, end)

	for i, kw := range v.positiveKeywords {
		inLine := posInLine[i]
		if inLine {
			impact += 25
			posFound = append(posFound, kw)
		} else if containsKeyword(boundary, kw) {
			impact += 10
			posFound = append(posFound, kw)
		}
	}

	for i, kw := range v.negativeKeywords {
		inLine := negInLine[i]
		if inLine {
			impact -= 15
			negFound = append(negFound, kw)
		} else if containsKeyword(boundary, kw) {
			impact -= 8
			negFound = append(negFound, kw)
		}
	}

	if impact > 50 {
		impact = 50
	} else if impact < -50 {
		impact = -50
	}

	return impact, posFound, negFound
}

// boundaryContext builds the small string needed to detect keywords that occur
// in the original fullContext (before + " " + line + " " + after) but NOT in
// the line itself — i.e. matches that straddle one of the two injected " "
// boundaries, plus matches living entirely in the ±contextWindow before/after
// slices. It mirrors fullContext at both junctions using only a bounded line
// prefix/suffix, so the per-match cost is O(window) rather than O(line).
//
// Correctness of the truncation: any keyword that straddles an injected " "
// spans at most maxKeywordLen bytes, so it reaches at most maxKeywordLen bytes
// into the line from each junction. We therefore take 2*maxKeywordLen bytes of
// line on each side, guaranteeing every straddling match lies wholly within the
// reproduced region and at least maxKeywordLen bytes away from the truncation
// seam. To stop the seam itself from fabricating a word boundary (which would
// mis-credit a keyword that is interior to the real line), each seam is guarded
// with a word byte ('0'): a keyword abutting the seam then gets a non-boundary
// there. Such a keyword is necessarily interior to the line — never straddling,
// since straddling matches are >= maxKeywordLen from the seam — so whenever it
// truly is a whole word in the line it is already credited via the per-line
// keywordPresence scan (inLine), and the boundaryContext result is only ever
// consulted when inLine is false. The '\x01' between the two junction regions
// (also a non-keyword, non-word byte) keeps them from forming a cross match.
func (v *Validator) boundaryContext(lineLower string, start, end int) string {
	k := 2 * v.maxKeywordLen

	bStart := start - contextWindow
	if bStart < 0 {
		bStart = 0
	}
	before := lineLower[bStart:start]

	aEnd := end + contextWindow
	if aEnd > len(lineLower) {
		aEnd = len(lineLower)
	}
	after := lineLower[end:aEnd]

	// linePrefix mirrors the start of the line (left side of the after|line and
	// before|line junctions); its tail seam is guarded so it cannot fabricate a
	// right word boundary for an interior keyword.
	linePrefix := lineLower
	prefixTruncated := false
	if len(linePrefix) > k {
		linePrefix = linePrefix[:k]
		prefixTruncated = true
	}
	// lineSuffix mirrors the end of the line; its head seam is guarded so it
	// cannot fabricate a left word boundary for an interior keyword.
	lineSuffix := lineLower
	suffixTruncated := false
	if len(lineSuffix) > k {
		lineSuffix = lineSuffix[len(lineSuffix)-k:]
		suffixTruncated = true
	}

	var b strings.Builder
	b.Grow(len(before) + len(after) + len(linePrefix) + len(lineSuffix) + 8)

	// before + " " + linePrefix reproduces the before|line junction.
	b.WriteString(before)
	b.WriteByte(' ')
	b.WriteString(linePrefix)
	if prefixTruncated {
		b.WriteByte('0') // guard: real line continues with a byte here
	}

	b.WriteByte('\x01') // separates the two junction regions (non-word, non-keyword)

	// lineSuffix + " " + after reproduces the line|after junction.
	if suffixTruncated {
		b.WriteByte('0') // guard: real line precedes lineSuffix with a byte here
	}
	b.WriteString(lineSuffix)
	b.WriteByte(' ')
	b.WriteString(after)

	return b.String()
}

// checkDigitValid validates the VIN check digit (position 9) using the standard
// weighted transliteration algorithm. Returns true if the check digit is correct.
func (v *Validator) checkDigitValid(vin string) bool {
	if len(vin) != 17 {
		return false
	}

	sum := 0
	for i := 0; i < 17; i++ {
		if i == 8 {
			continue // skip check digit position
		}
		val, ok := transliterationMap[vin[i]]
		if !ok {
			return false
		}
		sum += val * positionWeights[i]
	}

	remainder := sum % 11
	var expected byte
	if remainder == 10 {
		expected = 'X'
	} else {
		expected = byte('0' + remainder)
	}

	return vin[8] == expected
}

// isValidModelYear checks if position 10 is a valid model year code.
// Valid codes: A-H, J-N, P, R-T, V-Y (letters), 1-9 (digits).
func (v *Validator) isValidModelYear(c byte) bool {
	switch {
	case c >= '1' && c <= '9':
		return true
	case c >= 'A' && c <= 'H':
		return true
	case c >= 'J' && c <= 'N':
		return true
	case c == 'P':
		return true
	case c >= 'R' && c <= 'T':
		return true
	case c >= 'V' && c <= 'Y':
		return true
	}
	return false
}

// detectManufacturer returns the manufacturer name for a known WMI, or empty string.
func (v *Validator) detectManufacturer(vin string) string {
	if len(vin) < 3 {
		return ""
	}
	return knownWMIs[vin[:3]]
}

// isAllRepeating returns true if all characters in the string are the same.
func (v *Validator) isAllRepeating(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// isTestPattern checks if the VIN matches a known test/placeholder pattern.
func (v *Validator) isTestPattern(vin string) bool {
	for _, tp := range v.testPatterns {
		if vin == tp {
			return true
		}
	}
	return false
}

// lineLooksEncoded reports whether the LINE as a whole looks like encoded data
// (a hex dump). This verdict is identical for every match on the line, so the
// scan path computes it once per line and passes it to isEncodedDataAt rather
// than recomputing it per match (it walks the whole line twice).
//
// Hex dump patterns. The previous `Count(line,"0x") >= 3` rule dropped the
// whole line — and the valid VIN on it — whenever it mentioned three hex
// literals, e.g. "VIN 1HGBH41JXMN109186 colors 0xFF0000 0x00FF00 0x0000FF"
// (L47). A genuine hex dump is DOMINATED by 0x tokens, so we instead require
// a strict majority of whitespace tokens to be 0x-prefixed hex words.
func (v *Validator) lineLooksEncoded(line string) bool {
	if looksLikeHexDump(line) {
		return true
	}
	if strings.Count(line, " ") > 10 && isHexDump(line) {
		return true
	}
	return false
}

// isEncodedDataAt is the offset-based form of isEncodedData. lineIsHexDump is
// the precomputed per-line lineLooksEncoded verdict; start/end are the match's
// byte offsets within line, so the base64-adjacency check needs no
// strings.Index rescan (which would also have found the FIRST occurrence of a
// duplicated token rather than this match).
func (v *Validator) isEncodedDataAt(line string, start, end int, lineIsHexDump bool) bool {
	if lineIsHexDump {
		return true
	}

	// Base64-like context (long unbroken alphanumeric strings): a match flanked
	// by an alphanumeric byte is part of a longer token, not a standalone VIN.
	before := start - 1
	if before >= 0 && isAlphanumeric(line[before]) {
		return true
	}
	if end < len(line) && isAlphanumeric(line[end]) {
		return true
	}

	return false
}

// isEncodedData detects if the match is likely part of encoded data (base64,
// hex dumps, etc.). Retained for the detector.Validator interface and external
// callers; the internal scan path uses isEncodedDataAt with precomputed offsets
// and a hoisted per-line hex-dump verdict. Behavior is identical to the
// historical implementation, including using the FIRST occurrence of match.
func (v *Validator) isEncodedData(line, match string) bool {
	idx := strings.Index(line, match)
	start := idx
	end := idx + len(match)
	if idx < 0 {
		// No occurrence: only the per-line hex-dump verdict can apply.
		return v.lineLooksEncoded(line)
	}
	return v.isEncodedDataAt(line, start, end, v.lineLooksEncoded(line))
}

func isAlphanumeric(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func isHexDump(line string) bool {
	hexChars := 0
	for _, c := range line {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ' ' {
			hexChars++
		}
	}
	return len(line) > 0 && float64(hexChars)/float64(len(line)) > 0.85
}

// looksLikeHexDump reports whether a line is a hex dump — i.e. a strict majority
// of its whitespace-separated tokens are 0x-prefixed hex words (and there are at
// least three). This distinguishes a real dump ("0x1A 0x2B 0x3C ...") from a
// VIN line that merely mentions a few hex literals ("VIN ... 0xFF0000 0x00FF00
// 0x0000FF"), which should not be discarded.
func looksLikeHexDump(line string) bool {
	toks := strings.Fields(line)
	if len(toks) == 0 {
		return false
	}
	hex := 0
	for _, t := range toks {
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "0x") && len(lt) > 2 {
			hex++
		}
	}
	return hex >= 3 && hex*2 > len(toks)
}

// contextWindow is the number of characters captured before and after a match
// for BeforeText/AfterText context.
const contextWindow = 50

// buildContextAt builds context information around a match given its byte
// offsets within line, slicing a bounded ±contextWindow window instead of
// re-scanning the whole line with strings.Index (which is the offset-based
// equivalent of buildContext).
func (v *Validator) buildContextAt(line string, start, end int) detector.ContextInfo {
	ctx := detector.ContextInfo{
		FullLine: line,
	}

	bStart := start - contextWindow
	if bStart < 0 {
		bStart = 0
	}
	ctx.BeforeText = line[bStart:start]

	aEnd := end + contextWindow
	if aEnd > len(line) {
		aEnd = len(line)
	}
	ctx.AfterText = line[end:aEnd]

	return ctx
}

// buildContext extracts context information around a match within the current
// line. Retained for the detector.Validator interface and external callers; the
// internal scan path uses buildContextAt with the match's known offsets.
func (v *Validator) buildContext(line, match string) detector.ContextInfo {
	idx := strings.Index(line, match)
	if idx < 0 {
		return detector.ContextInfo{FullLine: line}
	}
	return v.buildContextAt(line, idx, idx+len(match))
}
