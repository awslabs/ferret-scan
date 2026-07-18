// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns used across validator methods.
var (
	// reStreetAddress matches a US street address: number + street name + street type.
	// Requires at least a street number, one or more name words, and a recognized suffix.
	// The suffix list is comprehensive but kept to common US types to minimize false positives.
	reStreetAddress = regexp.MustCompile(
		`\b(\d{1,6})\s+` + // street number (1-6 digits)
			`([A-Za-z][A-Za-z0-9]*(?:\s+[A-Za-z][A-Za-z0-9]*)*)` + // street name (1+ words)
			`\s+(` +
			`St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court|` +
			`Rd|Road|Way|Pkwy|Parkway|Cir|Circle|Pl|Place|Ter|Terrace|` +
			`Trl|Trail|Loop|Run|Pass|Pike|Hwy|Highway|Sq|Square` +
			`)` +
			`\.?` + // optional trailing dot
			`\b`,
	)

	// rePOBox matches P.O. Box addresses.
	rePOBox = regexp.MustCompile(`(?i)\b(?:P\.?\s*O\.?\s*Box|Post\s+Office\s+Box)\s+(\d{1,10})\b`)

	// reAptSuiteUnit matches apartment/suite/unit indicators (used for context boosting).
	reAptSuiteUnit = regexp.MustCompile(`(?i)\b(?:Apt|Apartment|Ste|Suite|Unit|#)\s*\.?\s*[A-Za-z0-9-]+\b`)

	// reCityStateZip matches a city, 2-letter state abbreviation, and 5 or 5+4 digit ZIP.
	reCityStateZip = regexp.MustCompile(
		`(?i)\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*),?\s+` + // city
			`(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|` +
			`MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|` +
			`SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)` + // state abbreviation
			`\s+(\d{5}(?:-\d{4})?)\b`, // ZIP code
	)

	// reZIPAlone matches a standalone 5-digit or 5+4 ZIP (used for context on adjacent lines).
	reZIPAlone = regexp.MustCompile(`\b\d{5}(?:-\d{4})?\b`)

	// reStateAbbrev matches a standalone 2-letter US state abbreviation.
	reStateAbbrev = regexp.MustCompile(
		`\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|` +
			`MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|` +
			`SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b`,
	)

	// reDirectionalAddr matches addresses with directional abbreviations (N., S., E., W., etc.)
	// before the street name, which the primary regex cannot handle due to the period.
	reDirectionalAddr = regexp.MustCompile(
		`\b(\d{1,6})\s+` + // street number
			`([NSEW]\.?\s+|(?:N[EW]|S[EW])\.?\s+)` + // directional prefix with optional dot
			`([A-Za-z][A-Za-z0-9]*(?:\s+[A-Za-z][A-Za-z0-9]*)*)` + // street name
			`\s+(` +
			`St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court|` +
			`Rd|Road|Way|Pkwy|Parkway|Cir|Circle|Pl|Place|Ter|Terrace|` +
			`Trl|Trail|Loop|Run|Pass|Pike|Hwy|Highway|Sq|Square` +
			`)` +
			`\.?` + // optional trailing dot
			`\b`,
	)

	// False positive patterns
	reIPAddress     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reVersion       = regexp.MustCompile(`\b\d+\.\d+\.\d+\b`)
	reCodeLineRef   = regexp.MustCompile(`\b\d+\s+\w+\.(go|py|js|ts|java|rb|rs|c|cpp|h|cs|swift|kt)\b`)
	reNumberedList  = regexp.MustCompile(`^\s*\d+[\.\)]\s+`)
	reMathExpr      = regexp.MustCompile(`\b\d+\s*[+\-*/=<>]+\s*\d+\b`)
	reAllDigitsLine = regexp.MustCompile(`^\s*\d+\s*$`)

	// Month names and day names that should not be street names by themselves.
	monthNames = map[string]bool{
		"january": true, "february": true, "march": true, "april": true,
		"may": true, "june": true, "july": true, "august": true,
		"september": true, "october": true, "november": true, "december": true,
		"jan": true, "feb": true, "mar": true, "apr": true,
		"jun": true, "jul": true, "aug": true, "sep": true,
		"oct": true, "nov": true, "dec": true,
		"monday": true, "tuesday": true, "wednesday": true, "thursday": true,
		"friday": true, "saturday": true, "sunday": true,
	}

	// Words unlikely to appear in real street names (prepositions, articles, common nouns).
	// Used to detect when the regex is being too greedy and matching non-address phrases.
	unlikelyStreetWords = map[string]bool{
		"on": true, "in": true, "at": true, "the": true, "of": true,
		"for": true, "to": true, "from": true, "with": true, "by": true,
		"is": true, "are": true, "was": true, "were": true, "be": true,
		"an": true, "and": true, "or": true, "not": true, "but": true,
		"connections": true, "processes": true, "items": true, "records": true,
		"entries": true, "requests": true, "events": true, "sessions": true,
	}
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively, using word-boundary detection.
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
// physical addresses using regex patterns and contextual analysis.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new Validator instance for physical addresses.
func NewValidator() *Validator {
	v := &Validator{
		positiveKeywords: []string{
			"address", "street", "mailing", "shipping", "billing",
			"residence", "home", "office", "deliver", "apt", "suite",
			"unit", "floor", "location", "postal", "mail to",
			"ship to", "send to", "located at",
		},
		negativeKeywords: []string{
			"ip", "version", "line", "page", "step", "item",
			"chapter", "section", "figure", "table", "equation",
			"test", "example", "sample", "placeholder", "fake",
			"mock", "demo", "lorem", "foo", "bar",
		},
	}

	v.regex = reStreetAddress

	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for physical addresses.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx is the context-aware form of ValidateContent, polling ctx
// once per line for cooperative cancellation.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		// Skip lines that look like false positive sources
		if v.isFalsePositiveLine(line) {
			continue
		}

		// Detect PO Box addresses
		poMatches := rePOBox.FindAllStringIndex(line, -1)
		for _, loc := range poMatches {
			matchText := line[loc[0]:loc[1]]

			confidence := v.calculatePOBoxConfidence(line, lines, lineNum)

			// Check negative keywords
			if v.hasNegativeKeywords(line) {
				confidence -= 25
			}

			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			contextInfo := v.buildContextInfo(line, loc[0], len(matchText))

			matches = append(matches, detector.Match{
				Text:       matchText,
				LineNumber: lineNum + 1,
				Type:       "PO_BOX",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "physical_address",
				Context:    contextInfo,
				Metadata: map[string]any{
					"source":        "preprocessed_content",
					"original_file": originalPath,
				},
			})
		}

		// Detect street addresses (primary pattern)
		streetMatches := reStreetAddress.FindAllStringIndex(line, -1)
		for _, loc := range streetMatches {
			matchText := line[loc[0]:loc[1]]

			// Validate this is not a false positive
			if v.isStreetFalsePositive(line, matchText, loc[0]) {
				continue
			}

			confidence := v.calculateStreetConfidence(matchText, line, lines, lineNum)

			// Check negative keywords
			if v.hasNegativeKeywords(line) {
				confidence -= 25
			}

			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			contextInfo := v.buildContextInfo(line, loc[0], len(matchText))

			matches = append(matches, detector.Match{
				Text:       matchText,
				LineNumber: lineNum + 1,
				Type:       "US_STREET_ADDRESS",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "physical_address",
				Context:    contextInfo,
				Metadata: map[string]any{
					"source":        "preprocessed_content",
					"original_file": originalPath,
				},
			})
		}

		// Detect street addresses with directional prefixes (N., S., E., W.)
		// These are missed by the primary regex due to the period in "N."
		dirMatches := reDirectionalAddr.FindAllStringIndex(line, -1)
		for _, loc := range dirMatches {
			matchText := line[loc[0]:loc[1]]

			// Skip if already matched by primary pattern
			alreadyMatched := false
			for _, sm := range streetMatches {
				if loc[0] >= sm[0] && loc[0] < sm[1] {
					alreadyMatched = true
					break
				}
			}
			if alreadyMatched {
				continue
			}

			if v.isStreetFalsePositive(line, matchText, loc[0]) {
				continue
			}

			confidence := v.calculateStreetConfidence(matchText, line, lines, lineNum)

			if v.hasNegativeKeywords(line) {
				confidence -= 25
			}

			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			contextInfo := v.buildContextInfo(line, loc[0], len(matchText))

			matches = append(matches, detector.Match{
				Text:       matchText,
				LineNumber: lineNum + 1,
				Type:       "US_STREET_ADDRESS",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "physical_address",
				Context:    contextInfo,
				Metadata: map[string]any{
					"source":        "preprocessed_content",
					"original_file": originalPath,
				},
			})
		}
	}

	return matches, nil
}

// calculateStreetConfidence computes confidence for a street address match.
func (v *Validator) calculateStreetConfidence(match, line string, lines []string, lineNum int) float64 {
	// Base confidence: street number + name + recognized type
	confidence := 50.0

	// Check for city/state/ZIP on same line
	if reCityStateZip.MatchString(line) {
		confidence += 30
	} else {
		// Check adjacent lines for city/state/ZIP
		adjacentContext := v.getAdjacentLines(lines, lineNum, 2)
		if reCityStateZip.MatchString(adjacentContext) {
			confidence += 25
		} else {
			// Check for state abbreviation or ZIP alone on adjacent lines
			if reStateAbbrev.MatchString(adjacentContext) && reZIPAlone.MatchString(adjacentContext) {
				confidence += 20
			} else if reZIPAlone.MatchString(adjacentContext) {
				confidence += 10
			}
		}
	}

	// Check for apt/suite/unit on same line or adjacent
	if reAptSuiteUnit.MatchString(line) {
		confidence += 10
	} else {
		adjacentContext := v.getAdjacentLines(lines, lineNum, 1)
		if reAptSuiteUnit.MatchString(adjacentContext) {
			confidence += 5
		}
	}

	// Positive keyword boost
	keywordBoost := v.calculateKeywordBoost(line, lines, lineNum)
	confidence += keywordBoost

	return confidence
}

// calculatePOBoxConfidence computes confidence for a PO Box match.
func (v *Validator) calculatePOBoxConfidence(line string, lines []string, lineNum int) float64 {
	// PO Box is a strong signal on its own
	confidence := 60.0

	// Check for city/state/ZIP on same line
	if reCityStateZip.MatchString(line) {
		confidence += 25
	} else {
		// Check adjacent lines
		adjacentContext := v.getAdjacentLines(lines, lineNum, 2)
		if reCityStateZip.MatchString(adjacentContext) {
			confidence += 20
		} else if reZIPAlone.MatchString(adjacentContext) {
			confidence += 10
		}
	}

	// Positive keyword boost
	keywordBoost := v.calculateKeywordBoost(line, lines, lineNum)
	confidence += keywordBoost

	return confidence
}

// calculateKeywordBoost returns positive keyword confidence boost.
func (v *Validator) calculateKeywordBoost(line string, lines []string, lineNum int) float64 {
	boost := 0.0

	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			boost += 15
			break // Only count once for same-line keywords
		}
	}

	// Check adjacent lines for keywords (weaker boost)
	adjacentContext := v.getAdjacentLines(lines, lineNum, 2)
	if boost == 0 {
		for _, kw := range v.positiveKeywords {
			if containsKeyword(adjacentContext, kw) {
				boost += 8
				break
			}
		}
	}

	return boost
}

// hasNegativeKeywords checks if the line contains negative keywords.
func (v *Validator) hasNegativeKeywords(line string) bool {
	for _, kw := range v.negativeKeywords {
		if containsKeyword(line, kw) {
			return true
		}
	}
	return false
}

// isFalsePositiveLine checks if the entire line is a known false positive pattern.
func (v *Validator) isFalsePositiveLine(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Skip empty lines
	if trimmed == "" {
		return true
	}

	// Skip lines that are just a number (line numbers, list items)
	if reAllDigitsLine.MatchString(trimmed) {
		return true
	}

	// Skip numbered list items where the number is the "address number"
	if reNumberedList.MatchString(trimmed) {
		// Only skip if the rest doesn't look like an address
		afterNum := reNumberedList.ReplaceAllString(trimmed, "")
		if !reStreetAddress.MatchString(afterNum) {
			return false // Let it through if the rest has a real address
		}
	}

	return false
}

// isStreetFalsePositive checks whether a street address match is actually a false positive.
func (v *Validator) isStreetFalsePositive(line, match string, matchStart int) bool {
	// Check if this is part of an IP address
	if reIPAddress.MatchString(line) {
		// Check if the street number overlaps with an IP
		ipLocs := reIPAddress.FindAllStringIndex(line, -1)
		for _, loc := range ipLocs {
			if matchStart >= loc[0] && matchStart < loc[1] {
				return true
			}
		}
	}

	// Check if this is a version string context
	if reVersion.MatchString(line) {
		// Only suppress if the match number is part of a version
		vLocs := reVersion.FindAllStringIndex(line, -1)
		for _, loc := range vLocs {
			if matchStart >= loc[0] && matchStart < loc[1] {
				return true
			}
		}
	}

	// Check if this is a code file reference (e.g., "123 main.go")
	if reCodeLineRef.MatchString(line) {
		cLocs := reCodeLineRef.FindAllStringIndex(line, -1)
		for _, loc := range cLocs {
			if matchStart >= loc[0] && matchStart < loc[1] {
				return true
			}
		}
	}

	// Check if the trailing dot of the match is actually part of a file extension
	// e.g., "100 North Dr.go" — the "Dr." is part of "Dr.go"
	matchEnd := matchStart + len(match)
	if matchEnd < len(line) && line[matchEnd-1] == '.' {
		// The match ended with a dot; check if it continues with alpha chars (file extension)
		rest := line[matchEnd:]
		if len(rest) > 0 && rest[0] >= 'a' && rest[0] <= 'z' || (len(rest) > 0 && rest[0] >= 'A' && rest[0] <= 'Z') {
			return true
		}
	}
	// Also check: match without dot but next char after match is a dot then alpha
	if matchEnd < len(line) && line[matchEnd] == '.' {
		rest := line[matchEnd+1:]
		if len(rest) > 0 && ((rest[0] >= 'a' && rest[0] <= 'z') || (rest[0] >= 'A' && rest[0] <= 'Z')) {
			return true
		}
	}

	// Check if the street number is part of a math expression
	if reMathExpr.MatchString(line) {
		mLocs := reMathExpr.FindAllStringIndex(line, -1)
		for _, loc := range mLocs {
			if matchStart >= loc[0] && matchStart < loc[1] {
				return true
			}
		}
	}

	// Reject very short street names with common code words
	// e.g., "1 Main Dr" is fine, but single-char names are suspicious
	parts := strings.Fields(match)
	if len(parts) >= 3 {
		// Street name is everything between number and type
		streetName := strings.Join(parts[1:len(parts)-1], " ")
		if len(streetName) <= 1 {
			return true // Single-character street names are suspicious
		}

		// Reject if the street name is a month/day name (e.g., "12 January Dr")
		nameWords := strings.Fields(streetName)
		if len(nameWords) == 1 {
			if monthNames[strings.ToLower(nameWords[0])] {
				return true
			}
		}

		// Reject if the street name contains unlikely words (prepositions, common nouns)
		// that indicate the regex is greedily matching a non-address phrase.
		// Only apply this heuristic when the name has multiple words and one of them
		// is clearly a non-street word, suggesting a phrase like "connections on Main".
		hasUnlikely := false
		hasRealName := false
		for _, w := range nameWords {
			lower := strings.ToLower(w)
			if unlikelyStreetWords[lower] {
				hasUnlikely = true
			} else {
				hasRealName = true
			}
		}
		// If the name part has unlikely words and the overall structure looks like
		// "N things preposition Name Suffix", reject it.
		if hasUnlikely && hasRealName && len(nameWords) >= 2 {
			// Check if the first word of the street name is an unlikely word
			// Pattern: "100 connections on Main Loop" — "connections" is first, unlikely
			if unlikelyStreetWords[strings.ToLower(nameWords[0])] {
				return true
			}
		}
	}

	return false
}

// getAdjacentLines returns concatenated text from lines adjacent to lineNum.
func (v *Validator) getAdjacentLines(lines []string, lineNum, radius int) string {
	var parts []string
	for i := lineNum - radius; i <= lineNum+radius; i++ {
		if i >= 0 && i < len(lines) && i != lineNum {
			parts = append(parts, lines[i])
		}
	}
	return strings.Join(parts, " ")
}

// buildContextInfo constructs context info for a match.
func (v *Validator) buildContextInfo(line string, matchStart, matchLen int) detector.ContextInfo {
	contextInfo := detector.ContextInfo{
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

	contextInfo.BeforeText = line[start:matchStart]
	contextInfo.AfterText = line[matchStart+matchLen : end]

	// Find positive/negative keywords on line
	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			contextInfo.PositiveKeywords = append(contextInfo.PositiveKeywords, kw)
		}
	}
	for _, kw := range v.negativeKeywords {
		if containsKeyword(line, kw) {
			contextInfo.NegativeKeywords = append(contextInfo.NegativeKeywords, kw)
		}
	}

	return contextInfo
}

// CalculateConfidence calculates the confidence score for a potential address match.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"has_street_number":  false,
		"has_street_name":    false,
		"has_street_type":    false,
		"has_city_state":     false,
		"has_zip":            false,
		"not_false_positive": true,
	}

	confidence := 50.0

	// Check street address components
	if reStreetAddress.MatchString(match) {
		checks["has_street_number"] = true
		checks["has_street_name"] = true
		checks["has_street_type"] = true
		confidence = 50.0
	} else if rePOBox.MatchString(match) {
		checks["has_street_number"] = true
		confidence = 60.0
	}

	// Check for city/state/ZIP
	if reCityStateZip.MatchString(match) {
		checks["has_city_state"] = true
		checks["has_zip"] = true
		confidence += 30
	}

	if confidence > 100 {
		confidence = 100
	}

	return confidence, checks
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	var impact float64

	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText

	// Positive keywords boost
	for _, kw := range v.positiveKeywords {
		if containsKeyword(fullContext, kw) {
			impact += 15
			break
		}
	}

	// Negative keywords penalty
	for _, kw := range v.negativeKeywords {
		if containsKeyword(fullContext, kw) {
			impact -= 20
			break
		}
	}

	// Cap impact
	if impact > 30 {
		impact = 30
	} else if impact < -30 {
		impact = -30
	}

	return impact
}
