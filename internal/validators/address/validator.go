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

		// Per-line invariants, hoisted out of the per-match loops. The confidence
		// functions and hasNegativeKeywords scan only the line (and adjacent
		// lines) and ignore the match, so their results are identical for every
		// match on this line. Computing them once per line instead of once per
		// match keeps scanning O(line length) rather than O(matches × line
		// length) — the latter is a single-long-line CPU-exhaustion DoS (a 48KB
		// line otherwise took ~63s). See the timing regression test.
		lineHasNegative := v.hasNegativeKeywords(line)
		var negativePenalty float64
		if lineHasNegative {
			negativePenalty = 25
		}
		// Keyword sets for ContextInfo, computed once per line (see buildContextInfo).
		linePositiveKeywords := v.keywordsPresent(line, v.positiveKeywords)
		lineNegativeKeywords := v.keywordsPresent(line, v.negativeKeywords)

		// Detect PO Box addresses
		poMatches := rePOBox.FindAllStringIndex(line, -1)
		var poConfidence float64
		if len(poMatches) > 0 {
			poConfidence = v.calculatePOBoxConfidence(line, lines, lineNum) - negativePenalty
		}
		for i, loc := range poMatches {
			if execguard.LineLoopCancelled(ctx, i) {
				return matches, ctx.Err()
			}
			matchText := line[loc[0]:loc[1]]

			confidence := poConfidence

			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			contextInfo := v.buildContextInfo(line, loc[0], len(matchText), linePositiveKeywords, lineNegativeKeywords)

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

		// Detect street addresses (primary pattern). The street confidence is a
		// per-line invariant too (base 50 plus line/adjacent-line signals; it
		// ignores the match), so compute it once and reuse for every match on the
		// line. streetStartSet indexes the primary-match start offsets so the
		// directional loop's "already matched" check is O(1) instead of O(matches).
		streetMatches := reStreetAddress.FindAllStringIndex(line, -1)
		var streetFP *streetFPContext
		var streetConfidence float64
		if len(streetMatches) > 0 {
			streetFP = v.newStreetFPContext(line)
			streetConfidence = v.calculateStreetConfidence("", line, lines, lineNum)
		}
		for i, loc := range streetMatches {
			if execguard.LineLoopCancelled(ctx, i) {
				return matches, ctx.Err()
			}
			matchText := line[loc[0]:loc[1]]

			// Validate this is not a false positive (uses per-line precomputed
			// FP locus sets; only the offset-overlap test is per match).
			if streetFP.isFalsePositive(matchText, loc[0]) {
				continue
			}

			confidence := streetConfidence

			// Check negative keywords (per-line invariant)
			if lineHasNegative {
				confidence -= 25
			}

			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			contextInfo := v.buildContextInfo(line, loc[0], len(matchText), linePositiveKeywords, lineNegativeKeywords)

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
		if len(dirMatches) > 0 && streetFP == nil {
			streetFP = v.newStreetFPContext(line)
			streetConfidence = v.calculateStreetConfidence("", line, lines, lineNum)
		}
		for i, loc := range dirMatches {
			if execguard.LineLoopCancelled(ctx, i) {
				return matches, ctx.Err()
			}
			matchText := line[loc[0]:loc[1]]

			// Skip if already matched by primary pattern. streetMatches is sorted
			// by start offset (FindAllStringIndex returns left-to-right), so a
			// binary search for the span containing loc[0] is O(log matches)
			// instead of the O(matches) linear scan that made this loop quadratic.
			if spanContains(streetMatches, loc[0]) {
				continue
			}

			if streetFP.isFalsePositive(matchText, loc[0]) {
				continue
			}

			confidence := streetConfidence

			if lineHasNegative {
				confidence -= 25
			}

			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			contextInfo := v.buildContextInfo(line, loc[0], len(matchText), linePositiveKeywords, lineNegativeKeywords)

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
// streetFPContext holds the per-line false-positive locus sets (IP, version,
// code-ref, math-expression spans) computed ONCE per line. The original
// isStreetFalsePositive re-ran four whole-line regex scans for every match,
// which is O(matches × line length) — the single-long-line DoS. Building the
// locus sets once and only doing the cheap offset-overlap test per match keeps
// it O(line length). newStreetFPContext runs the regexes lazily: FindAllStringIndex
// is only called when MatchString reports the pattern is present.
type streetFPContext struct {
	line     string
	ipLocs   [][]int
	verLocs  [][]int
	codeLocs [][]int
	mathLocs [][]int
}

func (v *Validator) newStreetFPContext(line string) *streetFPContext {
	c := &streetFPContext{line: line}
	if reIPAddress.MatchString(line) {
		c.ipLocs = reIPAddress.FindAllStringIndex(line, -1)
	}
	if reVersion.MatchString(line) {
		c.verLocs = reVersion.FindAllStringIndex(line, -1)
	}
	if reCodeLineRef.MatchString(line) {
		c.codeLocs = reCodeLineRef.FindAllStringIndex(line, -1)
	}
	if reMathExpr.MatchString(line) {
		c.mathLocs = reMathExpr.FindAllStringIndex(line, -1)
	}
	return c
}

func overlapsAny(locs [][]int, matchStart int) bool {
	for _, loc := range locs {
		if matchStart >= loc[0] && matchStart < loc[1] {
			return true
		}
	}
	return false
}

// spanContains reports whether pos falls inside any [start,end) span in locs.
// locs must be sorted by start offset (as FindAllStringIndex returns them),
// enabling an O(log n) binary search instead of an O(n) scan — this is what
// removes the quadratic "already matched by the primary pattern" check in the
// directional-address loop.
func spanContains(locs [][]int, pos int) bool {
	lo, hi := 0, len(locs)
	for lo < hi {
		mid := (lo + hi) / 2
		switch {
		case pos < locs[mid][0]:
			hi = mid
		case pos >= locs[mid][1]:
			lo = mid + 1
		default:
			return true // locs[mid][0] <= pos < locs[mid][1]
		}
	}
	return false
}

// isFalsePositive is the per-match test. It uses the precomputed per-line locus
// sets (no whole-line regex rescans) plus the genuinely match-local checks
// (file-extension trailing dot, street-name word heuristics).
func (c *streetFPContext) isFalsePositive(match string, matchStart int) bool {
	line := c.line

	// Part of an IP address / version string / code file ref / math expression?
	if overlapsAny(c.ipLocs, matchStart) ||
		overlapsAny(c.verLocs, matchStart) ||
		overlapsAny(c.codeLocs, matchStart) ||
		overlapsAny(c.mathLocs, matchStart) {
		return true
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
// buildContextInfo builds the ContextInfo for a match. posKW/negKW are the
// per-line keyword sets, computed ONCE per line in ValidateContentCtx and passed
// in — the original scanned every positive and negative keyword over the whole
// line for every match, which is O(matches × line length × keywords), the
// dominant cost of the single-long-line DoS. Only the ±50-char before/after
// slice is genuinely per match.
func (v *Validator) buildContextInfo(line string, matchStart, matchLen int, posKW, negKW []string) detector.ContextInfo {
	contextInfo := detector.ContextInfo{
		FullLine:         line,
		PositiveKeywords: posKW,
		NegativeKeywords: negKW,
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

	return contextInfo
}

// keywordsPresent returns the subset of keywords present in line, computed once
// per line (see buildContextInfo).
func (v *Validator) keywordsPresent(line string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsKeyword(line, kw) {
			found = append(found, kw)
		}
	}
	return found
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
