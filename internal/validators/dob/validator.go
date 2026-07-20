// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	stdctx "context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns for date detection.
var (
	// MM/DD/YYYY or DD/MM/YYYY (with /, -, or . as separator; dots are common
	// in forms and European-style documents, e.g. "03.14.1987")
	reNumericDate = regexp.MustCompile(`\b(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})\b`)

	// MM/DD/YY or DD/MM/YY two-digit-year form (e.g. "3/14/87"). Kept as a
	// separate pattern so the century-resolution logic (and its extra
	// ambiguity) only applies to candidates that actually need it. Both
	// separators are captured and compared in extractDates (RE2 has no
	// backreferences); mixed separators like "3/14-87" are rejected there.
	// The \b guards prevent overlap with the 4-digit-year pattern (a
	// trailing \d{2} of \d{4} has no word boundary).
	reNumericDate2Y = regexp.MustCompile(`\b(\d{1,2})([/\-.])(\d{1,2})([/\-.])(\d{2})\b`)

	// YYYY-MM-DD (ISO 8601)
	reISODate = regexp.MustCompile(`\b(\d{4})-(\d{2})-(\d{2})\b`)

	// Month DD, YYYY or Month DD YYYY, with optional ordinal suffix on the day
	// (e.g., "January 15, 1990", "Jan 15 1990", "March 14th, 1987")
	reMonthDDYYYY = regexp.MustCompile(`\b(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b`)

	// DD Month YYYY, with optional ordinal suffix (e.g., "15 January 1990",
	// "14th March 1987")
	reDDMonthYYYY = regexp.MustCompile(`\b(\d{1,2})(?:st|nd|rd|th)?\s+(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec),?\s+(\d{4})\b`)

	// reVersionContext marks lines whose dotted numbers are software versions,
	// not dates. Dotted two-digit-year candidates (x.y.zz) are shaped exactly
	// like semver strings, and a strong DOB keyword elsewhere on the line
	// (e.g. a service named "dob") would short-circuit the negative-keyword
	// pass — so the dotted 2Y extractor refuses candidates on such lines
	// outright rather than relying on confidence scoring.
	reVersionContext = regexp.MustCompile(`(?i)\b(?:version|build|release|upgrade|patch|changelog|semver|pip|npm|v\d+\.\d+)\b|==\d`)
)

// monthMap maps month names/abbreviations to their numeric value.
var monthMap = map[string]int{
	"january": 1, "february": 2, "march": 3, "april": 4,
	"may": 5, "june": 6, "july": 7, "august": 8,
	"september": 9, "october": 10, "november": 11, "december": 12,
	"jan": 1, "feb": 2, "mar": 3, "apr": 4,
	"jun": 6, "jul": 7, "aug": 8,
	"sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively.
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

// isWordByte reports whether b is a word character ([a-z0-9_]) for keyword
// boundary detection. text is already lowercased by the caller.
func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// Validator implements the detector.Validator interface for detecting
// dates of birth using regex patterns and contextual analysis.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new Validator instance with predefined
// patterns and keywords for detecting dates of birth.
func NewValidator() *Validator {
	v := &Validator{
		// Combined pattern is not used directly; we use the individual compiled
		// patterns above. This field satisfies the struct contract.
		pattern: `date_of_birth_composite`,
		positiveKeywords: []string{
			"date of birth", "dob", "born", "birthday", "birth date",
			"birthdate", "d.o.b", "age", "years old", "birth",
			"date-of-birth", "date_of_birth", "born on", "patient dob",
			"applicant dob", "member dob",
		},
		negativeKeywords: []string{
			"created", "modified", "expires", "expiry", "due", "deadline",
			"meeting", "published", "released", "updated", "version", "build",
			"compiled", "deployed", "installed", "accessed", "logged",
			"timestamp", "last modified", "created at", "updated at",
			"file date", "upload date", "download date", "start date",
			"end date", "effective date", "issue date", "event date",
			"schedule", "appointment", "calendar", "copyright",
			"test", "example", "sample", "placeholder", "fake", "mock", "demo",
		},
	}
	// The regex field holds a sentinel for struct completeness; actual matching
	// uses the package-level compiled patterns above.
	v.regex = reNumericDate
	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// dateCandidate holds a parsed date candidate extracted from text.
type dateCandidate struct {
	text  string
	start int
	day   int
	month int
	year  int
}

// ValidateContent validates content for dates of birth.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements cooperative-cancellation scanning for DOB.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		candidates := v.extractDates(line)
		if len(candidates) == 0 {
			continue
		}

		lowerLine := strings.ToLower(line)

		for _, cand := range candidates {
			// Structural validation: must be a plausible DOB date
			if !v.isPlausibleDOB(cand) {
				continue
			}

			// Calculate base confidence (very low without keywords)
			confidence, checks := v.CalculateConfidence(cand.text)

			// Build context info
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}
			matchIndex := cand.start
			if matchIndex >= 0 {
				start := matchIndex - 50
				if start < 0 {
					start = 0
				}
				end := matchIndex + len(cand.text) + 50
				if end > len(line) {
					end = len(line)
				}
				contextInfo.BeforeText = line[start:matchIndex]
				contextInfo.AfterText = line[matchIndex+len(cand.text) : end]
			}

			// Context analysis: keyword presence is the primary signal
			contextImpact := v.analyzeContext(lowerLine, contextInfo)
			confidence += contextImpact

			// Store keywords found
			contextInfo.PositiveKeywords = v.findKeywords(lowerLine, v.positiveKeywords)
			contextInfo.NegativeKeywords = v.findKeywords(lowerLine, v.negativeKeywords)
			contextInfo.ConfidenceImpact = contextImpact

			// Cap and floor
			if confidence > 100 {
				confidence = 100
			}
			if confidence < 0 {
				confidence = 0
			}

			// Skip matches that are too low confidence to surface
			if confidence <= 0 {
				continue
			}

			matches = append(matches, detector.Match{
				Text:       cand.text,
				LineNumber: lineNum + 1,
				Type:       "DATE_OF_BIRTH",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "dob",
				Context:    contextInfo,
				Metadata: map[string]any{
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}
	}

	return matches, nil
}

// extractDates finds all date candidates in a line using the pre-compiled patterns.
func (v *Validator) extractDates(line string) []dateCandidate {
	var candidates []dateCandidate
	seen := make(map[string]bool)

	// ISO dates: YYYY-MM-DD
	for _, loc := range reISODate.FindAllStringSubmatchIndex(line, -1) {
		text := line[loc[0]:loc[1]]
		if seen[text] {
			continue
		}
		seen[text] = true
		year, _ := strconv.Atoi(line[loc[2]:loc[3]])
		month, _ := strconv.Atoi(line[loc[4]:loc[5]])
		day, _ := strconv.Atoi(line[loc[6]:loc[7]])
		candidates = append(candidates, dateCandidate{
			text: text, start: loc[0],
			day: day, month: month, year: year,
		})
	}

	// Numeric dates: MM/DD/YYYY or DD/MM/YYYY
	for _, loc := range reNumericDate.FindAllStringSubmatchIndex(line, -1) {
		text := line[loc[0]:loc[1]]
		if seen[text] {
			continue
		}
		seen[text] = true
		part1, _ := strconv.Atoi(line[loc[2]:loc[3]])
		part2, _ := strconv.Atoi(line[loc[4]:loc[5]])
		year, _ := strconv.Atoi(line[loc[6]:loc[7]])

		// Attempt MM/DD/YYYY interpretation first, then DD/MM/YYYY
		day, month := v.resolveNumericDate(part1, part2)
		if day == 0 && month == 0 {
			continue
		}
		candidates = append(candidates, dateCandidate{
			text: text, start: loc[0],
			day: day, month: month, year: year,
		})
	}

	// Numeric dates with two-digit years: MM/DD/YY or DD/MM/YY
	for _, loc := range reNumericDate2Y.FindAllStringSubmatchIndex(line, -1) {
		text := line[loc[0]:loc[1]]
		if seen[text] {
			continue
		}
		// Mixed separators ("3/14-87") are not a date; require both to match.
		sep := line[loc[4]:loc[5]]
		if sep != line[loc[8]:loc[9]] {
			continue
		}
		// Dotted two-digit-year candidates are shaped like semver versions
		// ("2.14.87"); refuse them on version-context lines (see reVersionContext).
		if sep == "." && reVersionContext.MatchString(line) {
			continue
		}
		seen[text] = true
		part1, _ := strconv.Atoi(line[loc[2]:loc[3]])
		part2, _ := strconv.Atoi(line[loc[6]:loc[7]])
		yy, _ := strconv.Atoi(line[loc[10]:loc[11]])

		day, month := v.resolveNumericDate(part1, part2)
		if day == 0 && month == 0 {
			continue
		}
		candidates = append(candidates, dateCandidate{
			text: text, start: loc[0],
			day: day, month: month, year: resolveTwoDigitYear(yy),
		})
	}

	// Month DD, YYYY
	for _, loc := range reMonthDDYYYY.FindAllStringSubmatchIndex(line, -1) {
		text := line[loc[0]:loc[1]]
		if seen[text] {
			continue
		}
		seen[text] = true
		monthStr := strings.ToLower(line[loc[2]:loc[3]])
		day, _ := strconv.Atoi(line[loc[4]:loc[5]])
		year, _ := strconv.Atoi(line[loc[6]:loc[7]])
		month := monthMap[monthStr]
		candidates = append(candidates, dateCandidate{
			text: text, start: loc[0],
			day: day, month: month, year: year,
		})
	}

	// DD Month YYYY
	for _, loc := range reDDMonthYYYY.FindAllStringSubmatchIndex(line, -1) {
		text := line[loc[0]:loc[1]]
		if seen[text] {
			continue
		}
		seen[text] = true
		day, _ := strconv.Atoi(line[loc[2]:loc[3]])
		monthStr := strings.ToLower(line[loc[4]:loc[5]])
		year, _ := strconv.Atoi(line[loc[6]:loc[7]])
		month := monthMap[monthStr]
		candidates = append(candidates, dateCandidate{
			text: text, start: loc[0],
			day: day, month: month, year: year,
		})
	}

	return candidates
}

// resolveTwoDigitYear maps a two-digit year to a full year using the standard
// sliding-window rule: values up to the current two-digit year are 20xx,
// values above it are 19xx (in 2026: 14 → 2014, 87 → 1987). A DOB can't be in
// the future, so the pivot is the current year rather than a fixed cutoff.
func resolveTwoDigitYear(yy int) int {
	pivot := time.Now().Year() % 100
	if yy <= pivot {
		return 2000 + yy
	}
	return 1900 + yy
}

// resolveNumericDate resolves ambiguous MM/DD vs DD/MM numeric dates.
// Returns (day, month). Returns (0,0) if the date is invalid.
func (v *Validator) resolveNumericDate(part1, part2 int) (int, int) {
	// If part1 > 12, it must be a day (DD/MM format)
	if part1 > 12 && part1 <= 31 && part2 >= 1 && part2 <= 12 {
		return part1, part2
	}
	// If part2 > 12, part1 must be a month (MM/DD format)
	if part2 > 12 && part2 <= 31 && part1 >= 1 && part1 <= 12 {
		return part2, part1
	}
	// Both could be month or day — prefer MM/DD (US convention common in PII)
	if part1 >= 1 && part1 <= 12 && part2 >= 1 && part2 <= 31 {
		return part2, part1
	}
	return 0, 0
}

// isPlausibleDOB checks if a date could plausibly be a date of birth.
func (v *Validator) isPlausibleDOB(c dateCandidate) bool {
	// Basic calendar validity
	if c.month < 1 || c.month > 12 {
		return false
	}
	if c.day < 1 || c.day > 31 {
		return false
	}

	// Month-specific day limits (simplified — no leap year nuance needed for PII)
	daysInMonth := []int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if c.day > daysInMonth[c.month] {
		return false
	}

	// Year range: a living human's DOB should be between 1900 and the current
	// year (covers elderly and recent births without hardcoding a ceiling).
	if c.year < 1900 || c.year > time.Now().Year() {
		return false
	}

	return true
}

// CalculateConfidence returns the base structural confidence for a date match.
// Without keyword context, dates start at a very low confidence because most
// dates are NOT dates of birth.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_date":     true,
		"plausible_year": true,
		"not_test":       true,
	}

	// Base confidence is intentionally very low: a date by itself is almost
	// certainly not a DOB. Context keywords are the primary signal.
	confidence := 15.0

	return confidence, checks
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	lowerLine := strings.ToLower(context.FullLine)
	return v.analyzeContext(lowerLine, context)
}

// nonHumanIndicators are words that indicate a non-human subject is being
// described, reducing the signal of weak DOB-positive keywords like "born",
// "age", and "birth".
var nonHumanIndicators = []string{
	"project", "company", "idea", "server", "building", "wine", "team",
	"system", "tool", "framework", "software", "tradition", "service",
	"organization", "product", "brand", "initiative", "movement",
	"control", "minimum", "policy", "certificate", "bottled",
}

// strongPositiveKeywords are explicit PII field labels that should always
// dominate over negative keywords on the same line.
var strongPositiveKeywords = map[string]bool{
	"date of birth": true, "dob": true, "d.o.b": true,
	"date-of-birth": true, "date_of_birth": true,
	"patient dob": true, "applicant dob": true, "member dob": true,
	"birthdate": true, "birth date": true,
}

// disqualifierKeywords indicate the data is synthetic/fake. These override
// even strong positive DOB labels because "Test DOB: 01/01/2000" is not real PII.
var disqualifierKeywords = map[string]bool{
	"test": true, "example": true, "sample": true,
	"placeholder": true, "fake": true, "mock": true, "demo": true,
}

// analyzeContext performs keyword-based context analysis.
func (v *Validator) analyzeContext(lowerLine string, context detector.ContextInfo) float64 {
	var impact float64

	// Full text to scan for keywords: combine available context
	fullContext := lowerLine
	if context.BeforeText != "" || context.AfterText != "" {
		fullContext = strings.ToLower(context.BeforeText) + " " + lowerLine + " " + strings.ToLower(context.AfterText)
	}

	// Check positive keywords first to identify strong DOB signals
	positiveCount := 0
	hasStrongPositive := false
	for _, kw := range v.positiveKeywords {
		if containsKeyword(fullContext, kw) {
			positiveCount++
			if strongPositiveKeywords[kw] {
				hasStrongPositive = true
			}
		}
	}

	// Check negative keywords, separating disqualifiers from context negatives
	contextNegativeCount := 0
	hasDisqualifier := false
	for _, kw := range v.negativeKeywords {
		if containsKeyword(fullContext, kw) {
			if disqualifierKeywords[kw] {
				hasDisqualifier = true
			} else {
				contextNegativeCount++
			}
		}
	}

	// Disqualifiers (test/example/fake/mock) ALWAYS suppress, even with strong
	// positive keywords. "Test DOB: 01/01/2000" is synthetic data, not real PII.
	if hasDisqualifier {
		impact -= 50.0
		return impact
	}

	// Strong positive keywords dominate over context-negative keywords.
	// This prevents "DOB: 01/15/1990" from being suppressed just because
	// "schedule" or "updated" appears elsewhere on the same line.
	if hasStrongPositive {
		impact += 75.0 // base 15 + 75 = 90
		return impact
	}

	// No strong positive: context-negative keywords dominate
	if contextNegativeCount > 0 {
		impact -= float64(contextNegativeCount) * 20.0
		if impact < -50 {
			impact = -50
		}
		return impact
	}

	// No negatives found — evaluate weak positives
	if positiveCount == 0 {
		// No positive keywords — date is almost certainly not a DOB.
		return -10.0
	}

	// Weak positive keywords present (born, birthday, age, years old, birth).
	// Check for non-human subject indicators that reduce their signal.
	hasNonHuman := false
	for _, ind := range nonHumanIndicators {
		if containsKeyword(fullContext, ind) {
			hasNonHuman = true
			break
		}
	}

	if hasNonHuman {
		// Non-human subject detected with only weak keywords — suppress.
		// "The project was born on..." or "Server age: 5 years" are not DOBs.
		return -10.0
	}

	// Weak positive keywords with human context
	if positiveCount >= 2 {
		impact += 70.0 // Multiple weaker keywords → ~85
	} else {
		impact += 55.0 // Single weaker keyword (e.g., "born", "birthday") → ~70
	}

	return impact
}

// findKeywords returns all keywords from the list that appear in the text.
func (v *Validator) findKeywords(lowerText string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsKeyword(lowerText, kw) {
			found = append(found, kw)
		}
	}
	return found
}
