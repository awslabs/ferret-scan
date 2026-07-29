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
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
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
//
// ModeAlnum treats '_' as a word boundary, so a keyword is found inside a
// snake_case identifier ("customer_ssn", "TEST_VALUE") exactly as it is
// between spaces. Code and config — where those identifiers dominate — are
// primary scan targets for this tool.
func containsKeyword(text, keyword string) bool {
	return kwmatch.Contains(text, keyword)
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

		// Keyword tallies for this line, computed once and shared by every
		// candidate date on it. See dobLineKeywords for the measured cost of not
		// doing this.
		lineKW := v.newDOBLineKeywords(lowerLine)

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
			contextImpact := v.analyzeContextWith(lowerLine, contextInfo, lineKW)
			confidence += contextImpact

			// Store keywords found (per-line invariant, already tallied above).
			contextInfo.PositiveKeywords = lineKW.positives
			contextInfo.NegativeKeywords = lineKW.negatives
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

// dobLabelForms are the label spellings that mark a value as a date of birth.
// Used to decide whether a disqualifier modifies the label (see
// disqualifierModifiesLabel); the earliest occurrence wins, so order is for
// readability only.
var dobLabelForms = []string{
	"date of birth", "date-of-birth", "date_of_birth",
	"patient dob", "applicant dob", "member dob",
	"birthdate", "birth date", "dob",
}

// disqualifierModifiesLabel reports whether a synthetic-data keyword is
// positioned so that it describes THE DATE, rather than merely appearing
// somewhere in the same context.
//
// Two positions qualify:
//
//   - BEFORE the DOB label. Synthetic fixtures attach the marker to the label:
//     "Test DOB: 01/01/2000", "sample patient dob 3/14/87", "example date of
//     birth". Real records put the label first.
//
//   - As the FIRST WORD of an aside immediately after the value, separated only
//     by punctuation: "DOB: 03/14/1987 (test)", "dob 3/14/87 -- sample data".
//
// A clause with its own subject after the value does not qualify, which is what
// keeps "Patient DOB: 03/14/1987, blood sample collected at intake" reported.
//
// This is the same rule driverslicense uses. It was chosen there over two
// alternatives that were measured and rejected: a plain distance threshold (the
// real and synthetic classes interleave, so no cutoff separates them) and a
// compound-noun list of clinical terms (overfit -- it scored 6/12 on held-out
// phrasings, and every miss was a REAL record classified as synthetic).
func disqualifierModifiesLabel(lowerLine string, context detector.ContextInfo) bool {
	labelAt := -1
	for _, form := range dobLabelForms {
		if i := strings.Index(lowerLine, form); i >= 0 && (labelAt < 0 || i < labelAt) {
			labelAt = i
		}
	}

	// No recognizable label in the line: keep the old conservative behavior.
	if labelAt < 0 {
		return true
	}

	// A disqualifier anywhere before the label modifies it.
	if labelAt > 0 {
		prefix := lowerLine[:labelAt]
		for kw := range disqualifierKeywords {
			if containsKeyword(prefix, kw) {
				return true
			}
		}
	}

	// A disqualifier opening an aside right after the value is an apposition on
	// the value. AfterText is the post-match window the caller already computed,
	// so this needs no rescan of the line.
	after := strings.ToLower(context.AfterText)
	j := 0
	for j < len(after) && strings.IndexByte(" \t-/(<[|,;:#>", after[j]) >= 0 {
		j++
	}
	word := after[j:]
	end := 0
	for end < len(word) && isWordByteASCII(word[end]) {
		end++
	}
	return disqualifierKeywords[word[:end]]
}

// isWordByteASCII reports whether b is a letter, digit or underscore.
func isWordByteASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

// dobLineKeywords holds the keyword tallies for one line. Every field is a pure
// function of the line, so they are computed ONCE per line and reused for every
// candidate date on it.
//
// They used to be recomputed inside analyzeContext for every candidate, and each
// recomputation scanned the whole line against ~40 keywords. On a dense line that
// is O(candidates x line length x keywords) -- the single-long-line
// CPU-exhaustion shape. Measured before the hoist, on one line of distinct dates:
// 250 -> 0.14s, 500 -> 0.30s, 1000 -> 0.86s, 2000 -> 3.34s, 4000 -> 15.68s, i.e.
// ~4x per doubling.
//
// BeforeText and AfterText are windows INSIDE the same line, so the old
// "fullContext" (BeforeText + line + AfterText) contained no token the line did
// not already contain. Scanning the line alone is therefore equivalent, not an
// approximation.
type dobLineKeywords struct {
	positiveCount        int
	hasStrongPositive    bool
	contextNegativeCount int
	hasDisqualifier      bool
	hasNonHuman          bool
	positives            []string
	negatives            []string
}

// newDOBLineKeywords tallies every keyword class for the line in a single pass
// over the keyword lists.
func (v *Validator) newDOBLineKeywords(lowerLine string) *dobLineKeywords {
	lk := &dobLineKeywords{}

	for _, kw := range v.positiveKeywords {
		if containsKeyword(lowerLine, kw) {
			lk.positiveCount++
			lk.positives = append(lk.positives, kw)
			if strongPositiveKeywords[kw] {
				lk.hasStrongPositive = true
			}
		}
	}
	for _, kw := range v.negativeKeywords {
		if containsKeyword(lowerLine, kw) {
			lk.negatives = append(lk.negatives, kw)
			if disqualifierKeywords[kw] {
				lk.hasDisqualifier = true
			} else {
				lk.contextNegativeCount++
			}
		}
	}
	for _, ind := range nonHumanIndicators {
		if containsKeyword(lowerLine, ind) {
			lk.hasNonHuman = true
			break
		}
	}
	return lk
}

// analyzeContext performs keyword-based context analysis. Retained with its
// original signature for external callers and tests; it builds the per-line
// keyword cache and delegates.
func (v *Validator) analyzeContext(lowerLine string, context detector.ContextInfo) float64 {
	return v.analyzeContextWith(lowerLine, context, v.newDOBLineKeywords(lowerLine))
}

// analyzeContextWith is analyzeContext with the per-line keyword tallies supplied
// by the caller, so a line with many candidate dates pays for the keyword scan
// once rather than once per candidate.
func (v *Validator) analyzeContextWith(lowerLine string, context detector.ContextInfo, lk *dobLineKeywords) float64 {
	var impact float64

	positiveCount := lk.positiveCount
	hasStrongPositive := lk.hasStrongPositive
	contextNegativeCount := lk.contextNegativeCount
	hasDisqualifier := lk.hasDisqualifier

	// Disqualifiers (test/example/fake/mock) suppress even a strong positive
	// label, because "Test DOB: 01/01/2000" is synthetic data rather than real
	// PII -- but only when the disqualifier actually MODIFIES the label.
	//
	// It used to fire on the disqualifier appearing anywhere in the context, with
	// no positional bound at all, which deleted real records:
	//
	//   "Patient DOB: 03/14/1987, blood sample collected at intake"  -> nothing
	//   "Patient DOB: 03/14/1987, blood collected at intake"         -> reported
	//
	// "sample collected", "sample submitted" and "specimen sample" are ordinary
	// clinical vocabulary that co-occurs with a patient's date of birth on every
	// lab requisition. Because only reported findings are handed to the redactor,
	// and a file with no findings has no redacted output written at all, the DOB
	// stayed in cleartext.
	//
	// The positional rule is the one already used for driver's licences: the
	// disqualifier counts when it precedes the DOB label ("Test DOB:", "sample
	// patient dob") or opens an aside immediately after the value ("DOB:
	// 03/14/1987 (test)"). A disqualifier sitting in a following clause with its
	// own subject does not. When there is NO strong positive label the old
	// behavior is kept: the disqualifier is then the best signal available.
	if hasDisqualifier && (!hasStrongPositive || disqualifierModifiesLabel(lowerLine, context)) {
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
	// Check for non-human subject indicators that reduce their signal
	// (per-line invariant, computed once in newDOBLineKeywords).
	if lk.hasNonHuman {
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
