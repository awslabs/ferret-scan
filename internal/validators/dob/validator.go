// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	stdctx "context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"

	"github.com/awslabs/ferret-scan/v2/internal/bytefold"
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

// Label-adjacent shapes (#857). These are standard ways of writing a date of
// birth that the patterns above never matched, so a value directly after
// "Date of Birth:", "DOB" or {"dob": ...} produced no finding of any type and
// stayed in cleartext under --enable-redaction:
//
//   - ISO 8601 date-times, the output of toISOString() and every JSON
//     serializer: reISODate's trailing \b cannot sit between "14" and "T";
//   - year-first numerics with '/' or '.', and unpadded ISO dates (1987-3-14);
//   - month names in any case (MARCH, march, Oracle's DD-MON-YYYY 14-MAR-1987,
//     SAS DATE9 14MAR1987), "Mar.", "Sept", "14th of March", year-first
//     "1987 March 14" and "March 14,1987".
//
// They are an ADMISSION PATH ONLY, consulted after the patterns above: a
// candidate is kept only when an explicit DOB label ends at most maxLabelGap
// separator bytes before it (labelValueStarts), and never when it overlaps a
// candidate the patterns above produced, whose spans, scores and hashes are
// therefore untouched. The gate is what makes widening safe. Without it, on
// 1,726 text files (Go toolchain testdata and this repository's Markdown) these
// shapes added 210 findings, 209 of them ISO timestamps; gated on a DOB keyword
// anywhere on the line -- the model the scoring uses -- the corpus was clean
// but the timestamps beside a DOB key in one JSON object reported at 90-100
// ({"dob": null, "createdAt": "2024-..."}); gated on an adjacent label, both
// added nothing (#857).
//
// Every one of them is ANCHORED (^): it is tried only at the value start right
// after an admitting label, never scanned across the line. Scanned across a
// 1MB line, the three month-name patterns alone cost 1.0s -- twice the five
// original patterns together -- because a case-insensitive alternation of 23
// month names is expanded at every byte.
var (
	// YYYY-MM-DDTHH:MM, with whatever seconds, fraction and offset follow. The
	// span is the DATE PART only, as reISODate already gives for the SQL
	// "1987-03-14 00:00:00": redaction then masks the date and leaves the time.
	reISODateTime = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[Tt]\d{2}:\d{2}`)

	// YYYY/MM/DD, YYYY.MM.DD and the unpadded YYYY-M-D. Both separators are
	// captured and compared in code (RE2 has no backreferences). The padded
	// YYYY-MM-DD stays reISODate's.
	reYearFirstNumeric = regexp.MustCompile(`^(\d{4})([-/.])(\d{1,2})([-/.])(\d{1,2})\b`)

	// Month names in any case, in month-first, day-first and year-first order.
	// Each joiner is whitespace, '-', '/' or (where a digit meets a letter)
	// nothing; before a year a comma takes optional whitespace. Both joiners are
	// captured so joinersAgree can require one joiner per date.
	reMonthFirstAnyCase  = regexp.MustCompile(`(?i)^(` + monthNamePattern + `)(\.?)(\s+|-|/)(\d{1,2})(?:st|nd|rd|th)?(,\s*|\s+|-|/)(\d{4})\b`)
	reDayFirstAnyCase    = regexp.MustCompile(`(?i)^(\d{1,2})(?:st|nd|rd|th)?(\s+of\s+|\s+|-|/|)(` + monthNamePattern + `)(\.?)(,\s*|\s+|-|/|)(\d{4}|\d{2})\b`)
	reYearFirstMonthName = regexp.MustCompile(`(?i)^(\d{4})(\s+|-|/|)(` + monthNamePattern + `)(\.?)(\s+|-|/|)(\d{1,2})(?:st|nd|rd|th)?\b`)
)

// monthNamePattern lists every full month name before its abbreviations, and
// "sept" before "sep": Go's alternation is leftmost-first, so a prefix listed
// first would win and strand the rest of the word.
const monthNamePattern = `january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sept|sep|oct|nov|dec`

// monthMap maps month names/abbreviations to their numeric value.
var monthMap = map[string]int{
	"january": 1, "february": 2, "march": 3, "april": 4,
	"may": 5, "june": 6, "july": 7, "august": 8,
	"september": 9, "october": 10, "november": 11, "december": 12,
	"jan": 1, "feb": 2, "mar": 3, "apr": 4,
	"jun": 6, "jul": 7, "aug": 8,
	"sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}

// dobKeyword is one entry of positiveVocabulary.
type dobKeyword struct {
	word string
	// strong marks an explicit field label. It dominates context-negative
	// keywords in analyzeContext and is what markerBeforeDOBLabel locates.
	strong bool
	// admits marks a label that may admit a label-adjacent shape. The weak
	// keywords "age", "years old" and "birth" do not: "Patient age 39, seen
	// 2024-03-14T09:00:00Z" holds no date of birth.
	admits bool
}

// positiveVocabulary is the ONE list of DOB-positive keywords. Scoring
// (analyzeContext), admission of the label-adjacent shapes (labelValueStarts) and
// the positional disqualifier rule (markerBeforeDOBLabel) all derive from it,
// and all match it with kwmatch's LABEL semantics, so the camelCase key
// "dateOfBirth" is the label "date of birth" in each of them.
//
// The positional rule used to search a separate list of label spellings that
// lacked "d.o.b". "D.O.B.: 03/14/1987, blood sample collected" therefore found
// no label, fell back to "the disqualifier wins", and reported nothing while
// its "DOB:" twin scored 90 (#857) -- the drift #614/#616 removed from
// driverslicense. The order here is the order of the recorded PositiveKeywords.
var positiveVocabulary = []dobKeyword{
	{word: "date of birth", strong: true, admits: true},
	{word: "dob", strong: true, admits: true},
	{word: "born", admits: true},
	{word: "birthday", admits: true},
	{word: "birth date", strong: true, admits: true},
	{word: "birthdate", strong: true, admits: true},
	{word: "d.o.b", strong: true, admits: true},
	{word: "age"},
	{word: "years old"},
	{word: "birth"},
	{word: "date-of-birth", strong: true, admits: true},
	{word: "date_of_birth", strong: true, admits: true},
	{word: "born on", admits: true},
	{word: "patient dob", strong: true, admits: true},
	{word: "applicant dob", strong: true, admits: true},
	{word: "member dob", strong: true, admits: true},
}

// vocabularyWords returns, in vocabulary order, the words whose entry satisfies keep.
func vocabularyWords(keep func(dobKeyword) bool) []string {
	var words []string
	for _, k := range positiveVocabulary {
		if keep(k) {
			words = append(words, k.word)
		}
	}
	return words
}

var (
	// strongLabels are the explicit field labels, in vocabulary order.
	strongLabels = vocabularyWords(func(k dobKeyword) bool { return k.strong })
	// admittingLabels are the labels that may admit a label-adjacent shape.
	admittingLabels = vocabularyWords(func(k dobKeyword) bool { return k.admits })
)

// containsLabelLower is containsKeywordLower with kwmatch's LABEL semantics: a
// multi-word keyword's spaces may also match ZERO separator bytes, so "date of
// birth" finds "dateofbirth" -- the lowercased camelCase key "dateOfBirth", the
// default style of JSON and XML -- and "patient dob" finds "patientdob". Those
// keys used to score 5 (LOW) where their snake_case twins scored 90.
//
// Positive keywords only. A suppressor (negative keyword, disqualifier,
// non-human indicator) keeps containsKeywordLower, because widening a
// suppressor's reach silences real values: with label semantics "created at"
// would match the key "createdAt" and veto a weakly labelled date of birth
// beside it. See kwmatch.ContainsLabel.
func containsLabelLower(lowerText, lowerKeyword string) bool {
	return kwmatch.ContainsLabelLower(lowerText, lowerKeyword)
}

// containsKeywordLower reports whether lowerText contains lowerKeyword as a
// whole word/phrase. BOTH arguments must already be lowercased — every keyword
// list in this package is a lowercase literal, which TestKeywordListsAreLowercase
// enforces, and callers lowercase the line once per line.
//
// ContainsLower rather than Contains: Contains lowercases its text argument on
// every call, and the keyword scan runs once per keyword (79 of them). Passing
// an already-lowercased line makes that redundant work disappear; it measured as
// 80% of this validator's CPU on a dense line.
//
// kwmatch's alphanumeric word model treats '_' as a boundary, so a keyword is
// found inside a snake_case identifier ("date_of_birth", "TEST_VALUE") exactly
// as it is between spaces. Code and config — where those identifiers dominate —
// are primary scan targets for this tool.
func containsKeywordLower(lowerText, lowerKeyword string) bool {
	return kwmatch.ContainsLower(lowerText, lowerKeyword)
}

// Validator implements the detector.Validator interface for detecting
// dates of birth using regex patterns and contextual analysis.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer

	// skipLabelStemPrefilter runs the label-adjacent extractors on every line
	// instead of only on lines holding a label stem (see hasLabelStem). Tests
	// set it to prove the prefilter changes no finding; it is never set in
	// production.
	skipLabelStemPrefilter bool
}

// NewValidator creates and returns a new Validator instance with predefined
// patterns and keywords for detecting dates of birth.
func NewValidator() *Validator {
	v := &Validator{
		// Combined pattern is not used directly; we use the individual compiled
		// patterns above. This field satisfies the struct contract.
		pattern:          `date_of_birth_composite`,
		positiveKeywords: vocabularyWords(func(dobKeyword) bool { return true }),
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

		// Keyword analysis is line-global: analyzeContext and findKeywords read
		// only the lowercased line, so their results are identical for every
		// candidate on it. Each walks the whole line once per keyword (79 of
		// them), so running them per MATCH made the validator quadratic in line
		// length (~4x per doubling: 5.2s at 32KB, 22s at 64KB). Computing them
		// once per line is what keeps a dense line linear.
		//
		// Deferred to the first PLAUSIBLE candidate rather than done up-front, so
		// a line whose only dates are implausible (a changelog of 2024 releases,
		// a column of far-future dates) still pays nothing — the same work the
		// per-match version skipped by `continue`-ing before analyzeContext.
		var (
			lineScanned          bool
			lineContextImpact    float64
			linePositiveKeywords []string
			lineNegativeKeywords []string
			lowerLineCached      string
			lineHasDisqualifier  bool
		)

		for _, cand := range candidates {
			// Structural validation: must be a plausible DOB date
			if !v.isPlausibleDOB(cand) {
				continue
			}

			if !lineScanned {
				// bytefold.Lower, not strings.ToLower: this copy is indexed at
				// validator.go:223 with cand.start+len(cand.text), an offset produced
				// by the date regexes run on the UNFOLDED line. Unicode case mapping
				// is not byte-length-preserving, so a rune such as U+212A KELVIN SIGN
				// (3 bytes -> 1) earlier in the line shifted the two apart.
				//
				// The failure was a FALSE POSITIVE, not a panic, because
				// disqualifierOpensAsideAfter fails OPEN: its own guard
				// (matchEnd >= len(lowerLine), :588) absorbs the overshoot and returns
				// false, so the synthetic-marker rule simply stops firing. Measured on
				// v2.4.5: "date of birth: 03/14/1985 (test)" is correctly suppressed to
				// 0 findings, but with two U+212A ahead of it the same line publishes
				// DATE_OF_BIRTH at 90 HIGH. Every keyword read from this copy is ASCII,
				// so folding only ASCII loses no match.
				lowerLineCached = bytefold.Lower(line)
				lineContextImpact = v.analyzeContext(lowerLineCached)
				linePositiveKeywords = v.findLabels(lowerLineCached, v.positiveKeywords)
				lineNegativeKeywords = v.findKeywords(lowerLineCached, v.negativeKeywords)
				lineHasDisqualifier = hasDisqualifierOnLine(lowerLineCached)
				lineScanned = true
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

			// Context analysis: keyword presence is the primary signal. Computed
			// once per line above; identical for every candidate on this line.
			contextImpact := lineContextImpact

			// Per-match half of the disqualifier rule: a synthetic-data marker
			// opening an aside immediately after THIS value ("DOB: 03/14/1987
			// (test)") means the value is not real, regardless of the line-global
			// verdict. Uses the candidate's own end offset, so it reads only the
			// few bytes after the span.
			if lineHasDisqualifier && cand.start >= 0 &&
				disqualifierOpensAsideAfter(lowerLineCached, cand.start+len(cand.text)) {
				contextImpact = -50.0
			}

			confidence += contextImpact

			// Store keywords found. Also line-global, so reused rather than
			// recomputed per match. The slices are shared across the matches on
			// this line — read-only on every consumer (Match.Clear does not touch
			// them, and nothing downstream appends to or mutates them).
			contextInfo.PositiveKeywords = linePositiveKeywords
			contextInfo.NegativeKeywords = lineNegativeKeywords
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

// dateSpan is the byte range a pattern matched, used to deduplicate candidates.
//
// The key must be the SPAN, not the matched text. Several patterns can match the
// same bytes -- that is the duplicate worth collapsing -- but a text key also
// collapses the same date appearing TWICE on one line at different offsets, which
// are separate findings. Only one was emitted, so redaction rewrote only one:
// "Date of Birth: 1985-03-14 (DOB 1985-03-14)" produced one finding and the
// redacted line read "Date of Birth: ********** (DOB 1985-03-14)", leaving the
// second date in cleartext at rc=0. Same lesson as the duplicate-span dedup fix:
// key on bytes, not on rendered text.
type dateSpan struct {
	start int
	end   int
}

// extractDates finds all date candidates in a line using the pre-compiled patterns.
func (v *Validator) extractDates(line string) []dateCandidate {
	var candidates []dateCandidate
	seen := make(map[dateSpan]bool)

	// ISO dates: YYYY-MM-DD
	for _, loc := range reISODate.FindAllStringSubmatchIndex(line, -1) {
		text := line[loc[0]:loc[1]]
		if seen[dateSpan{loc[0], loc[1]}] {
			continue
		}
		seen[dateSpan{loc[0], loc[1]}] = true
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
		if seen[dateSpan{loc[0], loc[1]}] {
			continue
		}
		seen[dateSpan{loc[0], loc[1]}] = true
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
		if seen[dateSpan{loc[0], loc[1]}] {
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
		seen[dateSpan{loc[0], loc[1]}] = true
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
		if seen[dateSpan{loc[0], loc[1]}] {
			continue
		}
		seen[dateSpan{loc[0], loc[1]}] = true
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
		if seen[dateSpan{loc[0], loc[1]}] {
			continue
		}
		seen[dateSpan{loc[0], loc[1]}] = true
		day, _ := strconv.Atoi(line[loc[2]:loc[3]])
		monthStr := strings.ToLower(line[loc[4]:loc[5]])
		year, _ := strconv.Atoi(line[loc[6]:loc[7]])
		month := monthMap[monthStr]
		candidates = append(candidates, dateCandidate{
			text: text, start: loc[0],
			day: day, month: month, year: year,
		})
	}

	// Label-adjacent shapes, last, so they can never displace a candidate the
	// patterns above produced. Only on a line holding a label stem: every
	// admitting label contains one, and the stem scan costs less than
	// lowercasing the line to look for labels.
	if v.skipLabelStemPrefilter || hasLabelStem(line) {
		candidates = v.appendLabelAdjacent(line, candidates)
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

// AnalyzeContext analyzes the context around a match and returns a confidence
// adjustment. Scoring reads context.FullLine; BeforeText/AfterText are not
// consulted, because for this validator they are always slices of FullLine and
// re-joining them fabricated keywords (see analyzeContext).
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	lowerLine := strings.ToLower(context.FullLine)
	return v.analyzeContext(lowerLine)
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
// dominate over negative keywords on the same line. Derived from
// positiveVocabulary, never listed separately.
var strongPositiveKeywords = func() map[string]bool {
	m := make(map[string]bool, len(strongLabels))
	for _, w := range strongLabels {
		m[w] = true
	}
	return m
}()

// disqualifierKeywords indicate the data is synthetic/fake. These override
// even strong positive DOB labels because "Test DOB: 01/01/2000" is not real PII.
var disqualifierKeywords = map[string]bool{
	"test": true, "example": true, "sample": true,
	"placeholder": true, "fake": true, "mock": true, "demo": true,
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
// hasDisqualifierOnLine reports whether any synthetic-data keyword is present on
// the line at all. This is a per-LINE property, so it is computed once alongside
// the other line scans; the POSITIONAL decisions are made separately by
// markerBeforeDOBLabel (per line) and disqualifierOpensAsideAfter (per match).
func hasDisqualifierOnLine(lowerLine string) bool {
	for kw := range disqualifierKeywords {
		if containsKeywordLower(lowerLine, kw) {
			return true
		}
	}
	return false
}

// markerBeforeDOBLabel is the per-line half of the positional rule: a
// synthetic-data marker before the earliest strong DOB label modifies it.
//
// The label is located with kwmatch.IndexLabelLower over strongLabels -- the
// same vocabulary and the same label semantics that decided hasStrongPositive --
// so a line scored as strongly labelled always has a label to anchor on here.
// It used to search a separate list with strings.Index: that list lacked
// "d.o.b", so a "D.O.B.:" line with "sample" later in it found no label and was
// dropped, and the substring search found "dob" inside "adobe".
func markerBeforeDOBLabel(lowerLine string) bool {
	labelAt := -1
	for _, label := range strongLabels {
		if i := kwmatch.IndexLabelLower(lowerLine, label); i >= 0 && (labelAt < 0 || i < labelAt) {
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
			if containsKeywordLower(prefix, kw) {
				return true
			}
		}
	}

	return false
}

// disqualifierOpensAsideAfter reports whether a synthetic-data keyword is the
// first word of an aside that begins immediately after the value ending at
// matchEnd: "DOB: 03/14/1987 (test)", "dob 3/14/87 -- sample data".
//
// This is the per-MATCH half of the rule, so it takes the match's own end offset
// and reads the LINE -- never a BeforeText/AfterText window. Those windows are
// cut at arbitrary byte offsets, so a fragment can start mid-word and gain a word
// boundary it does not have; a "test" sliced out of "contest" is exactly how a
// genuine "patient date of birth" was dropped before (see analyzeContext).
// Slicing the real line at a real token boundary cannot fabricate a word.
//
// It reads only the handful of bytes after the span, so it does not reintroduce
// per-match whole-line work.
func disqualifierOpensAsideAfter(lowerLine string, matchEnd int) bool {
	if matchEnd < 0 || matchEnd >= len(lowerLine) {
		return false
	}
	after := lowerLine[matchEnd:]
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

// analyzeContext performs keyword-based context analysis.
//
// Keyword presence is evaluated against the LINE, not against a
// BeforeText+line+AfterText concatenation. BeforeText and AfterText are slices
// of the very same line (see ValidateContentCtx), so re-joining them onto the
// line adds no keyword the line does not already contain — it only adds two
// artifacts, both of which changed scoring:
//
//   - The synthetic " " joins let a multi-word keyword match across a junction,
//     e.g. a line ending "...that date" whose head is "of birth..." matched the
//     strong label "date of birth" that appears nowhere in the document,
//     scoring 90/HIGH instead of being dropped.
//   - The 50-byte windows are cut at arbitrary byte offsets, so a fragment can
//     start mid-word and gain a word boundary it does not have. That fired in
//     both directions: a fabricated "dob" boosted a bare date to HIGH, and a
//     fabricated "test" (cut out of "contest") pushed a genuine
//     "patient date of birth: 05/06/1990" to impact -50, dropping the finding
//     entirely — a real DOB missing from the report, and so from redaction.
//
// Both artifacts depended only on where the match happened to sit in the line,
// which is why identical text scored differently at different byte offsets.
// Scanning the line alone is the honest question ("is this keyword in the
// document near this match?") and is what the recorded PositiveKeywords /
// NegativeKeywords on the finding have always reflected.
func (v *Validator) analyzeContext(lowerLine string) float64 {
	var impact float64

	// Check positive keywords first to identify strong DOB signals. Matched as
	// LABELS (containsLabelLower), so "dateOfBirth" counts as "date of birth".
	positiveCount := 0
	hasStrongPositive := false
	for _, kw := range v.positiveKeywords {
		if containsLabelLower(lowerLine, kw) {
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
		if containsKeywordLower(lowerLine, kw) {
			if disqualifierKeywords[kw] {
				hasDisqualifier = true
			} else {
				contextNegativeCount++
			}
		}
	}

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
	// A disqualifier suppresses even a strong positive label -- "Test DOB:
	// 01/01/2000" is synthetic data, not real PII -- but ONLY when it is
	// positioned so that it describes the date.
	//
	// This used to fire on the keyword appearing anywhere on the line, which
	// deleted real records: "Patient DOB: 03/14/1987, blood sample collected at
	// intake" reported nothing while the same line without "sample" reported a
	// finding. "sample collected", "sample submitted" and "specimen sample" are
	// ordinary clinical vocabulary on every lab requisition, and because only
	// reported findings reach the redactor, the DOB stayed in cleartext.
	//
	// The line-global half is decided here (a marker before the label). The
	// per-match half -- a marker opening an aside immediately after THIS value --
	// cannot be a per-line property, so it is applied by the caller via
	// disqualifierOpensAsideAfter. With no strong label the old unconditional
	// behavior is kept: the disqualifier is then the only signal available.
	if hasDisqualifier && (!hasStrongPositive || markerBeforeDOBLabel(lowerLine)) {
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
		if containsKeywordLower(lowerLine, ind) {
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
// lowerText must already be lowercased; see containsKeywordLower for why that
// precondition is load-bearing on this path.
func (v *Validator) findKeywords(lowerText string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsKeywordLower(lowerText, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// findLabels is findKeywords for the POSITIVE keywords, matched with the same
// label semantics analyzeContext scores them with, so the recorded
// PositiveKeywords keep explaining the score ("dateOfBirth" records "date of
// birth").
func (v *Validator) findLabels(lowerText string, labels []string) []string {
	var found []string
	for _, kw := range labels {
		if containsLabelLower(lowerText, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// --- Label-adjacent admission (#857) -----------------------------------------

// maxLabelGap is how many bytes may separate a DOB label from a label-adjacent
// value, all of them isLabelGapByte. Eight covers every key/value and markup
// shape measured in #857: `Date of Birth: `, `{"dob": "`, `| DOB | `,
// `<DateOfBirth>`, a tab.
const maxLabelGap = 8

// maxLabelSpan bounds the length of an admitting label match. The longest label
// is 13 bytes ("applicant dob", "date of birth"); the slack admits runs of
// separators inside it ("date  of  birth"). With maxLabelGap this is the
// 48-byte window before the value that the #857 prototype searched.
const maxLabelSpan = 40

// isLabelGapByte reports whether b may sit between a DOB label and its value.
// Deliberately excludes '-', '/', '.', '_' and letters: "dob-service
// 2024.03.14", "dob_updated_at": "2024-..." and "dobUpdatedAt" name something
// other than a date of birth.
func isLabelGapByte(b byte) bool {
	switch b {
	case ' ', '\t', '"', '\'', ':', '=', '>', '|', '(', '[', '{', ',':
		return true
	}
	return false
}

// isAlnumLower reports whether b is [a-z0-9]: kwmatch's word byte, for text
// that is already ASCII-lowercased.
func isAlnumLower(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// labelValueStarts returns, sorted and without duplicates, every offset of
// lowerLine where a label-adjacent value may begin: right after an admitting
// label that has a word boundary on both sides, past at most maxLabelGap gap
// bytes.
//
// Admission is decided by ADJACENCY, not by a DOB keyword somewhere on the line
// (the model analyzeContext scores with), because that is the only gate #857
// measured as adding nothing: a line-global gate admits the timestamps that sit
// beside a DOB key in the same JSON object ({"dob": null, "createdAt":
// "2024-03-14T10:22:01Z"}) and scores them 90. Scoring is unchanged: an
// admitted value is scored by analyzeContext like any other candidate.
//
// Labels are found with kwmatch's label semantics over admittingLabels, never a
// list or regex written for this gate, so "dateOfBirth" admits exactly as it
// scores (#614/#616).
func labelValueStarts(lowerLine string) []int {
	var starts []int
	for _, label := range admittingLabels {
		for from := 0; from < len(lowerLine); {
			i := kwmatch.IndexLabelLower(lowerLine[from:], label)
			if i < 0 {
				break
			}
			s := from + i
			// kwmatch saw a word boundary at the slice edge; the line must give one too.
			if s == 0 || !isAlnumLower(lowerLine[s-1]) {
				if e := labelEnd(lowerLine, s, label); e > 0 {
					if p := valueStart(lowerLine, e, label); p >= 0 {
						starts = append(starts, p)
					}
				}
			}
			from = s + 1
		}
	}
	if len(starts) < 2 {
		return starts
	}
	sort.Ints(starts)
	out := starts[:1]
	for _, p := range starts[1:] {
		if p != out[len(out)-1] {
			out = append(out, p)
		}
	}
	return out
}

// labelEnd returns the end of the label match that starts at s, or -1 when the
// match runs past maxLabelSpan.
//
// kwmatch reports where a label match STARTS, and with label semantics its
// length varies ("date of birth", "dateOfBirth", "date  of  birth"), so the end
// is recovered from kwmatch itself: the prefix lowerLine[s:x] still holds the
// match at its start exactly when x is at or past the end. That is monotone in x
// because kwmatch's walk is deterministic (each keyword space consumes the
// longest run of separators) and reads no byte past the match, so the end is
// the shortest such prefix, found by binary search.
func labelEnd(lowerLine string, s int, label string) int {
	lo, hi := s+1, s+maxLabelSpan
	if hi > len(lowerLine) {
		hi = len(lowerLine)
	}
	if lo > hi || kwmatch.IndexLabelLower(lowerLine[s:hi], label) != 0 {
		return -1
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		if kwmatch.IndexLabelLower(lowerLine[s:mid], label) == 0 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// valueStart returns where a value may begin after a label ending at e: past
// the label's own closing period when it is an abbreviation ("D.O.B.: "), then
// past at most maxLabelGap gap bytes. -1 when the gap is longer, or when what
// follows cannot open a date (a value starts with a digit or a month name).
func valueStart(lowerLine string, e int, label string) int {
	p := e
	if p < len(lowerLine) && lowerLine[p] == '.' && strings.IndexByte(label, '.') >= 0 {
		p++
	}
	for gap := 0; p < len(lowerLine) && isLabelGapByte(lowerLine[p]); gap++ {
		if gap == maxLabelGap {
			return -1
		}
		p++
	}
	if p >= len(lowerLine) || !isAlnumLower(lowerLine[p]) {
		return -1
	}
	return p
}

// labelStems are the substrings every admitting label contains, so a line
// holding none of them cannot admit a label-adjacent shape. Each stem lies
// inside one word of its labels, and label semantics only flex the SPACES
// between words, so every spelling of a label ("dateOfBirth", "D.O.B.") still
// contains its stem. TestLabelStemsCoverEveryAdmittingLabel pins this.
var labelStems = [...]string{"dob", "d.o.b", "birth", "born"}

// hasLabelStem reports whether line contains a label stem, ASCII
// case-insensitively, without allocating. It runs on every line, so it is the
// whole cost of the label-adjacent path on a line that has no DOB label: the
// lowercased copy and the label search are made only where it passes.
func hasLabelStem(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i] | 0x20 // 'D'/'d' -> 'd', 'B'/'b' -> 'b'; no other byte lands on either
		if c != 'd' && c != 'b' {
			continue
		}
		for _, stem := range labelStems {
			if stem[0] == c && hasPrefixFoldASCII(line[i:], stem) {
				return true
			}
		}
	}
	return false
}

// hasPrefixFoldASCII reports whether s starts with lowerPrefix, folding ASCII
// uppercase in s.
func hasPrefixFoldASCII(s, lowerPrefix string) bool {
	if len(s) < len(lowerPrefix) {
		return false
	}
	for j := 0; j < len(lowerPrefix); j++ {
		b := s[j]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != lowerPrefix[j] {
			return false
		}
	}
	return true
}

// joinerKind classifies a month-name shape's joiner: whitespace (including
// " of " and a comma with optional whitespace), '-', '/', or nothing (0).
func joinerKind(j string) byte {
	switch j {
	case "":
		return 0
	case "-", "/":
		return j[0]
	}
	return ' '
}

// joinersAgree reports whether a month-name shape is written with one joiner:
// "14-MAR-1987", "14 Mar 1987", "14MAR1987" and "Mar. 14, 1987" are; "14-Mar
// 1987" is not. A period after an abbreviation needs whitespace after it
// ("Mar. 14", "14 Mar. 1987"); "14-MAR.-1987" is not a written date.
func joinersAgree(j1, j2 string, dotted bool) bool {
	k := joinerKind(j1)
	if k != joinerKind(j2) {
		return false
	}
	return !dotted || k == ' '
}

// spanSet marks the bytes of a line that a candidate already covers.
type spanSet []uint64

func newSpanSet(n int) spanSet { return make(spanSet, (n+63)/64) }

func (s spanSet) mark(start, end int) {
	for i := start; i < end; i++ {
		s[i>>6] |= 1 << (uint(i) & 63)
	}
}

func (s spanSet) overlaps(start, end int) bool {
	for i := start; i < end; i++ {
		if s[i>>6]&(1<<(uint(i)&63)) != 0 {
			return true
		}
	}
	return false
}

// appendLabelAdjacent appends the label-adjacent shapes (see reISODateTime) in
// line to candidates, which must already hold every candidate the original
// patterns produced.
//
// The patterns are anchored and tried only at the offsets labelValueStarts
// returns, so the cost is per LABEL, not per byte. A value is kept only when it
// overlaps no earlier candidate, so a value the original patterns already
// matched keeps its span, score and hash ("March 14, 1987" stays
// reMonthDDYYYY's) and is never reported twice. The overlap test is a byte set
// rather than a pairwise scan, so a dense line of labelled values stays linear.
func (v *Validator) appendLabelAdjacent(line string, candidates []dateCandidate) []dateCandidate {
	starts := labelValueStarts(bytefold.Lower(line)) // byte-length preserving: offsets stay valid
	if len(starts) == 0 {
		return candidates
	}
	version := -1 // reVersionContext verdict for this line, computed on demand
	var taken spanSet
	for _, p := range starts {
		c, ok := labelAdjacentValueAt(line, p, &version)
		if !ok {
			continue
		}
		end := c.start + len(c.text)
		if taken == nil {
			taken = newSpanSet(len(line))
			for _, prev := range candidates {
				taken.mark(prev.start, prev.start+len(prev.text))
			}
		}
		if taken.overlaps(c.start, end) {
			continue
		}
		taken.mark(c.start, end)
		candidates = append(candidates, c)
	}
	return candidates
}

// labelAdjacentValueAt matches a label-adjacent shape starting exactly at p.
// version caches the line's reVersionContext verdict (-1 = not yet computed).
func labelAdjacentValueAt(line string, p int, version *int) (dateCandidate, bool) {
	rest := line[p:]
	atoi := func(start, end int) int {
		n, _ := strconv.Atoi(rest[start:end])
		return n
	}
	month := func(start, end int) int {
		return monthMap[strings.ToLower(rest[start:end])]
	}
	cand := func(end, day, mon, year int) (dateCandidate, bool) {
		return dateCandidate{text: rest[:end], start: p, day: day, month: mon, year: year}, true
	}

	// Every shape opens with a 4-digit year, a 1-2 digit day or a month name, so
	// the leading bytes pick the patterns worth running; on a line dense with
	// labels and no dates none runs at all.
	digits := 0
	for digits < len(rest) && digits < 5 && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	switch {
	case digits == 1 || digits == 2:
		return dayFirstValueAt(rest, p)
	case digits == 0:
		if len(rest) < 3 || monthMap[strings.ToLower(rest[:3])] == 0 {
			return dateCandidate{}, false
		}
		// Month DD YYYY in any case: groups month, dot, joiner, day, joiner, year.
		loc := reMonthFirstAnyCase.FindStringSubmatchIndex(rest)
		if loc == nil || !joinersAgree(rest[loc[6]:loc[7]], rest[loc[10]:loc[11]], loc[5] > loc[4]) {
			return dateCandidate{}, false
		}
		return cand(loc[1], atoi(loc[8], loc[9]), month(loc[2], loc[3]), atoi(loc[12], loc[13]))
	case digits != 4:
		return dateCandidate{}, false
	}

	// YYYY-MM-DDTHH:MM...: the span is the date part, groups 1-3.
	if loc := reISODateTime.FindStringSubmatchIndex(rest); loc != nil {
		return cand(loc[7], atoi(loc[6], loc[7]), atoi(loc[4], loc[5]), atoi(loc[2], loc[3]))
	}

	// YYYY/MM/DD, YYYY.MM.DD, YYYY-M-D: groups year, sep, month, sep, day.
	if loc := reYearFirstNumeric.FindStringSubmatchIndex(rest); loc != nil {
		sep := rest[loc[4]:loc[5]]
		switch {
		case sep != rest[loc[8]:loc[9]]:
			return dateCandidate{}, false
		case sep == "-" && loc[7]-loc[6] == 2 && loc[11]-loc[10] == 2:
			return dateCandidate{}, false // YYYY-MM-DD is reISODate's
		case sep == ".":
			// A dotted year-first value is shaped like a CalVer release
			// ("2024.03.14"), and a strong label in a package name ("pip install
			// dob==2024.03.14") would otherwise lift it to 90.
			if *version < 0 {
				*version = 0
				if reVersionContext.MatchString(line) {
					*version = 1
				}
			}
			if *version == 1 {
				return dateCandidate{}, false
			}
		}
		return cand(loc[1], atoi(loc[10], loc[11]), atoi(loc[6], loc[7]), atoi(loc[2], loc[3]))
	}

	// YYYY Month DD in any case: groups year, joiner, month, dot, joiner, day.
	if loc := reYearFirstMonthName.FindStringSubmatchIndex(rest); loc != nil {
		if !joinersAgree(rest[loc[4]:loc[5]], rest[loc[10]:loc[11]], loc[9] > loc[8]) {
			return dateCandidate{}, false
		}
		return cand(loc[1], atoi(loc[12], loc[13]), month(loc[6], loc[7]), atoi(loc[2], loc[3]))
	}

	return dateCandidate{}, false
}

// dayFirstValueAt matches DD [of] Month YYYY|YY in any case at the start of
// rest, which begins at offset p of its line. Groups: day, joiner, month, dot,
// joiner, year.
func dayFirstValueAt(rest string, p int) (dateCandidate, bool) {
	loc := reDayFirstAnyCase.FindStringSubmatchIndex(rest)
	if loc == nil || !joinersAgree(rest[loc[4]:loc[5]], rest[loc[10]:loc[11]], loc[9] > loc[8]) {
		return dateCandidate{}, false
	}
	day, _ := strconv.Atoi(rest[loc[2]:loc[3]])
	year, _ := strconv.Atoi(rest[loc[12]:loc[13]])
	if loc[13]-loc[12] == 2 {
		year = resolveTwoDigitYear(year) // Oracle's DD-MON-RR: 14-MAR-87
	}
	return dateCandidate{
		text: rest[:loc[1]], start: p,
		day: day, month: monthMap[strings.ToLower(rest[loc[6]:loc[7]])], year: year,
	}, true
}
