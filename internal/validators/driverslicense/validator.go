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
	"github.com/awslabs/ferret-scan/v2/internal/tabular"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
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

	// New Jersey: 1 letter + 14 digits (15 characters total — extremely distinctive length)
	reNewJerseyDL = regexp.MustCompile(`\b[A-Za-z]\d{14}\b`)

	// Wisconsin: 1 letter + 13 digits (14 characters total — very distinctive length)
	reWisconsinDL = regexp.MustCompile(`\b[A-Za-z]\d{13}\b`)

	// Illinois: 1 letter + 11 digits
	reIllinoisDL = regexp.MustCompile(`\b[A-Za-z]\d{11}\b`)

	// Ohio: 2 letters + 6 digits
	reOhioDL = regexp.MustCompile(`\b[A-Za-z]{2}\d{6}\b`)

	// Composite pattern that matches ANY of the above formats in a single pass.
	// Used by ValidateContentCtx for the initial line scan; hits are then
	// classified into the specific state format in classifyMatch. Ordered
	// longest-first so the regex engine greedily matches the full token
	// without a shorter prefix stealing the match.
	reAnyDL = regexp.MustCompile(
		`\b(?:` +
			`[A-Za-z]{2}\d{6}` + // Ohio (2 letters + 6 digits)
			`|[A-Za-z]\d{14}` + // New Jersey (1 letter + 14 digits)
			`|[A-Za-z]\d{13}` + // Wisconsin (1 letter + 13 digits)
			`|[A-Za-z]\d{12}` + // Florida/Michigan (1 letter + 12 digits)
			`|[A-Za-z]\d{11}` + // Illinois (1 letter + 11 digits)
			`|[A-Za-z]\d{7}` + // California (1 letter + 7 digits)
			`|\d{9}` + // New York/Georgia (9 digits)
			`|\d{8}` + // Texas/Pennsylvania (8 digits)
			`)\b`)

	// State name patterns for context detection
	reStateName = regexp.MustCompile(`(?i)\b(?:california|texas|florida|new york|new jersey|pennsylvania|illinois|ohio|georgia|north carolina|michigan|wisconsin|CA|TX|FL|NY|NJ|PA|IL|OH|GA|NC|MI|WI)\b`)

	// Licenses are often printed with separators (e.g. "D123-4567-8901",
	// "123 456 789"). Candidates are normalized (separators stripped) and must
	// classify into one of the state formats above; see the shape guards in
	// evaluateSeparatedCandidate for the SSN/date collisions normalization
	// would otherwise introduce.
	reSeparatedDL = regexp.MustCompile(`\b[A-Za-z]{0,2}\d{1,4}(?:[- ]\d{1,4}){1,4}\b`)

	// The canonical SSN grouping (3-2-4). A dashed 9-digit token in this exact
	// grouping is overwhelmingly an SSN, never a printed DL — always rejected.
	reSSNShape = regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively. Word-boundary-aware matching prevents false positives from
// substring matches (e.g. "dl" inside "handle").
//
// ModeAlnum treats '_' as a word boundary, so a keyword is found inside a
// snake_case identifier ("customer_ssn", "TEST_VALUE") exactly as it is
// between spaces. Code and config — where those identifiers dominate — are
// primary scan targets for this tool.
func containsKeyword(text, keyword string) bool {
	return kwmatch.Contains(text, keyword)
}

// containsLabel is containsKeyword for a keyword that LABELS the value beside it, letting its
// spaces match zero separators so "drivers license" also finds "driversLicense" — the
// camelCase spelling JSON and ORM exports use (#372).
//
// Only the POSITIVE keyword gates use it. strongSuppressKeywords and negativeKeywords keep
// containsKeyword, because widening a suppressor's reach silences real values rather than
// finding more of them. See kwmatch.ContainsLabel.
func containsLabel(text, keyword string) bool {
	return kwmatch.ContainsLabel(text, keyword)
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
			// "address" is intentionally NOT a negative: a driver's-license record
			// almost always lists the holder's physical address on the same line,
			// so it hard-suppressed real DLs. "IP address" is still caught by the
			// "ip" keyword; a bare address line never reaches scoring because the
			// positive-keyword gate (lineHasPositiveKeyword) requires DL context.
			"ip", "port", "version", "build", "hash",
			"uuid", "guid", "isbn", "sku", "model",
			// Non-DL license/permit contexts (common false positive sources)
			"software", "fishing", "hunting", "gun", "concealed",
			"business", "plate", "immigration", "construction", "key",
			"expires", "expiry", "renew", "mailed", "activation",
			"work permit",
		},
		stateKeywords: []string{
			"california", "texas", "florida", "new york", "new jersey",
			"pennsylvania", "illinois", "ohio", "georgia", "north carolina",
			"michigan", "wisconsin",
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

	// In a CSV export the label IS the header row, one or more lines above the value,
	// and the keyword search stops at the newline. Measured: "Driver's License Number:
	// D12345678901234" scores 80, the identical value in a drivers_license COLUMN scores
	// nothing, and an unreported value is never handed to the redactor — the redacted
	// copy of that export still held the licence number in cleartext.
	//
	// tabular.Analyze is conservative (>=3 fields, consistent delimiter, word-like
	// header row), so a non-table document yields a nil table and behaviour is
	// unchanged. Analyzed ONCE per document.
	table := tabular.Analyze(content)

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		// Quick pre-check: does the line contain any DL-related keyword?
		// Because DL formats are extremely ambiguous (8 digits, 9 digits, etc.),
		// we ONLY scan lines that have at least one positive keyword present.
		//
		// A table data row is admitted when the HEADER ROW carries the keyword, because
		// in a CSV export that is where the label lives. Without this arm the row was
		// never scanned at all, so the per-column header boost below could not run and
		// a drivers_license column reported nothing — while the identical value written
		// inline as "Driver's License Number: D12345678901234" scores 80. Measured base
		// confidence for that value is 5 and the header contributes 55, so the value is
		// well clear of the emit threshold once the row is scanned.
		//
		// Admission is per ROW and deliberately permissive; whether a given candidate
		// actually sits in a labelled column is decided per COLUMN by impactForColumn,
		// so a notes column does not inherit the licence column's standing.
		// A bare field LABEL on the line above is context for this line's value.
		//
		// DRIVERS_LICENSE is label-gated — a licence has no checksum, and the formats are
		// ambiguous enough that this validator refuses to scan a line with no keyword at
		// all — so a two-line form
		//
		//	Driver's License Number
		//	D12345678901234
		//
		// reported nothing and the value was left in cleartext. Gated on
		// kwmatch.LooksLikeFieldLabel rather than on a keyword being present: measured,
		// "Please renew your driver's license soon." is the same length, carries the
		// keyword and has no digits, and the line after it is not a licence. Bounded to
		// exactly one line back, like the secrets validator's AWS-key window.
		labelAbove := ""
		if lineNum > 0 && kwmatch.LooksLikeFieldLabel(lines[lineNum-1], v.positiveKeywords) {
			labelAbove = lines[lineNum-1]
		}

		lineKeyworded := v.lineHasPositiveKeyword(line) || labelAbove != ""
		if !lineKeyworded && !v.tableHeaderHasPositiveKeyword(table, lineNum) {
			continue
		}

		idxMatches := v.regex.FindAllStringIndex(line, -1)
		sepMatches := v.separatedCandidates(line, idxMatches)
		if len(idxMatches) == 0 && len(sepMatches) == 0 {
			continue
		}

		// Per-line invariants, hoisted out of the per-match loop. AnalyzeContext
		// and findKeywordsOnLine scan only the whole line (they ignore the match
		// position), so their results are identical for every match on this line.
		// Computing them once per line instead of once per match is what keeps
		// scanning O(line length) rather than O(matches × line length) — the
		// latter is a single-long-line CPU-exhaustion DoS. See the timing test.
		//
		// The test/placeholder suppression is the one rule with a per-match part.
		// Its line-global half (a marker positioned before the DL label) is still
		// a per-line invariant and is evaluated inside AnalyzeContext below; its
		// per-match half (a marker opening an aside right after THIS value) is
		// checked in emit via markerOpensAsideAfter, which reads only the handful
		// of bytes after the span and so does not reintroduce the quadratic.
		lineImpact := v.AnalyzeContext("", detector.ContextInfo{FullLine: line})

		// Column bounds for this row, plus a memo of the per-header impact.
		//
		// The header is scored with the SAME keyword logic as a line, so a
		// drivers_license column carries exactly the weight the inline label would.
		// It is resolved per MATCH because the header varies along the row — folding
		// the row's headers together would let one column vouch for another's values.
		// The memo keys on the header cell, of which there are only as many as there
		// are columns, and each is a short string: this cannot reintroduce the
		// per-match whole-line scan that made this validator quadratic before.
		var lineBounds *tabular.LineBounds
		if table.IsTable() && lineNum != table.HeaderLine() {
			lineBounds = table.Bounds(line)
		}
		headerImpact := make(map[string]float64, 4)
		impactForColumn := func(off int) float64 {
			if lineBounds == nil {
				return 0
			}
			h := table.HeaderAt(lineBounds, off)
			if h == "" {
				return 0
			}
			if v, ok := headerImpact[h]; ok {
				return v
			}
			imp := v.AnalyzeContext("", detector.ContextInfo{FullLine: h})
			if imp < 0 {
				// A header only ever ADDS the standing an inline label would. It must
				// not penalise: a column named "notes" is not evidence against the
				// value in the drivers_license column beside it.
				imp = 0
			}
			headerImpact[h] = imp
			return imp
		}
		// Positives use the label-flexible matcher so a camelCase or snake_case label is REPORTED as
		// supporting evidence; negatives keep the strict one, because widening a suppressor silences
		// real values. See findLabelsOnLine.
		linePositiveKeywords := v.findLabelsOnLine(line, v.positiveKeywords)
		lineNegativeKeywords := v.findKeywordsOnLine(line, v.negativeKeywords)

		// emit scores one candidate and appends a match if it survives. text is
		// the span reported (and redacted); classifyText is the separator-free
		// form used for format classification and structural checks. For
		// contiguous matches they are the same string.
		emit := func(spanStart, spanEnd int, text, classifyText string) {
			format := v.classifyMatch(classifyText)
			if format == "" {
				return
			}

			// Calculate base confidence from structural validation
			confidence, checks := v.CalculateConfidence(classifyText)

			// Build context info
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}
			start := spanStart - 50
			if start < 0 {
				start = 0
			}
			end := spanEnd + 50
			if end > len(line) {
				end = len(line)
			}
			contextInfo.BeforeText = line[start:spanStart]
			contextInfo.AfterText = line[spanEnd:end]

			// Analyze context for keyword-based adjustment (per-line invariant)
			contextImpact := lineImpact

			// Per-match half of the test/placeholder rule: a marker opening an
			// aside immediately after THIS span ("D1234567 (placeholder)",
			// "D1234567 // sample data") is an apposition on the value, so the
			// value is not a real licence. Uses the span offset the caller
			// already has, so no rescan of the line.
			if markerOpensAsideAfter(line, spanEnd) {
				contextImpact = -20
			}

			confidence += contextImpact

			// A row admitted ONLY by its header row must have the label in the
			// candidate's OWN column. Without this the permissive row-level admission
			// leaks across columns: measured on a
			// name,member_id,drivers_license,routing_number export, the two
			// routing_number values were reported as driver's licences at 40 purely
			// because the row had been admitted for the licence column.
			if labelAbove != "" {
				// Scored with the same keyword logic as a line, so a label above carries
				// exactly the weight the inline form would. Never negative: a label
				// cannot be evidence AGAINST the value it names.
				if imp := v.AnalyzeContext("", detector.ContextInfo{FullLine: labelAbove}); imp > 0 {
					confidence += imp
				}
			}

			columnImpact := impactForColumn(spanStart)
			if !lineKeyworded && columnImpact <= 0 {
				return
			}
			confidence += columnImpact

			// Store keywords found (per-line invariant)
			contextInfo.PositiveKeywords = linePositiveKeywords
			contextInfo.NegativeKeywords = lineNegativeKeywords
			contextInfo.ConfidenceImpact = contextImpact

			// Clamp confidence
			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			// Skip very low confidence matches
			if confidence <= 0 {
				return
			}

			metadata := map[string]any{
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"format":            format,
				"source":            "preprocessed_content",
				"original_file":     originalPath,
			}
			if classifyText != text {
				metadata["normalized"] = classifyText
			}

			matches = append(matches, detector.Match{
				Text:       text,
				LineNumber: lineNum + 1,
				Type:       "DRIVERS_LICENSE",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "driverslicense",
				Context:    contextInfo,
				Metadata:   metadata,
			})
		}

		for i, loc := range idxMatches {
			if execguard.LineLoopCancelled(ctx, i) {
				return matches, ctx.Err()
			}
			match := line[loc[0]:loc[1]]
			emit(loc[0], loc[1], match, match)
		}

		// Separator-formatted candidates (D123-4567-8901): classified on the
		// normalized form, reported on the original span so redaction masks
		// the token as printed.
		for i, sc := range sepMatches {
			if execguard.LineLoopCancelled(ctx, i) {
				return matches, ctx.Err()
			}
			emit(sc.start, sc.end, line[sc.start:sc.end], sc.normalized)
		}
	}

	return matches, nil
}

// sepCandidate is a separator-formatted DL candidate: the original span on the
// line plus its normalized (separator-stripped) form.
type sepCandidate struct {
	start, end int
	normalized string
}

// separatedCandidates finds separator-formatted DL candidates (D123-4567-8901,
// "123 456 789") that classify into a known state format once separators are
// stripped. contiguousLocs are the spans already matched by reAnyDL (sorted by
// start, as FindAllStringIndex returns them); candidates overlapping them are
// skipped. Shape guards reject the token families that normalization would
// otherwise misclassify: SSNs (3-2-4 → 9 digits = NY), dates (12-31-1987 →
// 8 digits = TX), and ZIP+4 (5-4 → 9 digits = NY). Everything here is one
// regex pass plus O(candidate length) work per candidate, preserving the
// O(line length) per-line bound.
func (v *Validator) separatedCandidates(line string, contiguousLocs [][]int) []sepCandidate {
	var out []sepCandidate
	for _, loc := range reSeparatedDL.FindAllStringIndex(line, -1) {
		if overlapsSpans(contiguousLocs, loc[0], loc[1]) {
			continue
		}
		text := line[loc[0]:loc[1]]

		if reSSNShape.MatchString(text) {
			continue
		}
		if isDateOrZipShape(text) {
			continue
		}

		normalized := strings.Map(func(r rune) rune {
			if r == '-' || r == ' ' {
				return -1
			}
			return r
		}, text)
		if v.classifyMatch(normalized) == "" {
			continue
		}

		out = append(out, sepCandidate{start: loc[0], end: loc[1], normalized: normalized})
	}
	return out
}

// overlapsSpans reports whether [start,end) overlaps any span in locs
// (sorted by start offset).
func overlapsSpans(locs [][]int, start, end int) bool {
	for _, l := range locs {
		if l[0] >= end {
			return false
		}
		if l[1] > start {
			return true
		}
	}
	return false
}

// isDateOrZipShape rejects separated digit groupings that are canonically
// dates or ZIP+4 codes rather than printed license numbers:
// D-M-Y / M-D-Y ("12-31-1987", "31 12 87"), ISO-ish ("1987 12 31"),
// and ZIP+4 ("12345-6789").
func isDateOrZipShape(text string) bool {
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == '-' || r == ' ' })
	for _, p := range parts {
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false // letter prefix → not a date/zip shape
			}
		}
	}
	if len(parts) == 2 && len(parts[0]) == 5 && len(parts[1]) == 4 {
		return true // ZIP+4
	}
	if len(parts) == 3 {
		if len(parts[0]) <= 2 && len(parts[1]) <= 2 && (len(parts[2]) == 2 || len(parts[2]) == 4) {
			return true // D-M-Y / M-D-Y
		}
		if len(parts[0]) == 4 && len(parts[1]) <= 2 && len(parts[2]) <= 2 {
			return true // Y-M-D
		}
	}
	return false
}

// lineHasPositiveKeyword checks whether the line contains at least one
// DL-related keyword. This is the first gate: without a keyword, no format
// match is considered (because all DL formats overlap with generic numbers).
func (v *Validator) lineHasPositiveKeyword(line string) bool {
	for _, kw := range v.positiveKeywords {
		if containsLabel(line, kw) {
			return true
		}
	}
	// Also accept state name + a generic ID indicator. "id" is matched as a
	// WHOLE WORD (containsKeyword), not a raw substring: strings.Contains(lower,
	// "id") fired inside "resident"/"valid"/"midtown", so a state name plus any
	// such word wrongly opened the DL gate. "number"/"no."/"no:" stay as-is
	// (they do not collide with common words the way bare "id" does).
	if reStateName.MatchString(line) {
		lower := strings.ToLower(line)
		if containsKeyword(line, "id") || strings.Contains(lower, "number") ||
			strings.Contains(lower, "no.") || strings.Contains(lower, "no:") {
			return true
		}
	}
	return false
}

// classifyMatch determines which state DL format the match corresponds to.
// Returns a human-readable format string or "" if no specific format is matched.
// Ordered longest-first so that longer formats are checked before shorter ones
// that would also match (e.g. NJ 1L+14D before FL 1L+12D).
func (v *Validator) classifyMatch(match string) string {
	switch {
	case reNewJerseyDL.MatchString(match):
		// 1 letter + 14 digits: New Jersey
		return "NJ_1L14D"
	case reWisconsinDL.MatchString(match):
		// 1 letter + 13 digits: Wisconsin
		return "WI_1L13D"
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

// dlLabelForms are the label spellings that make a line a DL line at all. Kept
// in longest-plausible-first order only for readability; the search takes the
// EARLIEST occurrence, so order does not affect the result.
var dlLabelForms = []string{
	"driver's license", "drivers license", "driver license",
	"licence number", "license number", "license no",
	"d.l.", "dl:", "dl #", "dl#", "dl ",
}

// markerBeforeLabel reports whether a test/placeholder keyword appears before
// the DL label on this line. This is the per-LINE half of the rule described on
// markerModifiesLabel, split out so it can be hoisted out of the per-match loop
// (it does not depend on the match position). Keeping the hoist matters: the
// per-match form would make scanning O(matches x line length), which is the
// single-long-line CPU-exhaustion shape dos_test.go guards.
func markerBeforeLabel(line string) bool {
	lower := strings.ToLower(line)

	labelAt := -1
	for _, form := range dlLabelForms {
		if i := strings.Index(lower, form); i >= 0 && (labelAt < 0 || i < labelAt) {
			labelAt = i
		}
	}

	// No recognizable label form: keep the old conservative behavior and let any
	// keyword on the line suppress.
	if labelAt < 0 {
		for _, kw := range strongSuppressKeywords {
			if containsKeyword(line, kw) {
				return true
			}
		}
		return false
	}

	if labelAt == 0 {
		return false
	}
	for _, kw := range strongSuppressKeywords {
		if keywordIndexIn(lower[:labelAt], kw) >= 0 {
			return true
		}
	}
	return false
}

// markerOpensAsideAfter reports whether a test/placeholder keyword is the first
// word of an aside that starts immediately after the value ending at spanEnd.
// This is the per-MATCH half of the rule; it is O(1) in the line length because
// it reads only the few bytes following the span, and it takes the span offset
// the caller already has rather than re-locating the match.
func markerOpensAsideAfter(line string, spanEnd int) bool {
	if spanEnd < 0 || spanEnd >= len(line) {
		return false
	}
	tail := line[spanEnd:]

	// Skip the punctuation and whitespace that can introduce an aside.
	j := 0
	for j < len(tail) && strings.IndexByte(" \t-/(<[|,;:#>", tail[j]) >= 0 {
		j++
	}
	if j >= len(tail) {
		return false
	}

	// Take the next bare word.
	word := tail[j:]
	end := 0
	for end < len(word) && isWordByte(word[end]) {
		end++
	}
	word = strings.ToLower(word[:end])

	for _, kw := range strongSuppressKeywords {
		if word == kw {
			return true
		}
	}
	return false
}

// markerModifiesLabel reports whether a test/placeholder keyword is positioned
// so that it describes THE LICENCE ITSELF, rather than merely appearing
// somewhere on the same line.
//
// Two positions qualify, and they were derived by measurement rather than
// intuition:
//
//   - BEFORE the DL label. Genuine test data attaches the marker to the label:
//     "test DL: D1234567", "example driver license D1234567", "sample license
//     number: D1234567", "fake dl number D1234567", "placeholder driver license
//     D1234567". Real records never do this — the label comes first.
//
//   - As the FIRST WORD of an aside immediately after the value, with nothing
//     but punctuation between: "D1234567 (placeholder)", "D1234567 // sample
//     data", "D1234567 <- example value", "D1234567 [test data]", "D1234567 --
//     mock up only", "D1234567 fake". Here the marker is an apposition on the
//     value. Contrast a real record, where what follows the value is a clause
//     with its own subject: "D1234567, drug test negative", "D1234567 -- vision
//     test passed".
//
// Everything else is left alone, which is what recovers the real licences.
//
// Measured on 17 real-record phrasings and 17 genuine-test-data phrasings, half
// of each written as a held-out set after the rule was fixed: 15/17 real
// licences reported, 0/17 test values leaked. Two alternatives were rejected by
// measurement first — a pure distance threshold (no cutoff separates the classes;
// real records land at distance 1 and test data at 2, interleaved all the way
// out), and a compound-noun list of DMV terms like "road"/"vision" (6/12 on
// held-out data, and every miss was a REAL licence classified as test data).
//
// The one known miss is "Driver License Number: D1234567 sample submitted to
// lab", where "sample" opens the following clause AND is a bare noun. Losing an
// ambiguous sentence is the intended direction of error here: it suppresses,
// matching the old behavior, rather than inventing a finding.
func markerModifiesLabel(line, match string) bool {
	if markerBeforeLabel(line) {
		return true
	}
	if match == "" {
		return false
	}
	vi := strings.Index(strings.ToLower(line), strings.ToLower(match))
	if vi < 0 {
		return false
	}
	return markerOpensAsideAfter(line, vi+len(match))
}

// keywordIndexIn returns the byte offset of kw in s as a whole word, or -1.
// It exists so the before-the-label scan gets the same whole-word semantics
// containsKeyword provides, without allocating a substring per keyword.
func keywordIndexIn(s, kw string) int {
	from := 0
	for {
		i := strings.Index(s[from:], kw)
		if i < 0 {
			return -1
		}
		i += from
		beforeOK := i == 0 || !isWordByte(s[i-1])
		after := i + len(kw)
		afterOK := after >= len(s) || !isWordByte(s[after])
		if beforeOK && afterOK {
			return i
		}
		from = i + 1
		if from >= len(s) {
			return -1
		}
	}
}

// isWordByte reports whether b can be part of a word for whole-word matching.
func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

// tableHeaderHasPositiveKeyword reports whether any column header of a delimited table
// carries a DL keyword, for admitting a DATA row whose label sits in the header.
//
// Used only for admission. The precise per-column decision is impactForColumn, which
// scores the header of the match's own column.
func (v *Validator) tableHeaderHasPositiveKeyword(table *tabular.Table, lineNum int) bool {
	if !table.IsTable() || lineNum == table.HeaderLine() {
		return false
	}
	for _, h := range table.Headers() {
		if v.lineHasPositiveKeyword(h) {
			return true
		}
	}
	return false
}

// AnalyzeContext analyzes context around a match and returns a confidence adjustment.
// This is where the heavy lifting happens for DL detection: without keywords,
// the score stays at the low base of 20.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	line := context.FullLine
	var impact float64

	// Suppression is gated on WHERE the keyword sits relative to the DL label,
	// not merely on whether the line contains it anywhere.
	//
	// This check used to be `containsKeyword(line, kw)` over the whole line, and
	// returned -20 immediately. Against the base of 20 that landed on exactly 0,
	// and because the emit gate is `confidence <= 0`, the finding was deleted.
	// Two things made that wrong:
	//
	//   - It was line-global with no positional bound at all, so a keyword 400
	//     characters away killed the finding as effectively as an adjacent one.
	//   - The early return discarded the positive evidence before it was counted.
	//     ValidateContentCtx only scans lines that already contain a DL keyword
	//     (see lineHasPositiveKeyword), so every candidate reaching here is
	//     labelled. "Driver License Number: D1234567, road test scheduled"
	//     scores 95 without the phrase "road test" and scored 0 with it.
	//
	// "road test", "vision test", "drug test", "skills test", "breath sample"
	// and "sample collection" are ordinary DMV and HR vocabulary, so the old
	// rule deleted real licence numbers. That is a leak rather than a scoring
	// nit: only reported findings are handed to the redactor, and a file that
	// yields no findings has no redacted output written at all, so the whole
	// document survives in cleartext.
	//
	// See markerModifiesLabel for the rule and the measurements behind it.
	// When it fires the suppression is still absolute (return -20 against the
	// base of 20 lands on 0, and the emit gate is `confidence <= 0`), because a
	// marker attached to the label really does mean the licence is not real.
	// What changed is only WHICH lines qualify.
	if markerModifiesLabel(line, match) {
		return -20
	}

	// Check for explicit DL prefix patterns (strongest signal)
	lower := strings.ToLower(line)
	if strings.Contains(lower, "dl:") || strings.Contains(lower, "dl #") ||
		strings.Contains(lower, "dl#") || strings.Contains(lower, "d.l.") ||
		strings.Contains(lower, "driver's license:") || strings.Contains(lower, "drivers license:") ||
		strings.Contains(lower, "driver license:") || strings.Contains(lower, "license number:") ||
		strings.Contains(lower, "licence number:") || strings.Contains(lower, "license no:") ||
		strings.Contains(lower, "license no.") ||
		v.labelledFieldPrefix(lower) {
		impact += 75 // prefix pattern -> base 20 + 75 = 95
	} else {
		// Check for positive keywords (moderate signal)
		keywordCount := 0
		for _, kw := range v.positiveKeywords {
			if containsLabel(line, kw) {
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

// prefixLabels are the labels that, standing in the LABEL POSITION of a field, identify the value
// beside them as a driver's licence number. They are the same concepts as the literal substrings in
// AnalyzeContext, expressed once each instead of once per spelling.
var prefixLabels = []string{
	"driver's license", "drivers license", "driver license",
	"driver's licence", "drivers licence", "driver licence",
	"license number", "licence number", "license no", "licence no",
	"dl number", "dl",
	// The three-word forms are here for composition, and they are a no-op on their own. A keyword's
	// concatenation must equal the WHOLE word, so the label position "driverslicensenumber" is NOT
	// matched by "drivers license" — the trailing "number" makes it a different word. Without these
	// entries a camelCase three-word label would be detected but band-demoted, which is the very
	// defect this function fixes.
	//
	// On this branch alone they change nothing measurable, because `driversLicenseNumber:` produces no
	// finding at all to boost until the vocabulary gains the three-word positives (#438/#554). Adding
	// them cannot widen anything either: a label position containing "drivers license number"
	// necessarily contains "drivers license", which is already above.
	"drivers license number", "drivers licence number",
	"driver license number", "driver licence number",
	"driving license number", "driver's license number",
}

// valueSeparators end a field label. A labelled field is `<label><sep><value>`, and the separator is
// what distinguishes a label from prose: "please renew your drivers license soon" contains the label
// words but no separator, and must not earn the label boost.
const valueSeparators = ":#="

// labelledFieldPrefix reports whether the text before this line's first value separator is a
// driver's-licence label.
//
// # Why this exists
//
// The literal list in AnalyzeContext awards the label boost (+75, taking a finding from 20 to 95) by
// matching exact substrings such as "drivers license:". Those literals carry a space and a colon, so
// the SAME label written in any other convention could not match and fell through to the generic
// keyword arm at +45/+55. Measured at HEAD, one label per line, identical value:
//
//	drivers license: D1234567      95 HIGH
//	Drivers License: D1234567      95 HIGH
//	drivers_license: D1234567      75 MEDIUM
//	driversLicense: D1234567       65 MEDIUM
//	DriversLicense: D1234567       65 MEDIUM
//
// Three bands for one label, decided by the writing convention of whoever produced the file rather
// than by the evidence. camelCase and snake_case are the default key styles of JSON, REST payloads
// and ORM exports, so the two conventions that lose are the two a machine-generated export uses. A
// consumer gated on HIGH sees the spaced form and not the others (#553).
//
// # The rule
//
// This is deliberately NOT a wider substring search. It is narrower than the literals in one
// important way and wider in another:
//
//   - **Narrower:** the label must occupy the label POSITION — the text before the first `:`, `#` or
//     `=`. The literal list is a raw strings.Contains over the whole line, so it fires on a licence
//     label appearing anywhere, including after the value.
//   - **Wider:** the label is matched with kwmatch.ContainsLabel, so its spaces may match zero
//     separators and every convention of the same label counts.
//
// The separator requirement is what keeps prose out, and it is the same requirement the literals
// already encoded by ending in ':'. It is added as an EXTRA way to earn the boost rather than a
// replacement, so no line that scored 95 before can stop doing so.
func (v *Validator) labelledFieldPrefix(lowerLine string) bool {
	cut := strings.IndexAny(lowerLine, valueSeparators)
	if cut <= 0 {
		return false
	}
	label := lowerLine[:cut]

	// A label is short. Without this a whole paragraph ending in a colon would be searched, which
	// would readmit the prose the separator requirement exists to exclude.
	if len(label) > maxLabelPrefixLen {
		return false
	}
	for _, kw := range prefixLabels {
		if containsLabel(label, kw) {
			return true
		}
	}
	return false
}

// maxLabelPrefixLen bounds the label position. Field labels are short; a long run of text before a
// colon is a sentence, not a label.
const maxLabelPrefixLen = 64

// findLabelsOnLine returns which of the given keywords label a value on the line, matching each
// convention of the keyword.
//
// Separate from findKeywordsOnLine because that function is called with BOTH vocabularies, and the
// two directions are not symmetric: a positive keyword may reach further because doing so can only
// add evidence, while widening a suppressor silences real values. So the positive call site uses
// this and the negative call site keeps the strict matcher.
//
// What this fixes is reporting rather than scoring. Confidence comes from AnalyzeContext, which
// already used the label-flexible matcher; Context.PositiveKeywords is consumed only by the
// formatters — the text report's "Supporting keywords:" line and SARIF's positiveKeywords property.
// For a camelCase label both were EMPTY, so a reviewer was shown a finding with no stated supporting
// evidence even though the validator had matched a label to raise its confidence (#553).
func (v *Validator) findLabelsOnLine(line string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsLabel(line, kw) {
			found = append(found, kw)
		}
	}
	return found
}
