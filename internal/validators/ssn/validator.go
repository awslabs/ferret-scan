// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	stdctx "context"
	"regexp"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns used across validator methods.
var (
	reEmail          = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	rePhoneEnhanced  = regexp.MustCompile(`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	reDate           = regexp.MustCompile(`\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}`)
	reSSNEnhanced    = regexp.MustCompile(`\d{3}[-\s]?\d{2}[-\s]?\d{4}`)
	reNameEnhanced   = regexp.MustCompile(`\b[A-Z][a-z]+\s+[A-Z][a-z]+\b`)
	reMultiSpace3    = regexp.MustCompile(`\s{3,}`)
	reAllDigits      = regexp.MustCompile(`^\d+$`)
	reNumber         = regexp.MustCompile(`\d+`)
	reSSNStrict      = regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
	reCreditCard     = regexp.MustCompile(`\d{4}-\d{4}-\d{4}-\d{4}`)
	rePhoneStrict    = regexp.MustCompile(`\d{3}-\d{3}-\d{4}`)
	reMultiSpace2    = regexp.MustCompile(`\s{2,}`)
	reNameSSN        = regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+\d{3}-\d{2}-\d{4}`)
	reCSV            = regexp.MustCompile(`"[^"]*",\s*"[^"]*"`)
	reDigitSequences = regexp.MustCompile(`\b\d{18}\b`)
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively. The previous code used strings.Contains, so short keywords
// matched inside unrelated words — "hr" in "Christopher" (+45 inflation), "ein"
// in "Einstein", "ext" in "next", "code" in "barcode" — both fabricating context
// boosts on non-SSN lines and spuriously penalizing real SSNs.
//
// It is implemented as a plain string scan with manual boundary checks rather
// than a regex: AnalyzeContext/validateSSNByDomain/findKeywords invoke it on the
// order of a hundred times per matched SSN, and a compiled-regex MatchString per
// keyword made SSN-dense input ~13x slower. A "word" character here is
// [a-z0-9_]; a boundary is the string edge or any non-word byte, which also
// correctly anchors keywords whose own edges are non-word (e.g. "w-2").
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

// isWordByte reports whether b is a word character ([a-z0-9_]) for the purpose
// of keyword boundary detection. text is already lowercased by the caller.
func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// Validator implements the detector.Validator interface for detecting
// Social Security Numbers using regex patterns and contextual analysis.
type Validator struct {
	pattern string
	regex   *regexp.Regexp

	// Keywords that suggest an SSN context
	positiveKeywords []string

	// Keywords that suggest this is not an SSN
	negativeKeywords []string

	// Known invalid SSN patterns
	invalidPatterns []string

	// Enhanced domain-specific keywords for better context analysis
	hrKeywords         []string
	taxKeywords        []string
	healthcareKeywords []string

	// Global test patterns for enhanced false positive detection
	globalTestPatterns []string

	// Observability
	observer observability.Observer
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting Social Security Numbers.
func NewValidator() *Validator {
	v := &Validator{
		// SSN patterns: XXX-XX-XXXX, XXX XX XXXX, XXXXXXXXX only
		pattern: `\b(?:\d{3}-\d{2}-\d{4}|\d{3}\s\d{2}\s\d{4}|\d{9})\b`,
		positiveKeywords: []string{
			"ssn", "social security", "social security number", "social", "ein",
			"tax id", "taxpayer id", "identification number", "employee id",
			"federal id", "government id", "national id", "personal id",
			"identity", "benefits", "medicare", "medicaid", "irs", "w2", "w-2",
			"1099", "tax return", "tax form", "employment", "payroll",
			"hr", "human resources", "personnel", "employee record",
		},
		negativeKeywords: []string{
			"phone", "telephone", "fax", "zip", "postal", "area code",
			"extension", "ext", "routing", "account", "credit card", "card",
			"test", "example", "sample", "dummy", "fake", "mock", "demo",
			"template", "placeholder", "000-00-0000", "123-45-6789",
			"111-11-1111", "222-22-2222", "333-33-3333", "444-44-4444",
			"555-55-5555", "666-66-6666", "777-77-7777", "888-88-8888",
			"999-99-9999", "serial", "model", "version", "build",
			"encoded", "numeric", "code", "hash", "uuid", "guid",
		},
		invalidPatterns: []string{
			"000", "666", "900", "901", "902", "903", "904", "905", "906", "907", "908", "909",
		},
		hrKeywords: []string{
			"payroll", "hr", "human resources", "employee", "personnel", "staff",
			"employment", "hire", "onboarding", "benefits", "compensation",
			"employee record", "employee file", "personnel file", "hr system",
		},
		taxKeywords: []string{
			"tax", "w2", "w-2", "1099", "irs", "tax return", "tax form", "tax document",
			"tax filing", "tax preparation", "tax year", "tax id", "taxpayer",
			"federal tax", "state tax", "income tax", "tax liability",
		},
		healthcareKeywords: []string{
			"medical", "medicare", "medicaid", "insurance", "patient", "healthcare",
			"health record", "medical record", "patient record", "health plan",
			"medical insurance", "health insurance", "patient id", "medical id",
		},
		globalTestPatterns: []string{
			// Strong test-data indicators. Generic doc/config words
			// ("documentation", "readme", "template", "default", "tutorial") were
			// intentionally removed: they commonly appear on legitimate doc/config
			// lines that may also carry a real SSN, and a -40 penalty on their mere
			// presence pushed genuine SSNs below the surfacing threshold.
			"test", "example", "sample", "demo", "placeholder", "mock", "fake",
			"lorem ipsum", "john doe", "jane smith", "foo bar", "qwerty",
			"111111111", "222222222", "333333333", "444444444", "555555555",
			"777777777", "888888888", "999999999", "123456789", "987654321",
		},
	}

	// Compile the regex pattern once at initialization
	v.regex = regexp.MustCompile(v.pattern)

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// lineContext holds per-line analysis results that are identical for every match
// on the same line. Computing these once per line (instead of once per match)
// turns the previous O(matches * lineLength) hot path into O(lineLength + matches):
// none of these values depend on the individual match, so recomputing them for
// every match on a long, match-dense line was the source of the O(n^2) blowup.
type lineContext struct {
	lower         string          // strings.ToLower(line), reused for all keyword scans
	isTabular     bool            // v.isTabularData(line, ...) — match arg is unused
	isEnhancedTab bool            // v.isEnhancedTabularData(line, ...) — value arg is unused
	isEncoded     bool            // v.isEncodedData(line, ...) — match arg is unused
	keywordOnLine map[string]bool // containsKeyword(line, kw) for every keyword we test
}

// newLineContext precomputes the per-line-global analysis values once. Every map
// entry and boolean below is a pure function of the line text alone, so a match's
// position on the line never changes the result.
func (v *Validator) newLineContext(line string) *lineContext {
	lc := &lineContext{
		lower:         strings.ToLower(line),
		isTabular:     v.isTabularData(line, ""),
		isEnhancedTab: v.isEnhancedTabularData(line, ""),
		isEncoded:     v.isEncodedData(line, ""),
		keywordOnLine: make(map[string]bool),
	}

	// Cache whole-line keyword presence for every keyword the per-match analysis
	// consults. containsKeyword lowercases internally, so we pass the original
	// line here to keep results byte-for-byte identical to the previous code.
	cache := func(keywords []string) {
		for _, kw := range keywords {
			if _, ok := lc.keywordOnLine[kw]; !ok {
				lc.keywordOnLine[kw] = containsKeyword(line, kw)
			}
		}
	}
	cache(v.positiveKeywords)
	cache(v.negativeKeywords)
	cache(v.hrKeywords)
	cache(v.taxKeywords)
	cache(v.healthcareKeywords)
	cache(v.globalTestPatterns)

	return lc
}

// ValidateContent validates preprocessed content for SSNs
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: it is the
// context-aware form of ValidateContent, polling ctx once per line so a runaway
// scan of a large multi-line input is reclaimed promptly (v2 Phase 3). On
// cancellation it returns the matches gathered so far plus ctx.Err(), so a
// timed-out scan surfaces partial findings rather than discarding them.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	isDocx := strings.Contains(originalPath, ".docx")

	for lineNum, line := range lines {
		// Cooperative cancellation: stop promptly if the scan's deadline fired
		// or it was cancelled, returning what we have plus the reason.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}
		// Use FindAllStringIndex so we enumerate matches with their byte offsets in a
		// single regex pass (FindAllString already did one pass; this is equivalent).
		// We deliberately compute the context window from the FIRST occurrence of each
		// distinct token (cached below), preserving the exact behavior of the previous
		// strings.Index(line, match) call while removing its O(lineLength)-per-match
		// rescan — the source of the O(n^2) blowup on a long, match-dense single line.
		idxMatches := v.regex.FindAllStringIndex(line, -1)

		type matchSpan struct {
			text  string
			start int // first-occurrence offset of text on the line (matches old strings.Index)
		}
		var foundMatches []matchSpan
		var firstIndex map[string]int
		if len(idxMatches) > 0 {
			firstIndex = make(map[string]int)
			for _, loc := range idxMatches {
				txt := line[loc[0]:loc[1]]
				if _, seen := firstIndex[txt]; !seen {
					firstIndex[txt] = loc[0]
				}
				foundMatches = append(foundMatches, matchSpan{
					text:  txt,
					start: firstIndex[txt],
				})
			}
		}

		// For preprocessed content, also look for SSN patterns in concatenated number sequences
		if len(foundMatches) == 0 && isDocx {
			// This handles cases where text extraction concatenates SSNs with other data.
			// These synthesized candidates have no real offset on the line; mark with
			// start = -1 so the context window falls back to strings.Index (the prior
			// behavior for this branch).
			for _, m := range v.findSSNsInConcatenatedNumbers(line) {
				foundMatches = append(foundMatches, matchSpan{text: m, start: -1})
			}
		}

		// Precompute the per-line-global analysis once; reused for every match below.
		var lc *lineContext
		if len(foundMatches) > 0 {
			lc = v.newLineContext(line)
		}

		for _, ms := range foundMatches {
			match := ms.text
			// Clean the SSN for validation
			cleanMatch := v.cleanSSN(match)

			// Validate the SSN format and content
			if !v.isValidSSN(cleanMatch) {
				continue
			}

			// Calculate confidence
			confidence, checks := v.CalculateConfidence(match)

			// Skip if this looks like encoded data or numeric sequences
			if lc.isEncoded {
				continue
			}

			// For preprocessed content, create a simpler context info
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}

			// Extract some context around the match in the line. Prefer the known
			// offset from FindAllStringIndex; fall back to strings.Index only for the
			// synthesized docx-concatenation candidates (start == -1).
			matchIndex := ms.start
			if matchIndex < 0 {
				matchIndex = strings.Index(line, match)
			}
			if matchIndex >= 0 {
				start := matchIndex - 50
				if start < 0 {
					start = 0
				}
				end := matchIndex + len(match) + 50
				if end > len(line) {
					end = len(line)
				}

				contextInfo.BeforeText = line[start:matchIndex]
				contextInfo.AfterText = line[matchIndex+len(match) : end]
			}

			// Analyze context and adjust confidence
			contextImpact := v.analyzeContextWithLine(match, contextInfo, lc)
			confidence += contextImpact

			// Store keywords found in context
			contextInfo.PositiveKeywords = v.findKeywordsCached(lc, v.positiveKeywords)
			contextInfo.NegativeKeywords = v.findKeywordsCached(lc, v.negativeKeywords)
			contextInfo.ConfidenceImpact = contextImpact

			// Check if this is tabular data first - this is more reliable than keyword detection
			isTabular := lc.isTabular

			// Adjust confidence based on context, prioritizing tabular data detection
			if isTabular {
				// For tabular data, don't cap confidence regardless of keywords
				// Only apply mild penalty for negative keywords
				if len(contextInfo.NegativeKeywords) > 0 {
					confidence -= 10 // Very mild penalty for negative context in tabular data
				}
				// Don't cap confidence for tabular data - let the base confidence stand
			} else if len(contextInfo.PositiveKeywords) == 0 {
				// For non-tabular data without positive keywords, be more restrictive.
				if len(contextInfo.NegativeKeywords) > 0 {
					confidence -= 25 // Stronger penalty for negative context in non-tabular data
				} else {
					// The strongly-formatted hyphenated XXX-XX-XXXX form (which has
					// already passed all structural checks) is high-quality evidence
					// on its own, so allow it to reach the 60 MEDIUM threshold even
					// without a keyword (L45). The riskier separator-less / spaced
					// forms keep the stricter LOW cap of 50.
					capValue := 50.0
					if v.isStrongHyphenatedSSN(match) {
						capValue = 60.0
					}
					if confidence > capValue {
						confidence = capValue
					}
				}
			}

			// Drop known denylisted test SSNs (123-45-6789, 123-45-4321, all-same
			// digits, etc.). These are not real PII, yet a nearby positive keyword
			// like "ssn"/"employee" could previously push them to HIGH (100) — a
			// maximum-confidence false positive on a value the validator itself
			// flags as test data. The decision is made here, after context
			// analysis, so it is not defeated by keyword boosts. This is the
			// false-positive-minimizing behavior and matches the validator's own
			// denylist intent.
			if v.isTestSSN(v.cleanSSN(match)) {
				continue
			}

			// Ensure confidence stays within bounds
			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			// Skip matches with 0% confidence - they are false positives
			if confidence <= 0 {
				continue
			}

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1, // 1-based line numbering
				Type:       "SSN",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "ssn",
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

// AnalyzeContext analyzes the context around a match and returns a confidence
// adjustment. It is retained for external callers and computes a fresh per-line
// context on each call; ValidateContent uses analyzeContextWithLine to share that
// work across all matches on a line.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	return v.analyzeContextWithLine(match, context, v.newLineContext(context.FullLine))
}

// junctionWindowLen bounds how far a multi-word keyword can reach across the
// synthetic " " joins that AnalyzeContext inserts between BeforeText/FullLine and
// FullLine/AfterText. The longest keyword/test pattern is "social security
// number" (22 bytes); 64 is a comfortable upper bound so junction scanning stays
// O(1) per match instead of O(lineLength).
const junctionWindowLen = 64

// keywordInFullContext reports whether keyword appears in the lowercased
// concatenation BeforeText + " " + FullLine + " " + AfterText, exactly matching
// the original AnalyzeContext behavior — but without rescanning the whole line per
// match. Because BeforeText and AfterText are substrings of FullLine, a keyword is
// present in the full context iff it is present on the line (precomputed in lc) OR
// it straddles one of the two synthetic spaces. Only those bounded junction
// regions need scanning here.
func (v *Validator) keywordInFullContext(keyword, before, after string, lc *lineContext) bool {
	if lc.keywordOnLine[keyword] {
		return true
	}
	// Scan the tiny regions around each synthetic space join. before/after are
	// already substrings of the line, so any match not already covered above must
	// span "before + ' ' + line" or "line + ' ' + after".
	tail := func(s string) string {
		if len(s) > junctionWindowLen {
			return s[len(s)-junctionWindowLen:]
		}
		return s
	}
	head := func(s string) string {
		if len(s) > junctionWindowLen {
			return s[:junctionWindowLen]
		}
		return s
	}
	// junction 1: end-of-before + " " + start-of-line
	j1 := tail(before) + " " + head(lc.lower)
	if containsKeyword(j1, keyword) {
		return true
	}
	// junction 2: end-of-line + " " + start-of-after
	j2 := tail(lc.lower) + " " + head(after)
	return containsKeyword(j2, keyword)
}

// analyzeContextWithLine is the per-match context analysis that reuses the shared
// per-line context lc, eliminating the per-match whole-line rescans that caused the
// O(n^2) blowup. Its result is identical to the original AnalyzeContext.
func (v *Validator) analyzeContextWithLine(match string, context detector.ContextInfo, lc *lineContext) float64 {
	before := strings.ToLower(context.BeforeText)
	after := strings.ToLower(context.AfterText)

	var confidenceImpact float64 = 0

	// Enhanced domain-specific analysis (domain keywords are checked against the
	// full context; reuse the cached line/junction logic).
	confidenceImpact += v.validateSSNByDomainCached(before, after, lc)

	// Check for positive keywords (increase confidence)
	for _, keyword := range v.positiveKeywords {
		if v.keywordInFullContext(keyword, before, after, lc) {
			// Give more weight to keywords that are closer to the match
			if lc.keywordOnLine[keyword] {
				confidenceImpact += 25 // +25% for keywords in the same line
			} else {
				confidenceImpact += 10 // +10% for keywords in surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		if v.keywordInFullContext(keyword, before, after, lc) {
			// Give more weight to keywords that are closer to the match
			if lc.keywordOnLine[keyword] {
				confidenceImpact -= 15 // -15% for negative keywords in the same line
			} else {
				confidenceImpact -= 8 // -8% for negative keywords in surrounding context
			}
		}
	}

	// Enhanced tabular data detection (line-global; precomputed once per line)
	if lc.isEnhancedTab {
		confidenceImpact += 25 // Higher boost for enhanced tabular detection
	} else if lc.isTabular {
		confidenceImpact += 15 // Standard boost for basic tabular detection
	}

	// Check for global test patterns
	if v.isEnhancedTestPatternCached(match, before, after, lc) {
		confidenceImpact -= 40 // Strong penalty for test patterns
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 50 {
		confidenceImpact = 50 // Maximum +50% boost
	} else if confidenceImpact < -50 {
		confidenceImpact = -50 // Maximum -50% reduction
	}

	return confidenceImpact
}

// validateSSNByDomain provides domain-specific confidence boosts
func (v *Validator) validateSSNByDomain(ssn, context string) float64 {
	boost := 0.0

	// HR/Payroll context
	for _, keyword := range v.hrKeywords {
		if containsKeyword(context, keyword) {
			boost += 20
			break // Only apply once per domain
		}
	}

	// Tax document context
	for _, keyword := range v.taxKeywords {
		if containsKeyword(context, keyword) {
			boost += 25
			break // Only apply once per domain
		}
	}

	// Healthcare context
	for _, keyword := range v.healthcareKeywords {
		if containsKeyword(context, keyword) {
			boost += 18
			break // Only apply once per domain
		}
	}

	return boost
}

// validateSSNByDomainCached mirrors validateSSNByDomain but evaluates each domain
// keyword against the full context via the cached per-line context instead of
// rescanning the whole line for every match. Result is identical.
func (v *Validator) validateSSNByDomainCached(before, after string, lc *lineContext) float64 {
	boost := 0.0

	for _, keyword := range v.hrKeywords {
		if v.keywordInFullContext(keyword, before, after, lc) {
			boost += 20
			break
		}
	}

	for _, keyword := range v.taxKeywords {
		if v.keywordInFullContext(keyword, before, after, lc) {
			boost += 25
			break
		}
	}

	for _, keyword := range v.healthcareKeywords {
		if v.keywordInFullContext(keyword, before, after, lc) {
			boost += 18
			break
		}
	}

	return boost
}

// isEnhancedTabularData provides enhanced detection of tabular data structures
func (v *Validator) isEnhancedTabularData(line, value string) bool {
	// Count structured elements in the line
	structuredCount := 0

	// Email patterns
	structuredCount += len(reEmail.FindAllString(line, -1))

	// Phone patterns
	structuredCount += len(rePhoneEnhanced.FindAllString(line, -1))

	// Date patterns
	structuredCount += len(reDate.FindAllString(line, -1))

	// SSN patterns
	structuredCount += len(reSSNEnhanced.FindAllString(line, -1))

	// Name patterns (Title Case words)
	structuredCount += len(reNameEnhanced.FindAllString(line, -1))

	// If we have 3+ structured elements, it's likely tabular
	if structuredCount >= 3 {
		return true
	}

	// Check for common delimiters
	tabCount := strings.Count(line, "\t")
	commaCount := strings.Count(line, ",")
	pipeCount := strings.Count(line, "|")

	if tabCount >= 2 || commaCount >= 3 || pipeCount >= 2 {
		return true
	}

	// Check for multiple consecutive spaces (fixed-width tables)
	if len(reMultiSpace3.FindAllString(line, -1)) >= 2 {
		return true
	}

	return false
}

// isEnhancedTestPattern checks for enhanced test patterns
func (v *Validator) isEnhancedTestPattern(value, context string) bool {
	lowerValue := strings.ToLower(value)
	lowerContext := strings.ToLower(context)

	// Check global test patterns. The list mixes numeric patterns (e.g.
	// "111111111") with generic doc/config words ("demo", "default", "readme").
	// Match numeric/value patterns against the value itself, but match WORD
	// patterns against the context on whole-word boundaries only — the previous
	// raw substring scan over the whole line meant an unrelated word like "demo"
	// inside "demographic" (or simply present on a config line) applied the -40
	// test penalty and pushed real SSNs under the surfacing threshold.
	for _, pattern := range v.globalTestPatterns {
		// Value match: an actual test value embedded in the candidate.
		if strings.Contains(lowerValue, pattern) {
			return true
		}
		// Context match: require the pattern to appear as a whole word.
		if containsKeyword(lowerContext, pattern) {
			return true
		}
	}

	// Check for obvious test sequences
	cleanValue := v.cleanSSN(value)
	if v.isObviousTestSequence(cleanValue) {
		return true
	}

	return false
}

// isEnhancedTestPatternCached mirrors isEnhancedTestPattern but uses the cached
// per-line context for the whole-word context check, avoiding a per-match
// whole-line rescan. The value-based checks remain O(len(value)) per match.
// Result is identical to isEnhancedTestPattern.
func (v *Validator) isEnhancedTestPatternCached(value, before, after string, lc *lineContext) bool {
	lowerValue := strings.ToLower(value)

	for _, pattern := range v.globalTestPatterns {
		// Value match: an actual test value embedded in the candidate.
		if strings.Contains(lowerValue, pattern) {
			return true
		}
		// Context match: require the pattern to appear as a whole word in the
		// full context (line + bounded before/after windows).
		if v.keywordInFullContext(pattern, before, after, lc) {
			return true
		}
	}

	// Check for obvious test sequences
	cleanValue := v.cleanSSN(value)
	if v.isObviousTestSequence(cleanValue) {
		return true
	}

	return false
}

// isObviousTestSequence checks for obvious test number sequences
func (v *Validator) isObviousTestSequence(value string) bool {
	if len(value) != 9 {
		return false
	}

	// Check for repeating digits (e.g., 111111111)
	for i := 0; i < len(value)-3; i++ {
		if value[i] == value[i+1] && value[i] == value[i+2] && value[i] == value[i+3] {
			return true
		}
	}

	// Check for ascending/descending sequences
	if len(value) >= 6 {
		ascending := true
		descending := true

		for i := 0; i < len(value)-1; i++ {
			curr := int(value[i] - '0')
			next := int(value[i+1] - '0')

			if next != (curr+1)%10 {
				ascending = false
			}
			if next != (curr+9)%10 {
				descending = false
			}
		}

		if ascending || descending {
			return true
		}
	}

	return false
}

// findKeywordsCached mirrors findKeywords (whole-line, whole-word keyword
// presence) but reads the precomputed per-line cache instead of rescanning the
// line for each keyword on every match. Result is identical.
func (v *Validator) findKeywordsCached(lc *lineContext, keywords []string) []string {
	var found []string
	for _, keyword := range keywords {
		if lc.keywordOnLine[keyword] {
			found = append(found, keyword)
		}
	}
	return found
}

// CalculateConfidence calculates the confidence score for a potential SSN
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":             true,
		"digits":             true,
		"valid_area":         false,
		"not_test_number":    true,
		"not_sequential":     true,
		"not_repeating":      true,
		"not_common_pattern": true,
	}

	cleanMatch := v.cleanSSN(match)
	confidence := 70.0 // Start with higher base confidence for properly formatted SSNs

	// Check format (already validated in isValidSSN)
	if len(cleanMatch) != 9 {
		confidence -= 20
		checks["format"] = false
	}

	// Check if all digits
	if !reAllDigits.MatchString(cleanMatch) {
		confidence -= 20
		checks["digits"] = false
		return confidence, checks
	}

	// Check area number (first 3 digits)
	if len(cleanMatch) >= 3 {
		area := cleanMatch[0:3]
		if v.isValidAreaNumber(area) {
			checks["valid_area"] = true
			confidence += 15 // Increased boost for valid area numbers
		} else {
			confidence -= 15
		}
	}

	// Boost confidence for properly formatted SSNs (XXX-XX-XXXX pattern)
	hasSeparator := strings.ContainsAny(match, "- ")
	if strings.Contains(match, "-") && len(strings.Split(match, "-")) == 3 {
		parts := strings.Split(match, "-")
		if len(parts[0]) == 3 && len(parts[1]) == 2 && len(parts[2]) == 4 {
			confidence += 10 // Boost for proper formatting
		}
	}

	// Penalize the separator-less 9-digit form. Any standalone 9-digit token
	// (order/serial/ZIP9/product IDs) matches \d{9}, so on its own it is much
	// weaker evidence of an SSN than the dashed/spaced forms. It still surfaces
	// (lower base + context can lift it), but a bare 9-digit number no longer
	// reaches HIGH without corroboration. The dashed form is unaffected.
	if !hasSeparator {
		confidence -= 15
	}

	// Check for test numbers. ValidateContent drops known test SSNs outright
	// (after context analysis); here we record the failed check and apply the
	// historical penalty so CalculateConfidence remains meaningful for callers
	// that score a value directly.
	if v.isTestSSN(cleanMatch) {
		confidence -= 25
		checks["not_test_number"] = false
	}

	// Check for sequential numbers
	if v.isSequential(cleanMatch) {
		confidence -= 15
		checks["not_sequential"] = false
	}

	// Check for repeating patterns
	if v.hasRepeatingPatterns(cleanMatch) {
		confidence -= 15
		checks["not_repeating"] = false
	}

	// Check for common invalid patterns
	if v.matchesCommonPattern(cleanMatch) {
		confidence -= 20
		checks["not_common_pattern"] = false
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// Helper methods
func (v *Validator) cleanSSN(ssn string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ssn, "-", ""), " ", "")
}

// isStrongHyphenatedSSN reports whether match is the canonical hyphenated
// XXX-XX-XXXX form with a valid area number — the highest-quality SSN shape.
// Such a value is strong enough evidence to reach MEDIUM without a nearby
// keyword (L45), unlike the riskier bare/space-separated forms.
func (v *Validator) isStrongHyphenatedSSN(match string) bool {
	parts := strings.Split(match, "-")
	if len(parts) != 3 || len(parts[0]) != 3 || len(parts[1]) != 2 || len(parts[2]) != 4 {
		return false
	}
	return v.isValidAreaNumber(parts[0])
}

func (v *Validator) isValidSSN(ssn string) bool {
	if len(ssn) != 9 {
		return false
	}

	// Check for all zeros
	if ssn == "000000000" {
		return false
	}

	// Check area number (first 3 digits)
	area := ssn[0:3]
	if area == "000" || area == "666" {
		return false
	}

	// Check for 900-999 area numbers (invalid)
	if areaNum, err := strconv.Atoi(area); err == nil {
		if areaNum >= 900 {
			return false
		}
	}

	// Check group number (middle 2 digits)
	group := ssn[3:5]
	if group == "00" {
		return false
	}

	// Check serial number (last 4 digits)
	serial := ssn[5:9]
	if serial == "0000" {
		return false
	}

	return true
}

func (v *Validator) isValidAreaNumber(area string) bool {
	areaNum, err := strconv.Atoi(area)
	if err != nil {
		return false
	}

	// Valid area numbers are 001-665, 667-899
	return (areaNum >= 1 && areaNum <= 665) || (areaNum >= 667 && areaNum <= 899)
}

func (v *Validator) isTestSSN(ssn string) bool {
	testSSNs := map[string]bool{
		"123456789": true,
		"111111111": true,
		"222222222": true,
		"333333333": true,
		"444444444": true,
		"555555555": true,
		"777777777": true,
		"888888888": true,
		"999999999": true,
		"987654321": true,
		"123454321": true,
	}
	return testSSNs[ssn]
}

func (v *Validator) isSequential(ssn string) bool {
	// Check for ascending sequence
	ascending := true
	for i := 0; i < len(ssn)-1; i++ {
		curr := int(ssn[i] - '0')
		next := int(ssn[i+1] - '0')
		if next != (curr+1)%10 {
			ascending = false
			break
		}
	}

	// Check for descending sequence
	descending := true
	for i := 0; i < len(ssn)-1; i++ {
		curr := int(ssn[i] - '0')
		next := int(ssn[i+1] - '0')
		if next != (curr+9)%10 {
			descending = false
			break
		}
	}

	return ascending || descending
}

func (v *Validator) hasRepeatingPatterns(ssn string) bool {
	// Check for 3+ consecutive identical digits
	for i := 0; i < len(ssn)-2; i++ {
		if ssn[i] == ssn[i+1] && ssn[i] == ssn[i+2] {
			return true
		}
	}

	// Check for repeating blocks
	if len(ssn) == 9 {
		// Check for XXX-XX-XXXX where all parts are the same
		area := ssn[0:3]
		group := ssn[3:5]
		serial := ssn[5:9]

		if area == group+group[0:1] || area == serial[0:3] {
			return true
		}
	}

	return false
}

func (v *Validator) matchesCommonPattern(ssn string) bool {
	// Check for patterns like 123-45-6789
	if ssn == "123456789" {
		return true
	}

	// Check for all same digits
	firstDigit := ssn[0]
	allSame := true
	for i := 1; i < len(ssn); i++ {
		if ssn[i] != firstDigit {
			allSame = false
			break
		}
	}

	return allSame
}

// isEncodedData checks if the match appears to be part of encoded data or numeric sequences
func (v *Validator) isEncodedData(line, match string) bool {
	// First check if this looks like tabular data - if so, don't reject it
	if v.isTabularData(line, match) {
		return false
	}

	// Count total numbers in the line
	numbers := reNumber.FindAllString(line, -1)

	// For non-tabular data, if line has many numbers (>15), it's likely encoded data
	if len(numbers) > 15 {
		// But check if the numbers are structured (like SSNs, credit cards, phone numbers)
		structuredNumbers := 0

		// Count SSN patterns
		structuredNumbers += len(reSSNStrict.FindAllString(line, -1))

		// Count credit card patterns
		structuredNumbers += len(reCreditCard.FindAllString(line, -1))

		// Count phone patterns
		structuredNumbers += len(rePhoneStrict.FindAllString(line, -1))

		// If we have structured numbers, it's likely legitimate data
		if structuredNumbers >= 2 {
			return false
		}

		return true
	}

	// Check if the line contains mostly numbers and spaces (but not tabs - tabs suggest tabular data)
	numericChars := 0
	spaceChars := 0
	tabChars := 0
	totalChars := len(line)

	for _, char := range line {
		if char >= '0' && char <= '9' {
			numericChars++
		} else if char == ' ' {
			spaceChars++
		} else if char == '\t' {
			tabChars++
		}
	}

	// If line has tabs, it's likely tabular data, so don't reject
	if tabChars > 0 {
		return false
	}

	// If more than 85% of the line is numbers and spaces (and no tabs), it's likely encoded.
	if totalChars > 0 && float64(numericChars+spaceChars)/float64(totalChars) > 0.85 {
		// Guard against dropping a line that IS essentially a single SSN. A bare
		// SSN ("219099999" = 9/9 chars) or a space-separated one ("219 09 9999"
		// = 11/11) trivially exceeds 85% numeric, so the heuristic was silently
		// discarding two of the three SSN formats the validator advertises
		// whenever they appeared alone (CSV cell, log column, one value per line).
		// The 85% rule is meant to catch dense multi-number blobs; the caller has
		// already confirmed `match` is a valid SSN on this line, so a line with
		// only a few distinct number groups is that SSN, not encoded data. A
		// space-separated SSN tokenizes into 3 groups, so allow up to 3.
		if len(numbers) <= 3 {
			return false
		}
		return true
	}

	return false
}

// isTabularData checks if the SSN appears to be in a tabular format
func (v *Validator) isTabularData(line, match string) bool {
	// Check for common tabular delimiters
	tabCount := strings.Count(line, "\t")
	commaCount := strings.Count(line, ",")
	semicolonCount := strings.Count(line, ";")
	pipeCount := strings.Count(line, "|")

	// If line has common delimiters, likely tabular
	if tabCount > 0 || commaCount >= 2 || semicolonCount >= 2 || pipeCount >= 2 {
		return true
	}

	// Check for multiple consecutive spaces (common in fixed-width tabular data)
	multiSpaceMatches := reMultiSpace2.FindAllString(line, -1)
	if len(multiSpaceMatches) >= 2 {
		return true
	}

	// Check for common tabular patterns (names followed by SSNs)
	if reNameSSN.MatchString(line) {
		return true
	}

	// Check for CSV-style patterns (comma-separated values with quotes)
	if reCSV.MatchString(line) {
		return true
	}

	// Check if line contains multiple structured data elements
	structuredElements := 0

	// Count SSN-like patterns
	ssnSpans := reSSNStrict.FindAllStringIndex(line, -1)
	structuredElements += len(ssnSpans)

	// Count credit card-like patterns
	structuredElements += len(reCreditCard.FindAllString(line, -1))

	// Count phone-like patterns
	structuredElements += len(rePhoneStrict.FindAllString(line, -1))

	// Count email-like patterns
	structuredElements += len(reEmail.FindAllString(line, -1))

	// Count date-like patterns (MM/DD/YYYY, YYYY-MM-DD, etc.) — but not date
	// matches that sit INSIDE an SSN span: the tail of every XXX-XX-XXXX SSN
	// itself parses as \d{1,2}-\d{2}-\d{4}, so without this exclusion a line
	// holding a single bare SSN self-counts as two "structured elements" and
	// EVERY SSN line gets the +15 tabular boost — which is what flattened all
	// context discrimination (real vs decoy context both re-clamped to 100).
	//
	// Both index slices are sorted by start offset (FindAllStringIndex returns
	// left-to-right, non-overlapping), so a two-pointer merge walk keeps this
	// O(dates + ssns). The first version nested the span test — O(dates×ssns),
	// which on a 1MB single line of ~87K SSNs (the DoS regression shape) is
	// ~7.6 billion comparisons and pushed the perf test from ~2s to ~180s.
	si := 0
	for _, d := range reDate.FindAllStringIndex(line, -1) {
		for si < len(ssnSpans) && ssnSpans[si][1] < d[1] {
			si++
		}
		if si < len(ssnSpans) && d[0] >= ssnSpans[si][0] && d[1] <= ssnSpans[si][1] {
			continue // date is the tail of an SSN token
		}
		structuredElements++
	}

	// If multiple structured elements, likely tabular data
	return structuredElements >= 2
}

// findSSNsInConcatenatedNumbers looks for SSN patterns in concatenated number sequences
// This is specifically for preprocessed content where text extraction may concatenate numbers
func (v *Validator) findSSNsInConcatenatedNumbers(line string) []string {
	var matches []string

	// Look for sequences of exactly 18 digits (two 9-digit numbers concatenated)
	// This is much more restrictive than looking for any 9+ digit sequence
	digitSequences := reDigitSequences.FindAllString(line, -1)

	for _, seq := range digitSequences {
		// Split into two 9-digit candidates
		candidate1 := seq[0:9]
		candidate2 := seq[9:18]

		// Only accept if both halves could be valid SSNs
		if v.couldBeSSN(candidate1) && v.couldBeSSN(candidate2) {
			matches = append(matches, candidate1, candidate2)
		}
	}

	return matches
}

// couldBeSSN performs basic checks to see if a 9-digit string could be an SSN
func (v *Validator) couldBeSSN(candidate string) bool {
	if len(candidate) != 9 {
		return false
	}

	// Check area number (first 3 digits)
	area := candidate[0:3]
	if area == "000" || area == "666" {
		return false
	}

	// Check for 900-999 area numbers (invalid)
	if areaNum, err := strconv.Atoi(area); err == nil {
		if areaNum >= 900 {
			return false
		}
	}

	// Check group number (middle 2 digits)
	group := candidate[3:5]
	if group == "00" {
		return false
	}

	// Check serial number (last 4 digits)
	serial := candidate[5:9]
	if serial == "0000" {
		return false
	}

	return true
}
