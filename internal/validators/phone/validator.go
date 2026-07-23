// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	stdctx "context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns to avoid repeated compilation in hot paths.
var (
	phoneValidCharsPattern = regexp.MustCompile(`^[\d+\-.\s()]+$`)
	phoneCleanPattern      = regexp.MustCompile(`[^\d+]`)
	// reFictional555 matches the NANP reserved fictional exchange 555-0100..0199
	// in cleaned-digit form ("55501" + two digits), anchored to a 7- or 10/11-digit
	// number so it doesn't fire on an incidental "55501" run inside other digits.
	reFictional555         = regexp.MustCompile(`(?:^|[^\d])\+?1?(?:\d{3})?55501\d{2}$`)
	ssnPattern             = regexp.MustCompile(`^\d{3}[-.\s]\d{2}[-.\s]\d{4}$`)
	phoneMultiSpacePattern = regexp.MustCompile(`\s{2,}`)
	namePhonePattern       = regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+\(?\d{3}\)?`)
)

// Validator implements the detector.Validator interface for detecting
// phone numbers using regex patterns and contextual analysis.
type Validator struct {
	patterns []phonePattern

	// Keywords that suggest a phone context
	positiveKeywords []string

	// Keywords that suggest this is not a real phone
	negativeKeywords []string

	// Lowercased copies of the keyword lists, precomputed once so the per-match
	// context analysis does not call strings.ToLower(keyword) repeatedly. The
	// source lists are already lowercase, so these are equal in value; caching
	// them just removes per-match allocation/work.
	positiveKeywordsLower []string
	negativeKeywordsLower []string

	// maxKeywordLen is the byte length of the longest keyword across both lists.
	// It bounds the boundary-probe windows used by the long-line context path.
	maxKeywordLen int

	// Known test patterns that indicate test data
	knownTestPatterns []string

	// Common test phone numbers
	testPhoneNumbers []string

	// Country calling codes for validation
	countryCodeMap map[string]string

	// Optimized country code lookup (sorted by length, longest first)
	sortedCountryCodes []string

	// Observability
	observer observability.Observer
}

// phonePattern represents a phone number pattern with its format info
type phonePattern struct {
	name    string
	regex   *regexp.Regexp
	country string
	format  string
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns, keywords, and validation rules for detecting phone numbers.
func NewValidator() *Validator {
	v := &Validator{
		positiveKeywords: []string{
			"phone", "telephone", "tel", "call", "mobile", "cell", "cellular",
			"contact", "number", "fax", "voicemail", "extension", "ext",
			"dial", "ring", "caller", "emergency", "hotline", "helpline",
			"support", "service", "customer", "sales", "office", "home",
			"work", "business", "personal", "primary", "secondary",
			"toll-free", "tollfree", "free", "800", "888", "877", "866",
			"855", "844", "833", "directory", "assistance", "operator",
		},
		negativeKeywords: []string{
			"test", "example", "fake", "mock", "sample", "dummy", "placeholder",
			"demo", "template", "tutorial", "documentation", "readme",
			"lorem", "ipsum", "foo", "bar", "baz", "temp", "temporary",
			"invalid", "nonexistent", "blackhole", "devnull", "null",
			// SSN-specific keywords to avoid false positives. Generic words
			// "number"/"id"/"name"/"account" were removed (L28): they collide with
			// legitimate phone context ("phone number", "contact number") and
			// tabular contact records ("name, phone, id"), demoting real phones out
			// of HIGH/MEDIUM. The structural SSN/credit-card/timestamp checks (which
			// don't rely on these words) still suppress those data types.
			"ssn", "social", "security", "social security", "tax", "identification",
			"taxpayer", "employee", "federal", "ein", "itin",
			// Credit card and financial data keywords
			"credit", "card", "visa", "mastercard", "amex", "american express",
			"discover", "balance", "payment", "transaction", "amount",
			"first and last name", "last name", "first name",
			// Timestamp and technical keywords
			"timestamp", "unix", "epoch", "milliseconds", "seconds", "time",
			"created", "modified", "updated", "generated", "build", "version",
			"revision", "commit", "hash", "checksum", "uuid", "guid",
			// Operational/inventory vocabulary: phone-shaped tokens labeled
			// as these scored 65-100 (displayed) in the reranker-benchmark
			// corpus — order refs, RMAs, serials, SKUs, permits, lots, and
			// error codes are routinely formatted XXX-XXX-XXXX. A same-line
			// occurrence is strong evidence the number is not a phone.
			"error code", "fault code", "order reference", "order ref",
			"rma", "serial", "serial number", "s/n", "part no", "part number",
			"case number", "permit", "batch", "lot", "sku", "fixture",
			"row id", "bib number", "model", "promo code", "certificate",
			"asset tag", "bin", "accession", "stamped", "etched",
		},
		knownTestPatterns: []string{
			"555-0", "555-1", "000-000", "111-111", "222-222", "333-333",
			"444-444", "555-555", "666-666", "777-777", "888-888", "999-999",
			"123-456", "987-654", "000-0000", "111-1111", "test", "example",
		},
		testPhoneNumbers: []string{
			"555-0100", "555-0199", "555-1212", "867-5309", "123-456-7890",
			"000-000-0000", "111-111-1111", "222-222-2222", "333-333-3333",
			"444-444-4444", "555-555-5555", "666-666-6666", "777-777-7777",
			"888-888-8888", "999-999-9999", "987-654-3210", "012-345-6789",
		},
		countryCodeMap: initCountryCodeMap(),
	}

	// Initialize sorted country codes for optimized lookup
	v.sortedCountryCodes = initSortedCountryCodes(v.countryCodeMap)

	// Precompute lowercased keyword lists and the longest keyword length so the
	// per-match context analysis avoids repeated strings.ToLower(keyword) work and
	// can bound its boundary-probe windows.
	v.positiveKeywordsLower = lowerAll(v.positiveKeywords)
	v.negativeKeywordsLower = lowerAll(v.negativeKeywords)
	for _, kw := range v.positiveKeywordsLower {
		if len(kw) > v.maxKeywordLen {
			v.maxKeywordLen = len(kw)
		}
	}
	for _, kw := range v.negativeKeywordsLower {
		if len(kw) > v.maxKeywordLen {
			v.maxKeywordLen = len(kw)
		}
	}

	// Initialize phone patterns
	// NOTE: Patterns starting with non-word chars like ( or + use (?:^|\s|[,;|"'<>])
	// instead of \b because \b doesn't match between two non-word characters.
	v.patterns = []phonePattern{
		// US/Canada formats
		{
			name:    "US_Standard",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\(\d{3}\)\s?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "(XXX) XXX-XXXX",
		},
		{
			name:    "US_Dashed",
			regex:   regexp.MustCompile(`\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b`),
			country: "US/CA",
			format:  "XXX-XXX-XXXX",
		},
		{
			name:    "US_Plain",
			regex:   regexp.MustCompile(`\b\d{10}\b`),
			country: "US/CA",
			format:  "XXXXXXXXXX",
		},
		{
			name:    "US_International",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+1[-.\s]?\(?(\d{3})\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "+1 (XXX) XXX-XXXX",
		},
		// International formats
		{
			name: "International_Plus",
			// Tightened (M10): the middle/last groups now require 2-4 / 3-9 digits
			// so dotted version tags like "+2024.1.1" or "+1.2.3.4" (groups of 1)
			// no longer match as international phone numbers, while real numbers
			// (+44 20 7946 0958, +1 415 555 2671, +12025550173) still do.
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+\d{1,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{3,9}\b`),
			country: "International",
			format:  "+XX XXXX XXXX XXXX",
		},
		{
			name:    "International_00",
			regex:   regexp.MustCompile(`\b00\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b`),
			country: "International",
			format:  "00XX XXXX XXXX XXXX",
		},
		// UK formats
		{
			name: "UK_Standard",
			// Allow an optional THIRD group (M9): a real UK national number like
			// "0161 496 0345" is area + two subscriber groups, which the previous
			// two-group pattern truncated to "0161 496".
			regex:   regexp.MustCompile(`\b0\d{2,4}[-.\s]?\d{3,8}([-.\s]\d{3,4})?\b`),
			country: "UK",
			format:  "0XXX XXXXXXXX",
		},
		{
			name:    "UK_International",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+44[-.\s]?\d{1,4}[-.\s]?\d{3,8}\b`),
			country: "UK",
			format:  "+44 XXXX XXXXXXXX",
		},
		// European formats
		{
			name: "European",
			// Tightened (M10): last group requires 3-4 digits and inner groups
			// 2-4, so dotted version tags like "+2024.1.1" / "+1.2.3.4" no longer
			// match as European phone numbers.
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+\d{2}[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{3,4}\b`),
			country: "Europe",
			format:  "+XX XXXX XXXX XXXX",
		},
		// Mobile-specific patterns
		{
			name:    "Mobile_International",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b`),
			country: "Mobile",
			format:  "+XXX XXXX XXXX XXXX",
		},
		// Extension patterns
		{
			name:    "US_With_Extension",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\(?(\d{3})\)?[-.\s]?\d{3}[-.\s]?\d{4}[-.\s]?(?:ext\.?|extension|x)[-.\s]?\d{1,6}\b`),
			country: "US/CA",
			format:  "(XXX) XXX-XXXX ext XXXX",
		},
		{
			name:    "International_With_Extension",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}[-.\s]?(?:ext\.?|extension|x)[-.\s]?\d{1,6}\b`),
			country: "International",
			format:  "+XX XXXX XXXX ext XXXX",
		},
		// Toll-free patterns
		{
			name:    "US_TollFree",
			regex:   regexp.MustCompile(`\b(?:1[-.\s]?)?(?:800|833|844|855|866|877|888)[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "1-800-XXX-XXXX",
		},
		{
			name:    "US_TollFree_Parentheses",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])(?:1[-.\s]?)?\((?:800|833|844|855|866|877|888)\)[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "1-(800) XXX-XXXX",
		},
		{
			name:    "US_TollFree_International",
			regex:   regexp.MustCompile(`(?:^|[\s,;|"'<>])\+1[-.\s]?(?:800|833|844|855|866|877|888)[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			country: "US/CA",
			format:  "+1-800-XXX-XXXX",
		},
	}

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for phone numbers
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
		finishTiming = v.observer.StartTiming("phone_validator", "validate_content", originalPath)
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Process each pattern type
	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": len(matches)})
			}
			return matches, ctx.Err()
		}
		// Per-line state hoisted out of the per-match loop:
		//   - dedup indexes the cleaned-digit form of every match already accepted
		//     on THIS line so duplicate detection is O(1)-amortized per candidate
		//     instead of re-running the clean regex and a full containment scan over
		//     the whole accumulated match list (this O(M^2) churn was the single-line
		//     DoS). Semantics are identical to the original isDuplicateMatch.
		//   - lineIsTabular is a line-level property (delimiters / name-phone
		//     shape); isTabularData never inspected the individual match, so it is
		//     computed once per line rather than once per match.
		dedup := newLineDedup()
		lineIsTabular := v.isTabularDataLine(line)

		// For long lines, the original per-match context analysis re-lowercased
		// and re-scanned the WHOLE line for every match (O(matches x line length),
		// the dominant cost of the single-line DoS). Build the per-line keyword
		// cache once and use the hoisted, boundary-probe context path instead.
		// Short lines keep the original per-match construction so normal input is
		// byte-for-byte unchanged.
		lineLong := len(line) > hoistContextLineThreshold
		var lineCtx *lineKeywordCtx
		if lineLong {
			lineCtx = v.buildLineKeywordCtx(line, strings.ToLower(line))
		}

		for _, pattern := range v.patterns {
			// FindAllStringIndex yields each match's byte offset within the line, so
			// we no longer call strings.Index(line, match) per match (O(M*L) -> O(M))
			// and we avoid the latent bug where strings.Index returns the FIRST
			// occurrence of a duplicated token rather than the actual one.
			locs := pattern.regex.FindAllStringIndex(line, -1)

			for _, loc := range locs {
				rawMatch := line[loc[0]:loc[1]]
				// Trim leading delimiter captured by boundary group (?:^|[\s,;|"'<>]).
				// Advance the start offset past trimmed bytes so it still points at
				// the real match.
				match := strings.TrimLeft(rawMatch, " \t,;|\"'<>\r\n")
				matchIndex := loc[0] + (len(rawMatch) - len(match))
				matchEnd := matchIndex + len(match)

				// Skip if this match was already found by another pattern on this
				// line. Same containment semantics as isDuplicateMatch, evaluated in
				// O(1)-amortized time against the per-line dedup index.
				cleanNew := v.cleanPhoneNumber(match)
				if dedup.isDuplicate(cleanNew) {
					continue
				}

				// Skip if this phone number is embedded within an identifier or resource ID
				if v.isEmbeddedInIdentifierAt(match, line, matchIndex) {
					continue
				}

				// Calculate confidence
				confidence, checks := v.CalculateConfidence(match)

				// Analyze phone structure
				phoneInfo := v.AnalyzePhoneStructure(match, pattern)

				// For preprocessed content, create a context info
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract context around the match in the line using the known
				// offset (no rescan).
				start := matchIndex - 50
				if start < 0 {
					start = 0
				}
				end := matchEnd + 50
				if end > len(line) {
					end = len(line)
				}
				contextInfo.BeforeText = line[start:matchIndex]
				contextInfo.AfterText = line[matchEnd:end]

				// Analyze context and adjust confidence. Long lines use the hoisted
				// path (per-line keyword cache + per-match boundary probes); short
				// lines use the original whole-line construction unchanged.
				var contextImpact float64
				if lineLong {
					contextImpact = v.analyzeContextHoisted(match, contextInfo.BeforeText, contextInfo.AfterText, line, matchIndex, lineCtx)
				} else {
					contextImpact = v.AnalyzeContextAt(match, contextInfo, line, matchIndex)
				}

				// Check for tabular data and boost confidence (line-level flag)
				if lineIsTabular {
					contextImpact += 15 // Boost for tabular data
				}

				confidence += contextImpact

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

				// Store keywords found in context (hoisted for long lines).
				if lineLong {
					lowerBefore := strings.ToLower(contextInfo.BeforeText)
					lowerAfter := strings.ToLower(contextInfo.AfterText)
					probeBefore, probeAfter := boundaryProbes(lowerBefore, lowerAfter, lineCtx)
					contextInfo.PositiveKeywords = findKeywordsHoisted(v.positiveKeywords, v.positiveKeywordsLower, lineCtx.posInLowerLine, probeBefore, probeAfter)
					contextInfo.NegativeKeywords = findKeywordsHoisted(v.negativeKeywords, v.negativeKeywordsLower, lineCtx.negInLowerLine, probeBefore, probeAfter)
				} else {
					contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
					contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
				}
				contextInfo.ConfidenceImpact = contextImpact

				matches = append(matches, detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "PHONE",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "phone",
					Context:    contextInfo,
					Metadata: map[string]any{
						"country":           phoneInfo["country"],
						"format":            phoneInfo["format"],
						"pattern_name":      phoneInfo["pattern_name"],
						"clean_number":      phoneInfo["clean_number"],
						"validation_checks": checks,
						"context_impact":    contextInfo.ConfidenceImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
				// Record the accepted match's cleaned digits for subsequent dedup
				// on this line. Only matches that actually land in `matches`
				// participate in dedup, exactly as before (isDuplicateMatch scanned
				// the accumulated `matches`).
				dedup.add(cleanNew)
			}
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(strings.Split(content, "\n")),
			"content_length":  len(content),
		})
	}

	return matches, nil
}

// dedupMaxCleanLen bounds the cleaned-digit length for which the substring index
// is maintained. Phone-pattern matches clean to well under this many digits, so
// in practice every accepted match is indexed; the cap only guards against a
// pathological match cleaning to an enormous digit run (which would make the
// O(L^2) substring enumeration costly). Longer strings fall back to the linear
// scan in isDuplicateAgainst, which is still O(remaining) and rare.
const dedupMaxCleanLen = 32

// lineDedup reproduces isDuplicateMatch's per-line containment semantics — a new
// cleaned-digit string s is a duplicate of an accepted string e when
// e == s, s is a substring of e, or e is a substring of s — but in
// O(len(s)^2)-amortized time per candidate instead of scanning every accepted
// match. Because cleaned phone numbers are short and bounded (dedupMaxCleanLen),
// that per-candidate cost is effectively constant, removing the O(M^2) blowup on
// a single match-dense line.
//
// It maintains two indexes over the accepted strings:
//   - exact: the set of accepted strings (used to test "some accepted e is a
//     substring of s" by enumerating substrings of s).
//   - subOfAccepted: the set of ALL substrings of every accepted string (used to
//     test "s is a substring of some accepted e", which includes s == e).
//
// A small linear fallback list holds any accepted string longer than
// dedupMaxCleanLen so semantics stay exact without enumerating huge substring
// sets.
type lineDedup struct {
	exact         map[string]struct{}
	subOfAccepted map[string]struct{}
	longFallback  []string
}

func newLineDedup() *lineDedup {
	return &lineDedup{
		exact:         make(map[string]struct{}, 16),
		subOfAccepted: make(map[string]struct{}, 64),
	}
}

// isDuplicate reports whether cleanNew duplicates an already-accepted string,
// matching isDuplicateMatch exactly. Empty strings are never duplicates (the
// original skipped empty cleaned values on both sides).
func (d *lineDedup) isDuplicate(cleanNew string) bool {
	if cleanNew == "" {
		return false
	}

	// "cleanNew is a substring of (or equal to) some accepted string."
	if _, ok := d.subOfAccepted[cleanNew]; ok {
		return true
	}

	// "some accepted string is a substring of (or equal to) cleanNew": every
	// accepted string is shorter than or equal to cleanNew in this branch, so it
	// must appear as one of cleanNew's substrings, which are all present in the
	// exact set if it is a duplicate.
	if len(cleanNew) <= dedupMaxCleanLen {
		n := len(cleanNew)
		for i := 0; i < n; i++ {
			for j := i + 1; j <= n; j++ {
				if _, ok := d.exact[cleanNew[i:j]]; ok {
					return true
				}
			}
		}
	} else {
		// cleanNew is too long to enumerate cheaply; fall back to direct
		// containment against the exact accepted strings.
		for e := range d.exact {
			if strings.Contains(cleanNew, e) {
				return true
			}
		}
	}

	// Compare against any over-long accepted strings kept out of the indexes.
	for _, e := range d.longFallback {
		if e == cleanNew ||
			strings.Contains(e, cleanNew) ||
			strings.Contains(cleanNew, e) {
			return true
		}
	}

	return false
}

// add records an accepted match's cleaned-digit string. Empty strings are not
// stored (the original isDuplicateMatch skipped matches whose cleaned form was
// empty), so they never participate in dedup.
func (d *lineDedup) add(cleanStr string) {
	if cleanStr == "" {
		return
	}
	d.exact[cleanStr] = struct{}{}
	if len(cleanStr) <= dedupMaxCleanLen {
		n := len(cleanStr)
		for i := 0; i < n; i++ {
			for j := i + 1; j <= n; j++ {
				d.subOfAccepted[cleanStr[i:j]] = struct{}{}
			}
		}
	} else {
		d.longFallback = append(d.longFallback, cleanStr)
	}
}

// lowerAll returns a slice of the lowercased forms of the input strings.
func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// hoistContextLineThreshold is the line length (bytes) above which the per-match
// context analysis switches from the original whole-line construction to the
// hoisted path. Below it, lines are short enough that the original code runs as
// before (so all normal input is byte-for-byte unchanged); above it, the
// whole-line scans would otherwise be O(matches x line length) and cause the
// single-line DoS. It is a var (not a const) only so equivalence tests can force
// either path; production never mutates it.
var hoistContextLineThreshold = 4096

// lineKeywordCtx caches, once per line, the keyword presence facts that the
// original per-match AnalyzeContext/findKeywords recomputed for every match by
// scanning the entire line. For each keyword it records:
//   - inLowerLine: keyword present in strings.ToLower(line) — i.e. present in the
//     line portion of the lowercased fullContext.
//   - inRawLine: keyword present in the raw (non-lowercased) line — this mirrors
//     the original "same line" check strings.Contains(context.FullLine,
//     strings.ToLower(keyword)), which compared against the un-lowercased line.
//
// It also stores lowercased head/tail windows of the line so per-match boundary
// probes (BeforeText|line and line|AfterText junctions introduced by the
// fullContext concatenation) can be evaluated in O(maxKeywordLen) time.
type lineKeywordCtx struct {
	posInLowerLine []bool
	posInRawLine   []bool
	negInLowerLine []bool
	negInRawLine   []bool

	lowerHead string // lowercased prefix of the line, length up to maxKeywordLen
	lowerTail string // lowercased suffix of the line, length up to maxKeywordLen
}

// buildLineKeywordCtx precomputes per-line keyword presence for the hoisted
// context path. line is the raw line; lowerLine is strings.ToLower(line).
func (v *Validator) buildLineKeywordCtx(line, lowerLine string) *lineKeywordCtx {
	lc := &lineKeywordCtx{
		posInLowerLine: make([]bool, len(v.positiveKeywordsLower)),
		posInRawLine:   make([]bool, len(v.positiveKeywordsLower)),
		negInLowerLine: make([]bool, len(v.negativeKeywordsLower)),
		negInRawLine:   make([]bool, len(v.negativeKeywordsLower)),
	}
	for i, kw := range v.positiveKeywordsLower {
		lc.posInLowerLine[i] = strings.Contains(lowerLine, kw)
		lc.posInRawLine[i] = strings.Contains(line, kw)
	}
	for i, kw := range v.negativeKeywordsLower {
		lc.negInLowerLine[i] = strings.Contains(lowerLine, kw)
		lc.negInRawLine[i] = strings.Contains(line, kw)
	}

	w := v.maxKeywordLen
	if w > len(lowerLine) {
		w = len(lowerLine)
	}
	lc.lowerHead = lowerLine[:w]
	lc.lowerTail = lowerLine[len(lowerLine)-w:]
	return lc
}

// AnalyzeContext analyzes the context around a match and returns a confidence
// adjustment. It locates the match within the line; callers on the hot path
// should use AnalyzeContextAt to pass a precomputed offset instead.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	return v.AnalyzeContextAt(match, context, context.FullLine, strings.Index(context.FullLine, match))
}

// AnalyzeContextAt is the offset-aware form of AnalyzeContext. matchIndex is the
// byte offset of match within line (matchIndex < 0 means "not found"), which lets
// hasPhoneStructure skip its own strings.Index rescan.
func (v *Validator) AnalyzeContextAt(match string, context detector.ContextInfo, line string, matchIndex int) float64 {
	// CRITICAL: Check for structural indicators first (highest priority)
	// This uses what comes BEFORE/AFTER the match rather than keywords
	if !v.hasPhoneStructureAt(match, line, matchIndex) {
		// This is NOT a phone number (resource ID, timestamp, etc.)
		return -100 // Zero out confidence completely
	}

	// Combine all context text for analysis
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var confidenceImpact float64 = 0
	var hasPositiveKeywords bool = false

	// Check for positive keywords (increase confidence)
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			hasPositiveKeywords = true
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact += 15 // +15% for keywords in the same line
			} else {
				confidenceImpact += 8 // +8% for keywords in surrounding context
			}
		}
	}

	// Apply moderate penalty if NO positive phone context keywords are found
	// Structural analysis handles most false positives, so this is less critical
	if !hasPositiveKeywords {
		confidenceImpact -= 20 // -20% penalty for no phone context (reduced from -70%)
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact -= 35 // -35% for negative keywords in the same line
			} else {
				confidenceImpact -= 18 // -18% for negative keywords in surrounding context
			}
		}
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 40 {
		confidenceImpact = 40 // Maximum +40% boost
	} else if confidenceImpact < -80 {
		confidenceImpact = -80 // Maximum -80% reduction
	}

	return confidenceImpact
}

// findKeywords returns a list of keywords found in the context
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var found []string
	for _, keyword := range keywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			found = append(found, keyword)
		}
	}

	return found
}

// boundaryProbes builds the two short lowercased probe strings that reproduce the
// only keyword matches the fullContext concatenation can introduce beyond those
// already present in the line: a keyword spanning the
// BeforeText|" "|line junction or the line|" "|AfterText junction. Because the
// hoisted path only runs when the line is far longer than any keyword, no keyword
// can span the entire line, so these two probes are exhaustive.
func boundaryProbes(lowerBefore, lowerAfter string, lc *lineKeywordCtx) (string, string) {
	return lowerBefore + " " + lc.lowerHead, lc.lowerTail + " " + lowerAfter
}

// keywordInFullContext reports whether the i-th keyword (already lowercased,
// value lowerKw) is present in the lowercased fullContext, using the per-line
// cache plus the per-match boundary probes. This is exactly
// strings.Contains(fullContext, lowerKw) for the hoisted path.
func keywordInFullContext(inLowerLine bool, lowerKw, probeBefore, probeAfter string) bool {
	if inLowerLine {
		return true
	}
	return strings.Contains(probeBefore, lowerKw) || strings.Contains(probeAfter, lowerKw)
}

// analyzeContextHoisted reproduces AnalyzeContextAt's keyword scoring for long
// lines using the per-line keyword cache and per-match boundary probes, avoiding
// the O(matches x line length) whole-line rescans. The structural gate
// (hasPhoneStructureAt) and the arithmetic/caps are identical to AnalyzeContextAt.
func (v *Validator) analyzeContextHoisted(match string, before, after, line string, matchIndex int, lc *lineKeywordCtx) float64 {
	if !v.hasPhoneStructureAt(match, line, matchIndex) {
		return -100
	}

	lowerBefore := strings.ToLower(before)
	lowerAfter := strings.ToLower(after)
	probeBefore, probeAfter := boundaryProbes(lowerBefore, lowerAfter, lc)

	var confidenceImpact float64
	var hasPositiveKeywords bool

	for i, kw := range v.positiveKeywordsLower {
		if keywordInFullContext(lc.posInLowerLine[i], kw, probeBefore, probeAfter) {
			hasPositiveKeywords = true
			// Same-line bonus mirrors the original strings.Contains(FullLine,
			// lowerKw) against the RAW (un-lowercased) line.
			if lc.posInRawLine[i] {
				confidenceImpact += 15
			} else {
				confidenceImpact += 8
			}
		}
	}

	if !hasPositiveKeywords {
		confidenceImpact -= 20
	}

	for i, kw := range v.negativeKeywordsLower {
		if keywordInFullContext(lc.negInLowerLine[i], kw, probeBefore, probeAfter) {
			if lc.negInRawLine[i] {
				confidenceImpact -= 35
			} else {
				confidenceImpact -= 18
			}
		}
	}

	if confidenceImpact > 40 {
		confidenceImpact = 40
	} else if confidenceImpact < -80 {
		confidenceImpact = -80
	}

	return confidenceImpact
}

// findKeywordsHoisted is the long-line equivalent of findKeywords: it returns the
// original (source-cased) keywords present in the lowercased fullContext, using
// the per-line cache plus per-match boundary probes. keywords is the source list
// and lowerKeywords/inLowerLine are its precomputed lowercased forms and per-line
// presence flags (parallel slices).
func findKeywordsHoisted(keywords, lowerKeywords []string, inLowerLine []bool, probeBefore, probeAfter string) []string {
	var found []string
	for i, lowerKw := range lowerKeywords {
		if keywordInFullContext(inLowerLine[i], lowerKw, probeBefore, probeAfter) {
			found = append(found, keywords[i])
		}
	}
	return found
}

// CalculateConfidence calculates the confidence score for a potential phone number
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Find the best matching pattern for this phone number
	var bestPattern phonePattern
	found := false

	for _, pattern := range v.patterns {
		if pattern.regex.MatchString(match) {
			bestPattern = pattern
			found = true
			break
		}
	}

	// If no pattern matches, use a default pattern
	if !found {
		bestPattern = phonePattern{
			name:    "Unknown",
			country: "Unknown",
			format:  "Unknown",
		}
	}

	return v.calculateConfidenceWithPattern(match, bestPattern)
}

// calculateConfidenceWithPattern calculates confidence with a specific pattern
func (v *Validator) calculateConfidenceWithPattern(match string, pattern phonePattern) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_format":      true,
		"reasonable_length": true,
		"not_test_number":   true,
		"valid_digits":      true,
		"not_sequential":    true,
		"not_repeating":     true,
		"valid_country":     false,
		"not_ssn_pattern":   true,
		"not_timestamp":     true,
	}

	confidence := 100.0
	cleanMatch := v.cleanPhoneNumber(match)

	// CRITICAL: Check if this looks like an SSN pattern (XXX-XX-XXXX) vs phone (XXX-XXX-XXXX)
	if v.looksLikeSSN(match) {
		confidence -= 50 // Heavy penalty for SSN-like patterns
		checks["not_ssn_pattern"] = false
	}

	// Check if this looks like a timestamp
	if v.looksLikeTimestamp(match) {
		confidence -= 60 // Heavy penalty for timestamp patterns
		checks["not_timestamp"] = false
	} else {
		checks["not_timestamp"] = true
	}

	// Check if this looks like a credit card fragment
	if v.looksLikeCreditCard(match) {
		confidence -= 60 // Heavy penalty for credit card fragments
		checks["valid_format"] = false
	}

	// Check if this is obviously an invalid number pattern
	if v.looksLikeInvalidNumber(match) {
		confidence -= 70 // Very heavy penalty for invalid patterns
		checks["valid_format"] = false
	}

	// Check reasonable length (15%)
	if len(cleanMatch) < 7 || len(cleanMatch) > 15 {
		confidence -= 15
		checks["reasonable_length"] = false
	}

	// Check if it's a known test number (20%)
	if v.isTestPhoneNumber(match) {
		confidence -= 20
		checks["not_test_number"] = false
	}

	// Check for valid digits only (10%)
	if !phoneValidCharsPattern.MatchString(match) {
		confidence -= 10
		checks["valid_digits"] = false
	}

	// Check for sequential patterns (15%)
	if v.isSequentialNumber(cleanMatch) {
		confidence -= 15
		checks["not_sequential"] = false
	}

	// Check for repeating patterns (15%)
	if v.isRepeatingNumber(cleanMatch) {
		confidence -= 15
		checks["not_repeating"] = false
	}

	// Check country/format validity (15%)
	if v.isValidCountryFormat(match, pattern) {
		checks["valid_country"] = true
		confidence += 5 // Small boost for valid country format
	} else {
		confidence -= 10
	}

	// Boost confidence for well-formatted international numbers
	if strings.HasPrefix(match, "+") && len(cleanMatch) >= 10 {
		confidence += 10
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// AnalyzePhoneStructure breaks down the phone number into components
func (v *Validator) AnalyzePhoneStructure(phone string, pattern phonePattern) map[string]string {
	cleanNumber := v.cleanPhoneNumber(phone)

	result := map[string]string{
		"pattern_name": pattern.name,
		"country":      pattern.country,
		"format":       pattern.format,
		"clean_number": cleanNumber,
		"original":     phone,
	}

	// Extract country code if present
	if strings.HasPrefix(phone, "+") {
		// Use optimized lookup with sorted codes (longest first)
		for _, code := range v.sortedCountryCodes {
			if strings.HasPrefix(cleanNumber[1:], code) { // Skip the '+' prefix
				result["country_code"] = code
				result["country_name"] = v.countryCodeMap[code]
				break
			}
		}
	}

	return result
}

// Helper methods
func (v *Validator) cleanPhoneNumber(phone string) string {
	// Remove all non-digit characters except '+'. This is the byte-scan
	// equivalent of phoneCleanPattern.ReplaceAllString(phone, "") (regex
	// `[^\d+]`), kept inline because cleanPhoneNumber is called many times per
	// match on the hot path and the regex engine dominated those calls. ASCII
	// digits and '+' are single-byte, and every other byte (including the lead
	// bytes of multi-byte runes) is dropped — matching the regex's behavior of
	// removing any rune that is not an ASCII digit or '+'.
	if !needsClean(phone) {
		return phone
	}
	b := make([]byte, 0, len(phone))
	for i := 0; i < len(phone); i++ {
		c := phone[i]
		if (c >= '0' && c <= '9') || c == '+' {
			b = append(b, c)
		}
	}
	return string(b)
}

// needsClean reports whether phone contains any byte that cleanPhoneNumber would
// strip, letting the common already-clean case avoid an allocation.
func needsClean(phone string) bool {
	for i := 0; i < len(phone); i++ {
		c := phone[i]
		if !((c >= '0' && c <= '9') || c == '+') {
			return true
		}
	}
	return false
}

// hasPhoneSeparators reports whether the raw match is formatted like a phone
// number — i.e. it contains parentheses, dashes, dots, spaces or a leading "+".
// A bare run of digits with no separators is what timestamps, IDs and serials
// look like; the timestamp/date heuristics should only fire on those, not on a
// number a human clearly formatted as a phone (e.g. "(212) 555-0173").
func (v *Validator) hasPhoneSeparators(match string) bool {
	return strings.ContainsAny(match, "()-. ") || strings.HasPrefix(match, "+")
}

func (v *Validator) isTestPhoneNumber(phone string) bool {
	lowerPhone := strings.ToLower(phone)
	cleanDigits := v.cleanPhoneNumber(phone)

	// Match full known test numbers by cleaned-digit equality, not substring
	// (L29): substring matching on short fragments like "123-456" / "987-654"
	// penalized real numbers that merely contained those runs.
	for _, testNumber := range v.testPhoneNumbers {
		if cleanDigits == v.cleanPhoneNumber(testNumber) {
			return true
		}
	}

	// Textual placeholder words anywhere in the raw value are still a test signal.
	for _, word := range []string{"test", "example"} {
		if strings.Contains(lowerPhone, word) {
			return true
		}
	}

	// The 555-0100..555-0199 exchange is the reserved fictional/test range
	// (NANP): in cleaned digits that is "55501" + two digits. Match it
	// structurally rather than via the broad "555-0" fragment, which previously
	// also flagged real numbers containing that run.
	if reFictional555.MatchString(cleanDigits) {
		return true
	}

	return false
}

func (v *Validator) isSequentialNumber(cleanNumber string) bool {
	if len(cleanNumber) < 7 {
		return false
	}

	// Remove country code if present
	digits := cleanNumber
	if strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}

	// Check for ascending sequence (123456...)
	sequential := 0
	for i := 1; i < len(digits); i++ {
		if digits[i] == digits[i-1]+1 {
			sequential++
		} else {
			sequential = 0
		}
		if sequential >= 4 { // 5 consecutive ascending digits
			return true
		}
	}

	// Check for descending sequence (987654...)
	sequential = 0
	for i := 1; i < len(digits); i++ {
		if digits[i] == digits[i-1]-1 {
			sequential++
		} else {
			sequential = 0
		}
		if sequential >= 4 { // 5 consecutive descending digits
			return true
		}
	}

	return false
}

func (v *Validator) isRepeatingNumber(cleanNumber string) bool {
	if len(cleanNumber) < 7 {
		return false
	}

	// Remove country code if present
	digits := cleanNumber
	if strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}

	// Check for 5+ consecutive identical digits
	for i := 0; i < len(digits)-4; i++ {
		allSame := true
		for j := 1; j < 5; j++ {
			if digits[i+j] != digits[i] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}

func (v *Validator) isValidCountryFormat(phone string, pattern phonePattern) bool {
	// Basic validation based on pattern country
	switch pattern.country {
	case "US/CA":
		// US/Canada numbers should be 10 digits (excluding country code). Strip a
		// leading country code whether written "+1" or as a bare "1" (L30): a
		// toll-free / long-distance number like "1-800-555-1234" cleans to 11
		// digits, and the previous code only stripped "+1", so it wrongly scored
		// the bare-1 form as an invalid country format (-10 instead of +5).
		clean := v.cleanPhoneNumber(phone)
		clean = strings.TrimPrefix(clean, "+")
		if len(clean) == 11 && strings.HasPrefix(clean, "1") {
			clean = clean[1:]
		}
		return len(clean) == 10
	case "UK":
		// UK numbers vary but should follow basic format
		if strings.HasPrefix(phone, "+44") || strings.HasPrefix(phone, "0") {
			return true
		}
	case "International", "Europe", "Mobile":
		// Basic international format validation
		return strings.HasPrefix(phone, "+") || strings.HasPrefix(phone, "00")
	}

	return true // Default to valid for unknown patterns
}

// initSortedCountryCodes creates a sorted slice of country codes (longest first) for optimized lookup
func initSortedCountryCodes(countryCodeMap map[string]string) []string {
	codes := make([]string, 0, len(countryCodeMap))
	for code := range countryCodeMap {
		codes = append(codes, code)
	}

	// Sort by length (longest first) to match longer codes before shorter ones
	// This prevents "1" from matching before "1242" (Bahamas)
	sort.Slice(codes, func(i, j int) bool {
		return len(codes[i]) > len(codes[j])
	})

	return codes
}

// Initialize country code map
func initCountryCodeMap() map[string]string {
	return map[string]string{
		"1":   "US/Canada",
		"44":  "United Kingdom",
		"33":  "France",
		"49":  "Germany",
		"39":  "Italy",
		"34":  "Spain",
		"31":  "Netherlands",
		"32":  "Belgium",
		"41":  "Switzerland",
		"43":  "Austria",
		"45":  "Denmark",
		"46":  "Sweden",
		"47":  "Norway",
		"358": "Finland",
		"7":   "Russia",
		"86":  "China",
		"81":  "Japan",
		"82":  "South Korea",
		"91":  "India",
		"61":  "Australia",
		"64":  "New Zealand",
		"55":  "Brazil",
		"52":  "Mexico",
		"54":  "Argentina",
		"56":  "Chile",
		"57":  "Colombia",
		"58":  "Venezuela",
		"51":  "Peru",
		"27":  "South Africa",
		"20":  "Egypt",
		"212": "Morocco",
		"213": "Algeria",
		"216": "Tunisia",
		"218": "Libya",
		"234": "Nigeria",
		"254": "Kenya",
	}
}

// looksLikeSSN checks if the pattern matches SSN format (XXX-XX-XXXX) instead of phone
func (v *Validator) looksLikeSSN(match string) bool {
	// SSN pattern: exactly 9 digits in XXX-XX-XXXX format
	return ssnPattern.MatchString(match)
}

// looksLikeCreditCard checks if the pattern matches credit card fragments
func (v *Validator) looksLikeCreditCard(match string) bool {
	clean := v.cleanPhoneNumber(match)

	// Credit card fragments often have 4 digits
	if len(clean) == 4 {
		return true
	}

	// Patterns like XXXX-XXXX (8 digits) are often credit card fragments
	if len(clean) == 8 && strings.Contains(match, "-") {
		return true
	}

	// Look for patterns that start with common credit card prefixes in wrong context
	commonCCPrefixes := []string{"4", "5", "6", "3"}
	for _, prefix := range commonCCPrefixes {
		if strings.HasPrefix(clean, prefix) && len(clean) >= 4 && len(clean) <= 8 {
			return true
		}
	}

	return false
}

// looksLikeTimestamp checks if the pattern matches common timestamp formats.
//
// It only fires on a BARE run of digits with no phone separators: a number a
// human formatted with parens/dashes/spaces ("(212) 555-0173") is a phone, not
// a Unix timestamp, even though its 10-digit clean form (2125550173) falls in
// the 32-bit timestamp range — which is exactly how valid NANP area codes
// 200-214 (DC 202, NYC 212, 213/214) and the 19xx/20xx-prefixed long forms were
// being wrongly penalized -60.
func (v *Validator) looksLikeTimestamp(match string) bool {
	if v.hasPhoneSeparators(match) {
		return false
	}
	clean := v.cleanPhoneNumber(match)

	// Unix timestamp patterns (10 digits starting with 1 or 2)
	if len(clean) == 10 && (strings.HasPrefix(clean, "1") || strings.HasPrefix(clean, "2")) {
		// Check if it's in a reasonable timestamp range
		// 1000000000 = Sep 2001, 2147483647 = Jan 2038 (32-bit limit)
		if timestamp, err := strconv.ParseInt(clean, 10, 64); err == nil {
			if timestamp >= 1000000000 && timestamp <= 2147483647 {
				return true
			}
		}
	}

	// Millisecond timestamp patterns (13 digits starting with 1)
	if len(clean) == 13 && strings.HasPrefix(clean, "1") {
		if timestamp, err := strconv.ParseInt(clean, 10, 64); err == nil {
			if timestamp >= 1000000000000 && timestamp <= 2147483647000 {
				return true
			}
		}
	}

	// Date-like patterns that could be confused with phones
	// YYYYMMDDHHMMSS (14 digits starting with 19 or 20)
	if len(clean) >= 8 && (strings.HasPrefix(clean, "19") || strings.HasPrefix(clean, "20")) {
		// Basic year validation (1900-2099)
		if len(clean) >= 4 {
			year := clean[:4]
			if year >= "1900" && year <= "2099" {
				return true
			}
		}
	}

	return false
}

// looksLikeInvalidNumber checks for obviously invalid phone patterns
func (v *Validator) looksLikeInvalidNumber(match string) bool {
	clean := v.cleanPhoneNumber(match)

	// Patterns like +0000, 0000, 060000 are clearly invalid
	if strings.HasPrefix(clean, "+0000") || strings.HasPrefix(clean, "0000") {
		return true
	}

	// Numbers that are too short to be valid phones (less than 7 digits)
	if len(clean) < 7 {
		return true
	}

	// Numbers starting with a trunk "0" (UK/EU national format). These are valid
	// even when shorter than 10 digits, so we no longer reject them on length
	// alone (M8) — only the <7-digit floor above applies. A genuinely invalid
	// short leading-0 run is already caught by that floor.

	// All zeros or mostly zeros
	zeroCount := strings.Count(clean, "0")
	if float64(zeroCount)/float64(len(clean)) > 0.8 {
		return true
	}

	return false
}

// isTabularData checks if the phone number appears to be in a tabular format.
// The match argument is unused (the heuristic is purely line-level); it is kept
// for API compatibility and delegates to isTabularDataLine.
func (v *Validator) isTabularData(line, match string) bool {
	return v.isTabularDataLine(line)
}

// isTabularDataLine is the line-level tabular check, computed once per line on
// the hot path. It inspects only the line's delimiters / fixed-width spacing /
// name-phone shape — identical logic to the original isTabularData, with the
// regex scans (FindAllString / MatchString) run once per line instead of once
// per match.
func (v *Validator) isTabularDataLine(line string) bool {
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
	if len(phoneMultiSpacePattern.FindAllString(line, -1)) >= 2 {
		return true
	}

	// Check for common contact list patterns (names followed by phones)
	if namePhonePattern.MatchString(line) {
		return true
	}

	return false
}

// isEmbeddedInIdentifier checks if a phone number match is embedded within an identifier or resource ID
// This helps filter out false positives like "i-057034242931", "ami-050451375729", "vpc-1234567890"
func (v *Validator) isEmbeddedInIdentifier(match, line string) bool {
	return v.isEmbeddedInIdentifierAt(match, line, strings.Index(line, match))
}

// isEmbeddedInIdentifierAt is the offset-aware form of isEmbeddedInIdentifier.
// matchIndex is the byte offset of match within line (a negative value means the
// match was not located, in which case it is treated as not embedded).
func (v *Validator) isEmbeddedInIdentifierAt(match, line string, matchIndex int) bool {
	if matchIndex < 0 {
		return false
	}

	// Check character before the match
	if matchIndex > 0 {
		charBefore := line[matchIndex-1]
		// If the character before is alphanumeric or common identifier separators, this phone is embedded
		if (charBefore >= 'a' && charBefore <= 'z') ||
			(charBefore >= 'A' && charBefore <= 'Z') ||
			(charBefore >= '0' && charBefore <= '9') ||
			charBefore == '-' || charBefore == '_' || charBefore == ':' {
			return true
		}

		// Check for patterns like "Timestamp: 1234567890" where there's a space before the number
		// But exclude phone-related labels like "Phone:", "Tel:", etc.
		if charBefore == ' ' && matchIndex >= 2 {
			charBeforeSpace := line[matchIndex-2]
			if charBeforeSpace == ':' {
				// Extract the word before the colon to check if it's a phone-related label
				wordStart := matchIndex - 3
				for wordStart >= 0 && line[wordStart] != ' ' && line[wordStart] != '\t' {
					wordStart--
				}
				wordStart++ // Move to start of word

				if wordStart < matchIndex-2 {
					wordBeforeColon := strings.ToLower(line[wordStart : matchIndex-2])

					// Don't filter if this is a phone-related label
					phoneLabels := []string{"phone", "tel", "telephone", "mobile", "cell", "fax", "contact", "call", "emergency", "support", "office", "home", "work"}
					for _, label := range phoneLabels {
						if wordBeforeColon == label || strings.HasSuffix(wordBeforeColon, label) {
							return false // Don't filter - this is likely a real phone
						}
					}

					// Filter out non-phone identifier patterns
					identifierLabels := []string{"timestamp", "build", "version", "revision", "id", "key", "hash", "uuid", "guid", "token", "session", "request", "response"}
					for _, label := range identifierLabels {
						if wordBeforeColon == label || strings.HasSuffix(wordBeforeColon, label) {
							return true // Filter - this is an identifier
						}
					}
				}
			}
		}
	}

	// Check character after the match
	matchEnd := matchIndex + len(match)
	if matchEnd < len(line) {
		charAfter := line[matchEnd]
		// If the character after is alphanumeric or common identifier separators, this phone is embedded
		if (charAfter >= 'a' && charAfter <= 'z') ||
			(charAfter >= 'A' && charAfter <= 'Z') ||
			(charAfter >= '0' && charAfter <= '9') ||
			charAfter == '-' || charAfter == '_' || charAfter == ':' {
			return true
		}
	}

	// Additional check: look for common AWS/cloud resource patterns
	// Check if the match is part of a resource identifier pattern
	beforeContext := ""
	if matchIndex >= 10 {
		beforeContext = line[matchIndex-10 : matchIndex]
	} else {
		beforeContext = line[0:matchIndex]
	}

	afterContext := ""
	if matchEnd+10 <= len(line) {
		afterContext = line[matchEnd : matchEnd+10]
	} else {
		afterContext = line[matchEnd:]
	}

	fullContext := strings.ToLower(beforeContext + match + afterContext)

	// Common patterns that indicate this is an identifier, not a phone number
	identifierPatterns := []string{
		"instance", "ami-", "vpc-", "subnet-", "sg-", "igw-", "rtb-", "acl-",
		"vol-", "snap-", "eni-", "eip-", "nat-", "tgw-", "vpce-", "pcx-",
		"build", "version", "revision", "timestamp", "id:", "key:", "hash",
		"uuid", "guid", "token", "session", "request", "response",
	}

	for _, pattern := range identifierPatterns {
		if strings.Contains(fullContext, pattern) {
			return true
		}
	}

	return false
}

// hasPhoneStructure checks if the match is actually a phone number, not something else
// This uses structural analysis (what comes BEFORE/AFTER the match) rather than
// keyword matching, making it future-proof and context-agnostic.
func (v *Validator) hasPhoneStructure(match string, line string) bool {
	return v.hasPhoneStructureAt(match, line, strings.Index(line, match))
}

// hasPhoneStructureAt is the offset-aware form of hasPhoneStructure. matchIndex
// is the byte offset of match within line; a negative value means the match was
// not located and is treated as "not a phone structure" (same as the original
// strings.Index(line, match) < 0 guard).
func (v *Validator) hasPhoneStructureAt(match string, line string, matchIndex int) bool {
	if matchIndex < 0 {
		return false
	}

	// Get characters before and after the match
	var beforeMatch string
	if matchIndex >= 10 {
		beforeMatch = line[matchIndex-10 : matchIndex]
	} else if matchIndex > 0 {
		beforeMatch = line[0:matchIndex]
	}

	var afterMatch string
	matchEnd := matchIndex + len(match)
	if matchEnd+10 <= len(line) {
		afterMatch = line[matchEnd : matchEnd+10]
	} else if matchEnd < len(line) {
		afterMatch = line[matchEnd:]
	}

	// Check for NEGATIVE indicators (NOT a phone number)
	// These should be checked FIRST and return false immediately

	// 1. Resource ID patterns: prefix-digits or digits-suffix
	//    Examples: i-1234567890, ami-1234567890, vpc-1234567890
	if matchIndex > 0 {
		charBefore := line[matchIndex-1]

		// Check for resource ID patterns (letter-hyphen-digits)
		// But allow phone patterns like +1-555 or (555)
		if charBefore == '-' {
			// Check if there's a letter before the hyphen (resource ID pattern)
			if matchIndex >= 2 {
				charBeforeHyphen := line[matchIndex-2]
				if (charBeforeHyphen >= 'a' && charBeforeHyphen <= 'z') ||
					(charBeforeHyphen >= 'A' && charBeforeHyphen <= 'Z') {
					// This is likely a resource ID like ami-123456
					return false
				}
			}
			// If hyphen is preceded by digit or +, it's likely a phone number
			// Examples: +1-555, 1-800
		}

		// Underscore before digits indicates resource ID
		if charBefore == '_' {
			return false
		}

		// Letter immediately before (no space) indicates identifier
		// But allow closing parenthesis for phone formats like (555)
		if charBefore != ')' && charBefore != '+' {
			if (charBefore >= 'a' && charBefore <= 'z') || (charBefore >= 'A' && charBefore <= 'Z') {
				return false
			}
		}
	}

	// 2. Check what comes after the match
	if len(afterMatch) > 0 {
		firstChar := afterMatch[0]

		// Hyphen, underscore, or letter after indicates identifier/resource ID
		if firstChar == '-' || firstChar == '_' {
			return false
		}
		if (firstChar >= 'a' && firstChar <= 'z') || (firstChar >= 'A' && firstChar <= 'Z') {
			return false
		}

		// Colon after digits indicates ARN or timestamp
		//    Examples: arn:aws:iam::123456789012:role, timestamp:1234567890
		if firstChar == ':' {
			return false
		}
	}

	// 3. Check for ARN patterns in before context
	//    Examples: arn:aws:iam::, ::123456789012:
	if strings.Contains(beforeMatch, "::") || strings.Contains(beforeMatch, "arn:") {
		return false
	}

	// 4. Check for timestamp/build patterns in before context
	timestampIndicators := []string{"timestamp", "build", "created", "updated", "modified", "version"}
	beforeLower := strings.ToLower(beforeMatch)
	for _, indicator := range timestampIndicators {
		if strings.Contains(beforeLower, indicator) {
			// Check if this is a plain number (no separators) - likely timestamp
			cleanMatch := v.cleanPhoneNumber(match)
			if len(cleanMatch) == len(match) { // No separators removed = plain digits
				return false
			}
		}
	}

	// Check for POSITIVE indicators (IS a phone number)

	// 1. Phone terminators: space, comma, semicolon, period, closing punctuation
	if len(afterMatch) > 0 {
		firstChar := afterMatch[0]
		phoneTerminators := []byte{' ', '\t', ',', ';', '.', '!', '?', ')', ']', '}', '\n', '\r'}
		for _, terminator := range phoneTerminators {
			if firstChar == terminator {
				return true // Looks like a phone
			}
		}

		// Extension indicators
		if strings.HasPrefix(strings.ToLower(afterMatch), "ext") ||
			strings.HasPrefix(strings.ToLower(afterMatch), "x") {
			return true
		}
	}

	// 2. End of line
	if len(afterMatch) == 0 {
		return true
	}

	// 3. Phone has separators (dashes, spaces, parentheses)
	//    Plain digit sequences are more likely to be timestamps/IDs
	if strings.Contains(match, "-") || strings.Contains(match, " ") ||
		strings.Contains(match, "(") || strings.Contains(match, ")") {
		return true
	}

	// 4. Starts with + (international format)
	if strings.HasPrefix(match, "+") {
		return true
	}

	// Default: if ambiguous, assume it's a phone (favor false negatives over false positives)
	// But only if it has proper phone formatting
	cleanMatch := v.cleanPhoneNumber(match)
	hasFormatting := len(cleanMatch) < len(match) // Has separators

	return hasFormatting
}
