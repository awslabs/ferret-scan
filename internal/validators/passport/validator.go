// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	stdctx "context"
	"regexp"
	"strings"
	"unicode"

	"github.com/awslabs/ferret-scan/internal/context"
	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/execguard"
	"github.com/awslabs/ferret-scan/internal/observability"
)

// Package-level pre-compiled regexps for static patterns
var (
	// Country-specific format patterns
	reUSPassport     = regexp.MustCompile(`^[A-Z]\d{8}$`)
	reUKPassport     = regexp.MustCompile(`^\d{9}$`)
	reCanadaPassport = regexp.MustCompile(`^[A-Z]{2}\d{6}$`)
	reEUPassport     = regexp.MustCompile(`^[A-Z]{2}[A-Z0-9]{7}$`)

	// MRZ and generic character validation
	reMRZChars     = regexp.MustCompile(`^[A-Z0-9<]+$`)
	reGenericChars = regexp.MustCompile(`^[A-Z0-9]+$`)

	// Utility patterns
	reMultiSpace    = regexp.MustCompile(`\s{3,}`)
	reMultiSpace2   = regexp.MustCompile(`\s{2,}`)
	reTravelPattern = regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z0-9]{6,10}`)
	reDigitsOnly    = regexp.MustCompile(`^[0-9]+$`)

	// False positive patterns
	reFalsePositivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`^[A-Z]{2}\d{4}$`),
		regexp.MustCompile(`^(SKU|UPC|EAN)\d+$`),
		regexp.MustCompile(`^[A-Z]{3}-\d{4}$`),
	}

	// Form context patterns
	reFormPatterns = []*regexp.Regexp{
		regexp.MustCompile(`passport.*:`),
		regexp.MustCompile(`passport.*=`),
		regexp.MustCompile(`passport.*number.*:`),
		regexp.MustCompile(`passport.*no.*:`),
		regexp.MustCompile(`document.*:`),
		regexp.MustCompile(`document.*number.*:`),
		regexp.MustCompile(`travel.*document.*:`),
		regexp.MustCompile(`number.*:`),
		regexp.MustCompile(`no.*:`),
		regexp.MustCompile(`#.*:`),
	}
)

// Validator implements the detector.Validator interface for detecting
// passport numbers from various countries using regex patterns and contextual analysis.
type Validator struct {
	patterns         map[string]string
	compiledPatterns map[string]*regexp.Regexp

	// Keywords that suggest a passport context
	positiveKeywords []string

	// Keywords that suggest this is not a passport
	negativeKeywords []string

	// Valid country codes for passports
	validCountryCodes map[string]bool
	// validMRZCountryCodes holds 3-letter ICAO issuing-state codes used in the
	// MRZ (e.g. "GBR", "USA"), distinct from the 2-letter codes above.
	validMRZCountryCodes map[string]bool

	// Common English words that might be mistaken for passport numbers
	commonWords []string

	// Known test passport patterns
	knownTestPatterns []string

	// Enhanced context analysis
	contextAnalyzer *context.ContextAnalyzer

	// Travel-specific keywords for enhanced validation
	travelKeywords     []string
	governmentKeywords []string
	formKeywords       []string

	// Global test passport database
	globalTestPassports []string

	// Observability
	observer *observability.StandardObserver
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting passport numbers from various countries.
func NewValidator() *Validator {
	patterns := map[string]string{
		// Common passport formats by country - made more restrictive
		"US":     `\b[A-Z]\d{8}\b`,          // US: 1 letter followed by 8 digits
		"UK":     `\b\d{9}\b`,               // UK: 9 digits
		"Canada": `\b[A-Z]{2}\d{6}\b`,       // Canada: 2 letters followed by 6 digits
		"EU":     `\b[A-Z]{2}[A-Z0-9]{7}\b`, // EU: 2 letters followed by 7 alphanumeric chars
		// Removed overly broad Generic pattern - it was causing too many false positives
		// Machine Readable Zone (ICAO 9303). Line 1 of a TD3 passport MRZ is
		// "P" + document-type filler + 3-letter issuing state + name field,
		// e.g. "P<GBRSMITH<<JOHN<<...". The character after "P" is the
		// document sub-type, which for ordinary passports is the filler "<"
		// (it may also be a letter), so it must be matched by [A-Z<], not
		// [A-Z]. The previous patterns required a letter there (and MRZ_TD3
		// required three), so they never matched a standard passport MRZ.
		// No trailing \b: MRZ lines end in "<" or a digit, and "<" is a
		// non-word char so \b would fail after it.
		//
		// We require a literal "P<" prefix (the document-type filler for an
		// ordinary passport) followed by a 3-letter issuing state. Requiring
		// the "<" here — rather than [A-Z<] — is what stops a random uppercase
		// token like "PRUSA...<no fillers>" from matching: a real line-1 MRZ
		// for a passport begins "P<". The name field is then "<"-padded, which
		// the surfacing logic additionally checks (see hasMRZStructure).
		"MRZ":     `\bP<[A-Z]{3}[A-Z0-9<]{38,40}`, // Machine Readable Zone line 1 (~44-46 chars)
		"MRZ_TD3": `\bP<[A-Z]{3}[A-Z0-9<]{39}`,    // MRZ TD3 line 1 (exactly 44 chars)
	}

	compiledPatterns := make(map[string]*regexp.Regexp, len(patterns))
	for country, pattern := range patterns {
		compiledPatterns[country] = regexp.MustCompile(pattern)
	}

	return &Validator{
		patterns:         patterns,
		compiledPatterns: compiledPatterns,
		positiveKeywords: []string{
			// High-confidence passport-specific keywords
			"passport", "passport number", "passport no", "travel document",
			"travel document number", "document number", "document no",
			"mrz", "machine readable", "icao", "passport holder",

			// Medium-confidence travel-related keywords
			"visa", "immigration", "border control", "customs", "embassy", "consulate",
			"nationality", "citizenship", "issuing authority", "passport authority",

			// Lower-confidence general keywords
			"identification", "identity", "travel", "international", "foreign",
			"expiry", "expiration", "issue date", "valid until", "expires",
			"surname", "given name", "date of birth", "place of birth", "gender", "sex",
		},
		negativeKeywords: []string{
			// Test/fake data indicators
			"example", "test", "sample", "mock", "fake", "dummy", "placeholder",
			"template", "demo", "random", "generated", "simulation", "synthetic",

			// Technical identifiers
			"uuid", "guid", "serial", "serial number", "product code", "model",
			"version", "build", "revision", "commit", "hash", "checksum",

			// Business identifiers
			"tracking", "shipment", "order", "invoice", "receipt", "transaction",
			"customer", "account", "username", "login", "password", "pin",
			"reference", "confirmation", "booking", "reservation",

			// Database/system identifiers
			"primary key", "foreign key", "index", "database", "table", "record",
			"field", "column", "row", "entry", "item", "element",
		},
		validCountryCodes:    initValidCountryCodes(),
		validMRZCountryCodes: initValidMRZCountryCodes(),
		commonWords: []string{
			"positive", "negative", "passport", "document", "identity", "national",
			"personal", "official", "original", "certified", "verified", "approved",
			"accepted", "rejected", "expired", "renewed", "updated", "processed",
			"scanned", "uploaded", "downloaded", "attached", "included", "excluded",
		},
		knownTestPatterns: []string{
			"A00000000", "A11111111", "A12345678", "AA000000", "XX0000000",
			"000000000", "123456789", "AB123456", "AB000000", "XX0000000",
		},

		// Initialize context analyzer
		contextAnalyzer: context.NewContextAnalyzer(),

		// Travel-specific keywords for enhanced validation
		travelKeywords: []string{
			"airport", "flight", "airline", "boarding", "departure", "arrival",
			"terminal", "gate", "security", "checkpoint", "baggage", "luggage",
			"customs", "immigration", "visa", "entry", "exit", "transit",
			"vacation", "holiday", "business trip", "conference", "meeting",
		},

		// Government/official keywords
		governmentKeywords: []string{
			"government", "official", "authority", "department", "ministry",
			"embassy", "consulate", "foreign office", "state department",
			"homeland security", "border patrol", "immigration officer",
			"passport office", "visa office", "diplomatic", "consular",
		},

		// Form/document keywords
		formKeywords: []string{
			"application", "form", "document", "certificate", "record",
			"registration", "identification", "identity", "personal",
			"information", "details", "data", "field", "entry", "input",
		},

		// Global test passport database
		globalTestPassports: []string{
			"A00000000", "A11111111", "A12345678", "A99999999",
			"AA000000", "AB000000", "AB123456", "XX0000000", "XX123456",
			"000000000", "111111111", "123456789", "999999999",
			"GB000000000", "US000000000", "CA00000000", "FR00000000",
			"TEST123456", "SAMPLE123", "DEMO12345", "PLACEHOLDER",
			"EXAMPLE123", "FAKE123456", "MOCK123456", "DUMMY12345",
		},
	}
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Initialize valid country codes
func initValidCountryCodes() map[string]bool {
	codes := map[string]bool{
		// EU countries
		"AT": true, "BE": true, "BG": true, "HR": true, "CY": true,
		"CZ": true, "DK": true, "EE": true, "FI": true, "FR": true,
		"DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
		"LV": true, "LT": true, "LU": true, "MT": true, "NL": true,
		"PL": true, "PT": true, "RO": true, "SK": true, "SI": true,
		"ES": true, "SE": true,

		// Non-EU European countries
		"GB": true, "CH": true, "NO": true, "IS": true, "LI": true,

		// North America
		"US": true, "CA": true, "MX": true,

		// Major Asian countries
		"CN": true, "JP": true, "KR": true, "IN": true, "SG": true,

		// Major Oceania countries
		"AU": true, "NZ": true,

		// Major South American countries
		"BR": true, "AR": true, "CL": true,

		// Major African countries
		"ZA": true, "EG": true, "NG": true,
	}
	return codes
}

// initValidMRZCountryCodes returns the set of 3-letter ICAO issuing-state
// codes recognized in passport MRZ lines (a representative subset; ICAO 9303
// also defines codes like "GBR" for the UK and "D" for Germany, plus special
// codes such as "UNO"). This mirrors initValidCountryCodes but for the
// 3-letter MRZ alphabet.
func initValidMRZCountryCodes() map[string]bool {
	return map[string]bool{
		// Europe
		"GBR": true, "DEU": true, "FRA": true, "ITA": true, "ESP": true,
		"NLD": true, "BEL": true, "CHE": true, "AUT": true, "SWE": true,
		"NOR": true, "DNK": true, "FIN": true, "IRL": true, "PRT": true,
		"POL": true, "CZE": true, "GRC": true, "HUN": true, "ROU": true,
		// North America
		"USA": true, "CAN": true, "MEX": true,
		// Asia
		"CHN": true, "JPN": true, "KOR": true, "IND": true, "SGP": true,
		"HKG": true, "TWN": true, "THA": true, "MYS": true, "IDN": true,
		// Oceania
		"AUS": true, "NZL": true,
		// South America
		"BRA": true, "ARG": true, "CHL": true, "COL": true, "PER": true,
		// Africa / Middle East
		"ZAF": true, "EGY": true, "NGA": true, "ARE": true, "SAU": true,
		"ISR": true, "TUR": true,
	}
}

// mrzCountryCode extracts the 3-letter issuing-state code from an MRZ line-1
// string of the form "P" + sub-code + 3-letter country (e.g. "P<GBR..." ->
// "GBR"). Returns false if the string is too short to contain one.
func mrzCountryCode(mrz string) (string, bool) {
	// positions: [0]=P, [1]=doc sub-code, [2:5]=country code
	if len(mrz) < 5 {
		return "", false
	}
	return mrz[2:5], true
}

// hasMRZStructure reports whether s has the structural fingerprint of an ICAO
// 9303 TD3 line-1 MRZ, beyond merely matching the detection regex. This is the
// guard that lets a standalone MRZ bypass the prose-context requirement
// WITHOUT also waving through random long uppercase tokens (base32 secrets,
// hashes, IDs) that happen to start with a country-code-shaped substring.
//
// Two cheap, highly discriminating checks:
//   - It must begin "P<" (ordinary-passport document-type filler).
//   - The name field is "<"-padded, so a real line-1 MRZ contains many filler
//     characters. Random tokens contain none. We require the run of fillers a
//     genuine MRZ always has; a token with zero/near-zero "<" is rejected.
func hasMRZStructure(s string) bool {
	if !strings.HasPrefix(s, "P<") || len(s) < 44 {
		return false
	}
	// Count "<" fillers. Empirically a real TD3 line-1 has ~30+ (the name
	// field padding); the false-positive tokens we care about have 0. A
	// conservative floor of 5 cleanly separates the two while tolerating
	// unusually long names.
	fillers := strings.Count(s, "<")
	return fillers >= 5
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("passport_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("passport_validator", "validate_file", filePath)
		}
	}

	// Passport validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Passport validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// maxMatchesPerLinePerPattern bounds how many regex hits we will fully process
// for a single (line, pattern) pair. A single pathologically long line packed
// with thousands of passport-shaped tokens would otherwise drive the validator
// into multi-minute (effectively unbounded) processing — a denial-of-service
// surface. A line with this many distinct passport-shaped tokens is not
// realistic source/document content; the cap protects against adversarial
// input while leaving all normal inputs (which have a handful of matches per
// line at most) completely unaffected.
const maxMatchesPerLinePerPattern = 2000

// ValidateContent validates preprocessed content for passport numbers
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: the context-aware
// form of ValidateContent, polling ctx once per line so a runaway multi-line scan
// is reclaimed promptly (v2 Phase 3). On cancellation it returns the matches
// gathered so far plus ctx.Err().
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}
		// Per-LINE work hoisted OUT of the per-match loop. These values depend
		// only on the line (not on the individual match), so computing them once
		// per line instead of once per match removes the dominant
		// O(matches * lineLength) cost on lines packed with many matches.
		lineLower := strings.ToLower(line)
		// One lineContext per line: it memoizes "keyword present in the full
		// line" so the line-length scan for each distinct keyword happens at
		// most once per line, not once per match.
		lc := newLineContext(lineLower)
		// Tabular and form-context detection are pure functions of the line
		// (the match argument was never used in their bodies), so precompute.
		lineIsTabular := v.isTabularDataLine(line)
		lineIsForm := v.isInFormContextLine(lineLower)

		// Check each pattern against the line
		for country := range v.patterns {
			re := v.compiledPatterns[country]
			// Use FindAllStringIndex so each match's byte offset is known up
			// front. This eliminates the per-match strings.Index(line, match)
			// rescan (O(lineLength) each) AND fixes a latent correctness bug:
			// strings.Index returns the FIRST occurrence of a token, so a line
			// containing the same token more than once previously computed the
			// context window around the wrong (first) occurrence for every
			// later duplicate.
			foundIdx := re.FindAllStringIndex(line, maxMatchesPerLinePerPattern)

			for _, loc := range foundIdx {
				matchIndex := loc[0]
				match := line[loc[0]:loc[1]]

				// Skip if it's a common word or test pattern
				if v.isCommonWord(match) || v.isTestPattern(match) {
					continue
				}

				// Double-check that this match actually belongs to a valid country format
				actualCountry := v.determineCountry(match)
				if actualCountry == "" {
					continue // Skip matches that don't fit any specific passport format
				}

				confidence, checks := v.CalculateConfidence(match + ":" + country)

				// Create context info for the line
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract some context around the match in the line using the
				// known byte offset (no rescan).
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

				// Analyze context and adjust confidence. Pass the shared per-line
				// lineContext and the per-line form-context flag so the proximity
				// / keyword scan does not re-lower-case or re-scan the whole line
				// per match.
				contextImpact := v.analyzeContext(match, contextInfo, lc, lineIsForm)

				// Check for tabular data and boost confidence (per-line property).
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

				contextInfo.ConfidenceImpact = contextImpact

				// Require strong context for passport matches. Pass the shared
				// per-line lineContext and per-line form flag so this does not
				// re-lower-case or re-scan the whole line per match.
				hasStrongContext := v.hasStrongPassportContextWith(match, &contextInfo, lc, lineIsForm)

				// Skip matches with 0% confidence - they are false positives
				if confidence <= 0 {
					continue
				}

				// Only include matches with reasonable confidence AND strong context
				if confidence <= 60 || !hasStrongContext {
					continue
				}

				matches = append(matches, detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "PASSPORT",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "passport",
					Context:    contextInfo,
					Metadata: map[string]any{
						"country":           country,
						"validation_checks": checks,
						"context_impact":    contextImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
			}
		}
	}

	return matches, nil
}

// Check if two passport patterns are similar (likely part of a test sequence)
func (v *Validator) areSimilarPatterns(pat1, pat2 string) bool {
	// If they're identical except for the last character, they're likely sequential
	if len(pat1) == len(pat2) && len(pat1) >= 6 {
		samePrefix := true
		for i := 0; i < len(pat1)-1; i++ {
			if pat1[i] != pat2[i] {
				samePrefix = false
				break
			}
		}
		if samePrefix {
			return true
		}
	}

	// If they have the same pattern of letters and digits
	letterPattern1 := v.getLetterDigitPattern(pat1)
	letterPattern2 := v.getLetterDigitPattern(pat2)
	if letterPattern1 != "" && letterPattern1 == letterPattern2 {
		return true
	}

	return false
}

// Get the pattern of letters and digits (e.g., "AB123456" becomes "LL######")
func (v *Validator) getLetterDigitPattern(text string) string {
	if len(text) < 6 {
		return ""
	}

	var pattern strings.Builder
	for _, char := range text {
		if unicode.IsLetter(char) {
			pattern.WriteRune('L')
		} else if unicode.IsDigit(char) {
			pattern.WriteRune('#')
		} else {
			pattern.WriteRune(char)
		}
	}

	return pattern.String()
}

// edgeWindow is the number of bytes of the line head/tail included when testing
// whether a keyword straddles the boundary between the ±50-char context window
// and the (potentially very long) full line. It must be >= the longest keyword
// (22 chars) so no boundary-spanning keyword is missed. See lineContext.
const edgeWindow = 64

// lineContext caches the per-line work needed to test, in amortized O(1) per
// match, whether a keyword occurs in the lowercased combined context
//
//	beforeLower + " " + lineLower + " " + afterLower
//
// without re-lower-casing or re-scanning the full (possibly huge) line for
// every match. lineLower is computed once per line; only the small ±50-char
// before/after windows change per match.
//
// The crucial optimization for very long lines: whether a keyword appears in
// the line BODY (c.lineLower) is a per-line property — identical for every
// match on the line — so it is computed at most once per distinct keyword and
// memoized in inLineCache. Across the (potentially thousands of) matches on a
// single packed line this turns the O(matches * keywords * lineLength) blowup
// into O(distinctKeywords * lineLength) per line plus O(1) per match.
type lineContext struct {
	lineLower   string          // lower-cased full line (computed once per line)
	inLineCache map[string]bool // memoized "keyword present in lineLower"
}

func newLineContext(lineLower string) *lineContext {
	return &lineContext{lineLower: lineLower}
}

// inLine reports whether kw is present in the full lower-cased line, memoizing
// the (line-length) scan so it runs at most once per distinct keyword per line.
func (c *lineContext) inLine(kw string) bool {
	if c.inLineCache == nil {
		c.inLineCache = make(map[string]bool, 16)
	}
	if hit, ok := c.inLineCache[kw]; ok {
		return hit
	}
	hit := strings.Contains(c.lineLower, kw)
	c.inLineCache[kw] = hit
	return hit
}

// contains reports whether kw (already lower-case) appears in the lowercased
// concatenation beforeLower + " " + c.lineLower + " " + afterLower. This is
// byte-for-byte equivalent to
//
//	strings.Contains(strings.ToLower(before+" "+line+" "+after), kw)
//
// because ToLower is per-rune and the joiners are spaces. For short lines we
// build the concatenation directly (cheap); for long lines we test the line
// body via the memoized inLine() and use bounded head/tail edge windows to
// catch any keyword that straddles a context boundary — making the per-match
// cost independent of the line length.
func (c *lineContext) contains(kw, beforeLower, afterLower string) bool {
	if len(c.lineLower) <= 256 {
		return strings.Contains(beforeLower+" "+c.lineLower+" "+afterLower, kw)
	}
	if c.inLine(kw) {
		return true
	}
	head := c.lineLower
	if len(head) > edgeWindow {
		head = head[:edgeWindow]
	}
	if strings.Contains(beforeLower+" "+head, kw) {
		return true
	}
	tail := c.lineLower
	if len(tail) > edgeWindow {
		tail = tail[len(tail)-edgeWindow:]
	}
	return strings.Contains(tail+" "+afterLower, kw)
}

// AnalyzeContext analyzes the context around a match and returns a confidence
// adjustment. It is retained for external callers/tests; it derives the
// per-line values that the hot path supplies directly via analyzeContext.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	lineLower := strings.ToLower(context.FullLine)
	lineIsForm := v.isInFormContextLine(lineLower)
	return v.analyzeContext(match, context, newLineContext(lineLower), lineIsForm)
}

// analyzeContext is the per-match context analysis used by the hot path. It
// takes the shared per-line lineContext and a per-line form-context flag so
// that no per-match work scales with the line length. Behavior is identical to
// the original AnalyzeContext on all inputs.
func (v *Validator) analyzeContext(match string, context detector.ContextInfo, lc *lineContext, lineIsForm bool) float64 {
	beforeLower := strings.ToLower(context.BeforeText)
	afterLower := strings.ToLower(context.AfterText)

	var confidenceImpact float64 = 0

	// Check proximity to "passport" specifically - this is the strongest indicator
	passportProximity := v.calculatePassportProximityWith(match, context, lc)
	confidenceImpact += passportProximity

	// Check for positive keywords with weighted scoring
	for _, keyword := range v.positiveKeywords {
		keywordLower := strings.ToLower(keyword)
		if lc.contains(keywordLower, beforeLower, afterLower) {
			// Weight keywords by their specificity to passports
			weight := v.getKeywordWeight(keyword)

			// Give more weight to keywords that are closer to the match.
			// NOTE: preserves the original semantics of checking the
			// ORIGINAL-CASE full line against the lower-cased keyword.
			if strings.Contains(context.FullLine, keywordLower) {
				confidenceImpact += weight * 1.5 // Boost for same-line keywords
			} else {
				confidenceImpact += weight // Base weight for surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		keywordLower := strings.ToLower(keyword)
		if lc.contains(keywordLower, beforeLower, afterLower) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, keywordLower) {
				confidenceImpact -= 20 // Strong penalty for negative keywords in same line
			} else {
				confidenceImpact -= 10 // Moderate penalty for negative keywords in context
			}
		}
	}

	// Check for form-like structure (labels followed by values)
	if lineIsForm {
		confidenceImpact += 15 // Boost for form-like contexts
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 40 {
		confidenceImpact = 40 // Maximum +40% boost
	} else if confidenceImpact < -60 {
		confidenceImpact = -60 // Maximum -60% reduction
	}

	return confidenceImpact
}

// calculatePassportProximity calculates confidence boost based on proximity to
// "passport" keyword. Retained with its original signature for external
// callers/tests; it builds a lineContext and delegates.
func (v *Validator) calculatePassportProximity(match string, context detector.ContextInfo) float64 {
	return v.calculatePassportProximityWith(match, context, newLineContext(strings.ToLower(context.FullLine)))
}

// calculatePassportProximityWith is the per-match proximity calculation used by
// the hot path. lc carries the pre-lower-cased line (computed once per line)
// and memoizes the per-line "variant present in line" scans. To stay
// byte-for-byte identical with the original implementation, the match position
// used for the distance calculation is strings.Index(lineLower, match) — i.e.
// the first occurrence of the (original-case) match within the LOWER-CASED
// line, which is what the original code computed. That index is only ever
// needed when a passport variant is actually present on the line, so the
// (line-length) scan is skipped entirely for the common case.
func (v *Validator) calculatePassportProximityWith(match string, context detector.ContextInfo, lc *lineContext) float64 {
	lineLower := lc.lineLower
	beforeText := strings.ToLower(context.BeforeText)
	afterText := strings.ToLower(context.AfterText)

	// Check for "passport" in various forms
	passportVariants := []string{"passport", "passport number", "passport no", "passport #"}

	for _, variant := range passportVariants {
		// Same line - highest boost (memoized per-line scan).
		if lc.inLine(variant) {
			// Check if it's very close (within 20 characters). Only now do we
			// pay for locating the match within the line.
			matchIndex := strings.Index(lineLower, match)
			variantIndex := strings.Index(lineLower, variant)

			if matchIndex >= 0 && variantIndex >= 0 {
				distance := matchIndex - variantIndex
				if distance < 0 {
					distance = -distance
				}

				if distance <= 20 {
					return 25 // Very close to "passport" - high confidence
				} else if distance <= 50 {
					return 15 // Moderately close
				} else {
					return 8 // Same line but far apart
				}
			}
		}

		// In surrounding context - moderate boost
		if strings.Contains(beforeText, variant) || strings.Contains(afterText, variant) {
			return 5
		}
	}

	return 0
}

// getKeywordWeight returns the weight for a specific keyword based on its relevance to passports
func (v *Validator) getKeywordWeight(keyword string) float64 {
	highConfidenceKeywords := map[string]float64{
		"passport": 15, "passport number": 15, "passport no": 15, "travel document": 12,
		"travel document number": 12, "document number": 10, "document no": 10,
		"mrz": 12, "machine readable": 10, "icao": 8, "passport holder": 10,
	}

	mediumConfidenceKeywords := map[string]float64{
		"visa": 6, "immigration": 6, "border control": 6, "customs": 5,
		"embassy": 5, "consulate": 5, "nationality": 4, "citizenship": 4,
		"issuing authority": 6, "passport authority": 8,
	}

	lowConfidenceKeywords := map[string]float64{
		"identification": 3, "identity": 3, "travel": 2, "international": 2,
		"foreign": 2, "expiry": 3, "expiration": 3, "issue date": 3,
		"valid until": 3, "expires": 3, "surname": 2, "given name": 2,
		"date of birth": 2, "place of birth": 2, "gender": 1, "sex": 1,
	}

	keywordLower := strings.ToLower(keyword)

	if weight, exists := highConfidenceKeywords[keywordLower]; exists {
		return weight
	}
	if weight, exists := mediumConfidenceKeywords[keywordLower]; exists {
		return weight
	}
	if weight, exists := lowConfidenceKeywords[keywordLower]; exists {
		return weight
	}

	return 2 // Default weight for unlisted keywords
}

// isInFormContext checks if the match appears to be in a form-like context.
// The match argument is unused (form detection is a property of the line); it
// is kept for API compatibility with existing callers/tests.
func (v *Validator) isInFormContext(match string, context detector.ContextInfo) bool {
	return v.isInFormContextLine(strings.ToLower(context.FullLine))
}

// isInFormContextLine is the per-line form-context check operating on the
// already-lower-cased line. Computed once per line in the hot path.
func (v *Validator) isInFormContextLine(lineLower string) bool {
	// Look for form-like patterns: "label: value" or "label = value" or "label value"
	for _, re := range reFormPatterns {
		if re.MatchString(lineLower) {
			return true
		}
	}

	// Check for table-like structure (multiple values separated by tabs or multiple spaces)
	if strings.Count(lineLower, "\t") >= 2 || reMultiSpace.MatchString(lineLower) {
		return true
	}

	return false
}

// hasStrongPassportContext checks if there's strong contextual evidence this is
// actually a passport. Retained for external callers/tests; derives the
// per-line values and delegates to hasStrongPassportContextWith.
func (v *Validator) hasStrongPassportContext(match string, context *detector.ContextInfo) bool {
	if context == nil {
		return false
	}
	lineLower := strings.ToLower(context.FullLine)
	return v.hasStrongPassportContextWith(match, context, newLineContext(lineLower), v.isInFormContextLine(lineLower))
}

// hasStrongPassportContextWith is the per-match strong-context check used by the
// hot path. It takes the shared per-line lineContext and per-line form flag so
// it does not re-lower-case or re-scan the full line per match. Behavior is
// identical to hasStrongPassportContext on all inputs.
func (v *Validator) hasStrongPassportContextWith(match string, context *detector.ContextInfo, lc *lineContext, lineIsForm bool) bool {
	if context == nil {
		return false
	}

	// A well-formed MRZ is self-evidently a travel document: it begins "P<",
	// carries a valid 3-letter issuing-state code in-band, and has the "<"-
	// padded name field characteristic of the format. Such a match needs no
	// external keywords — requiring prose context here is why standalone MRZ
	// lines (the common real-world case) were missed entirely. The structure
	// check (hasMRZStructure) is what prevents a random uppercase token that
	// merely starts with a country-code-shaped substring from bypassing the
	// context requirement.
	if hasMRZStructure(match) {
		if code, ok := mrzCountryCode(match); ok && v.validMRZCountryCodes[code] {
			return true
		}
	}

	beforeLower := strings.ToLower(context.BeforeText)
	afterLower := strings.ToLower(context.AfterText)

	// Strong indicators - any of these is sufficient
	strongIndicators := []string{
		"passport", "passport number", "passport no", "passport #",
		"travel document", "travel document number", "document number",
		"mrz", "machine readable zone",
	}

	for _, indicator := range strongIndicators {
		if lc.contains(indicator, beforeLower, afterLower) {
			return true
		}
	}

	// Medium indicators - need at least 2 of these
	mediumIndicators := []string{
		"visa", "immigration", "border", "customs", "embassy", "consulate",
		"nationality", "citizenship", "travel", "international", "foreign",
		"expiry", "expiration", "expires", "valid until", "issue date",
	}

	mediumCount := 0
	for _, indicator := range mediumIndicators {
		if lc.contains(indicator, beforeLower, afterLower) {
			mediumCount++
			if mediumCount >= 2 {
				return true
			}
		}
	}

	// Form context can also be strong evidence if combined with any travel-related keyword
	if lineIsForm {
		travelKeywords := []string{"travel", "document", "identification", "identity", "international"}
		for _, keyword := range travelKeywords {
			if lc.contains(keyword, beforeLower, afterLower) {
				return true
			}
		}
	}

	return false
}

// findKeywords returns a list of keywords found in the context
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
	fullContext = strings.ToLower(fullContext)

	var found []string
	for _, keyword := range keywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			found = append(found, keyword)
		}
	}

	return found
}

// CalculateConfidence calculates the confidence score for a potential passport number
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Extract country from the match (added in Validate method)
	parts := strings.Split(match, ":")
	cleanMatch := parts[0]
	country := ""
	if len(parts) > 1 {
		country = parts[1]
	} else {
		country = v.determineCountry(cleanMatch)
	}

	checks := map[string]bool{
		"format":             true,
		"length":             true,
		"valid_country_code": false,
		"not_test_number":    true,
		"not_sequential":     true,
		"valid_characters":   true,
		"not_common_word":    true,
	}

	// Start with lower base confidence - require context to boost it
	confidence := 60.0

	// Clean the match (remove spaces, etc.)
	cleanMatch = strings.ReplaceAll(cleanMatch, " ", "")

	// Check if it's a known test pattern
	if v.isKnownTestPattern(cleanMatch) {
		confidence -= 30
		checks["not_test_number"] = false
	}

	// Check if it's a common English word
	if v.isLikelyWord(cleanMatch) {
		confidence -= 40
		checks["not_common_word"] = false
	}

	// Check format-specific validations
	switch country {
	case "US":
		// US passport: 1 letter followed by 8 digits
		if !reUSPassport.MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 9 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for test numbers
		if cleanMatch == "A00000000" || cleanMatch == "A11111111" || cleanMatch == "A12345678" {
			confidence -= 15
			checks["not_test_number"] = false
		}

	case "UK":
		// UK passport: 9 digits
		if !reUKPassport.MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 9 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for test numbers
		if cleanMatch == "000000000" || cleanMatch == "111111111" || cleanMatch == "123456789" {
			confidence -= 15
			checks["not_test_number"] = false
		}

	case "Canada":
		// Canadian passport: 2 letters followed by 6 digits
		if !reCanadaPassport.MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 8 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for valid country code
		if !v.validCountryCodes[cleanMatch[0:2]] {
			confidence -= 15
		} else {
			checks["valid_country_code"] = true
		}

		// Check for test numbers
		if cleanMatch == "AB000000" || cleanMatch == "AB123456" || cleanMatch == "AA000000" {
			confidence -= 15
			checks["not_test_number"] = false
		}

	case "EU":
		// EU passport: 2 letters followed by 7 alphanumeric chars
		if !reEUPassport.MatchString(cleanMatch) {
			confidence -= 30
			checks["format"] = false
		}

		// Check length
		if len(cleanMatch) != 9 {
			confidence -= 20
			checks["length"] = false
		}

		// Check for valid country code
		if !v.validCountryCodes[cleanMatch[0:2]] {
			confidence -= 15
		} else {
			checks["valid_country_code"] = true
		}

		// Check for invalid country codes like XX
		if cleanMatch[0:2] == "XX" || cleanMatch[0:2] == "ZZ" || cleanMatch[0:2] == "YY" {
			confidence -= 20
			checks["valid_country_code"] = false
		}

	case "MRZ", "MRZ_TD3":
		// Machine Readable Zone (ICAO 9303) line 1:
		// "P" + document-type sub-code + 3-letter issuing-state code + name field.
		if !strings.HasPrefix(cleanMatch, "P") {
			confidence -= 20
			checks["format"] = false
		}

		// Check for valid characters in MRZ (letters, numbers, and <)
		if !reMRZChars.MatchString(cleanMatch) {
			confidence -= 15
			checks["valid_characters"] = false
		}

		// Validate the embedded 3-letter issuing-state code (positions 2-4,
		// i.e. immediately after "P" + the document sub-code). A real MRZ
		// carries its country in-band, so this is a strong structural signal:
		// a valid code boosts confidence (a well-formed MRZ is unambiguous and
		// should clear the surfacing threshold on its own merit), while an
		// invalid one drops it.
		if code, ok := mrzCountryCode(cleanMatch); ok && v.validMRZCountryCodes[code] {
			confidence += 20
			checks["valid_country_code"] = true
		} else {
			confidence -= 10
			checks["valid_country_code"] = false
		}

	case "Generic":
		// Generic passport: 6-10 alphanumeric chars
		// This is a catch-all with lower confidence
		confidence -= 30 // Start with lower confidence for generic matches

		// Check for valid characters
		if !reGenericChars.MatchString(cleanMatch) {
			confidence -= 15
			checks["valid_characters"] = false
		}

		// Check for sequential or repeated characters
		if v.isSequentialOrRepeated(cleanMatch) {
			confidence -= 10
			checks["not_sequential"] = false
		}
	}

	// Check for common patterns that might be false positives
	if v.isPossibleFalsePositive(cleanMatch) {
		confidence -= 25
	}

	// Ensure confidence is within bounds
	if confidence < 0 {
		confidence = 0
	}

	return confidence, checks
}

// isKnownTestPattern checks if the pattern matches a known test pattern
func (v *Validator) isKnownTestPattern(text string) bool {
	for _, pattern := range v.knownTestPatterns {
		if text == pattern {
			return true
		}
	}
	return false
}

// isLikelyWord checks if the text is likely an English word
func (v *Validator) isLikelyWord(text string) bool {
	// Check against common words list
	for _, word := range v.commonWords {
		if strings.EqualFold(text, word) {
			return true
		}
	}

	// Simple heuristic: English words typically have vowels
	// and a reasonable vowel-to-consonant ratio
	if len(text) >= 5 {
		vowels := 0
		for _, char := range strings.ToUpper(text) {
			if strings.ContainsRune("AEIOU", char) {
				vowels++
			}
		}

		// If it has vowels and the ratio of vowels to length is reasonable for English
		vowelRatio := float64(vowels) / float64(len(text))
		return vowels >= 1 && vowelRatio >= 0.2 && vowelRatio <= 0.6
	}

	return false
}

// determineCountry tries to identify the country format based on the match pattern
func (v *Validator) determineCountry(match string) string {
	cleanMatch := strings.ReplaceAll(match, " ", "")

	// Try to match against each country pattern
	if reUSPassport.MatchString(cleanMatch) {
		return "US"
	} else if reUKPassport.MatchString(cleanMatch) {
		return "UK"
	} else if reCanadaPassport.MatchString(cleanMatch) {
		return "Canada"
	} else if reEUPassport.MatchString(cleanMatch) {
		return "EU"
	} else if strings.HasPrefix(cleanMatch, "P") && len(cleanMatch) > 40 {
		if len(cleanMatch) == 44 {
			return "MRZ_TD3"
		}
		return "MRZ"
	}

	// No generic fallback - only match specific passport formats
	return ""
}

// Helper methods
func (v *Validator) isSequentialOrRepeated(text string) bool {
	// Check for repeated characters (e.g., "AAAAAA")
	for i := 0; i < len(text)-3; i++ {
		if text[i] == text[i+1] && text[i] == text[i+2] && text[i] == text[i+3] {
			return true
		}
	}

	// Check for sequential characters (e.g., "ABCDEF" or "123456")
	// For digits
	digitSequence := true
	for i := 0; i < len(text)-3; i++ {
		if unicode.IsDigit(rune(text[i])) && unicode.IsDigit(rune(text[i+1])) &&
			unicode.IsDigit(rune(text[i+2])) && unicode.IsDigit(rune(text[i+3])) {
			if text[i+1] != text[i]+1 || text[i+2] != text[i]+2 || text[i+3] != text[i]+3 {
				digitSequence = false
				break
			}
		} else {
			digitSequence = false
			break
		}
	}

	// For letters
	letterSequence := true
	for i := 0; i < len(text)-3; i++ {
		if unicode.IsLetter(rune(text[i])) && unicode.IsLetter(rune(text[i+1])) &&
			unicode.IsLetter(rune(text[i+2])) && unicode.IsLetter(rune(text[i+3])) {
			if text[i+1] != text[i]+1 || text[i+2] != text[i]+2 || text[i+3] != text[i]+3 {
				letterSequence = false
				break
			}
		} else {
			letterSequence = false
			break
		}
	}

	return digitSequence || letterSequence
}

func (v *Validator) isPossibleFalsePositive(text string) bool {
	// Check for common false positives like product codes, serial numbers, etc.
	for _, re := range reFalsePositivePatterns {
		if re.MatchString(text) {
			return true
		}
	}

	// Check if it's a common English word
	if v.isLikelyWord(text) {
		return true
	}

	return false
}

func (v *Validator) getFormatDescription(country string) string {
	descriptions := map[string]string{
		"US":      "US passport (1 letter followed by 8 digits)",
		"UK":      "UK passport (9 digits)",
		"Canada":  "Canadian passport (2 letters followed by 6 digits)",
		"EU":      "EU passport (2 letters followed by 7 alphanumeric characters)",
		"Generic": "Generic passport format (6-10 alphanumeric characters)",
		"MRZ":     "Machine Readable Zone format",
		"MRZ_TD3": "Machine Readable Zone TD3 format",
	}

	if desc, ok := descriptions[country]; ok {
		return desc
	}

	return "Unknown passport format"
}

// isCommonWord checks if the match is a common English word that might be mistaken for a passport
func (v *Validator) isCommonWord(match string) bool {
	// Convert to lowercase for comparison
	lower := strings.ToLower(match)

	// Check against common words that might match passport patterns
	commonWords := []string{
		"password", "passport", "document", "number", "code", "test", "example",
		"sample", "demo", "placeholder", "template", "default", "unknown",
	}

	for _, word := range commonWords {
		if lower == word {
			return true
		}
	}

	return false
}

// isTabularData checks if the passport appears to be in a tabular format. The
// match argument is unused (tabular structure is a property of the line); it is
// kept for API compatibility with existing callers/tests.
func (v *Validator) isTabularData(line, match string) bool {
	return v.isTabularDataLine(line)
}

// isTabularDataLine is the per-line tabular-structure check. Computed once per
// line in the hot path instead of once per match.
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
	if len(reMultiSpace2.FindAllString(line, -1)) >= 2 {
		return true
	}

	// Check for common travel document patterns (names followed by passport numbers)
	if reTravelPattern.MatchString(line) {
		return true
	}

	return false
}

// isTestPattern checks if the match is a known test passport pattern
func (v *Validator) isTestPattern(match string) bool {
	// Check against known test patterns
	testPatterns := []string{
		"A12345678", "123456789", "AB123456", "TEST1234", "SAMPLE01",
		"DEMO1234", "EXAMPLE1", "PASSPORT1", "DOCUMENT1",
	}

	upper := strings.ToUpper(match)
	for _, pattern := range testPatterns {
		if upper == pattern {
			return true
		}
	}

	// Check for obvious test patterns (all same digits, sequential, etc.)
	if len(match) >= 6 {
		// All same character
		allSame := true
		for i := 1; i < len(match); i++ {
			if match[i] != match[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}

		// Sequential numbers
		if reDigitsOnly.MatchString(match) {
			sequential := true
			for i := 1; i < len(match); i++ {
				if match[i] != match[i-1]+1 {
					sequential = false
					break
				}
			}
			if sequential {
				return true
			}
		}
	}

	return false
}
