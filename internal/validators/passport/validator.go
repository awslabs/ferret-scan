// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	stdctx "context"
	"regexp"
	"strings"
	"unicode"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/tabular"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
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

	// reMixedCaseLabelGate is the label a passport number containing a lowercase
	// letter needs in the mixedCaseLabelGateWindow bytes before it (#888). The
	// window must END in the label and its separators, so the label sits right
	// before the value: "Passport Number: gk123456", "passport_number: gk123456",
	// "my passport no is gk123456", "passport: ya1234567", "showed passport
	// gk123456 at". A bare "passport" needs whitespace after it, which refuses a
	// path or a tag such as ".../passport:v20241012".
	//
	// (?i) widens only the LABEL, never a value: a value pattern under (?i) also
	// matches U+212A (Kelvin sign) and U+017F (long s), which Go folds into
	// [A-Za-z]. The line prefilter in ValidateContentCtx additionally requires
	// "passport" or "travel document" in the lower-cased line, so a label spelled
	// with those two runes is refused too.
	reMixedCaseLabelGate = regexp.MustCompile(`(?i)\b(?:passport|travel document)(?:[ _-]?(?:no\.?|number|num|nr\.?|#)\s*(?:[:=#-]\s*)?(?:is\s+)?|(?:\s*[:=])?\s+(?:is\s+)?)$`)

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
	// compiledMixedCase holds, for each national pattern whose shape contains
	// letters, the same shape with its letters widened to both ASCII cases. It
	// runs as a second pass, only on lines that carry a passport label, and only
	// its hits containing a lowercase letter are considered; see
	// ValidateContentCtx for why it is a second pass and not a widened first one.
	compiledMixedCase map[string]*regexp.Regexp
	// patternOrder fixes the order the patterns are applied in. The scan used to
	// range the patterns map, and Go randomizes map iteration, so when two
	// patterns matched the SAME span the resulting findings came out in a random
	// sequence. A real TD3 MRZ line is matched by both "MRZ" and "MRZ_TD3", and
	// the country name reaches the text report ("Country: MRZ" vs
	// "Country: MRZ_TD3"), so the same file produced two different reports.
	// Ordered most-specific-first, so the tightest matching format is the one
	// reported first.
	patternOrder []string

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
	observer observability.Observer
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

		// MRZ line 2 (ICAO 9303 TD3). Line 1 carries the holder's NAME; line 2
		// carries the passport NUMBER, date of birth, sex, expiry date and
		// personal number — so line 2 is the line with the identifiers on it, and
		// it was not matched by anything at all.
		//
		// The consequence is a cleartext leak on the most ordinary passport shape
		// there is. A scan, an OCR pipeline or any ICAO-compliant record emits
		// BOTH lines, and redaction covered only the first:
		//
		//   [PASSPORT-REDACTED]                            <- line 1, redacted
		//   L898902C36GBR7408122M1204159ZE184226B<<<<<9<   <- line 2, CLEARTEXT
		//
		// Fixed 44-character layout, positionally:
		//   [0:9]   document number (may be "<"-padded)
		//   [9]     document-number check digit
		//   [10:13] 3-letter issuing state
		//   [13:19] date of birth YYMMDD
		//   [19]    date-of-birth check digit
		//   [20]    sex: M, F or "<"
		//   [21:27] expiry date YYMMDD
		//   [27]    expiry check digit
		//   [28:42] personal number (may be "<"-padded)
		//   [42]    personal-number check digit
		//   [43]    composite check digit over the fields above
		//
		// The pattern is intentionally only a shape gate. Any run of 44 MRZ
		// characters matches it, including a base32 secret or a hash, so on its
		// own it would be a false-positive machine. What makes it safe is that
		// every candidate must then pass mrzLine2ChecksValid — five independent
		// 7-3-1 check digits. That is a value-intrinsic test: unlike a keyword it
		// cannot be defeated by anything an attacker writes NEAR the value.
		"MRZ_TD3_L2": `\b[A-Z0-9<]{44}`,
	}

	// Application order, most specific format first. MRZ_TD3 (exactly 44 chars)
	// before MRZ (44-46), and the fixed-shape national formats before the
	// broadest one (EU's 2 letters + 7 alphanumerics also matches Canada-shaped
	// and some US-shaped tokens). See Validator.patternOrder for why this is a
	// slice and not the map's own iteration order.
	// MRZ_TD3_L2 goes first: it is the most specific claim (a fixed 44-char
	// layout that must satisfy five check digits), and putting it ahead of the
	// national formats stops "US" or "EU" claiming a substring of a line-2 MRZ
	// and reporting a fragment instead of the whole line.
	patternOrder := []string{"MRZ_TD3_L2", "MRZ_TD3", "MRZ", "US", "UK", "Canada", "EU"}

	// The national shapes above with their letters widened to both ASCII cases, so
	// "Passport Number: gk123456" and "Gk123456" are candidates at all (#888): the
	// uppercase-only classes made every lowercase or Title-case value invisible,
	// and an invisible value is never handed to the redactor.
	//
	// Explicit [A-Za-z], never (?i). Go folds U+212A (Kelvin sign) and U+017F
	// (long s) into (?i)[A-Z], so (?i)^[A-Z]{2}\d{6}$ matches the 10-byte
	// "\u212aA123456", and every later check that slices the value by byte
	// (cleanMatch[0:2]) would cut a rune in half.
	//
	// UK has no letters, and the MRZ patterns stay uppercase: ICAO 9303 defines the
	// machine-readable zone over A-Z, 0-9 and "<" only.
	mixedCasePatterns := map[string]string{
		"US":     `\b[A-Za-z]\d{8}\b`,
		"Canada": `\b[A-Za-z]{2}\d{6}\b`,
		"EU":     `\b[A-Za-z]{2}[A-Za-z0-9]{7}\b`,
	}

	compiledPatterns := make(map[string]*regexp.Regexp, len(patterns))
	for country, pattern := range patterns {
		compiledPatterns[country] = regexp.MustCompile(pattern)
	}
	compiledMixedCase := make(map[string]*regexp.Regexp, len(mixedCasePatterns))
	for country, pattern := range mixedCasePatterns {
		if _, ok := patterns[country]; !ok {
			panic("passport: mixed-case pattern for unknown pattern " + country)
		}
		compiledMixedCase[country] = regexp.MustCompile(pattern)
	}

	// Guard against patternOrder drifting out of sync with patterns: a pattern
	// missing from the order would silently stop being applied, which for a
	// scanner means a passport format that is no longer detected at all.
	if len(patternOrder) != len(patterns) {
		panic("passport: patternOrder does not cover every pattern")
	}
	for _, name := range patternOrder {
		if _, ok := patterns[name]; !ok {
			panic("passport: patternOrder names unknown pattern " + name)
		}
	}

	return &Validator{
		patterns:          patterns,
		patternOrder:      patternOrder,
		compiledPatterns:  compiledPatterns,
		compiledMixedCase: compiledMixedCase,
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
func (v *Validator) SetObserver(observer observability.Observer) {
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

// initValidMRZCountryCodes returns the set of 3-letter issuing-state codes
// recognised in passport MRZ lines: the complete ISO 3166-1 alpha-3 list (249
// codes) plus the ICAO 9303 Part 3 special codes that never appear in ISO 3166.
//
// This replaces the previous {"a representative subset"} of 48 codes, which was
// essentially OECD plus the largest emerging economies and under-protected the
// document holders least likely to be represented in a Western test corpus.
// See [[#588]] — the six-country probe (USA/GBR/NGA/KEN/VNM/BGD) reproduced
// exactly this shape: an identical MRZ scored 85 for the first three and 75
// for the last three because {KEN,VNM,BGD} were absent from the subset.
//
// ISO 3166-1 alpha-3 is a slowly-changing closed set. It changes rarely — the
// most recent additions are SSD (2011) and MKD/SWZ renames within the last
// decade. Regenerating it in-tree is fine; a runtime fetch would gain nothing
// against the risk of a build-time network dependency.
//
// The ICAO specials matter for the same reason ISO codes do — an XXB or UTO
// document is exactly the kind of record whose PII most needs protecting, and
// an XXB stateless-persons travel document is not a synthetic edge case, it
// is the shape of the record for a real class of holders. Sources:
//
//	UTO             ICAO 9303 Part 3 example state, must not be treated as invalid on demo material
//	XXA/XXB/XXC     stateless / refugee / non-specified nationality travel documents
//	XOM             Sovereign Military Order of Malta
//	XCC             Caribbean Community
//	GBD/GBN/GBO/GBP/GBS   British national classes (dependent territories, overseas, etc.)
//	RKS             Kosovo (issued in the field; not in ISO 3166-1 for political reasons)
//	EUE             European Union laissez-passer
//
// Verified against a REAL scan of my own passport MRZ (redacted before commit)
// — the state code parses at the expected offset and the check digits verify.
func initValidMRZCountryCodes() map[string]bool {
	return map[string]bool{
		// ISO 3166-1 alpha-3, complete list (249 codes).
		"ABW": true, "AFG": true, "AGO": true, "AIA": true, "ALA": true, "ALB": true, "AND": true, "ARE": true,
		"ARG": true, "ARM": true, "ASM": true, "ATA": true, "ATF": true, "ATG": true, "AUS": true, "AUT": true,
		"AZE": true, "BDI": true, "BEL": true, "BEN": true, "BES": true, "BFA": true, "BGD": true, "BGR": true,
		"BHR": true, "BHS": true, "BIH": true, "BLM": true, "BLR": true, "BLZ": true, "BMU": true, "BOL": true,
		"BRA": true, "BRB": true, "BRN": true, "BTN": true, "BVT": true, "BWA": true, "CAF": true, "CAN": true,
		"CCK": true, "CHE": true, "CHL": true, "CHN": true, "CIV": true, "CMR": true, "COD": true, "COG": true,
		"COK": true, "COL": true, "COM": true, "CPV": true, "CRI": true, "CUB": true, "CUW": true, "CXR": true,
		"CYM": true, "CYP": true, "CZE": true, "DEU": true, "DJI": true, "DMA": true, "DNK": true, "DOM": true,
		"DZA": true, "ECU": true, "EGY": true, "ERI": true, "ESH": true, "ESP": true, "EST": true, "ETH": true,
		"FIN": true, "FJI": true, "FLK": true, "FRA": true, "FRO": true, "FSM": true, "GAB": true, "GBR": true,
		"GEO": true, "GGY": true, "GHA": true, "GIB": true, "GIN": true, "GLP": true, "GMB": true, "GNB": true,
		"GNQ": true, "GRC": true, "GRD": true, "GRL": true, "GTM": true, "GUF": true, "GUM": true, "GUY": true,
		"HKG": true, "HMD": true, "HND": true, "HRV": true, "HTI": true, "HUN": true, "IDN": true, "IMN": true,
		"IND": true, "IOT": true, "IRL": true, "IRN": true, "IRQ": true, "ISL": true, "ISR": true, "ITA": true,
		"JAM": true, "JEY": true, "JOR": true, "JPN": true, "KAZ": true, "KEN": true, "KGZ": true, "KHM": true,
		"KIR": true, "KNA": true, "KOR": true, "KWT": true, "LAO": true, "LBN": true, "LBR": true, "LBY": true,
		"LCA": true, "LIE": true, "LKA": true, "LSO": true, "LTU": true, "LUX": true, "LVA": true, "MAC": true,
		"MAF": true, "MAR": true, "MCO": true, "MDA": true, "MDG": true, "MDV": true, "MEX": true, "MHL": true,
		"MKD": true, "MLI": true, "MLT": true, "MMR": true, "MNE": true, "MNG": true, "MNP": true, "MOZ": true,
		"MRT": true, "MSR": true, "MTQ": true, "MUS": true, "MWI": true, "MYS": true, "MYT": true, "NAM": true,
		"NCL": true, "NER": true, "NFK": true, "NGA": true, "NIC": true, "NIU": true, "NLD": true, "NOR": true,
		"NPL": true, "NRU": true, "NZL": true, "OMN": true, "PAK": true, "PAN": true, "PCN": true, "PER": true,
		"PHL": true, "PLW": true, "PNG": true, "POL": true, "PRI": true, "PRK": true, "PRT": true, "PRY": true,
		"PSE": true, "PYF": true, "QAT": true, "REU": true, "ROU": true, "RUS": true, "RWA": true, "SAU": true,
		"SDN": true, "SEN": true, "SGP": true, "SGS": true, "SHN": true, "SJM": true, "SLB": true, "SLE": true,
		"SLV": true, "SMR": true, "SOM": true, "SPM": true, "SRB": true, "SSD": true, "STP": true, "SUR": true,
		"SVK": true, "SVN": true, "SWE": true, "SWZ": true, "SXM": true, "SYC": true, "SYR": true, "TCA": true,
		"TCD": true, "TGO": true, "THA": true, "TJK": true, "TKL": true, "TKM": true, "TLS": true, "TON": true,
		"TTO": true, "TUN": true, "TUR": true, "TUV": true, "TWN": true, "TZA": true, "UGA": true, "UKR": true,
		"UMI": true, "URY": true, "USA": true, "UZB": true, "VAT": true, "VCT": true, "VEN": true, "VGB": true,
		"VIR": true, "VNM": true, "VUT": true, "WLF": true, "WSM": true, "YEM": true, "ZAF": true, "ZMB": true,
		"ZWE": true,

		// ICAO 9303 Part 3 specials that are NOT ISO 3166-1 codes (13 codes).
		"UTO": true, "XXA": true, "XXB": true, "XXC": true, "XOM": true, "XCC": true, "GBD": true, "GBN": true,
		"GBO": true, "GBP": true, "GBS": true, "RKS": true, "EUE": true,
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

// mrzCharValue returns the ICAO 9303 numeric value of an MRZ character: digits
// are themselves, letters are A=10..Z=35, and the filler "<" is 0. Any other
// byte is invalid and reported as -1 so callers can reject the candidate rather
// than silently scoring it as a filler.
func mrzCharValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10
	case c == '<':
		return 0
	default:
		return -1
	}
}

// mrzCheckDigit computes the ICAO 9303 check digit for s using the 7-3-1
// repeating weights. Returns -1 if s contains a character with no defined MRZ
// value.
//
// This is the whole reason a 44-character shape gate is safe to add: the digit is
// a property of the VALUE. A keyword veto can be defeated by typing a word next
// to a secret; a check digit cannot be talked out of.
func mrzCheckDigit(s string) int {
	weights := [3]int{7, 3, 1}
	sum := 0
	for i := 0; i < len(s); i++ {
		v := mrzCharValue(s[i])
		if v < 0 {
			return -1
		}
		sum += v * weights[i%3]
	}
	return sum % 10
}

// mrzLine2ChecksValid reports whether s is a well-formed ICAO 9303 TD3 line-2
// MRZ: exactly 44 characters whose five check digits all verify.
//
// The five are the document number, date of birth, expiry date, personal number,
// and the composite over all of them. Requiring all five is what turns
// `[A-Z0-9<]{44}` from a false-positive machine into a precise test — the odds of
// 44 arbitrary MRZ characters satisfying five independent mod-10 digits are
// 1 in 100,000, and any real base32 secret or hash of that length fails on the
// first digit.
//
// The date fields are additionally range-checked (month 01-12, day 01-31). A
// check digit only proves internal consistency, so without this a 44-character
// token could satisfy the arithmetic while carrying "99" as a month; the range
// test costs nothing and removes that class.
func mrzLine2ChecksValid(s string) bool {
	if len(s) != 44 {
		return false
	}

	docNum, docCD := s[0:9], s[9]
	dob, dobCD := s[13:19], s[19]
	exp, expCD := s[21:27], s[27]
	personal, personalCD := s[28:42], s[42]
	compositeCD := s[43]

	// Sex must be M, F or the filler.
	switch s[20] {
	case 'M', 'F', '<':
	default:
		return false
	}

	// Issuing state is three letters (or "<"-padded for a stateless document).
	for i := 10; i < 13; i++ {
		if !(s[i] >= 'A' && s[i] <= 'Z') && s[i] != '<' {
			return false
		}
	}

	if !mrzDatePlausible(dob) || !mrzDatePlausible(exp) {
		return false
	}

	type field struct {
		text string
		want byte
	}
	for _, f := range []field{
		{docNum, docCD},
		{dob, dobCD},
		{exp, expCD},
		{personal, personalCD},
		{docNum + string(docCD) + dob + string(dobCD) + exp + string(expCD) + personal + string(personalCD), compositeCD},
	} {
		got := mrzCheckDigit(f.text)
		if got < 0 || byte('0'+got) != f.want {
			return false
		}
	}
	return true
}

// mrzDatePlausible reports whether a 6-character MRZ date field is a plausible
// YYMMDD. All six must be digits ("<" padding is not valid in a date), the month
// must be 01-12 and the day 01-31.
func mrzDatePlausible(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	month := int(s[2]-'0')*10 + int(s[3]-'0')
	day := int(s[4]-'0')*10 + int(s[5]-'0')
	return month >= 1 && month <= 12 && day >= 1 && day <= 31
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

// spannedMatch is an emitted finding that still remembers the byte span it
// occupied in its line, so overlapping claims from different patterns can be
// arbitrated before that information is discarded — detector.Match carries no
// offset, so afterwards two patterns claiming one document are indistinguishable
// from the same value genuinely appearing twice.
type spannedMatch struct {
	match detector.Match
	start int
	end   int
}

// keepOutermostSpans folds away claims contained within another claim on the same
// line, so one physical document yields one finding.
//
// The MRZ patterns overlap by construction: MRZ is `P<[A-Z]{3}[A-Z0-9<]{38,40}`
// and MRZ_TD3 is `P<[A-Z]{3}[A-Z0-9<]{39}`, so {39} is inside {38,40} and EVERY
// MRZ_TD3 hit is also an MRZ hit. Each pattern runs independently, and the emit
// loop appended every surviving hit, so a single ICAO 9303 TD3 line 1 produced two
// PASSPORT findings. Two shapes, both reproduced:
//
//   - line 1 exactly 44 chars: both patterns return the IDENTICAL span, giving two
//     findings with the same text differing only in metadata["country"]
//     ("MRZ_TD3" vs "MRZ" — the pattern name, not an issuing state).
//   - line 1 45+ chars: MRZ_TD3 returns [0:44] and MRZ returns [0:45], a strict
//     PREFIX. Exact-span keying would miss this one, which is why containment is
//     the test and not equality.
//
// The nested case is the more damaging of the two: --generate-suppressions wrote
// two rules with two different match_text_hash values for one leak, and one of
// them keyed a truncated 44-byte prefix that is not a complete token anywhere in
// the file — a baseline entry that can never match the document it came from.
//
// Longest span wins, which is the honest choice here: the widest match is the one
// that covers the whole token, so the reported Text is a complete MRZ line rather
// than a truncation. Confidence is deliberately NOT the tiebreak — both MRZ arms
// of CalculateConfidence score identically (same +20 valid-country-code boost,
// both land at 80/100), so ranking on confidence would pick arbitrarily. On an
// exact-span tie the incumbent survives, and patternOrder is a fixed slice
// ("MRZ_TD3" before "MRZ", most specific first) rather than the map's random
// order, so the winner is deterministic run to run.
//
// Confidence is carried up to the maximum of the folded claims. That keeps a merge
// from ever demoting a finding into a lower severity band than it would have had —
// the leak-safe direction, and the same rule the secrets validator's
// mergeBySpanKeepStrongest applies.
//
// Surviving findings keep their original relative order, so byte order downstream
// is unchanged. O(n^2) in claims per line, which is bounded and tiny: at most one
// hit per pattern per position and only six patterns.
func keepOutermostSpans(claims []spannedMatch) []spannedMatch {
	if len(claims) < 2 {
		return claims
	}

	keep := make([]spannedMatch, 0, len(claims))
	for i, c := range claims {
		contained := false
		for j, other := range claims {
			if i == j {
				continue
			}
			// Strictly wider span that covers this one: this claim is redundant.
			if other.start <= c.start && other.end >= c.end &&
				(other.end-other.start) > (c.end-c.start) {
				contained = true
				break
			}
			// Identical span: the earlier claim (more specific pattern, per
			// patternOrder) is the incumbent and survives.
			if other.start == c.start && other.end == c.end && j < i {
				contained = true
				break
			}
		}
		if contained {
			continue
		}
		// Carry up the strongest confidence any folded claim assigned, so folding
		// cannot lower the reported severity.
		for j, other := range claims {
			if i == j {
				continue
			}
			if other.start >= c.start && other.end <= c.end &&
				other.match.Confidence > c.match.Confidence {
				c.match.Confidence = other.match.Confidence
			}
		}
		keep = append(keep, c)
	}
	return keep
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

	// Recognise delimited tabular content ONCE per document. In a CSV export the
	// only passport label is the header row, so without this the whole file scans
	// as unlabelled values and reports nothing. Analyze is conservative: anything
	// ambiguous (ragged rows, unbalanced quotes, no header-ish cells) returns a
	// non-table and leaves behavior exactly as before.
	table := tabular.Analyze(content)

	// Whether any column of the table is a passport column. Computed once per
	// document; it only decides whether data rows get the mixed-case pass, and the
	// per-match column header still decides each value.
	tableNamesPassport := false
	for _, h := range table.Headers() {
		if namesPassport(h) {
			tableNamesPassport = true
			break
		}
	}

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

		// A bare field label on the previous line is context for this line's value.
		// Bounded to exactly one line back, mirroring the +/-1 window the secrets
		// validator already uses for AWS keys (awsSecretContextOpen), so the cost is one
		// short-string test per line and cannot grow with document size.
		if lineNum > 0 && kwmatch.LooksLikeFieldLabel(lines[lineNum-1], v.positiveKeywords) {
			lc.labelAbove = strings.ToLower(strings.TrimSpace(lines[lineNum-1]))
			if namesPassport(lc.labelAbove) {
				// Once per line, and only when the mixed-case gate can read it.
				lc.firstWord = firstASCIIWord(line)
			}
		}

		// Field offsets for this line, computed once and reused for every match on
		// it, so mapping a match to its column stays a binary search rather than a
		// per-match rescan. Nil when the document is not tabular, or on the header
		// row itself (a header cell is a label, not a value to report).
		var lineBounds *tabular.LineBounds
		if table.IsTable() && lineNum != table.HeaderLine() {
			lineBounds = table.Bounds(line)
		}

		// Collected per line, with byte spans retained, so overlapping claims can
		// be arbitrated before the spans are lost (detector.Match has no offset
		// field). See keepOutermostSpans.
		var lineMatches []spannedMatch

		cl := candidateLine{
			line:          line,
			lineNum:       lineNum,
			lc:            lc,
			lineIsForm:    lineIsForm,
			lineIsTabular: lineIsTabular,
			originalPath:  originalPath,
		}

		// Whether this line can carry the label a mixed-case value needs: a
		// passport word on the line itself, a passport label on the line above, or
		// a passport column on a table row. Without one the mixed-case gate refuses
		// every candidate, so the mixed-case pass is not run at all and a line
		// without a passport label costs what it cost before #888. Plain Contains on
		// the lowered line rather than lc.inLine, so lines that never reach a
		// proximity check do not allocate the memo map.
		mixedCaseLine := strings.Contains(lineLower, "passport") ||
			strings.Contains(lineLower, "travel document") ||
			namesPassport(lc.labelAbove) ||
			(lineBounds != nil && tableNamesPassport)

		// Check each pattern against the line, in the fixed order (see
		// Validator.patternOrder) rather than the patterns map's random one.
		for _, country := range v.patternOrder {
			re := v.compiledPatterns[country]
			if re == nil {
				continue
			}
			// Use FindAllStringIndex so each match's byte offset is known up
			// front. This eliminates the per-match strings.Index(line, match)
			// rescan (O(lineLength) each) AND fixes a latent correctness bug:
			// strings.Index returns the FIRST occurrence of a token, so a line
			// containing the same token more than once previously computed the
			// context window around the wrong (first) occurrence for every
			// later duplicate.
			foundIdx := re.FindAllStringIndex(line, maxMatchesPerLinePerPattern)

			for _, loc := range foundIdx {
				// The column header naming THIS match's column. Set per match
				// because the column varies along the row; resolved by binary
				// search over the per-line bounds computed above, so this is
				// O(log fields) rather than a rescan. Empty for non-tabular
				// documents, which leaves scoring exactly as it was.
				lc.columnHeader = table.HeaderAt(lineBounds, loc[0])

				if sm, ok := v.scoreCandidate(&cl, country, loc[0], loc[1], line[loc[0]:loc[1]]); ok {
					lineMatches = append(lineMatches, sm)
				}
			}

			// The mixed-case pass (#888): the same shape with lowercase letters
			// admitted, for a value written "gk123456" or "Gk123456".
			//
			// A second pass, not a widened first one, because of the per-line hit
			// cap. A widened first pass would share maxMatchesPerLinePerPattern
			// between uppercase values and every lowercase word of the right shape
			// (any 9-character word is EU-shaped), so on a long line those words
			// could use up the cap before an uppercase passport later on it was
			// reached: a finding main reports, lost. Kept apart, the uppercase pass
			// above is exactly what it was, and this one has its own cap.
			mixed := v.compiledMixedCase[country]
			if mixed == nil || !mixedCaseLine {
				continue
			}
			for _, loc := range mixed.FindAllStringIndex(line, maxMatchesPerLinePerPattern) {
				match := line[loc[0]:loc[1]]
				// An all-uppercase hit is the uppercase pass's, already considered.
				if !hasASCIILower(match) {
					continue
				}
				lc.columnHeader = table.HeaderAt(lineBounds, loc[0])
				if !v.mixedCaseLabelled(line, loc[0], lc) || v.isLowercasePlaceholder(match) {
					continue
				}
				// One canonical form for every later check: the country prefix,
				// the test-number lists and the format anchors are all uppercase.
				// Length-preserving, so it is never confused with an offset.
				if sm, ok := v.scoreCandidate(&cl, country, loc[0], loc[1], asciiUpper(match)); ok {
					lineMatches = append(lineMatches, sm)
				}
			}
		}

		// One document, one finding: fold away claims that cover the same bytes.
		for _, sm := range keepOutermostSpans(lineMatches) {
			matches = append(matches, sm.match)
		}
	}

	return matches, nil
}

// candidateLine is the per-line state scoreCandidate reads, all of it computed
// once per line by ValidateContentCtx.
type candidateLine struct {
	line          string
	lineNum       int
	lc            *lineContext
	lineIsForm    bool
	lineIsTabular bool
	originalPath  string
}

// scoreCandidate scores the candidate at line[start:end], claimed by the pattern
// named country, and returns the finding when it is reported.
//
// canon is the form every VALUE check reads: the candidate itself, or its ASCII
// upper-case form for a candidate with lowercase letters. The reported Text, the
// span and the context always keep the original bytes, because those are what
// the redactor rewrites and what a suppression rule hashes.
func (v *Validator) scoreCandidate(cl *candidateLine, country string, start, end int, canon string) (spannedMatch, bool) {
	line, lc := cl.line, cl.lc
	matchIndex := start
	match := line[start:end]

	// A line-2 MRZ candidate is only a passport if its check digits
	// verify. The pattern is a 44-character shape gate that any base32
	// secret or hash of that length also satisfies, so this test is what
	// makes it precise rather than a false-positive machine. Five
	// independent mod-10 digits have to line up.
	if country == "MRZ_TD3_L2" && !mrzLine2ChecksValid(canon) {
		return spannedMatch{}, false
	}

	// Skip if it's a common word or test pattern
	if v.isCommonWord(canon) || v.isTestPattern(canon) {
		return spannedMatch{}, false
	}

	// Double-check that this match actually belongs to a valid country format
	actualCountry := v.determineCountry(canon)
	if actualCountry == "" {
		return spannedMatch{}, false // Skip matches that don't fit any specific passport format
	}

	confidence, checks := v.CalculateConfidence(canon + ":" + country)

	// Create context info for the line
	contextInfo := detector.ContextInfo{
		FullLine: line,
	}

	// Extract some context around the match in the line using the
	// known byte offset (no rescan).
	ctxStart := matchIndex - 50
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := matchIndex + len(match) + 50
	if ctxEnd > len(line) {
		ctxEnd = len(line)
	}

	contextInfo.BeforeText = line[ctxStart:matchIndex]
	contextInfo.AfterText = line[matchIndex+len(match) : ctxEnd]

	// Analyze context and adjust confidence. Pass the shared per-line
	// lineContext and the per-line form-context flag so the proximity
	// / keyword scan does not re-lower-case or re-scan the whole line
	// per match.
	contextImpact := v.analyzeContext(match, contextInfo, lc, cl.lineIsForm)

	// Check for tabular data and boost confidence (per-line property).
	if cl.lineIsTabular {
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
	hasStrongContext := v.hasStrongPassportContextWith(match, &contextInfo, lc, cl.lineIsForm)

	// Skip matches with 0% confidence - they are false positives
	if confidence <= 0 {
		return spannedMatch{}, false
	}

	// Only include matches with reasonable confidence AND strong context
	if confidence <= 60 || !hasStrongContext {
		return spannedMatch{}, false
	}

	return spannedMatch{
		start: start,
		end:   end,
		match: detector.Match{
			Text:       match,
			LineNumber: cl.lineNum + 1, // 1-based line numbering
			Type:       "PASSPORT",
			Confidence: confidence,
			Filename:   cl.originalPath,
			Validator:  "passport",
			Context:    contextInfo,
			Metadata: map[string]any{
				"country":           country,
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
				"original_file":     cl.originalPath,
			},
		},
	}, true
}

// mixedCaseLabelGateWindow is how many bytes before a mixed-case candidate its
// passport label and separators must fit in (#888).
const mixedCaseLabelGateWindow = 50

// mixedCaseLabelled reports whether the mixed-case candidate starting at
// line[start] carries a passport label: the mixedCaseLabelGateWindow bytes before
// it end in reMixedCaseLabelGate, or its column header names a passport, or the
// field label on the line above names a passport and the candidate is the first
// word of its line (only indentation, a bullet or punctuation before it), as in
// "Passport Number" written above "gk123456". The first-word rule is the VIN
// validator's (#860): without it a passport label line vouched for any token on
// the next line, and "image: registry.example.com/team/passport:v20241012" under
// "Passport Number: invalid01" reported v20241012.
//
// This gate is what keeps the mixed-case pass from reporting the lowercase
// identifiers that sit near the word "passport" in logs and code: a request id
// after "passport-svc req=", a kid in a passport.js comment, "img482071" in
// "passport photo booth saved img482071.jpg". Measured without it on the #888
// decoys, 19 findings in 10 of 12 files at 72.5-100; with it, none. A label
// AFTER the value ("gk123456 (passport number)") is deliberately not covered.
//
// Uppercase values keep today's context rules and never come here, so the gate
// cannot hide a value that was reported before it existed.
func (v *Validator) mixedCaseLabelled(line string, start int, lc *lineContext) bool {
	if namesPassport(lc.columnHeader) {
		return true
	}
	if start == lc.firstWord && namesPassport(lc.labelAbove) {
		return true
	}
	lo := start - mixedCaseLabelGateWindow
	if lo < 0 {
		lo = 0
	}
	loc := reMixedCaseLabelGate.FindStringIndex(line[lo:start])
	if loc == nil {
		return false
	}
	// The \b before the label is tested against the window, where its first byte
	// always looks like a boundary. It is a boundary of the LINE only when the
	// byte before the window is not a word byte ("xpassport" is no label).
	if loc[0] == 0 && lo > 0 && isASCIIWordByte(line[lo-1]) {
		return false
	}
	return true
}

// lowercasePlaceholderRuns are the leading letter runs of the placeholders a
// labelled field holds when it has no real value. Each is EU-shaped once a digit
// follows ("redacted1", "tbd123456") and every one passes the label gate, so
// without this list all nine of the #888 labelled placeholders reported at 85.
var lowercasePlaceholderRuns = map[string]bool{
	"redacted": true, "password": true, "pending": true, "unknown": true,
	"missing": true, "sample": true, "document": true, "tbd": true,
	"abc": true, "xyz": true, "none": true, "null": true, "test": true,
}

// isLowercasePlaceholder reports whether a mixed-case candidate is a placeholder
// rather than a value: its leading letter run is one of lowercasePlaceholderRuns,
// or a word of four letters or more by the isLikelyWord test, which catches the
// placeholders nobody listed ("Passport Number: invalid01" and "deleted01" were
// EU 100 without it).
//
// Applied to mixed-case candidates only. On uppercase values it would remove
// findings reported today (REDACTED1 and PASSWORD1 under a passport label are EU
// 85), which would make it a suppressor narrowing, not a recall fix.
// "gk123456", "ya1234567", "de1234567" and "k12345678" have runs of one or two
// letters and are not touched.
func (v *Validator) isLowercasePlaceholder(match string) bool {
	n := 0
	for n < len(match) && isASCIILetter(match[n]) {
		n++
	}
	run := strings.ToLower(match[:n])
	if lowercasePlaceholderRuns[run] {
		return true
	}
	return n >= 4 && v.isLikelyWord(run)
}

// namesPassport reports whether a lowercased label (a column header, the field
// label above a value) names a passport.
func namesPassport(label string) bool {
	return strings.Contains(label, "passport") || strings.Contains(label, "travel document")
}

// hasASCIILower reports whether s contains an ASCII lowercase letter.
func hasASCIILower(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return true
		}
	}
	return false
}

// asciiUpper upper-cases the ASCII letters of s and leaves every other byte as it
// is, so the result has exactly len(s) bytes. strings.ToUpper is not
// length-preserving on non-ASCII input (#656); the mixed-case patterns only ever
// match ASCII, but the canonical form must not depend on that remaining true.
func asciiUpper(s string) string {
	if !hasASCIILower(s) {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isASCIIWordByte reports whether c is a regexp \w byte: [0-9A-Za-z_].
func isASCIIWordByte(c byte) bool {
	return isASCIILetter(c) || (c >= '0' && c <= '9') || c == '_'
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
	inWordCache map[string]bool // memoized "keyword present in lineLower as a whole word"

	// columnHeader is the lowercased header cell naming the column this match
	// sits in, when the document is delimited tabular data and the match is on a
	// data row. Empty otherwise.
	//
	// This exists because PASSPORT is label-GATED — it reports nothing without a
	// nearby label — and the label search stops at the newline. In a CSV export
	// the label IS the header row, one or more lines above the value, so
	//
	//	name,email,passport_number,country
	//	Jane,jane@corp.example,987654321,US
	//
	// produced NO passport finding at all, while the identical text written inline
	// as "Passport Number: 987654321" scores HIGH. An unreported value is never
	// handed to the redactor, so the redacted output of that CSV still contained
	// the passport number in cleartext.
	//
	// Treating the column header as context for its own column's values is what
	// closes that. It is set per match (the column varies along the row) but
	// resolved by binary search over per-line bounds, so the per-match cost is
	// logarithmic rather than a rescan.
	columnHeader string

	// labelAbove is the lowercased previous line when that line is a bare form-field
	// LABEL rather than prose.
	//
	// Same defect as columnHeader in a different layout. PASSPORT is label-gated and the
	// keyword search stops at the newline, so a two-line form
	//
	//	Field: Passport Number
	//	Value: 512345678
	//
	// produced no passport finding. Worse than a plain miss: the number was reported as
	// an SSN at 50 instead, so redaction applied SSN's partial mask and left four digits
	// readable in a file the tool called redacted.
	//
	// Gated on kwmatch.LooksLikeFieldLabel rather than on a keyword being present,
	// because a keyword alone admits prose: "Please renew your driver's license soon."
	// is the same length, carries the keyword and has no digits. The shape test is what
	// separates them.
	labelAbove string

	// firstWord is the offset of the line's first ASCII letter or digit, or -1 when
	// the line has none. Computed only when labelAbove names a passport, because it
	// is only read by the mixed-case gate's label-above arm: a label line vouches for
	// the value written under it, not for a token inside the next field's line.
	firstWord int
}

func newLineContext(lineLower string) *lineContext {
	return &lineContext{lineLower: lineLower, firstWord: -1}
}

// firstASCIIWord returns the offset of the first ASCII letter or digit in s, or -1.
func firstASCIIWord(s string) int {
	for i := 0; i < len(s); i++ {
		if isASCIILetter(s[i]) || (s[i] >= '0' && s[i] <= '9') {
			return i
		}
	}
	return -1
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

// inLineAsWord reports whether kw occurs in the full lower-cased line with no
// ASCII word byte immediately before or after it, memoized like inLine. Each
// occurrence is tested once and the next search starts past it, so the scan is
// linear in the line.
func (c *lineContext) inLineAsWord(kw string) bool {
	if c.inWordCache == nil {
		c.inWordCache = make(map[string]bool, 16)
	}
	if hit, ok := c.inWordCache[kw]; ok {
		return hit
	}
	hit := false
	if kw != "" && c.inLine(kw) {
		for from := 0; from <= len(c.lineLower)-len(kw); {
			i := strings.Index(c.lineLower[from:], kw)
			if i < 0 {
				break
			}
			i += from
			end := i + len(kw)
			if (i == 0 || !isASCIIWordByte(c.lineLower[i-1])) &&
				(end == len(c.lineLower) || !isASCIIWordByte(c.lineLower[end])) {
				hit = true
				break
			}
			from = i + 1
		}
	}
	c.inWordCache[kw] = hit
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
	// The column header names this value's column, so a keyword in it is context
	// FOR this value in exactly the way a same-line label is. Checked first
	// because it is a short string and the common case is a miss.
	if c.columnHeader != "" && strings.Contains(c.columnHeader, kw) {
		return true
	}
	// A bare field label on the line above is context for this line's value, for the
	// same reason. Also a short string, so the miss is cheap.
	if c.labelAbove != "" && strings.Contains(c.labelAbove, kw) {
		return true
	}
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

			// Give more weight to keywords on the match's own line.
			//
			// The first test is the original one: the lowered keyword in the
			// original-case line. On its own it meant "Passport" and "PASSPORT"
			// never earned the 1.5x that "passport" did, so the same sentence
			// scored lower when its label was capitalised (#888). The second test
			// grants it to the keyword in any letter case, but only as a whole
			// word of the lowered line. A bare substring test of the lowered line
			// would also grant it to "mrz" inside base64 ("...LajVlMRZ8W4t...") and
			// was measured to report EU-shaped chunks of PGP test keys in
			// golang.org/x/crypto at 63; a capitalised label is the same word, an
			// accidental run of letters inside a token is not. The first test is
			// kept as it was, so no score main computed can fall.
			if strings.Contains(context.FullLine, keywordLower) || lc.inLineAsWord(keywordLower) {
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
			// Give more weight to keywords that are closer to the match.
			//
			// Deliberately still the ORIGINAL-CASE line, unlike the positive
			// keywords above: this branch is a suppressor, so making it
			// case-blind would take points away and drop findings that are
			// reported today ("Customer passport GK123456 on booking" is one).
			// Left as it was by #888; a case-blind negative check needs its own
			// measurement.
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
// and memoizes the per-line "variant present in line" scans.
//
// The distance is measured between the first occurrence of the LOWERED match
// and the first occurrence of the variant, both in the lowered line. Both
// operands of every Index are lower-case, so the two offsets are in the same
// coordinate space even when lower-casing changes the line's byte length
// (#656), and only their difference is used. The match used to be searched for
// in its original case, which can never be found in a lowered line once it
// contains a capital letter: every letter-bearing passport number (C12345678,
// GK123456) got no same-line boost at all, while a 9-digit number in the same
// sentence got 25 (#888).
//
// That index is only ever needed when a passport variant is actually present
// on the line, so the (line-length) scan is skipped entirely for the common
// case.
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
			matchIndex := strings.Index(lineLower, strings.ToLower(match))
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
	// A line-1 MRZ with the structural fingerprint (P< prefix, 44 chars, filler run) bypasses
	// the prose-context requirement. The issuing-state code is NOT part of this gate — that was
	// #588: an incomplete list of 48 codes silently dropped KEN/VNM/BGD/... passports because
	// their codes lost the bypass, and a scanned document without a nearby "passport" keyword
	// then stayed in cleartext. The +20/-10 nudge at scoring time still fires on an unrecognised
	// code, so weak evidence is still charged; it just does not remove the bypass. hasMRZStructure
	// itself is a stronger structural claim than the country code is — a random 3-letter token
	// starting with an ISO code and no "<" fillers is exactly what it is built to reject.
	if hasMRZStructure(match) {
		return true
	}

	// A line-2 MRZ needs the same bypass, and has a stronger claim to it. Line 1
	// is recognized structurally ("P<" plus filler padding); line 2 is recognized
	// ARITHMETICALLY — five independent 7-3-1 check digits over the document
	// number, dates and personal number all have to verify.
	//
	// Without this it does not matter that the checks pass: line 2 carries no
	// "passport" keyword (it is pure machine-readable data), so the prose-context
	// requirement drops it and the number stays in cleartext. That is the whole
	// leak — a scanned passport emits both lines, line 1 was redacted and line 2
	// was not.
	if mrzLine2ChecksValid(match) {
		return true
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

	case "MRZ_TD3_L2":
		// Machine Readable Zone (ICAO 9303) line 2: document number, its check
		// digit, 3-letter issuing state, date of birth + check digit, sex, expiry
		// + check digit, personal number + check digit, composite check digit.
		//
		// The candidate has already satisfied all five check digits by the time
		// it reaches here (mrzLine2ChecksValid gates both the emit loop and
		// determineCountry), so this is a stronger claim than any of the shape-only
		// national formats: five independent mod-10 digits over the document's own
		// bytes. +25 puts a verified line 2 clear of the surfacing threshold on its
		// own merit, which it has to be — line 2 is pure machine-readable data and
		// carries no prose keyword to lean on.
		confidence += 25

		if !reMRZChars.MatchString(cleanMatch) {
			confidence -= 15
			checks["valid_characters"] = false
		}

		// Issuing state sits at [10:13] on line 2 (not [2:5] as on line 1), which
		// is why the generic 2-letter validCountryCodes lookup used elsewhere
		// reports it as invalid and docked the score.
		if len(cleanMatch) >= 13 && v.validMRZCountryCodes[cleanMatch[10:13]] {
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
	// Check against common words list. Unconditional: a match that literally IS one of these
	// words is a false positive whatever its shape.
	for _, word := range v.commonWords {
		if strings.EqualFold(text, word) {
			return true
		}
	}

	// The vowel-ratio heuristic below is only meaningful when the WHOLE match could be an
	// English word, and an English word is made of letters. Applying it to anything else was
	// #591, and it silently dropped real passports:
	//
	//   - An MRZ is 44 characters of format: "P<" + issuing state + a "<"-padded name field.
	//     Its vowel content is decided entirely by the HOLDER'S NAME, so whether a passport was
	//     protected depended on how the holder is called. Measured on 16 real names, 10 MISSED
	//     (base 60 + 20 for a valid country code - 40 here - 25 from isPossibleFalsePositive
	//     = 15, under the 60 emit threshold): ERIKSSON, JOHANSSON, GARCIA, TANAKA, MUELLER,
	//     ROSSI, PAPADOPOULOS, OKONKWO, AALTO, KAMEHAMEHA. Reported: SMITH, GHYNSKI, OMOLLO,
	//     SINGH, NGUYEN, KOWALSKI. The bias is not incidental -- it falls on Swedish, Spanish,
	//     Japanese, German, Italian, Greek, Igbo, Finnish and Hawaiian orthographies, which use
	//     more vowels than English does.
	//
	//   - A national passport NUMBER contains digits, and two of them can still land in the
	//     window. Measured: the Canadian shape AE123456 (2 vowels of 8 = 25%) scored 0 where
	//     BC123456 scored 45, and the EU shape AE1234567 scored 0 too. Two letters of a
	//     document number decided whether it was reported.
	//
	// By the sink rule each of those is a cleartext leak: only reported findings reach the
	// redactor. Requiring letters is what makes the heuristic apply where it means something --
	// a digit or an MRZ filler "<" occurs in no English word, so nothing that was correctly
	// caught before is let through.
	if !isWordShaped(text) {
		return false
	}

	// Simple heuristic: English words typically have vowels
	// and a reasonable vowel-to-consonant ratio
	if len([]rune(text)) >= 5 {
		vowels := 0
		runes := []rune(strings.ToUpper(text))
		for _, char := range runes {
			if strings.ContainsRune("AEIOU", char) {
				vowels++
			}
		}

		// If it has vowels and the ratio of vowels to length is reasonable for English
		vowelRatio := float64(vowels) / float64(len(runes))
		return vowels >= 1 && vowelRatio >= 0.2 && vowelRatio <= 0.6
	}

	return false
}

// isWordShaped reports whether text could be a single English word: letters only.
//
// Counted in RUNES, not bytes, so an accented word ("Café") is still word-shaped and the ratio
// below is computed against the character count rather than the UTF-8 length -- measuring a
// 5-character word as 6 bytes would move it in the window for no reason.
//
// Empty is NOT word-shaped: an empty string has no vowels, so the ratio is undefined and the
// old code's len >= 5 guard was the only thing stopping a divide-by-zero.
func isWordShaped(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
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
	} else if mrzLine2ChecksValid(cleanMatch) {
		// A TD3 line-2 MRZ has no "P" prefix — it starts with the document
		// number — so it reaches this branch. Identify it by the check digits
		// rather than by shape: this function's result gates emission (the caller
		// skips a match whose country is ""), so without this arm every line-2
		// finding would be silently dropped after passing the checks above.
		return "MRZ_TD3_L2"
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
