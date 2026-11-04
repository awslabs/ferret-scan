// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	stdctx "context"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"

	"github.com/awslabs/ferret-scan/v2/internal/bytefold"
)

// Pre-compiled regex patterns for bank account detection.
// intrinsicValueFloor is the confidence a checksum-valid value keeps even when
// the line's keywords score it to zero. It applies to IBAN only — the mod-97
// checksum is the one value-intrinsic proof in this validator that an attacker
// cannot forge away, since a real IBAN they want to exfiltrate must pass it.
// SWIFT/BIC is format-only, and bare US account numbers have no checksum, so
// context is the only evidence those have and suppressing them stays correct.
// ABA has a checksum but also passes for roughly 1 in 10 random 9-digit numbers,
// so its banking-context requirement is load-bearing against false positives
// rather than an attacker-controlled suppressor; see THREAT_MODEL.md §4.7 for the
// residual.
const intrinsicValueFloor = 15.0

var (
	// ABA routing number: 9 digits, word-boundary anchored.
	reABA = regexp.MustCompile(`\b\d{9}\b`)

	// IBAN: 2-letter country code + 2 check digits + up to 30 alphanumeric.
	// We require at least 15 characters total (shortest valid IBAN is Norway at 15).
	// The grouped display forms are read by findDisplayIBANs instead of a regex.
	reIBAN = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)

	// SWIFT/BIC: 4 bank + 2 country + 2 location + optional 3 branch (8 or 11 chars).
	reSWIFT = regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`)

	// US bank account number: 8-17 digits, word-boundary anchored.
	reUSAccount = regexp.MustCompile(`\b\d{8,17}\b`)

	// Helper patterns for false positive suppression.
	rePhoneLike   = regexp.MustCompile(`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	reDateLike    = regexp.MustCompile(`\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}`)
	reVersionLike = regexp.MustCompile(`\b[vV]?\d+\.\d+\.\d+`)
	// reVersionPrefix matches a "v"/"v." version prefix bound to a digit at a
	// word boundary (v.1, v2, V.10), so a version-labelled number is suppressed
	// without a bare "v." substring firing inside unrelated words.
	reVersionPrefix = regexp.MustCompile(`\b[vV]\.?\d`)

	// IBAN countries, lengths and BBAN structures: ibanRegistry in iban_registry.go, generated
	// from the SWIFT IBAN Registry (#862).
)

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

// containsLabel is containsKeyword for a keyword that LABELS the value it sits beside,
// letting its spaces match zero separators so "routing number" also finds "routingNumber".
//
// Only positive keyword lists may use it. containsKeyword still requires a separator, which
// is what the negative and phone-suppressor lists here keep — widening a suppressor silences
// real values, and "call us" -> "callus" is a live example in this package: the phone
// suppressor gates looksLikePhone, so an ordinary clinical line mentioning a callus would
// drop a real account number beside it. See kwmatch.ContainsLabel.
func containsLabel(text, keyword string) bool {
	return kwmatch.ContainsLabel(text, keyword)
}

// Validator implements the detector.Validator interface for detecting
// bank account numbers, routing numbers, IBANs, and SWIFT/BIC codes.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new Validator instance for bank account detection.
func NewValidator() *Validator {
	v := &Validator{
		pattern: `\b\d{8,17}\b`, // base pattern for US account numbers
		positiveKeywords: []string{
			"routing", "aba", "account number", "bank account", "checking",
			"savings", "wire", "swift", "bic", "iban", "transit",
			"financial institution", "deposit", "ach", "direct deposit",
			"bank", "routing number", "account no", "acct",
		},
		negativeKeywords: []string{
			"phone", "zip", "postal", "serial", "model", "version",
			"test", "example", "sample", "ssn", "social security",
			"placeholder", "fake", "mock", "demo", "ip address",
			"order", "invoice", "tracking", "confirmation",
		},
	}
	v.regex = regexp.MustCompile(v.pattern)
	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates content for bank account information.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// lineContext holds per-line values that are invariant across every match on
// the line. AnalyzeContext, hasStrongNegativeContext and hasBankingKeywords all
// scan the whole line and ignore the match position, so their results are the
// same for every match — computing them once per line instead of once per match
// is what keeps scanning O(line length) instead of O(matches × line length).
// The latter is a CPU-exhaustion DoS on a single long line (a crafted 48KB line
// otherwise pins a core for seconds). See the timing regression test.
type lineContext struct {
	lower          string  // bytefold.Lower(line), for near-match keyword probes
	keywordImpact  float64 // AnalyzeContext result (positive/negative keyword scan)
	strongNegative bool    // hasStrongNegativeContext(line)
	bankingKeyword bool    // hasBankingKeywords(line)
	phoneKeyword   bool    // any phone-context keyword on the line (looksLikePhone)
}

// buildLineContext computes the per-line invariants once. AnalyzeContext is
// invoked with an empty before/after window and the full line: because the
// function only tests keyword PRESENCE in BeforeText+FullLine+AfterText and
// FullLine already spans the whole line, this yields the identical keyword set
// (and therefore identical impact) as the original per-match calls.
func (v *Validator) buildLineContext(line string) lineContext {
	return lineContext{
		// bytefold.Lower, not strings.ToLower. keywordNearMatch indexes this copy
		// with offsets taken from `line`, and Unicode case mapping is not
		// length-preserving: U+212A KELVIN SIGN folds 3 bytes to 1, so a line
		// carrying a run of them made the offsets overshoot and panicked, which
		// the router recovered into ZERO findings for the whole file at exit 0
		// (#656). Folding only ASCII costs nothing here -- every keyword probed
		// for is ASCII -- and makes the position invariant true by construction.
		lower:          bytefold.Lower(line),
		keywordImpact:  v.AnalyzeContext("", detector.ContextInfo{FullLine: line}),
		strongNegative: v.hasStrongNegativeContext(line),
		bankingKeyword: v.hasBankingKeywords(line),
		// Phone-context keywords are line-global (looksLikePhone asked the
		// same six whole-line questions for EVERY 10-digit match). Hoisting
		// them here turns the US-account scan from O(matches × line length)
		// back to O(line length) — this was the bankaccount O(n^2) the
		// expanded complexity guard caught.
		phoneKeyword: containsKeyword(line, "phone") || containsKeyword(line, "telephone") ||
			containsKeyword(line, "fax") || containsKeyword(line, "call us") ||
			containsKeyword(line, "mobile") || containsKeyword(line, "cell"),
	}
}

// ValidateContentCtx is the context-aware form of ValidateContent.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		lc := v.buildLineContext(line)
		lineMatches := v.scanLine(ctx, line, lineNum, originalPath, lc)
		matches = append(matches, lineMatches...)
	}

	return matches, nil
}

// scanLine scans a single line for all bank account related patterns. The
// precomputed lineContext is shared across the per-pattern scanners so none of
// them re-scan the whole line per match.
func (v *Validator) scanLine(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// Scan for IBAN (highest specificity first)
	matches = append(matches, v.scanIBAN(ctx, line, lineNum, originalPath, lc)...)

	// Scan for SWIFT/BIC
	matches = append(matches, v.scanSWIFT(ctx, line, lineNum, originalPath, lc)...)

	// Scan for ABA routing numbers
	matches = append(matches, v.scanABA(ctx, line, lineNum, originalPath, lc)...)

	// Scan for US bank account numbers (only if banking context present)
	matches = append(matches, v.scanUSAccount(ctx, line, lineNum, originalPath, lc)...)

	return matches
}

// upperWithOffsets uppercases line and, when that is not a byte-for-byte mapping,
// returns a table translating each byte offset in the result back to an offset in
// line.
//
// Uppercasing is per-rune and can change a rune's byte length: U+017F LATIN SMALL
// LETTER LONG S occupies 2 bytes and uppercases to "S", which occupies 1. Every
// offset after such a rune is therefore shifted, and slicing line with an offset
// found in the uppercased copy addresses the wrong bytes. Measured, before this
// existed:
//
//	input:    Payment ref ſ IBAN GB82WEST12345698765432 end
//	reported: " GB82WEST1234569876543"  (leading space, final digit missing)
//	redacted: Payment ref ſ IBAN**********************2 end
//
// The last digit of the IBAN stayed in cleartext and the mask covered the preceding
// space instead, at rc=0. The same shift makes scanSWIFT's "original must already
// be uppercase" comparison fail against a mis-sliced string, dropping a real SWIFT
// code entirely.
//
// The uppercased string is built here rather than by strings.ToUpper so the text and
// its offset table cannot disagree. A nil table means the identity mapping, which
// holds for any all-ASCII line — the overwhelming majority — so the common path
// allocates no table.
func upperWithOffsets(line string) (string, []int) {
	ascii := true
	for i := 0; i < len(line); i++ {
		if line[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToUpper(line), nil
	}

	var b strings.Builder
	b.Grow(len(line) + 8)
	offsets := make([]int, 0, len(line)+8)
	for i, r := range line {
		before := b.Len()
		b.WriteRune(unicode.ToUpper(r))
		for j := before; j < b.Len(); j++ {
			offsets = append(offsets, i)
		}
	}
	// One past the end, so a match's exclusive end offset maps too.
	offsets = append(offsets, len(line))
	return b.String(), offsets
}

// origSpan translates a [start,end) span in the uppercased line back to line.
// A nil table is the identity mapping.
func origSpan(offsets []int, start, end int) (int, int) {
	if offsets == nil {
		return start, end
	}
	last := len(offsets) - 1
	if start < 0 {
		start = 0
	}
	if start > last {
		start = last
	}
	if end < start {
		end = start
	}
	if end > last {
		end = last
	}
	return offsets[start], offsets[end]
}

// scanIBAN detects and validates IBAN numbers.
func (v *Validator) scanIBAN(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// Try case-insensitive match by checking uppercase version. upperMap translates
	// offsets in upperLine back to line — uppercasing is not length-preserving.
	upperLine, upperMap := upperWithOffsets(line)
	idxMatches := reIBAN.FindAllStringIndex(upperLine, -1)

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := upperLine[loc[0]:loc[1]]

		// Validate IBAN structure
		if !v.isValidIBAN(candidate) {
			continue
		}

		// Back to offsets in the ORIGINAL line before slicing it — see
		// upperWithOffsets.
		oStart, oEnd := origSpan(upperMap, loc[0], loc[1])

		// Context adjustment (per-line invariant)
		contextInfo := v.buildContextInfo(line, oStart, oEnd-oStart)

		confidence := 85.0 // IBAN with valid checksum is high confidence

		// Context adjustment (per-line invariant: keyword presence over the line)
		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// Value-intrinsic floor (TM-11). The mod-97 checksum was verified by
		// isValidIBAN above, so this IBAN is validated by the value itself.
		// Keywords are document content: the strongNegative hard-drop that used
		// to sit here, and the confidence<=0 drop below, let anyone who could add
		// three negative words to the line erase the finding — and since
		// redaction only rewrites what was emitted, the IBAN then passed through
		// --enable-redaction in cleartext. Measured: "IBAN GB82WEST12345698765432"
		// scores 100, +1 keyword 80, +2 keywords 60, and +3 keywords produced no
		// finding at all. Context may now demote to the bottom of LOW; it may not
		// erase. Note isValidIBAN itself still rejects outright — that is
		// value-intrinsic *fakeness*, which an attacker cannot use to hide a real
		// IBAN, because a real one must pass mod-97.
		confidence = clampConfidence(confidence)
		if lc.strongNegative || confidence <= 0 {
			confidence = intrinsicValueFloor
		}

		matches = append(matches, detector.Match{
			Text:       line[oStart:oEnd], // preserve original case
			LineNumber: lineNum + 1,
			Type:       "IBAN",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"country":        candidate[:2],
				"context_impact": contextImpact,
				// Every check below was already decided by the isValidIBAN gate above; this
				// records the results so --explain can narrate them. Without it the
				// explanation collapsed to "Flagged as an IBAN; nearby context raised
				// confidence by 15%" — restating the type and a number the reviewer had
				// already been shown, with no mention of the mod-97 proof that is the whole
				// reason this finding is trustworthy (#363). valid_characters covers the BBAN
				// structure check (#862): every character has the class the registry gives its
				// position. No key was added for it, so the metadata a finding carries is unchanged.
				//
				// Recording only, never scoring: isValidIBAN is a hard gate, so all three are
				// necessarily true here and adding them changes no confidence. Metadata is not
				// an input to the suppression hash either (that reads type, confidence, line,
				// filename, offsets and the hashed text), so existing rules keep matching.
				"validation_checks": map[string]bool{
					"valid_country":    true,
					"valid_length":     true,
					"mod97_checksum":   true,
					"valid_characters": true,
				},
			},
		})
	}

	// Second pass: display-format IBANs, grouped in fours by spaces or hyphens, and any form
	// joined to a label by '_'. Each candidate is read at its country's registered length and
	// must pass the identical isValidIBAN gate; the reported span is the original grouped text
	// so redaction masks the whole token. See findDisplayIBANs.
	for _, d := range v.findDisplayIBANs(ctx, upperLine) {
		normalized := d.normalized

		// Back to offsets in the ORIGINAL line — see upperWithOffsets.
		oStart, oEnd := origSpan(upperMap, d.start, d.end)

		// Value-intrinsic floor (TM-11) — same reasoning as the compact-form pass
		// above; mod-97 is verified, so context may demote but not erase.
		confidence := clampConfidence(85.0 + lc.keywordImpact)
		if lc.strongNegative || confidence <= 0 {
			confidence = intrinsicValueFloor
		}

		matches = append(matches, detector.Match{
			Text:       line[oStart:oEnd], // original case and spacing
			LineNumber: lineNum + 1,
			Type:       "IBAN",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    v.buildContextInfo(line, oStart, oEnd-oStart),
			Metadata: map[string]any{
				"country":        normalized[:2],
				"context_impact": lc.keywordImpact,
				"normalized":     normalized,
				// Same four checks as the compact-form pass above, and for the same reason:
				// this pass applies the identical isValidIBAN gate to the normalized value.
				// Recording only; no score or hash input changes.
				"validation_checks": map[string]bool{
					"valid_country":    true,
					"valid_length":     true,
					"mod97_checksum":   true,
					"valid_characters": true,
				},
			},
		})
	}

	return matches
}

// displayIBAN is one IBAN found by findDisplayIBANs: its [start, end) span in the uppercased line
// and its value with the separators removed.
type displayIBAN struct {
	start, end int
	normalized string
}

// underscoreLabelWindow bounds how far either side of a '_'-joined value the label check reads,
// so a line of '_'-joined candidates stays linear. A label further away than this inside one
// identifier is not plausibly naming the value.
const underscoreLabelWindow = 64

// findDisplayIBANs reads IBANs in their printed form: the electronic value broken into groups of
// four ("DE89 3704 0044 0532 0130 00"), with a single space, two spaces or a hyphen between groups,
// and the last group (L-4) mod 4 long, or 4 when that is 0. It replaces a regex,
//
//	\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b
//
// that lost IBANs in three ways, measured on main for #862:
//
//   - Its optional short last group took the next word whenever the country's length is a
//     multiple of 4, and a failing candidate was dropped whole: "IBAN: <ES IBAN> BIC: EXMPESMM"
//     read the "BIC:" into the candidate, failed the length check and reported nothing. That held
//     for 29 of the 74 countries it knew, before any word of 1-4 characters ("BIC", "EUR", "for",
//     "2026"), so the footer of an invoice had its BIC masked and its IBAN left in cleartext.
//   - FindAll is non-overlapping, so no start inside a rejected candidate was ever tried:
//     "Ref XX12 <IBAN>" and two IBANs on one line lost the IBAN after the rejected start.
//   - It accepted one ASCII space only, so hyphen- and double-space-grouped IBANs were never
//     found, and the normalized pass (which folds Unicode dashes to '-') had nothing to land on.
//
// So every candidate is read at exactly its country's registered length. A candidate starts at
// each two letters and two digits that begin a word: at the start of the line, after any byte
// outside [A-Za-z0-9_], or after a '_' (see below). The separator is taken from the first gap
// and must repeat at every gap. The byte after the last group must not be a letter, digit or
// '_', which keeps a cut out of a longer run (a hex dump row, a licence key). A hyphen-grouped
// value additionally must not continue a hyphen run on either side ("ABCD-<value>",
// "<value>-ABCD"): the trailing word that a spaced IBAN must tolerate ("BIC:", "EUR") has no
// hyphenated counterpart in print. On rejection the scan moves to the next start, including
// starts inside the rejected span; on acceptance it resumes after the span.
//
// The compact form at an ordinary boundary is the reIBAN pass's, and is skipped here. A value of
// any form joined to its neighbour by '_' ("iban_DE89...", "bank_iban_DE89 3704 ...") is a value
// that \b never matched, because '_' is a word byte to RE2. It is reported only when the
// '_'-joined identifier names it with one of this validator's positive keywords, so
// "statement_<IBAN>.pdf" and "<IBAN>_2026.pdf" stay unreported.
//
// Every candidate passes the same isValidIBAN gate as a compact one, including the BBAN
// structure check. That check is what keeps this wider read from widening the false positives:
// measured with the check disabled, the wider read took a seeded 4 MiB xxd dump from 13 IBAN
// findings (main) to 54; with it, the dump reports none (#862).
//
// Not accepted, since none is the standard print form and each would need its own decoy
// measurement: a split head ("DE 89 3704 ..."), mixed separators, grouping by BBAN component.
//
// Each start reads at most 34 characters across at most 8 gaps, so the scan is linear in the line.
func (v *Validator) findDisplayIBANs(ctx stdctx.Context, u string) []displayIBAN {
	var found []displayIBAN
	var buf [maxIBANLength]byte
	for i := 0; i+4 <= len(u); i++ {
		if execguard.LineLoopCancelled(ctx, i) {
			return found
		}
		if !isUpperLetter(u[i]) || !isUpperLetter(u[i+1]) || !isDigit(u[i+2]) || !isDigit(u[i+3]) {
			continue
		}
		leadUnderscore := false
		if i > 0 {
			switch p := u[i-1]; {
			case p == '_':
				leadUnderscore = true
			case isIdentByte(p):
				continue // inside a word: not a start
			}
		}
		country, ok := lookupIBANCountry(u[i], u[i+1])
		if !ok {
			continue
		}
		sep := displaySeparator(u, i+4)
		end, n := readIBANGroups(u, i, country.length, sep, buf[:])
		if end < 0 {
			continue
		}
		trailUnderscore := false
		if end < len(u) {
			switch c := u[end]; {
			case c == '_':
				trailUnderscore = true
			case isIdentByte(c):
				continue // a cut out of a longer run
			}
		}
		if sep == "" && !leadUnderscore && !trailUnderscore {
			continue // the compact pass reports this value
		}
		if sep == "-" && continuesHyphenRun(u, i, end) {
			continue
		}
		normalized := string(buf[:n])
		if !v.isValidIBAN(normalized) {
			continue
		}
		if (leadUnderscore || trailUnderscore) && !v.underscoreJoinIsLabelled(u, i, end, leadUnderscore, trailUnderscore) {
			continue
		}
		found = append(found, displayIBAN{start: i, end: end, normalized: normalized})
		i = end - 1 // resume after the accepted span
	}
	return found
}

// displaySeparator returns the gap a display-form IBAN uses, read at the first gap (offset j, just
// after the 4-character head): two spaces, one space, a hyphen, or "" for the compact form.
func displaySeparator(u string, j int) string {
	switch {
	case j+1 < len(u) && u[j] == ' ' && u[j+1] == ' ':
		return "  "
	case j < len(u) && u[j] == ' ':
		return " "
	case j < len(u) && u[j] == '-':
		return "-"
	}
	return ""
}

// readIBANGroups reads an IBAN of exactly length characters starting at u[i], grouped in fours
// with sep between groups, into buf. It returns the end offset of the last group and the number
// of characters written, or -1 when the text does not hold that grouping.
func readIBANGroups(u string, i, length int, sep string, buf []byte) (int, int) {
	n := copy(buf, u[i:i+4])
	pos := i + 4
	for rem := length - 4; rem > 0; {
		g := 4
		if rem < 4 {
			g = rem
		}
		if sep != "" {
			if !strings.HasPrefix(u[pos:], sep) {
				return -1, 0
			}
			pos += len(sep)
		}
		if pos+g > len(u) {
			return -1, 0
		}
		for k := 0; k < g; k++ {
			c := u[pos+k]
			if !isUpperLetter(c) && !isDigit(c) {
				return -1, 0
			}
			buf[n] = c
			n++
		}
		pos += g
		rem -= g
	}
	return pos, n
}

// continuesHyphenRun reports whether the hyphen-grouped span [i, end) is one segment of a longer
// hyphenated token: a letter or digit joined to it by a hyphen on either side.
func continuesHyphenRun(u string, i, end int) bool {
	if i >= 2 && u[i-1] == '-' && isAlnumByte(u[i-2]) {
		return true
	}
	return end+1 < len(u) && u[end] == '-' && isAlnumByte(u[end+1])
}

// underscoreJoinIsLabelled reports whether the identifier a '_'-joined value sits in names it:
// one of the positive keywords in the part of the identifier before the value (leading '_') or
// after it (trailing '_'). Each side is read at most underscoreLabelWindow bytes; when the
// identifier runs past that, the partial segment at the cut is dropped, so a cut can never turn
// "xbank" into "bank".
func (v *Validator) underscoreJoinIsLabelled(u string, start, end int, lead, trail bool) bool {
	if lead {
		j := start
		for j > 0 && start-j < underscoreLabelWindow && isIdentByte(u[j-1]) {
			j--
		}
		if j > 0 && isIdentByte(u[j-1]) {
			k := strings.IndexByte(u[j:start], '_')
			if k < 0 {
				j = start
			} else {
				j += k
			}
		}
		if v.namesBankingValue(u[j:start]) {
			return true
		}
	}
	if trail {
		j := end
		for j < len(u) && j-end < underscoreLabelWindow && isIdentByte(u[j]) {
			j++
		}
		if j < len(u) && isIdentByte(u[j]) {
			k := strings.LastIndexByte(u[end:j], '_')
			if k < 0 {
				j = end
			} else {
				j = end + k
			}
		}
		if v.namesBankingValue(u[end:j]) {
			return true
		}
	}
	return false
}

// namesBankingValue reports whether s holds one of the positive keywords as a label.
func (v *Validator) namesBankingValue(s string) bool {
	if s == "" {
		return false
	}
	for _, kw := range v.positiveKeywords {
		if containsLabel(s, kw) {
			return true
		}
	}
	return false
}

func isUpperLetter(c byte) bool { return c >= 'A' && c <= 'Z' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnumByte(c byte) bool { return isDigit(c) || isUpperLetter(c) || (c >= 'a' && c <= 'z') }

// isIdentByte is RE2's \w: the bytes that do not end a word, so a value starts and ends next to
// anything else.
func isIdentByte(c byte) bool { return isAlnumByte(c) || c == '_' }

// scanSWIFT detects and validates SWIFT/BIC codes.
func (v *Validator) scanSWIFT(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// upperMap translates offsets in upperLine back to line — see upperWithOffsets.
	// Without it the originalText comparison below runs against a mis-sliced string
	// and silently drops a real SWIFT code.
	upperLine, upperMap := upperWithOffsets(line)
	idxMatches := reSWIFT.FindAllStringIndex(upperLine, -1)

	// bicLabel caches hasBICLabel(line) for the all-letter gate below.
	var bicLabel, bicLabelKnown bool

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := upperLine[loc[0]:loc[1]]
		oStart, oEnd := origSpan(upperMap, loc[0], loc[1])

		// The original text must be uppercase -- real SWIFT codes are always uppercase.
		originalText := line[oStart:oEnd]
		if originalText != candidate {
			continue
		}

		// Validate SWIFT structure
		if !v.isValidSWIFT(candidate) {
			continue
		}

		// SWIFT codes without banking context are often false positives (random 8-char strings)
		contextInfo := v.buildContextInfo(line, oStart, oEnd-oStart)
		hasBankingContext := lc.bankingKeyword

		// An all-letter candidate (no digit anywhere) is word-shaped: any 8- or
		// 11-letter uppercase word whose 5th and 6th letters spell a country code
		// passes isValidSWIFT. Only a label that names the code itself admits one:
		// "swift", "bic", or "iban", since a BIC is printed beside its IBAN on
		// payment details. A generic banking word used to admit it as well, and on a
		// bank-customer document that is most lines, so CUSTOMER (CUST+OM+ER),
		// BUSINESS (BUSI+NE+SS) and MITIGATIONS (MITI+GA+TIONS) were reported as
		// SWIFT_BIC at 100 (#801).
		//
		// The cost: an all-letter BIC whose line names only the bank ("Deutsche Bank
		// DEUTDEFF") is no longer reported. No shape test tells it from a word:
		// DEUTDEFF has three vowels and no consonant run longer than two, exactly
		// like CUSTOMER and BUSINESS. A candidate with a digit (CHASUS33, NWBKGB2L)
		// is not a word, so a generic banking word stays enough for it.
		//
		// The label is a whole-line property, so it is looked up once per line and
		// only on a line that has such a candidate: a per-match scan would make a
		// long line of words quadratic (see lineContext).
		if isCommonWord(candidate) {
			if !bicLabelKnown {
				bicLabel, bicLabelKnown = hasBICLabel(line), true
			}
			if !bicLabel {
				continue
			}
		}

		if lc.strongNegative {
			continue
		}

		confidence := 50.0 // Base is conservative for SWIFT without context
		if hasBankingContext {
			confidence = 75.0
		}

		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// SWIFT needs banking context to reach meaningful confidence
		if !hasBankingContext && confidence < 40 {
			continue
		}

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       originalText,
			LineNumber: lineNum + 1,
			Type:       "SWIFT_BIC",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"bank_code":      candidate[:4],
				"country_code":   candidate[4:6],
				"context_impact": contextImpact,
			},
		})
	}

	return matches
}

// isCommonWord checks if an uppercase string is likely a common English word
// rather than a real SWIFT/BIC code. Real SWIFT codes almost always contain at
// least one digit in positions 6-7 (location code) or are composed of unusual
// letter combinations. Words that are all letters and pronounceable are likely
// English words, not bank identifiers.
//
// Strategy: if the candidate is 8 all-letter characters (no digits anywhere),
// it is very likely a word, not a SWIFT code. Real 8-char SWIFT codes nearly
// always have digits in the location code (e.g. CHASUS33; BNPAFRPP is one
// exception, which scanSWIFT reports only on a line that names the code). For
// 11-char codes, the branch suffix often has digits too.
func isCommonWord(s string) bool {
	// All-letter strings of length 8 or 11 with no digits are almost certainly
	// English words or identifiers, not SWIFT codes.
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return false // has a digit -- likely a real SWIFT code
		}
	}
	// All letters, no digits. Unless the line names the code ("swift", "bic",
	// "iban") this is almost certainly not a SWIFT code; the caller requires that
	// label for the real all-alpha ones (BNPAFRPP, DEUTDEFF). See #801.
	return true
}

// scanABA detects and validates US ABA routing numbers.
func (v *Validator) scanABA(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	idxMatches := reABA.FindAllStringIndex(line, -1)

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := line[loc[0]:loc[1]]

		// Must be exactly 9 digits
		if len(candidate) != 9 {
			continue
		}

		// Validate ABA routing number.
		//
		// Nothing follows this but the emit. There USED to be a
		// `testRoutingNumbers[candidate]` denylist here, and it was a leak: of its
		// 14 entries only two — 011000015 (FRB Boston) and 021000021 (JPMorgan
		// Chase) — ever reached it, because isValidABA rejects the other twelve
		// first on prefix range or checksum. Those two are REAL, in-production
		// routing numbers that happen to be popular in documentation. So the
		// denylist's entire net effect was to suppress two live values while
		// contributing nothing against false positives, and because only reported
		// findings reach the redactor, suppressing them left them in the cleartext
		// of a "redacted" document. See #628.
		//
		// Deliberately not replaced by a shape rule here: every test-shaped value
		// it covered (all-same digits, 123456789, 987654321) already fails
		// isValidABA, and TestEveryFormerDenylistEntryIsRejectedOnItsOwnMerits
		// pins that so a future widening of the prefix table cannot quietly turn
		// one of them into a finding.
		if !v.isValidABA(candidate) {
			continue
		}

		contextInfo := v.buildContextInfo(line, loc[0], 9)
		if lc.strongNegative {
			continue
		}

		// ABA routing numbers are only 9 digits -- lots of 9-digit numbers exist.
		// Without banking context, confidence is low.
		hasBankingContext := lc.bankingKeyword

		confidence := 40.0 // Conservative base for bare 9-digit number
		if hasBankingContext {
			confidence = 70.0
		}

		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// Without any banking keywords, bare 9-digit numbers should not surface.
		if !hasBankingContext && confidence < 50 {
			continue
		}

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		matches = append(matches, detector.Match{
			Text:       candidate,
			LineNumber: lineNum + 1,
			Type:       "ABA_ROUTING",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata: map[string]any{
				"federal_reserve_district": candidate[:2],
				"context_impact":           contextImpact,
			},
		})
	}

	return matches
}

// scanUSAccount detects US bank account numbers (8-17 digits) only when banking
// keywords are present nearby.
func (v *Validator) scanUSAccount(ctx stdctx.Context, line string, lineNum int, originalPath string, lc lineContext) []detector.Match {
	var matches []detector.Match

	// US account numbers are just digit sequences -- require banking context.
	if !lc.bankingKeyword {
		return nil
	}

	idxMatches := reUSAccount.FindAllStringIndex(line, -1)

	// cloudPhrase caches hasCloudAccountPhrase(line) for the 12-digit ceiling below.
	var cloudPhrase, cloudPhraseKnown bool

	for i, loc := range idxMatches {
		if execguard.LineLoopCancelled(ctx, i) {
			return matches
		}
		candidate := line[loc[0]:loc[1]]
		length := len(candidate)

		// Skip anything exactly 9 digits (handled by ABA scanner)
		if length == 9 {
			continue
		}

		// Skip numbers that look like credit card numbers (Luhn valid, 13-19 digits).
		// Credit cards are a different validator's domain; flagging them as bank
		// account numbers is a cross-validator false positive.
		if looksLikeCreditCard(candidate) {
			continue
		}

		// Skip if this looks like a phone number
		if v.looksLikePhone(line, loc[0], loc[1], lc.phoneKeyword) {
			continue
		}

		// Skip if this looks like a date
		if v.looksLikeDate(line, loc[0], loc[1]) {
			continue
		}

		// Skip if preceded by version-like patterns
		if v.looksLikeVersion(line, loc[0]) {
			continue
		}

		contextInfo := v.buildContextInfo(line, loc[0], length)
		if lc.strongNegative {
			continue
		}

		confidence := 55.0 // Moderate base (requires banking context to even enter here)

		contextImpact := lc.keywordImpact
		confidence += contextImpact

		// Account numbers very close to "account" keyword get a boost. Uses the
		// per-line lowercased copy (lc.lower) so we don't re-lower the whole line
		// per match; keywordNearMatch only inspects a ±30-char window by offset.
		if v.keywordNearMatch(lc.lower, loc[0], "account") ||
			v.keywordNearMatch(lc.lower, loc[0], "acct") {
			confidence += 15
		}

		confidence = clampConfidence(confidence)
		if confidence <= 0 {
			continue
		}

		metadata := map[string]any{
			"length":         length,
			"context_impact": contextImpact,
		}

		// Twelve digits is the shape of an AWS account id or a Google Cloud project
		// number, and those are written beside the word "account" by definition. On
		// a line that names one ("AWS account", "account id", "payer", "tenant"...)
		// a banking word such as "deposit" is not evidence of a bank account, yet it
		// admitted the run here and the "account" proximity boost lifted it to 85
		// MEDIUM, and the document bridge's +20 tabular boost to 100 HIGH (#805).
		//
		// A ceiling, not a drop: a bare account number has no checksum, so this is
		// the same context-only evidence that admitted it, and a real account number
		// labelled this way is still reported and still redacted, just at LOW. The
		// ceiling is published in the metadata as well as applied here, because the
		// bridge raises confidence after this returns.
		if length == cloudAccountIDLength {
			if !cloudPhraseKnown {
				cloudPhrase, cloudPhraseKnown = hasCloudAccountPhrase(line), true
			}
			if cloudPhrase {
				if confidence > cloudAccountIDCeiling {
					confidence = cloudAccountIDCeiling
				}
				metadata[confidenceCeilingKey] = cloudAccountIDCeiling
			}
		}

		matches = append(matches, detector.Match{
			Text:       candidate,
			LineNumber: lineNum + 1,
			Type:       "US_BANK_ACCOUNT",
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "bank_account",
			Context:    contextInfo,
			Metadata:   metadata,
		})
	}

	return matches
}

// CalculateConfidence calculates the confidence score for a potential bank account match.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":        true,
		"valid_length":  false,
		"checksum":      false,
		"not_test":      true,
		"valid_country": false,
	}

	upper := strings.ToUpper(strings.TrimSpace(match))

	// Determine what type this is
	if len(upper) >= 15 && len(upper) <= 34 && len(upper) >= 2 && unicode.IsLetter(rune(upper[0])) && unicode.IsLetter(rune(upper[1])) {
		// Looks like IBAN
		checks["valid_length"] = true
		if v.isValidIBAN(upper) {
			checks["checksum"] = true
			checks["valid_country"] = true
			return 85.0, checks
		}
		return 30.0, checks
	}

	if (len(upper) == 8 || len(upper) == 11) && isAllAlphaOrDigit(upper) && hasMinLetters(upper, 6) {
		// Looks like SWIFT
		checks["valid_length"] = true
		if v.isValidSWIFT(upper) {
			checks["valid_country"] = true
			return 60.0, checks
		}
		return 25.0, checks
	}

	// Digit-only: ABA or account number
	clean := stripNonDigits(match)
	if len(clean) == 9 {
		checks["valid_length"] = true
		// A test-pattern SHAPE, not an identity denylist.
		//
		// This decides the "not_test" signal that --explain renders as a
		// likely_test verdict, and it used to read the same testRoutingNumbers map
		// scanABA did — which meant two real bank routing numbers were reported as
		// test values. Every one of the twelve entries that was genuinely a test
		// value is recognisable from its digits alone, so the shape rule is a
		// complete replacement for the map minus its two false entries (#628).
		if isTestPatternDigits(clean) {
			checks["not_test"] = false
			return 20.0, checks
		}
		if v.isValidABA(clean) {
			checks["checksum"] = true
			return 65.0, checks
		}
		return 30.0, checks
	}

	if len(clean) >= 8 && len(clean) <= 17 {
		checks["valid_length"] = true
		return 50.0, checks
	}

	checks["format"] = false
	return 10.0, checks
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
	var impact float64

	for _, keyword := range v.positiveKeywords {
		if containsKeyword(fullContext, keyword) {
			impact += 15
		}
	}

	for _, keyword := range v.negativeKeywords {
		if containsKeyword(fullContext, keyword) {
			impact -= 20
		}
	}

	// Cap impact
	if impact > 40 {
		impact = 40
	} else if impact < -50 {
		impact = -50
	}

	return impact
}

// --- Validation helpers ---

// isValidABA validates a 9-digit ABA routing number using the checksum algorithm.
// The first two digits must be 01-32 (Federal Reserve routing symbol range).
// Checksum: 3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9) mod 10 == 0
func (v *Validator) isValidABA(s string) bool {
	if len(s) != 9 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}

	// First two digits must be 01-32 (or 61-72 for electronic, 80 for traveler's checks)
	prefix, _ := strconv.Atoi(s[:2])
	validPrefix := (prefix >= 1 && prefix <= 32) ||
		(prefix >= 61 && prefix <= 72) ||
		prefix == 80
	if !validPrefix {
		return false
	}

	// Checksum validation
	d := make([]int, 9)
	for i := 0; i < 9; i++ {
		d[i] = int(s[i] - '0')
	}
	checksum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return checksum%10 == 0
}

// isValidIBAN validates an uppercased, separator-free IBAN against the SWIFT IBAN Registry
// (ibanRegistry): the country must be registered, the length must be that country's, the check
// digits must be numeric and not 00, 01 or 99, every BBAN character must have the class the
// registry gives its position, and the ISO 7064 mod 97-10 checksum must hold.
//
// The BBAN structure check (#862) is value-intrinsic, like mod-97: a real IBAN conforms to its
// country's registered structure by definition, so no content can use the check to hide one. It
// is what lets the display-form scan read more forms without reporting more noise. A
// letter-bearing token behind "DE" plus two digits passes mod-97 about once in 97 tries and used
// to be reported at 85 (195 of 20,000 seeded "ref DE<kk><18 random A-Z0-9>" lines on main), but a
// German BBAN is 18 digits; a group of hex from an xxd dump behind "be" passes for a Belgian IBAN
// the same way, and a Belgian BBAN is 12 digits. Both are now rejected. What remains is the
// residual the check cannot see: a random value that fits a country whose BBAN is mostly
// alphanumeric ("c"), such as GT or MD, and happens to pass mod-97.
func (v *Validator) isValidIBAN(s string) bool {
	if len(s) < minIBANLength || len(s) > maxIBANLength {
		return false
	}

	// Country code must be registered, and the length must be that country's.
	country, ok := lookupIBANCountry(s[0], s[1])
	if !ok || len(s) != country.length {
		return false
	}

	// Check digits (positions 2-3) must be numeric
	if s[2] < '0' || s[2] > '9' || s[3] < '0' || s[3] > '9' {
		return false
	}

	// Check digits must not be "00" or "01" or "99"
	checkDigits := s[2:4]
	if checkDigits == "00" || checkDigits == "01" || checkDigits == "99" {
		return false
	}

	// Every BBAN character must have its registered class: digit, letter, or either.
	if !bbanConforms(s[4:], country.layout) {
		return false
	}

	return ibanChecksumValid(s)
}

// ibanChecksumValid computes the ISO 7064 mod 97-10 check over an uppercased IBAN: the first four
// characters moved to the end, each letter read as two digits (A=10 ... Z=35), and the whole
// number taken mod 97, which must be 1. The remainder is carried digit by digit, so no big number
// or intermediate string is built. Any character other than A-Z and 0-9 fails.
func ibanChecksumValid(s string) bool {
	if len(s) < 5 {
		return false
	}
	remainder := 0
	for i := 0; i < len(s); i++ {
		c := s[(i+4)%len(s)]
		switch {
		case c >= '0' && c <= '9':
			remainder = (remainder*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			remainder = (remainder*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

// isValidSWIFT validates a SWIFT/BIC code structure.
func (v *Validator) isValidSWIFT(s string) bool {
	if len(s) != 8 && len(s) != 11 {
		return false
	}

	// First 4: bank code (letters only)
	for i := 0; i < 4; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}

	// Chars 4-5: country code (must be valid ISO 3166-1)
	countryCode := s[4:6]
	if !isValidCountryCode(countryCode) {
		return false
	}

	// Chars 6-7: location code (letters or digits)
	for i := 6; i < 8; i++ {
		if !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
			return false
		}
	}

	// Optional chars 8-10: branch code (letters or digits)
	if len(s) == 11 {
		for i := 8; i < 11; i++ {
			if !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9')) {
				return false
			}
		}
	}

	return true
}

// isValidCountryCode checks if a 2-letter code is a valid ISO 3166-1 country.
func isValidCountryCode(code string) bool {
	// Common SWIFT country codes (non-exhaustive but covers major financial centers)
	validCodes := map[string]bool{
		"AD": true, "AE": true, "AF": true, "AG": true, "AL": true, "AM": true,
		"AO": true, "AR": true, "AT": true, "AU": true, "AZ": true, "BA": true,
		"BB": true, "BD": true, "BE": true, "BF": true, "BG": true, "BH": true,
		"BI": true, "BJ": true, "BM": true, "BN": true, "BO": true, "BR": true,
		"BS": true, "BT": true, "BW": true, "BY": true, "BZ": true, "CA": true,
		"CD": true, "CF": true, "CG": true, "CH": true, "CI": true, "CL": true,
		"CM": true, "CN": true, "CO": true, "CR": true, "CU": true, "CV": true,
		"CY": true, "CZ": true, "DE": true, "DJ": true, "DK": true, "DM": true,
		"DO": true, "DZ": true, "EC": true, "EE": true, "EG": true, "ER": true,
		"ES": true, "ET": true, "FI": true, "FJ": true, "FK": true, "FM": true,
		"FO": true, "FR": true, "GA": true, "GB": true, "GD": true, "GE": true,
		"GH": true, "GI": true, "GL": true, "GM": true, "GN": true, "GQ": true,
		"GR": true, "GT": true, "GW": true, "GY": true, "HK": true, "HN": true,
		"HR": true, "HT": true, "HU": true, "ID": true, "IE": true, "IL": true,
		"IN": true, "IQ": true, "IR": true, "IS": true, "IT": true, "JM": true,
		"JO": true, "JP": true, "KE": true, "KG": true, "KH": true, "KI": true,
		"KM": true, "KN": true, "KP": true, "KR": true, "KW": true, "KY": true,
		"KZ": true, "LA": true, "LB": true, "LC": true, "LI": true, "LK": true,
		"LR": true, "LS": true, "LT": true, "LU": true, "LV": true, "LY": true,
		"MA": true, "MC": true, "MD": true, "ME": true, "MG": true, "MH": true,
		"MK": true, "ML": true, "MM": true, "MN": true, "MO": true, "MR": true,
		"MT": true, "MU": true, "MV": true, "MW": true, "MX": true, "MY": true,
		"MZ": true, "NA": true, "NE": true, "NG": true, "NI": true, "NL": true,
		"NO": true, "NP": true, "NR": true, "NZ": true, "OM": true, "PA": true,
		"PE": true, "PG": true, "PH": true, "PK": true, "PL": true, "PS": true,
		"PT": true, "PW": true, "PY": true, "QA": true, "RO": true, "RS": true,
		"RU": true, "RW": true, "SA": true, "SB": true, "SC": true, "SD": true,
		"SE": true, "SG": true, "SI": true, "SK": true, "SL": true, "SM": true,
		"SN": true, "SO": true, "SR": true, "SS": true, "ST": true, "SV": true,
		"SY": true, "SZ": true, "TD": true, "TG": true, "TH": true, "TJ": true,
		"TL": true, "TM": true, "TN": true, "TO": true, "TR": true, "TT": true,
		"TV": true, "TW": true, "TZ": true, "UA": true, "UG": true, "US": true,
		"UY": true, "UZ": true, "VA": true, "VC": true, "VE": true, "VG": true,
		"VN": true, "VU": true, "WS": true, "XK": true, "YE": true, "ZA": true,
		"ZM": true, "ZW": true,
	}
	return validCodes[code]
}

// --- Context helpers ---

// buildContextInfo constructs a ContextInfo from a line and match position.
func (v *Validator) buildContextInfo(line string, matchStart, matchLen int) detector.ContextInfo {
	ci := detector.ContextInfo{
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

	ci.BeforeText = line[start:matchStart]
	ci.AfterText = line[matchStart+matchLen : end]

	return ci
}

// hasBankingKeywords checks if the line contains any banking-related keywords.
func (v *Validator) hasBankingKeywords(line string) bool {
	for _, kw := range v.positiveKeywords {
		if containsLabel(line, kw) {
			return true
		}
	}
	return false
}

// bicLabels are the keywords that name a SWIFT/BIC code itself rather than banking
// in general. "iban" is one because payment details print the BIC beside the IBAN
// ("IBAN: ... BIC: ..."). Each is also a positive keyword, so a line carrying one
// still sets bankingKeyword and scores exactly as before.
var bicLabels = []string{"swift", "bic", "iban"}

// hasBICLabel reports whether the line names a SWIFT/BIC code. scanSWIFT requires
// it before reporting an all-letter candidate (see isCommonWord, #801).
func hasBICLabel(line string) bool {
	for _, kw := range bicLabels {
		if containsLabel(line, kw) {
			return true
		}
	}
	return false
}

// hasStrongNegativeContext checks for negative keywords that strongly indicate
// this is not a bank account number. Returns true when negative evidence
// overwhelmingly outweighs positive evidence (e.g. "test example sample" with
// only one banking keyword nearby).
func (v *Validator) hasStrongNegativeContext(line string) bool {
	negCount := 0
	hasPostalNeg := false
	for _, kw := range v.negativeKeywords {
		if containsKeyword(line, kw) {
			negCount++
			if kw == "zip" || kw == "postal" {
				hasPostalNeg = true
			}
		}
	}
	if negCount == 0 {
		return false
	}

	posCount := 0
	hasOnlyRoutingPos := true
	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			posCount++
			if kw != "routing" && kw != "routing number" && kw != "transit" {
				hasOnlyRoutingPos = false
			}
		}
	}

	// Suppress when negatives strongly outnumber positives (3+ negatives with
	// at most 1 positive, or 2+ negatives with zero positives).
	if negCount >= 3 && posCount <= 1 {
		return true
	}
	if negCount >= 2 && posCount == 0 {
		return true
	}

	// Special case: "zip"/"postal" + only ambiguous keywords ("routing", "transit")
	// indicates postal/mail routing, not bank routing. Suppress this combination.
	if hasPostalNeg && posCount <= 1 && hasOnlyRoutingPos {
		return true
	}

	return false
}

// keywordNearMatch checks if a keyword appears within 30 chars of the match position.
func (v *Validator) keywordNearMatch(lowerLine string, matchStart int, keyword string) bool {
	start := matchStart - 30
	if start < 0 {
		start = 0
	}
	end := matchStart + 30
	if end > len(lowerLine) {
		end = len(lowerLine)
	}
	return strings.Contains(lowerLine[start:end], keyword)
}

// --- False positive suppression helpers ---

// rePhoneFormatted matches phone numbers with explicit separators/parens,
// distinguishing them from bare digit sequences.
var rePhoneFormatted = regexp.MustCompile(`\(\d{3}\)\s?\d{3}[-.]?\d{4}|\d{3}[-.\s]\d{3}[-.\s]\d{4}`)

// looksLikePhone checks if the digit sequence at the given position is part of a phone number.
// Only returns true if the match appears as a formatted phone (with separators/parens) or
// if phone-related keywords are present in the line. Bare 10-digit numbers in banking
// context are NOT suppressed as phones.
func (v *Validator) looksLikePhone(line string, start, end int, phoneKeyword bool) bool {
	matchLen := end - start
	// Phone numbers are exactly 10 digits. Longer sequences are not phones.
	if matchLen != 10 {
		return false
	}

	// Phone-context keywords on the line (precomputed once per line in
	// lineContext — see phoneKeyword). Scanning them per match was the O(n^2).
	if phoneKeyword {
		return true
	}

	// Check if the surrounding text has a formatted phone pattern (parens/dashes/dots)
	windowStart := start - 6
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 2
	if windowEnd > len(line) {
		windowEnd = len(line)
	}
	window := line[windowStart:windowEnd]
	return rePhoneFormatted.MatchString(window)
}

// looksLikeDate checks if the digit sequence is part of a date pattern.
func (v *Validator) looksLikeDate(line string, start, end int) bool {
	windowStart := start - 3
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 3
	if windowEnd > len(line) {
		windowEnd = len(line)
	}
	window := line[windowStart:windowEnd]
	return reDateLike.MatchString(window)
}

// looksLikeVersion checks if the digit sequence is preceded by a version indicator.
//
// The "version" word is matched on a WHOLE-WORD boundary (containsKeyword), not a
// raw substring: a bare strings.Contains matched "version" inside "conversion",
// "subversion" and "aversion", wrongly suppressing a real account number that
// happened to follow one of those words. The "v." prefix check is likewise
// anchored to a version token (reVersionPrefix: "v." or "v" immediately before a
// digit at a word boundary, e.g. "v.1"/"v2"), not any word merely ending in "v".
func (v *Validator) looksLikeVersion(line string, start int) bool {
	windowStart := start - 10
	if windowStart < 0 {
		windowStart = 0
	}
	window := line[windowStart:start]
	return reVersionLike.MatchString(window) ||
		containsKeyword(window, "version") ||
		reVersionPrefix.MatchString(window)
}

// cloudAccountIDLength is the digit count of an AWS account id (and of a typical
// Google Cloud project number). Only a run of exactly this length is capped by
// cloudAccountPhrases; every other length scores as before.
const cloudAccountIDLength = 12

// cloudAccountIDCeiling is the confidence a 12-digit run may not exceed on a line
// that names a cloud account: 55, the LOW ceiling used across the tree
// (contradictingHeaderCap in ssn, bareHandleCeiling in socialmedia), just under the
// MEDIUM bar of 60. Not zero, so the value is still reported and redacted.
const cloudAccountIDCeiling = 55.0

// confidenceCeilingKey is the Match.Metadata key the document bridge reads to keep a
// bound after it adds its own context adjustment (validators.ConfidenceCeilingKey).
// Duplicated rather than imported, as in the ssn, email and ipaddress validators:
// importing internal/validators would make this package depend on the bridge that
// consumes its findings. A test pins the two strings together.
const confidenceCeilingKey = "confidence_ceiling"

// cloudAccountPhrases name a cloud account, project or tenant identifier (#805). They
// are matched with containsKeyword, which requires a separator between words, like
// the negative list and unlike the positive one: they demote a finding, and a demoting
// list widened to "accountid" would reach JSON keys it was never meant for.
var cloudAccountPhrases = []string{
	"aws account", "aws accounts", "account id", "account ids", "payer",
	"management account", "org id", "organization id", "subscription id",
	"project number", "project id", "tenant",
}

// hasCloudAccountPhrase reports whether the line names a cloud account identifier.
func hasCloudAccountPhrase(line string) bool {
	for _, kw := range cloudAccountPhrases {
		if containsKeyword(line, kw) {
			return true
		}
	}
	return false
}

// --- Utility helpers ---

// looksLikeCreditCard checks if a digit string passes the Luhn algorithm,
// which is used for credit card number validation. Numbers of 13-19 digits
// that pass Luhn are almost certainly credit card numbers, not bank accounts.
func looksLikeCreditCard(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	// Luhn algorithm
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func clampConfidence(c float64) float64 {
	if c > 100 {
		return 100
	}
	if c < 0 {
		return 0
	}
	return c
}

// isTestPatternDigits reports whether a digit string is a value nobody was ever
// assigned: every digit the same, or a run of consecutive digits ascending or
// descending.
//
// Shape, never identity. The map this replaced listed two real routing numbers
// alongside twelve shapes, and a reviewer reading a list of nine-digit literals
// has no way to tell which is which — 021000021 and 111111111 look equally
// synthetic. A predicate cannot make that mistake: a real value has to look
// synthetic to be demoted.
func isTestPatternDigits(s string) bool {
	if len(s) < 4 {
		// Too short for either shape to mean anything: "111" is as likely a
		// legitimate three-digit field as a placeholder.
		return false
	}
	allSame, ascending, descending := true, true, true
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			allSame = false
		}
		if s[i] != s[i-1]+1 {
			ascending = false
		}
		if s[i] != s[i-1]-1 {
			descending = false
		}
	}
	return allSame || ascending || descending
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func isAllAlphaOrDigit(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func hasMinLetters(s string, n int) bool {
	count := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			count++
		}
	}
	return count >= n
}
