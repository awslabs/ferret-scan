// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns for medical identifier detection.
var (
	// NPI: exactly 10 digits starting with 1 or 2
	reNPI = regexp.MustCompile(`\b[12]\d{9}\b`)

	// DEA: 2 chars (first = registration type, second = alpha) + 7 digits
	reDEA = regexp.MustCompile(`\b[ABCDFGMabcdfgm][A-Za-z]\d{7}\b`)

	// Medicare Beneficiary Identifier (MBI): 11 chars, specific positional format
	// Pos1=C(1-9), Pos2=A, Pos3=AN, Pos4=N, Pos5=A, Pos6=AN, Pos7=N, Pos8=A, Pos9=A, Pos10=N, Pos11=N
	// C = digit 1-9; A = alpha excluding S,L,O,I,B,Z; N = digit 0-9; AN = A or N
	reMBI = regexp.MustCompile(`\b[1-9][AC-HJ-KM-NP-RT-Y][0-9AC-HJ-KM-NP-RT-Y][0-9][AC-HJ-KM-NP-RT-Y][0-9AC-HJ-KM-NP-RT-Y][0-9][AC-HJ-KM-NP-RT-Y][AC-HJ-KM-NP-RT-Y][0-9][0-9]\b`)

	// Medicare cards print the MBI with dashes in a 4-3-4 grouping
	// (e.g. 1EG4-TE5-MK73). Same positional character rules as reMBI with
	// dashes at the card positions; the match is normalized (dashes stripped)
	// and re-validated against reMBI before being reported, and the reported
	// span is the original dashed text so redaction covers the whole token.
	reMBIDashed = regexp.MustCompile(`\b[1-9][AC-HJ-KM-NP-RT-Y][0-9AC-HJ-KM-NP-RT-Y][0-9]-[AC-HJ-KM-NP-RT-Y][0-9AC-HJ-KM-NP-RT-Y][0-9]-[AC-HJ-KM-NP-RT-Y][AC-HJ-KM-NP-RT-Y][0-9][0-9]\b`)

	// MRN: 6-10 digits (very generic, requires strong medical context)
	reMRN = regexp.MustCompile(`\b\d{6,10}\b`)

	// Insurance member ID: alphanumeric 8-20 chars (letters and digits mixed)
	reInsuranceID = regexp.MustCompile(`\b[A-Za-z0-9]{8,20}\b`)
)

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

// isWordByte reports whether b is a word character ([a-z0-9_]).
func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// Validator implements the detector.Validator interface for detecting
// medical identifiers (NPI, DEA, MRN, Insurance Member ID, Medicare MBI).
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new Validator instance.
func NewValidator() *Validator {
	return &Validator{
		positiveKeywords: []string{
			"medical record", "mrn", "patient id", "member id", "insurance",
			"npi", "provider", "medicare", "medicaid", "beneficiary",
			"subscriber", "policy number", "group number", "dea", "prescriber",
			"pharmacy", "hospital", "clinic", "health plan", "health insurance",
			"patient", "physician", "doctor", "medical", "healthcare",
			"health record", "enrollment", "covered", "copay", "deductible",
			"claims", "formulary", "prior authorization", "referral",
			// Legacy Medicare identifier + pharmacy-benefit card fields.
			"hicn", "rxbin", "rxpcn", "rxgrp",
		},
		negativeKeywords: []string{
			"phone", "ssn", "account", "order", "invoice", "tracking",
			"serial", "model", "version", "ip address", "zip",
			"test", "example", "sample", "placeholder", "fake", "mock", "demo",
			"lorem", "foo", "bar", "todo", "fixme",
		},
	}
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for medical identifiers.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx is the context-aware form of ValidateContent.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		lineMatches := v.scanLine(ctx, line, lineNum, originalPath)
		matches = append(matches, lineMatches...)
	}

	return matches, nil
}

// medicalLineContext holds the per-line-invariant context predicates and
// keyword sets, computed once per line in scanLine and passed to every
// evaluator. Every field is a pure function of the line, so computing them
// per match (as the evaluators used to) was the source of the O(n^2) blowup
// on a dense line.
type medicalLineContext struct {
	lineImpact float64
	posKW      []string
	negKW      []string
	phone      bool // hasPhoneContext
	provider   bool // hasProviderContext
	dea        bool // hasDEAContext
	medicare   bool // hasMedicareContext
	medical    bool // hasMedicalContext
	mrnKeyword bool // hasMRNKeyword
	insKeyword bool // hasInsuranceKeyword
	// MRN suppressor keywords, split into two tiers (see the eval in
	// evaluateMRN). nonMedHardKW marks a different NUMBER TYPE (phone/ssn/zip/
	// postal/fax/extension) that a bare 6-10 digit run is far likelier to be
	// than an MRN — always suppresses. nonMedSoftKW marks identifier LABELS
	// (account/order/invoice/tracking/serial) that legitimately sit beside a
	// real MRN in hospital records ("Patient account number: 1234567"); it
	// suppresses only when NO strong MRN keyword is present, so a labelled MRN
	// is not hard-dropped.
	nonMedHardKW bool
	nonMedSoftKW bool
	nonInsKW     bool // nonInsuranceKeywordPresent (insurance suppressor keywords)
}

// scanLine scans a single line for all medical ID types.
func (v *Validator) scanLine(ctx stdctx.Context, line string, lineNum int, originalPath string) []detector.Match {
	var matches []detector.Match

	lowerLine := strings.ToLower(line)

	// Per-line invariants, hoisted out of the per-match loop. analyzeContext and
	// the keyword-collection in buildContext scan only lowerLine (they ignore the
	// match string), so their results are identical for every match on this line.
	// Computing them ONCE per line instead of once per match is what keeps
	// scanning O(line length) rather than O(matches × line length) — the latter
	// is a single-long-line CPU-exhaustion DoS. See the timing regression test.
	lineImpact := v.analyzeContext("", lowerLine)
	linePositiveKeywords := v.keywordsPresent(lowerLine, v.positiveKeywords)
	lineNegativeKeywords := v.keywordsPresent(lowerLine, v.negativeKeywords)

	// Per-line context predicates, hoisted out of the per-match evaluators.
	// Each hasXContext scans the whole lowerLine and ignores the match, so its
	// result is identical for every match on the line. The evaluators
	// previously called them per match — with ~5000 matches on a dense
	// digit line (MRN \d{6,10} + NPI) that is O(matches × line length), the
	// medicalid O(n^2) the expanded complexity guard caught. Computed once
	// here and passed down via lc.
	lc := medicalLineContext{
		lineImpact:   lineImpact,
		posKW:        linePositiveKeywords,
		negKW:        lineNegativeKeywords,
		phone:        v.hasPhoneContext(lowerLine),
		provider:     v.hasProviderContext(lowerLine),
		dea:          v.hasDEAContext(lowerLine),
		medicare:     v.hasMedicareContext(lowerLine),
		medical:      v.hasMedicalContext(lowerLine),
		mrnKeyword:   v.hasMRNKeyword(lowerLine),
		insKeyword:   v.hasInsuranceKeyword(lowerLine),
		nonMedHardKW: v.nonMedicalHardKeywordPresent(lowerLine),
		nonMedSoftKW: v.nonMedicalSoftKeywordPresent(lowerLine),
		nonInsKW:     v.nonInsuranceKeywordPresent(lowerLine),
	}

	// scanMatches runs one regex over the line, polling ctx between matches so a
	// single pathological line stays interruptible, and hands each candidate to
	// the evaluator with the hoisted per-line context. The match byte offset from
	// FindAllStringIndex is passed through so buildContext never re-scans the
	// line with strings.Index.
	scanMatches := func(re *regexp.Regexp, eval func(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool)) bool {
		for i, loc := range re.FindAllStringIndex(line, -1) {
			if execguard.LineLoopCancelled(ctx, i) {
				return false
			}
			match := line[loc[0]:loc[1]]
			if m, ok := eval(match, line, lowerLine, lc, loc[0], lineNum, originalPath); ok {
				matches = append(matches, m)
			}
		}
		return true
	}

	// Check for NPI numbers
	if !scanMatches(reNPI, v.evaluateNPI) {
		return matches
	}

	// Check for DEA numbers
	if !scanMatches(reDEA, v.evaluateDEA) {
		return matches
	}

	// Check for Medicare MBI (contiguous and card-printed dashed forms)
	if !scanMatches(reMBI, v.evaluateMBI) {
		return matches
	}
	if !scanMatches(reMBIDashed, v.evaluateDashedMBI) {
		return matches
	}

	// Check for MRN (only if medical context is present on the line)
	if v.hasMedicalContext(lowerLine) {
		if !scanMatches(reMRN, v.evaluateMRN) {
			return matches
		}
	}

	// Check for Insurance Member IDs (only if insurance context is present)
	if v.hasInsuranceContext(lowerLine) {
		if !scanMatches(reInsuranceID, v.evaluateInsuranceID) {
			return matches
		}
	}

	return matches
}

// evaluateNPI checks an NPI candidate and returns a match if valid.
func (v *Validator) evaluateNPI(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool) {
	// NPI must pass the NPI-specific Luhn check (prefix 80840)
	if !npiLuhnValid(match) {
		return detector.Match{}, false
	}

	// If the line has phone/contact context, suppress NPI entirely.
	// A 10-digit number in a "contact", "call", "phone", or "fax" context
	// is overwhelmingly more likely to be a phone number than an NPI,
	// even if medical keywords are also present on the line.
	if lc.phone {
		return detector.Match{}, false
	}

	confidence := 80.0 // Valid Luhn checksum gives strong structural confidence

	// Context adjustments (per-line invariant, computed once in scanLine)
	contextImpact := lc.lineImpact
	confidence += contextImpact

	// Without any medical/provider context, suppress heavily
	if !lc.provider {
		confidence -= 40
	}

	confidence = clamp(confidence)
	if confidence <= 0 {
		return detector.Match{}, false
	}

	return detector.Match{
		Text:       match,
		LineNumber: lineNum + 1,
		Type:       "NPI",
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "medicalid",
		Context:    v.buildContext(match, line, matchStart, lc.posKW, lc.negKW),
		Metadata: map[string]any{
			"subtype":        "NPI",
			"luhn_valid":     true,
			"context_impact": contextImpact,
		},
	}, true
}

// evaluateDEA checks a DEA number candidate and returns a match if valid.
func (v *Validator) evaluateDEA(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool) {
	// Validate DEA checksum
	if !deaChecksumValid(match) {
		return detector.Match{}, false
	}

	confidence := 85.0 // DEA with valid checksum is strong evidence

	contextImpact := lc.lineImpact
	confidence += contextImpact

	// Without prescriber/pharmacy context, reduce confidence
	if !lc.dea {
		confidence -= 30
	}

	confidence = clamp(confidence)
	if confidence <= 0 {
		return detector.Match{}, false
	}

	return detector.Match{
		Text:       match,
		LineNumber: lineNum + 1,
		Type:       "DEA_NUMBER",
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "medicalid",
		Context:    v.buildContext(match, line, matchStart, lc.posKW, lc.negKW),
		Metadata: map[string]any{
			"subtype":           "DEA",
			"checksum_valid":    true,
			"context_impact":    contextImpact,
			"registrant_type":   string(match[0]),
			"last_name_initial": string(match[1]),
		},
	}, true
}

// evaluateMBI checks a Medicare MBI candidate and returns a match if valid.
func (v *Validator) evaluateMBI(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool) {
	confidence := 75.0 // MBI format is fairly specific

	contextImpact := lc.lineImpact
	confidence += contextImpact

	// Without medicare/beneficiary context, reduce
	if !lc.medicare {
		confidence -= 35
	}

	confidence = clamp(confidence)
	if confidence <= 0 {
		return detector.Match{}, false
	}

	return detector.Match{
		Text:       match,
		LineNumber: lineNum + 1,
		Type:       "MEDICARE_MBI",
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "medicalid",
		Context:    v.buildContext(match, line, matchStart, lc.posKW, lc.negKW),
		Metadata: map[string]any{
			"subtype":        "MBI",
			"context_impact": contextImpact,
		},
	}, true
}

// evaluateDashedMBI checks a card-printed dashed MBI candidate (1EG4-TE5-MK73).
// The dashes are stripped and the result re-validated against the contiguous
// MBI rules; scoring is identical to evaluateMBI. The reported Text keeps the
// original dashed form so redaction masks the token as printed.
func (v *Validator) evaluateDashedMBI(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool) {
	normalized := strings.ReplaceAll(match, "-", "")
	if !reMBI.MatchString(normalized) {
		return detector.Match{}, false
	}

	m, ok := v.evaluateMBI(normalized, line, lowerLine, lc, matchStart, lineNum, originalPath)
	if !ok {
		return detector.Match{}, false
	}

	// Report the original dashed span (position and text) for correct redaction.
	m.Text = match
	m.Context = v.buildContext(match, line, matchStart, lc.posKW, lc.negKW)
	m.Metadata["normalized"] = normalized
	return m, true
}

// evaluateMRN checks an MRN candidate and returns a match if valid.
func (v *Validator) evaluateMRN(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool) {
	// MRN is very generic (just digits), so only detect with strong medical context.
	// Skip if it looks like a phone, SSN component, zip code, year, etc.
	//
	// Hard suppressors (a different number TYPE) always veto. Soft suppressors
	// (account/order/invoice/tracking/serial labels) veto ONLY without a strong
	// MRN keyword: a hospital record line "Patient account number: 1234567"
	// carries both "patient account" (an MRN keyword) and "account" (a soft
	// suppressor), and the real MRN must not be hard-dropped by the label.
	if lc.nonMedHardKW || (lc.nonMedSoftKW && !lc.mrnKeyword) || v.looksLikeNonMedicalNumberShape(match) {
		return detector.Match{}, false
	}

	// If this 10-digit number already passes NPI Luhn validation, don't also
	// report it as MRN — the NPI evaluator handles it with higher specificity.
	if len(match) == 10 && (match[0] == '1' || match[0] == '2') && npiLuhnValid(match) {
		return detector.Match{}, false
	}

	confidence := 15.0 // Very low base — digits without keywords are ambiguous

	// Only boost if we have strong MRN-specific keywords
	if lc.mrnKeyword {
		confidence += 55 // Strong keyword match -> 70
	} else if lc.medical {
		confidence += 30 // Generic medical context -> 45
	}

	contextImpact := lc.lineImpact
	confidence += contextImpact

	confidence = clamp(confidence)
	if confidence <= 0 {
		return detector.Match{}, false
	}

	return detector.Match{
		Text:       match,
		LineNumber: lineNum + 1,
		Type:       "MRN",
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "medicalid",
		Context:    v.buildContext(match, line, matchStart, lc.posKW, lc.negKW),
		Metadata: map[string]any{
			"subtype":        "MRN",
			"context_impact": contextImpact,
		},
	}, true
}

// evaluateInsuranceID checks an insurance member ID candidate.
func (v *Validator) evaluateInsuranceID(match, line, lowerLine string, lc medicalLineContext, matchStart int, lineNum int, originalPath string) (detector.Match, bool) {
	// Insurance IDs must contain a mix of letters and digits
	if !hasLettersAndDigits(match) {
		return detector.Match{}, false
	}

	// Skip if it looks like a common non-insurance pattern
	if lc.nonInsKW || v.looksLikeNonInsuranceIDShape(match, lc.insKeyword) {
		return detector.Match{}, false
	}

	confidence := 50.0 // Moderate base — alphanumeric with insurance context

	// Boost if strong insurance keywords present
	if lc.insKeyword {
		confidence += 20 // -> 70
	}

	contextImpact := lc.lineImpact
	confidence += contextImpact

	confidence = clamp(confidence)
	if confidence <= 0 {
		return detector.Match{}, false
	}

	return detector.Match{
		Text:       match,
		LineNumber: lineNum + 1,
		Type:       "INSURANCE_MEMBER_ID",
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "medicalid",
		Context:    v.buildContext(match, line, matchStart, lc.posKW, lc.negKW),
		Metadata: map[string]any{
			"subtype":        "INSURANCE_MEMBER_ID",
			"context_impact": contextImpact,
		},
	}, true
}

// CalculateConfidence calculates the confidence score for a potential medical ID.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":       true,
		"not_test":     true,
		"has_checksum": false,
	}

	// Try to determine what type this match is
	if reNPI.MatchString(match) && npiLuhnValid(match) {
		checks["has_checksum"] = true
		return 80.0, checks
	}
	if reDEA.MatchString(match) && deaChecksumValid(match) {
		checks["has_checksum"] = true
		return 85.0, checks
	}
	if reMBI.MatchString(match) {
		return 75.0, checks
	}

	// Generic (MRN / Insurance ID)
	return 50.0, checks
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	lowerLine := strings.ToLower(context.FullLine)
	return v.analyzeContext(match, lowerLine)
}

// strongNegativeKeywords are test/placeholder indicators that should suppress
// findings heavily regardless of positive context.
var strongNegativeKeywords = []string{
	"test", "example", "sample", "placeholder", "fake", "mock", "demo",
}

// analyzeContext performs keyword-based context scoring.
func (v *Validator) analyzeContext(match, lowerLine string) float64 {
	var impact float64

	// Check for strong negative keywords first (test/example/etc.)
	// These suppress hard, overriding positive keywords.
	strongNegCount := 0
	for _, kw := range strongNegativeKeywords {
		if containsKeyword(lowerLine, kw) {
			strongNegCount++
			impact -= 25
		}
	}

	for _, kw := range v.positiveKeywords {
		if containsKeyword(lowerLine, kw) {
			impact += 10
		}
	}

	for _, kw := range v.negativeKeywords {
		// Skip strong negatives already counted above
		isStrong := false
		for _, s := range strongNegativeKeywords {
			if kw == s {
				isStrong = true
				break
			}
		}
		if isStrong {
			continue
		}
		if containsKeyword(lowerLine, kw) {
			impact -= 15
		}
	}

	// Cap impact
	if impact > 40 {
		impact = 40
	} else if impact < -60 {
		impact = -60
	}

	// When ANY strong negative keyword is present (test/example/mock/etc.),
	// the net impact must stay negative. Test/placeholder data is NEVER a
	// real finding regardless of how many positive keywords surround it.
	if strongNegCount > 0 && impact > -25 {
		impact = -25
	}

	return impact
}

// buildContext builds a ContextInfo from the line surrounding the match.
// keywordsPresent returns the subset of keywords that appear in lowerLine.
// Hoisted per line (not per match) so buildContext does no per-match keyword
// scanning — see scanLine's O(n^2) note.
func (v *Validator) keywordsPresent(lowerLine string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsKeyword(lowerLine, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// buildContext builds the ContextInfo for a match. matchStart is the match's
// byte offset within line (from FindAllStringIndex) so we never re-scan the
// line with strings.Index, and posKW/negKW are the per-line keyword sets
// computed once in scanLine. Both changes keep this O(1) per match instead of
// O(line length + keywords), which is what removes the single-long-line DoS.
func (v *Validator) buildContext(match, line string, matchStart int, posKW, negKW []string) detector.ContextInfo {
	ci := detector.ContextInfo{
		FullLine:         line,
		PositiveKeywords: posKW,
		NegativeKeywords: negKW,
	}

	if matchStart >= 0 {
		start := matchStart - 50
		if start < 0 {
			start = 0
		}
		end := matchStart + len(match) + 50
		if end > len(line) {
			end = len(line)
		}
		ci.BeforeText = line[start:matchStart]
		ci.AfterText = line[matchStart+len(match) : end]
	}

	return ci
}

// --- Context helper functions ---

func (v *Validator) hasMedicalContext(lowerLine string) bool {
	medicalKW := []string{
		"medical record", "mrn", "patient", "hospital", "clinic",
		"physician", "doctor", "healthcare", "health record", "medical",
		"admission", "discharge", "diagnosis", "treatment",
	}
	for _, kw := range medicalKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasProviderContext(lowerLine string) bool {
	providerKW := []string{
		"npi", "provider", "physician", "doctor", "nurse", "practitioner",
		"clinician", "medical", "healthcare", "hospital", "clinic",
		"practice", "health plan", "registry",
	}
	for _, kw := range providerKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasPhoneContext(lowerLine string) bool {
	phoneKW := []string{
		"phone", "call", "fax", "contact", "dial", "reach",
		"tel", "telephone", "mobile", "cell",
	}
	for _, kw := range phoneKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasDEAContext(lowerLine string) bool {
	deaKW := []string{
		"dea", "prescriber", "pharmacy", "controlled substance",
		"narcotic", "schedule", "dispensing", "prescription",
		"drug enforcement", "registrant",
	}
	for _, kw := range deaKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasMedicareContext(lowerLine string) bool {
	medicareKW := []string{
		"medicare", "mbi", "beneficiary", "cms", "medicaid",
		"enrollment", "coverage", "part a", "part b", "part d",
		// HICN is the legacy Medicare Health Insurance Claim Number (the
		// SSN-based identifier the MBI replaced); it is still a Medicare
		// identifier label and appears on older records/exports.
		"hicn", "health insurance claim",
	}
	for _, kw := range medicareKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasMRNKeyword(lowerLine string) bool {
	mrnKW := []string{
		"mrn", "medical record", "patient id", "patient number",
		"record number", "chart number", "admission number",
		// "patient account (number)" is the standard hospital-billing label for
		// the MRN/account identifier; without it, the "account" soft suppressor
		// would hard-drop the real MRN on this line.
		"patient account",
	}
	for _, kw := range mrnKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasInsuranceContext(lowerLine string) bool {
	insKW := []string{
		"insurance", "member id", "member number", "subscriber",
		"policy number", "group number", "health plan", "enrollee",
		"covered", "copay", "deductible", "claims",
		// Pharmacy-benefit card fields printed alongside the member ID on
		// insurance cards (RxBIN / RxPCN / RxGRP).
		"rxbin", "rxpcn", "rxgrp", "rx bin", "rx group",
	}
	for _, kw := range insKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

func (v *Validator) hasInsuranceKeyword(lowerLine string) bool {
	strongKW := []string{
		"member id", "member number", "subscriber id", "policy number",
		"insurance id", "group number", "enrollee id",
	}
	for _, kw := range strongKW {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

// looksLikeNonMedicalNumber checks if a digit sequence is likely not an MRN.
// nonMedicalHardKeywordPresent reports whether the line names a different NUMBER
// TYPE (phone/SSN/zip/postal/fax/extension) — a bare 6-10 digit run beside these
// is overwhelmingly that, not an MRN, so it suppresses unconditionally.
// Line-global — hoisted into medicalLineContext (was scanned per match).
func (v *Validator) nonMedicalHardKeywordPresent(lowerLine string) bool {
	for _, kw := range []string{
		"phone", "ssn", "zip", "postal", "fax", "extension",
	} {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

// nonMedicalSoftKeywordPresent reports whether the line carries an identifier
// LABEL (account/order/invoice/tracking/serial) that commonly sits beside a real
// MRN in hospital records. It suppresses only when no strong MRN keyword is
// present (see evaluateMRN), so "Patient account number: 1234567" is not dropped.
// Line-global — hoisted into medicalLineContext (was scanned per match).
func (v *Validator) nonMedicalSoftKeywordPresent(lowerLine string) bool {
	for _, kw := range []string{
		"account", "order", "invoice", "tracking", "serial",
	} {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

// looksLikeNonMedicalNumberShape is the match-only (no line scan) half of the
// old looksLikeNonMedicalNumber: length-based SSN/phone/year heuristics.
func (v *Validator) looksLikeNonMedicalNumberShape(match string) bool {
	// Skip 4-digit years embedded in longer text
	if len(match) == 4 {
		// Bare 4-digit matches shouldn't reach here (regex requires 6+)
		return true
	}
	// Skip if the match is exactly 9 digits (likely SSN) or 10 digits starting
	// with 1 (likely phone number)
	if len(match) == 9 {
		return true // Likely an SSN
	}
	if len(match) == 10 && match[0] == '1' {
		return true // Likely a phone number with leading 1
	}
	return false
}

// looksLikeNonInsuranceID checks if an alphanumeric string is likely not an insurance ID.
// nonInsuranceKeywordPresent reports whether the line carries a keyword that
// makes an alphanumeric token more likely a non-insurance identifier.
// Line-global — hoisted into medicalLineContext (was scanned per match).
func (v *Validator) nonInsuranceKeywordPresent(lowerLine string) bool {
	for _, kw := range []string{
		"phone", "ssn", "account", "order", "invoice", "tracking",
		"serial", "model", "version", "ip address",
	} {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

// looksLikeNonInsuranceIDShape is the match-only (no line scan) half of the
// old looksLikeNonInsuranceID: hex/UUID/tech-code shape heuristics. insKeyword
// is the hoisted lc.insKeyword (the one line-dependent input this half needs).
func (v *Validator) looksLikeNonInsuranceIDShape(match string, insKeyword bool) bool {
	lower := strings.ToLower(match)

	// Skip if it looks like a hex string (all hex chars)
	if isHexString(lower) {
		return true
	}
	// Skip if it has a "0x" hex prefix
	if strings.HasPrefix(lower, "0x") && isHexString(lower[2:]) {
		return true
	}
	// Skip if it looks like a UUID component
	if len(match) == 8 || len(match) == 12 || len(match) == 16 {
		if isHexString(lower) {
			return true
		}
	}
	// Skip common tech identifiers (all uppercase + digits) unless a strong
	// insurance keyword is present on the line.
	if isAllUpperOrDigit(match) && !insKeyword {
		return true
	}
	return false
}

// --- Checksum functions ---

// npiLuhnValid validates an NPI number using the Luhn algorithm with the
// "80840" prefix as specified by CMS (the NPI check digit is computed over
// the 10-digit NPI prefixed with "80840" to form a 15-digit number).
func npiLuhnValid(npi string) bool {
	if len(npi) != 10 {
		return false
	}
	// Prefix "80840" + NPI gives a 15-digit number that must pass standard Luhn
	full := "80840" + npi
	return luhnValid(full)
}

// luhnValid validates a numeric string using the standard Luhn algorithm.
func luhnValid(s string) bool {
	if len(s) == 0 {
		return false
	}
	var sum int
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// deaChecksumValid validates a DEA number checksum.
// DEA format: 2 letters + 7 digits
// Checksum: (d1+d3+d5) + 2*(d2+d4+d6) -> last digit of sum = d7
func deaChecksumValid(dea string) bool {
	if len(dea) != 9 {
		return false
	}
	// First char must be registration type
	first := dea[0]
	if first != 'A' && first != 'B' && first != 'C' && first != 'D' &&
		first != 'F' && first != 'G' && first != 'M' &&
		first != 'a' && first != 'b' && first != 'c' && first != 'd' &&
		first != 'f' && first != 'g' && first != 'm' {
		return false
	}
	// Second char must be alpha
	second := dea[1]
	if !((second >= 'A' && second <= 'Z') || (second >= 'a' && second <= 'z')) {
		return false
	}
	// Remaining 7 must be digits
	digits := make([]int, 7)
	for i := 0; i < 7; i++ {
		c := dea[i+2]
		if c < '0' || c > '9' {
			return false
		}
		digits[i] = int(c - '0')
	}

	sum := (digits[0] + digits[2] + digits[4]) + 2*(digits[1]+digits[3]+digits[5])
	return sum%10 == digits[6]
}

// --- Utility functions ---

func hasLettersAndDigits(s string) bool {
	hasLetter := false
	hasDigit := false
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			hasLetter = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if hasLetter && hasDigit {
			return true
		}
	}
	return false
}

func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isAllUpperOrDigit(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func clamp(confidence float64) float64 {
	if confidence > 100 {
		return 100
	}
	if confidence < 0 {
		return 0
	}
	return confidence
}
