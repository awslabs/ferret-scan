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
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// intrinsicValueFloor is the confidence a checksum-valid identifier keeps even
// when the line's keywords score it to zero. It applies to NPI and DEA only —
// the two subtypes here with a value-intrinsic check (CMS NPI-Luhn, DEA
// checksum). MRN and insurance member IDs have no such check, so context is the
// only evidence they have and suppressing them to nothing stays correct; that
// residual is documented in THREAT_MODEL.md §4.7.
const intrinsicValueFloor = 15.0

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
	reMBIDashed = regexp.MustCompile(`\b[1-9][AC-HJ-KM-NP-RT-Y][0-9AC-HJ-KM-NP-RT-Y][0-9][ -][AC-HJ-KM-NP-RT-Y][0-9AC-HJ-KM-NP-RT-Y][0-9][ -][AC-HJ-KM-NP-RT-Y][AC-HJ-KM-NP-RT-Y][0-9][0-9]\b`)

	// MRN: 6-10 digits (very generic, requires strong medical context)
	reMRN = regexp.MustCompile(`\b\d{6,10}\b`)

	// Insurance member ID: alphanumeric 8-20 chars (letters and digits mixed)
	reInsuranceID = regexp.MustCompile(`\b[A-Za-z0-9]{8,20}\b`)
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
	nonInsKW     bool // nonInsuranceKeywordPresent (different NUMBER TYPE; always suppresses)
	nonInsSoftKW bool // nonInsuranceSoftKeywordPresent (identifier LABELS; suppress only without an insurance keyword)
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
		nonInsSoftKW: v.nonInsuranceSoftKeywordPresent(lowerLine),
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

	// Phone/contact context suppresses NPI entirely. A 10-digit number near
	// "contact"/"call"/"phone"/"fax" is overwhelmingly more likely to be a phone
	// number, and roughly 1 in 10 phone-shaped 10-digit numbers starting 1 or 2
	// pass the NPI-Luhn check, so this carries real false-positive weight — see
	// TestAdversarial_NPI_PhoneNumbers and TestAdversarial_PhoneLike_InMedicalContext,
	// which pin phone-shaped NPI-Luhn-valid values like 1212555126.
	//
	// KNOWN RESIDUAL, deliberately not fixed here. This drop is a
	// cross-validator arbitration (NPI vs PHONE over the same bytes) implemented
	// as a keyword veto inside one validator, and it has two costs:
	//
	//   1. Recall: "Provider NPI 1234567893, phone 555-0100" reports no NPI,
	//      because one "phone" anywhere on the line vetoes a checksum-valid,
	//      explicitly labelled NPI that is not the phone number.
	//   2. TM-11: the veto is attacker-controlled document content, so appending
	//      the single word "phone" erases the NPI, which then passes through
	//      --enable-redaction in cleartext.
	//
	// Gating on provider context was tried and rejected: "physician"/"hospital"
	// is provider context, so it readmitted exactly the phone-number FPs the
	// adversarial tests exist to prevent. A correct fix needs same-span
	// arbitration between the medicalid and phone validators (which number does
	// the phone keyword actually bind to), not a better keyword rule here. Today
	// nothing arbitrates: internal/parallel/validator_runner.go concatenates each
	// validator's matches, so "NPI 1234567893" already emits both NPI 90 and
	// PHONE 10 for the same bytes. Tracked separately; the floor below covers the
	// scoring half of TM-11, which is what this change is scoped to.
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

	// Value-intrinsic floor (TM-11). An NPI that passes the CMS NPI-Luhn check
	// above is validated by the value itself; the keywords that pushed the score
	// to zero are document content, so without this floor anyone who could add
	// words to the line could erase the finding entirely — and because redaction
	// only rewrites what was emitted, the NPI then passed through
	// --enable-redaction in cleartext. Measured: "NPI 1234567893" scores 90, and
	// the same line padded with test/example/fake/... produced no finding at all.
	// Context may demote to the bottom of LOW; it may not erase. The `lc.phone`
	// return above is deliberately left as a hard drop: that is a *structural*
	// disambiguation (a 10-digit number in phone context is a phone number), not
	// an attacker's claim about sensitivity.
	confidence = clamp(confidence)
	if confidence <= 0 {
		confidence = intrinsicValueFloor
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

	// Value-intrinsic floor (TM-11) — see evaluateNPI. The DEA checksum is
	// verified above, so context may demote but not erase.
	confidence = clamp(confidence)
	if confidence <= 0 {
		confidence = intrinsicValueFloor
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
	normalized := strings.NewReplacer("-", "", " ", "").Replace(match)
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
	// Two tiers, mirroring evaluateMRN: a different number type always
	// suppresses; an identifier LABEL suppresses only when no insurance keyword
	// is present, so a labelled member ID beside "patient account 88213" survives.
	if lc.nonInsKW || (lc.nonInsSoftKW && !lc.insKeyword) ||
		v.looksLikeNonInsuranceIDShape(match, lc.insKeyword) {
		return detector.Match{}, false
	}

	// A value that already passes a checksum belonging to a MORE SPECIFIC
	// subtype is reported by that subtype's evaluator, not here. evaluateMRN
	// has carried the NPI half of this rule for a while; DEA needed the same
	// veto once the hex gate above became keyword-deferred, because a valid DEA
	// number is 2 letters + 7 digits and "AB1234563" is entirely hex digits —
	// the unconditional gate had been suppressing the duplicate by accident.
	// Relying on that was fragile: the same accident dropped real member IDs
	// (the bug this change fixes), and it only ever covered DEAs whose letters
	// happen to fall in A-F.
	if reDEA.MatchString(match) && deaChecksumValid(match) {
		return detector.Match{}, false
	}
	if reNPI.MatchString(match) && npiLuhnValid(match) {
		return detector.Match{}, false
	}
	if reMBI.MatchString(match) {
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
		// "Member Identification Number" is the label printed on the physical
		// Medicare card next to the MBI. Keywords match on whole tokens, so
		// "member id" does not cover it — "identification" is not the token
		// "id" — and without an entry here the card's own wording scored the
		// MBI at LOW instead of HIGH.
		"member identification",
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
		// Long form of "patient id" — not reachable from the abbreviation,
		// since keywords match whole tokens.
		"patient identification",
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
		// Long-form spellings of the same card/EDI field labels. Keywords match
		// whole tokens, so the abbreviated entries above do not cover them.
		// Deliberately excludes "certificate number" and "policy
		// identification": both are common in crypto (X.509) and IAM/Terraform
		// contexts, where they produced false positives on build IDs and key
		// material.
		"member identification", "subscriber identification", "policyholder",
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
		// Long forms of the same labels. This list also gates the
		// all-uppercase-ID shape check in looksLikeNonInsuranceIDShape, so a
		// card-style ID ("W1234567801") beside a long-form label was dropped
		// outright rather than merely scored low. Kept narrow on purpose:
		// "certificate number" and a bare "policy identification" also name
		// X.509 and IAM objects, so they are not included.
		"member identification", "subscriber identification",
		"enrollee identification", "policyholder id",
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
// nonInsuranceKeywordPresent reports whether the line names a different NUMBER
// TYPE, which a member-ID-shaped value is far likelier to be. These always
// suppress, the same tier as nonMedicalHardKeywordPresent for MRN.
func (v *Validator) nonInsuranceKeywordPresent(lowerLine string) bool {
	for _, kw := range []string{
		"phone", "ssn", "serial", "model", "version", "ip address",
	} {
		if containsKeyword(lowerLine, kw) {
			return true
		}
	}
	return false
}

// nonInsuranceSoftKeywordPresent reports whether the line carries an identifier
// LABEL that commonly sits BESIDE a real member ID rather than describing it.
//
// These four were previously in the hard list above, which made them delete a
// member ID even when the line also carried an explicit insurance label. That is
// wrong on the same grounds evaluateMRN already documents for its own soft tier:
// "account", "order", "invoice" and "tracking" are the definitional content of a
// claim form, an EOB and a remittance advice, so they co-occur with a real member
// ID constantly. "Subscriber member id W1234567801; patient account 88213 has a
// zero balance" reported nothing, while the same line without the word "account"
// reported a finding.
//
// A dropped finding is never handed to the redactor, and a file that yields no
// findings has no redacted output written at all, so the member ID stayed in
// cleartext.
//
// Split rather than deleted: with NO insurance keyword on the line these words
// are still the best available signal that a mixed alphanumeric token is an order
// number rather than a member ID, so they keep suppressing in that case. This
// mirrors the hard/soft split evaluateMRN has carried for a while; the insurance
// path simply never adopted it.
func (v *Validator) nonInsuranceSoftKeywordPresent(lowerLine string) bool {
	for _, kw := range []string{
		"account", "order", "invoice", "tracking",
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

	// Skip if it looks like a hex string (all hex chars) — hashes, commit SHAs
	// and hex blobs in source and logs. This used to fire unconditionally, which
	// dropped a whole shape of real member ID silently: IDs are commonly a
	// letter prefix plus digits, and for a single leading letter 6 of 26 fall in
	// A-F, so "member id: E1122334455" produced no finding at all and therefore
	// also passed --enable-redaction in cleartext with exit code 0.
	//
	// The keyword alone is NOT enough to lift it, because a hash genuinely does
	// appear beside a member-id label ("Member id verification: <md5>" —
	// TestAdversarial_InsuranceID_HexHash). Casing is what separates the two:
	// hex digests are conventionally printed all-lowercase (git SHAs, sha256sum,
	// HTTP etags), while an ID printed on an insurance card is not. So an
	// all-lowercase hex run stays suppressed no matter what the line says, and
	// only a hex run carrying an uppercase letter defers to the keyword.
	//
	// KNOWN RESIDUAL, accepted: an UPPERCASE 8-20 char hex blob on a line with a
	// strong insurance label now matches ("member id: 0A1B2C3D4E5F6789"). That is
	// the intended direction of the trade — uppercase beside "member id:" reads
	// as a card ID far more than as a digest — and it is bounded, because the
	// same blob without an insurance label is still dropped. Measured against 300
	// real commit SHAs and 60 label-prefixed full SHAs: zero new false positives,
	// since git prints lowercase and a 40-char SHA is outside reInsuranceID's
	// 8-20 range anyway.
	if isHexString(lower) && (!insKeyword || !hasUpper(match)) {
		return true
	}
	// Skip if it has a "0x" hex prefix. Unconditional on purpose: "0x..." is
	// not a plausible member ID, so no keyword should rescue it.
	if strings.HasPrefix(lower, "0x") && isHexString(lower[2:]) {
		return true
	}
	// NOTE: a UUID-component check for len 8/12/16 used to sit here. Its only
	// condition beyond the length was isHexString(lower), which the gate above
	// had already tested unconditionally, so it could never fire — and once
	// that gate became keyword-deferred it would have come alive and re-dropped
	// exactly the 8/12/16-character labeled hex IDs this fix recovers (measured:
	// "ABCDEF123456" beside "member id:"). Removed rather than given the same
	// !insKeyword guard, which would only restore it to being unreachable.
	//
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

// hasUpper reports whether s contains at least one A-Z. It distinguishes a
// card-printed identifier from a hex digest, which is conventionally lowercase.
func hasUpper(s string) bool {
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
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
