// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// SignalSynthesizer is the default Explainer: a deterministic, dependency-free
// synthesis of signals the detection engine already computed and stored on
// Match.Metadata. It performs no inference and makes no network calls.
//
// It is intentionally NOT "AI": it re-phrases existing data (validation checks,
// vendor, context impact, file location) so a reviewer sees the "why" at the
// point of decision (pre-commit, PR comment, suppression file) instead of only
// in verbose scan output.
type SignalSynthesizer struct{}

// NewSignalSynthesizer returns the default explainer.
func NewSignalSynthesizer() *SignalSynthesizer { return &SignalSynthesizer{} }

// confidence tier thresholds, kept consistent with the text formatter
// (internal/formatters/text/formatter.go getConfidenceLevel).
const (
	highConfidence   = 90.0
	mediumConfidence = 60.0
)

// Explain implements Explainer. It never mutates m.
func (s *SignalSynthesizer) Explain(m detector.Match) Explanation {
	checks := validationChecks(m)
	inTestFile := looksLikeTestPath(m.Filename)

	return Explanation{
		Rationale:           s.rationale(m, checks, inTestFile),
		Verdict:             s.verdict(m, checks, inTestFile),
		DraftSuppressReason: s.draftSuppressReason(m, checks, inTestFile),
	}
}

// rationale builds a plain-language "why this matched" sentence from the
// signals the validator already recorded.
func (s *SignalSynthesizer) rationale(m detector.Match, checks map[string]bool, inTestFile bool) string {
	var parts []string

	subject := describeType(m)
	parts = append(parts, fmt.Sprintf("Flagged as %s", subject))

	// Positive structural checks that passed (e.g. luhn, length, prefix).
	if passed := passedChecks(checks); len(passed) > 0 {
		parts = append(parts, fmt.Sprintf("it passed %s", joinHuman(passed)))
	}

	// Context contribution, if the engine scored one.
	if impact, ok := metaFloat(m, "context_impact"); ok && impact != 0 {
		if impact > 0 {
			parts = append(parts, fmt.Sprintf("nearby context raised confidence by %.0f%%", impact))
		} else {
			parts = append(parts, fmt.Sprintf("nearby context lowered confidence by %.0f%%", -impact))
		}
	}

	// Signals that point toward test / placeholder data.
	var weak []string
	if v, ok := checks["not_test"]; ok && !v {
		weak = append(weak, "it matches a known test/placeholder pattern")
	}
	if v, ok := checks["not_repeating"]; ok && !v {
		weak = append(weak, "it is a repeating/sequential value")
	}
	if inTestFile {
		weak = append(weak, fmt.Sprintf("it is in a test file (%s)", filepath.Base(m.Filename)))
	}
	if len(weak) > 0 {
		parts = append(parts, "but "+joinHuman(weak))
	}

	sentence := strings.Join(parts, "; ")
	if !strings.HasSuffix(sentence, ".") {
		sentence += "."
	}
	// Always anchor on the engine's confidence so the reader sees the basis.
	return fmt.Sprintf("%s (confidence %.0f%%, %s)", sentence, m.Confidence, tier(m.Confidence))
}

// verdict glosses the EXISTING confidence, nudged by explicit test signals.
// It is never an independent claim and never contradicts a HIGH finding.
func (s *SignalSynthesizer) verdict(m detector.Match, checks map[string]bool, inTestFile bool) Verdict {
	// A HIGH-confidence finding always surfaces as likely-real regardless of
	// weaker test hints — never talk a reviewer out of a real secret.
	if m.Confidence >= highConfidence {
		return VerdictLikelyReal
	}

	testSignal := inTestFile
	if v, ok := checks["not_test"]; ok && !v {
		testSignal = true
	}

	switch {
	case testSignal && m.Confidence < mediumConfidence:
		return VerdictLikelyTest
	case m.Confidence >= mediumConfidence:
		return VerdictLikelyReal
	default:
		return VerdictUncertain
	}
}

// draftSuppressReason produces a human-reviewable justification for a generated
// suppression rule. It is a suggestion, never an auto-suppression.
func (s *SignalSynthesizer) draftSuppressReason(m detector.Match, checks map[string]bool, inTestFile bool) string {
	loc := "this location"
	if m.Filename != "" {
		loc = filepath.Base(m.Filename)
	}
	switch s.verdict(m, checks, inTestFile) {
	case VerdictLikelyTest:
		switch {
		case inTestFile:
			return fmt.Sprintf("Test fixture: %s in test file %s; not a real %s.", strings.ToLower(describeType(m)), loc, m.Type)
		default:
			return fmt.Sprintf("Placeholder/example: %s matches a known test pattern; not a real %s.", strings.ToLower(describeType(m)), m.Type)
		}
	case VerdictLikelyReal:
		return fmt.Sprintf("REVIEW BEFORE SUPPRESSING: %s in %s looks like real %s (confidence %.0f%%).", strings.ToLower(describeType(m)), loc, m.Type, m.Confidence)
	default:
		return fmt.Sprintf("Confirm whether %s in %s is real before suppressing (confidence %.0f%%).", strings.ToLower(describeType(m)), loc, m.Confidence)
	}
}

// --- helpers over the verified Metadata contract ---

// validationChecks pulls the map[string]bool the validators store under
// "validation_checks" (e.g. creditcard: luhn, length, not_test, ...).
func validationChecks(m detector.Match) map[string]bool {
	if m.Metadata == nil {
		return nil
	}
	if c, ok := m.Metadata["validation_checks"].(map[string]bool); ok {
		return c
	}
	return nil
}

// passedChecks returns the human-formatted names of structural checks that
// passed, excluding the negative-signal keys handled separately.
func passedChecks(checks map[string]bool) []string {
	if checks == nil {
		return nil
	}
	skip := map[string]bool{"not_test": true, "not_repeating": true}
	var passed []string
	for name, ok := range checks {
		if ok && !skip[name] {
			passed = append(passed, humanizeCheck(name))
		}
	}
	sort.Strings(passed)
	return passed
}

// describeType renders a readable subject, preferring vendor when present
// (e.g. "a Visa card"). It avoids redundancy when the vendor and the finding
// type are the same word (e.g. type "VISA" + vendor "Visa" -> "a Visa card",
// not "a Visa visa").
func describeType(m detector.Match) string {
	t := friendlyType(m.Type)
	if vendor, ok := metaString(m, "vendor"); ok && vendor != "" {
		if strings.EqualFold(vendor, t) {
			// Vendor already names the type. Add a generic noun for readability
			// only for card-like findings (the credit-card validator is the
			// one that sets a vendor matching the type); otherwise the vendor
			// name alone reads fine.
			if _, ok := m.Metadata["card_type"]; ok {
				return "a " + vendor + " card"
			}
			return "a " + vendor
		}
		return fmt.Sprintf("a %s %s", vendor, t)
	}
	if startsWithVowel(t) {
		return "an " + t
	}
	return "a " + t
}

// friendlyType lowercases and de-snakes a finding type for prose.
func friendlyType(t string) string {
	return strings.ToLower(strings.ReplaceAll(t, "_", " "))
}

// humanizeCheck renders a validation_checks key for prose (mirrors the text
// formatter's formatCheckName, lowercased for mid-sentence use).
func humanizeCheck(check string) string {
	switch check {
	case "luhn":
		return "the Luhn checksum"
	case "length":
		return "the length check"
	case "entropy":
		return "the entropy check"
	case "vendor":
		return "vendor-prefix validation"
	case "prefix":
		return "the prefix check"
	}
	return "the " + strings.ReplaceAll(check, "_", " ") + " check"
}

func tier(confidence float64) string { return strings.ToLower(tierUpper(confidence)) }

func tierUpper(confidence float64) string {
	switch {
	case confidence >= highConfidence:
		return "HIGH"
	case confidence >= mediumConfidence:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// looksLikeTestPath reports whether a path is conventionally a test/fixture
// location. Conservative: only well-known markers.
func looksLikeTestPath(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(base, "_test.go") || strings.HasPrefix(base, "test_") {
		return true
	}
	for _, marker := range []string{"/testdata/", "/test/", "/tests/", "/fixtures/", "/__tests__/", "/examples/"} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func metaString(m detector.Match, key string) (string, bool) {
	if m.Metadata == nil {
		return "", false
	}
	v, ok := m.Metadata[key].(string)
	return v, ok
}

func metaFloat(m detector.Match, key string) (float64, bool) {
	if m.Metadata == nil {
		return 0, false
	}
	v, ok := m.Metadata[key].(float64)
	return v, ok
}

func startsWithVowel(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}

// joinHuman renders a slice as "a", "a and b", or "a, b, and c".
func joinHuman(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}
