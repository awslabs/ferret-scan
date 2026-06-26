// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/config"
	"github.com/awslabs/ferret-scan/internal/detector"
)

// helper to create a validator with specific disabled types
func newValidatorWithDisabledTypes(types []string) *Validator {
	v := NewValidator()
	if len(types) == 0 {
		return v
	}
	cfg := &config.Config{
		Validators: map[string]map[string]interface{}{
			"intellectual_property": {
				"disabled_types": toAnySlice(types),
			},
		},
	}
	v.Configure(cfg)
	return v
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// matchesContainIPType checks if any match has the given ip_type metadata
func matchesContainIPType(matches []detector.Match, ipType string) bool {
	for _, m := range matches {
		if mt, ok := m.Metadata["ip_type"]; ok && mt == ipType {
			return true
		}
	}
	return false
}

// countMatchesByIPType counts matches with a specific ip_type
func countMatchesByIPType(matches []detector.Match, ipType string) int {
	count := 0
	for _, m := range matches {
		if mt, ok := m.Metadata["ip_type"]; ok && mt == ipType {
			count++
		}
	}
	return count
}

// --- Test content samples ---

const (
	copyrightLine   = "Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved."
	patentLine      = "This technology is covered by US9123456 patent."
	trademarkLine   = "ProductName Trademark is registered."
	tradeSecretLine = "This document is Classified and restricted."
	internalURLLine = "See https://wiki.internal.example.com/docs for details."
	cleanLine       = "This is a normal line of code with no sensitive data."
)

// combinedContent has one of each IP type
var combinedContent = copyrightLine + "\n" +
	patentLine + "\n" +
	trademarkLine + "\n" +
	tradeSecretLine + "\n" +
	cleanLine + "\n"

// --- Baseline: no types disabled ---

func TestNoDisabledTypes_DetectsAll(t *testing.T) {
	v := NewValidator()
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !matchesContainIPType(matches, "copyright") {
		t.Error("expected copyright match, got none")
	}
	if !matchesContainIPType(matches, "patent") {
		t.Error("expected patent match, got none")
	}
	if !matchesContainIPType(matches, "trademark") {
		t.Error("expected trademark match, got none")
	}
	// trade_secret may appear from "Confidential" and "Proprietary"
	if !matchesContainIPType(matches, "trade_secret") {
		t.Error("expected trade_secret match, got none")
	}
}

// --- Disable copyright ---

func TestDisableCopyright(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"copyright"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "copyright") {
		t.Error("copyright should be disabled but was detected")
	}
	// Other types should still work
	if !matchesContainIPType(matches, "patent") {
		t.Error("patent should still be detected when copyright is disabled")
	}
	if !matchesContainIPType(matches, "trademark") {
		t.Error("trademark should still be detected when copyright is disabled")
	}
	if !matchesContainIPType(matches, "trade_secret") {
		t.Error("trade_secret should still be detected when copyright is disabled")
	}
}

// --- Disable patent ---

func TestDisablePatent(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"patent"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "patent") {
		t.Error("patent should be disabled but was detected")
	}
	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should still be detected when patent is disabled")
	}
	if !matchesContainIPType(matches, "trademark") {
		t.Error("trademark should still be detected when patent is disabled")
	}
	if !matchesContainIPType(matches, "trade_secret") {
		t.Error("trade_secret should still be detected when patent is disabled")
	}
}

// --- Disable trademark ---

func TestDisableTrademark(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"trademark"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "trademark") {
		t.Error("trademark should be disabled but was detected")
	}
	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should still be detected when trademark is disabled")
	}
	if !matchesContainIPType(matches, "patent") {
		t.Error("patent should still be detected when trademark is disabled")
	}
	if !matchesContainIPType(matches, "trade_secret") {
		t.Error("trade_secret should still be detected when trademark is disabled")
	}
}

// --- Disable trade_secret ---

func TestDisableTradeSecret(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"trade_secret"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "trade_secret") {
		t.Error("trade_secret should be disabled but was detected")
	}
	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should still be detected when trade_secret is disabled")
	}
	if !matchesContainIPType(matches, "patent") {
		t.Error("patent should still be detected when trade_secret is disabled")
	}
	if !matchesContainIPType(matches, "trademark") {
		t.Error("trademark should still be detected when trade_secret is disabled")
	}
}

// --- Disable internal_url ---

func TestDisableInternalURL(t *testing.T) {
	v := NewValidator()
	// Configure with an internal URL pattern, then disable it
	cfg := &config.Config{
		Validators: map[string]map[string]interface{}{
			"intellectual_property": {
				"internal_urls": []any{
					"http[s]?:\\/\\/wiki\\.internal\\.example\\.com",
				},
				"disabled_types": []any{"internal_url"},
			},
		},
	}
	v.Configure(cfg)

	content := internalURLLine + "\n" + copyrightLine + "\n"
	matches, err := v.ValidateContent(content, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "internal_url") {
		t.Error("internal_url should be disabled but was detected")
	}
	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should still be detected when internal_url is disabled")
	}
}

// --- Internal URL enabled (control test) ---

func TestInternalURLEnabled(t *testing.T) {
	v := NewValidator()
	cfg := &config.Config{
		Validators: map[string]map[string]interface{}{
			"intellectual_property": {
				"internal_urls": []any{
					"wiki\\.internal\\.example\\.com",
				},
			},
		},
	}
	v.Configure(cfg)

	matches, err := v.ValidateContent(internalURLLine+"\n", "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !matchesContainIPType(matches, "internal_url") {
		t.Error("internal_url should be detected when enabled and configured")
	}
}

// --- Disable multiple types at once ---

func TestDisableMultipleTypes(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"copyright", "trade_secret"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "copyright") {
		t.Error("copyright should be disabled")
	}
	if matchesContainIPType(matches, "trade_secret") {
		t.Error("trade_secret should be disabled")
	}
	if !matchesContainIPType(matches, "patent") {
		t.Error("patent should still be detected")
	}
	if !matchesContainIPType(matches, "trademark") {
		t.Error("trademark should still be detected")
	}
}

// --- Disable all types ---

func TestDisableAllTypes(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"copyright", "patent", "trademark", "trade_secret"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches when all types disabled, got %d", len(matches))
		for _, m := range matches {
			t.Logf("  unexpected match: ip_type=%v text=%q", m.Metadata["ip_type"], m.Text)
		}
	}
}

// --- Case insensitivity of disabled_types ---

func TestDisabledTypesCaseInsensitive(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{"Copyright", "PATENT", "Trade_Secret"})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matchesContainIPType(matches, "copyright") {
		t.Error("copyright should be disabled (case-insensitive)")
	}
	if matchesContainIPType(matches, "patent") {
		t.Error("patent should be disabled (case-insensitive)")
	}
	if matchesContainIPType(matches, "trade_secret") {
		t.Error("trade_secret should be disabled (case-insensitive)")
	}
	if !matchesContainIPType(matches, "trademark") {
		t.Error("trademark should still be detected")
	}
}

// --- Empty disabled_types has no effect ---

func TestEmptyDisabledTypes(t *testing.T) {
	v := newValidatorWithDisabledTypes([]string{})
	matches, err := v.ValidateContent(combinedContent, "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should be detected with empty disabled_types")
	}
	if !matchesContainIPType(matches, "patent") {
		t.Error("patent should be detected with empty disabled_types")
	}
}

// --- Real-world scenario: ProServe copyright headers ---

func TestProServeScenario_CopyrightOnEveryFile(t *testing.T) {
	// Simulate a codebase where every file has a copyright header
	content := `// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
`
	// Without disabling copyright — should find matches
	vEnabled := NewValidator()
	matchesEnabled, _ := vEnabled.ValidateContent(content, "main.go")
	copyrightCountEnabled := countMatchesByIPType(matchesEnabled, "copyright")
	if copyrightCountEnabled == 0 {
		t.Error("expected copyright findings in ProServe code without disabled_types")
	}

	// With copyright disabled — should find zero copyright matches
	vDisabled := newValidatorWithDisabledTypes([]string{"copyright"})
	matchesDisabled, _ := vDisabled.ValidateContent(content, "main.go")
	copyrightCountDisabled := countMatchesByIPType(matchesDisabled, "copyright")
	if copyrightCountDisabled != 0 {
		t.Errorf("expected 0 copyright findings with disabled_types=[copyright], got %d", copyrightCountDisabled)
	}
}

// --- Table-driven test for each type individually ---

func TestDisableEachTypeIndividually(t *testing.T) {
	tests := []struct {
		name        string
		disableType string
		content     string
		shouldFind  bool // false = should NOT find this type
		ipType      string
	}{
		{
			name:        "copyright disabled, copyright content",
			disableType: "copyright",
			content:     "Copyright 2024 Amazon.com, Inc.",
			shouldFind:  false,
			ipType:      "copyright",
		},
		{
			name:        "copyright enabled, copyright content",
			disableType: "",
			content:     "Copyright 2024 Amazon.com, Inc.",
			shouldFind:  true,
			ipType:      "copyright",
		},
		{
			name:        "patent disabled, patent content",
			disableType: "patent",
			content:     "Covered by US9123456 patent filing.",
			shouldFind:  false,
			ipType:      "patent",
		},
		{
			name:        "patent enabled, patent content",
			disableType: "",
			content:     "Covered by US9123456 patent filing.",
			shouldFind:  true,
			ipType:      "patent",
		},
		{
			name:        "trademark disabled, trademark content",
			disableType: "trademark",
			content:     "ProductName Trademark is registered.",
			shouldFind:  false,
			ipType:      "trademark",
		},
		{
			name:        "trademark enabled, trademark content",
			disableType: "",
			content:     "ProductName Trademark is registered.",
			shouldFind:  true,
			ipType:      "trademark",
		},
		{
			name:        "trade_secret disabled, trade_secret content",
			disableType: "trade_secret",
			content:     "This document is Classified.",
			shouldFind:  false,
			ipType:      "trade_secret",
		},
		{
			name:        "trade_secret enabled, trade_secret content",
			disableType: "",
			content:     "This document is Classified.",
			shouldFind:  true,
			ipType:      "trade_secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v *Validator
			if tt.disableType != "" {
				v = newValidatorWithDisabledTypes([]string{tt.disableType})
			} else {
				v = NewValidator()
			}

			matches, err := v.ValidateContent(tt.content+"\n", "test.go")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			found := matchesContainIPType(matches, tt.ipType)
			if tt.shouldFind && !found {
				t.Errorf("expected to find %s match but didn't", tt.ipType)
			}
			if !tt.shouldFind && found {
				t.Errorf("expected %s to be disabled but it was detected", tt.ipType)
			}
		})
	}
}

// --- Configure with no config does not crash ---

func TestConfigureNilConfig(t *testing.T) {
	v := NewValidator()
	v.Configure(nil)
	// Should still work with defaults
	matches, err := v.ValidateContent(copyrightLine+"\n", "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should be detected with nil config")
	}
}

// --- Configure with empty validators map ---

func TestConfigureEmptyValidators(t *testing.T) {
	v := NewValidator()
	cfg := &config.Config{
		Validators: map[string]map[string]interface{}{},
	}
	v.Configure(cfg)
	matches, err := v.ValidateContent(copyrightLine+"\n", "test.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchesContainIPType(matches, "copyright") {
		t.Error("copyright should be detected with empty validators config")
	}
}

// --- Pattern overrides from config ---

// TestConfigure_InvalidRegexDoesNotPanic locks in the contract that an
// invalid regex from config logs a warning and falls back to the built-in
// default. Previously regexp.MustCompile would panic the entire scan when
// users supplied a malformed pattern (or, more commonly, a YAML-escape-mangled
// pattern from a double-quoted scalar like "\b(...)\b"). See validator.go
// applyIPPatternOverride.
func TestConfigure_InvalidRegexDoesNotPanic(t *testing.T) {
	v := NewValidator()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Configure must not panic on invalid user regex; got: %v", r)
		}
	}()

	cfg := &config.Config{
		Validators: map[string]map[string]interface{}{
			"intellectual_property": {
				"intellectual_property_patterns": map[string]any{
					"trade_secret": "(unclosed group", // invalid regex
				},
			},
		},
	}
	v.Configure(cfg)

	// Built-in trade_secret pattern should still fire — invalid override
	// must not silently erase the default.
	matches, err := v.ValidateContent("This is Confidential information.\n", "test.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchesContainIPType(matches, "trade_secret") {
		t.Error("invalid override should leave the built-in trade_secret pattern in place")
	}
}

// TestConfigure_ValidPatternOverrideApplied confirms a well-formed user
// pattern actually replaces the built-in. The user-supplied narrowed pattern
// matches "Trade Secret" but not generic terms like "Confidential" or
// "Restricted" that the default catches.
func TestConfigure_ValidPatternOverrideApplied(t *testing.T) {
	v := NewValidator()

	cfg := &config.Config{
		Validators: map[string]map[string]interface{}{
			"intellectual_property": {
				"intellectual_property_patterns": map[string]any{
					// Narrow override: only matches "Trade Secret" exactly.
					"trade_secret": `\bTrade\s+Secret\b`,
				},
			},
		},
	}
	v.Configure(cfg)

	// Generic "Confidential" should NOT match the narrowed pattern.
	matches, err := v.ValidateContent("This is Confidential information.\n", "test.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matchesContainIPType(matches, "trade_secret") {
		t.Error("narrowed override should not match generic 'Confidential'")
	}

	// "Trade Secret" should still match.
	matches, err = v.ValidateContent("This is a Trade Secret.\n", "test.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matchesContainIPType(matches, "trade_secret") {
		t.Error("narrowed override should still match 'Trade Secret'")
	}
}

// TestTrademarkSymbolForms is a regression test for the trailing-\b bug: the ™, ®,
// (TM), and (R) markers — the dominant real-world trademark indicators — were never
// detected because a trailing ASCII \b cannot follow a non-word character. The word
// forms ("X Trademark") DID match, which is why earlier tests missed the gap.
func TestTrademarkSymbolForms(t *testing.T) {
	v := NewValidator()

	// True positives that must now be detected.
	positives := []string{
		"Acme™",    // Acme™
		"Acme®",    // Acme®
		"Acme(TM)", // (TM)
		"Acme(R)",  // (R)
		"Use of Photoshop™ is governed by license.", // ™ mid-line
		"the Windows® operating system",             // ® mid-line
		"ProductName Trademark is registered.",      // word form (unchanged)
		"FooBar Registered Trademark notice",        // registered word form
	}
	for _, line := range positives {
		matches, err := v.ValidateContent(line+"\n", "test.txt")
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", line, err)
		}
		if !matchesContainIPType(matches, "trademark") {
			t.Errorf("expected trademark detection for %q, got none", line)
		}
	}

	// Must NOT false-match: no trademark marker present, and "Trademarked" must not
	// partial-match the "...Trademark" word alternative (trailing \b on word forms).
	negatives := []string{
		"This is a normal line of code.",
		"version 2.0 of the library",
		"FooBar Trademarked goods are sold here", // 'Trademarked' != 'Trademark'
	}
	for _, line := range negatives {
		matches, err := v.ValidateContent(line+"\n", "test.txt")
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", line, err)
		}
		if matchesContainIPType(matches, "trademark") {
			t.Errorf("expected NO trademark detection for %q, but got one", line)
		}
	}
}

// tradeSecretConfidence returns the confidence of the first trade_secret match on
// the line, or -1 if none was produced.
func tradeSecretConfidence(t *testing.T, v *Validator, line string) float64 {
	t.Helper()
	matches, err := v.ValidateContent(line+"\n", "test.txt")
	if err != nil {
		t.Fatalf("unexpected error for %q: %v", line, err)
	}
	for _, m := range matches {
		if mt, ok := m.Metadata["ip_type"]; ok && mt == "trade_secret" {
			return m.Confidence
		}
	}
	return -1
}

// TestTradeSecretBareWordScoring is a regression test for bare generic trade-secret
// words surfacing at MEDIUM with no context. "Restricted"/"Classified"/"Proprietary"
// used to score 70-80 (>=60 MEDIUM); they now start below 60 so they only reach
// MEDIUM with corroborating context, while explicit confidentiality phrases stay
// MEDIUM-capable. We still detect all of them (so nothing is lost at LOW), but the
// bucket must differ.
func TestTradeSecretBareWordScoring(t *testing.T) {
	v := NewValidator()
	const mediumThreshold = 60.0

	// Bare generic words: detected, but BELOW the MEDIUM threshold without context.
	bare := []string{"Restricted", "Classified", "Proprietary"}
	for _, w := range bare {
		conf := tradeSecretConfidence(t, v, "Status: "+w)
		if conf < 0 {
			t.Errorf("%q should still be detected (at LOW), got no trade_secret match", w)
			continue
		}
		if conf >= mediumThreshold {
			t.Errorf("bare %q should score below MEDIUM (%.0f) without context, got %.1f", w, mediumThreshold, conf)
		}
	}

	// Explicit confidentiality phrases must remain MEDIUM-capable.
	explicit := []string{"Trade Secret", "Company Confidential", "Internal Use Only", "Confidential"}
	for _, w := range explicit {
		conf := tradeSecretConfidence(t, v, "Notice: "+w)
		if conf < mediumThreshold {
			t.Errorf("explicit marker %q should stay MEDIUM (>=%.0f), got %.1f", w, mediumThreshold, conf)
		}
	}
}

// TestPatentPrefixCaseSensitive is a regression test for M28: the patent prefix
// was case-insensitive, so lowercase currency/quantity figures ("cn 100,000,000
// yuan") matched as patents. The prefix is now case-sensitive (office codes are
// uppercase) while real uppercase patents still match.
func TestPatentPrefixCaseSensitive(t *testing.T) {
	v := NewValidator()
	// Currency/quantity prose must NOT be a patent.
	for _, line := range []string{"the cn 100,000,000 yuan", "jp 123,456,789 yen", "ep 12,345,678"} {
		matches, _ := v.ValidateContent(line+"\n", "test.txt")
		if matchesContainIPType(matches, "patent") {
			t.Errorf("lowercase currency %q should not match as a patent", line)
		}
	}
	// Real uppercase patents must still match.
	for _, line := range []string{"US 9,123,456 patent", "filed EP1234567 today"} {
		matches, _ := v.ValidateContent(line+"\n", "test.txt")
		if !matchesContainIPType(matches, "patent") {
			t.Errorf("real patent %q should be detected", line)
		}
	}
}

// TestCopyrightFooterVariants is a regression test for M29: copyright notices
// without a year, with em-dash ranges, or with parenthesized/no-year entities
// were missed because the pattern required a 4-digit year + ASCII-only name.
func TestCopyrightFooterVariants(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"© 2024",
		"© 2024 — Acme",
		"© 2024 (Acme)",
		"© Acme Corporation",
		"Copyright Acme Inc. All rights reserved",
		"© 2020-2024 Example LLC",
	} {
		matches, _ := v.ValidateContent(line+"\n", "test.txt")
		if !matchesContainIPType(matches, "copyright") {
			t.Errorf("copyright footer %q should be detected", line)
		}
	}
}

// TestEnsureCaseInsensitive is a regression test for M30: non-capturing "(?:..."
// and named "(?P<..." groups were mistaken for inline-flag groups, so a config
// override starting with one was left case-sensitive instead of getting (?i).
func TestEnsureCaseInsensitive(t *testing.T) {
	v := NewValidator()
	cases := map[string]bool{ // want (?i) prepended?
		`(?:US\d+)`: true, `(?P<x>a)`: true, `plain`: true,
		`(?i)foo`: false, `(?im)foo`: false, `(?-i)foo`: false, `(?s:.*)`: false,
	}
	for p, want := range cases {
		got := v.ensureCaseInsensitive(p)
		if (got != p) != want {
			t.Errorf("ensureCaseInsensitive(%q)=%q, prepended=%v want=%v", p, got, got != p, want)
		}
	}
}

// TestTradeSecretSuppressedByOpenSourceLicense is a regression test for L12: a
// trade-secret marker (Proprietary/Confidential/Trade Secret) on a line that
// also carries a recognized open-source / public-domain license must be capped
// below the MEDIUM threshold, since open licensing contradicts trade-secrecy.
func TestTradeSecretSuppressedByOpenSourceLicense(t *testing.T) {
	v := NewValidator()
	tsConf := func(line string) float64 {
		matches, _ := v.ValidateContent(line+"\n", "test.txt")
		for _, m := range matches {
			if mt, ok := m.Metadata["ip_type"]; ok && mt == "trade_secret" {
				return m.Confidence
			}
		}
		return -1
	}
	for _, line := range []string{
		"Proprietary blend, MIT license applies",
		"Confidential? No, this is open source",
		"Trade Secret SPDX-License-Identifier: Apache-2.0",
		"Proprietary algorithm released under the GPL",
	} {
		if c := tsConf(line); c >= 60 {
			t.Errorf("L12: %q should be capped below MEDIUM with an OSS license present, got %.1f", line, c)
		}
	}
}

// TestValidateContentSingleLineDoSBound is a performance regression test for the
// O(n^2) DoS in detectPatternsByLine / the legal-notice reconstruction path. The
// blowup shape for INTELLECTUAL_PROPERTY is a SINGLE very long line (no newlines)
// packed with IP matches. Before the fix, a ~1MB single line did not complete in
// 10 minutes (a 50KB line already took ~32s); the per-match strings.Index rescan,
// the per-match AnalyzeContext full-line lowercasing, an O(M^2) proximity overlap
// loop, and the per-match strings.ToLower(FullLine) in identifySemanticGroups were
// all quadratic in the single line. After the fix this completes in well under a
// second.
//
// The ceiling is intentionally generous (5s) so the test asserts "not quadratic"
// without being flaky on slow/loaded CI hardware — a genuine regression reintroduces
// many-second-to-minute behavior and trips it; normal variation will not.
func TestValidateContentSingleLineDoSBound(t *testing.T) {
	// Build a ~1MB single line (no newlines) packed with copyright, patent,
	// trade-secret and trademark markers — every IP sub-type, so the full
	// reconstruction path (the most expensive code) is exercised.
	const targetBytes = 1 << 20 // ~1MB
	unit := "Copyright 2024 Acme Inc. US9123456 Confidential Proprietary Acme(TM) "
	var sb strings.Builder
	sb.Grow(targetBytes + len(unit))
	for sb.Len() < targetBytes {
		sb.WriteString(unit)
	}
	content := sb.String() // no trailing newline => a single line

	v := NewValidator()

	const ceiling = 5 * time.Second
	start := time.Now()
	matches, err := v.ValidateContent(content, "dos_bound.txt")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Sanity: the packed line must still yield a finding (guards against a future
	// change that makes it "fast" by dropping detection entirely).
	if len(matches) == 0 {
		t.Fatalf("expected at least one finding on the packed worst-case line, got none")
	}
	if raceEnabled {
		// -race inflates wall-clock 5-20x; the scan still ran above (so -race
		// checks for data races), but the timing ceiling is skipped.
		t.Logf("worst-case ~1MB single line validated in %s (%d findings) (timing assertion skipped under -race)", elapsed, len(matches))
		return
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a ~1MB single line took %s, exceeding the %s ceiling; "+
			"the O(n^2) per-line behavior may have regressed", elapsed, ceiling)
	}
	t.Logf("worst-case ~1MB single line validated in %s (%d findings)", elapsed, len(matches))
}
