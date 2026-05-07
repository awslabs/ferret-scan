// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"ferret-scan/internal/config"
	"ferret-scan/internal/detector"
	"testing"
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
