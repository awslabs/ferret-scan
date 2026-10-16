// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"strings"
	"testing"
)

// TestParseRedactionStrategyIsExact pins the #772 contract: the three names, exactly, and an error
// for everything else, with a hint only when a case or whitespace variant of a valid name was given.
func TestParseRedactionStrategyIsExact(t *testing.T) {
	accepted := map[string]RedactionStrategy{
		"simple":            RedactionSimple,
		"format_preserving": RedactionFormatPreserving,
		"synthetic":         RedactionSynthetic,
	}
	for name, want := range accepted {
		got, err := ParseRedactionStrategy(name)
		if err != nil || got != want {
			t.Errorf("ParseRedactionStrategy(%q) = %v, %v; want %v, nil", name, got, err, want)
		}
		if got.String() != name {
			t.Errorf("%v.String() = %q, want %q (the parser and String must round-trip)", got, got.String(), name)
		}
	}

	refused := []struct {
		value string
		hint  string // "" when no hint is expected
	}{
		{"simpel", ""}, {"SIMPLE", "simple"}, {"Simple", "simple"}, {" simple", "simple"},
		{"simple ", "simple"}, {"synthetc", ""}, {"format-preserving", ""}, {"FORMAT_PRESERVING", "format_preserving"},
		{"none", ""}, {"bogus", ""}, {"", ""}, {"  ", ""}, {"simple,", ""}, {"simple,synthetic", ""},
	}
	for _, tc := range refused {
		got, err := ParseRedactionStrategy(tc.value)
		if err == nil {
			t.Errorf("ParseRedactionStrategy(%q) accepted as %v; before #772 this value became format_preserving silently", tc.value, got)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, `"`+tc.value+`"`) {
			t.Errorf("%q: the error does not quote the value: %s", tc.value, msg)
		}
		for _, name := range RedactionStrategyNames {
			if !strings.Contains(msg, name) {
				t.Errorf("%q: the error does not name %q: %s", tc.value, name, msg)
			}
		}
		if tc.hint == "" && strings.Contains(msg, "did you mean") {
			t.Errorf("%q: unexpected hint in %s", tc.value, msg)
		}
		if tc.hint != "" && !strings.Contains(msg, `did you mean "`+tc.hint+`"`) {
			t.Errorf("%q: want a hint for %q, got %s", tc.value, tc.hint, msg)
		}
	}
}

// TestRedactionStrategyValid pins Valid on the three definitions and on the values a cast can produce.
func TestRedactionStrategyValid(t *testing.T) {
	for _, s := range []RedactionStrategy{RedactionSimple, RedactionFormatPreserving, RedactionSynthetic} {
		if !s.Valid() {
			t.Errorf("%v.Valid() = false", s)
		}
	}
	for _, s := range []RedactionStrategy{-1, 3, 7, 100} {
		if s.Valid() {
			t.Errorf("RedactionStrategy(%d).Valid() = true", int(s))
		}
	}
	// The zero value is simple: a struct that never set a strategy keeps nothing of the original,
	// which is the fail-safe direction. Renumbering would change the audit log's integers.
	var zero RedactionStrategy
	if zero != RedactionSimple || zero.String() != "simple" {
		t.Errorf("the zero value is %v (%q), want simple", zero, zero.String())
	}
	if len(RedactionStrategyNames) != 3 {
		t.Errorf("RedactionStrategyNames = %v, want the three names", RedactionStrategyNames)
	}
}
