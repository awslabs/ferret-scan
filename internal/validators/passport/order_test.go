// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	stdctx "context"
	"strings"
	"testing"
)

// td3MRZ is a real ICAO 9303 TD3 line 1: 44 characters. It matches BOTH the
// "MRZ" pattern (38-40 trailing filler chars) and "MRZ_TD3" (exactly 39), so
// the same span is claimed by two entries of the patterns map. That overlap is
// what made the map's iteration order observable.
const td3MRZ = "P<GBRSMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<"

func mrzContent() string {
	return "passport holder machine readable zone icao\n" + td3MRZ + "\n"
}

// signature renders the emitted matches as an order-sensitive string. The
// "country" metadata key is the pattern name, and it reaches the user: the text
// formatter prints it for every passport finding.
func signature(t *testing.T, content string) string {
	t.Helper()
	v := NewValidator()
	matches, err := v.ValidateContentCtx(stdctx.Background(), content, "/test/passport.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	parts := make([]string, 0, len(matches))
	for _, m := range matches {
		country, _ := m.Metadata["country"].(string)
		parts = append(parts, country)
	}
	return strings.Join(parts, ",")
}

// TestPatternOrderIsFixed pins the emitted order for a span two patterns claim.
// Before the fix the scan ranged v.patterns (a map), so this produced either
// "MRZ_TD3,MRZ" or "MRZ,MRZ_TD3" at random.
func TestPatternOrderIsFixed(t *testing.T) {
	got := signature(t, mrzContent())
	if got != "MRZ_TD3,MRZ" {
		t.Fatalf("pattern order = %q, want %q (patternOrder puts the more specific TD3 pattern first)", got, "MRZ_TD3,MRZ")
	}
}

// TestPatternOrderStableAcrossRuns is the anti-flake guard: Go randomizes map
// iteration per range statement, so a single call can pass by luck. 200 calls
// on the same content must all agree.
func TestPatternOrderStableAcrossRuns(t *testing.T) {
	seen := make(map[string]int)
	content := mrzContent()
	for i := 0; i < 200; i++ {
		seen[signature(t, content)]++
	}
	if len(seen) != 1 {
		t.Fatalf("emit order varied across 200 runs: %d distinct orders %v", len(seen), seen)
	}
}

// TestPatternOrderCoversEveryPattern guards the panic in NewValidator. If a new
// pattern is added to the patterns map and not to patternOrder, that pattern
// would silently stop being applied — for a scanner that means a passport
// format that is no longer detected at all, which is a missed finding, not a
// cosmetic regression. NewValidator panics instead; this asserts it does not
// panic today and that the slice really covers the map.
func TestPatternOrderCoversEveryPattern(t *testing.T) {
	v := NewValidator()
	if len(v.patternOrder) != len(v.compiledPatterns) {
		t.Fatalf("patternOrder has %d names but there are %d compiled patterns", len(v.patternOrder), len(v.compiledPatterns))
	}
	inOrder := make(map[string]bool, len(v.patternOrder))
	for _, name := range v.patternOrder {
		if inOrder[name] {
			t.Fatalf("patternOrder lists %q twice", name)
		}
		inOrder[name] = true
		if v.compiledPatterns[name] == nil {
			t.Fatalf("patternOrder names %q, which has no compiled pattern", name)
		}
	}
	for name := range v.compiledPatterns {
		if !inOrder[name] {
			t.Fatalf("pattern %q is missing from patternOrder, so it would never be applied", name)
		}
	}
}
