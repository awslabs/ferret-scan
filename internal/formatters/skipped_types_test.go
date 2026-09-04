// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"strings"
	"testing"
)

// #583: the scan reported "14 skipped" and nothing said which 14.
//
// On this repository they were 13 compiled Go test binaries and a .DS_Store, so no coverage was lost —
// but the output was byte-identical to one where fourteen customer documents had been declined, which
// is the whole problem. The summary now reads
//
//	Files: 29 scanned, 14 skipped (.test × 13, .DS_Store × 1) | Findings: 203 (...)

func TestSkippedTypeLabel(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"cloudresources.test", ".test"},
		{"/a/b/core.test", ".test"},
		{"IMAGE.PNG", ".png"},                // normalised, so .PNG and .png share a bucket
		{".DS_Store", ".DS_Store"},           // dotfile: filepath.Ext returns the whole name
		{"/x/.gitignore", ".gitignore"},      // same, and it must not read as an extension
		{".pre-commit-config.yaml", ".yaml"}, // dotfile WITH a real extension
		{"Makefile", "(no extension)"},
		{"/usr/bin/env", "(no extension)"},
	} {
		if got := SkippedTypeLabel(tc.path); got != tc.want {
			t.Errorf("SkippedTypeLabel(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestSkippedTypeCountsGroups(t *testing.T) {
	got := SkippedTypeCounts([]string{"a.test", "b.test", "c.png", ".DS_Store", "Makefile"})
	want := map[string]int{".test": 2, ".png": 1, ".DS_Store": 1, "(no extension)": 1}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
	if SkippedTypeCounts(nil) != nil {
		t.Error("nil input must produce a nil map, so the field is omitted from json")
	}
}

// TestFormatSkippedTypesIsDeterministic is not pedantry: ranging the map directly would make this
// string vary run to run, and it appears in CI logs people diff and in the summary box whose width is
// computed from it.
func TestFormatSkippedTypesIsDeterministic(t *testing.T) {
	counts := map[string]int{".b": 2, ".a": 2, ".c": 5, ".d": 1}
	first := FormatSkippedTypes(counts)
	for i := 0; i < 50; i++ {
		if got := FormatSkippedTypes(counts); got != first {
			t.Fatalf("run %d rendered %q, first run rendered %q", i, got, first)
		}
	}
	// Descending count, then label. .c(5) then the two 2s alphabetically, then .d(1).
	if want := "(.c × 5, .a × 2, .b × 2, .d × 1)"; first != want {
		t.Errorf("got %q, want %q", first, want)
	}
}

// TestOverflowIsDisclosedNotDropped is the rule this whole change exists to enforce, applied to its own
// output: a truncation that reads as completeness is the defect, so the hidden count must be stated.
func TestOverflowIsDisclosedNotDropped(t *testing.T) {
	counts := map[string]int{}
	for i := 0; i < MaxSkippedTypesShown+5; i++ {
		counts[string(rune('a'+i))] = MaxSkippedTypesShown + 5 - i
	}
	got := FormatSkippedTypes(counts)

	if !strings.Contains(got, "and 5 more types") {
		t.Errorf("overflow not disclosed in %q — a silent cap is exactly the failure this change fixes", got)
	}
	if n := strings.Count(got, " × "); n != MaxSkippedTypesShown {
		t.Errorf("showed %d types, want %d", n, MaxSkippedTypesShown)
	}

	// Singular, because "and 1 more types" is the kind of detail that makes output look generated.
	one := map[string]int{}
	for i := 0; i < MaxSkippedTypesShown+1; i++ {
		one[string(rune('a'+i))] = MaxSkippedTypesShown + 1 - i
	}
	if s := FormatSkippedTypes(one); !strings.Contains(s, "and 1 more type,") && !strings.HasSuffix(s, "and 1 more type)") {
		t.Errorf("got %q, want the singular 'more type'", s)
	}
}

// TestEmptyRendersNothing keeps the summary line clean on a run with no skips: a trailing "()" would
// appear on every healthy scan.
func TestEmptyRendersNothing(t *testing.T) {
	for _, in := range []map[string]int{nil, {}} {
		if got := FormatSkippedTypes(in); got != "" {
			t.Errorf("FormatSkippedTypes(%v) = %q, want empty", in, got)
		}
	}
	if got := SummarizeSkippedTypes(nil); got != "" {
		t.Errorf("SummarizeSkippedTypes(nil) = %q, want empty", got)
	}
}

// TestTheCapIsPresentationOnly pins that the structured value machine consumers read is NOT truncated.
// Capping the map would silently lose data for anyone parsing json.
func TestTheCapIsPresentationOnly(t *testing.T) {
	var paths []string
	for i := 0; i < MaxSkippedTypesShown+4; i++ {
		paths = append(paths, "f."+string(rune('a'+i)))
	}
	counts := SkippedTypeCounts(paths)
	if len(counts) != MaxSkippedTypesShown+4 {
		t.Errorf("counts has %d entries, want %d — the cap must not reach the structured value",
			len(counts), MaxSkippedTypesShown+4)
	}
	if !strings.Contains(FormatSkippedTypes(counts), "more type") {
		t.Error("the rendered form should still be capped")
	}
}
