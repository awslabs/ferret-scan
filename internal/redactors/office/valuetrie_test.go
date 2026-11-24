// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// locateFixture is n lines of extracted text, each holding one distinct e-mail, split across two
// parts at the half way mark the way a document and its docProps are concatenated, with one
// position per line the way extraction records one per text element.
func locateFixture(n int) (text string, positions []OfficeTextPosition, values []string) {
	var doc strings.Builder
	for i := 0; i < n; i++ {
		v := fmt.Sprintf("user%06d.x%d@corp%d.example.org", i, (i*7919)%100000, i%97)
		line := fmt.Sprintf("contact %s for details", v)
		part := "word/document.xml"
		if i >= n/2 {
			part = "word/footer1.xml"
		}
		positions = append(positions, OfficeTextPosition{FileName: part, DocumentOffset: doc.Len(), Text: line})
		doc.WriteString(line + " ")
		values = append(values, v)
	}
	return doc.String(), positions, values
}

// locateEachReference is the implementation locateAll replaced: one locateMatch per distinct value,
// each walking the extracted text from its start (#1054).
func locateEachReference(text string, positions []OfficeTextPosition, values []string) []matchLocation {
	partCount := distinctPartCount(positions)
	out := make([]matchLocation, len(values))
	for i, v := range values {
		out[i] = locateMatch(text, positions, v, partCount)
	}
	return out
}

// locateAll must answer exactly what locateMatch answers, value by value: the same first offset and
// the same parts in the same order. Random texts over a two-letter alphabet make every hard case
// common: values nested in other values, values that overlap themselves ("aa" in "aaa"), values that
// are a prefix or suffix of another, occurrences straddling a part boundary or falling in a gap.
func TestLocateAllEqualsLocateMatch(t *testing.T) {
	rng := rand.New(rand.NewSource(1054))
	letters := []string{"a", "b"}
	word := func(maxLen int) string {
		var b strings.Builder
		for n := 1 + rng.Intn(maxLen); n > 0; n-- {
			b.WriteString(letters[rng.Intn(2)])
		}
		return b.String()
	}
	for trial := 0; trial < 3000; trial++ {
		var doc strings.Builder
		var positions []OfficeTextPosition
		for p, parts := 0, 1+rng.Intn(3); p < parts; p++ {
			for e := rng.Intn(4); e >= 0; e-- {
				txt := word(12)
				positions = append(positions, OfficeTextPosition{FileName: fmt.Sprintf("p%d.xml", p), DocumentOffset: doc.Len(), Text: txt})
				doc.WriteString(txt)
				if rng.Intn(3) == 0 { // bytes no position covers
					doc.WriteString(word(3))
				}
			}
		}
		seen := map[string]bool{}
		var values []string
		for k := 1 + rng.Intn(6); k > 0; k-- {
			if v := word(5); !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
		partCount := distinctPartCount(positions)
		want := locateEachReference(doc.String(), positions, values)
		got := locateAll(doc.String(), positions, values, partCount)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("trial %d: text %q positions %+v values %q\n got  %+v\n want %+v", trial, doc.String(), positions, values, got, want)
		}
	}
}

// presence must report what strings.Contains reports for every value, nested ones included: a
// strings.Replacer would consume a value nested in a longer one and hide it.
func TestValueTriePresenceEqualsContains(t *testing.T) {
	values := []string{"abcd", "bc", "c", "xyz", "abcdabcd", "yz", "aa"}
	for _, text := range []string{"", "abcd", "zabcdz", "xyzaabcdabcd", "ab", "aaa", "xy z"} {
		held := make([]bool, len(values))
		newValueTrie(values).presence(text, held)
		for i, v := range values {
			if held[i] != strings.Contains(text, v) {
				t.Errorf("text %q value %q: presence %v, Contains %v", text, v, held[i], strings.Contains(text, v))
			}
		}
	}
}

// Locating the reported values must cost one pass over the extracted text however many distinct values
// there are. It used to cost one strings.Index walk per value, and the i-th value's first occurrence sits
// about i values into the text, so N distinct values scanned N^2/2 value-lengths: a .pptx of distinct
// e-mails cost 0.73 s of redaction at 8,000 values and 2.41 s at 16,000, 84% of it in strings.Index
// (locateMatch, redactor.go:1714 on a73c55d6; #1054).
//
// What is ASSERTED is locateAll's cost against the per-value implementation on one input, guardValues distinct
// values, both timed within the same measurement on the CPU clock (internal/perfguard: GC off, minimum of
// interleaved pairs). Both see the same machine at the same moment, so host load or a runner image moves
// both and the ratio stays put. Neither instrument of the other kind works here: the defect copies no
// bytes (strings.Index allocates nothing), so allocated bytes read the same for the regressed code; and a
// growth ratio of the one-pass code alone moves with the cache (docs/testing/TEST_PLAN.md, "Sampling
// answers variance"). The growth of locateAll over guardValues/4 -> guardValues values is logged, not asserted.
//
// Readings are recorded in the pull request body (per-pair spread, quiet and loaded host, -race).
func TestLocateAllCostsOnePassNotOnePerValue(t *testing.T) {
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}
	text0, pos0, v0 := locateFixture(guardValues / 4)
	text1, pos1, v1 := locateFixture(guardValues)

	// Non-vacuity: every value is found, in the right part, by both implementations, at both sizes.
	for _, tc := range []struct {
		text string
		pos  []OfficeTextPosition
		vals []string
	}{{text0, pos0, v0}, {text1, pos1, v1}} {
		for name, locs := range map[string][]matchLocation{
			"locateAll":           locateAll(tc.text, tc.pos, tc.vals, 0),
			"per-value reference": locateEachReference(tc.text, tc.pos, tc.vals),
		} {
			for i, loc := range locs {
				wantPart := "word/document.xml"
				if i >= len(tc.vals)/2 {
					wantPart = "word/footer1.xml"
				}
				if loc.firstOffset != strings.Index(tc.text, tc.vals[i]) || len(loc.parts) != 1 || loc.parts[0].FileName != wantPart {
					t.Fatalf("%s, %d values: value %d located at %d in %+v, want offset %d in %s",
						name, len(tc.vals), i, loc.firstOffset, loc.parts, strings.Index(tc.text, tc.vals[i]), wantPart)
				}
			}
		}
	}

	g, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { locateAll(text0, pos0, v0, 0) },
		func() { locateAll(text1, pos1, v1, 0) })
	if err != nil {
		t.Fatalf("measuring growth: %v", err)
	}
	t.Logf("locateAll, 4x values: %s (logged, not asserted; linear is ~4x, one walk per value ~16x)", g)

	// "base" is locateAll and "big" the reference, so Ratio is reference / locateAll.
	r, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { locateAll(text1, pos1, v1, 0) },
		func() { locateEachReference(text1, pos1, v1) })
	if err != nil {
		t.Fatalf("measuring the two implementations: %v", err)
	}
	t.Logf("per-value reference / locateAll at %d values: %s", len(v1), r)
	if _, ok := r.Ticks(); !ok {
		t.Logf("ratio NOT asserted: %s", r.ResolutionNote())
		return
	}
	perfguard.ReportMargin(t, "office locateAll, per-value reference over one pass", r, locateAllBound, perfguard.StayAbove)
	if r.Ratio < locateAllBound {
		t.Errorf("locateAll costs %s of one walk per value at %d values; want the per-value code at least %.1fx dearer: locating has a per-value pass again",
			r, len(v1), locateAllBound)
	}
}
