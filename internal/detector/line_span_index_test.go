// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"fmt"
	"strings"
	"testing"
)

// The two strategies must produce IDENTICAL spans for the same input.
//
// This is the load-bearing test of the change. resolveByIndex exists only to be faster; any
// disagreement with resolveByRescan is a behaviour change smuggled in as an optimisation, and every
// consumer of these offsets — SARIF regions, gitlab-sast ids, the redaction overlap pass — depends on
// the exact hand-out rules rather than merely on "some position".
//
// The cases are chosen to cover each rule that took a comment to explain: successive occurrences of a
// repeated value, an overlapping candidate that a cursor advancing past the whole match must skip,
// exhaustion (reuse the first, advance nothing), and a value absent from the line.
func TestIndexAndRescanAgree(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		texts []string
	}{
		{"distinct values in order", "a 10.0.0.1 b 10.0.0.2 c 10.0.0.3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"distinct values out of order", "a 10.0.0.1 b 10.0.0.2 c 10.0.0.3", []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}},
		{"one value repeated", "x 4.4.4.4 y 4.4.4.4 z 4.4.4.4", []string{"4.4.4.4", "4.4.4.4", "4.4.4.4"}},
		{"more matches than occurrences", "only 4.4.4.4 once", []string{"4.4.4.4", "4.4.4.4", "4.4.4.4"}},
		{"overlapping candidate", "aaa", []string{"aa", "aa"}},
		{"overlapping longer run", "aaaaa", []string{"aa", "aa", "aa"}},
		{"absent value", "nothing here", []string{"10.0.0.1"}},
		{"present and absent mixed", "has 10.0.0.1 only", []string{"10.0.0.1", "10.0.0.2"}},
		{"different lengths", "a 1.1.1.1 bb 222.222.222.222 c", []string{"1.1.1.1", "222.222.222.222"}},
		{"value is the whole line", "10.0.0.1", []string{"10.0.0.1"}},
		{"adjacent occurrences", "1.1.1.11.1.1.1", []string{"1.1.1.1", "1.1.1.1"}},
		{"repeat interleaved with distinct", "p 5.5.5.5 q 6.6.6.6 r 5.5.5.5", []string{"5.5.5.5", "6.6.6.6", "5.5.5.5"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			build := func() ([]Match, []int) {
				ms := make([]Match, len(tc.texts))
				idxs := make([]int, len(tc.texts))
				for i, txt := range tc.texts {
					ms[i] = Match{Text: txt, LineNumber: 1, Context: ContextInfo{FullLine: tc.line}}
					idxs[i] = i
				}
				return ms, idxs
			}

			msA, idxsA := build()
			byIndex := make([]LineSpan, len(msA))
			resolveByIndex(tc.line, 1, msA, idxsA, byIndex)

			msB, idxsB := build()
			byRescan := make([]LineSpan, len(msB))
			resolveByRescan(tc.line, 1, msB, idxsB, byRescan, map[int]map[string]int{})

			for i := range byIndex {
				if byIndex[i] != byRescan[i] {
					t.Errorf("match %d (%q) disagrees:\n  index  = %+v\n  rescan = %+v\n  line   = %q",
						i, tc.texts[i], byIndex[i], byRescan[i], tc.line)
				}
			}
		})
	}
}

// A randomised sweep over the same equivalence, because the hand-picked cases above can only cover
// the shapes I thought of. Deterministic seed so a failure is reproducible.
func TestIndexAndRescanAgreeOnGeneratedInput(t *testing.T) {
	values := []string{"aa", "ab", "aab", "b", "bb", "abab", "ba"}
	alphabet := "ab"

	// A deterministic pseudo-random walk: no math/rand, so this cannot vary between runs.
	next := func(state *uint64, n int) int {
		*state = *state*6364136223846793005 + 1442695040888963407
		return int((*state >> 33) % uint64(n))
	}

	state := uint64(42)
	for trial := 0; trial < 400; trial++ {
		var sb strings.Builder
		for i := 0; i < 24; i++ {
			sb.WriteByte(alphabet[next(&state, len(alphabet))])
		}
		line := sb.String()

		texts := make([]string, 0, 6)
		for i := 0; i < 1+next(&state, 5); i++ {
			texts = append(texts, values[next(&state, len(values))])
		}

		build := func() ([]Match, []int) {
			ms := make([]Match, len(texts))
			idxs := make([]int, len(texts))
			for i, txt := range texts {
				ms[i] = Match{Text: txt, LineNumber: 1, Context: ContextInfo{FullLine: line}}
				idxs[i] = i
			}
			return ms, idxs
		}

		msA, idxsA := build()
		byIndex := make([]LineSpan, len(msA))
		resolveByIndex(line, 1, msA, idxsA, byIndex)

		msB, idxsB := build()
		byRescan := make([]LineSpan, len(msB))
		resolveByRescan(line, 1, msB, idxsB, byRescan, map[int]map[string]int{})

		for i := range byIndex {
			if byIndex[i] != byRescan[i] {
				t.Fatalf("trial %d, match %d (%q) disagrees on line %q:\n  index  = %+v\n  rescan = %+v",
					trial, i, texts[i], line, byIndex[i], byRescan[i])
			}
		}
	}
}

// Lines are grouped into a map, so they are RESOLVED in randomised order. The result must not depend
// on that order — each line owns its own cursor, and a span is written by match index.
//
// Asserted because map-order nondeterminism reaching the output is a defect this repo has shipped
// before: the same file reported a different number of findings run to run.
func TestResolveLineSpansIsIndependentOfLineOrder(t *testing.T) {
	build := func() []Match {
		var ms []Match
		for lineNo := 1; lineNo <= 40; lineNo++ {
			line := fmt.Sprintf("row %d has 10.0.%d.1 and 10.0.%d.1 again", lineNo, lineNo, lineNo)
			for rep := 0; rep < 2; rep++ {
				ms = append(ms, Match{
					Text:       fmt.Sprintf("10.0.%d.1", lineNo),
					LineNumber: lineNo,
					Context:    ContextInfo{FullLine: line},
				})
			}
		}
		return ms
	}

	first := ResolveLineSpans(build())
	for run := 0; run < 25; run++ {
		got := ResolveLineSpans(build())
		for i := range first {
			if got[i] != first[i] {
				t.Fatalf("run %d differs at match %d: %+v vs %+v — line resolution order is "+
					"reaching the output", run, i, got[i], first[i])
			}
		}
	}

	// Non-vacuity: the two matches per line must land on DIFFERENT offsets, or this test would
	// hold for a function that assigned everything the same position.
	if !first[0].OK || !first[1].OK || first[0].Start == first[1].Start {
		t.Fatalf("the two occurrences on line 1 resolved to %+v and %+v; distinct offsets are the "+
			"whole point of the cursor", first[0], first[1])
	}
}

// useIndex must choose rescanning for ordinary input and indexing for the machine-generated shape.
// If it ever chose indexing for a handful of matches it would add map allocations to every scan.
func TestUseIndexPicksTheCheaperStrategy(t *testing.T) {
	mk := func(line string, texts ...string) ([]Match, []int) {
		ms := make([]Match, len(texts))
		idxs := make([]int, len(texts))
		for i, txt := range texts {
			ms[i] = Match{Text: txt, LineNumber: 1, Context: ContextInfo{FullLine: line}}
			idxs[i] = i
		}
		return ms, idxs
	}

	t.Run("a few matches: rescan", func(t *testing.T) {
		line := "a 10.0.0.1 b 10.0.0.2 c" + strings.Repeat(" pad", 500)
		ms, idxs := mk(line, "10.0.0.1", "10.0.0.2")
		if useIndex(line, ms, idxs) {
			t.Error("indexing chosen for 2 matches: building the maps costs more than two short scans")
		}
	})

	t.Run("short line: rescan", func(t *testing.T) {
		line := "10.0.0.1 10.0.0.2"
		texts := make([]string, 0, 100)
		for i := 0; i < 100; i++ {
			texts = append(texts, "10.0.0.1")
		}
		ms, idxs := mk(line, texts...)
		if useIndex(line, ms, idxs) {
			t.Error("indexing chosen for a line under the byte floor")
		}
	})

	t.Run("many distinct values of few lengths: index", func(t *testing.T) {
		var sb strings.Builder
		var texts []string
		for i := 0; i < 2000; i++ {
			v := fmt.Sprintf("%d.%d.1.2", (i/254)%200+11, i%254+1)
			texts = append(texts, v)
			sb.WriteString("host " + v + " ")
		}
		line := sb.String()
		ms, idxs := mk(line, texts...)
		if !useIndex(line, ms, idxs) {
			t.Error("rescanning chosen for 2000 distinct values on one line — this is the shape " +
				"that costs one full line traversal PER VALUE")
		}
	})

	t.Run("many matches but one repeated value: rescan", func(t *testing.T) {
		// The cursor already makes this linear, so indexing would only add allocations.
		line := strings.Repeat("host 4.4.4.4 ", 2000)
		texts := make([]string, 0, 2000)
		for i := 0; i < 2000; i++ {
			texts = append(texts, "4.4.4.4")
		}
		ms, idxs := mk(line, texts...)
		if useIndex(line, ms, idxs) {
			t.Error("indexing chosen for ONE repeated value: rescanning is already linear here " +
				"because the cursor advances past each occurrence")
		}
	})
}
