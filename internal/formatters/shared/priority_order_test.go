// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"sort"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestLessByPriority_IsTotalOrder is the regression test for formatter output
// stability. The display comparator used to be (confidence desc, type asc) only,
// which is NOT a total order: two findings with the same confidence and type kept
// their input-slice order, and that order can be nondeterministic (map iteration
// upstream). The serialized output then flapped run to run on unchanged input.
//
// This asserts that sorting a deliberately-shuffled set of same-(confidence,type)
// findings produces one fixed order, and that the order is the intended one
// (confidence desc, then type, line, filename, text asc).
func TestLessByPriority_IsTotalOrder(t *testing.T) {
	// Same confidence and type, differing only by line — the case the old
	// comparator left unordered.
	base := []detector.Match{
		{Type: "EMAIL", Confidence: 60, LineNumber: 30, Text: "c@x.com", Filename: "f"},
		{Type: "EMAIL", Confidence: 60, LineNumber: 10, Text: "a@x.com", Filename: "f"},
		{Type: "EMAIL", Confidence: 60, LineNumber: 20, Text: "b@x.com", Filename: "f"},
		{Type: "SSN", Confidence: 90, LineNumber: 5, Text: "111", Filename: "f"},
		{Type: "EMAIL", Confidence: 90, LineNumber: 5, Text: "z@x.com", Filename: "f"},
	}

	want := sortedCopy(base)

	// Feed many different input permutations; each must sort to the same order.
	perms := [][]int{
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{2, 0, 4, 1, 3},
		{1, 3, 0, 4, 2},
		{3, 4, 0, 2, 1},
	}
	for pi, perm := range perms {
		in := make([]detector.Match, len(base))
		for i, idx := range perm {
			in[i] = base[idx]
		}
		got := sortedCopy(in)
		for i := range want {
			if got[i].Type != want[i].Type || got[i].Confidence != want[i].Confidence ||
				got[i].LineNumber != want[i].LineNumber || got[i].Text != want[i].Text {
				t.Fatalf("perm %d: sort is not a stable total order at index %d: got %+v, want %+v",
					pi, i, got[i], want[i])
			}
		}
	}

	// Assert the intended ordering explicitly: highest confidence first, then by
	// type, then line. The two conf=90 come first (EMAIL before SSN by type),
	// then the three conf=60 EMAILs by line 10,20,30.
	wantOrder := []struct {
		typ  string
		conf float64
		line int
	}{
		{"EMAIL", 90, 5},
		{"SSN", 90, 5},
		{"EMAIL", 60, 10},
		{"EMAIL", 60, 20},
		{"EMAIL", 60, 30},
	}
	for i, w := range wantOrder {
		if want[i].Type != w.typ || want[i].Confidence != w.conf || want[i].LineNumber != w.line {
			t.Errorf("order index %d: got (%s,%.0f,L%d), want (%s,%.0f,L%d)",
				i, want[i].Type, want[i].Confidence, want[i].LineNumber, w.typ, w.conf, w.line)
		}
	}
}

func sortedCopy(in []detector.Match) []detector.Match {
	out := make([]detector.Match, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return LessByPriority(out[i], out[j]) })
	return out
}

// TestSortSuppressedByPriority_IsTotalOrder is the companion regression test for
// the suppressed block. Nothing sorted suppressed findings at all: every
// formatter gave `matches` a total order but emitted `suppressedMatches` in
// arrival order, which is per-file worker completion order. Measured on a real
// 5-file scan, `--show-suppressed` produced a different [SUPP] row order on all
// 10 runs of the same binary over unchanged input, in text, JSON, YAML and CSV.
func TestSortSuppressedByPriority_IsTotalOrder(t *testing.T) {
	base := []detector.SuppressedMatch{
		// Identical finding, two different rules — the last tiebreaker.
		{Match: detector.Match{Type: "EMAIL", Confidence: 60, LineNumber: 7, Text: "a@x.com", Filename: "f"}, SuppressedBy: "SUP-2"},
		{Match: detector.Match{Type: "EMAIL", Confidence: 60, LineNumber: 7, Text: "a@x.com", Filename: "f"}, SuppressedBy: "SUP-1"},
		// Same (confidence, type), differing line — unordered before this fix.
		{Match: detector.Match{Type: "PHONE", Confidence: 90, LineNumber: 30, Text: "c", Filename: "f"}, SuppressedBy: "SUP-3"},
		{Match: detector.Match{Type: "PHONE", Confidence: 90, LineNumber: 10, Text: "a", Filename: "f"}, SuppressedBy: "SUP-4"},
		{Match: detector.Match{Type: "SSN", Confidence: 90, LineNumber: 10, Text: "b", Filename: "f"}, SuppressedBy: "SUP-5"},
	}

	key := func(s detector.SuppressedMatch) string {
		return s.Match.Type + "|" + s.SuppressedBy
	}

	sortedSuppressedCopy := func(in []detector.SuppressedMatch) []detector.SuppressedMatch {
		out := make([]detector.SuppressedMatch, len(in))
		copy(out, in)
		SortSuppressedByPriority(out)
		return out
	}

	want := sortedSuppressedCopy(base)

	perms := [][]int{
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{2, 0, 4, 1, 3},
		{1, 3, 0, 4, 2},
		{3, 4, 0, 2, 1},
	}
	for pi, perm := range perms {
		in := make([]detector.SuppressedMatch, len(base))
		for i, idx := range perm {
			in[i] = base[idx]
		}
		got := sortedSuppressedCopy(in)
		for i := range want {
			if key(got[i]) != key(want[i]) {
				t.Fatalf("perm %d: suppressed sort is not a stable total order at index %d: got %s, want %s",
					pi, i, key(got[i]), key(want[i]))
			}
		}
	}

	// The intended order: highest confidence first, then type, then line, and
	// finally the suppressing rule id for otherwise-identical entries.
	wantOrder := []string{"PHONE|SUP-4", "PHONE|SUP-3", "SSN|SUP-5", "EMAIL|SUP-1", "EMAIL|SUP-2"}
	for i, w := range wantOrder {
		if key(want[i]) != w {
			t.Errorf("order index %d: got %s, want %s", i, key(want[i]), w)
		}
	}
}
