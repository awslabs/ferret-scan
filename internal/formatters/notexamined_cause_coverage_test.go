// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"fmt"
	"testing"
)

// #635: CapNotExamined returned a flat files[:50] prefix of a list its caller sorted
// cause-then-path, so the first cause in sort order took the whole budget whenever it had 50 or more
// entries and every later cause vanished from the enumeration.
//
// Measured on a tree of 60 unreadable files plus 3 unparseable PDFs, SARIF output:
//
//	before:  50 "cannot read" + 1 summary, ZERO "cannot parse"
//	after:   47 "cannot read" + 3 "cannot parse" + 1 summary
//
// A consumer of the first learned that 13 files were omitted and could not learn that some of them
// failed for a reason with a different remedy — fix the permissions, versus the file is not a PDF.

func mkFiles(spec ...struct {
	cause NotExaminedCause
	n     int
}) []NotExaminedFile {
	var out []NotExaminedFile
	for _, s := range spec {
		for i := 0; i < s.n; i++ {
			out = append(out, NotExaminedFile{
				Path:   fmt.Sprintf("c%d-%d.txt", int(s.cause), i),
				Cause:  s.cause,
				Detail: "d",
			})
		}
	}
	return out
}

func countByCause(files []NotExaminedFile) map[NotExaminedCause]int {
	m := map[NotExaminedCause]int{}
	for _, f := range files {
		m[f.Cause]++
	}
	return m
}

// The REAL cause constants, not stand-ins. NotExaminedCause is an int enum, so invented values would
// stringify as "unknown" and collide with each other in a map literal — which is exactly what a first
// version of this file did, and the compiler caught it as "duplicate key unknown".
//
// Using the real ones also keeps the fixtures honest about sort order: the caller sorts by cause, and
// these are declared in that order.
const (
	causeA = NotExaminedUnreadable
	causeB = NotExaminedUnparseable
	causeC = NotExaminedNoText
	causeD = NotExaminedCutShort
)

func TestCapNotExaminedKeepsEveryCausePresent(t *testing.T) {
	type spec = struct {
		cause NotExaminedCause
		n     int
	}

	for _, tc := range []struct {
		name  string
		files []NotExaminedFile
	}{
		{
			// The reproduction, in the proportions that produced it.
			name:  "60 of one cause and 3 of another",
			files: mkFiles(spec{causeA, 60}, spec{causeB, 3}),
		},
		{
			// The pathological shape: one cause could swallow the whole budget many times over.
			name:  "5000 of one cause and 3 of another",
			files: mkFiles(spec{causeA, 5000}, spec{causeB, 3}),
		},
		{
			name:  "four causes, the first alone over the cap",
			files: mkFiles(spec{causeA, 200}, spec{causeB, 2}, spec{causeC, 1}, spec{causeD, 7}),
		},
		{
			// A cause that sorts LAST and has exactly one entry is the easiest thing to lose.
			name:  "a single entry in the last cause",
			files: mkFiles(spec{causeA, 100}, spec{causeD, 1}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := countByCause(tc.files)
			shown, total := CapNotExamined(tc.files)

			// Non-vacuity: the cap must actually bite, or this test is about the pass-through path.
			if len(tc.files) <= MaxNotExaminedEntries {
				t.Fatalf("fixture has %d entries, at or under the cap of %d — it does not exercise "+
					"the truncation this test is about", len(tc.files), MaxNotExaminedEntries)
			}
			if total != len(tc.files) {
				t.Errorf("total = %d, want %d — the summary depends on this being the FULL count",
					total, len(tc.files))
			}
			if len(shown) > MaxNotExaminedEntries {
				t.Errorf("returned %d entries, over the cap of %d. The cap is not cosmetic: an "+
					"unbounded list pushes a SARIF upload toward the size-rejection limit and loses "+
					"the whole report", len(shown), MaxNotExaminedEntries)
			}
			// The budget should be spent, not left on the table.
			if len(shown) != MaxNotExaminedEntries {
				t.Errorf("returned %d entries when %d were available and the cap is %d — slack in the "+
					"budget is enumeration a consumer could have had", len(shown), len(tc.files),
					MaxNotExaminedEntries)
			}

			got := countByCause(shown)
			for cause := range want {
				if got[cause] == 0 {
					t.Errorf("cause %v has %d entries in the input and NONE in the enumeration: a "+
						"whole class of miss disappeared while the total said only that something did",
						cause, want[cause])
				}
			}
		})
	}
}

// TestCapNotExaminedPreservesOrder pins that the result is a subsequence of the input.
//
// The caller sorts cause-then-path and two reports of one scan must stay byte-comparable, so a
// reordering here would be a nondeterminism-shaped defect even though the allocation is deterministic.
func TestCapNotExaminedPreservesOrder(t *testing.T) {
	type spec = struct {
		cause NotExaminedCause
		n     int
	}
	files := mkFiles(spec{causeA, 40}, spec{causeB, 40}, spec{causeC, 40})
	shown, _ := CapNotExamined(files)

	j := 0
	for _, f := range shown {
		for j < len(files) && files[j] != f {
			j++
		}
		if j == len(files) {
			t.Fatalf("the returned entries are not a subsequence of the input — the order the caller " +
				"established (cause, then path) was not preserved")
		}
		j++
	}
	if len(shown) == 0 {
		t.Fatal("nothing was returned, so the subsequence check above proves nothing")
	}
}

// TestCapNotExaminedPassesSmallListsThrough is the must-NOT-change half: under the cap, the output
// must be exactly the input, or every ordinary report's bytes move.
func TestCapNotExaminedPassesSmallListsThrough(t *testing.T) {
	type spec = struct {
		cause NotExaminedCause
		n     int
	}
	files := mkFiles(spec{causeA, 3}, spec{causeB, 2})
	shown, total := CapNotExamined(files)
	if total != 5 || len(shown) != 5 {
		t.Fatalf("shown=%d total=%d, want 5 and 5", len(shown), total)
	}
	for i := range files {
		if shown[i] != files[i] {
			t.Errorf("entry %d changed under the cap: got %+v want %+v", i, shown[i], files[i])
		}
	}
}

func TestAllocateCauseQuotas(t *testing.T) {
	for _, tc := range []struct {
		name   string
		causes []NotExaminedCause
		counts map[NotExaminedCause]int
		budget int
		want   map[NotExaminedCause]int
	}{
		{
			name:   "even split when both causes are plentiful",
			causes: []NotExaminedCause{causeA, causeB},
			counts: map[NotExaminedCause]int{causeA: 100, causeB: 100},
			budget: 50,
			want:   map[NotExaminedCause]int{causeA: 25, causeB: 25},
		},
		{
			// The reproduction: a small cause takes only what it has and the rest goes to the big one,
			// so the budget is fully spent AND the small cause is present.
			name:   "a small cause takes only what it has",
			causes: []NotExaminedCause{causeA, causeB},
			counts: map[NotExaminedCause]int{causeA: 60, causeB: 3},
			budget: 50,
			want:   map[NotExaminedCause]int{causeA: 47, causeB: 3},
		},
		{
			name:   "budget larger than the input",
			causes: []NotExaminedCause{causeA, causeB},
			counts: map[NotExaminedCause]int{causeA: 2, causeB: 1},
			budget: 50,
			want:   map[NotExaminedCause]int{causeA: 2, causeB: 1},
		},
		{
			// Defensive: only eight causes exist in the model, so this branch should never run live —
			// but zero for everything would be the alternative, and that is the bug being fixed.
			name:   "more causes than budget",
			causes: []NotExaminedCause{causeA, causeB, causeC, causeD},
			counts: map[NotExaminedCause]int{causeA: 9, causeB: 9, causeC: 9, causeD: 9},
			budget: 2,
			want:   map[NotExaminedCause]int{causeA: 1, causeB: 1},
		},
		{
			name:   "no causes",
			causes: nil,
			counts: map[NotExaminedCause]int{},
			budget: 50,
			want:   map[NotExaminedCause]int{},
		},
		{
			name:   "zero budget",
			causes: []NotExaminedCause{causeA},
			counts: map[NotExaminedCause]int{causeA: 5},
			budget: 0,
			want:   map[NotExaminedCause]int{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := allocateCauseQuotas(tc.causes, tc.counts, tc.budget)
			if len(got) != len(tc.want) {
				t.Fatalf("quota = %v, want %v", got, tc.want)
			}
			sum := 0
			for c, n := range got {
				if n != tc.want[c] {
					t.Errorf("quota[%v] = %d, want %d (full: %v)", c, n, tc.want[c], got)
				}
				if n > tc.counts[c] {
					t.Errorf("quota[%v] = %d but only %d entries exist — the caller would enumerate "+
						"fewer than promised and leave budget unspent", c, n, tc.counts[c])
				}
				sum += n
			}
			if sum > tc.budget {
				t.Errorf("quotas sum to %d, over the budget of %d", sum, tc.budget)
			}
		})
	}
}
