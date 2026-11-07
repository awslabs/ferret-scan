// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The re-anchoring search is quadratic per basename and type, so it is bounded twice: the number of
// comparisons by MaxReanchorComparisons, and the cost of one comparison by hashing the part of the
// composite before the line number once per finding. These guards pin both, on counts and allocations
// where they can, since a timing ratio flakes on a loaded host.

// shiftedRows is a file of n distinct SSN rows with a rule for each, and the same rows one line lower:
// n rules to relocate, n candidates for each, n*n comparisons.
func shiftedRows(t *testing.T, n int) (*SuppressionManager, []detector.Match) {
	t.Helper()
	var was, now []detector.Match
	for i := 1; i <= n; i++ {
		line := fmt.Sprintf("row %d ssn 123-45-6780", i)
		was = append(was, ssnAt("rows.txt", line, i))
		now = append(now, ssnAt("rows.txt", line, i+1))
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := NewSuppressionManager(path).GenerateSuppressionRules(was, "generated", true); err != nil {
		t.Fatal(err)
	}
	sm, _ := loadWithWarnings(t, path)
	return sm, now
}

// TestTheSearchStaysWithinItsLimit: a group that does not fit costs no comparison at all, and one that
// fits costs exactly its findings times its keys. Without the limit the 300-row group makes 90,000
// comparisons; with it, none.
func TestTheSearchStaysWithinItsLimit(t *testing.T) {
	sm, now := shiftedRows(t, 300)
	sm.reanchorLimit = 300*300 - 1
	identities, ruled, identified := sm.batchState(now)
	plan := sm.planReanchor(now, identities, ruled, identified)
	if plan.comparisons > sm.reanchorLimit || len(plan.notEvaluated) != 300 || len(plan.accepted) != 0 {
		t.Errorf("limit %d: %d comparisons, %d not evaluated, %d moved", sm.reanchorLimit, plan.comparisons,
			len(plan.notEvaluated), len(plan.accepted))
	}

	sm.reanchorLimit = 300 * 300
	plan = sm.planReanchor(now, identities, ruled, identified)
	if plan.comparisons != 300*300 || len(plan.accepted) != 300 {
		t.Errorf("limit %d: %d comparisons, %d moved, want 90000 and 300", sm.reanchorLimit, plan.comparisons, len(plan.accepted))
	}
	if MaxReanchorComparisons < 300*300 {
		t.Errorf("the published limit %d does not cover a 300-row file", MaxReanchorComparisons)
	}
}

// TestAComparisonAllocatesNothing: each comparison restores the saved state into one reused hash.
// Measured 0 allocations; hashing the whole composite instead allocates 1 per comparison (and costs the
// line's length), which is what this catches.
func TestAComparisonAllocatesNothing(t *testing.T) {
	form := (&SuppressionManager{}).newLineOpenForm(onLongLine(64<<10), hashVersionCurrent)
	if form.state == nil {
		t.Skip("this build cannot save a SHA-256 state; comparisons take the slow path")
	}
	hasher := newAnchorHasher()
	line := 0
	if got := testing.AllocsPerRun(1000, func() { line++; hasher.at(&form, line) }); got != 0 {
		t.Errorf("a comparison allocates %.1f times", got)
	}
}

// TestAComparisonCostsTheSameOnALongLine: a comparison costs the same for a finding on an 8 KiB line
// (the most of the line the identity hashes) as for one on a short line. Each reading is the minimum of
// 2,000 calls. Measured 0.9-1.1x; 36-61x with the saved state dropped, so every comparison hashes the
// whole composite. The threshold is 4x.
func TestAComparisonCostsTheSameOnALongLine(t *testing.T) {
	sm := &SuppressionManager{}
	long := sm.newLineOpenForm(onLongLine(64<<10), hashVersionCurrent)
	short := sm.newLineOpenForm(onLine("ssn 123-45-6780", "123-45-6780", "SSN", 1), hashVersionCurrent)
	if len(long.head) < maxHashLineLen || len(short.head) > 64 {
		t.Fatalf("fixture error: heads of %d and %d bytes", len(long.head), len(short.head))
	}
	hasher := newAnchorHasher()
	fastest := func(f *lineOpenForm) time.Duration {
		best := time.Duration(math.MaxInt64)
		for i := 0; i < 2000; i++ {
			start := time.Now()
			hasher.at(f, 1000+i)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	fastest(&short) // warm up
	ratio := float64(fastest(&long)) / float64(max(fastest(&short), time.Nanosecond))
	t.Logf("one comparison, 8 KiB line / short line: %.2fx", ratio)
	if ratio > 4 {
		t.Errorf("a comparison costs %.1fx more on a long line: it hashes the line once per comparison", ratio)
	}
}

// BenchmarkReanchorComparison is what MaxReanchorComparisons is measured against: one finding compared
// with one key, every candidate form included.
func BenchmarkReanchorComparison(b *testing.B) {
	sm := &SuppressionManager{}
	for _, c := range []struct {
		name string
		m    detector.Match
	}{
		{"plain", onLine("social security number: 123-45-6780", "123-45-6780", "SSN", 4)},
		{"every form", identityFixtures["indented CRLF line, trailing space"]},
		{"8 KiB line", onLongLine(64 << 10)},
	} {
		b.Run(c.name, func(b *testing.B) {
			open := sm.openIdentity(c.m)
			hasher := newAnchorHasher()
			sink := 0
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				open.digestsAt(hasher, anchorKey{line: i, conf: "90.00"}, true, func(d [32]byte) { sink += int(d[0]) })
			}
			_ = sink
		})
	}
}

// BenchmarkReanchorWorstCase is a group at the published limit: rows*rows comparisons.
func BenchmarkReanchorWorstCase(b *testing.B) {
	t := &testing.T{}
	rows := int(math.Sqrt(float64(MaxReanchorComparisons)))
	sm, now := shiftedRows(t, rows)
	identities, ruled, identified := sm.batchState(now)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan := sm.planReanchor(now, identities, ruled, identified)
		if len(plan.accepted) != rows {
			b.Fatalf("%d moved, want %d", len(plan.accepted), rows)
		}
	}
}
