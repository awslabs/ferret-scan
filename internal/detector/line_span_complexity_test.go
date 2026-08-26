// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// AssignLineColumns runs on EVERY scan, so its growth is a scan-path concern.
//
// The occurrence cursor it inherits from the redaction overlap pass used to run only
// when redacting. Wiring it into parallel.RunValidators put it on the path of every
// scan, including read-only ones, which changes who pays for it: a dense
// single-line document is now this function's worst case on every run.
//
// Writing these tests found a quadratic that was NOT the one expected, which is the
// reason they exist in isolation rather than end-to-end.
//
// The assumption going in was that the cursor made the repeated-value case linear and
// that only distinct values were superlinear. Measured, it was the opposite way round:
// ONE repeated value cost 18.5x for 4x input (19.5ms at K=8000), worse than distinct
// values at 14.2x. The cursor was never the cost. The line-id map key contains the
// whole line TEXT, so every lookup hashed the line — O(line length) per match, i.e.
// O(matches x line length) — and the interning it documents removes quadratic string
// COMPARISON from the containment loop while leaving that hashing in place.
//
// A one-entry memo for the preceding line fixed it: matches from a line arrive
// together and share the identical FullLine string, so the common case became a length
// check and a pointer compare. K=8000 went 19.5ms -> 0.69ms, a 28x improvement, and
// growth 18.5x -> 8.1x at times small enough that noise dominates.
//
// Both shapes are now linear:
//
//   - MANY OCCURRENCES OF ONE VALUE. The cursor advances past each occurrence and the
//     memo removes the per-match hash.
//   - MANY DISTINCT VALUES. This was O(K x line length) — each value owned a cursor
//     starting at zero, so every strings.Index scanned from the line start to that value.
//     ResolveLineSpans now indexes a dense line in ONE pass instead, keyed on value
//     LENGTH rather than on value, so the cost no longer carries a factor of K (#388).
//
// Two claims that used to sit here were wrong, and correcting them is why the ratio below
// is now ASSERTED rather than logged:
//
//   - "Making it linear needs a multi-pattern single pass over the line, not a tweak, and
//     per-validator execution budgets already bound pathological single-line input." The
//     first half was right and is what was done. The second half was not: nothing bounded
//     it.
//   - "None of this is visible end-to-end, because validator cost dominates a real scan:
//     through the CLI on a dense single-line file the whole change measured +1.7% to
//     +8.9%." Measured directly at 64,000 distinct values on a 1.14 MB line,
//     ResolveLineSpans was 8.14s of a 9.64s scan — 84% of it, not a rounding error. The
//     +1.7% to +8.9% figure came from a fixture that did not reach this shape. A shape
//     measured only in isolation can look harmless there and dominate in production;
//     measure BOTH.
//
// After the change the same 64,000-value line resolves in 53ms, and every input size
// measured is faster than before — 1.14x at 1,000 values through 6.3x at 32,000 end to
// end, with no size slower.

// columnsAbsoluteCeiling bounds the largest sample.
//
// Sized from measurement with real headroom: the biggest fixture here costs single-digit
// milliseconds locally, so this catches an order-of-magnitude regression while
// tolerating a heavily loaded shared runner. It is not a micro-benchmark.
const columnsAbsoluteCeiling = 4 * time.Second

// buildDistinctOnOneLine returns k matches for k DISTINCT values that all sit on one
// line, which is the worst case for a per-value cursor.
func buildDistinctOnOneLine(k int) []Match {
	var sb strings.Builder
	sb.Grow(k * 20)
	vals := make([]string, 0, k)
	for i := 0; i < k; i++ {
		v := fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000)
		vals = append(vals, v)
		sb.WriteString("SSN ")
		sb.WriteString(v)
		sb.WriteString(" ")
	}
	line := sb.String()

	out := make([]Match, 0, k)
	for _, v := range vals {
		out = append(out, Match{
			Text:       v,
			Type:       "SSN",
			LineNumber: 1,
			Context:    ContextInfo{FullLine: line},
		})
	}
	return out
}

// buildRepeatedOnOneLine returns k matches for the SAME value repeated k times on one
// line — the case the cursor is designed for, which must stay linear.
func buildRepeatedOnOneLine(k int) []Match {
	const v = "449-87-4100"
	line := strings.Repeat("SSN "+v+" ", k)
	out := make([]Match, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, Match{
			Text:       v,
			Type:       "SSN",
			LineNumber: 1,
			Context:    ContextInfo{FullLine: line},
		})
	}
	return out
}

// timeAssign runs AssignLineColumns and asserts the assignment actually happened.
//
// The floor is the non-vacuity signal: a function that stopped assigning columns would
// be fast and would leave every consumer back on a first-occurrence search, which is
// the defect this machinery exists to remove. Distinctness is checked too, because
// assigning every match the SAME column is also fast and also wrong.
func timeAssign(t *testing.T, matches []Match, wantDistinct bool) time.Duration {
	t.Helper()

	start := time.Now()
	AssignLineColumns(matches)
	elapsed := time.Since(start)

	seen := make(map[int]struct{}, len(matches))
	for i := range matches {
		if matches[i].StartColumn <= 0 {
			t.Fatalf("match %d of %d has no column — a timing target must never accept an "+
				"assignment that silently stopped happening", i, len(matches))
		}
		if matches[i].EndColumn <= matches[i].StartColumn {
			t.Fatalf("match %d has columns %d-%d", i, matches[i].StartColumn, matches[i].EndColumn)
		}
		if wantDistinct {
			if _, dup := seen[matches[i].StartColumn]; dup {
				t.Fatalf("column %d assigned twice — collapsing every match onto one column "+
					"is fast and is the exact bug this replaces", matches[i].StartColumn)
			}
			seen[matches[i].StartColumn] = struct{}{}
		}
	}
	return elapsed
}

// bestAssign times AssignLineColumns over freshly built fixtures and returns the FASTEST run.
//
// Best-of-N, not a single sample, because this is a shared CI runner and the failure mode of a
// ratio assertion is a spike in either term. A spike inflates a duration; it never deflates one, so
// the minimum is the closest thing to the machine's actual cost and is the only summary statistic
// that a scheduler hiccup cannot move in the direction that fails the build.
//
// Fixtures are rebuilt per attempt because timeAssign MUTATES its matches — it assigns the columns
// it then asserts on — so reusing one slice would time an already-assigned run. mk is a thunk
// rather than a (size, builder) pair so that every timing target here can use it whatever its
// builder's arity: the first version of this helper took func(int) and so could only be applied to
// one of the four tests, which left the other three on a single sample.
//
// That gap was not theoretical. TestAssignLineColumnsComplexityDistinctAndRepeated failed on a
// macOS CI runner at base=40.67ms big=306.40ms against a 250ms ceiling, while the same commit
// locally measured base=4.2-6.0ms big=18.8-23.5ms. The base being ~7x its local value says the
// machine was loaded; the big term being ~13x says the load landed inside the big run. A spike in
// one sample is precisely what best-of-N removes, and it is why all four targets now use it.
func bestAssign(t *testing.T, mk func() []Match, wantDistinct bool) time.Duration {
	t.Helper()
	const attempts = 3
	var best time.Duration
	for i := 0; i < attempts; i++ {
		d := timeAssign(t, mk(), wantDistinct)
		if best == 0 || d < best {
			best = d
		}
	}
	return best
}

// TestAssignLineColumnsComplexityRepeatedValue: the cursor's own case must be linear.
func TestAssignLineColumnsComplexityRepeatedValue(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	const baseK, bigK = 2000, 8000 // 4x

	tBase := bestAssign(t, func() []Match { return buildRepeatedOnOneLine(baseK) }, true)
	tBig := bestAssign(t, func() []Match { return buildRepeatedOnOneLine(bigK) }, true)

	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x input, ONE repeated value: %.1fx (base=%v big=%v) — the cursor advances past "+
		"each occurrence and the line-id memo removes the per-match line hash, so this "+
		"walks the line once. Was 18.5x before the memo.", ratio, tBase, tBig)

	if tBig > columnsAbsoluteCeiling {
		t.Errorf("assigning columns for %d repeated occurrences took %v (> %v) — the cursor "+
			"is no longer advancing, or the per-match line hash is back",
			bigK, tBig, columnsAbsoluteCeiling)
	}
}

// TestAssignLineColumnsComplexityDistinctValues is the ratchet on the known shape.
func TestAssignLineColumnsComplexityDistinctValues(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	// 8000/32000, not 2000/8000. The smaller pair put the BASE at half a millisecond, where
	// scheduler noise is a large fraction of the measurement: across ten local runs on an idle
	// machine the ratio ranged 3.6x to 6.9x, a 2.3x spread against an 8x threshold, and a loaded
	// Windows CI runner produced 8.9x and failed the build on main itself.
	//
	// At this size the base is ~2ms and the same ten runs span 3.76x to 4.28x — a 0.5x spread. The
	// signal did not change; the sample became large enough to see it. Measured, not guessed.
	const baseK, bigK = 8000, 32000 // 4x

	tBase := bestAssign(t, func() []Match { return buildDistinctOnOneLine(baseK) }, true)
	tBig := bestAssign(t, func() []Match { return buildDistinctOnOneLine(bigK) }, true)

	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x input, K DISTINCT values on one line: %.1fx (base=%v big=%v) — linear is 4x. "+
		"Was 16.2x when each value owned a cursor starting at zero.", ratio, tBase, tBig)

	if tBig > columnsAbsoluteCeiling {
		t.Errorf("assigning columns for %d distinct values on one line took %v (> %v) — a "+
			"regression of this size means the per-value scan got worse than a single pass "+
			"over the line", bigK, tBig, columnsAbsoluteCeiling)
	}

	// ASSERTED now, where it used to be logged only.
	//
	// The ceiling above cannot catch this shape returning: at K=8000 the old quadratic cost
	// 148ms, which is comfortably inside a 4s ceiling, so it passed for as long as the
	// quadratic existed. A growth bound is what actually pins the shape.
	//
	// 8x rather than 4x because both the value COUNT and the line LENGTH grow with K here. A return
	// to O(K x line) would show 16x, so with the measurement now stable at ~4.2x this sits roughly
	// midway between the real cost and the regression it guards against — headroom on both sides
	// rather than the 8.0-against-a-3.6-to-6.9-spread it had before.
	const maxGrowth = 8.0
	if tBase > 0 && ratio > maxGrowth {
		t.Errorf("4x input cost %.1fx (base=%v big=%v), over %.0fx: the per-value line rescan is "+
			"back. Each distinct value scanning from the line start is O(K x line length), which "+
			"measured 8.14s of a 9.64s scan on a 1.14MB line before #388",
			ratio, tBase, tBig, maxGrowth)
	}
}

// A file of MANY LINES must be linear in the number of lines: interning keys each line
// separately, so no cross-line work should accumulate. This is the ordinary-document
// shape, as opposed to the pathological single line above.
func TestAssignLineColumnsComplexityManyLines(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	build := func(lines int) []Match {
		out := make([]Match, 0, lines)
		for i := 0; i < lines; i++ {
			v := fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000)
			line := fmt.Sprintf("row %d SSN %s end", i, v)
			out = append(out, Match{
				Text: v, Type: "SSN", LineNumber: i + 1,
				Context: ContextInfo{FullLine: line},
			})
		}
		return out
	}

	const baseN, bigN = 5000, 20000 // 4x

	tBase := bestAssign(t, func() []Match { return build(baseN) }, false)
	tBig := bestAssign(t, func() []Match { return build(bigN) }, false)

	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x input, one match per line across many lines: %.1fx (base=%v big=%v)",
		ratio, tBase, tBig)

	if tBig > columnsAbsoluteCeiling {
		t.Errorf("assigning columns across %d lines took %v (> %v) — the ordinary document "+
			"shape must stay linear in the number of lines", bigN, tBig, columnsAbsoluteCeiling)
	}
}

// The INDEX path must stay linear when values are also REPEATED, which needs its own guard.
//
// The two existing shapes miss it: many-distinct-values uses the index but never repeats a value, and
// one-repeated-value stays on the rescan path (correctly — the cursor already makes that linear, so
// indexing would only add allocations). The shape that exercises both at once is a log with thousands
// of DISTINCT values each appearing many times, which is ordinary machine-generated input.
//
// It guards a specific mechanism: resolveByIndex keeps a per-value pointer into that value's
// occurrence list so hand-out is amortised O(1). Removing that pointer's advance leaves correctness
// untouched — the end-offset check still skips consumed occurrences — while making each match rescan
// the occurrence list from the start, i.e. quadratic in the repeat count. Mutation-verified: deleting
// the advance passes every other test in this package.
func TestAssignLineColumnsComplexityDistinctAndRepeated(t *testing.T) {
	if testing.Short() {
		t.Skip("column-assignment complexity guard skipped in -short mode")
	}

	build := func(distinct, repeats int) []Match {
		var sb strings.Builder
		vals := make([]string, 0, distinct)
		for i := 0; i < distinct; i++ {
			vals = append(vals, fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000))
		}
		for r := 0; r < repeats; r++ {
			for _, v := range vals {
				sb.WriteString("SSN ")
				sb.WriteString(v)
				sb.WriteString(" ")
			}
		}
		line := sb.String()

		out := make([]Match, 0, distinct*repeats)
		for r := 0; r < repeats; r++ {
			for _, v := range vals {
				out = append(out, Match{
					Text: v, Type: "SSN", LineNumber: 1,
					Context: ContextInfo{FullLine: line},
				})
			}
		}
		return out
	}

	// Hold the distinct count fixed and grow the REPEAT count, so what scales is exactly the
	// occurrence-list walking this pins. The repeat count has to be LARGE for that walk to be
	// measurable: without the pointer the r-th match of a value walks r entries, so the cost is
	// O(repeats^2) per value and only separates from linear once repeats is in the hundreds. A
	// first attempt used 4 and 16 repeats, where the difference is a few hundred thousand steps
	// and the mutation survived.
	const distinct = 40

	tBase := bestAssign(t, func() []Match { return build(distinct, 500) }, false)
	tBig := bestAssign(t, func() []Match { return build(distinct, 2000) }, false) // 4x the repeats

	ratio := float64(tBig) / float64(tBase)
	t.Logf("4x the repeats of %d distinct values on one line: %.1fx (base=%v big=%v) — linear is 4x",
		distinct, ratio, tBase, tBig)

	// The scale-free GROWTH RATIO is the discriminator here, and the absolute time is only a
	// catastrophe net. An earlier version of this comment argued the opposite — that the absolute
	// figure was "the far cleaner signal" and the ratio was "exactly where scheduler noise lives"
	// — and set the ceiling at 250ms, ~10x above what this host measured. A windows-latest runner
	// then failed it at 307ms while the ratio read 5.7x, correctly reporting the code as linear.
	// The ceiling was not measuring the algorithm, it was measuring the runner.
	//
	// That is the general problem with an absolute wall-clock bound on shared CI: it cannot be
	// both slow-machine-safe and fast-machine-sensitive. A regression costs ~423ms on this host,
	// so a ceiling loose enough for a 12x-slower runner (>3.7s) would no longer catch it there.
	// The ratio has no such conflict, because both halves of it are measured on the same machine
	// in the same run.
	//
	// Re-derived at HEAD by replacing `p := next[text]` with `p := 0` in resolveByIndex, which is
	// exactly the regression described below:
	//
	//	                       base       big     ratio
	//	with the pointer      ~4.0ms   ~19.0ms   4.6-4.9x   (3 runs, this host)
	//	                     ~3.9ms   ~21.0ms   5.2-5.9x   (3 runs, GOMAXPROCS=1, a loaded runner)
	//	                     54.1ms    307.2ms       5.7x   (windows-latest CI, the false failure)
	//	without it            29.3ms    423.0ms  13.6-14.4x
	//
	// 9x rather than 8x because it splits the two populations evenly: 9.0/5.9 = 1.53x headroom
	// above the worst correct reading, 13.6/9.0 = 1.51x below the best regressed one. At 8x the
	// headroom above 5.9x was only 1.36x, and 5.9x came from the constrained-CPU run — the case
	// most like the runner that flaked.
	//
	// bestAssign takes the best of three attempts for each half, which is what keeps the
	// numerator and denominator comparable.
	const maxGrowth = 9.0
	if tBase > 0 && ratio > maxGrowth {
		t.Errorf("4x the repeats cost %.1fx (base=%v big=%v), over %.0fx: hand-out is walking "+
			"each value's occurrence list from the start instead of carrying a pointer into it, "+
			"which is O(repeats^2) per value", ratio, tBase, tBig, maxGrowth)
	}

	// Catastrophe net, in line with columnsAbsoluteCeiling and with every other complexity guard
	// in this repo (all 2-20s). This is deliberately NOT tuned close to the observed cost: at
	// 250ms it was the only sub-second wall-clock ceiling in the tree, and it was the one that
	// flaked. Its job is to fail loudly if the cost becomes absurd on any machine, not to
	// discriminate linear from quadratic — the ratio above does that.
	if tBig > columnsAbsoluteCeiling {
		t.Errorf("resolving %d repeats of %d distinct values took %v (> %v) — far beyond any "+
			"plausible runner, so this is a complexity change and not a slow machine",
			2000, distinct, tBig, columnsAbsoluteCeiling)
	}
}
