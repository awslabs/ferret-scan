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
// Two claims that used to sit here were wrong, and correcting them is why a growth bound is
// asserted at all rather than merely logged:
//
// (Which growth bound has since changed. The many-distinct-values guard now asserts cost against the
// MATCH COUNT at a fixed line length — the axis resolveByIndex documents independence from — because
// the original pair grew the count and the line together, leaving only a 4x window between correct
// and regressed that a Windows runner's constant factors exceeded twice. That pair's ratio is still
// logged; see TestAssignLineColumnsComplexityDistinctValues for both populations.)
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

// buildDistinctSubsetOnFixedLine builds a line holding lineValues distinct values and returns
// matchCount of them, spread evenly across the line rather than taken from its head.
//
// This is the fixture that isolates the ONE axis resolveByIndex claims independence from. Its doc
// comment states the property outright — "The cost is therefore independent of how MANY values there
// are, which is the term that made rescanning quadratic" — so holding the line fixed and varying only
// the match count measures exactly that claim, and nothing else.
//
// buildDistinctOnOneLine, by contrast, grows the value count AND the line length together, so the
// correct cost grows 4x for 4x input and the regression shows 16x. A 4x-wide window is not enough on
// a shared runner: see the measurements on TestAssignLineColumnsComplexityDistinctValues.
//
// Spread rather than head-first because resolveByRescan carries a per-value cursor that starts at
// zero, so a head-first subset would sit in the cheapest part of the line and understate the
// regression. Every match must also still be PRESENT on the line, or timeAssign's non-vacuity floor
// fails and the timing means nothing.
func buildDistinctSubsetOnFixedLine(lineValues, matchCount int) []Match {
	var sb strings.Builder
	sb.Grow(lineValues * 20)
	vals := make([]string, 0, lineValues)
	for i := 0; i < lineValues; i++ {
		v := fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000)
		vals = append(vals, v)
		sb.WriteString("SSN ")
		sb.WriteString(v)
		sb.WriteString(" ")
	}
	line := sb.String()

	stride := lineValues / matchCount
	if stride < 1 {
		stride = 1
	}
	out := make([]Match, 0, matchCount)
	for i := 0; i < lineValues && len(out) < matchCount; i += stride {
		out = append(out, Match{
			Text:       vals[i],
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

	// The growth ratio of THIS pair is logged and no longer asserted. Asserting it was tried twice
	// and failed twice on CI against correct code:
	//
	//	         base       big     ratio
	//	audit host, 6 runs      2.2-2.5ms   9.3-10.4ms   3.7-4.6x
	//	GOMAXPROCS=1, 4 runs    2.3-2.9ms  10.0-12.1ms   4.0-4.3x
	//	windows-latest CI       40.67ms      ~362ms          8.9x   <- failed an 8.0 limit
	//	windows-latest CI       12.05ms     116.64ms         9.7x   <- failed it again
	//	regressed (measured)   141.1ms      2.184s          15.5x
	//
	// The first failure was answered by growing the sample from 2000/8000 to 8000/32000, on the
	// theory that the base was too small to measure. That did stabilise the LOCAL spread to
	// 3.76x-4.28x — and the guard then failed again at 9.7x, so the theory was wrong. Windows is not
	// noisy around 4x here; it sits systematically at 9-10x, because the big case degrades
	// disproportionately there (base 4.8x slower than this host, big 12x slower). A threshold BELOW
	// its own correct population cannot be rescued by better sampling.
	//
	// The structural reason this ratio is a poor instrument: buildDistinctOnOneLine grows the value
	// count AND the line length together, so correct is 4x and the regression is 16x. A 4x-wide
	// window has to absorb every machine's constant-factor differences, and Windows' exceeds it.
	//
	// And the mechanism behind that, which also explains why the resize made things WORSE rather than
	// better: the base term walks a 128KB line and the big term a 512KB one, so the two terms have
	// DIFFERENT cache and TLB footprints. A machine with a smaller cache inflates the ratio itself,
	// because only the big term falls out of cache. Growing the fixture 4x doubled that footprint
	// asymmetry, which is why a change intended to stabilise the measurement moved the Windows
	// reading from 8.9x to 9.7x. No sampling statistic can remove a systematic offset of that kind.
	//
	// The assertion that replaces it is below, and it does not have that problem: both of its terms
	// measure the SAME string, so the footprint is identical and a uniformly slower machine cancels.
	if tBase > 0 {
		t.Logf("(growth of this pair is informational: measured 3.7x-4.6x correct here, 8.9x and "+
			"9.7x on windows-latest, 15.5x regressed — see the comment above for why it is not "+
			"asserted; ratio this run %.1fx)", ratio)
	}

	// The REAL discriminator: cost must be independent of the match COUNT at a fixed line length.
	//
	// That is resolveByIndex's own documented claim — "The cost is therefore independent of how MANY
	// values there are, which is the term that made rescanning quadratic" — so it is the property
	// worth pinning, and measuring it directly puts the correct population at ~1.0x where a
	// uniformly slower machine cancels out instead of shifting the answer.
	//
	// Measured on the audit host by forcing useIndex to return false, which restores the per-value
	// rescan (the exact O(K x line length) shape #388 removed):
	//
	//	                                base        big       ratio
	//	correct, 5 runs                9.4-10.2ms  11.0-12.3ms  1.08-1.26x
	//	correct, GOMAXPROCS=1, 3 runs  8.8-9.8ms   11.2-12.6ms  1.18-1.32x
	//	regressed, 2 runs              405-423ms   1.63-1.66s   3.92-4.03x
	//
	// So 2.2 sits 1.67x above the worst correct reading and 1.78x below the best regressed one —
	// balanced, and both margins wider than anything a retuned version of the old ratio could buy
	// (12.5 between 9.7x and 15.5x gives only 1.29x and 1.24x).
	//
	// The absolute figures separate by 41x at the SAME match count (10ms against 415ms), which is
	// the sanity check that this pair really is measuring the regression and not sampling noise.
	const lineValues = 96000
	const subsetBase, subsetBig = 2000, 8000 // 4x the matches, identical line

	fBase := bestAssign(t, func() []Match { return buildDistinctSubsetOnFixedLine(lineValues, subsetBase) }, true)
	fBig := bestAssign(t, func() []Match { return buildDistinctSubsetOnFixedLine(lineValues, subsetBig) }, true)

	fRatio := float64(fBig) / float64(fBase)
	t.Logf("fixed %d-value line, matches %d -> %d (4x): %.2fx (base=%v big=%v) — independent of the "+
		"match count is ~1.0x; the per-value rescan measures ~4.0x", lineValues, subsetBase, subsetBig,
		fRatio, fBase, fBig)

	const maxCountGrowth = 2.2
	if fBase > 0 && fRatio > maxCountGrowth {
		t.Errorf("4x the MATCHES on an unchanged line cost %.2fx (base=%v big=%v), over %.1fx: "+
			"resolveByIndex's cost is supposed to be independent of how many values there are, so "+
			"this says each value is scanning the line again — O(K x line length), which measured "+
			"8.14s of a 9.64s scan on a 1.14MB line before #388",
			fRatio, fBase, fBig, maxCountGrowth)
	}

	// A second live assertion on the same fixture, deliberately NOT tuned close to the observation.
	//
	// The regressed big term is 1.63-1.66s against a correct 11.0-12.6ms — a 130x absolute gap — so an
	// absolute bound is unusually informative here, and unlike the ratio it survives the ratio itself
	// being defeated by some future constant-factor surprise. Two independent live assertions is the
	// point; the old shape had one live and one decorative.
	//
	// 1s, not the 100ms that the measured gap would justify. 100ms buys 7.9x below and 16.3x above on
	// THIS host, which looks better on paper — and is exactly the mistake this whole test is a
	// correction of. Windows ran the old big term 12x slower than this host; 12 x 12.6ms is 151ms, so
	// a 100ms ceiling would fail there on correct code. 1s tolerates a runner 79x slower than this one
	// while still sitting 1.63x under the regression, which is the trade an absolute bound on a shared
	// runner has to make.
	const bigAbsoluteCeiling = 1 * time.Second
	if fBig > bigAbsoluteCeiling {
		t.Errorf("resolving %d matches on a fixed %d-value line took %v (> %v) — %v on the audit "+
			"host, and the per-value rescan measured 1.63-1.66s, so this is a complexity change and "+
			"not a slow machine", subsetBig, lineValues, fBig, bigAbsoluteCeiling, "11.0-12.6ms")
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
