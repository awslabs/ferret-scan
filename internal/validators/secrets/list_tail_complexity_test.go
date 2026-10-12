// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// The list-tail walk must cost O(line length), however many heads share the line (#754).
//
// The first version of findListTailSecrets split the whole rest of the line once per head, so K
// heads on one line cost O(K^2). Measured through the CLI on one line of K `;`-separated
// `token=<16 random alphanumerics>` assignments, median of three interleaved samples:
//
//	K = 2,000    0.80s     (0.24s after this fix)
//	K = 4,000    2.62s     (0.61s)
//	K = 8,000   11.13s     (0.86s)    <- 4x the input, 13.9x the time
//
// TestValidatorComplexityIsSubQuadratic in internal/goldencorpus could not see it. Its secrets input
// separates assignments with SPACES, so no head is ever followed by a separator and the tail path
// never runs. These targets are the shape it misses: every head is followed by one.
//
// Two targets, because the walk has two properties and each one needs its own shape to be seen:
//
//   - separated lists: `token=<v1>,<w1>;token=<v2>,<w2>;...`. Each list has one member and the next
//     `token=` opens a new pair, so every walk is one element long. The regression it catches is the
//     eager split of everything after each head, i.e. the v2.5.3 splitter coming back.
//   - heads nested in members: `token=<v1>,-token=<v2>,-token=<v3>,...`. `-token=<v>` fits the value
//     class and is not a pair (a key starts with a letter or `_`), so it is a list MEMBER -- and the
//     singular pattern, which is not anchored at a word boundary, also finds a head inside it. Every
//     head's tail therefore runs to the end of the line, and only the shared `walked` set keeps the
//     total linear: without it this is O(K^2) even though the walk is lazy. The first target cannot
//     see that regression, because its walks are one element long either way.
//
// Timed at findListTailSecrets itself. Through ValidateContent or findKeywordSecrets the scoring and
// the ~100 other patterns are a linear term that only dilutes the one being guarded: at 1,000 heads
// the regressed ratio read 9.75x-10.78x there, a 1.2x-1.35x margin over this bound. A ratio needs
// the guarded term to dominate the base reading.
//
// Measured on darwin/arm64, CPU clock, 4x input, minimum of perfguard.DefaultPairs; correct code 8
// runs plain and 4 under -race, each mutation 4 runs plain and 2 under -race:
//
//	                                   correct        no `walked` set     v2.5.3 splitter
//	separated lists          plain     3.92x-4.32x    3.74x-4.14x (*)     15.18x-15.33x
//	                         -race     3.91x-4.16x    3.96x-3.99x (*)     13.81x-13.99x
//	heads nested in members  plain     3.80x-4.71x    13.34x-13.98x       13.30x-14.49x
//	                         -race     3.88x-4.05x    11.51x-11.53x       11.72x-11.83x
//
//	(*) linear, as designed: this mutation is the nested target's to catch.
//
// 8.0 is the same bound maxGrowthRatio uses: 1.70x above the worst correct reading and 1.66x below
// the best regressed one plain. Under -race the regressed side compresses to 1.44x, as #509 measured
// for the goldencorpus guard. Both regressions are ALSO caught without any timing, by the exact
// candidate count asserted after the ratio: at 500 heads the splitter emitted 250,000 (separated) and
// 124,750 (nested) candidates where a correct walk emits 500 and 499, one per member.
//
// It runs under -race too, as the detector and SVG perfguard guards do, rather than skipping as the
// goldencorpus guard does: correct code costs ~4s and ~240MB RSS there (~0.6s and ~130MB plain).
// The goldencorpus skip exists for a 6.9-8.1GB working set; a REGRESSED walk reaches ~3.1GB under
// -race here (0.9GB plain), from those duplicate candidates, which is the failure this exists to
// report.
const listTailMaxGrowthRatio = 8.0

// listTailBaseHeads is the head count of the base input; the big input has 4x as many.
//
// Large enough that the base reading clears perfguard's resolution gate: ~4.5ms for the nested
// target and ~8ms for the separated one on darwin/arm64, many ticks of its microsecond CPU clock.
// Windows' 15.625ms CPU tick is not cleared, and the tick gate declines the ratio there -- the same
// platform gap every perfguard guard in the repo has (#619), logged rather than asserted.
//
// Small enough that a regression stays affordable: the regressed walk's working set grows as K^2.
const listTailBaseHeads = 500

// listTailMinBaseLineBytes keeps the BASE line above the length at which Go's regexp stops using its
// backtracker for these patterns. regexp switches from the bit-state backtracker to the NFA once the
// input reaches 256Kbit / len(prog.Inst), which for the 26 unquoted patterns is 7,084 bytes
// (secret_?access_?key, 37 instructions) to 12,483 (pwd, 21). A base line under that runs on a
// different engine from the 4x line, and the ratio then measures the engine switch: values of 8
// bytes put the nested base line at 8,000 bytes and read 5.45x-5.60x on CORRECT code.
const listTailMinBaseLineBytes = 12_500

// listTailValues returns k distinct mixed-case alphanumeric values, generated at run time so no
// credential-shaped literal sits in the source. Distinct, because a repeated value can let a cache
// or a dedup step flatten a quadratic into something that measures linear.
func listTailValues(k int) []string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rng := rand.New(rand.NewSource(754)) // deterministic: the fixture must not vary between runs
	out := make([]string, k)
	b := make([]byte, 15)
	for i := range out {
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		// A fixed upper-case letter, lower-case letter and digit make every value clear
		// plausibleUnquotedSecret and never match shoutySentinel, so the counts asserted below are
		// exact rather than "k minus however many draws came out all-lower or all-upper".
		out[i] = "Qx7" + string(b)
	}
	return out
}

// buildSeparatedLists is one line of k two-element lists, each opened by its own head:
// `token=<v1>,<w1>;token=<v2>,<w2>;...`. `,` inside a list and `;` between lists, so both
// separators are on the timed path.
//
// Each list has exactly one member, and the next `token=` opens a new pair and ends it, so a correct
// walk emits k candidates in O(line length). The v2.5.3 splitter split everything after each head.
func buildSeparatedLists(k int) string {
	vals := listTailValues(2 * k)
	var sb strings.Builder
	sb.Grow(k * 46)
	for i := 0; i < k; i++ {
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString("token=")
		sb.WriteString(vals[2*i])
		sb.WriteByte(',')
		sb.WriteString(vals[2*i+1])
	}
	sb.WriteByte('\n')
	return sb.String()
}

// buildNestedHeads is one line where every list member after the first also contains a head:
// `token=<v1>,-token=<v2>,-token=<v3>,...`.
func buildNestedHeads(k int) string {
	var sb strings.Builder
	sb.Grow(k * 27)
	for i, v := range listTailValues(k) {
		if i > 0 {
			sb.WriteString(",-")
		}
		sb.WriteString("token=")
		sb.WriteString(v)
	}
	sb.WriteByte('\n')
	return sb.String()
}

func TestListTailIsLinearInLineLength(t *testing.T) {
	if testing.Short() {
		t.Skip("list-tail complexity guard skipped in -short mode")
	}

	targets := []struct {
		name  string
		build func(k int) string
		// wantMatches is the exact candidate count for k heads.
		wantMatches func(k int) int
	}{
		{
			name:  "separated lists",
			build: buildSeparatedLists,
			// One member per list.
			wantMatches: func(k int) int { return k },
		},
		{
			name:  "heads nested in members",
			build: buildNestedHeads,
			// Every `-token=<v>` after the first head is a member of the first head's list, emitted
			// once even though k-1 further heads reach it.
			wantMatches: func(k int) int { return k - 1 },
		},
	}

	for _, tgt := range targets {
		t.Run(tgt.name, func(t *testing.T) {
			v := NewValidator()
			base := tgt.build(listTailBaseHeads)
			big := tgt.build(4 * listTailBaseHeads)
			if len(base) < listTailMinBaseLineBytes {
				t.Fatalf("%s: base line is %d bytes, under the %d at which every pattern is on the NFA — "+
					"the ratio would compare two regexp engines", tgt.name, len(base), listTailMinBaseLineBytes)
			}

			// Timed at findListTailSecrets, not ValidateContent: see listTailMaxGrowthRatio.
			var nBase, nBig int
			g, err := perfguard.Measure(perfguard.DefaultPairs,
				func() { nBase = len(v.findListTailSecrets(base)) },
				func() { nBig = len(v.findListTailSecrets(big)) })
			if err != nil {
				t.Fatalf("measuring findListTailSecrets: %v", err)
			}

			// NON-VACUITY, on the readings that were actually timed: a walk that silently stopped
			// emitting members is fast, and a guard timing it would report a beautifully flat ratio.
			// Fewer than the correct count is therefore fatal here; MORE than it is the duplication
			// the walk exists to prevent, and is reported after the ratio below.
			wantBase, wantBig := tgt.wantMatches(listTailBaseHeads), tgt.wantMatches(4*listTailBaseHeads)
			if nBase < wantBase || nBig < wantBig {
				t.Fatalf("%s: %d tail candidates at %d heads (want %d) and %d at %d heads (want %d) — the "+
					"walk is not reaching the members, so the ratio below would not be timing it",
					tgt.name, nBase, listTailBaseHeads, wantBase, nBig, 4*listTailBaseHeads, wantBig)
			}
			if nBig <= nBase {
				t.Fatalf("%s: candidates did not grow with the input: %d at base, %d at 4x", tgt.name, nBase, nBig)
			}

			t.Logf("%s: 4x heads on one line cost %s; %s", tgt.name, g, g.ResolutionNote())

			// Asserted only where the base reading spans enough clock ticks for the ratio to be a
			// measurement rather than arithmetic on tick counts. See perfguard.Growth.Ticks.
			if _, resolvable := g.Ticks(); !resolvable {
				t.Logf("%s: growth ratio NOT asserted — %s", tgt.name, g.ResolutionNote())
			} else if g.Ratio > listTailMaxGrowthRatio {
				t.Errorf("%s: 4x heads on one line cost %s — linear is ~4x and quadratic ~16x. A list "+
					"tail is being re-walked per head: either appendListTail is splitting past the "+
					"first non-member again, or a walk no longer stops at a separator another walk "+
					"has already passed", tgt.name, g)
			}

			// The exact count, after the ratio so a regression reports its timing as well. Each list
			// member is emitted ONCE however many heads reach it; the v2.5.3 splitter emitted every
			// element once per head before it, for dedupeScopedBySpan to throw away.
			for _, c := range []struct{ heads, got, want int }{
				{listTailBaseHeads, nBase, wantBase}, {4 * listTailBaseHeads, nBig, wantBig},
			} {
				if c.got != c.want {
					t.Errorf("%s: %d heads produced %d tail candidates, want %d — every list member "+
						"once, however many heads reach it", tgt.name, c.heads, c.got, c.want)
				}
			}
		})
	}
}
