// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// The list-tail walk and the collection scan must each cost O(line length), however many heads or
// openers share the line (#754).
//
// Both shipped in v2.5.3 at O(K x line length) for K heads on one line. Through the CLI, median of
// three interleaved samples:
//
//	                                                            K = 2,000   4,000    8,000
//	`token=<v>` joined by `;` (findListTailSecrets)     v2.5.3     0.81s    2.53s    9.96s
//	                                                    now        0.23s    0.39s    0.82s
//	`token=[<v>` joined by ` ` (findCollectionSecrets)  v2.5.3     1.51s    6.02s   25.04s
//	                                                    now        0.23s    0.41s    0.81s
//
// TestValidatorComplexityIsSubQuadratic in internal/goldencorpus could not see either. Its secrets
// input separates assignments with SPACES and closes what it opens, so no head is followed by a
// separator and no bracket is left open. These targets are the shapes it misses.
//
// Each target is the shape one regression needs in order to be seen:
//
//   - separated lists: `token=<v1>,<w1>;token=<v2>,<w2>;...`. Each list has one member and the next
//     `token=` opens a new pair, so every walk is one element long. The regression it catches is the
//     eager split of everything after each head, i.e. the v2.5.3 splitter coming back.
//   - heads nested in members: `token=<v1>,/token=<v2>,/token=<v3>,...`. `/token=<v>` fits the value
//     class and is not a pair (`/` can neither begin nor continue a key), so it is a list MEMBER --
//     and the singular pattern, which is not anchored at a word boundary, also finds a head inside it.
//     Every head's tail therefore runs to the end of the line, and only the shared `walked` set keeps
//     the total linear: without it this is O(K^2) even though the walk is lazy. The first target
//     cannot see that regression, because its walks are one element long either way.
//   - unclosed collections, joined by spaces: `token=[<v1> token=[<v2> ...`. No bracket closes, so in
//     v2.5.3 every opener's region ran to the end of the line and its one element WAS the rest of the
//     line. The count is the same either way (one element per opener); the reported text is not, so
//     the total text length is asserted as well.
//   - unclosed collections, joined by commas: `token=[<v1>, token=[<v2>, ...`. The same regions, split
//     at the commas: in v2.5.3 every later `token=[<v>` was a candidate once per earlier opener.
//
// Timed at the function itself. Through ValidateContent or findKeywordSecrets the scoring and the
// ~100 other patterns are a linear term that only dilutes the one being guarded: at 1,000 heads the
// regressed tail ratio read 9.75x-10.78x there, a 1.2x-1.35x margin over this bound. A ratio needs
// the guarded term to dominate the base reading.
//
// Measured on darwin/arm64, CPU clock, 4x input, minimum of perfguard.DefaultPairs, in three sets
// taken hours apart at load averages of 5 to 200 and reported here as their union: correct code 22
// runs plain and 11 under -race, each regression 14 runs plain and 7 under -race. The v2.5.3
// regions column is both of its forms, the old region bound alone and the old function whole:
//
//	                                       correct        no `walked`     v2.5.3 tail     v2.5.3 regions
//	separated lists                plain   3.81x-4.41x    (linear)        14.22x-16.02x   (linear)
//	                               -race   3.70x-4.07x    (linear)        12.54x-13.81x   (linear)
//	heads nested in members        plain   3.63x-4.20x    12.78x-14.43x   12.77x-14.59x   (linear)
//	                               -race   3.71x-4.17x    10.37x-14.51x   10.85x-18.67x   (linear)
//	unclosed, joined by spaces     plain   3.75x-4.18x    (linear)        (linear)        17.39x-21.96x
//	                               -race   3.38x-4.13x    (linear)        (linear)        18.26x-21.24x
//	unclosed, joined by commas     plain   3.66x-4.16x    (linear)        (linear)        16.96x-20.76x
//	                               -race   3.57x-4.11x    (linear)        (linear)        16.67x-19.79x
//
//	(linear): that regression does not reach this target; another target is the one that catches it.
//
// 8.0 is the same bound maxGrowthRatio uses: 1.81x above the worst correct reading and 1.60x below
// the best regressed one, plain. Every regression also fails the exact counts asserted after the
// ratio, without any timing: at 500 heads the v2.5.3 tail emitted 250,000 (separated) and 124,750
// (nested) candidates where a correct walk emits 500 and 499, and the v2.5.3 regions emitted
// 4,004,000 bytes of candidate text (spaces) and 125,250 candidates (commas) where correct code
// emits 12,000 bytes and 500.
//
// NOT ASSERTED UNDER -race, as the goldencorpus guard is not (see
// listGuardRatioNotAssertableUnderRace). Every target is still measured and logged there, and the
// exact counts below are asserted under both builds: they need no clock, and every regression above
// fails them too.
const listGuardMaxGrowthRatio = 8.0

// listGuardBaseHeads is the head count of the base input; the big input has 4x as many.
//
// Large enough that the base reading clears perfguard's resolution gate on darwin/arm64's
// microsecond CPU clock. Windows' 15.625ms CPU tick is not cleared, and the tick gate declines the
// ratio there -- the same platform gap every perfguard guard in the repo has (#619), logged rather
// than asserted.
//
// Small enough that a regression stays affordable: a regressed walk's working set grows as K^2.
const listGuardBaseHeads = 500

// listGuardMinBaseLineBytes keeps the BASE line above the length at which Go's regexp stops using
// its backtracker for these patterns. regexp switches from the bit-state backtracker to the NFA once
// the input reaches 256Kbit / len(prog.Inst), which is 7,084 bytes (secret[_-]?access[_-]?key, 37
// instructions) to 12,483 (pwd, 21) for the 26 unquoted patterns the tail is found by, and 7,489 to
// 13,797 for the 26 collection openers. A base line under that runs on a different engine from the
// 4x line, and the ratio then measures the engine switch: values of 8 bytes put the nested base line
// at 8,000 bytes and read 5.45x-5.60x on CORRECT code.
const listGuardMinBaseLineBytes = 14_000

// listGuardValues returns k distinct mixed-case alphanumeric values of 24 bytes, generated at run
// time so no credential-shaped literal sits in the source. Distinct, because a repeated value can
// let a cache or a dedup step flatten a quadratic into something that measures linear.
func listGuardValues(k int) []string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rng := rand.New(rand.NewSource(754)) // deterministic: the fixture must not vary between runs
	out := make([]string, k)
	b := make([]byte, listGuardValueBytes-3)
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

const listGuardValueBytes = 24

// buildSeparatedLists is one line of k two-element lists, each opened by its own head:
// `token=<v1>,<w1>;token=<v2>,<w2>;...`. `,` inside a list and `;` between lists, so both
// separators are on the timed path.
func buildSeparatedLists(k int) string {
	vals := listGuardValues(2 * k)
	var sb strings.Builder
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
// `token=<v1>,/token=<v2>,/token=<v3>,...`.
func buildNestedHeads(k int) string {
	var sb strings.Builder
	for i, v := range listGuardValues(k) {
		if i > 0 {
			sb.WriteString(",/")
		}
		sb.WriteString("token=")
		sb.WriteString(v)
	}
	sb.WriteByte('\n')
	return sb.String()
}

// buildUnclosedCollections is one line of k collection openers that never close, joined by sep:
// `token=[<v1><sep>token=[<v2><sep>...`.
func buildUnclosedCollections(sep string) func(k int) string {
	return func(k int) string {
		var sb strings.Builder
		for i, v := range listGuardValues(k) {
			if i > 0 {
				sb.WriteString(sep)
			}
			sb.WriteString("token=[")
			sb.WriteString(v)
		}
		sb.WriteByte('\n')
		return sb.String()
	}
}

// listGuardTarget is one shape timed at one function.
type listGuardTarget struct {
	name  string
	build func(k int) string
	find  func(v *Validator, line string) []collectionSecretCandidate
	// wantMatches is the exact candidate count for k heads.
	wantMatches func(k int) int
	// wantTextBytes, when set, is the exact total length of the candidates' text for k heads.
	wantTextBytes func(k int) int
	// regressed names what a failure of this target means.
	regressed string
}

func findListTail(v *Validator, line string) []collectionSecretCandidate {
	return v.findListTailSecrets(line)
}

func findCollections(v *Validator, line string) []collectionSecretCandidate {
	return v.findCollectionSecrets(line)
}

func TestListTailIsLinearInLineLength(t *testing.T) {
	runListGuard(t, []listGuardTarget{
		{
			name:  "separated lists",
			build: buildSeparatedLists,
			find:  findListTail,
			// One member per list.
			wantMatches: func(k int) int { return k },
			regressed: "a list tail is being split past its first non-member again, as the v2.5.3 " +
				"splitter split everything after every head",
		},
		{
			name:  "heads nested in members",
			build: buildNestedHeads,
			find:  findListTail,
			// Every `/token=<v>` after the first head is a member of the first head's list, emitted
			// once even though k-1 further heads reach it.
			wantMatches: func(k int) int { return k - 1 },
			regressed: "a walk no longer stops at a separator another walk has already passed, so " +
				"every head re-walks the list",
		},
	})
}

func TestCollectionIsLinearInLineLength(t *testing.T) {
	runListGuard(t, []listGuardTarget{
		{
			name:  "unclosed collections joined by spaces",
			build: buildUnclosedCollections(" "),
			find:  findCollections,
			// One element per opener, and each is its value alone: the region ends where the next
			// collection's key begins.
			wantMatches:   func(k int) int { return k },
			wantTextBytes: func(k int) int { return k * listGuardValueBytes },
			regressed: "a collection that never closes runs to the end of the line again, through " +
				"every collection after it",
		},
		{
			name:          "unclosed collections joined by commas",
			build:         buildUnclosedCollections(", "),
			find:          findCollections,
			wantMatches:   func(k int) int { return k },
			wantTextBytes: func(k int) int { return k * listGuardValueBytes },
			regressed: "a collection that never closes runs to the end of the line again, and " +
				"reports every later `token=[<v>` once per earlier opener",
		},
	})
}

func runListGuard(t *testing.T, targets []listGuardTarget) {
	t.Helper()
	if testing.Short() {
		t.Skip("list complexity guard skipped in -short mode")
	}
	for _, tgt := range targets {
		t.Run(tgt.name, func(t *testing.T) {
			v := NewValidator()
			base := tgt.build(listGuardBaseHeads)
			big := tgt.build(4 * listGuardBaseHeads)
			if len(base) < listGuardMinBaseLineBytes {
				t.Fatalf("%s: base line is %d bytes, under the %d at which every pattern is on the NFA — "+
					"the ratio would compare two regexp engines", tgt.name, len(base), listGuardMinBaseLineBytes)
			}

			var baseOut, bigOut []collectionSecretCandidate
			g, err := perfguard.Measure(perfguard.DefaultPairs,
				func() { baseOut = tgt.find(v, base) },
				func() { bigOut = tgt.find(v, big) })
			if err != nil {
				t.Fatalf("measuring %s: %v", tgt.name, err)
			}
			nBase, nBig := len(baseOut), len(bigOut)

			// NON-VACUITY, on the readings that were actually timed: a function that silently stopped
			// emitting is fast, and a guard timing it would report a beautifully flat ratio. Fewer
			// than the correct count is therefore fatal here; MORE than it is the duplication these
			// functions must not do, and is reported after the ratio below.
			wantBase, wantBig := tgt.wantMatches(listGuardBaseHeads), tgt.wantMatches(4*listGuardBaseHeads)
			if nBase < wantBase || nBig < wantBig {
				t.Fatalf("%s: %d candidates at %d heads (want %d) and %d at %d heads (want %d) — the "+
					"function is not reaching the members, so the ratio below would not be timing it",
					tgt.name, nBase, listGuardBaseHeads, wantBase, nBig, 4*listGuardBaseHeads, wantBig)
			}
			if nBig <= nBase {
				t.Fatalf("%s: candidates did not grow with the input: %d at base, %d at 4x", tgt.name, nBase, nBig)
			}

			t.Logf("%s: 4x heads on one line cost %s; %s", tgt.name, g, g.ResolutionNote())

			// Asserted only without -race, and where the base reading spans enough clock ticks for
			// the ratio to be a measurement rather than arithmetic on tick counts.
			if note := listGuardRatioNotAssertableUnderRace(); note != "" {
				t.Logf("%s: growth ratio NOT asserted — %s", tgt.name, note)
			} else if _, resolvable := g.Ticks(); !resolvable {
				t.Logf("%s: growth ratio NOT asserted — %s", tgt.name, g.ResolutionNote())
			} else {
				perfguard.ReportMargin(t, "secrets "+tgt.name, g, listGuardMaxGrowthRatio, perfguard.StayBelow)
				if g.Ratio > listGuardMaxGrowthRatio {
					t.Errorf("%s: 4x heads on one line cost %s — linear is ~4x and quadratic ~16x: %s",
						tgt.name, g, tgt.regressed)
				}
			}

			// The exact counts, after the ratio so a regression reports its timing as well, and
			// under both builds, since they need no clock.
			for _, c := range []struct {
				heads int
				got   []collectionSecretCandidate
			}{{listGuardBaseHeads, baseOut}, {4 * listGuardBaseHeads, bigOut}} {
				if want := tgt.wantMatches(c.heads); len(c.got) != want {
					t.Errorf("%s: %d heads produced %d candidates, want %d — %s",
						tgt.name, c.heads, len(c.got), want, tgt.regressed)
				}
				if tgt.wantTextBytes == nil {
					continue
				}
				total := 0
				for _, m := range c.got {
					total += len(m.text)
				}
				if want := tgt.wantTextBytes(c.heads); total != want {
					t.Errorf("%s: %d heads produced %d bytes of candidate text, want %d — %s",
						tgt.name, c.heads, total, want, tgt.regressed)
				}
			}
		})
	}
}

// listGuardRatioNotAssertableUnderRace explains why listGuardMaxGrowthRatio must not be compared
// when the race detector is active, or returns "" when it may. It is the goldencorpus guard's rule
// (thresholdNotAssertableUnderRace in internal/goldencorpus), for the same reason: -race does not
// scale a ratio, it distorts it, and here it compresses the regressed side.
//
// Measured on darwin/arm64 (table at listGuardMaxGrowthRatio): under -race correct code reads as it
// does without it, 3.38x-4.17x, but a regressed walk fell to 10.37x, 1.30x from the bound -- under
// the repo's 1.5x rule. A bound with 1.5x on both sides under both builds would have to sit between
// 6.6x and 6.9x on that one machine's readings, and the goldencorpus guard measured ubuntu-latest
// compressing quadratics further still, so the ratio is left to the build that ships. go-test.yml
// asserts it in its own step without -race; the main suite runs these tests under -race for the race
// detector and the exact counts.
func listGuardRatioNotAssertableUnderRace() string {
	if !raceEnabled {
		return ""
	}
	return "the race detector is active, and it compresses this ratio (measured: a regressed walk fell " +
		"to 10.37x against the 8.0 bound). listGuardMaxGrowthRatio describes the guard as shipped, " +
		"which go-test.yml asserts without -race"
}

// The race gate decides whether any of the four ratios above is asserted, so its POLARITY is pinned,
// as TestTheRaceGateIsNotTakenWithoutRace pins the goldencorpus one: a gate that returned a note
// unconditionally would leave every target passing while asserting no ratio at all. Runs in both
// modes and asserts opposite things in each, so neither build tag can hide a mistake.
func TestListGuardRaceGateIsNotTakenWithoutRace(t *testing.T) {
	note := listGuardRatioNotAssertableUnderRace()
	if raceEnabled {
		if note == "" {
			t.Error("the race detector IS active but the gate reports the ratio assertable")
		}
		return
	}
	if note != "" {
		t.Errorf("this is a NON-race run, yet the gate is skipping the ratio assertions: %q", note)
	}
}
