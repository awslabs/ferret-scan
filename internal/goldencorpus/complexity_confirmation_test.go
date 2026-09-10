// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// #546: the growth-ratio guard failed on CORRECT code. Five readings this guard produced on
// unmodified validators sat in (8.0, 12.0] — dob 8.60x under -race, medicalid 9.68x plain —
// every one of which passes at the pre-#535 threshold of 12.0 and none of which is a defect.
// Host load average was 143-175 on 14 CPUs, and CI runs this suite with -race on shared
// runners, so that is the configuration that matters.
//
// The cause is the STATISTIC, not the threshold. A single pair of wall-clock readings is not
// stable under contention. Measured on the four flakiest targets at load average 160, 24
// trials each:
//
//	single pair                1.20 - 6.82x
//	min of independent mins    2.87 - 6.07x
//	MEDIAN of paired readings  3.58 - 6.03x
//
// Note single-shot's 1.20x on linear code: contention inflates the BASE term too, which drives
// the ratio DOWN. That is why the minimum is unsafe — it is biased toward passing and could
// mask a real quadratic — and why the median, robust in both directions, is the right choice.
//
// The threshold could not be fixed instead. A reproduced quadratic reads 15.4-15.6x plain but
// only 12.4-12.7x under -race, so the bound must stay well below 12.4 while contended correct
// code reached 9.68x. No single number has margin at both ends.

// quadraticValidator is deliberately O(n^2): for every match it rescans the whole input.
//
// A synthetic validator rather than a mutated real one, because #535's own note reproduced a
// quadratic by defeating dob's keyword hoist — an invasive edit to production code that cannot
// live in a test. This shape is the pattern the guard exists to catch (per-match full-input
// rescan), so it exercises the same failure mode without touching a shipped validator.
type quadraticValidator struct{}

func (quadraticValidator) ValidateContent(content, _ string) ([]detector.Match, error) {
	// Pre-sized, and the match scan uses strings.Index rather than a per-byte slice compare. Both keep
	// the fixture's own LINEAR cost out of what is timed, so the ratio measures the quadratic step.
	//
	// This matters on ubuntu-latest, where the base reading was dominated by linear cost and this
	// control measured 7.46x and 7.85x -- BELOW its own 8.0 threshold, i.e. the guard could not detect
	// the regression it exists for. For a 4x step the ratio is 4*(1+3f) where f is the quadratic share
	// of the base, and f was 0.29 there against 0.80 locally.
	//
	// RESOLVED, 2026-09-08 (#599): ubuntu-latest now reads 15.16x and macos-latest 15.49x, from run
	// 34281522336 on main. Two things fixed it and only one of them is this fixture -- dropping -race
	// from the guard (#602) removed the amplifier, because the 7.46x came from the detector instrumenting
	// every copy of the large detector.Match struct. Kept rather than deleted because the reasoning
	// below is what makes the fixture's shape deliberate, and the f = 0.29 measurement is the evidence
	// for the detection floor now recorded at maxGrowthRatio.
	//
	// Contributions measured in isolation, three runs each under -race on darwin/arm64, because the
	// first two explanations reached for were both wrong:
	//
	//	as it was (append per match, per-byte scan)   13.49x - 14.06x
	//	pre-sized only                               14.65x - 14.89x
	//	strings.Index only                           13.30x - 13.78x   <- no effect alone
	//	both                                         14.96x - 15.31x
	//
	// The order is not obvious: strings.Index does nothing by itself because repeated slice growth
	// dominates and hides the scan; once pre-sized the per-byte compare becomes visible and removing
	// it closes the gap. A third change -- emitting only every 64th match -- measured 15.87x against
	// 15.82x, i.e. nothing, and was dropped rather than shipped on a story it could not support.
	//
	// A first attempt at this shipped WITHOUT the tick gate on the assertion above and broke
	// windows-latest: making the base cheaper made it span FEWER of that platform's 15.625ms ticks, so
	// the ratio became pure quantisation. The two platforms want opposite fixtures -- ubuntu a larger
	// quadratic share, Windows a longer absolute time -- which is why the gate is what makes this safe.
	out := make([]detector.Match, 0, 1+strings.Count(content, "XQZ"))
	for off := 0; ; {
		j := strings.Index(content[off:], "XQZ")
		if j < 0 {
			break
		}
		off += j + 1
		// The quadratic step: a full-input scan per match.
		n := strings.Count(content, "a")
		out = append(out, detector.Match{Text: "XQZ", Type: "TEST", Confidence: float64(50 + n%2)})
	}
	return out, nil
}

func quadraticUnit(i int) string { return "XQZ aaaaaaaaaaaaaaaa " }

// thresholdNotAssertableUnderRace explains why a maxGrowthRatio comparison must not be made when the
// race detector is active, or returns "" when it may.
//
// maxGrowthRatio is a property of the SHIPPED guard, which runs without -race (go-test.yml has a
// dedicated non-race step for exactly these tests). Comparing an instrumented reading against it is a
// claim about a configuration nothing ships.
//
// The reason it is a SKIP and not a scaled bound: -race does not scale a ratio, it distorts it
// ASYMMETRICALLY, and in both directions depending on the shape. Measured, same test in the same CI job,
// non-race step then race step:
//
//	                                base            big             ratio
//	emit-per-match (ubuntu)         4.397->13.841ms  62.675->99.385ms  14.25x -> 7.18x
//	sparse 1-in-4096 (macos)        22.293->47.809ms 134.69->402.884ms  6.04x -> 8.43x
//	synthetic quadratic (macos)     4.592-> 9.202ms  72.026->72.442ms  15.69x -> 7.87x
//
// The emit-heavy base inflates 3.1x while its big inflates 1.6x, because instrumentation costs scale
// with the per-match ALLOCATION rather than with the scan, and the base has proportionally more emit per
// unit of scan. The synthetic quadratic is worse: base doubles while big moves 0.6%. There is no single
// multiplier -- one shape halves, another rises 40%.
//
// This is also a correction to race_ceiling_race_test.go, which states "the ratio check is unaffected
// either way: -race inflates the base and the 4x measurement equally, so the growth factor it asserts on
// is preserved". That holds for a pure-compute fixture and is false for an allocating one, which is what
// every control in this file is.
//
// These three readings are the whole of #620's and #643's CI failures.
func thresholdNotAssertableUnderRace() string {
	if !raceDetectorEnabled {
		return ""
	}
	return "the race detector is active, and it distorts this ratio asymmetrically (measured: an " +
		"emit-heavy base inflates 3.1x against its big's 1.6x, taking 14.25x to 7.18x). maxGrowthRatio " +
		"describes the guard as shipped, which runs without -race — go-test.yml's non-race step is " +
		"where this assertion is made"
}

// TestGrowthRatioStillCatchesAGenuineQuadratic is the half that protects the guard's purpose.
//
// The estimator must not be so noise-tolerant that it stops detecting the thing it exists for.
// A real quadratic must exceed the threshold, and asserting it here is what stops a future
// robustness change from quietly buying stability with blindness.
func TestGrowthRatioStillCatchesAGenuineQuadratic(t *testing.T) {
	newV := func() validatorUnderTest { return quadraticValidator{} }

	// Sized so the base CPU reading clears perfguard.MinMeasurableCPU. A first version used reps = 300,
	// giving a 45µs base, which is below the resolution the ratio is computed at.
	const reps = 3000
	base := buildComplexityInput(quadraticUnit(0), nil, reps)
	big := buildComplexityInput(quadraticUnit(0), nil, reps*4)

	g := growthRatio(t, newV, base, big)
	t.Logf("synthetic quadratic: %.2fx on the %s clock (min base=%v big=%v, per-pair %s)",
		g.Ratio, g.Clock, g.BaseMin, g.BigMin, perfguard.FormatRatios(g.Samples))

	// Non-vacuity: the fixture must actually be driving the quadratic path. A reject path is
	// fast and its ratio is noise, which would make the assertion below meaningless. The counts
	// come from the same measurement, so they describe the readings being judged.
	if g.baseMatches == 0 || g.bigMatches <= g.baseMatches {
		t.Fatalf("fixture is not exercising the quadratic path: base=%d big=%d matches",
			g.baseMatches, g.bigMatches)
	}

	// Asserted only where the clock can support a ratio. On windows-latest the CPU clock advances
	// 15.625ms at a time, so this control's base was a single tick and its "ratio" was one integer
	// over another -- which is why an earlier fixture change to this test passed on main and FAILED
	// there. See Growth.Ticks.
	if note := thresholdNotAssertableUnderRace(); note != "" {
		t.Logf("quadratic control NOT asserted — %s", note)
	} else if _, resolvable := g.Ticks(); !resolvable {
		t.Logf("quadratic control NOT asserted — %s", g.ResolutionNote())
	} else if g.Ratio <= maxGrowthRatio {
		t.Errorf("a genuine O(n^2) validator measured %.2fx on the %s clock, at or below the %.1f "+
			"threshold — the guard would no longer detect the regression it exists for. "+
			"min base=%v big=%v, per-pair %s. %s",
			g.Ratio, g.Clock, maxGrowthRatio, g.BaseMin, g.BigMin,
			perfguard.FormatRatios(g.Samples), g.ResolutionNote())
	}
}

// TestGrowthRatioStaysLowOnLinearCode is the must-NOT-fire half.
//
// #546 was this direction failing: correct code read 8.60x and 9.68x on a contended runner and
// the guard reported an O(n^2) regression that did not exist. The validator here allocates a
// Match per finding exactly as production ones do, because allocation was the specific thing that
// made a single-pass scan read 8.17x — see withGCOff.
func TestGrowthRatioStaysLowOnLinearCode(t *testing.T) {
	newV := func() validatorUnderTest { return linearValidator{} }
	const reps = 40000
	base := buildComplexityInput(linearUnit, nil, reps)
	big := buildComplexityInput(linearUnit, nil, reps*4)

	g := growthRatio(t, newV, base, big)
	t.Logf("linear control: %.2fx on the %s clock (min base=%v big=%v, per-pair %s)",
		g.Ratio, g.Clock, g.BaseMin, g.BigMin, perfguard.FormatRatios(g.Samples))

	// Same tick gate as the quadratic half. This direction matters just as much: on windows-latest a
	// linear control read exactly "2.00x" from base=15.625ms big=31.25ms -- two ticks over one -- and a
	// 1-tick base can just as easily quantise UPWARD past the threshold and fail correct code, which is
	// what #546 was.
	if note := thresholdNotAssertableUnderRace(); note != "" {
		t.Logf("linear control NOT asserted — %s", note)
	} else if _, resolvable := g.Ticks(); !resolvable {
		t.Logf("linear control NOT asserted — %s", g.ResolutionNote())
	} else if g.Ratio > maxGrowthRatio {
		t.Errorf("a single-pass validator measured %.2fx on the %s clock, above the %.1f "+
			"threshold — this is #546, the guard failing on correct code. min base=%v big=%v, "+
			"per-pair %s", g.Ratio, g.Clock, maxGrowthRatio, g.BaseMin, g.BigMin, perfguard.FormatRatios(g.Samples))
	}
}

// TestNothingInThisPackageRunsInParallel protects the assumption the CPU clock depends on.
//
// getrusage(RUSAGE_SELF) reports CPU for the WHOLE PROCESS, so it is only a measure of the
// validator under test while nothing else in this process is burning CPU concurrently. Two facts
// make that true today, and this test pins the one that a future edit could break:
//
//  1. `go test` builds and runs one binary PER PACKAGE, so the other packages competing for the
//     machine are separate processes and their CPU does not enter this reading. That is why the
//     estimator survives a loaded runner — measured with 28 external busy-loop processes on 14
//     CPUs, the minimum base reading was 3.727ms against 3.703ms idle.
//  2. No test in this package runs concurrently with another. This is the fragile half.
//
// Measured, so this is not a theoretical worry: running the linear control with 28 busy
// GOROUTINES in-process made it read 11.62x with the base inflated from 4.374ms to 39.559ms —
// a false O(n^2) report on a single-pass scan. Adding t.Parallel() anywhere in this package would
// do exactly that to whichever measurement happened to overlap.
func TestNothingInThisPackageRunsInParallel(t *testing.T) {
	offenders, scanned, err := perfguard.AssertNoParallelTests(".")
	if err != nil {
		t.Fatalf("scanning this package for parallel tests: %v", err)
	}

	// Non-vacuity: if the directory walk stopped finding test files, the assertion below would
	// pass on an empty set.
	if scanned < 5 {
		t.Fatalf("scanned only %d _test.go files in this package; the check is not reading the "+
			"sources it is meant to police", scanned)
	}
	if len(offenders) > 0 {
		t.Errorf("t.Parallel found at %s. The complexity guard measures process-wide CPU time "+
			"(getrusage RUSAGE_SELF), so a test running concurrently with a measurement is "+
			"charged to the validator being measured: in-process load inflated a base reading "+
			"4.374ms -> 39.559ms and turned a 4.07x linear scan into 11.62x, above the %.1f "+
			"threshold. Either keep this package sequential or move the complexity guard to a "+
			"clock that is not process-wide.", strings.Join(offenders, ", "), maxGrowthRatio)
	}
}

// linearUnit is one repetition of the linear control's input.
//
// Deliberately ONE match per ~200 bytes. A first version used "XQZ aaaa " -- a match every 9
// bytes, 160k matches at the big size -- and the slice growth and GC that caused made the
// control noisier than any real validator: it read [4.02x 14.18x 3.85x 15.64x] where the 18
// real targets read 3.20-4.51x. A control must be at least as stable as the thing it models.
const linearUnit = "XQZ " + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "

// linearValidator scans the input once.
type linearValidator struct{}

func (linearValidator) ValidateContent(content, _ string) ([]detector.Match, error) {
	// Pre-sized from the input, so repeated slice growth is not part of what is timed. detector.Match
	// is a large struct and -race instruments every copy, which is what made an append-driven
	// version read 8.17x on a CI runner for a single-pass scan.
	out := make([]detector.Match, 0, 1+len(content)/len(linearUnit))
	for i := 0; i+3 <= len(content); i++ {
		if content[i:i+3] == "XQZ" {
			out = append(out, detector.Match{Text: "XQZ", Type: "TEST", Confidence: 50})
		}
	}
	return out, nil
}

// emittingQuadraticValidator is the SECOND quadratic control #599 asked for.
//
// quadraticValidator above is deliberately clean: pre-sized slice, strings.Index scan, a bare
// Match. That was the right fix for the fixture defect it had, but it also removed the per-match
// cost every real validator pays -- and #599's question was precisely whether the threshold still
// holds for the realistic shape. One control cannot answer both: the clean one proves the
// ESTIMATOR discriminates, this one proves the THRESHOLD does.
//
// So this emits like a production validator does: append to a nil slice, populate Context with
// before/after/full-line spans, and allocate a Metadata map per finding.
type emittingQuadraticValidator struct{}

func (emittingQuadraticValidator) ValidateContent(content, _ string) ([]detector.Match, error) {
	var out []detector.Match // NOT pre-sized, as production validators are not
	for off := 0; ; {
		j := strings.Index(content[off:], "XQZ")
		if j < 0 {
			break
		}
		start := off + j
		off = start + 1

		// The quadratic step: a full-input scan per match.
		n := strings.Count(content, "a")
		out = append(out, detector.Match{
			Text:       content[start : start+3],
			Type:       "TEST",
			Confidence: float64(50 + n%2),
			Validator:  "emitting-quadratic-control",
			Context:    contextAround(content, start),
			Metadata:   map[string]any{"validator": "emitting-quadratic-control"},
		})
	}
	return out, nil
}

// contextAround builds the same shape of ContextInfo a real validator attaches to a finding.
func contextAround(content string, start int) detector.ContextInfo {
	lo, hi := start-40, start+43
	if lo < 0 {
		lo = 0
	}
	if hi > len(content) {
		hi = len(content)
	}
	return detector.ContextInfo{
		BeforeText: content[lo:start],
		AfterText:  content[start+3 : hi],
		FullLine:   content[lo:hi],
	}
}

// TestGrowthRatioCatchesAnEmitPerMatchQuadratic answers #599's question directly.
//
// The concern was that making quadraticValidator clean removed the per-match emit cost, so the
// control no longer modelled a real validator: a genuine regression carrying that cost might read
// lower and slip under 8.0. Measured on darwin/arm64, same fixture size, three runs each:
//
//	clean control (unsized append)   15.07x   f=0.92
//	full production-shaped emit      14.94x   f=0.91
//
// The emit dilutes the ratio by about 1%, not by the factor #599 feared. The 7.46x/7.85x ubuntu
// readings that motivated the issue came from -race instrumenting every copy of the large
// detector.Match struct, and the guard no longer runs under -race (#602) -- so the amplifier is
// gone, not merely diluted. Under -race this shape still reads 13.33x.
func TestGrowthRatioCatchesAnEmitPerMatchQuadratic(t *testing.T) {
	newV := func() validatorUnderTest { return emittingQuadraticValidator{} }

	// Same size as the clean control, so the two readings are directly comparable.
	const reps = 3000
	base := buildComplexityInput(quadraticUnit(0), nil, reps)
	big := buildComplexityInput(quadraticUnit(0), nil, reps*4)

	g := growthRatio(t, newV, base, big)
	t.Logf("emit-per-match quadratic: %.2fx on the %s clock (min base=%v big=%v, per-pair %s)",
		g.Ratio, g.Clock, g.BaseMin, g.BigMin, perfguard.FormatRatios(g.Samples))

	// Non-vacuity, same as the clean control: a fixture that is not emitting is not modelling
	// the cost this test exists to include.
	if g.baseMatches == 0 || g.bigMatches <= g.baseMatches {
		t.Fatalf("fixture is not exercising the quadratic path: base=%d big=%d matches",
			g.baseMatches, g.bigMatches)
	}

	if note := thresholdNotAssertableUnderRace(); note != "" {
		t.Logf("emit-per-match quadratic control NOT asserted — %s", note)
	} else if _, resolvable := g.Ticks(); !resolvable {
		t.Logf("emit-per-match quadratic control NOT asserted — %s", g.ResolutionNote())
	} else if g.Ratio <= maxGrowthRatio {
		t.Errorf("a genuine O(n^2) validator that emits a Match per finding measured %.2fx on the "+
			"%s clock, at or below the %.1f threshold — this is #599: the per-match emit cost "+
			"dilutes the ratio enough to hide a real regression. min base=%v big=%v, per-pair %s. %s",
			g.Ratio, g.Clock, maxGrowthRatio, g.BaseMin, g.BigMin,
			perfguard.FormatRatios(g.Samples), g.ResolutionNote())
	}
}

// sparseQuadraticValidator takes the quadratic path only for every Nth match. Everything else is
// a linear scan with a production-shaped emit.
//
// This is the shape a real O(n^2) regression usually has: a full-input rescan guarded by some
// filter, so it fires on a subset of findings rather than all of them.
type sparseQuadraticValidator struct {
	every int

	// rescans counts how many times the quadratic path actually ran, so the test below can prove
	// the fixture is quadratic rather than assuming it.
	rescans *int
}

func (v sparseQuadraticValidator) ValidateContent(content, _ string) ([]detector.Match, error) {
	var out []detector.Match
	seen := 0
	for off := 0; ; {
		j := strings.Index(content[off:], "XQZ")
		if j < 0 {
			break
		}
		start := off + j
		off = start + 1

		seen++
		confidence := 50.0
		if seen%v.every == 0 {
			// The quadratic step, on a sparse subset of the matches.
			confidence = float64(50 + strings.Count(content, "a")%2)
			*v.rescans++
		}
		out = append(out, detector.Match{
			Text:       content[start : start+3],
			Type:       "TEST",
			Confidence: confidence,
			Validator:  "sparse-quadratic-control",
			Context:    contextAround(content, start),
			Metadata:   map[string]any{"validator": "sparse-quadratic-control"},
		})
	}
	return out, nil
}

// TestGrowthRatioMissesASparseQuadratic records a LIMIT of this guard, deliberately.
//
// It asserts the CURRENT, WRONG behaviour: a genuinely O(n^2) validator goes undetected. That is
// intentional. The limit is real, it is arithmetic rather than a tuning mistake, and a test that
// pins it is the only thing that stops it being rediscovered a fourth time (#509, #546, #579, #599
// are all retunings of this one threshold). A change that closes the gap must INVERT this
// assertion in the same commit, with the linear control still passing — do not delete it.
//
// The arithmetic. For a 4x input step the measured ratio is
//
//	ratio = 4 * (1 + 3f)      f = the quadratic share of the BASE reading
//
// so ratio > 8.0 requires f > 1/3. An O(n^2) term that is less than a third of the base reading is
// invisible to this guard at any threshold it could safely carry. f grows with n, so whether a
// given regression is caught depends on the FIXTURE SIZE as much as on the code -- measured on
// darwin/arm64, ratio by (rescan density, reps):
//
//	rescan every    reps 3000   reps 12000   reps 48000
//	  1 match          14.62x      —            —
//	 16 matches         9.45x      12.55x       14.87x
//	 64 matches         4.95x       9.92x       13.03x
//	256 matches         4.81x       6.30x        8.88x
//	4096 matches         —           —           4.82x - 5.26x   <- this test
//
// And no threshold fixes it: the cell this test uses reads ~5.1x while correct code reaches 4.65x
// (see maxGrowthRatio), so a bound between them would have 1.10x margin against the repo's 1.5x
// rule. Closing this needs a third input size to fit a curve, or a larger step -- not a retune.
//
// Under -race the boundary moves the wrong way (the instrumented emit dilutes further): a 1-in-16
// rescan reads 8.37x plain and 5.85x under -race. The guard runs without -race, which is what
// keeps the operative column the plain one.
func TestGrowthRatioMissesASparseQuadratic(t *testing.T) {
	rescans := 0
	newV := func() validatorUnderTest { return sparseQuadraticValidator{every: 4096, rescans: &rescans} }

	// 48000 reps because the LINEAR term has to be large enough to measure: at reps=3000 this
	// shape's base is 254µs-330µs, under perfguard.MinMeasurableCPU, and the ratio would be an
	// artefact rather than a reading. Base lands at 5.1ms-6.9ms here.
	const reps = 48000
	base := buildComplexityInput(quadraticUnit(0), nil, reps)
	big := buildComplexityInput(quadraticUnit(0), nil, reps*4)

	g := growthRatio(t, newV, base, big)
	t.Logf("sparse quadratic (1 rescan per 4096 matches): %.2fx on the %s clock "+
		"(min base=%v big=%v, per-pair %s) — recorded as MISSED at the %.1f threshold",
		g.Ratio, g.Clock, g.BaseMin, g.BigMin, perfguard.FormatRatios(g.Samples), maxGrowthRatio)

	// Non-vacuity, and the part that matters most here. An assertion that something is NOT
	// detected passes trivially against a fixture that does no quadratic work at all, which would
	// turn this test into decoration. Prove the quadratic path ran.
	if rescans == 0 {
		t.Fatalf("the quadratic path never ran: this fixture is not O(n^2) and the assertion below "+
			"would hold for a purely linear validator. base=%d big=%d matches",
			g.baseMatches, g.bigMatches)
	}
	if g.baseMatches == 0 || g.bigMatches <= g.baseMatches {
		t.Fatalf("fixture is not scaling: base=%d big=%d matches", g.baseMatches, g.bigMatches)
	}

	if note := thresholdNotAssertableUnderRace(); note != "" {
		t.Logf("sparse quadratic control NOT asserted — %s", note)
	} else if _, resolvable := g.Ticks(); !resolvable {
		t.Logf("sparse quadratic control NOT asserted — %s", g.ResolutionNote())
	} else if g.Ratio > maxGrowthRatio {
		t.Errorf("a sparse O(n^2) validator measured %.2fx on the %s clock, ABOVE the %.1f "+
			"threshold — the guard now catches this shape, which is BETTER than what this test "+
			"records. Do not silence it: invert the assertion, state the new detection floor in "+
			"maxGrowthRatio's comment, and check the linear control still passes. "+
			"min base=%v big=%v, per-pair %s",
			g.Ratio, g.Clock, maxGrowthRatio, g.BaseMin, g.BigMin, perfguard.FormatRatios(g.Samples))
	}
}

// TestTheRaceGateIsNotTakenWithoutRace pins the POLARITY of thresholdNotAssertableUnderRace.
//
// That one function now decides whether four controls in this file assert anything. If it ever returned
// a non-empty note unconditionally -- an inverted condition, a debugging line left in, a refactor that
// dropped the raceDetectorEnabled check -- all four would pass while asserting NOTHING, and the suite
// would go green with the guard switched off. That is the exact failure #619 documents for windows, and
// it is worth one test to make it impossible.
//
// Runs in both modes and asserts opposite things in each, so neither build tag can hide a mistake.
func TestTheRaceGateIsNotTakenWithoutRace(t *testing.T) {
	note := thresholdNotAssertableUnderRace()

	if raceDetectorEnabled {
		if note == "" {
			t.Error("the race detector IS active but the gate reports the threshold assertable — the " +
				"four maxGrowthRatio controls would compare an instrumented ratio against a bound that " +
				"describes un-instrumented code, which is how #620 and #643 failed")
		}
		return
	}
	if note != "" {
		t.Errorf("this is a NON-race run, yet the gate is skipping the maxGrowthRatio assertions: %q. "+
			"All four controls in this file would pass while asserting nothing.", note)
	}
}
