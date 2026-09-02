// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/address"
	"github.com/awslabs/ferret-scan/v2/internal/validators/bankaccount"
	"github.com/awslabs/ferret-scan/v2/internal/validators/cloudresources"
	"github.com/awslabs/ferret-scan/v2/internal/validators/creditcard"
	"github.com/awslabs/ferret-scan/v2/internal/validators/dob"
	"github.com/awslabs/ferret-scan/v2/internal/validators/driverslicense"
	"github.com/awslabs/ferret-scan/v2/internal/validators/email"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ipaddress"
	"github.com/awslabs/ferret-scan/v2/internal/validators/medicalid"
	"github.com/awslabs/ferret-scan/v2/internal/validators/otp"
	"github.com/awslabs/ferret-scan/v2/internal/validators/passport"
	"github.com/awslabs/ferret-scan/v2/internal/validators/personname"
	"github.com/awslabs/ferret-scan/v2/internal/validators/phone"
	"github.com/awslabs/ferret-scan/v2/internal/validators/secrets"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ssn"
	"github.com/awslabs/ferret-scan/v2/internal/validators/vin"
)

// This file is the second half of the Phase 0 regression net (the first being
// the golden snapshots): a COMPLEXITY guard. The v2 audit found that ~12 of 13
// validators shared an O(n^2) per-line rescan pattern, fixed ad hoc. As the
// consolidation introduces a shared scanning primitive (Move C), there is a real
// risk of reintroducing quadratic behavior. These tests assert that each
// validator's runtime grows roughly LINEARLY with input size on a dense,
// match-bearing input — so a regression to O(n^2) fails loudly here instead of
// silently becoming a DoS vector in production.
//
// The assertion is deliberately loose (it allows a large constant-factor and
// GC/scheduler noise) because we are catching algorithmic class changes
// (linear -> quadratic), not micro-benchmarking. A 10x input that takes ~10x
// time passes; one that takes ~100x fails.

// validatorUnderTest is the minimal shape every validator exposes.
type validatorUnderTest interface {
	ValidateContent(content string, originalPath string) ([]detector.Match, error)
}

// complexityTargets are validators driven directly (bypassing the bridge stack)
// so the timing reflects the validator's own scanning cost, not orchestration.
// Each builder returns a fresh validator and a single-line unit of input that
// the validator will scan densely.
//
// A target supplies its input EITHER as `unit` (repeated verbatim) or as `gen`
// (called with 0..reps-1 to emit a distinct value per repetition). Prefer `gen`:
// complexity_generators_test.go documents why identical repeats can silently
// defeat this whole guard. `unit` is kept for the validators whose per-match cost
// does not depend on value distinctness.
var complexityTargets = []struct {
	name string
	new  func() validatorUnderTest
	unit string // one "row" of input; repeated to scale size (mutually exclusive with gen)
	// gen builds repetition i. Use when the validator dedups candidates, so
	// repeating one value would pin the match count flat as the input grows.
	gen       func(i int) string
	threshold time.Duration
	// minMatches, when > 0, is the floor asserted at BOTH measured sizes. It is
	// what makes the timing numbers mean something: see TestValidatorComplexityIsSubQuadratic.
	minMatches int
	// wantMatchGrowth requires the big input to yield strictly more matches than
	// the base input. Set for targets whose per-match cost is the thing under
	// test; leave false where the validator legitimately consolidates.
	wantMatchGrowth bool
	// baseReps overrides the default base repetition count. Needed when a target
	// has to land on a particular side of an internal size/count cap for the two
	// measurements to exercise the SAME code path (see socialmedia).
	baseReps int
}{
	{
		name: "ssn",
		new:  func() validatorUnderTest { return ssn.NewValidator() },
		// Dense near-SSN tokens on one line stress the per-match context rescan.
		unit:            "ssn 449-87-4100 and 555-12-3456 and 111-22-3333 ",
		minMatches:      800,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name: "ipaddress",
		new:  func() validatorUnderTest { return ipaddress.NewValidator() },
		// The old unit ("203.0.113.42 / 10.0.0.5 / 192.168.1.1 / 8.8.8.8") produced
		// ZERO matches: TEST-NET-3, RFC1918 and the well-known public resolver are
		// all vetoed, so this subtest timed the reject path and asserted nothing.
		// genPublicIP emits distinct routable addresses that survive the vetoes.
		gen:             genPublicIP,
		threshold:       5 * time.Second,
		minMatches:      500,
		wantMatchGrowth: true,
	},
	{
		name:            "email",
		new:             func() validatorUnderTest { return email.NewValidator() },
		unit:            "mail a@b.com x@y.org user@example.net admin@corp.co ",
		minMatches:      1000,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name: "phone",
		new:  func() validatorUnderTest { return phone.NewValidator() },
		// The old unit repeated three numbers, so per-line dedup pinned the match
		// count at 3 at EVERY size: the per-match cost never grew and a quadratic
		// per-match path would have measured as linear.
		gen:             genPhone,
		threshold:       5 * time.Second,
		minMatches:      500,
		wantMatchGrowth: true,
	},
	{
		name:            "creditcard",
		new:             func() validatorUnderTest { return creditcard.NewValidator() },
		unit:            "card 4532015112830366 5425233430109903 374245455400126 ",
		minMatches:      800,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	// The 13 remaining text-mode validators (METADATA excluded — it scans
	// extracted file metadata, not text windows). Each unit is a dense,
	// match-bearing line; keyword-gated validators (dob, driverslicense,
	// medicalid, otp, passport, bankaccount US-account) carry their trigger
	// keyword so the per-match context scan — the O(n^2)-prone path — is
	// actually exercised, not short-circuited by an empty candidate set.
	{
		name:            "address",
		new:             func() validatorUnderTest { return address.NewValidator() },
		unit:            "ship to 123 Main St and 456 Oak Ave and 789 Elm Blvd, Springfield IL 62704 ",
		minMatches:      800,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name:            "bankaccount",
		new:             func() validatorUnderTest { return bankaccount.NewValidator() },
		unit:            "routing 026009593 account 1234567890 iban DE89370400440532013000 swift BOFAUS3N ",
		minMatches:      1000,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name:            "cloudresources",
		new:             func() validatorUnderTest { return cloudresources.NewValidator() },
		unit:            "arn:aws:iam::123456789012:role/Admin arn:aws:s3:::my-bucket/key i-0abcd1234ef567890 ",
		minMatches:      500,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name: "dob",
		new:  func() validatorUnderTest { return dob.NewValidator() },
		// The old unit repeated four dates, which extractDates dedups per line: the
		// match count was 4 at every size. This validator was in fact quadratic
		// (22s on a 64KB single line) while THIS SUBTEST reported normal growth —
		// the concrete miss that motivated hardening the whole file.
		gen:             genDOB,
		threshold:       5 * time.Second,
		minMatches:      300,
		wantMatchGrowth: true,
	},
	{
		name:            "driverslicense",
		new:             func() validatorUnderTest { return driverslicense.NewValidator() },
		unit:            "driver license D1234567 dl 12345678 licence D123-4567-8901 dmv A9876543 ",
		minMatches:      1000,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name: "intellectualproperty",
		new:  func() validatorUnderTest { return intellectualproperty.NewValidator() },
		gen:  genIntellectualProperty,
		// This validator CONSOLIDATES: thousands of candidates become one
		// aggregate finding, so a match-growth requirement would be wrong here.
		// The floor still holds the timing honest (1 real finding, not 0).
		threshold:  5 * time.Second,
		minMatches: 1,
	},
	{
		name:            "medicalid",
		new:             func() validatorUnderTest { return medicalid.NewValidator() },
		unit:            "npi 1234567893 dea FC9825487 mbi 1EG4-TE5-MK73 mrn 8432197 patient record ",
		minMatches:      1000,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name:            "otp",
		new:             func() validatorUnderTest { return otp.NewValidator() },
		unit:            "2fa secret K5CUWY3ZNRXW4Z3T totp KRUGKIDROVUWG2ZA backup code abcd-efgh-1234 ",
		minMatches:      800,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name:            "passport",
		new:             func() validatorUnderTest { return passport.NewValidator() },
		unit:            "passport 512345678 travel document L8837362 visa passport no 987654321 ",
		minMatches:      500,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
	{
		name: "personname",
		new:  func() validatorUnderTest { return personname.NewValidator() },
		// The old unit repeated four names -> 4 matches at every size.
		gen:             genPersonName,
		minMatches:      300,
		wantMatchGrowth: true,
		// personname and secrets are the heaviest validators per byte
		// (dictionary lookups per candidate token; entropy + multi-pattern
		// secret scanning). They scale LINEARLY — the ratio check below is the
		// true O(n^2) guard and holds for them — but their linear constant is
		// large enough that the 128KB 4x input runs ~6s on the slow, shared
		// macos CI runner (well under 100ms locally). A 15s absolute ceiling
		// keeps a genuine quadratic blowup (which would be many tens of
		// seconds on this input) failing loudly while tolerating runner noise.
		threshold: 15 * time.Second,
	},
	{
		name:            "secrets",
		new:             func() validatorUnderTest { return secrets.NewValidator() },
		unit:            "AWS_KEY=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghij1234567890abcdef ",
		minMatches:      500,
		wantMatchGrowth: true,
		threshold:       15 * time.Second, // see personname note: heavy-but-linear
	},
	{
		name: "socialmedia",
		// This validator is CONFIG-GATED: NewValidator alone leaves
		// patternsConfigured false, so ValidateContent returns immediately at
		// validator.go's "patterns configured" check. The old subtest measured
		// that early return — a ~42ns no-op that could never fail. Configure it
		// from the shipped config.yaml so the real scan runs.
		new: newConfiguredSocialMedia,
		// URL-shaped profiles, one per line. Two constraints, both measured:
		//   - "@handle" text does NOT match: the shipped config's handle regex is
		//     PCRE and RE2 rejects it, so it is silently dropped (tracked
		//     separately). Only URL patterns actually fire.
		//   - Both sizes must sit on the SAME side of maxClusterMatches (1000),
		//     because above it clustering is skipped. Straddling the cap compared
		//     two different code paths and made the big input measure 4x FASTER
		//     than the base (226ms at 400 matches vs 213ms at 1600). These sizes
		//     stay above it, where the path is linear.
		gen: genSocialMediaProfile,
		// 1200 base / 4800 big: both above maxClusterMatches, per the note above.
		baseReps:        1200,
		threshold:       5 * time.Second,
		minMatches:      1100,
		wantMatchGrowth: true,
	},
	{
		name:            "vin",
		new:             func() validatorUnderTest { return vin.NewValidator() },
		unit:            "vin 1HGCM82633A004352 vehicle 2FMDK3GC4BBA12345 vin JH4KA7561PC008269 ",
		minMatches:      500,
		wantMatchGrowth: true,
		threshold:       5 * time.Second,
	},
}

// TestValidatorComplexityIsSubQuadratic checks that a 4x input step does not roughly sixteen-fold
// the work any validator does. maxGrowthRatio is the limit: linear is ~4x, quadratic ~16x.
//
// 8.0, unchanged in value but now resting on a different measurement, because the statistic
// underneath it changed. It is a ratio of MINIMUM CPU readings with GC disabled (see growthRatio
// and withGCOff) rather than a median of wall-clock ratios, and that is what makes one number
// viable on a loaded runner.
//
// Why the old basis had to be replaced (#579): under 28 external busy-loop processes on 14 CPUs
// with -race, the wall-clock statistic INVERTED — a genuine O(n^2) validator read 9.94x while a
// single-pass one read 10.20x. The populations did not merely overlap; the linear reading was the
// higher of the two, and at 10.20x it is above this threshold, which is #546 exactly: the guard
// failing on correct code. No threshold can fix that, because the ordering itself was wrong. Two
// causes, both measured and both removed:
//
//   - CONTENTION inflates the base term hardest, because a short measurement is descheduled
//     proportionally more than a long one, and that drives the ratio DOWN toward passing.
//     Contention steals wall time without changing cycle count, so CPU time is immune to it and
//     getrusage(RUSAGE_SELF) excludes other processes entirely.
//   - GC is real CPU work and scales with heap, so it survives the switch of clocks. An
//     ALLOCATING linear validator read 10.04x with GC on and 3.95x with it off. Production
//     validators allocate a Match per finding and cannot avoid it, which is why GC is disabled
//     for the measurement rather than the fixtures being rewritten.
//
// The correct-code population on the new statistic, all 18 targets, -race:
//
//	3.81x - 4.60x
//
// against a genuine quadratic at 13.85x-16.15x, measured idle and under the same external load
// (13.85x loaded, 14.00x-16.15x idle — the ratio of minimums moves ~1% where the median of ratios
// moved 9% and its worst sample halved). So 8.0 sits 1.74x above the worst correct reading and
// 1.75x below the observed quadratic: symmetric margin, where the previous statistic had none.
//
// Kept from the earlier derivation because they are still true and still the reason this is one
// number rather than a per-configuration table: -race compresses a wall-clock ratio about 1.24x
// (it inflates the base 1.39x and the big term 1.11x on a reproduced dob quadratic), and #509
// reported correct readings up to 8.29x under GOMAXPROCS=1 which never reproduced here. Both were
// arguments about wall clock. The ratio is logged on every run, with the clock named, so the
// evidence for the next change is in CI output rather than inferred from a failure.
//
// The one dependency this rests on is that nothing else in this process burns CPU during a
// measurement — see TestNothingInThisPackageRunsInParallel, which enforces it.
const maxGrowthRatio = 8.0

func TestValidatorComplexityIsSubQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}

	for _, tgt := range complexityTargets {
		tgt := tgt
		t.Run(tgt.name, func(t *testing.T) {
			// Two single-line inputs: base and 4x. A single long line is the
			// worst case for the per-line rescan pattern.
			baseReps := 400
			if tgt.baseReps > 0 {
				baseReps = tgt.baseReps
			}
			baseLine := buildComplexityInput(tgt.unit, tgt.gen, baseReps)
			bigLine := buildComplexityInput(tgt.unit, tgt.gen, baseReps*4) // 4x size

			// Absolute ceiling: even the big input must finish quickly. With
			// bounded execution and linear scanning this is generous; an O(n^2)
			// blowup on a dense line would blow past it.
			// ONE measurement drives all three assertions below — ceiling, non-vacuity and
			// growth. Timing each validator separately for the ceiling doubled the cost of the
			// slowest test in the repo for no extra information.
			g := growthRatio(t, tgt.new, baseLine, bigLine)
			tBase, nBase := g.baseWallMin, g.baseMatches
			tBig, nBig := g.bigWallMin, g.bigMatches

			// NON-VACUITY FLOOR. Both assertions below are ceilings or ratios, and
			// both pass trivially when the validator matches nothing: a reject path
			// is fast and its ratio is noise. Three subtests in this file were
			// silently in that state (ipaddress and socialmedia matched nothing;
			// dob matched a flat 4) while dob was quadratic in production. Assert
			// the measurement had something to measure BEFORE trusting the timing.
			if tgt.minMatches > 0 {
				if nBase < tgt.minMatches {
					t.Fatalf("%s: base input produced %d matches, want >= %d — the timing "+
						"assertions below would be measuring a reject path, not the scan",
						tgt.name, nBase, tgt.minMatches)
				}
				if nBig < tgt.minMatches {
					t.Fatalf("%s: 4x input produced %d matches, want >= %d — a validator that "+
						"stops matching as input grows makes a timing ceiling meaningless",
						tgt.name, nBig, tgt.minMatches)
				}
			}
			if tgt.wantMatchGrowth && nBig <= nBase {
				t.Errorf("%s: 4x input produced %d matches vs %d at base — the match count "+
					"must grow with the input, otherwise per-match cost is constant and a "+
					"per-match O(n^2) path passes the ratio check below",
					tgt.name, nBig, nBase)
			}

			// The absolute ceiling is scaled when the race detector is active.
			//
			// CI runs this suite with -race, which instruments every memory access
			// and costs 10-20x on scan-heavy code. Measured on the socialmedia
			// target: 0.33s without -race, 4.97s with it, against a 5s ceiling —
			// passing by 30ms on a developer machine and failing at 7-13s on the
			// slower CI runners. That is a property of the instrumentation, not an
			// O(n^2) regression.
			//
			// The RATIO check below is the assertion that actually detects quadratic
			// behaviour. It is NOT unaffected by -race, which is what this comment
			// claimed until #509 measured it: -race inflates the base term more than the
			// big one (1.39x against 1.11x on a reproduced dob quadratic), so the growth
			// factor COMPRESSES by about 1.24x. maxGrowthRatio accounts for that. Keeping
			// a tight ceiling for normal runs preserves its value as a backstop against a
			// pathological absolute blow-up.
			ceiling := tgt.threshold
			if raceDetectorEnabled {
				ceiling *= raceCeilingMultiplier
			}
			if tBig > ceiling {
				t.Errorf("%s: 4x input took %v (> %v ceiling%s) — possible O(n^2) regression on a single long line",
					tgt.name, tBig, ceiling, raceNote())
			}

			// Relative growth: 4x input under linear scaling is ~4x time; under
			// quadratic it is ~16x. Fail above 12x (generous headroom for
			// constant factors, GC, and measurement noise on small absolute
			// times). Only meaningful when the base time is large enough to
			// measure; below 2ms the ratio is dominated by noise.
			{
				ratio, gBase, gBig, clock, samples := g.ratio, g.baseMin, g.bigMin, g.clock, g.samples
				// Logged on every run, not only on failure. This guard governs 18 targets from
				// one threshold, and the margin between the correct and regressed populations is
				// the thinnest in the repo (#509) — so the readings need to be visible in CI
				// output rather than reconstructable only from a failure.
				t.Logf("%s: 4x input took %.2fx longer on the %s clock (min base=%v big=%v over %d pairs %s; ceiling pair wall base=%v big=%v)%s",
					tgt.name, ratio, clock, gBase, gBig, growthPairs, formatRatios(samples), tBase, tBig, raceNote())

				// See growthRatio for why this is a ratio of minimum CPU readings rather
				// than one wall-clock pair.
				if ratio > maxGrowthRatio {
					t.Errorf("%s: 4x input took %.1fx longer on the %s clock (minimum of %d pairs, "+
						"base=%v big=%v, per-pair %v) — superlinear growth suggests an O(n^2) regression",
						tgt.name, ratio, clock, growthPairs, gBase, gBig, formatRatios(samples))
				}
			}
		})
	}
}

// minMeasurableCPU is the smallest CPU reading this file will divide by.
//
// getrusage reports microseconds and GetProcessTimes 100ns ticks, but both accumulate at
// timer-tick granularity — 15.6ms on Windows by default. Dividing two readings near that
// granularity produces a quantised ratio, which is the noise regime the wall-clock version of
// this guard already had to escape. Callers fall back to wall clock below this and SAY SO, so a
// platform with a coarse CPU clock cannot silently switch the ratio assertion off.
const minMeasurableCPU = 2 * time.Millisecond

// reading is one ValidateContent measurement.
//
// Both clocks are kept because the two assertions in this file need different ones. The absolute
// ceiling is a claim about how long a user waits, which is wall clock by definition. The growth
// ratio is a claim about algorithmic complexity, and wall clock cannot carry it on a contended
// machine: measured under 28 busy-loops on 14 CPUs with -race, a genuine O(n^2) validator read
// 9.94x while a linear one read 10.20x — the populations INVERTED (#579). Contention steals wall
// time without changing how many cycles the work costs, so CPU time separates them: 14.86x
// against 4.00x on the same run.
type reading struct {
	wall    time.Duration
	cpu     time.Duration
	matches int
}

// timeValidate runs ValidateContent once and returns both clocks AND the match count.
//
// The count is not decoration: it is what the caller uses to prove the duration measured real
// scanning work rather than an early return. Discarding it (as this helper used to) is how three
// subtests in this file became no-ops without any test failing.
//
// GC is NOT disabled here. It is disabled by the caller across a whole group of readings — see
// withGCOff — because SetGCPercent triggers a collection when it restores, and paying that
// between a base and a big reading would land inside the very interval being measured.
func timeValidate(t *testing.T, v validatorUnderTest, content string) reading {
	t.Helper()

	cpuBefore, err := processCPUTime()
	if err != nil {
		t.Fatalf("processCPUTime: %v", err)
	}
	start := time.Now()
	matches, vErr := v.ValidateContent(content, "<complexity>")
	elapsed := time.Since(start)
	cpuAfter, err := processCPUTime()
	if err != nil {
		t.Fatalf("processCPUTime: %v", err)
	}
	if vErr != nil {
		t.Fatalf("ValidateContent error: %v", vErr)
	}
	return reading{wall: elapsed, cpu: cpuAfter - cpuBefore, matches: len(matches)}
}

// withGCOff runs fn with the garbage collector disabled, then restores it.
//
// Measured under load with -race: an ALLOCATING linear validator read 10.04x with GC on and
// 3.95x with it off, against a true value of 4.0x. The inflation is GC work, which is real CPU
// time and therefore is not removed by switching clocks — and it scales with heap size, so it
// hits the big reading harder than the base one and inflates the ratio. Production validators
// allocate a Match per finding and cannot be rewritten to avoid it, so disabling GC for the
// measurement is what makes the ratio mean what it claims on real code.
//
// A collection is forced on the way out. Without it the heap that accumulated while GC was off
// is carried into the next target, which is how 18 subtests in sequence would otherwise turn a
// bounded measurement into growing memory pressure.
func withGCOff(fn func()) {
	previous := debug.SetGCPercent(-1)
	defer func() {
		debug.SetGCPercent(previous)
		runtime.GC()
	}()
	fn()
}

// buildComplexityInput scales a target's input to reps repetitions, from either a
// static unit or a per-index generator. Exactly one of the two is set; the
// non-vacuity test enforces that.
func buildComplexityInput(unit string, gen func(int) string, reps int) string {
	if gen == nil {
		return strings.Repeat(unit, reps)
	}
	var sb strings.Builder
	for i := 0; i < reps; i++ {
		sb.WriteString(gen(i))
	}
	return sb.String()
}

// growthPairs is how many base/big pairs growthRatio measures.
//
// 2, and the number is a cost decision made against measured stability rather than a guess.
// Minimums converge fast because contamination only ever ADDS: under 28 external busy-loop
// processes on 14 CPUs the minimum base reading was 3.727ms against 3.703ms idle, a 0.6%
// difference over 9 pairs. So the marginal sample buys very little, while each one costs 5x a
// base reading (the 4x input dominates). Measured on all 18 targets with -race:
//
//	pairs   suite time   worst correct-code reading
//	1 (old)     22.4s    n/a — a single reading is what #546 and #579 are about
//	2           45.8s    4.60x
//	3           69.8s    4.54x
//
// Going from 2 to 3 moves the worst reading by 0.06x for another 24 seconds, so 2 it is. Two is
// still strictly more than one bad sample can defeat, which is the property that matters.
const growthPairs = 2

// growth is everything one growthRatio call measured.
//
// The wall-clock minima are carried alongside the growth clock because the absolute ceiling is a
// claim about elapsed time, not cycles, and reusing these readings is what keeps the guard from
// timing each validator twice. Minima rather than a single reading there too: a contended sample
// would otherwise trip the ceiling on code that is fast.
type growth struct {
	ratio                   float64
	baseMin, bigMin         time.Duration
	baseWallMin, bigWallMin time.Duration
	baseMatches, bigMatches int
	clock                   string
	samples                 []float64
}

// growthRatio measures both inputs growthPairs times and returns bigMin/baseMin.
//
// THE MINIMUM, NOT THE MEDIAN, AND THAT IS THE POINT. getrusage reports CPU for the whole
// process, so a short measurement also collects whatever the runtime's other threads burned
// during it — sysmon, the race detector's background work, and any GC that a previous target
// left pending. That contamination is strictly ADDITIVE and grows with how long the measurement
// is descheduled, so it inflates the base term hardest and drives the ratio DOWN, toward passing.
// The minimum over a few trials is the least-contaminated estimate of each term, and because the
// error is one-signed the minimum cannot overshoot the true cost.
//
// Measured, -race, quadratic against linear synthetics:
//
//	                     median of ratios          ratio of minimums
//	quadratic, idle      13.66x (13.05-14.17)      14.17x
//	quadratic, loaded    12.48x ( 7.24-15.19)      14.00x
//	linear, idle          3.65x ( 2.41- 4.11)       3.75x
//	linear, loaded        2.92x ( 1.67- 3.73)       3.18x
//
// The ratio of minimums moves 1.2% between idle and loaded on the quadratic where the median of
// ratios moves 9% and its worst sample halves. That is what makes one threshold viable.
//
// There is no trigger-then-confirm split any more. The old design took ONE pair and re-measured
// only when it exceeded the threshold, which is a false-negative hole: a genuine quadratic whose
// single reading was contaminated down to 7.17x — measured, #579 — never entered confirmation and
// the guard passed it. Measuring the same way every time costs a few seconds and removes that.
func growthRatio(t *testing.T, newV func() validatorUnderTest, baseLine, bigLine string) growth {
	t.Helper()

	// No separate warm-up pair. Taking a MINIMUM already discards a cold reading, because a
	// first-touch cost that inflates a sample makes it the maximum, not the minimum. The
	// wall-clock version of this needed an explicit warm-up only because a median gives the cold
	// sample a vote.
	var bases, bigs []reading
	for i := 0; i < growthPairs; i++ {
		var b, g reading
		withGCOff(func() {
			b = timeValidate(t, newV(), baseLine)
			g = timeValidate(t, newV(), bigLine)
		})
		bases = append(bases, b)
		bigs = append(bigs, g)
	}

	// Choose the clock from the least-contaminated base reading, so a coarse CPU clock is
	// detected on the cleanest sample rather than on an unlucky one.
	useCPU := true
	for _, b := range bases {
		if b.cpu < minMeasurableCPU {
			useCPU = false
			break
		}
	}
	clock := "wall"
	if useCPU {
		clock = "cpu"
	}
	pick := func(r reading) time.Duration {
		if useCPU {
			return r.cpu
		}
		return r.wall
	}

	g := growth{clock: clock, baseMatches: bases[0].matches, bigMatches: bigs[0].matches}
	g.baseMin, g.bigMin = pick(bases[0]), pick(bigs[0])
	g.baseWallMin, g.bigWallMin = bases[0].wall, bigs[0].wall
	for i := range bases {
		if d := pick(bases[i]); d < g.baseMin {
			g.baseMin = d
		}
		if d := pick(bigs[i]); d < g.bigMin {
			g.bigMin = d
		}
		if bases[i].wall < g.baseWallMin {
			g.baseWallMin = bases[i].wall
		}
		if bigs[i].wall < g.bigWallMin {
			g.bigWallMin = bigs[i].wall
		}
		if db := pick(bases[i]); db > 0 {
			g.samples = append(g.samples, float64(pick(bigs[i]))/float64(db))
		}
	}
	if g.baseMin <= 0 {
		t.Fatalf("every base reading was zero on the %s clock; the ratio cannot be computed", clock)
	}
	g.ratio = float64(g.bigMin) / float64(g.baseMin)
	return g
}

// formatRatios renders ratios for a failure message at the precision that matters.
func formatRatios(rs []float64) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%.2fx", r))
	}
	return "[" + strings.Join(parts, " ") + "]"
}
