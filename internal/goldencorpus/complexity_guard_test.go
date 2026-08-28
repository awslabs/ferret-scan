// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
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

// TestValidatorComplexityIsSubQuadratic checks that doubling input size does not
// roughly quadruple runtime for any validator. It measures at two sizes and
// asserts the growth ratio stays well under the quadratic expectation.
// maxGrowthRatio is the growth-ratio limit for a 4x input step. Linear is ~4x, quadratic ~16x.
//
// 8.0, measured. It replaces 12.0, and the comment above the absolute ceiling used to justify
// that number by asserting "-race inflates both measurements equally, so the growth factor is
// preserved". That is false (#509).
//
// Measured on the dob target by defeating its line-global keyword hoist
// (internal/validators/dob/validator.go, the fix its own comment at :157-167 describes), which
// restores a genuine O(n^2):
//
//	                       base       big      ratio
//	quadratic, no -race   ~99ms     ~1.54s    15.4-15.6x
//	quadratic, -race     ~138ms     ~1.72s    12.4-12.7x
//
// -race inflates the BASE 1.39x and the big term only 1.11x, so the ratio COMPRESSES ~1.24x.
// Against 12.0 that left 1.03x of headroom over the very defect this guard exists to catch:
// all four runs failed, but by 0.4-0.7x. The same compression was measured independently on the
// detector's line-span guard (7.3x -> 5.6x), so it is a property of the instrumentation and not
// of one target. CI runs this suite with -race, so that is the configuration that matters.
//
// The correct-code population, 144 readings over all 18 targets and three configurations:
//
//	plain                54 readings   2.97-4.55x
//	-race                54 readings   3.59-4.68x
//	-race GOMAXPROCS=1   36 readings   3.22-4.58x
//
// So 8.0 clears every margin this repo aims for, in both configurations:
//
//	              below   above
//	plain         1.76x   1.93x
//	-race         1.71x   1.55x
//
// against 12.0's 2.56x below and 1.03x above. No -race conditional is needed: one number does
// better in both configurations than 12.0 did in either.
//
// #509 reported correct readings up to 8.29x on cloudresources under GOMAXPROCS=1, which would
// leave no room at 8.0. That did NOT reproduce here in 144 readings — the worst anywhere was
// 4.68x, and cloudresources specifically read 4.00-4.20x. Recorded because it is the one figure
// behind this number I could not confirm: if a runner does produce 8x on correct code, the ratio
// is logged on every run now, so the evidence will be in the output rather than inferred from a
// failure.
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
			tBase, nBase := timeValidate(t, tgt.new(), baseLine)
			tBig, nBig := timeValidate(t, tgt.new(), bigLine)

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
			if tBase > 2*time.Millisecond {
				ratio := float64(tBig) / float64(tBase)
				// Logged on every run, not only on failure. This guard governs 18 targets from
				// one threshold, and the margin between the correct and regressed populations is
				// the thinnest in the repo (#509) — so the readings need to be visible in CI
				// output rather than reconstructable only from a failure.
				t.Logf("%s: 4x input took %.2fx longer (base=%v big=%v)%s",
					tgt.name, ratio, tBase, tBig, raceNote())
				if ratio > maxGrowthRatio {
					t.Errorf("%s: 4x input took %.1fx longer (base=%v big=%v) — superlinear growth suggests an O(n^2) regression",
						tgt.name, ratio, tBase, tBig)
				}
			}
		})
	}
}

// timeValidate runs ValidateContent once and returns the wall-clock duration AND
// the match count. The count is not decoration: it is what the caller uses to
// prove the duration measured real scanning work rather than an early return.
// Discarding it (as this helper used to) is how three subtests in this file
// became no-ops without any test failing.
func timeValidate(t *testing.T, v validatorUnderTest, content string) (time.Duration, int) {
	t.Helper()
	start := time.Now()
	matches, err := v.ValidateContent(content, "<complexity>")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	return elapsed, len(matches)
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
