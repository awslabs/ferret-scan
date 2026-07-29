// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"fmt"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/validators/socialmedia"
)

// Distinct-value generators for the complexity guard.
//
// WHY THESE EXIST. The guard scales its input by repeating a unit and comparing
// runtime at two sizes. If the unit is repeated VERBATIM, every validator that
// dedups candidates collapses the repeats: the match count stays flat as the
// input grows, so the per-match work never grows either — and a per-match
// quadratic measures as linear and PASSES.
//
// That is not hypothetical. The dob subtest reported normal growth on a 4x input
// while the validator was in fact quadratic: 22s on a 64KB single line, ~4x per
// doubling. Its unit held four dates, extractDates dedups per line, so the
// subtest compared 4 matches against 4 matches. Two more subtests (ipaddress,
// socialmedia) matched NOTHING at all and timed a reject path.
//
// Rules for anything added here:
//
//  1. Emit a DISTINCT value per index. Distinctness is what makes the match count
//     grow with the input, which is what the timing is supposed to be a function of.
//  2. Do not let the value space WRAP within the sizes used. A wrapped generator
//     silently caps the match count at large n, which understates growth exactly
//     where a quadratic would show up.
//  3. Emit values that actually MATCH. Every generator here is covered by
//     TestComplexityGeneratorsAreNonVacuous below, which is the standing check
//     that a validator change has not quietly turned a subtest into a no-op.
//  4. Avoid values the validator suppresses for reasons unrelated to the value
//     itself. See genPersonName for a concrete trap.

// genPublicIP emits distinct ROUTABLE addresses.
//
// The previous static unit used 203.0.113.42 (TEST-NET-3), 10.0.0.5 and
// 192.168.1.1 (RFC1918) and 8.8.8.8 (well-known resolver) — all four vetoed, so
// the subtest produced zero matches. These two /16s are ordinary public space
// that survives the vetoes. Both octets are bounded to 251 so no generated octet
// can reach 255 and form a broadcast-looking address.
func genPublicIP(i int) string {
	return fmt.Sprintf("ip 172.217.%d.%d host 151.101.%d.%d ",
		i%256, (i/256)%251, (i*7)%256, (i*13)%251)
}

// genPhone emits distinct numbers inside the reserved 555-01xx range so the
// values cannot correspond to a real subscriber. 10,000 distinct per prefix is
// far above the repetition counts used here.
func genPhone(i int) string {
	return fmt.Sprintf("call 212-555-%04d or 415-555-%04d ", i%10000, (i*3)%10000)
}

// genDOB emits distinct plausible dates of birth, each with an explicit label so
// the keyword-gated context path (the O(n^2)-prone one) is exercised rather than
// short-circuited. 12 x 28 x 110 is ~37k distinct dates, well above the sizes
// used, so the value space does not wrap.
func genDOB(i int) string {
	return fmt.Sprintf("date of birth %02d/%02d/%04d ", 1+i%12, 1+i%28, 1900+i%110)
}

// genIntellectualProperty emits a distinct legal-notice line per index. This
// validator consolidates its candidates into one aggregate finding, so the
// target asserts a floor of 1 rather than match growth; the distinct indices
// still make the CANDIDATE count (the thing whose per-item cost is under test)
// grow with the input.
func genIntellectualProperty(i int) string {
	return fmt.Sprintf("Copyright %d Acme%d. Confidential and Proprietary. Trade Secret %d. ",
		1990+i%40, i, i)
}

// genSocialMediaProfile emits distinct profile URLs, one per line.
//
// Two measured constraints shape this:
//
//   - "@handle" text does NOT match. The shipped config's handle pattern is PCRE
//     and RE2 rejects it, so it is dropped silently; only the URL patterns fire.
//     A generator built on "@alice" would be vacuous.
//   - One per line, and both measured sizes above maxClusterMatches. On a single
//     line the clustering stage is O(M^2), and it is SKIPPED above that cap — so
//     an input straddling the cap measured the big size as FASTER than the base
//     (226ms at 400 matches vs 213ms at 1600), which is a meaningless ratio.
func genSocialMediaProfile(i int) string {
	return fmt.Sprintf("follow twitter.com/user%d on socials\n", i)
}

// pnFirst and pnLast are literal name lists rather than draws from the embedded
// name database, and they deliberately EXCLUDE surnames that double as place
// words ("Lake", "River", "Brooks", "Ford", "Hill").
//
// The trap: personname applies its geographic/business/product context penalties
// LINE-GLOBALLY. One surname that is also a geo word contributes -35 to every
// other name on that line, and the total clamps at -50, which is enough to push
// a solid two-token name from 92 below the 50 emit threshold. Drawing names from
// the database produced 1164 findings at one size and ZERO at the next (the
// added surname was "Lake") — a generator that goes vacuous precisely as it
// scales. 60 x 60 = 3600 distinct combinations, above the sizes used here.
var pnFirst = []string{
	"Aaron", "Abigail", "Adam", "Adrian", "Alan", "Albert", "Alexis", "Alfred",
	"Amanda", "Amber", "Andrea", "Angela", "Anita", "Anthony", "Arthur", "Ashley",
	"Barbara", "Benjamin", "Bernard", "Beverly", "Bradley", "Brenda", "Brian", "Bruce",
	"Carl", "Carmen", "Carol", "Catherine", "Cecil", "Charles", "Cheryl", "Christina",
	"Clara", "Clifford", "Colleen", "Craig", "Crystal", "Curtis", "Cynthia", "Dale",
	"Daniel", "Darlene", "David", "Dawn", "Deborah", "Dennis", "Diana", "Dolores",
	"Donald", "Doris", "Dorothy", "Douglas", "Duane", "Dustin", "Earl", "Edith",
	"Edward", "Eileen", "Elaine", "Eleanor",
}

var pnLast = []string{
	"Abbott", "Acosta", "Adkins", "Aguilar", "Albright", "Alvarez", "Anderson", "Andrews",
	"Archer", "Arnold", "Ashby", "Atkinson", "Ayers", "Bagley", "Bailey", "Baldwin",
	"Ballard", "Barker", "Barnett", "Barrett", "Bartlett", "Bass", "Bateman", "Bauer",
	"Beasley", "Bennett", "Benson", "Bergeron", "Bishop", "Blackwell", "Blair", "Blevins",
	"Bolton", "Bond", "Booker", "Boone", "Bowden", "Bowman", "Boyer", "Bradshaw",
	"Brady", "Brennan", "Briggs", "Bryant", "Buckley", "Burgess", "Burnett", "Burton",
	"Bush", "Butler", "Byrd", "Cabrera", "Cahill", "Cain", "Caldwell", "Calhoun",
	"Callahan", "Cameron", "Campos", "Cantrell",
}

// genPersonName emits a distinct first+last pair per index. The index arithmetic
// advances both components so consecutive repetitions do not share a surname.
func genPersonName(i int) string {
	return fmt.Sprintf("contact %s %s and ",
		pnFirst[i%len(pnFirst)], pnLast[(i/len(pnFirst)+i)%len(pnLast)])
}

// newConfiguredSocialMedia returns a socialmedia validator with the shipped
// patterns loaded.
//
// SOCIAL_MEDIA is config-gated: a bare NewValidator leaves patternsConfigured
// false and ValidateContent returns an empty slice immediately. The complexity
// subtest was therefore timing that early return — a no-op that could not fail
// no matter how the scanning code changed.
func newConfiguredSocialMedia() validatorUnderTest {
	v := socialmedia.NewValidator()
	if cfg, err := config.LoadConfig(repoConfigPath); err == nil {
		v.Configure(cfg)
	}
	// A load failure leaves the validator unconfigured, which
	// TestComplexityGeneratorsAreNonVacuous reports as a vacuous target rather
	// than letting it pass silently.
	return v
}

// repoConfigPath is the shipped config, relative to this package's directory.
const repoConfigPath = "../../config.yaml"

// TestComplexityGeneratorsAreNonVacuous is the standing guard on the guard.
//
// Every timing assertion in this package is only as meaningful as the match count
// underneath it: a ceiling passes trivially if the validator stops matching, and
// a growth ratio is noise if the match count is flat. This test pins both
// properties for every target INDEPENDENTLY of the timing, so a validator change
// that silences a subtest fails here with a clear reason instead of leaving a
// green no-op behind.
//
// It runs at a small size and asserts nothing about time, so it stays fast and
// is not skipped in -short mode.
func TestComplexityGeneratorsAreNonVacuous(t *testing.T) {
	for _, tgt := range complexityTargets {
		tgt := tgt
		t.Run(tgt.name, func(t *testing.T) {
			if (tgt.unit == "") == (tgt.gen == nil) {
				t.Fatalf("%s: exactly one of unit/gen must be set", tgt.name)
			}

			const smallReps = 200
			small := buildComplexityInput(tgt.unit, tgt.gen, smallReps)
			large := buildComplexityInput(tgt.unit, tgt.gen, smallReps*2)

			mSmall, err := tgt.new().ValidateContent(small, "<generators>")
			if err != nil {
				t.Fatalf("%s: ValidateContent(small): %v", tgt.name, err)
			}
			mLarge, err := tgt.new().ValidateContent(large, "<generators>")
			if err != nil {
				t.Fatalf("%s: ValidateContent(large): %v", tgt.name, err)
			}

			if len(mSmall) == 0 {
				t.Fatalf("%s: 0 matches on %d bytes — this target is VACUOUS, so its "+
					"timing assertions measure a reject path and can never fail. Either the "+
					"input no longer matches (check vetoes/config gating) or the validator "+
					"changed.", tgt.name, len(small))
			}

			// Match growth is what makes per-match cost a function of input size.
			// Consolidating validators are exempt, and say so in the target.
			if tgt.wantMatchGrowth && len(mLarge) <= len(mSmall) {
				t.Errorf("%s: doubling the input did not increase matches (%d -> %d). The "+
					"per-match cost therefore does not grow with input size, which is what "+
					"lets a per-match quadratic pass the ratio check. Make the generator emit "+
					"distinct values, or clear wantMatchGrowth if this validator consolidates.",
					tgt.name, len(mSmall), len(mLarge))
			}
		})
	}
}
