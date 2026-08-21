// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
)

// The complexity guard in complexity_guard_test.go covers 18 validators and
// nothing else: every target calls validator.ValidateContent directly, so the
// timing reflects a validator's own scanning cost. That deliberate scoping left
// the REDACTION path unguarded, and redaction is where the tool's security value
// is realised — a reported finding that is not redacted is a cleartext leak.
//
// The gap was not theoretical. Redaction was quadratic in
// (matches x content bytes) while scanning the same fixtures stayed linear:
// cost grew ~4x per input doubling, reaching ~78s on roughly 1MB of dense
// matches, against a 100MB MaxFileSize ceiling. Nothing failed.
//
// Two families are needed, and the second is the one that matters:
//
//   - growing: matches AND content grow together. This is the shape a user
//     hits, but it cannot distinguish O(m) from O(m*n) — both look superlinear
//     in total input.
//   - fixedMatches: match count held CONSTANT while content grows. Cost here
//     must stay proportional to content, not to content x matches. This is the
//     family that isolates a per-match whole-document rescan.

// Why this file asserts ABSOLUTE cost and not a growth RATIO.
//
// A 4x-input ratio is the right assertion for the validator guard, and it was the
// first thing tried here. It does not work for redaction, and the measurements
// say so plainly. For the fixture pair below, on one machine:
//
//	no -race   9.3, 12.6, 12.7, 12.5, 12.9
//	-race      10.3, 9.5, 11.9, 12.2, 11.8
//	CI runner  16.6
//
// and the KNOWN-QUADRATIC code before the per-match rescan was removed measured
// 12.6-13.7. A threshold high enough not to flake on 16.6 sits above the very
// behaviour it is supposed to catch, so it would have zero detection power while
// still failing builds at random. The first version of this test was set at 16.0
// and did exactly that: it passed on the quadratic code (vacuous) and then failed
// CI at 16.6 (flaky) — the worst of both.
//
// So: the ratio is LOGGED for a human, and the assertion is an absolute ceiling,
// which is immune to noise in the base measurement and still catches an
// order-of-magnitude regression. Redaction remains superlinear; nothing here
// should be read as proving otherwise.
const (
	// redactionAbsoluteCeiling bounds the wall time to redact the big fixture
	// (2000 matches). Measured ~150-250ms locally and ~440ms on a slow shared
	// runner, so this tolerates a heavily loaded machine while failing on a
	// 20-30x blowup. Scaled by raceCeilingMultiplier under -race.
	redactionAbsoluteCeiling = 8 * time.Second

	// fixedMatchAbsoluteCeiling bounds the fixed-match family, whose big case is
	// smaller (200 matches over 8x content, measured well under 100ms).
	fixedMatchAbsoluteCeiling = 5 * time.Second
)

// buildRedactionFixture returns text with n distinct SSNs, one per line, plus
// the matches a scan would report for them.
//
// The values are DISTINCT by construction. Identical repeated values would let
// a redactor replace every occurrence in one pass and defeat the measurement —
// the same trap complexity_generators_test.go documents for the validator half.
func buildRedactionFixture(n int, fillerLines int) (string, []detector.Match) {
	var b strings.Builder
	matches := make([]detector.Match, 0, n)
	for i := 0; i < n; i++ {
		// Distinct, and none of these are real: area group 900+ is unassigned.
		ssn := fmt.Sprintf("9%02d-%02d-%04d", i%100, (i/100)%100, i%10000)
		line := fmt.Sprintf("record %d ssn %s", i, ssn)
		b.WriteString(line)
		b.WriteByte('\n')
		matches = append(matches, detector.Match{
			Text:       ssn,
			Type:       "SSN",
			Confidence: 100,
			LineNumber: i + 1,
			Context:    detector.ContextInfo{FullLine: line},
		})
	}
	for i := 0; i < fillerLines; i++ {
		b.WriteString("filler line carrying no sensitive value whatsoever\n")
	}
	return b.String(), matches
}

// timeRedact redacts and returns the elapsed time plus the number of redaction
// mappings produced. The mapping count is the non-vacuity signal: a redactor
// that fails to locate its matches is fast and produces nothing.
//
// It goes through the exported RedactDocument (real files) rather than the
// unexported text-level helper: the public entry point is what the CLI uses, and
// a timing guard should measure the path that ships. File I/O adds a constant
// that cancels in the ratio.
// buildRedactionFixtureRepeated returns text with n distinct SSNs each emitted TWICE, plus the
// matches a scan would report for all 2n occurrences.
//
// This is the shape buildRedactionFixture deliberately excludes, and excluding it is what let a
// quadratic hide from the guard for so long. Its comment explains the omission — repeated values
// "would let a redactor replace every occurrence in one pass and defeat the measurement" — which is
// true of the plaintext REPLACEMENT step and false of the POSITION CORRELATION that runs first.
//
// Correlation scores an exact match 0.95 for a unique value but 0.95*(0.5+0.5/n) for n occurrences,
// which is 0.7125 at n=2 — below the 0.8 confidenceThreshold. So every duplicated value fell
// through to the fuzzy matcher, which slid over the whole document per match. Measured at HEAD
// before the fix, at equal file size and equal finding count:
//
//	fixture   bytes   duplicated   distinct
//	n=75      3.9KB      0.89s      0.07s
//	n=150     7.9KB     19.92s      0.11s
//	n=300    16.0KB    128.49s      0.10s
//
// Quadratic against a flat control, and 16x past this file's 8s ceiling at 16KB. A log or CSV that
// repeats any value is the ordinary case, not a hostile one (#376).
func buildRedactionFixtureRepeated(n int) (string, []detector.Match) {
	var b strings.Builder
	matches := make([]detector.Match, 0, 2*n)
	line := 0
	for i := 0; i < n; i++ {
		// Distinct across i, and none are real: area group 900+ is unassigned.
		ssn := fmt.Sprintf("9%02d-%02d-%04d", i%100, (i/100)%100, i%10000)
		for _, tag := range [2]string{"record", "repeat"} {
			line++
			text := fmt.Sprintf("%s %d ssn %s", tag, i, ssn)
			b.WriteString(text)
			b.WriteByte('\n')
			matches = append(matches, detector.Match{
				Text:       ssn,
				Type:       "SSN",
				Confidence: 100,
				LineNumber: line,
				Context:    detector.ContextInfo{FullLine: text},
			})
		}
	}
	return b.String(), matches
}

// A value repeated in the document must not cost more than a distinct one.
//
// Asserted against the same redactionAbsoluteCeiling the rest of this file uses, and paired with a
// DISTINCT control of the same size and match count so the assertion cannot pass by the whole
// redactor being slow or the machine being fast. timeRedact's leak floor applies to every sample,
// so an "optimisation" that skips matches fails instead of looking quick.
func TestRedactionComplexity_RepeatedValues(t *testing.T) {
	const n = 300 // 600 matches, ~16KB — 128s at HEAD before the fix

	repeatedText, repeatedMatches := buildRedactionFixtureRepeated(n)
	distinctText, distinctMatches := buildRedactionFixture(2*n, 0)

	repeated, _ := timeRedact(t, repeatedText, repeatedMatches)
	distinct, _ := timeRedact(t, distinctText, distinctMatches)

	if repeated > redactionAbsoluteCeiling {
		t.Errorf("redacting %d repeated-value matches over %d bytes took %v, ceiling %v — a "+
			"document that repeats a value routes every match through the whole-document fuzzy "+
			"slide (#376). The distinct control of the same shape took %v",
			len(repeatedMatches), len(repeatedText), repeated, redactionAbsoluteCeiling, distinct)
	}

	// The comparison is the real signal: the two fixtures are the same size and carry the same
	// number of matches, so any large gap is the duplicate-value path costing extra rather than
	// redaction being slow in general.
	if distinct > 0 && repeated > 20*distinct && repeated > 500*time.Millisecond {
		t.Errorf("repeated values took %v against %v for the same size and match count (%.0fx) — "+
			"the duplicate path is doing work the distinct path is not", repeated, distinct,
			float64(repeated)/float64(distinct))
	}
}

func timeRedact(t *testing.T, text string, matches []detector.Match) (time.Duration, int) {
	t.Helper()

	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(text), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	outPath := filepath.Join(dir, "out.txt")

	r := plaintext.NewPlainTextRedactor(nil, nil)
	start := time.Now()
	res, err := r.RedactDocument(in, outPath, matches, redactors.RedactionSimple)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read redacted output: %v", err)
	}
	out := string(raw)
	mappings := res.RedactionMap
	// Correctness floor, asserted on every timing sample: a redaction that
	// leaves the value in place is not a faster redaction, it is a leak. This
	// is what stops an "optimisation" that skips matches from passing.
	for i := range matches {
		if strings.Contains(out, matches[i].Text) {
			t.Fatalf("redacted output still contains match %d of %d (type %s, line %d) — "+
				"a timing target must never accept a redaction that leaks",
				i, len(matches), matches[i].Type, matches[i].LineNumber)
		}
	}
	return elapsed, len(mappings)
}

// TestRedactionComplexity_GrowingMatchesAndContent is the user-facing shape.
func TestRedactionComplexity_GrowingMatchesAndContent(t *testing.T) {
	const (
		baseN = 500
		bigN  = 2000 // 4x
	)

	baseText, baseMatches := buildRedactionFixture(baseN, 0)
	bigText, bigMatches := buildRedactionFixture(bigN, 0)

	tBase, nBase := timeRedact(t, baseText, baseMatches)
	tBig, nBig := timeRedact(t, bigText, bigMatches)

	// NON-VACUITY: assert the measurement had something to measure. Every
	// assertion below is a ratio or a ceiling, and all of them pass trivially
	// when nothing is redacted.
	if nBase < baseN {
		t.Fatalf("base input produced %d redaction mappings, want %d — the timing "+
			"assertions would be measuring a path that skips matches, not redaction",
			nBase, baseN)
	}
	if nBig < bigN {
		t.Fatalf("4x input produced %d redaction mappings, want %d — a redactor that "+
			"stops redacting as input grows makes a timing ratio meaningless", nBig, bigN)
	}
	if nBig <= nBase {
		t.Errorf("4x input produced %d mappings vs %d at base — the redacted count must "+
			"grow with the input, otherwise per-match cost is constant and a per-match "+
			"O(n^2) path passes the ratio check below", nBig, nBase)
	}

	// The ratio is reported but NOT asserted, and that is deliberate — see
	// redactionRatioCeiling. Measured spread on one machine for this exact
	// fixture pair: 9.3-12.9 without -race, 9.5-12.2 with it, and 16.6 on a CI
	// runner. A threshold that accommodates 16.6 cannot detect the ~13x that the
	// known-quadratic code produced, so the assertion would be pure flake with no
	// detection power. Logging keeps the number visible for a human comparing
	// runs.
	if tBase > 2*time.Millisecond {
		t.Logf("4x input redaction ratio: %.1fx (base=%v big=%v) — informational; "+
			"redaction is still superlinear, see the absolute ceiling below",
			float64(tBig)/float64(tBase), tBase, tBig)
	}

	// ABSOLUTE ceiling instead. This is what a ratio cannot give: it is immune to
	// the noise in tBase, it fails on a genuine order-of-magnitude regression,
	// and it is scaled for the race detector exactly as the validator guard does.
	//
	// Sized from measurement with real headroom: the fixture costs ~150-250ms
	// here and ~440ms on a slow shared runner, so 8s catches a 20-30x blowup
	// while tolerating a heavily loaded machine.
	ceiling := redactionAbsoluteCeiling
	if raceDetectorEnabled {
		ceiling *= raceCeilingMultiplier
	}
	if tBig > ceiling {
		t.Errorf("redacting %d matches took %v (> %v ceiling%s) — a regression of this "+
			"size means redaction cost is scaling with (matches x content) again",
			bigN, tBig, ceiling, raceNote())
	}
}

// TestRedactionComplexity_FixedMatchesGrowingContent is the family that isolates
// a per-match whole-document rescan: the match count never changes, so any
// growth beyond the content ratio is per-match work over the whole document.
func TestRedactionComplexity_FixedMatchesGrowingContent(t *testing.T) {
	const (
		matchCount  = 200
		baseFiller  = 1000
		bigFiller   = 8000 // 8x the filler
		contentRise = 8.0
	)

	baseText, matches := buildRedactionFixture(matchCount, baseFiller)
	bigText, _ := buildRedactionFixture(matchCount, bigFiller)

	tBase, nBase := timeRedact(t, baseText, matches)
	tBig, nBig := timeRedact(t, bigText, matches)

	// NON-VACUITY: both runs must actually redact all of the same matches.
	if nBase < matchCount || nBig < matchCount {
		t.Fatalf("mappings base=%d big=%d, want >= %d for both — the ratio below is "+
			"meaningless if either run skipped matches", nBase, nBig, matchCount)
	}

	// Guard the premise: the match count MUST be identical across the two runs,
	// otherwise this is just the growing family with extra steps.
	if nBase != nBig {
		t.Fatalf("mappings differ between runs (base=%d big=%d) — this family is only "+
			"meaningful with the match count pinned", nBase, nBig)
	}

	// Ratio logged, not asserted — same reasoning as the growing family.
	if tBase > 2*time.Millisecond {
		t.Logf("%.0fx more content at a FIXED %d matches: %.1fx longer (base=%v big=%v) "+
			"— informational", contentRise, matchCount, float64(tBig)/float64(tBase), tBase, tBig)
	}

	ceiling := fixedMatchAbsoluteCeiling
	if raceDetectorEnabled {
		ceiling *= raceCeilingMultiplier
	}
	if tBig > ceiling {
		t.Errorf("%.0fx more content at a FIXED %d matches took %v (> %v ceiling%s) — with "+
			"the match count pinned, a blowup of this size means each match is being "+
			"located by scanning the whole document again",
			contentRise, matchCount, tBig, ceiling, raceNote())
	}
}
