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

const (
	// redactionRatioCeiling bounds the growth factor for a 4x input. Linear is
	// ~4x; quadratic is ~16x.
	//
	// MEASURED HONESTLY: on the code this test was written against, the growing
	// family ratio is 10.0-13.2 and the pre-fix ratio was 12.6-13.7. Those
	// overlap, so a ratio ceiling CANNOT distinguish "quadratic" from "quadratic
	// with a better constant" at these sizes — it can only catch a NEW
	// order-of-magnitude regression. The ceiling is therefore set above the
	// current behaviour deliberately: it is a regression backstop, not a proof
	// of linearity, and redaction is still superlinear. Do not read a pass here
	// as "redaction is linear".
	redactionRatioCeiling = 16.0

	// fixedMatchRatioCeiling applies with the match count PINNED, so cost should
	// track content only. Measured 4.8-6.3x for an 8x content rise (pre-fix
	// 5.4-6.9x), i.e. sublinear in content because per-match work dominates.
	fixedMatchRatioCeiling = 10.0
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

	if tBase > 2*time.Millisecond {
		ratio := float64(tBig) / float64(tBase)
		if ratio > redactionRatioCeiling {
			t.Errorf("4x input took %.1fx longer to redact (base=%v big=%v) — superlinear "+
				"growth suggests redaction is O(matches x content). Scanning the same "+
				"fixtures is linear, so this is a redaction-side regression",
				ratio, tBase, tBig)
		}
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

	if tBase > 2*time.Millisecond {
		ratio := float64(tBig) / float64(tBase)
		if ratio > fixedMatchRatioCeiling {
			t.Errorf("%.0fx more content at a FIXED %d matches took %.1fx longer "+
				"(base=%v big=%v) — cost is scaling with content x matches, which means "+
				"each match is being located by scanning the whole document",
				contentRise, matchCount, ratio, tBase, tBig)
		}
	}
}
