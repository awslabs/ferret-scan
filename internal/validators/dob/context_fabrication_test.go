// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestKeywordListsAreLowercase is the precondition for containsKeywordLower.
//
// The hot path compares an already-lowercased line against these keywords with
// kwmatch.ContainsLower, which does NOT lowercase either argument. An uppercase
// byte anywhere in a keyword literal would therefore make that keyword
// permanently unmatchable — silently, with no test failure anywhere else. For a
// positive keyword that means a real DOB scores 5 instead of 90; for a
// disqualifier it means synthetic test data is reported as real PII.
func TestKeywordListsAreLowercase(t *testing.T) {
	v := NewValidator()

	lists := map[string][]string{
		"positiveKeywords":   v.positiveKeywords,
		"negativeKeywords":   v.negativeKeywords,
		"nonHumanIndicators": nonHumanIndicators,
	}
	for name, list := range lists {
		for _, kw := range list {
			if kw != strings.ToLower(kw) {
				t.Errorf("%s contains a non-lowercase keyword %q; kwmatch.ContainsLower "+
					"never lowercases its arguments, so this keyword can never match", name, kw)
			}
		}
	}

	maps := map[string]map[string]bool{
		"strongPositiveKeywords": strongPositiveKeywords,
		"disqualifierKeywords":   disqualifierKeywords,
	}
	for name, m := range maps {
		for kw := range m {
			if kw != strings.ToLower(kw) {
				t.Errorf("%s has a non-lowercase key %q", name, kw)
			}
		}
	}

	// The classifier maps are keyed by the same strings the lists hold. A key
	// that matches nothing in the lists is dead weight that silently stops
	// classifying — e.g. a "DOB" key would never mark "dob" as strong.
	inList := make(map[string]bool, len(v.positiveKeywords)+len(v.negativeKeywords))
	for _, kw := range v.positiveKeywords {
		inList[kw] = true
	}
	for _, kw := range v.negativeKeywords {
		inList[kw] = true
	}
	for name, m := range maps {
		for kw := range m {
			if !inList[kw] {
				t.Errorf("%s key %q appears in no keyword list, so it can never be "+
					"consulted (the classifier is only reached for keywords that matched)", name, kw)
			}
		}
	}
}

// TestContextScoringIsOffsetInvariant is the regression gate on the defect this
// file is named for: scoring must depend on what the line SAYS, never on where
// in the line the match happens to sit.
//
// analyzeContext used to scan a per-match concatenation
//
//	strings.ToLower(BeforeText) + " " + lowerLine + " " + strings.ToLower(AfterText)
//
// where BeforeText/AfterText are the ±50-byte windows around the match — both
// slices of that same line. Re-joining them could not add a keyword the line
// lacked, but it added two artifacts that changed the score:
//
//  1. the synthetic " " joins let a multi-word keyword match ACROSS a junction;
//  2. the 50-byte windows are cut at an arbitrary byte offset, so a fragment can
//     start mid-word and gain a word boundary the line does not give it.
//
// Sliding the match along the line while keeping the words identical isolates
// exactly that: any score change is fabrication, because no keyword moved in or
// out of the text. Each case below is a measured offset from the unfixed code.
func TestContextScoringIsOffsetInvariant(t *testing.T) {
	v := NewValidator()

	// buildLine puts `pad` bytes of filler between a fixed prefix and the date,
	// moving ONLY the 50-byte window start relative to the prefix's words.
	buildLine := func(prefix string, pad int, date string) string {
		return prefix + strings.Repeat("q", pad) + " " + date
	}

	t.Run("disqualifier cut out of a longer word must not delete a real DOB", func(t *testing.T) {
		// THE LEAK CASE. The line explicitly says "patient date of birth" and
		// carries an unrelated word, "contest", that merely CONTAINS "test".
		//
		// "test" is a disqualifierKeyword: matching it forces impact -= 50 and
		// returns early, taking the base-15 finding to -35, and the scan drops
		// findings at confidence <= 0. So a "test" fabricated by a window cut
		// does not just lower a score — it DELETES the finding. A DOB missing
		// from the report is never handed to the redactor either, so the
		// cleartext value survives into the output.
		//
		// At pad=44 the 50-byte before-window began inside "contest", handing
		// the fragment "test" a leading word boundary. Measured on the unfixed
		// code: pad=43 -> 1 finding at conf 90, pad=44 -> 0 findings,
		// pad=45 -> 1 finding at conf 90. Eight bytes of filler either side of
		// a vanishing real DOB.
		const prefix = "patient date of birth, annual contest "
		for pad := 38; pad <= 52; pad++ {
			line := buildLine(prefix, pad, "05/06/1990")
			matches, err := v.ValidateContent(line, "leak.txt")
			if err != nil {
				t.Fatalf("pad=%d: ValidateContent: %v", pad, err)
			}
			if len(matches) != 1 {
				t.Fatalf("pad=%d: got %d findings, want 1 — the line says "+
					"\"patient date of birth\" and the only \"test\" is inside \"contest\". "+
					"A window cut fabricated a disqualifier and dropped a real DOB, which "+
					"also removes it from redaction.\n  line: %q", pad, len(matches), line)
			}
			if matches[0].Confidence < 90 {
				t.Errorf("pad=%d: confidence %.0f, want >= 90 for an explicit "+
					"\"date of birth\" label", pad, matches[0].Confidence)
			}
		}
	})

	t.Run("keyword cut out of a longer word must not boost a bare date", func(t *testing.T) {
		// The false-positive direction. "xdob" contains "dob" but is not the
		// word "dob"; with only "xdob" on the line the date is unlabelled and
		// must stay low-confidence. At pad=45 the before-window began inside
		// "xdob", so the fragment "dob" gained a leading boundary and matched
		// as the strong label: measured 5 at every other pad in 40..56, and 90
		// at pad=45 alone.
		var high []int
		for pad := 40; pad <= 56; pad++ {
			line := "xdob " + strings.Repeat("y", pad) + " 1990-05-06"
			matches, err := v.ValidateContent(line, "boost.txt")
			if err != nil {
				t.Fatalf("pad=%d: ValidateContent: %v", pad, err)
			}
			if len(matches) != 1 {
				t.Fatalf("pad=%d: got %d findings, want 1 (the date is always extracted)", pad, len(matches))
			}
			if matches[0].Confidence >= 60 {
				high = append(high, pad)
			}
		}
		if len(high) > 0 {
			t.Errorf("pads %v scored >= 60 on a line whose only \"dob\"-like text is "+
				"inside the word \"xdob\" — a word-boundary fabricated by the 50-byte "+
				"window cut, not a label in the document", high)
		}
	})

	t.Run("multi-word keyword must not match across a window junction", func(t *testing.T) {
		// The junction case. "date of birth" appears NOWHERE on this line:
		// "of birth" opens it and "that date" closes it. Joining
		// before + " " + line + " " + after put the trailing "...that date" in
		// front of the leading "of birth...", so "date of birth" matched at the
		// synthetic join. Measured: 90 (strong-label HIGH) unfixed vs 70 fixed,
		// where 70 comes from the weak "birth" keyword that IS on the line.
		const line = "of birth was verified on that date 05/06/1990"
		matches, err := v.ValidateContent(line, "junction.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("got %d findings, want 1", len(matches))
		}
		if strings.Contains(strings.ToLower(line), "date of birth") {
			t.Fatal("test premise broken: the line now literally contains \"date of birth\"")
		}
		if matches[0].Confidence >= 90 {
			t.Errorf("confidence %.0f: the strong label \"date of birth\" is not on this "+
				"line — it was fabricated by joining the after-window (\"...that date\") "+
				"to the before-window (\"of birth...\") with a synthetic space.\n  line: %q",
				matches[0].Confidence, line)
		}
	})
}

// TestAnalyzeContextIgnoresWindowFields locks the narrowed contract of the
// exported AnalyzeContext: it scores from FullLine only. BeforeText/AfterText
// stay populated on the emitted Match (the suppression context hash, SARIF
// region and --show-match all read them), so this asserts they are inert for
// SCORING, not that they are unused.
//
// A caller cannot make the score move by supplying windows, including windows
// that are not substrings of the line at all — the case the old concatenation
// would have scored on.
func TestAnalyzeContextIgnoresWindowFields(t *testing.T) {
	v := NewValidator()

	const line = "record value 05/06/1990 on file"
	base := v.AnalyzeContext("05/06/1990", detector.ContextInfo{FullLine: line})

	windows := []struct {
		name   string
		before string
		after  string
	}{
		{"empty", "", ""},
		{"real windows", "record value ", " on file"},
		{"foreign strong label", "date of birth: ", " confirmed"},
		{"foreign disqualifier", "test ", " sample"},
		{"junction-forming fragments", "of birth", "that date"},
	}
	for _, w := range windows {
		got := v.AnalyzeContext("05/06/1990", detector.ContextInfo{
			BeforeText: w.before,
			FullLine:   line,
			AfterText:  w.after,
		})
		if got != base {
			t.Errorf("%s: AnalyzeContext returned %.0f, want %.0f (== the FullLine-only "+
				"score). Window text must not influence scoring: it is either a slice of "+
				"the line (adding nothing) or foreign text the document never contained.",
				w.name, got, base)
		}
	}
}

// buildDenseDateLine returns a single line of ~targetBytes packed with DISTINCT
// plausible DOB dates and a DOB label, i.e. the worst case for any per-match
// whole-line work.
//
// Distinct values are the whole point. extractDates dedups candidates per line,
// so a line built by repeating one identical unit collapses to a handful of
// matches no matter how long it gets: the per-match cost never grows and a
// quadratic validator measures as linear. The shared complexity guard used
// identical repeats, which is why it rated this validator's growth as normal
// while it was in fact quadratic.
//
// The date space is deliberately wide enough not to wrap before the sizes used
// here: 110 years x 12 months x 28 days x 3 separators is ~110k distinct dates
// (~1.3MB of text). Wrapping would silently cap the match count and make a
// re-introduced quadratic look sublinear at larger sizes.
func buildDenseDateLine(targetBytes int) string {
	seps := [3]byte{'/', '-', '.'}
	var sb strings.Builder
	sb.WriteString("patient date of birth records:")
	y, m, d, s := 1900, 1, 1, 0
	for sb.Len() < targetBytes {
		fmt.Fprintf(&sb, " %02d%c%02d%c%04d", m, seps[s], d, seps[s], y)
		d++
		if d > 28 {
			d = 1
			m++
		}
		if m > 12 {
			m = 1
			y++
		}
		if y > 2009 {
			y = 1900
			s = (s + 1) % len(seps)
		}
	}
	return sb.String()
}

// TestWorstCaseSingleLineTiming is the performance regression guard for the
// O(n^2) DoS on a single dense line.
//
// Cause: analyzeContext and findKeywords ran a fresh keyword scan PER MATCH,
// each walking the whole line once per keyword (79 of them). Growth was ~4x per
// DOUBLING of input, where linear is 2x — measured on the unfixed code with the
// generator below: 384ms at 8KB, 1.61s at 16KB, 5.20s at 32KB, 22.12s at 64KB.
//
// There were two layers, and fixing only the first leaves the validator
// quadratic — worth stating because it is the trap this guard exists to catch:
//
//  1. kwmatch.Contains lowercases its text argument on every call, so the whole
//     line was re-lowercased ~46 times per match; strings.ToLower measured 80%
//     of total CPU. Hoisting just the lowercasing still left this test at 25.4s,
//     with internal/bytealg.IndexByteString then 70% flat.
//  2. The scan itself was per-match. Because analyzeContext and findKeywords
//     read only the line, their results are identical for every candidate on
//     that line, so the scan belongs per-LINE. That is the fix that makes a
//     dense line linear (23.4ms at 64KB, a 944x speedup), and it mirrors what
//     the ipaddress validator already does.
//
// A regression in either layer shows up here as a blown ceiling.
func TestWorstCaseSingleLineTiming(t *testing.T) {
	v := NewValidator()
	line := buildDenseDateLine(1 << 20) // ~1MB single line, no newlines

	start := time.Now()
	matches, err := v.ValidateContent(line, "worst.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}
	t.Logf("worst-case single line: len=%d bytes, matches=%d, elapsed=%s",
		len(line), len(matches), elapsed)

	// Non-vacuity floor: a ceiling alone passes trivially if the validator
	// stops matching. Unfixed, this input produced ~57k matches.
	if len(matches) == 0 {
		t.Fatalf("expected matches on a line full of labelled DOB dates, got 0 — " +
			"the timing assertion below would be measuring nothing")
	}

	if raceEnabled {
		// -race inflates wall-clock 5-20x; the scan ran above (so -race checks
		// for data races), but the timing ceiling is meaningless and skipped.
		t.Logf("timing assertion skipped under -race")
		return
	}
	const ceiling = 5 * time.Second
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a ~1MB single line took %s, exceeding %s "+
			"(possible reintroduction of the per-match whole-line keyword scan)",
			elapsed, ceiling)
	}
}
