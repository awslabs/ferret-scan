// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	stdctx "context"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// buildMRZLine1 returns an ICAO 9303 TD3 line 1 padded with "<" fillers to the
// requested total length. 44 is the canonical width; 45 exercises the nested-span
// case, where MRZ_TD3 matches the first 44 bytes and MRZ matches all 45.
func buildMRZLine1(total int) string {
	const head = "P<GBRSMITH<<JOHN<ALBERT"
	if total <= len(head) {
		return head[:total]
	}
	return head + strings.Repeat("<", total-len(head))
}

func scan(t *testing.T, content string) []detector.Match {
	t.Helper()
	v := NewValidator()
	matches, err := v.ValidateContentCtx(stdctx.Background(), content, "/test/passport.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	return matches
}

// TestOneMRZYieldsOneFinding is the core gate.
//
// The MRZ patterns overlap by construction — MRZ is `[A-Z0-9<]{38,40}` and
// MRZ_TD3 is `[A-Z0-9<]{39}`, so every MRZ_TD3 hit is also an MRZ hit — and the
// emit loop appended every surviving hit from every pattern. One physical passport
// line therefore produced two PASSPORT findings.
//
// Both overlap shapes are covered, because they fail differently: at 44 chars the
// two spans are IDENTICAL, and at 45+ the TD3 span is a strict PREFIX of the MRZ
// span. An exact-span dedup key would fix the first and miss the second.
func TestOneMRZYieldsOneFinding(t *testing.T) {
	for _, width := range []int{44, 45, 46} {
		t.Run(strings.TrimSpace(string(rune('0'+width/10))+string(rune('0'+width%10))+" chars"), func(t *testing.T) {
			line := buildMRZLine1(width)
			content := "passport holder machine readable zone icao\n" + line + "\n"

			matches := scan(t, content)
			if len(matches) != 1 {
				var got []string
				for _, m := range matches {
					country, _ := m.Metadata["country"].(string)
					got = append(got, country+":"+m.Text)
				}
				t.Fatalf("line-1 width %d produced %d findings, want 1 — one physical MRZ is "+
					"one document. Overlapping patterns claiming the same bytes must be folded, "+
					"or the report double-counts one passport and --generate-suppressions writes "+
					"two rules for one leak.\n  got: %v", width, len(matches), got)
			}

			// The survivor must be the WIDEST span any pattern could claim, not a
			// narrower one — reporting the TD3 prefix when MRZ matched more would
			// hash a value that appears nowhere complete in the file.
			//
			// "Widest any pattern could claim" is not always the whole line: MRZ is
			// `[A-Z0-9<]{38,40}` after a 5-char head, so it tops out at 45 bytes. At
			// 46+ chars NOTHING matches the full token, which is a pre-existing
			// pattern-width ceiling and not a dedup artifact (tracked separately).
			// So the bound asserted here is min(len(line), 45).
			wantLen := len(line)
			if wantLen > 45 {
				wantLen = 45
			}
			if got := len(matches[0].Text); got != wantLen {
				t.Errorf("reported span is %d bytes, want %d (the widest any pattern can "+
					"claim on a %d-char line) — got %q", got, wantLen, len(line), matches[0].Text)
			}
			if !strings.HasPrefix(line, matches[0].Text) {
				t.Errorf("reported text %q is not a prefix of the MRZ line %q",
					matches[0].Text, line)
			}
		})
	}
}

// TestRepeatedMRZOnOneLineYieldsTwoFindings is the other half of the contract, and
// the reason the dedup key has to be the byte SPAN rather than (type, line, text).
//
// The same MRZ value appearing twice on one line is two real leaks at two
// offsets. A text-based key would collapse them and under-report an actual
// double-disclosure.
func TestRepeatedMRZOnOneLineYieldsTwoFindings(t *testing.T) {
	line := buildMRZLine1(44)
	content := "passport " + line + " and passport " + line + "\n"

	matches := scan(t, content)
	if len(matches) != 2 {
		t.Fatalf("the same MRZ twice on one line produced %d findings, want 2 — these are "+
			"two distinct disclosures at two offsets, not one claim seen twice. Folding them "+
			"would under-report a real double-leak.", len(matches))
	}
}

// TestDistinctMRZsAreBothReported guards the obvious regression: folding must be
// per line and per span, never across documents.
func TestDistinctMRZsAreBothReported(t *testing.T) {
	gbr := buildMRZLine1(44)
	usa := "P<USAJONES<<MARY<ELLEN" + strings.Repeat("<", 44-len("P<USAJONES<<MARY<ELLEN"))
	content := "passport records icao machine readable zone\n" + gbr + "\n" + usa + "\n"

	matches := scan(t, content)
	if len(matches) != 2 {
		t.Fatalf("two different MRZs produced %d findings, want 2", len(matches))
	}
}

// TestKeepOutermostSpans unit-tests the arbitration directly, including the cases
// the corpus above cannot reach.
func TestKeepOutermostSpans(t *testing.T) {
	mk := func(start, end int, conf float64, label string) spannedMatch {
		return spannedMatch{
			start: start,
			end:   end,
			match: detector.Match{
				Text:       label,
				Confidence: conf,
				Metadata:   map[string]any{"country": label},
			},
		}
	}
	labels := func(in []spannedMatch) []string {
		out := make([]string, 0, len(in))
		for _, m := range in {
			out = append(out, m.match.Text)
		}
		return out
	}
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	cases := []struct {
		name string
		in   []spannedMatch
		want []string
	}{
		{"empty", nil, []string{}},
		{"single", []spannedMatch{mk(0, 44, 80, "a")}, []string{"a"}},
		{
			// The 44-char case: identical spans, incumbent wins.
			"identical spans keep the first",
			[]spannedMatch{mk(0, 44, 80, "TD3"), mk(0, 44, 80, "MRZ")},
			[]string{"TD3"},
		},
		{
			// The 45-char case: the wider span wins even though it is second.
			"nested span keeps the wider",
			[]spannedMatch{mk(0, 44, 80, "TD3"), mk(0, 45, 80, "MRZ")},
			[]string{"MRZ"},
		},
		{
			"disjoint spans both survive",
			[]spannedMatch{mk(0, 44, 80, "a"), mk(60, 104, 80, "b")},
			[]string{"a", "b"},
		},
		{
			"partial overlap is not containment, both survive",
			[]spannedMatch{mk(0, 44, 80, "a"), mk(20, 70, 80, "b")},
			[]string{"a", "b"},
		},
		{
			"three nested spans collapse to the widest",
			[]spannedMatch{mk(0, 44, 80, "inner"), mk(0, 45, 80, "mid"), mk(0, 46, 80, "outer")},
			[]string{"outer"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := labels(keepOutermostSpans(tc.in))
			if !eq(got, tc.want) {
				t.Errorf("keepOutermostSpans = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFoldingNeverLowersConfidence pins the leak-safe direction: folding must not
// demote a finding into a lower severity band than it would have had, because a
// band change can drop it below a --confidence filter or flip an exit code.
func TestFoldingNeverLowersConfidence(t *testing.T) {
	// The narrower claim scores higher; the wider one survives and must inherit it.
	in := []spannedMatch{
		{start: 0, end: 44, match: detector.Match{Text: "inner", Confidence: 100}},
		{start: 0, end: 45, match: detector.Match{Text: "outer", Confidence: 80}},
	}
	got := keepOutermostSpans(in)
	if len(got) != 1 {
		t.Fatalf("got %d survivors, want 1", len(got))
	}
	if got[0].match.Confidence != 100 {
		t.Errorf("survivor confidence = %.0f, want 100 — folding must carry up the strongest "+
			"confidence any folded claim assigned, so a merge can never lower severity",
			got[0].match.Confidence)
	}
}
