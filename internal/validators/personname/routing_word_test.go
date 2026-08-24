// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/context"
)

// Go's regexp finds leftmost NON-OVERLAPPING matches. A Title-Case routing word in
// front of a name therefore does not merely widen the span — it CONSUMES the given
// name, and the real name is never offered as a candidate:
//
//	"Attn Marcus Holloway"      basic_western_name claims "Attn Marcus", the scan
//	                            resumes at "Holloway", one token cannot match, and
//	                            nothing at all is reported.
//	"Attention Marcus Holloway" three_part_name claims the whole string, so the
//	                            routing word sits inside the reported value.
//	"X Marcus Holloway"         reported 92 — a one-letter token cannot start a name
//	                            token, so it consumes nothing. This is what pins the
//	                            cause to the consumed token rather than to scoring.
//
// The first form is a cleartext leak: an unreported name is never handed to the
// redactor. The scorecorpus mutation for this fix shows it directly — removing the
// mask turns 5 labels into whole_leak in the redacted artifact.

var routingWordLines = []string{
	"Attn Marcus Holloway",
	"Attention Marcus Holloway",
	"Dear Marcus Holloway",
	"Regards Marcus Holloway",
	"Sincerely Marcus Holloway",
	"Thanks Marcus Holloway",
	"Cc Marcus Holloway",
	"Bcc Marcus Holloway",
	"Fwd Marcus Holloway",
	"Subject Marcus Holloway",
	"Re Marcus Holloway",
}

func TestRoutingWordDoesNotHideTheName(t *testing.T) {
	v := NewValidator()

	for _, line := range routingWordLines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if findMatch(matches, "Marcus Holloway") == nil {
				t.Fatalf("%q did not report \"Marcus Holloway\", got %v — an unreported "+
					"name is never redacted", line, matchTexts(matches))
			}
		})
	}
}

// TestRoutingWordIsNotInsideTheReportedValue is the other half. The value reported is
// the value the redactor replaces, so a span carrying the routing word redacts the
// wrong bytes even when the name is found.
func TestRoutingWordIsNotInsideTheReportedValue(t *testing.T) {
	v := NewValidator()

	for _, line := range routingWordLines {
		routing := strings.Fields(line)[0]
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if strings.Contains(m.Text, routing) {
					t.Errorf("reported %q at %.0f: the routing word %q is inside the value",
						m.Text, m.Confidence, routing)
				}
			}
		})
	}
}

// TestUnpunctuatedRoutingWordAgreesWithPunctuated states the contract as an equality.
// The punctuated form was always correct — the colon is a boundary the patterns cannot
// cross — so the fix is that dropping the punctuation must not change the answer.
func TestUnpunctuatedRoutingWordAgreesWithPunctuated(t *testing.T) {
	v := NewValidator()

	for _, pair := range []struct{ bare, punctuated string }{
		{"Attn Marcus Holloway", "Attn: Marcus Holloway"},
		{"Attention Marcus Holloway", "Attention: Marcus Holloway"},
		{"Dear Marcus Holloway", "Dear, Marcus Holloway"},
	} {
		t.Run(pair.bare, func(t *testing.T) {
			bare, err := v.ValidateContent(pair.bare, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			punct, err := v.ValidateContent(pair.punctuated, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(punct) == 0 {
				t.Fatalf("the punctuated form reported nothing, so the comparison is empty")
			}
			if findMatch(bare, punct[0].Text) == nil {
				t.Errorf("punctuated %q reports %q, bare %q reports %v",
					pair.punctuated, punct[0].Text, pair.bare, matchTexts(bare))
			}
		})
	}
}

// TestMaskBoundsRatherThanJoins pins the reason maskChar is '#' and not a space.
// nameSpace accepts a RUN of spaces, so blanking the routing word would let the tokens
// on either side of the hole join into one candidate — and its text, read back from the
// original line, would be a string that is not a name and was never in the document as
// one.
func TestMaskBoundsRatherThanJoins(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"Holloway Attn Marcus",
		"Chen Dear Sarah",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			tokens := strings.Fields(line)
			joined := tokens[0] + " " + tokens[2]
			for _, m := range matches {
				if m.Text == joined {
					t.Errorf("reported %q: the two sides joined across the masked word", m.Text)
				}
			}
		})
	}
}

// TestMaskedMatchTextComesFromTheOriginalLine guards the offset invariant. A match
// found in the masked line must index the original line unchanged, so no reported
// value may contain the mask character.
func TestMaskedMatchTextComesFromTheOriginalLine(t *testing.T) {
	v := NewValidator()
	const line = "Prepared for the team. Attn Marcus Holloway please review by Friday."

	matches, err := v.ValidateContent(line, "memo.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no finding, so the invariant is untested")
	}
	for _, m := range matches {
		if strings.ContainsRune(m.Text, maskChar) {
			t.Errorf("reported %q, which carries the mask character: the text was taken "+
				"from the masked line instead of the original", m.Text)
		}
		if !strings.Contains(line, m.Text) {
			t.Errorf("reported %q, which does not appear in the line at all", m.Text)
		}
	}
}

// TestMaskingCannotLoseAName pins the property that makes masking safe, and the reason
// maskNonNameGivenWords needs no name-database check of its own.
//
// findPatternCandidates keeps the unmasked candidates and ADDS the masked ones, so
// masking a word that turns out to be a real given name cannot remove the name: the
// original candidate is still there. The test forces that situation by putting a real
// given name into the mask list, which is the only way to exercise it — every word
// actually in routingWordsMap is a non-name, so asserting against today's list would
// pass whether the property held or not.
//
// routingWordsMap is a package variable and these tests do not run in parallel, so the
// insert is safe as long as it is undone.
func TestMaskingCannotLoseAName(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct{ word, line, want string }{
		{"will", "Will Smith attended", "Will Smith"},
		{"may", "May Chen signed", "May Chen"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if routingWordsMap[tc.word] {
				t.Fatalf("%q is already a routing word, so it no longer forces the case "+
					"this test exists for — pick a word that is not in the map", tc.word)
			}
			routingWordsMap[tc.word] = true
			defer delete(routingWordsMap, tc.word)

			matches, err := v.ValidateContent(tc.line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if findMatch(matches, tc.want) == nil {
				t.Errorf("want %q, got %v: masking a real given name removed the name, so "+
					"the masked pass is replacing candidates instead of adding to them",
					tc.want, matchTexts(matches))
			}
		})
	}
}

// TestMaskingKeepsTheNameBytesCovered is the companion property. A masked-pass candidate
// can be WIDER than an unmasked finding and then win the containment rule in
// deduplicateMatches, so a finding can disappear from the output — but only in favour of
// a longer span that contains it, which still covers the same bytes for the redactor.
func TestMaskingKeepsTheNameBytesCovered(t *testing.T) {
	v := NewValidator()
	const line = "Attn Marcus Holloway Smith"

	matches, err := v.ValidateContent(line, "memo.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no finding at all for %q", line)
	}
	covered := false
	for _, m := range matches {
		if strings.Contains(m.Text, "Holloway Smith") {
			covered = true
		}
		if strings.Contains(m.Text, "Attn") {
			t.Errorf("reported %q: the routing word is inside the value", m.Text)
		}
	}
	if !covered {
		t.Errorf("no reported value covers \"Holloway Smith\": %v — the surname bytes are "+
			"no longer handed to the redactor", matchTexts(matches))
	}
}

// TestMaskIsLimitedToRoutingWords is the precision counterweight, measured rather than
// assumed: masking every Title-Case function word exposed 18 findings on 714 real
// documents that had been hidden behind one, almost all false. These are that shape.
func TestMaskIsLimitedToRoutingWords(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"For Firm Fixed Price contracts only.",
		"The Fixed Price applies.",
		"About Epic House today.",
		"With Person Sessions scheduled.",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "doc.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("%q reported %v: the mask reached beyond routing words", line, matchTexts(matches))
			}
		})
	}
}

// TestRoutingWordMaskAppliesOnBothScoringPaths is the dual-path guard. The candidate
// finder is shared by findNamesInLine and findNamesInLineWithContext precisely so this
// cannot drift, and this test is what would notice if it did.
func TestRoutingWordMaskAppliesOnBothScoringPaths(t *testing.T) {
	v := NewValidator()
	const line = "Attn Marcus Holloway"

	plain, err := v.ValidateContent(line, "memo.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	withCtx, err := v.ValidateWithContext(line, "memo.txt", context.ContextInsights{
		DocumentType:          "correspondence",
		Domain:                "hr",
		SemanticContext:       map[string]float64{"person": 0.9},
		ConfidenceAdjustments: map[string]float64{},
	})
	if err != nil {
		t.Fatalf("ValidateWithContext: %v", err)
	}

	if findMatch(plain, "Marcus Holloway") == nil {
		t.Errorf("ValidateContent lost the name: %v", matchTexts(plain))
	}
	if findMatch(withCtx, "Marcus Holloway") == nil {
		t.Errorf("ValidateWithContext lost the name — the candidate finder is not shared: %v",
			matchTexts(withCtx))
	}
}

// TestRoutingWordAfterASurnameIsUnchanged records a limitation rather than a fix.
// "Holloway Attn Marcus Whitfield" is claimed whole by four_part_name, and the
// containment rule in deduplicateMatches then drops the correct inner span because it
// compares lengths and not confidence. Measured identical before and after this change
// (82 both ways), so it is pre-existing and out of scope here — pinned so that a future
// change to overlap resolution has to decide about it deliberately.
func TestRoutingWordAfterASurnameIsUnchanged(t *testing.T) {
	v := NewValidator()
	const line = "Holloway Attn Marcus Whitfield"

	matches, err := v.ValidateContent(line, "memo.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if findMatch(matches, line) == nil {
		t.Skipf("the pre-existing four_part_name span for %q no longer appears (%v); if "+
			"overlap resolution changed deliberately, update this expectation", line, matchTexts(matches))
	}
}
