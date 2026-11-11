// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"slices"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestSameLineBareNameBesideLongerMatchIsKept is #966. deduplicateMatches dropped a match when
// another match on its line was longer and CONTAINED ITS TEXT, wherever either sat, so the bare
// "John Smith" in "Signed by John Smith, witnessed by Dr. John Smith." was dropped and survived
// redaction. Containment is now by span: a separate occurrence is kept, the occurrence inside
// the longer match still collapses into it. Both scoring paths share the dedup; both are run.
func TestSameLineBareNameBesideLongerMatchIsKept(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		line string
		want []string // every PERSON_NAME text on the line, sorted
	}{
		{"Signed by John Smith, witnessed by Dr. John Smith.", []string{"Dr. John Smith", "John Smith"}},
		{"Witnessed by Dr. John Smith, signed by John Smith.", []string{"Dr. John Smith", "John Smith"}},
		{"Approved by Maria Garcia; countersigned by Ms. Maria Garcia on Monday.", []string{"Maria Garcia", "Ms. Maria Garcia"}},
		{"Signed by John Smith, witnessed by Dr. John Smith, filed by John Smith.", []string{"Dr. John Smith", "John Smith"}},
		// Controls: the inner occurrence alone still collapses; a repeated bare value is one finding.
		{"Control: witnessed by Dr. John Smith only.", []string{"Dr. John Smith"}},
		{"Signed by John Smith and again by John Smith today.", []string{"John Smith"}},
	}
	insights := context.ContextInsights{
		DocumentType: "correspondence", Domain: "hr",
		SemanticContext: map[string]float64{}, ConfidenceAdjustments: map[string]float64{},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			plain, err := v.ValidateContent(c.line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			withCtx, err := v.ValidateWithContext(c.line, "memo.txt", insights)
			if err != nil {
				t.Fatalf("ValidateWithContext: %v", err)
			}
			for path, got := range map[string][]detector.Match{"ValidateContent": plain, "ValidateWithContext": withCtx} {
				texts := matchTexts(got)
				slices.Sort(texts)
				if !slices.Equal(texts, c.want) {
					t.Errorf("%s: got %q, want %q", path, texts, c.want)
				}
			}
		})
	}
}

// at builds a match the way findNamesInLine does: Context recorded at the candidate's TRUE offset.
func at(line, text string, start int, conf float64) detector.Match {
	if line[start:start+len(text)] != text {
		panic("fixture: " + text + " is not at the given offset")
	}
	return detector.Match{
		Text: text, LineNumber: 1, Confidence: conf, Type: "PERSON_NAME",
		Context: detector.LineContext(line, start, start+len(text)),
	}
}

func TestDeduplicateMatchesBySpan(t *testing.T) {
	v := NewValidator()
	const line = "Witnessed by Dr. John Smith, signed by John Smith."
	inner := strings.Index(line, "John Smith")
	bare := strings.LastIndex(line, "John Smith")
	titled := strings.Index(line, "Dr. John Smith")

	t.Run("inner occurrence collapses, bare one is kept", func(t *testing.T) {
		got := v.deduplicateMatches([]detector.Match{
			at(line, "John Smith", inner, 92),
			at(line, "John Smith", bare, 92),
			at(line, "Dr. John Smith", titled, 100),
		})
		texts := matchTexts(got)
		if !slices.Equal(texts, []string{"John Smith", "Dr. John Smith"}) {
			t.Fatalf("got %q, want first-appearance order [John Smith, Dr. John Smith]", texts)
		}
	})

	t.Run("representative is the best UNCONTAINED occurrence", func(t *testing.T) {
		got := v.deduplicateMatches([]detector.Match{
			at(line, "John Smith", inner, 99), // contained: its confidence must not be reported
			at(line, "John Smith", bare, 70),
			at(line, "Dr. John Smith", titled, 100),
		})
		if m := findMatch(got, "John Smith"); m == nil || m.Confidence != 70 {
			t.Fatalf("got %+v, want the bare occurrence at 70", got)
		}
	})

	// The resolver hands out occurrences left to right, so a lone bare candidate is placed on
	// the INNER occurrence. Its recorded context disagrees with that placement, so the span is
	// not trusted and the match is kept rather than dropped by a position it never had.
	t.Run("misplaced span is kept, not dropped", func(t *testing.T) {
		got := v.deduplicateMatches([]detector.Match{
			at(line, "Dr. John Smith", titled, 100),
			at(line, "John Smith", bare, 92),
		})
		if findMatch(got, "John Smith") == nil {
			t.Fatalf("got %q: the bare name was dropped by the occurrence inside the titled one", matchTexts(got))
		}
	})

	t.Run("only the inner occurrence: collapses", func(t *testing.T) {
		const l = "Control: witnessed by Dr. John Smith only."
		got := v.deduplicateMatches([]detector.Match{
			at(l, "John Smith", strings.Index(l, "John Smith"), 92),
			at(l, "Dr. John Smith", strings.Index(l, "Dr. John Smith"), 100),
		})
		if texts := matchTexts(got); !slices.Equal(texts, []string{"Dr. John Smith"}) {
			t.Fatalf("got %q, want [Dr. John Smith]", texts)
		}
	})

	t.Run("same span from two patterns is one finding", func(t *testing.T) {
		const l = "Signed by John Smith."
		s := strings.Index(l, "John Smith")
		got := v.deduplicateMatches([]detector.Match{at(l, "John Smith", s, 80), at(l, "John Smith", s, 90)})
		if len(got) != 1 || got[0].Confidence != 90 {
			t.Fatalf("got %+v, want one finding at 90", got)
		}
	})

	t.Run("partial overlap is not containment", func(t *testing.T) {
		const l = "Mary Ann Lee"
		got := v.deduplicateMatches([]detector.Match{at(l, "Mary Ann", 0, 80), at(l, "Ann Lee", 5, 80)})
		if len(got) != 2 {
			t.Fatalf("got %q, want both", matchTexts(got))
		}
	})

	t.Run("different lines never compare", func(t *testing.T) {
		a := at("Dr. John Smith", "Dr. John Smith", 0, 100)
		b := at("John Smith", "John Smith", 0, 92)
		b.LineNumber = 2
		if got := v.deduplicateMatches([]detector.Match{a, b}); len(got) != 2 {
			t.Fatalf("got %q, want both", matchTexts(got))
		}
	})
}
