// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"strings"
	"testing"
)

// findBestFuzzyMatch short-circuits on an exact occurrence, and the whole justification for doing
// so is that the result is IDENTICAL to what the slide would have returned — not merely good
// enough. This pins every field of that result, because "identical" is a claim about all of them.
//
// Without this, three mutations survived: returning strings.LastIndex instead of strings.Index,
// returning idx+1, and returning Similarity 0.5. Each violates the stated contract while leaving
// the end-to-end plaintext redaction output unchanged, because that path replaces every occurrence
// regardless of which one was reported. A consumer that uses the reported Index — format-preserving
// redaction, position mapping — would get a wrong offset with no test to catch it (#376).
func TestFindBestFuzzyMatch_ExactOccurrence(t *testing.T) {
	dpc := NewDefaultPositionCorrelator()

	t.Run("returns the FIRST occurrence, not any later one", func(t *testing.T) {
		target := "449-87-4100"
		// Three occurrences. The slide starts at offset 0 and breaks on the first exact hit, so
		// the first is the answer; LastIndex would give the third.
		original := "alpha " + target + " beta " + target + " gamma " + target + " end"
		want := strings.Index(original, target)

		got := dpc.findBestFuzzyMatch(target, original)
		if got == nil {
			t.Fatal("no match for a value that occurs three times verbatim")
		}
		if got.Index != want {
			t.Errorf("Index = %d, want %d (the FIRST occurrence). The slide breaks on the first "+
				"exact hit, so any other offset is not what it would have returned — and a "+
				"consumer that trusts this offset redacts the wrong bytes", got.Index, want)
		}
		if got.Text != target {
			t.Errorf("Text = %q, want %q", got.Text, target)
		}
		if got.EditDistance != 0 {
			t.Errorf("EditDistance = %d, want 0 for an exact occurrence", got.EditDistance)
		}
		if got.Similarity != 1.0 {
			t.Errorf("Similarity = %v, want 1.0 — calculateStringSimilarity returns exactly 1.0 "+
				"for identical strings, so this is what the slide would have produced",
				got.Similarity)
		}
	})

	t.Run("the reported Index actually locates the value", func(t *testing.T) {
		// Independent of the arithmetic above: slice the original at the reported offset and
		// require the value to be there. An off-by-one fails this even if it looks plausible.
		target := "449-87-4100"
		original := "padding padding " + target + " trailing"

		got := dpc.findBestFuzzyMatch(target, original)
		if got == nil {
			t.Fatal("no match")
		}
		if got.Index < 0 || got.Index+len(target) > len(original) {
			t.Fatalf("Index %d is out of range for a %d-byte document", got.Index, len(original))
		}
		if at := original[got.Index : got.Index+len(target)]; at != target {
			t.Errorf("the document at the reported Index %d holds %q, not %q — the offset does "+
				"not point at the value it claims to have found", got.Index, at, target)
		}
	})

	t.Run("at the very start and the very end", func(t *testing.T) {
		target := "449-87-4100"
		for name, original := range map[string]string{
			"at offset 0":  target + " trailing text",
			"at the end":   "leading text " + target,
			"whole string": target,
		} {
			t.Run(name, func(t *testing.T) {
				got := dpc.findBestFuzzyMatch(target, original)
				if got == nil {
					t.Fatal("no match")
				}
				if want := strings.Index(original, target); got.Index != want {
					t.Errorf("Index = %d, want %d", got.Index, want)
				}
				if got.EditDistance != 0 || got.Similarity != 1.0 {
					t.Errorf("EditDistance = %d, Similarity = %v; want 0 and 1.0",
						got.EditDistance, got.Similarity)
				}
			})
		}
	})
}

// The genuinely-fuzzy path must still work. The short-circuit only fires on a verbatim occurrence,
// so a value that differs by an edit still goes through the slide — and if it did not, this change
// would have replaced fuzzy matching rather than accelerated it.
func TestFindBestFuzzyMatch_StillMatchesInexactly(t *testing.T) {
	dpc := NewDefaultPositionCorrelator()

	// One digit differs, so strings.Index finds nothing and the slide runs.
	target := "449-87-4100"
	original := "the record shows 449-87-4109 on file"
	if strings.Contains(original, target) {
		t.Fatal("test setup: the target is present verbatim, so the slide is not being exercised")
	}

	got := dpc.findBestFuzzyMatch(target, original)
	if got == nil {
		t.Fatal("no fuzzy match for a value differing by one digit: the slide is no longer " +
			"reachable, which would mean the short-circuit replaced fuzzy matching instead of " +
			"accelerating it")
	}
	if got.EditDistance == 0 {
		t.Errorf("EditDistance = 0 for a value that is NOT present verbatim (%q vs %q)",
			got.Text, target)
	}
	if got.EditDistance > dpc.maxEditDistance {
		t.Errorf("EditDistance %d exceeds maxEditDistance %d, so this should have been nil",
			got.EditDistance, dpc.maxEditDistance)
	}
}

// A value that is absent and not close to anything must still return nil.
func TestFindBestFuzzyMatch_NoMatch(t *testing.T) {
	dpc := NewDefaultPositionCorrelator()
	if got := dpc.findBestFuzzyMatch("449-87-4100", "nothing resembling that value here at all"); got != nil {
		t.Errorf("got %+v, want nil for an absent value", got)
	}
	if got := dpc.findBestFuzzyMatch("", "some text"); got != nil {
		t.Errorf("got %+v, want nil for an empty target", got)
	}
	if got := dpc.findBestFuzzyMatch("target", ""); got != nil {
		t.Errorf("got %+v, want nil for empty original text", got)
	}
}
