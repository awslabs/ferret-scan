// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Every pattern here requires each name token to start with a capital, so a
// lowercase nobiliary particle terminated the match and the name was never a
// candidate. That defeated the off-list-surname marker: a title says "the following
// tokens are a person" regardless of whether the surname is on any list, but the
// pattern carrying the title never matched in the first place.
//
// The capitalised spelling failed the other way round. name_with_title accepts
// exactly two name tokens after the title, so "Dr. Marco Di Salvo" was reported as
// "Dr. Marco Di" — a value that stops mid-surname, which is worse than a miss
// because it reaches the redactor and leaves the rest of the name in cleartext.

// findMatch returns the match whose text equals want, or nil.
func findMatch(matches []detector.Match, want string) *detector.Match {
	for i := range matches {
		if matches[i].Text == want {
			return &matches[i]
		}
	}
	return nil
}

func matchTexts(matches []detector.Match) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Text)
	}
	return out
}

// TestLowercaseParticleNameIsReported is the recall gate for #422. A name absent
// from the report is never handed to the redactor, so each of these was a cleartext
// leak of a real person's name.
func TestLowercaseParticleNameIsReported(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct {
		line, want, lastName string
	}{
		{"Dr. Ludwig van Beethoven wrote the report.", "Dr. Ludwig van Beethoven", "Beethoven"},
		{"Dr. Otto von Bismarck signed it.", "Dr. Otto von Bismarck", "Bismarck"},
		{"Mr. Ahmed bin Salman attended.", "Mr. Ahmed bin Salman", "Salman"},
		{"Prof. Maria de la Cruz presented.", "Prof. Maria de la Cruz", "Cruz"},
		{"Dr. Jan van den Broek reviewed it.", "Dr. Jan van den Broek", "Broek"},
		{"Ms. Sofia della Rocca approved.", "Ms. Sofia della Rocca", "Rocca"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			m := findMatch(matches, tc.want)
			if m == nil {
				t.Fatalf("want %q reported, got %v", tc.want, matchTexts(matches))
			}

			// The pattern that fired must be the particle-aware one. Without this the
			// test would keep passing if some other pattern happened to cover the span,
			// and would no longer be testing the particle at all.
			if got := m.Metadata["pattern"]; got != "name_with_title_and_particle" {
				t.Errorf("matched by pattern %v, want name_with_title_and_particle", got)
			}

			// Surname parsing must survive the title: if the new pattern were missing
			// from the ParseNameComponents title case, LastName would still be right but
			// FirstName would be the title. Assert the surname explicitly, because it is
			// what the database lookup and the redaction span depend on.
			comps, ok := m.Metadata["name_components"].(NameComponents)
			if !ok {
				t.Fatalf("name_components missing or wrong type: %T", m.Metadata["name_components"])
			}
			if comps.LastName != tc.lastName {
				t.Errorf("LastName = %q, want %q (components: %+v)", comps.LastName, tc.lastName, comps)
			}
			if isTitle(comps.FirstName) {
				t.Errorf("FirstName = %q is a title, so the title was not stripped", comps.FirstName)
			}
		})
	}
}

// TestOffListParticleSurnameStaysBelowHigh pins the ceiling. These surnames are not
// in the ~2.3K list, so the finding is admitted on the title marker alone and must
// never present as HIGH — the same rule the unverified-surname ceiling applies to
// every other marker-admitted name.
func TestOffListParticleSurnameStaysBelowHigh(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"Dr. Ludwig van Beethoven wrote the report.",
		"Dr. Otto von Bismarck signed it.",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("no finding, so the ceiling is untested")
			}
			for _, m := range matches {
				if m.Confidence > unverifiedSurnameCeiling {
					t.Errorf("%q scored %.0f, above the %.0f ceiling for an off-list surname",
						m.Text, m.Confidence, unverifiedSurnameCeiling)
				}
			}
		})
	}
}

// TestCapitalisedParticleSpanReachesTheSurname is the span gate. Before the fix each
// of these was reported truncated at the particle, so the reported value — the value
// the redactor replaces — stopped mid-surname.
func TestCapitalisedParticleSpanReachesTheSurname(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct{ line, want, truncated string }{
		{"Dr. Marco Di Salvo", "Dr. Marco Di Salvo", "Dr. Marco Di"},
		{"Dr. Anna Della Rosa", "Dr. Anna Della Rosa", "Dr. Anna Della"},
		{"Ms. Carla Da Costa", "Ms. Carla Da Costa", "Ms. Carla Da"},
		{"Dr. Paulo Dos Santos", "Dr. Paulo Dos Santos", "Dr. Paulo Dos"},
		{"Mrs. Elena Del Rio", "Mrs. Elena Del Rio", "Mrs. Elena Del"},
		{"Dr. Piet Van Der Berg", "Dr. Piet Van Der Berg", "Dr. Piet Van"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if findMatch(matches, tc.want) == nil {
				t.Errorf("want the full span %q, got %v", tc.want, matchTexts(matches))
			}
			if m := findMatch(matches, tc.truncated); m != nil {
				t.Errorf("still reporting the truncated span %q at %.0f: redaction of that "+
					"value leaves the rest of the surname in cleartext", m.Text, m.Confidence)
			}
		})
	}
}

// TestParticleSpanDoesNotAbsorbAFollowingWord is the precision counterpart. The
// extra token the titled pattern accepts is restricted to a particle for exactly
// this reason: a pattern that simply allowed a fourth token would swallow the next
// word of the sentence.
func TestParticleSpanDoesNotAbsorbAFollowingWord(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct{ line, want string }{
		{"Dr. John Smith Reviewed the chart.", "Dr. John Smith"},
		{"Dr. Sarah Chen Approved the change.", "Dr. Sarah Chen"},
		{"Dr. Maria Lopez Signed the form.", "Dr. Maria Lopez"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "memo.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if findMatch(matches, tc.want) == nil {
				t.Fatalf("want %q, got %v", tc.want, matchTexts(matches))
			}
			for _, m := range matches {
				if len(m.Text) > len(tc.want) && strings.HasPrefix(m.Text, tc.want) {
					t.Errorf("span %q absorbed the following word", m.Text)
				}
			}
		})
	}
}

// TestParticleSetExcludesEnglishFunctionWords keeps the set closed. "of" and "and"
// are ordinary English function words, not nobiliary particles, and admitting them
// would turn every "<Capital> of <Capital>" organisation name into a candidate.
func TestParticleSetExcludesEnglishFunctionWords(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"Institute of Technology",
		"Bank of America",
		"Department of Justice",
		"Smith and Wesson",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "doc.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				for _, fw := range []string{" of ", " and "} {
					if strings.Contains(m.Text, fw) {
						t.Errorf("reported %q: %q was treated as a particle", m.Text, strings.TrimSpace(fw))
					}
				}
			}
		})
	}
}
