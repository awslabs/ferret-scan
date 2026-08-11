// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	stdctx "context"
	"strings"
	"testing"
)

// An English function word is not a given name.
//
// The name patterns match Title-Case SHAPE — two capitalised tokens of 2+ letters —
// so an article or preposition in front of a REAL surname satisfies
// basic_western_name exactly as a real given name does. The surname gate cannot
// catch this class, because the surname is genuine: "grace", "morgan" and "young"
// are all in the name database. Measured on shipped code, 49 of 49 leading function
// words produced a PERSON_NAME finding at MEDIUM.

func scanText(t *testing.T, content string) []struct {
	Text string
	Conf float64
} {
	t.Helper()
	ms, err := NewValidator().ValidateContentCtx(stdctx.Background(), content, "t.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	out := make([]struct {
		Text string
		Conf float64
	}, 0, len(ms))
	for _, m := range ms {
		out = append(out, struct {
			Text string
			Conf float64
		}{m.Text, m.Confidence})
	}
	return out
}

// TestFunctionWordGivenIsNotAName is the precision half.
func TestFunctionWordGivenIsNotAName(t *testing.T) {
	// Every leading word here is a function word; every trailing word is a REAL
	// surname in the shipped database, which is what makes the class invisible to
	// the surname gate.
	for _, lead := range []string{
		"The", "This", "That", "These", "Those", "Our", "Your", "Their", "His",
		"Her", "Its", "My", "Some", "Any", "Each", "Every", "All", "Both", "Most",
		"Such", "What", "Which", "When", "Where", "While", "After", "Before",
		"With", "From", "Into", "Upon", "About", "Also", "Only", "Just", "Very",
		"More", "Less", "Next", "Last", "Per", "Via", "No", "Not", "Now", "Then",
		"Than", "Here", "There",
	} {
		t.Run(lead, func(t *testing.T) {
			got := scanText(t, lead+" Morgan signed the form.\n")
			for _, m := range got {
				if strings.EqualFold(m.Text, lead+" Morgan") {
					t.Errorf("%q reported as a PERSON_NAME at %.0f. A function word is "+
						"not a given name; the surname %q is real, which is why the "+
						"surname gate cannot catch this.", m.Text, m.Conf, "Morgan")
				}
			}
		})
	}
}

// TestNameDatabaseArbitratesFunctionWordCollisions is the RECALL half, and the one
// that matters more.
//
// functionWordsMap is deliberately complete, so it contains words that are also
// real names: the modals "will" and "may", the article "an", the pronoun "he", the
// quantifier "many". Each belongs to real people. isFunctionWordGiven consults the
// name databases FIRST and defers to them.
//
// Mutation-proven: deleting the deference (returning true for any map hit) compiles
// and drops every name below to zero findings. An unreported name is never handed to
// the redactor, so that mutation is a cleartext leak, not a scoring regression.
func TestNameDatabaseArbitratesFunctionWordCollisions(t *testing.T) {
	for _, name := range []string{
		"Will Smith",  // modal verb
		"May Chen",    // modal verb
		"An Nguyen",   // article
		"He Zhang",    // pronoun
		"Many Morgan", // quantifier
	} {
		t.Run(name, func(t *testing.T) {
			got := scanText(t, "Signed by "+name+" today.\n")
			var found bool
			for _, m := range got {
				if strings.Contains(m.Text, name) || strings.Contains(name, m.Text) {
					found = true
				}
			}
			if !found {
				t.Errorf("%q was NOT reported. It is a real name whose given half "+
					"collides with a function word, so the name database must win. "+
					"An undetected name is never redacted — this is a cleartext leak.", name)
			}
		})
	}
}

// TestFunctionWordFilterAppliesOnlyToTheGivenHalf — scoping.
//
// The filter reads the GIVEN half only. A function word appearing anywhere else in
// the line, or as the surname of an otherwise ordinary name, must not suppress the
// finding, or a precision fix becomes a recall bug.
func TestFunctionWordFilterAppliesOnlyToTheGivenHalf(t *testing.T) {
	cases := map[string]string{
		"function word elsewhere in the line": "The report was signed by Sarah Morgan today.\n",
		"function word after the name":        "Sarah Morgan is here now.\n",
		"two real names in prose":             "From Sarah Morgan to David Chen.\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			got := scanText(t, content)
			if len(got) == 0 {
				t.Fatalf("no finding for %q: the given halves are real names and a "+
					"function word elsewhere in the line is irrelevant", content)
			}
		})
	}
}

// TestSingleTokenSurnameIsUnaffected pins the shape boundary.
//
// These patterns require TWO tokens, so a bare surname was never a finding and this
// change must not create one.
func TestSingleTokenSurnameIsUnaffected(t *testing.T) {
	for _, content := range []string{"Morgan signed it.\n", "The Morgan.\n"} {
		got := scanText(t, content)
		for _, m := range got {
			if strings.EqualFold(strings.TrimSpace(m.Text), "Morgan") {
				t.Errorf("bare %q became a finding at %.0f; single-token surnames are "+
					"out of scope for these patterns", m.Text, m.Conf)
			}
		}
	}
}
