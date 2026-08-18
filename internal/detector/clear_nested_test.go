// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"testing"
)

// Clear() must scrub the matches a consolidated finding carries, not just its own fields.
//
// A SOCIAL_MEDIA_CLUSTER finding replaces N real matches with one summary and keeps the
// originals in Metadata["cluster_members"], each with its own Text and its own
// Context.FullLine. So the match type holding the MOST cleartext — N values plus N whole
// source lines — was the one Clear() left untouched, while reporting success for having
// scrubbed the summary string.
//
// It matters most through pkg/redact, where Clear() is the scrubbing contract an embedding
// caller relies on: the caller cleared its matches and still held the input's cleartext.
func TestClearScrubsNestedClusterMembers(t *testing.T) {
	const (
		handleA  = "jane_doe_1985"
		handleB  = "j.doe.official"
		fullLine = "Follow me: instagram.com/jane_doe_1985 and twitter.com/j.doe.official"
	)

	member := func(text string) Match {
		return Match{
			Text: text,
			Type: "SOCIAL_MEDIA",
			Context: ContextInfo{
				FullLine:   fullLine,
				BeforeText: "Follow me: ",
				AfterText:  " and more",
			},
		}
	}

	m := Match{
		Text: "2 social media handles on one line",
		Type: "SOCIAL_MEDIA_CLUSTER",
		Context: ContextInfo{
			FullLine: fullLine,
		},
		Metadata: map[string]interface{}{
			"explanation":     "advisory text",
			"cluster_members": []Match{member(handleA), member(handleB)},
		},
	}

	// Hold a reference to the nested slice so the assertion sees the same backing array the
	// caller would still be holding. Deleting the map key alone would not scrub these.
	retained, ok := m.Metadata["cluster_members"].([]Match)
	if !ok {
		t.Fatal("fixture is wrong: cluster_members is not []Match, so the test would assert nothing")
	}

	m.Clear()

	if m.Text != "" || m.Context.FullLine != "" {
		t.Errorf("the top-level fields were not scrubbed: Text=%q FullLine=%q", m.Text, m.Context.FullLine)
	}
	if _, still := m.Metadata["cluster_members"]; still {
		t.Error("cluster_members is still present in Metadata after Clear()")
	}

	for i := range retained {
		if retained[i].Text != "" {
			t.Errorf("member %d still holds its value %q — Clear() scrubbed the summary and left "+
				"every value the summary replaced, which is the opposite of what it reports",
				i, retained[i].Text)
		}
		if retained[i].Context.FullLine != "" {
			t.Errorf("member %d still holds the whole source line %q — each member carries its own "+
				"Context, so a cluster retained N full lines of the input",
				i, retained[i].Context.FullLine)
		}
		if retained[i].Context.BeforeText != "" || retained[i].Context.AfterText != "" {
			t.Errorf("member %d still holds surrounding context: before=%q after=%q",
				i, retained[i].Context.BeforeText, retained[i].Context.AfterText)
		}
	}
}

// A self-referential structure must terminate rather than recurse forever.
//
// Deleting the key BEFORE clearing the members is what makes that true: the recursive call
// finds no key and stops. Reversing the two turns this into unbounded recursion, which
// overflows the stack and panics — so no explicit timeout is needed here, a hang is not the
// failure mode.
func TestClearTerminatesOnSelfReferentialMetadata(t *testing.T) {
	m := Match{Text: "outer", Metadata: map[string]interface{}{}}
	inner := Match{Text: "inner", Metadata: m.Metadata} // shares the same map
	m.Metadata["cluster_members"] = []Match{inner}

	m.Clear()

	if m.Text != "" {
		t.Errorf("Text = %q, want empty", m.Text)
	}
}

// Clear() must stay safe on the ordinary shapes: nil metadata, and a wrong type under the key.
func TestClearHandlesMissingOrWrongTypedClusterMembers(t *testing.T) {
	cases := map[string]Match{
		"nil metadata":   {Text: "x"},
		"empty metadata": {Text: "x", Metadata: map[string]interface{}{}},
		"wrong type":     {Text: "x", Metadata: map[string]interface{}{"cluster_members": "not a slice"}},
		"nil slice":      {Text: "x", Metadata: map[string]interface{}{"cluster_members": []Match(nil)}},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			m.Clear() // must not panic
			if m.Text != "" {
				t.Errorf("Text = %q, want empty", m.Text)
			}
		})
	}
}

// The literal key must match what the redactors write, or the scrub silently applies to
// nothing. Asserted against the source rather than an import, which would be a cycle.
func TestClusterMembersKeyMatchesRedactors(t *testing.T) {
	if clusterMembersMetadataKey != "cluster_members" {
		t.Errorf("key = %q; redactors.ClusterMembersKey is \"cluster_members\" and the two must "+
			"agree or Clear() scrubs nothing", clusterMembersMetadataKey)
	}
}
