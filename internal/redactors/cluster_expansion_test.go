// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A consolidated cluster must be expanded back into the real spans it replaced.
//
// SOCIAL_MEDIA clustering replaces the matches it groups with ONE synthesized match
// whose Text is a rendered summary — "twitter: janedoe | linkedin: janedoe" — that occurs
// nowhere in the document. Every redactor locates a match by searching for its Text, so
// the cluster masked nothing and the real spans had already been dropped.
//
// Measured on the shipped binary with the shipped config, a 3-line fixture holding two
// clustered handles:
//
//	[HIGH] SOCIAL_MEDIA SOCIAL_MEDIA_CLUSTER 95.00% line 1
//	Files: 1 scanned | Findings: 1
//	diff input redacted -> IDENTICAL
//
// for simple, synthetic AND format_preserving. One HIGH finding at 95%, both handles in
// the clear. See #289.
func TestExpandClusterMatchesReplacesClusterWithItsMembers(t *testing.T) {
	members := []detector.Match{
		{Text: "https://twitter.com/janedoe", Type: "SOCIAL_MEDIA", LineNumber: 1, Confidence: 90,
			Context: detector.ContextInfo{FullLine: "Profile: https://twitter.com/janedoe"}},
		{Text: "https://linkedin.com/in/janedoe", Type: "SOCIAL_MEDIA", LineNumber: 3, Confidence: 90,
			Context: detector.ContextInfo{FullLine: "And https://linkedin.com/in/janedoe"}},
	}
	cluster := detector.Match{
		// A rendered summary, not a span of the document.
		Text:       "twitter: janedoe | linkedin: janedoe",
		Type:       "SOCIAL_MEDIA_CLUSTER",
		LineNumber: 1,
		Confidence: 95,
		Context:    detector.ContextInfo{FullLine: "Profile: https://twitter.com/janedoe"},
		Metadata:   map[string]interface{}{ClusterMembersKey: members},
	}

	in := []detector.Match{
		{Text: "unrelated@example.com", Type: "EMAIL", LineNumber: 5},
		cluster,
	}
	out := ExpandClusterMatches(in)

	if len(out) != 3 {
		t.Fatalf("got %d matches, want 3 (the email plus both cluster members) — %+v", len(out), out)
	}
	// Order preserved: matches before the cluster keep their position.
	if out[0].Text != "unrelated@example.com" {
		t.Errorf("out[0] = %q, want the untouched earlier match", out[0].Text)
	}
	for i, want := range []string{"https://twitter.com/janedoe", "https://linkedin.com/in/janedoe"} {
		if out[i+1].Text != want {
			t.Errorf("out[%d].Text = %q, want %q", i+1, out[i+1].Text, want)
		}
	}
	// The synthesized text must be gone: it matches nothing, so leaving it in would
	// preserve exactly the finding that redacts nothing.
	for _, m := range out {
		if m.Type == "SOCIAL_MEDIA_CLUSTER" {
			t.Error("the cluster survived expansion; its Text occurs nowhere in the document, " +
				"so it would redact nothing while the real spans stayed dropped")
		}
	}
	// Members must carry the per-line context redaction needs to position them: a cluster
	// spans SEVERAL lines while its own LineNumber/FullLine name only the primary
	// sub-match's, which is why a full-line restore (RestoreBoundedMatchText) is not
	// enough here.
	if out[2].LineNumber != 3 || out[2].Context.FullLine == out[1].Context.FullLine {
		t.Errorf("member 2 has line %d and FullLine %q — each member must keep its OWN line, "+
			"or every line but the primary stays in cleartext",
			out[2].LineNumber, out[2].Context.FullLine)
	}
}

// The input must not be mutated: formatters report the single consolidated finding, and
// the finding count must not change because redaction expanded it.
func TestExpandClusterMatchesDoesNotMutateInput(t *testing.T) {
	members := []detector.Match{{Text: "https://twitter.com/janedoe", LineNumber: 1}}
	in := []detector.Match{{
		Text:     "twitter: janedoe",
		Type:     "SOCIAL_MEDIA_CLUSTER",
		Metadata: map[string]interface{}{ClusterMembersKey: members},
	}}

	_ = ExpandClusterMatches(in)

	if len(in) != 1 || in[0].Text != "twitter: janedoe" || in[0].Type != "SOCIAL_MEDIA_CLUSTER" {
		t.Errorf("input was mutated: %+v — the caller still reports the consolidated finding", in)
	}
}

// Fail-safe direction: a cluster that cannot be expanded is passed through unchanged
// rather than dropped, so expansion can only ever WIDEN what redaction sees.
func TestExpandClusterMatchesPassesThroughWhatItCannotExpand(t *testing.T) {
	cases := []struct {
		name string
		m    detector.Match
	}{
		{"no metadata", detector.Match{Text: "x", Type: "SOCIAL_MEDIA_CLUSTER"}},
		{"no members key", detector.Match{Text: "x", Type: "SOCIAL_MEDIA_CLUSTER",
			Metadata: map[string]interface{}{"other": 1}}},
		{"members wrong type", detector.Match{Text: "x", Type: "SOCIAL_MEDIA_CLUSTER",
			Metadata: map[string]interface{}{ClusterMembersKey: "not a slice"}}},
		{"members empty", detector.Match{Text: "x", Type: "SOCIAL_MEDIA_CLUSTER",
			Metadata: map[string]interface{}{ClusterMembersKey: []detector.Match{}}}},
		{"members all textless", detector.Match{Text: "x", Type: "SOCIAL_MEDIA_CLUSTER",
			Metadata: map[string]interface{}{ClusterMembersKey: []detector.Match{{Text: ""}}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := ExpandClusterMatches([]detector.Match{c.m})
			if len(out) != 1 || out[0].Text != c.m.Text {
				t.Errorf("got %+v, want the original passed through — dropping a match it "+
					"cannot expand would REMOVE it from the redaction input", out)
			}
		})
	}

	// A member with no text is unlocatable and must not be emitted, but its siblings
	// must survive.
	mixed := detector.Match{Text: "cluster", Type: "SOCIAL_MEDIA_CLUSTER",
		Metadata: map[string]interface{}{ClusterMembersKey: []detector.Match{
			{Text: ""}, {Text: "real@example.com", LineNumber: 2},
		}}}
	out := ExpandClusterMatches([]detector.Match{mixed})
	if len(out) != 1 || out[0].Text != "real@example.com" {
		t.Errorf("got %+v, want just the locatable member", out)
	}
}

// No clusters means no copy and no change — the common path.
func TestExpandClusterMatchesLeavesOrdinaryMatchesAlone(t *testing.T) {
	in := []detector.Match{
		{Text: "a@example.com", LineNumber: 1},
		{Text: "b@example.com", LineNumber: 2},
	}
	out := ExpandClusterMatches(in)
	if len(out) != len(in) {
		t.Fatalf("got %d, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Text != in[i].Text {
			t.Errorf("out[%d] = %q, want %q", i, out[i].Text, in[i].Text)
		}
	}
	if ExpandClusterMatches(nil) != nil {
		t.Error("nil input should return nil")
	}
}

// Several clusters in one slice must all expand.
func TestExpandClusterMatchesHandlesMultipleClusters(t *testing.T) {
	mk := func(text string, members ...string) detector.Match {
		ms := make([]detector.Match, 0, len(members))
		for i, s := range members {
			ms = append(ms, detector.Match{Text: s, LineNumber: i + 1})
		}
		return detector.Match{Text: text, Type: "SOCIAL_MEDIA_CLUSTER",
			Metadata: map[string]interface{}{ClusterMembersKey: ms}}
	}
	out := ExpandClusterMatches([]detector.Match{
		mk("c1", "one", "two"),
		{Text: "middle", LineNumber: 9},
		mk("c2", "three"),
	})
	want := []string{"one", "two", "middle", "three"}
	if len(out) != len(want) {
		t.Fatalf("got %d matches, want %d — %+v", len(out), len(want), out)
	}
	for i := range want {
		if out[i].Text != want[i] {
			t.Errorf("out[%d] = %q, want %q", i, out[i].Text, want[i])
		}
	}
}
