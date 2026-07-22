// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func boundedMatch(fullLine string) detector.Match {
	return detector.Match{
		Text:       "© 2026, Amazon Web Services [+218 more matches on line]",
		LineNumber: 1,
		Type:       "INTELLECTUAL_PROPERTY",
		Validator:  "INTELLECTUAL_PROPERTY",
		Context:    detector.ContextInfo{FullLine: fullLine},
		Metadata:   map[string]any{MatchTextTruncatedKey: true},
	}
}

func TestRestoreBoundedMatchText_RestoresFullLine(t *testing.T) {
	fullLine := strings.Repeat("© 2026, Amazon Web Services, Inc. Confidential. ", 100)
	in := []detector.Match{boundedMatch(fullLine)}

	out := RestoreBoundedMatchText(in)
	if len(out) != 1 {
		t.Fatalf("match count changed: %d", len(out))
	}
	if out[0].Text != strings.TrimSpace(fullLine) {
		t.Errorf("Text not restored to full line (len=%d, want %d)", len(out[0].Text), len(strings.TrimSpace(fullLine)))
	}
	// Caller's slice must not be mutated.
	if in[0].Text == out[0].Text {
		t.Errorf("input match was mutated in place")
	}
}

func TestRestoreBoundedMatchText_PassThroughUnflagged(t *testing.T) {
	in := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Context: detector.ContextInfo{FullLine: "ssn 449-87-4100 here"}},
		{Text: "no metadata", Type: "INTELLECTUAL_PROPERTY"},
		{Text: "flag false", Type: "INTELLECTUAL_PROPERTY",
			Context:  detector.ContextInfo{FullLine: "flag false line"},
			Metadata: map[string]any{MatchTextTruncatedKey: false}},
	}
	out := RestoreBoundedMatchText(in)
	if len(out) != len(in) {
		t.Fatalf("match count changed: %d", len(out))
	}
	for i := range in {
		if out[i].Text != in[i].Text {
			t.Errorf("match %d Text changed: %q -> %q", i, in[i].Text, out[i].Text)
		}
	}
}

func TestRestoreBoundedMatchText_FlaggedWithoutFullLineUnchanged(t *testing.T) {
	// Fail-safe degenerate case: the flag is set but FullLine is empty — there
	// is nothing to widen to, so the match must pass through unchanged rather
	// than get an empty Text (which would make redaction skip it anyway).
	m := detector.Match{
		Text:     "bounded [+3 more matches on line]",
		Type:     "INTELLECTUAL_PROPERTY",
		Metadata: map[string]any{MatchTextTruncatedKey: true},
	}
	out := RestoreBoundedMatchText([]detector.Match{m})
	if out[0].Text != m.Text {
		t.Errorf("Text changed despite empty FullLine: %q", out[0].Text)
	}
}
