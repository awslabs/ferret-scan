// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestTextFormatter_VerboseDoesNotLeakWhenHidden is a regression test for the
// PII-leak class: the verbose "Context snippet" prints the raw before/[match]/
// after text, so it must be gated on ShowMatch. With ShowMatch=false the secret
// must not appear, even under --verbose.
func TestTextFormatter_VerboseDoesNotLeakWhenHidden(t *testing.T) {
	const secret = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 1,
		Type:       "SECRETS",
		Confidence: 95,
		Filename:   "config.go",
		Validator:  "secrets",
		Context: detector.ContextInfo{
			FullLine:   `apiKey := "` + secret + `"`,
			BeforeText: `apiKey := "`,
			AfterText:  `"`,
		},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch: false,
		Verbose:   true, // verbose must not re-leak the value via the context snippet
		NoColor:   true,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Errorf("text output leaked the secret value with ShowMatch=false, Verbose=true")
	}
}

// TestTextFormatter_VerboseDetailedViewDoesNotLeak is a regression test for the
// primary verbose leak: in --verbose mode the detailed "Match found ... : VALUE"
// line and the summary match column printed match.Text regardless of ShowMatch.
// With ShowMatch=false the value must be [HIDDEN] everywhere, including the
// detailed view and suppressed-match detail; --show-match reveals it.
func TestTextFormatter_VerboseDetailedViewDoesNotLeak(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 5,
		Type:       "VISA",
		Confidence: 100,
		Filename:   "card.docx",
		Validator:  "creditcard",
		Context:    detector.ContextInfo{FullLine: secret, BeforeText: "x ", AfterText: " y"},
	}}
	suppressed := []detector.SuppressedMatch{{Match: matches[0], SuppressedBy: "rule-1", RuleReason: "known test"}}
	levels := map[string]bool{"high": true, "medium": true, "low": true}

	// Verbose + hidden (color and no-color) and suppressed must not leak.
	for _, noColor := range []bool{true, false} {
		out, err := NewFormatter().Format(matches, suppressed, formatters.FormatterOptions{
			Verbose: true, ShowMatch: false, NoColor: noColor, ConfidenceLevel: levels,
		})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}
		if strings.Contains(out, secret) {
			t.Errorf("verbose detailed view leaked the value (noColor=%v):\n%s", noColor, out)
		}
		if !strings.Contains(out, "[HIDDEN]") {
			t.Errorf("expected [HIDDEN] in hidden verbose output (noColor=%v)", noColor)
		}
	}

	// --show-match must still reveal the value.
	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		Verbose: true, ShowMatch: true, NoColor: true, ConfidenceLevel: levels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(out, secret) {
		t.Errorf("--show-match should reveal the value in verbose output")
	}
}

// TestTextFormatter_PrecommitHonorsShowMatch is a regression test for the
// pre-commit reveal gap: formatPrecommitOutput never printed match.Text, so
// --show-match was a silent no-op there even though the resolution guidance
// told users to "Use --show-match flag to see exact matches." The matched
// value must surface in pre-commit output when ShowMatch is set, and stay
// [HIDDEN] when it is not (so the hint is truthful in both directions).
func TestTextFormatter_PrecommitHonorsShowMatch(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 2,
		Type:       "CREDIT_CARD",
		Confidence: 100,
		Filename:   "cards.tsv",
		Validator:  "creditcard",
		Context:    detector.ContextInfo{FullLine: "Robert Aragon\t" + secret},
	}}
	levels := map[string]bool{"high": true, "medium": true, "low": true}

	// Hidden: pre-commit output must not print the value; it shows [HIDDEN].
	hidden, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		PrecommitMode: true, ShowMatch: false, NoColor: true, ConfidenceLevel: levels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(hidden, secret) {
		t.Errorf("pre-commit output leaked the value with ShowMatch=false:\n%s", hidden)
	}
	if !strings.Contains(hidden, "[HIDDEN]") {
		t.Errorf("pre-commit output should show [HIDDEN] for the match when ShowMatch=false:\n%s", hidden)
	}

	// Revealed: --show-match surfaces the value (makes the resolution hint honest).
	shown, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		PrecommitMode: true, ShowMatch: true, NoColor: true, ConfidenceLevel: levels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(shown, secret) {
		t.Errorf("pre-commit --show-match should reveal the matched value:\n%s", shown)
	}
}

// TestTextFormatter_PrecommitGuidanceHintMatchesState is a regression test for
// the misleading resolution hint: pre-commit guidance unconditionally said
// "Use --show-match flag to see exact matches", even when the operator had
// already passed --show-match (the values were already on screen). The hint
// must appear only when ShowMatch is off, i.e. only when following it would
// actually change the output.
func TestTextFormatter_PrecommitGuidanceHintMatchesState(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 2,
		Type:       "CREDIT_CARD",
		Confidence: 100,
		Filename:   "cards.tsv",
		Validator:  "creditcard",
	}}
	levels := map[string]bool{"high": true, "medium": true, "low": true}
	const hint = "Use --show-match flag"

	// ShowMatch off: values are [HIDDEN], so the hint is actionable — show it.
	hidden, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		PrecommitMode: true, ShowMatch: false, NoColor: true, ConfidenceLevel: levels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(hidden, hint) {
		t.Errorf("pre-commit guidance should suggest --show-match when it is off:\n%s", hidden)
	}

	// ShowMatch on: values are already shown; suggesting the flag is misleading.
	shown, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		PrecommitMode: true, ShowMatch: true, NoColor: true, ConfidenceLevel: levels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(shown, hint) {
		t.Errorf("pre-commit guidance must not suggest --show-match when it is already on:\n%s", shown)
	}
	// The remaining guidance is still present in both states.
	if !strings.Contains(shown, "Resolution options:") || !strings.Contains(hidden, "Resolution options:") {
		t.Errorf("resolution guidance header should be present in both states")
	}
}
