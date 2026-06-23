// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/formatters"
)

// TestJUnitFormatter_VerboseDoesNotLeakWhenHidden is a regression test for the
// PII-leak class: when ShowMatch is false the raw secret must never reach the
// output, and --verbose must not re-leak it via the FullLine context field.
func TestJUnitFormatter_VerboseDoesNotLeakWhenHidden(t *testing.T) {
	const secret = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 1,
		Type:       "SECRETS",
		Confidence: 95,
		Filename:   "config.go",
		Validator:  "secrets",
		Context:    detector.ContextInfo{FullLine: `apiKey := "` + secret + `"`},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       false,
		Verbose:         true, // verbose must not re-leak the value
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Errorf("JUnit output leaked the secret value with ShowMatch=false, Verbose=true:\n%s", out)
	}

	// Sanity: with ShowMatch=true the value is allowed to appear (confirms the
	// match isn't simply being filtered out, so the negative case above is real).
	out2, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       true,
		Verbose:         true,
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(out2, secret) {
		t.Errorf("JUnit output should include the value when ShowMatch=true")
	}
}

// TestJUnitFormatter_SuppressedHonorsShowMatch is a regression test for the
// reveal gap where createTestCaseForSuppressedFile emitted an empty <testcase>
// and ignored ShowMatch entirely — so --show-match was a silent no-op for
// suppressed findings, inconsistent with every other formatter. The suppressed
// value must surface in <system-out> when ShowMatch is set, stay hidden when it
// is not, and never be reported as a <failure>.
func TestJUnitFormatter_SuppressedHonorsShowMatch(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	suppressed := []detector.SuppressedMatch{{
		Match: detector.Match{
			Text:       secret,
			LineNumber: 2,
			Type:       "VISA",
			Confidence: 100,
			Filename:   "cards.tsv",
			Validator:  "creditcard",
			Context:    detector.ContextInfo{FullLine: "Robert Aragon\t" + secret},
		},
		SuppressedBy: "SUP-00000001",
		RuleReason:   "known test card",
	}}
	allLevels := map[string]bool{"high": true, "medium": true, "low": true}

	// Hidden: the value must not appear, but the suppressed finding's structural
	// detail should still be present (so the entry is informative).
	hidden, err := NewFormatter().Format(nil, suppressed, formatters.FormatterOptions{
		ShowMatch: false, Verbose: true, ConfidenceLevel: allLevels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(hidden, secret) {
		t.Errorf("JUnit suppressed output leaked the value with ShowMatch=false:\n%s", hidden)
	}
	if !strings.Contains(hidden, "SUP-00000001") {
		t.Errorf("JUnit suppressed output should still show the suppressing rule id:\n%s", hidden)
	}
	// Suppressed findings are informational, not failures.
	if strings.Contains(hidden, "<failure") {
		t.Errorf("suppressed findings must not be reported as <failure>:\n%s", hidden)
	}

	// Revealed: --show-match surfaces the value in <system-out>.
	shown, err := NewFormatter().Format(nil, suppressed, formatters.FormatterOptions{
		ShowMatch: true, Verbose: true, ConfidenceLevel: allLevels,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(shown, secret) {
		t.Errorf("JUnit suppressed output should reveal the value when ShowMatch=true:\n%s", shown)
	}
	if strings.Contains(shown, "<failure") {
		t.Errorf("suppressed findings must not be reported as <failure> even when revealed:\n%s", shown)
	}
}
